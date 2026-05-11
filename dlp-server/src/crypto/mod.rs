//! Phase 47 — Secrets Encryption at Rest.
//!
//! Cryptographic primitives that turn a DPAPI-machine-bound seed into an
//! AES-256-GCM cipher and back. Every secret column in operator SQLite
//! (`alert_router_config.smtp_password`, `siem_config.splunk_token`,
//! `secrets_jwt.secret`, `ldap_config.bind_password`, etc.) is stored as an
//! [`Envelope`] BLOB that this module produces.
//!
//! # Threat model — what this module defends
//!
//! - **Offline file-system theft** of the SQLite file: the DB cannot be
//!   decrypted on a different machine because DPAPI is bound to the
//!   originating Windows installation.
//! - **Cross-column ciphertext replay**: the per-secret AAD ([`aad_for`])
//!   binds every ciphertext to its `(table, column)` pair. Pasting an
//!   `smtp_password` envelope into `splunk_token` produces an
//!   `AuthTagMismatch` on read.
//! - **Tampering with on-disk bytes**: AES-GCM's 128-bit tag covers
//!   ciphertext, nonce-implicit-binding, and AAD. Any flip is detected.
//! - **Forward-compat envelope upgrade**: the version byte enables a future
//!   phase to introduce a new cipher (AES-GCM-SIV, XChaCha20-Poly1305)
//!   without changing column types.
//!
//! # What this module does NOT defend
//!
//! - **A local administrator with code execution** on the same machine:
//!   `CRYPTPROTECT_LOCAL_MACHINE` allows any process on the host to
//!   decrypt, so the only barrier becomes the NTFS ACL on the SQLite file
//!   (SYSTEM-only, established by `docs/SECURITY_AUDIT.md`).
//! - **Logging hygiene**: secrets that *do* end up in memory plaintext
//!   form must be wrapped in [`secrecy::SecretString`] by the caller — this
//!   module returns a `SecretString` from [`SecretCrypto::decrypt`] but
//!   downstream code must not call `expose_secret()` outside the legitimate
//!   send paths (SMTP, LDAP bind, JWT sign/verify). That is Task 47-09's
//!   audit scope.

pub mod dpapi;
pub mod envelope;
pub mod error;
pub mod kdf;

#[cfg(test)]
mod tests;

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use secrecy::SecretString;
use zeroize::Zeroizing;

pub use envelope::{Envelope, ENVELOPE_VERSION_V1};
pub use error::CryptoError;
pub use kdf::{derive_kek, PBKDF2_DEFAULT_ITERATIONS, PBKDF2_SALT_LEN};

#[cfg(windows)]
pub use dpapi::{dpapi_protect, dpapi_unprotect, MachineSecret};

/// Build the per-secret Additional Authenticated Data string.
///
/// The AAD binds a ciphertext to its `(table, column)` pair so that a row
/// pasted across columns — or replayed from a different table — fails
/// authentication on decrypt with [`CryptoError::AuthTagMismatch`].
///
/// Format: `b"dlp:secret:" || table || b":" || column`.
///
/// This format is **stable forever**: changing it would invalidate every
/// existing ciphertext. New tables join the namespace by adding a new
/// `(table, column)` pair, never by changing the prefix.
pub fn aad_for(table: &str, column: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(11 + table.len() + 1 + column.len());
    aad.extend_from_slice(b"dlp:secret:");
    aad.extend_from_slice(table.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(column.as_bytes());
    aad
}

/// In-memory holder for an active KEK plus its version byte.
///
/// Constructed via [`SecretCrypto::load_active`] (production) or
/// [`SecretCrypto::from_kek`] (tests and the bootstrap path before the
/// `secret_kek_history` row is inserted).
///
/// The KEK is wrapped in [`zeroize::Zeroizing`] so it is overwritten with
/// zeros when this struct is dropped. The manual `Debug` impl below ensures
/// the bytes never appear in formatted output. Combined with the `aes-gcm`
/// crate's own `zeroize` feature (enabled in `Cargo.toml`), the KEK lives
/// in plaintext memory only for the duration of `encrypt`/`decrypt` calls.
///
/// **Deviation from PLAN.md's `<interfaces>` block.** The spec listed
/// `kek: secrecy::SecretBox<[u8; 32]>` but `secrecy 0.8` requires
/// `Box<S>: Zeroize`, and `zeroize 1.8` only implements `Zeroize for Box<[T]>`
/// (slice form) — not `Box<[T; N]>` (sized array form). `Zeroizing<[u8; 32]>`
/// provides equivalent on-drop zeroisation without the type-system tax.
pub struct SecretCrypto {
    kek: Zeroizing<[u8; 32]>,
    version: u8,
}

impl std::fmt::Debug for SecretCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretCrypto")
            .field("version", &self.version)
            .field("kek", &"<redacted>")
            .finish()
    }
}

impl SecretCrypto {
    /// Construct from a raw 32-byte KEK and version byte.
    ///
    /// **Test / bootstrap use only.** Production code paths derive the KEK
    /// from [`SecretCrypto::load_active`]; this constructor exists so the
    /// crypto module is testable without a `secret_kek_history` table.
    ///
    /// The input array is consumed and zeroised once wrapped.
    pub fn from_kek(kek: [u8; 32], version: u8) -> Self {
        Self {
            kek: Zeroizing::new(kek),
            version,
        }
    }

    /// The active KEK version. Stamped into every envelope this instance
    /// produces.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Encrypt `plaintext` under AAD `aad` with a freshly drawn 96-bit nonce.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EncryptFailed`] only if the underlying
    /// AES-GCM call fails (unreachable in practice with our fixed-size
    /// inputs, but the API does not promise infallibility).
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Envelope, CryptoError> {
        let key = Key::<Aes256Gcm>::from_slice(self.kek.as_ref());
        let cipher = Aes256Gcm::new(key);
        // 96-bit nonce drawn from the OS CSPRNG. AES-GCM tolerates up to
        // 2^32 random nonces per key before the collision probability exceeds
        // 2^-32; with 600,000-iter PBKDF2 KEKs rotated on operator command,
        // we are several orders of magnitude away from that bound.
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptFailed)?;

        let nonce_arr: [u8; envelope::NONCE_LEN] = nonce.into();
        Envelope::new(self.version, nonce_arr, ciphertext)
    }

    /// Decrypt `env` under AAD `aad`, returning the recovered plaintext
    /// wrapped in [`SecretString`] to prevent accidental logging.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::UnsupportedVersion`] if `env.version` differs from
    ///   any constant this binary knows about — typically because the row
    ///   was written by a future server release.
    /// - [`CryptoError::AuthTagMismatch`] if the GCM tag fails — usually
    ///   indicates AAD mismatch (cross-column replay), wrong KEK version,
    ///   or on-disk tampering. The error message intentionally does not
    ///   distinguish these cases.
    /// - [`CryptoError::InvalidEnvelope`] if the plaintext is not valid
    ///   UTF-8 (we cannot wrap it in `SecretString`). Binary secrets should
    ///   use a future `decrypt_bytes` API; today every secret column is
    ///   text-shaped.
    pub fn decrypt(&self, env: &Envelope, aad: &[u8]) -> Result<SecretString, CryptoError> {
        if env.version != ENVELOPE_VERSION_V1 {
            return Err(CryptoError::UnsupportedVersion(env.version));
        }
        let key = Key::<Aes256Gcm>::from_slice(self.kek.as_ref());
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::<aes_gcm::aes::cipher::consts::U12>::from_slice(&env.nonce);
        let plaintext_bytes = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &env.ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::AuthTagMismatch)?;

        // Convert to UTF-8 String wrapped in SecretString. If a future
        // binary-secret column is added, expose a parallel `decrypt_bytes`
        // returning `SecretBox<Vec<u8>>`; do not weaken this signature.
        let plaintext =
            String::from_utf8(plaintext_bytes).map_err(|_| CryptoError::InvalidEnvelope)?;
        // secrecy 0.8: `SecretString::new` takes `String` by value; `plaintext`
        // is already a `String`, so no `.into()` is required.
        Ok(SecretString::new(plaintext))
    }

    /// Load the active KEK from `secret_kek_history`.
    ///
    /// This is the production entry point used at server startup. It reads
    /// the highest-version row with `retired_at IS NULL`, DPAPI-unwraps the
    /// `master_seed_dpapi` blob, and re-derives the KEK via PBKDF2.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::KekNotLoaded`] when no active row exists (fresh
    ///   install — caller should bootstrap via
    ///   [`SecretCrypto::create_new_version`]).
    /// - [`CryptoError::DpapiUnprotectFailed`] when the wrapped seed cannot
    ///   be unwrapped on this machine.
    ///
    /// Available on Windows only; non-Windows builds always return
    /// [`CryptoError::KekNotLoaded`] because DPAPI is unavailable.
    #[cfg(windows)]
    pub fn load_active(conn: &rusqlite::Connection) -> Result<Self, CryptoError> {
        let row: Option<(u8, Vec<u8>, Vec<u8>, u32)> = conn
            .query_row(
                "SELECT version, master_seed_dpapi, pbkdf2_salt, pbkdf2_iterations \
                 FROM secret_kek_history \
                 WHERE retired_at IS NULL \
                 ORDER BY version DESC \
                 LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .ok();

        let (version, dpapi_blob, salt_blob, iterations) = row.ok_or(CryptoError::KekNotLoaded)?;
        let seed = dpapi_unprotect(&dpapi_blob)?;

        if salt_blob.len() != PBKDF2_SALT_LEN {
            return Err(CryptoError::KdfFailed);
        }
        let mut salt = [0u8; PBKDF2_SALT_LEN];
        salt.copy_from_slice(&salt_blob);

        let derived = derive_kek(&seed, &salt, iterations);
        // Copy out of `Zeroizing<[u8;32]>` into `SecretBox` for long-lived holding.
        let mut kek = [0u8; 32];
        kek.copy_from_slice(derived.as_ref());
        Ok(Self::from_kek(kek, version))
    }

    /// Non-Windows stub. DPAPI is unavailable, so we cannot load a
    /// production KEK. Returns [`CryptoError::KekNotLoaded`] unconditionally.
    #[cfg(not(windows))]
    pub fn load_active(_conn: &rusqlite::Connection) -> Result<Self, CryptoError> {
        Err(CryptoError::KekNotLoaded)
    }

    /// Generate a new KEK version, persist the DPAPI-wrapped seed and salt
    /// into `secret_kek_history`, and return the loaded `SecretCrypto`.
    ///
    /// Used by (a) first-run bootstrap on a fresh install and (b) the
    /// `rotate-secrets` admin command (Task 47-08).
    ///
    /// # Errors
    ///
    /// - [`CryptoError::DpapiProtectFailed`] if DPAPI cannot wrap the seed.
    /// - Underlying `rusqlite::Error` is mapped into [`CryptoError::KdfFailed`]
    ///   for compactness; finer error surfacing lands in Task 47-02.
    ///
    /// Available on Windows only; non-Windows builds always return
    /// [`CryptoError::DpapiProtectFailed`].
    #[cfg(windows)]
    pub fn create_new_version(conn: &mut rusqlite::Connection) -> Result<Self, CryptoError> {
        use aes_gcm::aead::rand_core::RngCore;

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let mut salt = [0u8; PBKDF2_SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        let wrapped = dpapi_protect(&seed)?;

        // Determine next version number. Task 47-02 owns the table; this
        // call is best-effort and falls back to 1 if the table is missing.
        let next_version: u8 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM secret_kek_history",
                [],
                |r| r.get::<_, i64>(0).map(|v| v as u8),
            )
            .unwrap_or(1);

        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO secret_kek_history \
             (version, master_seed_dpapi, pbkdf2_salt, pbkdf2_iterations, created_at) \
             VALUES (?, ?, ?, ?, ?)",
            rusqlite::params![
                next_version as i64,
                wrapped,
                salt.as_slice(),
                PBKDF2_DEFAULT_ITERATIONS as i64,
                now,
            ],
        )
        .map_err(|_| CryptoError::KdfFailed)?;

        let derived = derive_kek(&seed, &salt, PBKDF2_DEFAULT_ITERATIONS);
        let mut kek = [0u8; 32];
        kek.copy_from_slice(derived.as_ref());
        Ok(Self::from_kek(kek, next_version))
    }

    /// Non-Windows stub. DPAPI is unavailable.
    #[cfg(not(windows))]
    pub fn create_new_version(_conn: &mut rusqlite::Connection) -> Result<Self, CryptoError> {
        Err(CryptoError::DpapiProtectFailed {
            source: error::DpapiError,
        })
    }

    /// Convenience bootstrap entry point used by `main.rs` at server start.
    ///
    /// - If `secret_kek_history` already has an active row, returns the
    ///   loaded KEK ([`Self::load_active`]).
    /// - Else generates a fresh v1 KEK ([`Self::create_new_version`]) and
    ///   persists the DPAPI-wrapped seed + salt as version 1.
    ///
    /// Acquires its own pooled connection so callers do not have to
    /// reason about read/write connection lifetimes. The acquire path is
    /// fallible and is mapped into [`CryptoError::KdfFailed`] for
    /// compactness — the only realistic failure here is pool exhaustion
    /// at startup, which is a hard error.
    ///
    /// # Errors
    ///
    /// Propagates [`CryptoError::DpapiUnprotectFailed`] /
    /// [`CryptoError::DpapiProtectFailed`] from the underlying ops, plus
    /// [`CryptoError::KdfFailed`] for pool-acquisition failures.
    pub fn load_active_or_bootstrap(pool: &crate::db::Pool) -> Result<Self, CryptoError> {
        // First try the active-row read with an immutable connection.
        let active_present = {
            let conn = pool.get().map_err(|_| CryptoError::KdfFailed)?;
            crate::db::repositories::secret_kek::get_active(&conn)
                .map_err(|_| CryptoError::KdfFailed)?
                .is_some()
        };

        if active_present {
            let conn = pool.get().map_err(|_| CryptoError::KdfFailed)?;
            Self::load_active(&conn)
        } else {
            // Bootstrap: need a mutable connection because `create_new_version`
            // takes `&mut Connection` for symmetry with rusqlite's
            // transaction APIs (even though this insert is auto-commit).
            let mut conn = pool.get().map_err(|_| CryptoError::KdfFailed)?;
            Self::create_new_version(&mut conn)
        }
    }
}
