//! Error types for the Phase 47 crypto module.
//!
//! All variants are intentionally opaque in their `Display` impl: a leaked
//! error message must never reveal plaintext, KEK bytes, ciphertext, or any
//! other sensitive byte sequence. The Windows-specific DPAPI variants carry
//! the underlying `windows::core::Error` only because it is a HRESULT code,
//! never a buffer.

use thiserror::Error;

/// All cryptographic operations performed by the `crypto` module return this
/// error type. It is `#[non_exhaustive]` so we can add variants in future
/// phases (e.g., HSM-backed KEKs) without a breaking change.
///
/// # Display safety
///
/// Every `Display` rendering is a fixed string plus, for `UnsupportedVersion`,
/// the offending version byte. **Never** include plaintext, ciphertext, nonces,
/// AAD, or KEK material in any error variant — these strings end up in logs.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// `CryptProtectData` returned a failure HRESULT during master-seed protection.
    ///
    /// Surfaced when first-run KEK bootstrap or rotation cannot persist the
    /// DPAPI-wrapped seed. Typically indicates a misconfigured service account
    /// or LSA secret unavailability. Recovery requires operator intervention.
    #[error("DPAPI protect failed")]
    DpapiProtectFailed {
        /// HRESULT from `CryptProtectData`. Logged as-is — contains no secret material.
        #[source]
        source: DpapiError,
    },

    /// `CryptUnprotectData` returned a failure HRESULT during master-seed unwrap.
    ///
    /// Returned at startup when the SQLite file has been moved to a different
    /// machine (DPAPI master key not present), the service identity changed
    /// (LSA secret rotation), or the DB file is corrupted. Caller surfaces as
    /// a hard startup error per CONTEXT D-Q4.
    #[error("DPAPI unprotect failed")]
    DpapiUnprotectFailed {
        /// HRESULT from `CryptUnprotectData`. Logged as-is — contains no secret material.
        #[source]
        source: DpapiError,
    },

    /// PBKDF2 key derivation failed.
    ///
    /// In practice unreachable with the `pbkdf2` crate's infallible
    /// `pbkdf2_hmac` entry point, but reserved for future PRF backends
    /// (e.g., hardware-accelerated PBKDF2) that may return errors.
    #[error("KDF failed")]
    KdfFailed,

    /// AES-256-GCM `Aead::encrypt` returned an error.
    ///
    /// Unreachable in practice for our usage (correct key length, correct
    /// nonce size, well-formed AAD), but kept for completeness so we never
    /// `.unwrap()` a fallible call.
    #[error("encryption failed")]
    EncryptFailed,

    /// AES-256-GCM authentication tag mismatch.
    ///
    /// This is the **primary** integrity signal: triggered when (a) the
    /// ciphertext or tag was tampered with on disk, (b) the wrong AAD was
    /// supplied (cross-column replay attempt), or (c) the wrong KEK version
    /// was used. The error message intentionally does **not** distinguish
    /// these cases to avoid leaking information to an attacker probing the
    /// system.
    #[error("authentication tag mismatch")]
    AuthTagMismatch,

    /// Envelope version byte did not match any version this binary supports.
    ///
    /// Returned when a `*_encrypted` BLOB was written by a future release.
    /// Forward-compatibility guard: rather than panicking we surface a clean
    /// error so the caller can decide whether to fail open or fail closed.
    #[error("unsupported envelope version: {0}")]
    UnsupportedVersion(u8),

    /// On-disk envelope is shorter than the minimum 13 bytes
    /// (1 version + 12 nonce) or otherwise malformed.
    #[error("invalid envelope")]
    InvalidEnvelope,

    /// `SecretCrypto::load_active` could not find any active row in
    /// `secret_kek_history` — caller should bootstrap a new KEK.
    #[error("no active KEK loaded")]
    KekNotLoaded,
}

/// Opaque newtype around the platform-specific DPAPI failure.
///
/// On Windows this wraps `windows::core::Error`; on other platforms it is a
/// stub so the crate continues to compile (DPAPI call sites are
/// `#[cfg(windows)]`-gated and never construct this on non-Windows builds).
#[cfg(windows)]
#[derive(Debug, Error)]
#[error("DPAPI HRESULT: {hresult:#010x}")]
pub struct DpapiError {
    /// The native HRESULT returned by `CryptProtectData` / `CryptUnprotectData`.
    pub hresult: u32,
}

#[cfg(windows)]
impl From<windows::core::Error> for DpapiError {
    fn from(e: windows::core::Error) -> Self {
        Self {
            // HRESULT::0 yields the i32 code; cast to u32 for unsigned hex display.
            hresult: e.code().0 as u32,
        }
    }
}

/// Non-Windows stub. `crypto::dpapi` is `#[cfg(windows)]`-gated, so the only
/// way to reach this on non-Windows is via the type system, never at runtime.
#[cfg(not(windows))]
#[derive(Debug, Error)]
#[error("DPAPI is not available on this platform")]
pub struct DpapiError;
