//! PBKDF2-HMAC-SHA256 key derivation.
//!
//! Used to turn the DPAPI-unwrapped master seed plus a per-KEK random salt
//! into the 256-bit AES key. Iteration count is **600,000** per OWASP 2023
//! guidance (D-Q2 in `47-CONTEXT.md`).
//!
//! ## Why a wrapper
//!
//! The `pbkdf2` crate exposes `pbkdf2_hmac::<Sha256>` — a thin functional API.
//! This module wraps it for three reasons:
//!
//! 1. Stable type signature `derive_kek(seed, salt, iter) -> [u8; 32]` so
//!    Phase 47 callers do not depend on the underlying crate's generics.
//! 2. Single chokepoint to add zeroisation of the output buffer (`Zeroizing`)
//!    once the caller has consumed it.
//! 3. Easy place to swap in a future PRF (Argon2id) without touching every
//!    call site.

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Length of the PBKDF2 salt in bytes. 128 bits is the NIST-recommended
/// minimum for password-based key derivation salts.
pub const PBKDF2_SALT_LEN: usize = 16;

/// Default PBKDF2 iteration count for KEK derivation. 600,000 iterations of
/// HMAC-SHA256 is the OWASP 2023 recommendation and matches the
/// `pbkdf2_iterations` default in the `secret_kek_history` schema.
pub const PBKDF2_DEFAULT_ITERATIONS: u32 = 600_000;

/// Derive a 256-bit Key Encryption Key (KEK) from the DPAPI-unwrapped master
/// seed.
///
/// # Arguments
///
/// * `seed` - Variable-length bytes from `dpapi_unprotect` of the row's
///   `master_seed_dpapi` column. We do not enforce a length here because
///   `CryptUnprotectData` may add platform-specific framing; the salt and
///   iteration count provide the cryptographic strength.
/// * `salt` - 16-byte random salt drawn at KEK-creation time and stored in
///   `secret_kek_history.pbkdf2_salt`.
/// * `iterations` - PBKDF2 work factor. Use [`PBKDF2_DEFAULT_ITERATIONS`]
///   unless re-deriving a historical KEK whose row says otherwise.
///
/// # Returns
///
/// The derived 32-byte KEK wrapped in [`Zeroizing`]; the caller may copy it
/// into [`secrecy::SecretBox`] for long-lived storage. Once the `Zeroizing`
/// wrapper is dropped, the underlying buffer is overwritten with zeros to
/// minimise the in-memory exposure window.
///
/// # Errors
///
/// Infallible — `pbkdf2_hmac` does not return a `Result` for SHA-256, which
/// has no output-length constraint at 32 bytes. We still document this for
/// API parity with future PRF backends (e.g., Argon2id) that *can* fail.
pub fn derive_kek(
    seed: &[u8],
    salt: &[u8; PBKDF2_SALT_LEN],
    iterations: u32,
) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // `pbkdf2_hmac` writes the derived bytes in place.
    //
    // Rust note: the turbofish picks the PRF (HMAC-SHA256). Python developers
    // familiar with `hashlib.pbkdf2_hmac("sha256", ...)` will recognise this
    // as the same construction; the Rust API just hoists the digest choice
    // into a generic.
    pbkdf2_hmac::<Sha256>(seed, salt, iterations, out.as_mut());
    out
}

/// Internal helper used by KAT tests. Writes the derived bytes into an
/// arbitrary-length output buffer — useful for matching RFC 7914 vectors
/// whose `dkLen` is 64 bytes.
///
/// Not exposed publicly: production code only ever derives 32-byte KEKs.
#[cfg(test)]
pub(crate) fn pbkdf2_sha256_into(seed: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2_hmac::<Sha256>(seed, salt, iterations, out);
}
