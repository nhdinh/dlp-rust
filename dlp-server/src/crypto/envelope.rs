//! On-disk envelope for AES-256-GCM ciphertext.
//!
//! Binary layout (written verbatim to `*_encrypted` BLOB columns):
//!
//! ```text
//! +--------+----------+----------------------------------+
//! | ver(1) | nonce(12)| ciphertext_with_gcm_tag (>= 16)  |
//! +--------+----------+----------------------------------+
//! ```
//!
//! Overhead is **29 bytes** per encrypted secret:
//! - 1 byte version
//! - 12 byte nonce (96-bit, AES-GCM standard)
//! - 16 byte GCM authentication tag (appended to ciphertext)
//!
//! The version byte enables forward-compatible upgrade to AES-256-GCM-SIV or
//! XChaCha20-Poly1305 in a future phase without ever touching column types.
//! Reading an envelope whose version byte does not match a known constant
//! returns `CryptoError::UnsupportedVersion`.

use crate::crypto::error::CryptoError;

/// Version byte for the original AES-256-GCM envelope shipped in Phase 47.
///
/// Reserved values:
/// - `0` — never used; rejected as invalid to catch zero-initialised buffers.
/// - `1` — AES-256-GCM, 96-bit nonce from `OsRng`, AAD = `b"dlp:secret:<table>:<column>"`.
/// - `2`+ — reserved for future phases.
pub const ENVELOPE_VERSION_V1: u8 = 1;

/// Length of an AES-GCM nonce in bytes (RFC 5116 / NIST SP 800-38D recommended).
pub const NONCE_LEN: usize = 12;

/// Length of the AES-GCM authentication tag appended to every ciphertext.
pub const TAG_LEN: usize = 16;

/// Minimum envelope size: 1 version byte + 12 nonce bytes + 16 tag bytes.
/// Plaintext of length 0 still yields a 29-byte envelope because of the tag.
pub const MIN_ENVELOPE_LEN: usize = 1 + NONCE_LEN + TAG_LEN;

/// In-memory representation of an encrypted secret ready for serialisation or
/// after deserialisation from the database.
///
/// Held by value, not by reference, because each envelope is tiny (29+ bytes)
/// and copying simplifies lifetime management in the repository layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Format version. Currently always [`ENVELOPE_VERSION_V1`].
    pub version: u8,
    /// 96-bit AES-GCM nonce. MUST be unique per `(key, message)` pair; we
    /// generate it via `OsRng` for every encrypt call.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with the 16-byte GCM authentication tag appended. The tag
    /// is **not** a separate field because the `aes-gcm` crate's `encrypt`
    /// returns them as a single concatenated `Vec<u8>` and the `decrypt`
    /// path expects the same.
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    /// Construct an envelope from its parts. Used by `SecretCrypto::encrypt`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidEnvelope`] when the ciphertext is shorter
    /// than the 16-byte authentication tag — a defensive guard for callers
    /// that bypass `SecretCrypto::encrypt`.
    pub fn new(
        version: u8,
        nonce: [u8; NONCE_LEN],
        ciphertext: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        if ciphertext.len() < TAG_LEN {
            return Err(CryptoError::InvalidEnvelope);
        }
        Ok(Self {
            version,
            nonce,
            ciphertext,
        })
    }

    /// Serialise to the on-disk BLOB layout.
    ///
    /// The returned `Vec<u8>` is written directly into the
    /// `<col>_encrypted` SQLite column.
    pub fn serialize(&self) -> Vec<u8> {
        let mut blob = Vec::with_capacity(1 + NONCE_LEN + self.ciphertext.len());
        blob.push(self.version);
        blob.extend_from_slice(&self.nonce);
        blob.extend_from_slice(&self.ciphertext);
        blob
    }

    /// Parse an envelope from its on-disk BLOB representation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidEnvelope`] when `blob.len() < 29`.
    /// Version-byte validation is performed at the decrypt site rather than
    /// here, because the version byte itself is not invalid — only "unknown"
    /// to this binary.
    pub fn deserialize(blob: &[u8]) -> Result<Self, CryptoError> {
        if blob.len() < MIN_ENVELOPE_LEN {
            return Err(CryptoError::InvalidEnvelope);
        }
        // Index 0: version, indices 1..=12: nonce, 13..: ciphertext+tag.
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&blob[1..1 + NONCE_LEN]);
        Ok(Self {
            version: blob[0],
            nonce,
            ciphertext: blob[1 + NONCE_LEN..].to_vec(),
        })
    }
}
