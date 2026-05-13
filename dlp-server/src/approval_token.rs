//! Approval Token Service — Ed25519 JWT signing and verification.
//!
//! This module provides cryptographic signing and verification for approval
//! tokens used in the T3 Data Owner and T4 Board digital-signature workflows.
//!
//! ## Key storage
//!
//! The Ed25519 signing key is stored encrypted at rest using the Phase 47
//! `SecretCrypto` envelope infrastructure (PBKDF2 + DPAPI + AES-256-GCM).
//! The key is loaded once at startup and held in memory for the server lifetime.
//!
//! ## Spike verification
//!
//! The following API pattern was verified by the `/tmp/ed25519-spike` crate
//! before this module was written:
//!
//! ```rust,ignore
//! use ed25519_dalek::pkcs8::EncodePrivateKey;
//! use ed25519_dalek::SigningKey;
//! use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
//!
//! let signing_key = SigningKey::generate(&mut rand::thread_rng());
//! let pkcs8_der = signing_key.to_pkcs8_der().unwrap();
//! let enc_key = EncodingKey::from_ed_der(pkcs8_der.as_bytes());
//! let verifying_key = signing_key.verifying_key();
//! let dec_key = DecodingKey::from_ed_der(&verifying_key.to_bytes());
//! ```
//!
//! ## T4 Board digital signature
//!
//! T4 approvals require a Board member to sign a canonical message with their
//! Ed25519 private key. The canonical format includes `jti` (approval ID) to
//! prevent signature replay across different approvals:
//!
//! ```text
//! DLP-T4-SIGNATURE:{jti}:{sub}:{obj}:{act}:{valid_until}
//! ```

use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rusqlite::OptionalExtension;

use dlp_common::ApprovalClaims;

use crate::AppError;

/// Service for signing and verifying approval tokens.
///
/// Holds an Ed25519 keypair in memory. The private key is loaded from
/// encrypted storage at construction time (or generated if absent).
pub struct ApprovalTokenService {
    /// Ed25519 signing key — never leaves this process.
    signing_key: SigningKey,
    /// Corresponding verifying key — shared with agents for token validation.
    verifying_key: VerifyingKey,
}

impl std::fmt::Debug for ApprovalTokenService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalTokenService")
            .field("verifying_key_hex", &self.verifying_key_hex())
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

/// Well-known `system_kv` key for the encrypted signing key.
const KEY_APPROVAL_SIGNING_KEY: &str = "approval_signing_key_encrypted";
/// Well-known `system_kv` key for the verifying key (public, stored for convenience).
const KEY_APPROVAL_VERIFYING_KEY: &str = "approval_verifying_key";
/// Well-known `system_kv` key for the Board public key.
const KEY_BOARD_PUBLIC_KEY: &str = "board_public_key";
/// Expected issuer claim for replay protection.
const EXPECTED_ISSUER: &str = "dlp-server";

impl ApprovalTokenService {
    /// Loads or generates the Ed25519 keypair using Phase 47 encrypted storage.
    ///
    /// # Arguments
    ///
    /// * `crypto` — the active `SecretCrypto` instance for envelope encryption
    /// * `conn` — a SQLite connection for reading/writing `system_kv`
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` on crypto or database failures.
    pub fn new(
        crypto: &crate::crypto::SecretCrypto,
        conn: &rusqlite::Connection,
    ) -> Result<Self, AppError> {
        // Try to load existing encrypted key from system_kv.
        let existing_key: Option<String> = conn
            .query_row(
                "SELECT value FROM system_kv WHERE key = ?1",
                rusqlite::params![KEY_APPROVAL_SIGNING_KEY],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("db error reading signing key: {e}")))?;

        if let Some(key_hex) = existing_key {
            // Decrypt the stored envelope.
            let envelope = crate::crypto::Envelope::deserialize(
                &hex::decode(&key_hex).map_err(|e| {
                    AppError::Internal(anyhow::anyhow!("invalid hex in stored signing key: {e}"))
                })?,
            )
            .map_err(|e| {
                AppError::Internal(anyhow::anyhow!("invalid envelope for signing key: {e}"))
            })?;

            let decrypted = crypto
                .decrypt_bytes(
                    &envelope,
                    &crate::crypto::aad_for("system_kv", "approval_signing_key"),
                )
                .map_err(|e| {
                    AppError::Internal(anyhow::anyhow!("failed to decrypt signing key: {e}"))
                })?;

            let key_bytes: [u8; 32] = decrypted.try_into().map_err(
                |_| {
                    AppError::Internal(anyhow::anyhow!(
                        "decrypted signing key is not 32 bytes"
                    ))
                },
            )?;

            let signing_key = SigningKey::from_bytes(&key_bytes);
            let verifying_key = signing_key.verifying_key();

            return Ok(Self {
                signing_key,
                verifying_key,
            });
        }

        // No existing key — generate a new one.
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        // Encrypt and store the signing key.
        let envelope = crypto
            .encrypt(
                signing_key.to_bytes().as_slice(),
                &crate::crypto::aad_for("system_kv", "approval_signing_key"),
            )
            .map_err(|e| {
                AppError::Internal(anyhow::anyhow!("failed to encrypt signing key: {e}"))
            })?;

        let key_hex = hex::encode(envelope.serialize());
        conn.execute(
            "INSERT OR REPLACE INTO system_kv (key, value) VALUES (?1, ?2)",
            rusqlite::params![KEY_APPROVAL_SIGNING_KEY, key_hex],
        )
        .map_err(|e| {
            AppError::Internal(anyhow::anyhow!("db error storing signing key: {e}"))
        })?;

        // Store the verifying key (public) for convenience.
        let verifying_hex = hex::encode(verifying_key.to_bytes());
        conn.execute(
            "INSERT OR REPLACE INTO system_kv (key, value) VALUES (?1, ?2)",
            rusqlite::params![KEY_APPROVAL_VERIFYING_KEY, verifying_hex],
        )
        .map_err(|e| {
            AppError::Internal(anyhow::anyhow!("db error storing verifying key: {e}"))
        })?;

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Signs the given claims into a JWT using EdDSA.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if JWT encoding fails.
    pub fn sign_token(&self, claims: &ApprovalClaims) -> Result<String, AppError> {
        let pkcs8_der = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("pkcs8 encoding failed: {e}")))?;
        let enc_key = EncodingKey::from_ed_der(pkcs8_der.as_bytes());

        encode(
            &Header::new(Algorithm::EdDSA),
            claims,
            &enc_key,
        )
        .map_err(|e| AppError::Internal(anyhow::anyhow!("jwt encode failed: {e}")))
    }

    /// Verifies a JWT signature and validates the `iss` claim.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthorized` if the token is invalid, expired,
    /// tampered, or has the wrong issuer.
    pub fn verify_token(&self, token: &str) -> Result<ApprovalClaims, AppError> {
        let dec_key = DecodingKey::from_ed_der(&self.verifying_key.to_bytes());
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[EXPECTED_ISSUER]);

        decode::<ApprovalClaims>(token, &dec_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| AppError::Unauthorized(format!("token verification failed: {e}")))
    }

    /// Returns the hex-encoded public verifying key.
    ///
    /// Agents use this key to validate approval tokens locally.
    #[must_use]
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Stores the Board public key in `system_kv`.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` on database failure.
    pub fn store_board_public_key(
        conn: &rusqlite::Connection,
        pubkey_hex: &str,
    ) -> Result<(), AppError> {
        conn.execute(
            "INSERT OR REPLACE INTO system_kv (key, value) VALUES (?1, ?2)",
            rusqlite::params![KEY_BOARD_PUBLIC_KEY, pubkey_hex],
        )
        .map_err(|e| AppError::Internal(anyhow::anyhow!("db error storing board pubkey: {e}")))?;
        Ok(())
    }

    /// Retrieves the Board public key from `system_kv`.
    ///
    /// Returns `None` if no key has been stored.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` on database failure.
    pub fn get_board_public_key(
        conn: &rusqlite::Connection,
    ) -> Result<Option<String>, AppError> {
        let result: Option<String> = conn
            .query_row(
                "SELECT value FROM system_kv WHERE key = ?1",
                rusqlite::params![KEY_BOARD_PUBLIC_KEY],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| {
                AppError::Internal(anyhow::anyhow!("db error reading board pubkey: {e}"))
            })?;
        Ok(result)
    }

    /// Verifies an Ed25519 signature against the Board public key.
    ///
    /// # Arguments
    ///
    /// * `pubkey_hex` — hex-encoded Ed25519 public key
    /// * `message` — the message bytes that were signed
    /// * `signature_hex` — hex-encoded Ed25519 signature
    ///
    /// # Errors
    ///
    /// Returns `AppError::BadRequest` if the pubkey or signature hex is invalid.
    /// Returns `AppError::Internal` for other crypto failures.
    pub fn verify_board_signature(
        pubkey_hex: &str,
        message: &[u8],
        signature_hex: &str,
    ) -> Result<bool, AppError> {
        let pubkey_bytes = hex::decode(pubkey_hex).map_err(|e| {
            AppError::BadRequest(format!("invalid board pubkey hex: {e}"))
        })?;
        let pubkey_bytes: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
            AppError::BadRequest("board pubkey must be exactly 32 bytes".to_string())
        })?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|e| {
            AppError::BadRequest(format!("invalid board pubkey: {e}"))
        })?;

        let sig_bytes = hex::decode(signature_hex).map_err(|e| {
            AppError::BadRequest(format!("invalid signature hex: {e}"))
        })?;
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|e| {
            AppError::BadRequest(format!("invalid signature: {e}"))
        })?;

        Ok(verifying_key.verify(message, &signature).is_ok())
    }
}

/// Canonical T4 board signature message format.
///
/// Format: `DLP-T4-SIGNATURE:{jti}:{sub}:{obj}:{act}:{valid_until}`
///
/// This includes `jti` (approval ID) to prevent signature replay across
/// different approvals. The board member signs this exact string with their
/// Ed25519 private key.
///
/// # Arguments
///
/// * `jti` — approval ID (token ID)
/// * `sub` — requester SID
/// * `obj` — data object ID
/// * `act` — allowed action
/// * `valid_until` — expiry timestamp (ISO-8601)
#[must_use]
pub fn t4_canonical_message(jti: &str, sub: &str, obj: &str, act: &str, valid_until: &str) -> String {
    format!("DLP-T4-SIGNATURE:{jti}:{sub}:{obj}:{act}:{valid_until}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretCrypto;
    use crate::db::new_pool;

    fn make_test_crypto() -> SecretCrypto {
        // Deterministic test KEK — NOT for production use.
        let kek = [0xABu8; 32];
        SecretCrypto::from_kek(kek, 1)
    }

    fn make_test_claims(jti: &str) -> ApprovalClaims {
        ApprovalClaims {
            iss: EXPECTED_ISSUER.to_string(),
            sub: "S-1-5-21-1".to_string(),
            obj: "label-001".to_string(),
            act: "WRITE".to_string(),
            dst: Some("C:\\Data".to_string()),
            dev: Some("fp-abc".to_string()),
            iat: 1_000_000_000,
            exp: 2_000_000_000,
            jti: jti.to_string(),
        }
    }

    #[test]
    fn test_sign_and_verify_token() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");
        let crypto = make_test_crypto();
        let service = ApprovalTokenService::new(&crypto, &conn).expect("create service");

        let claims = make_test_claims("approval-001");
        let token = service.sign_token(&claims).expect("sign token");

        // Token must be a valid JWT (3 dot-separated parts).
        assert_eq!(token.split('.').count(), 3, "token must be JWT format");

        let verified = service.verify_token(&token).expect("verify token");
        assert_eq!(verified.sub, claims.sub);
        assert_eq!(verified.obj, claims.obj);
        assert_eq!(verified.act, claims.act);
        assert_eq!(verified.dst, claims.dst);
        assert_eq!(verified.dev, claims.dev);
        assert_eq!(verified.jti, claims.jti);
        assert_eq!(verified.iss, EXPECTED_ISSUER);
    }

    #[test]
    fn test_verify_rejects_tampered_token() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");
        let crypto = make_test_crypto();
        let service = ApprovalTokenService::new(&crypto, &conn).expect("create service");

        let claims = make_test_claims("approval-001");
        let token = service.sign_token(&claims).expect("sign token");

        // Tamper with the payload (middle segment).
        let mut parts: Vec<&str> = token.split('.').collect();
        parts[1] = "dGFtcGVyZWQ"; // base64 of "tampered"
        let tampered = parts.join(".");

        let result = service.verify_token(&tampered);
        assert!(result.is_err(), "tampered token must be rejected");
    }

    #[test]
    fn test_verify_rejects_expired_token() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");
        let crypto = make_test_crypto();
        let service = ApprovalTokenService::new(&crypto, &conn).expect("create service");

        let claims = ApprovalClaims {
            iss: EXPECTED_ISSUER.to_string(),
            sub: "S-1-5-21-1".to_string(),
            obj: "label-001".to_string(),
            act: "WRITE".to_string(),
            dst: None,
            dev: None,
            iat: 1_000_000_000,
            exp: 1_000_000_001, // already expired
            jti: "approval-expired".to_string(),
        };
        let token = service.sign_token(&claims).expect("sign token");

        let result = service.verify_token(&token);
        assert!(result.is_err(), "expired token must be rejected");
    }

    #[test]
    fn test_verify_rejects_wrong_issuer() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");
        let crypto = make_test_crypto();
        let service = ApprovalTokenService::new(&crypto, &conn).expect("create service");

        let bad_claims = ApprovalClaims {
            iss: "attacker".to_string(),
            sub: "S-1-5-21-1".to_string(),
            obj: "label-001".to_string(),
            act: "WRITE".to_string(),
            dst: None,
            dev: None,
            iat: 1_000_000_000,
            exp: 2_000_000_000,
            jti: "approval-bad-iss".to_string(),
        };
        let token = service.sign_token(&bad_claims).expect("sign token");

        let result = service.verify_token(&token);
        assert!(result.is_err(), "wrong issuer must be rejected");
    }

    #[test]
    fn test_new_generates_key_when_none_exists() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");
        let crypto = make_test_crypto();

        let service = ApprovalTokenService::new(&crypto, &conn).expect("create service");
        let vk_hex = service.verifying_key_hex();
        assert_eq!(vk_hex.len(), 64, "verifying key hex must be 64 chars (32 bytes)");

        // Verify key was stored in system_kv.
        let stored: String = conn
            .query_row(
                "SELECT value FROM system_kv WHERE key = ?1",
                rusqlite::params![KEY_APPROVAL_SIGNING_KEY],
                |r| r.get(0),
            )
            .expect("stored key must exist");
        assert!(!stored.is_empty(), "stored key must not be empty");
    }

    #[test]
    fn test_new_loads_existing_key() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");
        let crypto = make_test_crypto();

        // First creation.
        let service1 = ApprovalTokenService::new(&crypto, &conn).expect("create service 1");
        let vk_hex1 = service1.verifying_key_hex();

        // Second creation should load the same key.
        let service2 = ApprovalTokenService::new(&crypto, &conn).expect("create service 2");
        let vk_hex2 = service2.verifying_key_hex();

        assert_eq!(vk_hex1, vk_hex2, "reloading must produce same verifying key");
    }

    #[test]
    fn test_board_public_key_store_retrieve() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let pubkey = "deadbeef".to_string();
        ApprovalTokenService::store_board_public_key(&conn, &pubkey).expect("store");

        let retrieved = ApprovalTokenService::get_board_public_key(&conn)
            .expect("get")
            .expect("must exist");
        assert_eq!(retrieved, pubkey);
    }

    #[test]
    fn test_board_signature_verification() {
        // Generate a board keypair.
        let board_signing = SigningKey::generate(&mut rand::thread_rng());
        let board_verifying = board_signing.verifying_key();
        let pubkey_hex = hex::encode(board_verifying.to_bytes());

        let message = b"test message for board";
        let signature = board_signing.sign(message);
        let signature_hex = hex::encode(signature.to_bytes());

        let valid = ApprovalTokenService::verify_board_signature(
            &pubkey_hex,
            message,
            &signature_hex,
        )
        .expect("verify");
        assert!(valid, "valid signature must verify");

        // Tampered message.
        let invalid = ApprovalTokenService::verify_board_signature(
            &pubkey_hex,
            b"tampered",
            &signature_hex,
        )
        .expect("verify tampered");
        assert!(!invalid, "tampered message must fail verification");
    }

    #[test]
    fn test_t4_canonical_message_format() {
        let msg = t4_canonical_message(
            "approval-001",
            "S-1-5-21-1",
            "label-001",
            "WRITE",
            "2026-05-15T00:00:00Z",
        );
        assert_eq!(
            msg,
            "DLP-T4-SIGNATURE:approval-001:S-1-5-21-1:label-001:WRITE:2026-05-15T00:00:00Z"
        );
    }

    #[test]
    fn test_t4_canonical_message_deterministic() {
        let msg1 = t4_canonical_message("a", "b", "c", "d", "e");
        let msg2 = t4_canonical_message("a", "b", "c", "d", "e");
        assert_eq!(msg1, msg2, "canonical message must be deterministic");
    }

    #[test]
    fn test_verifying_key_hex_round_trip() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");
        let crypto = make_test_crypto();
        let service = ApprovalTokenService::new(&crypto, &conn).expect("create service");

        let vk_hex = service.verifying_key_hex();
        let decoded = hex::decode(&vk_hex).expect("decode hex");
        assert_eq!(decoded.len(), 32, "decoded key must be 32 bytes");
    }
}
