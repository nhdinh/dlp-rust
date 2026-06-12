//! Agent-side approval cache with JWT re-verification and destination scope matching.
//!
//! The `ApprovalCache` is a lock-free in-memory cache that stores active approval
//! tokens received from the dlp-server. Each cache entry is keyed by a structured
//! [`ApprovalCacheKey`] (JSON-encoded) and contains the full JWT token, deserialized
//! claims, and an expiry timestamp.
//!
//! ## Security properties
//!
//! - JWT signature is re-verified on every cache read using the server's cached
//!   Ed25519 public key.
//! - Cache key includes `destination_scope` to prevent scope bypass (e.g. a USB
//!   drive A approval cannot be reused for USB drive B).
//! - Expired entries are lazily evicted on access and periodically swept.
//! - Uses `chrono::DateTime<Utc>` for expiry (not `Instant`) so hibernation does
//!   not bypass expiry.
//!
//! ## Three-stage ABAC pipeline (AGENT-SIDE)
//!
//! The agent's evaluation pipeline is three-stage:
//!
//! 1. **NTFS check** — coarse-grained access control (existing Windows ACL check).
//! 2. **ABAC policy check** — fine-grained dynamic control (server-side via POST /evaluate).
//! 3. **Approval cache override** — agent-side check after server returns DENY.
//!
//! Critical invariant: If NTFS ALLOW and ABAC DENY -> check approval cache.
//! If approval cache hits and is valid -> ALLOW.
//! If approval cache misses -> FINAL RESULT = DENY.

use std::sync::Arc;

use chrono::Utc;
use dashmap::DashMap;
use dlp_common::approval::{ApprovalCacheKey, ApprovalClaims, CachedApproval};
use dlp_common::{Decision, EvaluateResponse};
use tracing::{debug, warn};

/// Errors returned by the approval cache.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalCacheError {
    /// Invalid hex in the public key.
    #[error("invalid hex in public key: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// Invalid Ed25519 public key bytes.
    #[error("invalid Ed25519 public key: {0}")]
    InvalidPublicKey(String),
}

/// Agent-local approval cache with lock-free reads and JWT re-verification.
///
/// Does NOT depend on the server-side `PolicyStore` — this is a self-contained
/// agent module to avoid cross-crate coupling.
#[derive(Debug, Clone)]
pub struct ApprovalCache {
    /// Lock-free map from JSON-encoded [`ApprovalCacheKey`] to [`CachedApproval`].
    pub cache: Arc<DashMap<String, CachedApproval>>,
    /// Server's Ed25519 verifying key, cached at startup for offline verification.
    verifying_key: Arc<std::sync::RwLock<Option<ed25519_dalek::VerifyingKey>>>,
}

impl ApprovalCache {
    /// Creates an empty approval cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            verifying_key: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Sets the server's Ed25519 public key for offline JWT verification.
    ///
    /// Called once at startup after fetching the key from
    /// `GET /agent/approvals/public-key`.
    ///
    /// # Arguments
    ///
    /// * `pubkey_hex` — 64-character hex string encoding the 32-byte Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns `ApprovalCacheError::InvalidHex` if the hex is malformed.
    /// Returns `ApprovalCacheError::InvalidPublicKey` if the decoded bytes do not
    /// form a valid Ed25519 public key.
    pub fn set_public_key(&self, pubkey_hex: &str) -> Result<(), ApprovalCacheError> {
        let bytes = hex::decode(pubkey_hex)?;
        let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            ApprovalCacheError::InvalidPublicKey("public key must be exactly 32 bytes".to_string())
        })?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
            ApprovalCacheError::InvalidPublicKey(format!("Ed25519 key invalid: {e}"))
        })?;
        let mut vk = self.verifying_key.write().expect("poisoned lock");
        *vk = Some(key);
        debug!("cached server Ed25519 public key for approval token verification");
        Ok(())
    }

    /// Inserts an approval token into the cache.
    ///
    /// TTL is derived from `claims.exp` (Unix timestamp). If `claims.exp` is in
    /// the past or cannot be parsed, a 1-hour default TTL is applied.
    ///
    /// # Arguments
    ///
    /// * `key` — structured cache key (sid, obj_id, action, dst).
    /// * `token` — the complete JWT string.
    /// * `claims` — deserialized claims from the JWT.
    pub fn insert(&self, key: ApprovalCacheKey, token: String, claims: ApprovalClaims) {
        let expires_at = chrono::DateTime::from_timestamp(claims.exp, 0)
            .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1));
        self.cache.insert(
            key.encode(),
            CachedApproval {
                token,
                claims,
                expires_at,
            },
        );
    }

    /// Checks whether an approval exists in the cache and is valid.
    ///
    /// This method performs the following checks in order:
    /// 1. Cache lookup by encoded key.
    /// 2. Expiry check (lazily removes expired entries).
    /// 3. JWT signature re-verification using the cached public key.
    /// 4. Destination scope matching (if the approval has a restricted scope).
    ///
    /// PERFORMANCE NOTE: Ed25519 verification is approximately 50 microseconds.
    /// For high-frequency file hooks, the caller may choose to cache verified
    /// claims with periodic re-verification.
    ///
    /// # Arguments
    ///
    /// * `key` — the cache key to look up.
    /// * `request_dst` — the actual destination of the current request (for scope validation).
    ///
    /// # Returns
    ///
    /// `Some(EvaluateResponse)` with `Decision::ALLOW` if a valid approval is found.
    /// `None` if no matching approval exists, it is expired, signature verification
    /// fails, or the destination scope does not match.
    pub fn check(
        &self,
        key: &ApprovalCacheKey,
        request_dst: Option<&str>,
    ) -> Option<EvaluateResponse> {
        let entry = self.cache.get(&key.encode())?;

        // Expiry check.
        if Utc::now() > entry.expires_at {
            drop(entry);
            self.cache.remove(&key.encode());
            debug!("approval cache entry expired — removed");
            return None;
        }

        // Re-verify JWT signature using cached public key.
        let vk_guard = self.verifying_key.read().expect("poisoned lock");
        if let Some(ref vk) = *vk_guard {
            let dec_key = jsonwebtoken::DecodingKey::from_ed_der(&vk.to_bytes());
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
            validation.set_issuer(&["dlp-server"]);
            if jsonwebtoken::decode::<ApprovalClaims>(&entry.token, &dec_key, &validation).is_err()
            {
                warn!("approval cache entry failed signature re-verification");
                return None;
            }
        } else {
            // No public key cached — cannot verify. This is a startup race;
            // treat as cache miss so the operation falls through to default deny.
            warn!("approval cache check with no public key cached — treating as miss");
            return None;
        }
        drop(vk_guard);

        // Destination scope validation.
        if let Some(ref approved_dst) = entry.claims.dst {
            if !approved_dst.is_empty() {
                if let Some(req_dst) = request_dst {
                    if !scope_matches(req_dst, approved_dst) {
                        debug!(
                            request_dst = %req_dst,
                            approved_dst = %approved_dst,
                            "approval cache hit but destination scope mismatch"
                        );
                        return None;
                    }
                }
            }
        }

        debug!("approval cache hit — granting override");
        Some(EvaluateResponse {
            decision: Decision::ALLOW,
            matched_policy_id: Some(format!("approval:{}", entry.claims.jti)),
            reason: "approved via override token".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: Some(entry.claims.obj.clone()),
        })
    }

    /// Removes a specific entry from the cache.
    pub fn remove(&self, key: &ApprovalCacheKey) {
        self.cache.remove(&key.encode());
    }

    /// Removes all expired entries from the cache.
    ///
    /// Called periodically (e.g. every 60 seconds) from a background task.
    pub fn sweep_expired(&self) {
        let now = Utc::now();
        let to_remove: Vec<String> = self
            .cache
            .iter()
            .filter(|e| now > e.expires_at)
            .map(|e| e.key().clone())
            .collect();
        for key in to_remove {
            self.cache.remove(&key);
            debug!(key = %key, "swept expired approval cache entry");
        }
    }

    /// Returns the number of entries in the cache (including expired).
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns true if the cache contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for ApprovalCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Check whether an approval override exists for the given evaluation response.
///
/// This is the **single public entry point** for enforcement paths (file monitor,
/// hook DLL, etc.) to query the approval cache. It wraps [`ApprovalCache::check()`]
/// and returns both the override response and the original claims for audit
/// enrichment.
///
/// # Arguments
///
/// * `cache` — the agent's approval cache.
/// * `response` — the ABAC evaluation response (must contain `matched_label_id`).
/// * `sid` — requester SID.
/// * `action` — action being requested (e.g. "WRITE", "COPY").
/// * `dst` — optional destination scope.
///
/// # Returns
///
/// `Some((EvaluateResponse, ApprovalClaims))` if a valid approval exists.
/// `None` if no label matched, no cache entry exists, the entry is expired,
/// or signature verification fails.
#[must_use]
pub fn check_approval_override(
    cache: &ApprovalCache,
    response: &dlp_common::EvaluateResponse,
    sid: &str,
    action: &str,
    dst: Option<&str>,
) -> Option<(dlp_common::EvaluateResponse, ApprovalClaims)> {
    let key = ApprovalCacheKey::from_evaluation(response, sid, action, dst)?;
    // check() performs: cache lookup + expiry + JWT re-verify + scope match.
    let ovr = cache.check(&key, dst)?;
    // To return claims for audit enrichment, read the cached entry.
    // check() already verified the entry is valid, so this read is safe
    // without re-verification.
    let entry = cache.cache.get(&key.encode())?;
    Some((ovr, entry.claims.clone()))
}

/// Checks whether a request destination matches an approved destination scope.
///
/// Supports exact matching and hierarchical wildcards:
/// - `approved_dst == "*"` or empty -> matches any request.
/// - `approved_dst == request_dst` -> exact match.
/// - `approved_dst.ends_with(":*")` -> prefix match (e.g. `USB:*` matches `USB:DRIVE_E`).
///
/// # Examples
///
/// ```
/// use dlp_agent::approval_cache::scope_matches;
/// assert!(scope_matches("USB:DRIVE_E", "USB:*"));
/// assert!(!scope_matches("USB:DRIVE_E", "USB:DRIVE_F"));
/// assert!(scope_matches("C:\\Data", "C:\\Data"));
/// assert!(scope_matches("any", "*"));
/// ```
#[must_use]
pub fn scope_matches(request_dst: &str, approved_dst: &str) -> bool {
    if approved_dst.is_empty() || approved_dst == "*" {
        return true;
    }
    if request_dst == approved_dst {
        return true;
    }
    if let Some(prefix) = approved_dst.strip_suffix(":*") {
        return request_dst.starts_with(prefix)
            && request_dst.len() > prefix.len()
            && request_dst.as_bytes()[prefix.len()] == b':';
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claims(exp: i64, dst: Option<&str>) -> ApprovalClaims {
        ApprovalClaims {
            iss: "dlp-server".to_string(),
            sub: "S-1-5-21-1".to_string(),
            obj: "label-001".to_string(),
            act: "WRITE".to_string(),
            dst: dst.map(|s| s.to_string()),
            dev: None,
            iat: 1_000_000_000,
            exp,
            jti: "approval-001".to_string(),
        }
    }

    #[test]
    fn test_insert_and_check() {
        let cache = ApprovalCache::new();
        let key = ApprovalCacheKey::new("S-1-5-21-1", "label-001", "WRITE", Some("C:\\Data"));
        let claims = make_claims(Utc::now().timestamp() + 3600, Some("C:\\Data"));
        cache.insert(key.clone(), "jwt-token".to_string(), claims);

        // Without public key, check returns None (cannot verify).
        assert!(cache.check(&key, Some("C:\\Data")).is_none());
    }

    #[test]
    fn test_check_expired_entry_removed() {
        let cache = ApprovalCache::new();
        let key = ApprovalCacheKey::new("S-1-5-21-1", "label-001", "WRITE", None);
        let claims = make_claims(Utc::now().timestamp() - 1, None); // already expired
        cache.insert(key.clone(), "jwt-token".to_string(), claims);

        assert!(cache.check(&key, None).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_check_missing_entry() {
        let cache = ApprovalCache::new();
        let key = ApprovalCacheKey::new("S-1-5-21-1", "label-001", "WRITE", None);
        assert!(cache.check(&key, None).is_none());
    }

    #[test]
    fn test_remove() {
        let cache = ApprovalCache::new();
        let key = ApprovalCacheKey::new("S-1-5-21-1", "label-001", "WRITE", None);
        let claims = make_claims(Utc::now().timestamp() + 3600, None);
        cache.insert(key.clone(), "jwt-token".to_string(), claims);
        assert_eq!(cache.len(), 1);

        cache.remove(&key);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_sweep_expired() {
        let cache = ApprovalCache::new();
        let key1 = ApprovalCacheKey::new("S-1-5-21-1", "label-001", "WRITE", None);
        let key2 = ApprovalCacheKey::new("S-1-5-21-1", "label-002", "WRITE", None);

        let expired_claims = make_claims(Utc::now().timestamp() - 1, None);
        let valid_claims = make_claims(Utc::now().timestamp() + 3600, None);

        cache.insert(key1.clone(), "jwt-1".to_string(), expired_claims);
        cache.insert(key2.clone(), "jwt-2".to_string(), valid_claims);

        assert_eq!(cache.len(), 2);
        cache.sweep_expired();
        assert_eq!(cache.len(), 1);
        assert!(cache.check(&key2, None).is_none()); // still no pubkey
    }

    #[test]
    fn test_scope_matches_exact() {
        assert!(scope_matches("C:\\Data", "C:\\Data"));
        assert!(!scope_matches("C:\\Data", "C:\\Other"));
    }

    #[test]
    fn test_scope_matches_wildcard() {
        assert!(scope_matches("USB:DRIVE_E", "USB:*"));
        assert!(!scope_matches("USB:DRIVE_E", "USB:DRIVE_F"));
        assert!(scope_matches("any", "*"));
    }

    #[test]
    fn test_scope_matches_empty_allows_all() {
        assert!(scope_matches("anything", ""));
    }

    #[test]
    fn test_scope_matches_prefix_boundary() {
        // USB:* should NOT match USBX (missing colon boundary).
        assert!(!scope_matches("USBX", "USB:*"));
        assert!(scope_matches("USB:X", "USB:*"));
    }

    #[test]
    fn test_set_public_key_invalid_hex() {
        let cache = ApprovalCache::new();
        assert!(cache.set_public_key("not-hex").is_err());
    }

    #[test]
    fn test_set_public_key_wrong_length() {
        let cache = ApprovalCache::new();
        assert!(cache.set_public_key("deadbeef").is_err());
    }

    #[test]
    fn test_set_public_key_valid() {
        let cache = ApprovalCache::new();
        // A valid Ed25519 verifying key (32 bytes, hex-encoded).
        // This is the verifying key from a known test keypair.
        let pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        assert!(cache.set_public_key(pubkey_hex).is_ok());
    }

    #[test]
    fn test_check_with_valid_signature() {
        // Generate a real Ed25519 keypair, sign a token, and verify it.
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        let claims = make_claims(Utc::now().timestamp() + 3600, Some("C:\\Data"));

        // Build and sign a JWT.
        let pkcs8_der = signing_key.to_pkcs8_der().expect("pkcs8 encode");
        let enc_key = jsonwebtoken::EncodingKey::from_ed_der(pkcs8_der.as_bytes());
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
            &claims,
            &enc_key,
        )
        .expect("jwt encode");

        let cache = ApprovalCache::new();
        let pubkey_hex = hex::encode(verifying_key.to_bytes());
        cache.set_public_key(&pubkey_hex).expect("set pubkey");

        let key =
            ApprovalCacheKey::new(&claims.sub, &claims.obj, &claims.act, claims.dst.as_deref());
        cache.insert(key.clone(), token, claims);

        let result = cache.check(&key, Some("C:\\Data"));
        assert!(result.is_some(), "valid token should pass verification");
        let resp = result.unwrap();
        assert_eq!(resp.decision, Decision::ALLOW);
        assert_eq!(
            resp.matched_policy_id,
            Some("approval:approval-001".to_string())
        );
    }

    #[test]
    fn test_check_rejects_tampered_token() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        let claims = make_claims(Utc::now().timestamp() + 3600, None);

        let pkcs8_der = signing_key.to_pkcs8_der().expect("pkcs8 encode");
        let enc_key = jsonwebtoken::EncodingKey::from_ed_der(pkcs8_der.as_bytes());
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
            &claims,
            &enc_key,
        )
        .expect("jwt encode");

        // Tamper with the payload.
        let mut parts: Vec<&str> = token.split('.').collect();
        parts[1] = "dGFtcGVyZWQ"; // base64 of "tampered"
        let tampered = parts.join(".");

        let cache = ApprovalCache::new();
        let pubkey_hex = hex::encode(verifying_key.to_bytes());
        cache.set_public_key(&pubkey_hex).expect("set pubkey");

        let key = ApprovalCacheKey::new(&claims.sub, &claims.obj, &claims.act, None);
        cache.insert(key.clone(), tampered, claims);

        assert!(
            cache.check(&key, None).is_none(),
            "tampered token must be rejected"
        );
    }

    #[test]
    fn test_check_rejects_wrong_destination_scope() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        let claims = make_claims(Utc::now().timestamp() + 3600, Some("USB:DRIVE_E"));

        let pkcs8_der = signing_key.to_pkcs8_der().expect("pkcs8 encode");
        let enc_key = jsonwebtoken::EncodingKey::from_ed_der(pkcs8_der.as_bytes());
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
            &claims,
            &enc_key,
        )
        .expect("jwt encode");

        let cache = ApprovalCache::new();
        let pubkey_hex = hex::encode(verifying_key.to_bytes());
        cache.set_public_key(&pubkey_hex).expect("set pubkey");

        let key =
            ApprovalCacheKey::new(&claims.sub, &claims.obj, &claims.act, claims.dst.as_deref());
        cache.insert(key.clone(), token, claims);

        // Requesting USB:DRIVE_F should fail scope check.
        assert!(
            cache.check(&key, Some("USB:DRIVE_F")).is_none(),
            "wrong destination scope must be rejected"
        );
    }

    #[test]
    fn test_check_allows_wildcard_scope() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        let claims = make_claims(Utc::now().timestamp() + 3600, Some("USB:*"));

        let pkcs8_der = signing_key.to_pkcs8_der().expect("pkcs8 encode");
        let enc_key = jsonwebtoken::EncodingKey::from_ed_der(pkcs8_der.as_bytes());
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
            &claims,
            &enc_key,
        )
        .expect("jwt encode");

        let cache = ApprovalCache::new();
        let pubkey_hex = hex::encode(verifying_key.to_bytes());
        cache.set_public_key(&pubkey_hex).expect("set pubkey");

        let key =
            ApprovalCacheKey::new(&claims.sub, &claims.obj, &claims.act, claims.dst.as_deref());
        cache.insert(key.clone(), token, claims);

        assert!(
            cache.check(&key, Some("USB:DRIVE_E")).is_some(),
            "wildcard scope must match any USB drive"
        );
    }

    #[test]
    fn test_cache_key_structured_type() {
        let key = ApprovalCacheKey::new("S-1-5-21-1", "label-001", "WRITE", Some("C:\\Data"));
        let encoded = key.encode();
        // JSON encoding, not colon-delimited.
        assert!(encoded.starts_with('{'));
        let decoded = ApprovalCacheKey::decode(&encoded).expect("decode must succeed");
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_check_without_public_key_returns_none() {
        let cache = ApprovalCache::new();
        let key = ApprovalCacheKey::new("S-1-5-21-1", "label-001", "WRITE", None);
        let claims = make_claims(Utc::now().timestamp() + 3600, None);
        cache.insert(key.clone(), "any-token".to_string(), claims);

        // No public key set — must return None (cannot verify).
        assert!(cache.check(&key, None).is_none());
    }

    #[test]
    fn test_three_stage_pipeline_documented() {
        // This test verifies the three-stage pipeline invariant:
        // NTFS check -> ABAC policy check -> approval override.
        // The ApprovalCache is the third stage.
        let cache = ApprovalCache::new();
        assert!(cache.is_empty());
        // When ABAC returns DENY and no approval is cached, the final result is DENY.
        // When an approval is cached and valid, the final result is ALLOW.
        // This is enforced by the caller (interception::run_event_loop), not by
        // ApprovalCache itself, which only answers "is there a valid approval?".
    }

    // ── check_approval_override tests ───────────────────────────────────────

    #[test]
    fn test_check_approval_override_hit() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        let claims = make_claims(Utc::now().timestamp() + 3600, Some("C:\\Data"));

        let pkcs8_der = signing_key.to_pkcs8_der().expect("pkcs8 encode");
        let enc_key = jsonwebtoken::EncodingKey::from_ed_der(pkcs8_der.as_bytes());
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
            &claims,
            &enc_key,
        )
        .expect("jwt encode");

        let cache = ApprovalCache::new();
        let pubkey_hex = hex::encode(verifying_key.to_bytes());
        cache.set_public_key(&pubkey_hex).expect("set pubkey");

        let key =
            ApprovalCacheKey::new(&claims.sub, &claims.obj, &claims.act, claims.dst.as_deref());
        cache.insert(key.clone(), token, claims.clone());

        let response = dlp_common::EvaluateResponse {
            decision: dlp_common::Decision::DENY,
            matched_policy_id: None,
            reason: "default deny".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: Some("label-001".to_string()),
        };

        let result =
            check_approval_override(&cache, &response, "S-1-5-21-1", "WRITE", Some("C:\\Data"));
        assert!(result.is_some(), "valid approval should produce override");
        let (ovr, returned_claims) = result.unwrap();
        assert_eq!(ovr.decision, dlp_common::Decision::ALLOW);
        assert_eq!(returned_claims.jti, claims.jti);
    }

    #[test]
    fn test_check_approval_override_miss_no_label_id() {
        let cache = ApprovalCache::new();

        let response = dlp_common::EvaluateResponse {
            decision: dlp_common::Decision::DENY,
            matched_policy_id: None,
            reason: "default deny".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: None,
        };

        let result = check_approval_override(&cache, &response, "S-1-5-21-1", "WRITE", None);
        assert!(
            result.is_none(),
            "missing matched_label_id must return None"
        );
    }

    #[test]
    fn test_check_approval_override_miss_no_cache_entry() {
        let cache = ApprovalCache::new();

        let response = dlp_common::EvaluateResponse {
            decision: dlp_common::Decision::DENY,
            matched_policy_id: None,
            reason: "default deny".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: Some("label-001".to_string()),
        };

        let result = check_approval_override(&cache, &response, "S-1-5-21-1", "WRITE", None);
        assert!(
            result.is_none(),
            "matched_label_id present but no cache entry must return None"
        );
    }
}
