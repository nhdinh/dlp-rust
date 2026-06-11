//! Approval Workflow Engine types for the DLP system.
//!
//! Defines the core data model for the approval workflow including:
//! - `ApprovalStatus` — lifecycle state of an approval request
//! - `Approval` — full approval record
//! - `ApprovalToken` — JWT token wrapper
//! - `ApprovalRequest` — user submission for an approval
//! - `ApprovalClaims` — JWT payload claims (shared with server to break circular dependency)
//! - `CachedApproval` — in-memory cached approval with deserialized claims
//! - `ApprovalCacheKey` — structured cache key for approval lookups

use serde::{Deserialize, Serialize};

/// Lifecycle state of an approval request.
///
/// An approval starts as `Pending`, and transitions to `Approved` or `Rejected`
/// via Data Owner (T3) or Board (T4) review. `Revoked` is set when an active
/// approval is explicitly cancelled. `Expired` is set when a time-bounded
/// approval lapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus {
    /// Awaiting Data Owner or Board review.
    Pending,
    /// Data Owner or Board has granted the approval.
    Approved,
    /// Data Owner or Board has denied the approval.
    Rejected,
    /// Previously-approved approval was explicitly cancelled.
    Revoked,
    /// Time-bounded approval has lapsed.
    Expired,
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        };
        write!(f, "{s}")
    }
}

/// Error returned when parsing an invalid `ApprovalStatus` string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid approval status: {0}")]
pub struct ApprovalStatusError(pub String);

impl TryFrom<&str> for ApprovalStatus {
    type Error = ApprovalStatusError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            other => Err(ApprovalStatusError(other.to_string())),
        }
    }
}

/// A full approval record capturing the entire lifecycle.
///
/// Stored in the central SQLite database and referenced by the agent
/// via `ApprovalToken` JWTs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    /// UUID string identifying the approval.
    pub id: String,
    /// AD SID of the user requesting the override.
    pub requester_sid: String,
    /// AD SID of the Data Owner who granted the approval (None until granted).
    pub approver_sid: Option<String>,
    /// FK to `labels.id` — the data being accessed.
    ///
    /// Note: this is a soft reference. During pilot phase the data object
    /// may not yet exist in the labels table.
    pub data_object_id: String,
    /// Action being approved (e.g. "WRITE", "COPY").
    pub allowed_action: String,
    /// Where the data can go (None = any destination).
    pub destination_scope: Option<String>,
    /// ISO-8601 timestamp when the approval becomes valid (None until granted).
    pub valid_from: Option<String>,
    /// ISO-8601 timestamp when the approval expires (None until granted).
    pub valid_until: Option<String>,
    /// Hex-encoded Ed25519 signature for T4 Board approval (None for T3).
    pub signature: Option<String>,
    /// Current lifecycle state.
    pub status: ApprovalStatus,
    /// User-provided justification text (max 500 chars, validated at API boundary).
    pub justification: String,
    /// ISO-8601 timestamp of creation.
    pub created_at: String,
    /// ISO-8601 timestamp of last update.
    pub updated_at: String,
}

/// A signed JWT approval token.
///
/// The `token` field is the complete JWT string (JWS format with EdDSA
/// signature). The `jti` field matches `approval.id` for correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalToken {
    /// The complete JWT string.
    pub token: String,
    /// Token ID — matches the approval UUID.
    pub jti: String,
}

/// A request for approval submitted by a user.
///
/// This is the input to the approval creation endpoint. The API boundary
/// validates `justification` length (max 500 chars).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// AD SID of the requesting user.
    pub requester_sid: String,
    /// ID of the data object being requested.
    pub data_object_id: String,
    /// Action being requested (e.g. "WRITE", "COPY").
    pub allowed_action: String,
    /// Destination scope restriction (None = any).
    pub destination_scope: Option<String>,
    /// User-provided justification (max 500 chars at API boundary).
    pub justification: String,
    /// Device fingerprint for binding the approval to a specific endpoint.
    pub device_fingerprint: Option<String>,
}

/// JWT claims for an approval token.
///
/// Shared in `dlp-common` to break the circular dependency between
/// `dlp-server` (which signs tokens) and `dlp-agent` (which verifies them).
///
/// Standard claims:
/// - `iss` — issuer ("dlp-server") for replay protection
/// - `sub` — requester SID
/// - `iat` / `exp` — issued-at / expires-at (Unix timestamps)
/// - `jti` — token ID (matches approval.id)
///
/// Custom claims:
/// - `obj` — data_object_id
/// - `act` — allowed_action
/// - `dst` — destination_scope
/// - `dev` — device_fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalClaims {
    /// Issuer — "dlp-server" for replay protection.
    pub iss: String,
    /// Subject — requester SID.
    pub sub: String,
    /// Data object ID.
    pub obj: String,
    /// Allowed action.
    pub act: String,
    /// Destination scope.
    pub dst: Option<String>,
    /// Device fingerprint.
    pub dev: Option<String>,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expires at (Unix timestamp).
    pub exp: i64,
    /// Token ID (matches approval.id).
    pub jti: String,
}

/// An approval cached in memory with deserialized claims.
///
/// Used by the agent's in-memory approval cache to avoid repeated
/// JWT verification on every policy evaluation.
#[derive(Debug, Clone)]
pub struct CachedApproval {
    /// The complete JWT string.
    pub token: String,
    /// Deserialized claims (avoids re-parsing the JWT).
    pub claims: ApprovalClaims,
    /// Expiry timestamp for cache TTL.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Structured cache key for approval lookups.
///
/// Uses JSON encoding to avoid delimiter collision issues that plague
/// colon-delimited string formats. Includes `destination_scope` to prevent
/// scope bypass (e.g. USB drive A approval cannot be used for USB drive B).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApprovalCacheKey {
    /// Requester SID.
    pub sid: String,
    /// Data object ID.
    pub obj_id: String,
    /// Action being requested.
    pub action: String,
    /// Destination scope (None = any).
    pub dst: Option<String>,
}

impl ApprovalCacheKey {
    /// Create a new cache key.
    ///
    /// # Arguments
    ///
    /// * `sid` — requester SID
    /// * `obj_id` — data object ID
    /// * `action` — action string
    /// * `dst` — optional destination scope
    #[must_use]
    pub fn new(sid: &str, obj_id: &str, action: &str, dst: Option<&str>) -> Self {
        Self {
            sid: sid.to_string(),
            obj_id: obj_id.to_string(),
            action: action.to_string(),
            dst: dst.map(|s| s.to_string()),
        }
    }

    /// Encode as a JSON string for DashMap storage.
    ///
    /// JSON encoding avoids delimiter collision issues and is human-readable
    /// for debugging.
    #[must_use]
    pub fn encode(&self) -> String {
        // JSON serialization of this struct is infallible for valid strings.
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Decode from a JSON string.
    ///
    /// Returns `None` if the input is not valid JSON or does not match
    /// the expected structure.
    #[must_use]
    pub fn decode(encoded: &str) -> Option<Self> {
        serde_json::from_str(encoded).ok()
    }

    /// Construct a cache key from an `EvaluateResponse` and identity/action context.
    ///
    /// Returns `None` if the evaluation response does not contain a `matched_label_id`,
    /// which is required to form the cache key's `obj_id` field.
    ///
    /// # Arguments
    ///
    /// * `response` — the evaluation response from the ABAC engine.
    /// * `sid` — requester SID (from session identity).
    /// * `action` — action being requested (e.g. "WRITE", "COPY").
    /// * `dst` — optional destination scope.
    #[must_use]
    pub fn from_evaluation(
        response: &crate::EvaluateResponse,
        sid: &str,
        action: &str,
        dst: Option<&str>,
    ) -> Option<Self> {
        let obj_id = response.matched_label_id.as_deref()?;
        Some(Self::new(sid, obj_id, action, dst))
    }
}

/// Legacy helper for backward compatibility during migration.
///
/// DEPRECATED: Use `ApprovalCacheKey::encode()` instead.
#[must_use]
pub fn approval_cache_key(sid: &str, obj_id: &str, action: &str, dst: Option<&str>) -> String {
    ApprovalCacheKey::new(sid, obj_id, action, dst).encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approval_status_serde_round_trip() {
        let status = ApprovalStatus::Pending;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"pending\"");
        let round_trip: ApprovalStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, round_trip);
    }

    #[test]
    fn test_approval_status_display_and_parse() {
        assert_eq!(ApprovalStatus::Approved.to_string(), "approved");
        let parsed: ApprovalStatus = "approved".try_into().unwrap();
        assert_eq!(parsed, ApprovalStatus::Approved);
    }

    #[test]
    fn test_approval_serde_round_trip() {
        let approval = Approval {
            id: "approval-001".to_string(),
            requester_sid: "S-1-5-21-1".to_string(),
            approver_sid: Some("S-1-5-21-2".to_string()),
            data_object_id: "label-001".to_string(),
            allowed_action: "WRITE".to_string(),
            destination_scope: Some("C:\\Data".to_string()),
            valid_from: Some("2026-05-14T00:00:00Z".to_string()),
            valid_until: Some("2026-05-15T00:00:00Z".to_string()),
            signature: Some("deadbeef".to_string()),
            status: ApprovalStatus::Approved,
            justification: "Business need".to_string(),
            created_at: "2026-05-14T00:00:00Z".to_string(),
            updated_at: "2026-05-14T01:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&approval).unwrap();
        let round_trip: Approval = serde_json::from_str(&json).unwrap();
        assert_eq!(approval, round_trip);
    }

    #[test]
    fn test_approval_token_serde_round_trip() {
        let token = ApprovalToken {
            token: "eyJhbGciOiJFZERTQSJ9.test".to_string(),
            jti: "approval-001".to_string(),
        };
        let json = serde_json::to_string(&token).unwrap();
        let round_trip: ApprovalToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, round_trip);
    }

    #[test]
    fn test_approval_request_serde_round_trip() {
        let req = ApprovalRequest {
            requester_sid: "S-1-5-21-1".to_string(),
            data_object_id: "label-001".to_string(),
            allowed_action: "COPY".to_string(),
            destination_scope: Some("E:\\".to_string()),
            justification: "Need to copy to USB".to_string(),
            device_fingerprint: Some("fp-abc".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let round_trip: ApprovalRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, round_trip);
    }

    #[test]
    fn test_approval_status_invalid_try_from() {
        let result: Result<ApprovalStatus, _> = "invalid".try_into();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "invalid approval status: invalid");
    }

    #[test]
    fn test_approval_cache_key_encode_decode() {
        let key = ApprovalCacheKey::new("S-1-5-21-1", "label-001", "WRITE", Some("C:\\Data"));
        let encoded = key.encode();
        let decoded = ApprovalCacheKey::decode(&encoded).expect("decode must succeed");
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_approval_cache_key_none_dst() {
        let key = ApprovalCacheKey::new("S-1-5-21-1", "label-001", "WRITE", None);
        let encoded = key.encode();
        let decoded = ApprovalCacheKey::decode(&encoded).expect("decode must succeed");
        assert_eq!(key, decoded);
        assert_eq!(decoded.dst, None);
    }

    #[test]
    fn test_cached_approval_fields() {
        let claims = ApprovalClaims {
            iss: "dlp-server".to_string(),
            sub: "S-1-5-21-1".to_string(),
            obj: "label-001".to_string(),
            act: "WRITE".to_string(),
            dst: Some("C:\\Data".to_string()),
            dev: Some("fp-abc".to_string()),
            iat: 1_000_000_000,
            exp: 2_000_000_000,
            jti: "approval-001".to_string(),
        };
        let cached = CachedApproval {
            token: "jwt-string".to_string(),
            claims,
            expires_at: chrono::Utc::now(),
        };
        assert_eq!(cached.claims.iss, "dlp-server");
        assert_eq!(cached.claims.jti, "approval-001");
    }

    #[test]
    fn test_approval_claims_serde_round_trip() {
        let claims = ApprovalClaims {
            iss: "dlp-server".to_string(),
            sub: "S-1-5-21-1".to_string(),
            obj: "label-001".to_string(),
            act: "WRITE".to_string(),
            dst: Some("C:\\Data".to_string()),
            dev: Some("fp-abc".to_string()),
            iat: 1_000_000_000,
            exp: 2_000_000_000,
            jti: "approval-001".to_string(),
        };
        let json = serde_json::to_string(&claims).unwrap();
        let round_trip: ApprovalClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(claims.sub, round_trip.sub);
        assert_eq!(claims.obj, round_trip.obj);
        assert_eq!(claims.act, round_trip.act);
        assert_eq!(claims.dst, round_trip.dst);
        assert_eq!(claims.dev, round_trip.dev);
        assert_eq!(claims.iat, round_trip.iat);
        assert_eq!(claims.exp, round_trip.exp);
        assert_eq!(claims.jti, round_trip.jti);
        assert_eq!(claims.iss, round_trip.iss);
    }

    #[test]
    fn test_legacy_approval_cache_key_helper() {
        let key = approval_cache_key("S-1-5-21-1", "label-001", "WRITE", Some("C:\\Data"));
        let decoded = ApprovalCacheKey::decode(&key).expect("decode must succeed");
        assert_eq!(decoded.sid, "S-1-5-21-1");
        assert_eq!(decoded.obj_id, "label-001");
        assert_eq!(decoded.action, "WRITE");
        assert_eq!(decoded.dst, Some("C:\\Data".to_string()));
    }

    #[test]
    fn test_approval_status_try_from_case_insensitive() {
        let upper: ApprovalStatus = "PENDING".try_into().unwrap();
        assert_eq!(upper, ApprovalStatus::Pending);
        let mixed: ApprovalStatus = "Revoked".try_into().unwrap();
        assert_eq!(mixed, ApprovalStatus::Revoked);
    }

    #[test]
    fn test_approval_cache_key_from_evaluation_some() {
        let response = crate::EvaluateResponse {
            decision: crate::Decision::DENY,
            matched_policy_id: None,
            reason: "default deny".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: Some("label-001".to_string()),
        };

        let key = ApprovalCacheKey::from_evaluation(&response, "S-1-5-21-1", "WRITE", Some("C:\\Data"));
        assert!(key.is_some());
        let key = key.unwrap();
        assert_eq!(key.sid, "S-1-5-21-1");
        assert_eq!(key.obj_id, "label-001");
        assert_eq!(key.action, "WRITE");
        assert_eq!(key.dst, Some("C:\\Data".to_string()));
    }

    #[test]
    fn test_approval_cache_key_from_evaluation_none() {
        let response = crate::EvaluateResponse {
            decision: crate::Decision::DENY,
            matched_policy_id: None,
            reason: "default deny".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: None,
        };

        let key = ApprovalCacheKey::from_evaluation(&response, "S-1-5-21-1", "WRITE", None);
        assert!(key.is_none(), "None matched_label_id must return None");
    }
}
