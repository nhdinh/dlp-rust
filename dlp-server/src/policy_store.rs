//! In-memory policy cache with ABAC evaluation engine.
//!
//! ## Cache Strategy
//! - Load all policies from DB at startup via `PolicyRepository::list`.
//! - Cache lives in `RwLock<Vec<Policy>>` — read path needs no lock acquisition.
//! - `invalidate()` and `refresh()` acquire write lock and swap in a new Vec.
//!
//! ## Evaluation Order
//! Policies are evaluated in ascending `priority` order (lowest first, first-match wins).
//! Disabled policies are skipped entirely.

use std::sync::Arc;

use dlp_common::abac::{
    AbacContext, AppField, Decision, EvaluateResponse, Policy, PolicyCondition, PolicyMode,
};
use dlp_common::Classification;
use parking_lot::RwLock;
use tracing::{error, info, warn};

use crate::db::repositories::PolicyRepository;
use crate::db::Pool;
use crate::policy_engine_error::PolicyEngineError;

/// Background cache refresh interval (5 minutes).
pub const POLICY_REFRESH_INTERVAL_SECS: u64 = 300;

/// Converts a `PolicyMode` to its DB string representation.
pub(crate) const fn mode_str(mode: PolicyMode) -> &'static str {
    match mode {
        PolicyMode::ALL => "ALL",
        PolicyMode::ANY => "ANY",
        PolicyMode::NONE => "NONE",
    }
}

/// The policy evaluation store.
///
/// Holds an in-memory cache of all policies loaded from the database.
/// Evaluation is a read-only cache hit — no database call on the hot path.
pub struct PolicyStore {
    cache: RwLock<Vec<Policy>>,
    pool: Arc<Pool>,
}

impl PolicyStore {
    /// Loads all policies from the database and builds the in-memory cache.
    ///
    /// Called once at startup. Blocks briefly while SQLite reads all rows.
    ///
    /// # Arguments
    ///
    /// * `pool` — Shared database connection pool.
    ///
    /// # Errors
    ///
    /// Returns `PolicyEngineError` if the initial load fails.
    pub fn new(pool: Arc<Pool>) -> Result<Self, PolicyEngineError> {
        let policies = Self::load_from_db(&pool)
            .map_err(|e| PolicyEngineError::PolicyNotFound(e.to_string()))?;
        info!(count = policies.len(), "policy store loaded");
        Ok(Self {
            cache: RwLock::new(policies),
            pool,
        })
    }

    /// Re-reads all enabled policies from the database and replaces the cache.
    ///
    /// Called by the background refresh task. Logs errors but does NOT panic —
    /// a failed refresh means the stale cache is used until the next interval.
    pub fn refresh(&self) {
        match Self::load_from_db(&self.pool) {
            Ok(policies) => {
                let count = policies.len();
                *self.cache.write() = policies;
                info!(count, "policy store refreshed");
            }
            Err(e) => {
                error!(error = %e, "policy store refresh failed — using stale cache");
            }
        }
    }

    /// Immediately invalidates the cache and reloads from the database.
    ///
    /// Called by admin CRUD handlers after a successful DB commit so the next
    /// evaluation request sees the updated policy set.
    pub fn invalidate(&self) {
        match Self::load_from_db(&self.pool) {
            Ok(policies) => {
                let count = policies.len();
                *self.cache.write() = policies;
                info!(count, "policy store invalidated");
            }
            Err(e) => {
                warn!(error = %e, "policy store invalidation failed — keeping stale cache");
            }
        }
    }

    /// Evaluates `ctx` against the cached policy set.
    ///
    /// Returns a decision for the first enabled policy whose conditions all
    /// match. If no policy matches, applies tiered default-deny (D-01):
    /// - T1 / T2 → `Decision::ALLOW`
    /// - T3 / T4 → `Decision::DENY`
    ///
    /// This is the **hot path** — it acquires only a read lock on the cache.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The internal ABAC evaluation context (converted from `EvaluateRequest`
    ///   at the HTTP boundary per D-04).
    pub fn evaluate(&self, ctx: &AbacContext) -> EvaluateResponse {
        let cache = self.cache.read();

        for policy in cache.iter() {
            if !policy.enabled {
                continue;
            }
            let conditions_match = match policy.mode {
                PolicyMode::ALL => policy.conditions.iter().all(|c| condition_matches(c, ctx)),
                PolicyMode::ANY => policy.conditions.iter().any(|c| condition_matches(c, ctx)),
                PolicyMode::NONE => !policy.conditions.iter().any(|c| condition_matches(c, ctx)),
            };
            if conditions_match {
                return EvaluateResponse {
                    decision: policy.action,
                    matched_policy_id: Some(policy.id.clone()),
                    reason: format!("matched policy '{}'", policy.name),
                };
            }
        }

        // No policy matched — tiered default-deny (D-01).
        match ctx.resource.classification {
            Classification::T1 | Classification::T2 => EvaluateResponse::default_allow(),
            Classification::T3 | Classification::T4 => EvaluateResponse::default_deny(),
        }
    }

    /// Lists all cached policies (for admin read-back / diagnostics).
    #[must_use]
    pub fn list_policies(&self) -> Vec<Policy> {
        self.cache.read().clone()
    }

    /// Loads all policies from the database via `PolicyRepository::list`.
    fn load_from_db(pool: &Pool) -> Result<Vec<Policy>, rusqlite::Error> {
        let rows = PolicyRepository::list(pool)?;

        // Deserialize each policy row. Skip rows with invalid JSON rather than
        // crashing the server — log and continue.
        let mut policies = Vec::with_capacity(rows.len());
        for row in rows {
            match deserialize_policy_row(&row) {
                Ok(p) => policies.push(p),
                Err(e) => {
                    warn!(policy_id = %row.id, error = %e, "skipped policy with malformed conditions or mode");
                }
            }
        }

        // Policies are already sorted by priority ASC from the SQL query.
        Ok(policies)
    }
}

/// Deserializes a `PolicyRow` into a `Policy`.
///
/// Handles the translation from DB `action` string (`"Allow"`, `"Deny"`, etc.)
/// to the `Decision` enum, and from the `mode` column to `PolicyMode`.
fn deserialize_policy_row(
    row: &crate::db::repositories::policies::PolicyRow,
) -> Result<Policy, serde_json::Error> {
    let conditions: Vec<PolicyCondition> = serde_json::from_str(&row.conditions)?;
    let action = match row.action.to_lowercase().as_str() {
        "allow" => Decision::ALLOW,
        "deny" => Decision::DENY,
        "allow_with_log" | "allowwithlog" => Decision::AllowWithLog,
        "deny_with_alert" | "denywithalert" => Decision::DenyWithAlert,
        _ => Decision::DENY,
    };
    let mode = match row.mode.as_str() {
        "ALL" => PolicyMode::ALL,
        "ANY" => PolicyMode::ANY,
        "NONE" => PolicyMode::NONE,
        other => {
            return Err(serde::de::Error::custom(format!(
                "invalid policy mode: {other}"
            )));
        }
    };
    Ok(Policy {
        id: row.id.clone(),
        name: row.name.clone(),
        description: row.description.clone(),
        priority: row.priority as u32,
        conditions,
        action,
        enabled: row.enabled != 0,
        mode,
        version: row.version as u64,
    })
}

/// Evaluates a single condition against an ABAC evaluation context.
///
/// Returns `true` if the condition matches, `false` otherwise.
/// Operators `"in"` and `"not_in"` on non-MemberOf conditions return `false`
/// defensively (they only apply to group membership checks).
///
/// # Arguments
///
/// * `condition` - The policy condition to evaluate.
/// * `ctx` - The internal ABAC context built from the evaluation request.
fn condition_matches(condition: &PolicyCondition, ctx: &AbacContext) -> bool {
    match condition {
        PolicyCondition::Classification { op, value } => {
            compare_op_classification(op, &ctx.resource.classification, value)
        }
        PolicyCondition::MemberOf { op, group_sid } => {
            memberof_matches(op, group_sid, &ctx.subject.groups)
        }
        PolicyCondition::DeviceTrust { op, value } => {
            compare_op(op, &ctx.subject.device_trust, value)
        }
        PolicyCondition::NetworkLocation { op, value } => {
            compare_op(op, &ctx.subject.network_location, value)
        }
        PolicyCondition::AccessContext { op, value } => {
            compare_op(op, &ctx.environment.access_context, value)
        }
        PolicyCondition::SourceApplication { field, op, value } => {
            app_identity_matches(field, op, value, ctx.source_application.as_ref())
        }
        PolicyCondition::DestinationApplication { field, op, value } => {
            app_identity_matches(field, op, value, ctx.destination_application.as_ref())
        }
    }
}

/// Compares two values using the given operator string.
///
/// Supports `"eq"` and `"neq"` for all `T: PartialEq` types.
/// Operators `"in"` and `"not_in"` return `false` (not applicable to scalar types).
fn compare_op<T: PartialEq>(op: &str, actual: &T, expected: &T) -> bool {
    match op {
        "eq" => actual == expected,
        "neq" => actual != expected,
        // Defensive: "in"/"not_in" on non-MemberOf conditions never match.
        "in" | "not_in" => false,
        _ => false,
    }
}

/// Specialised Classification comparison for ordinal operators `gt`/`lt`.
///
/// Separate from the generic `compare_op` because ordinal semantics (T1 < T2 < T3 < T4)
/// differ from a simple `PartialEq` check. Uses `classification_ord` to map tiers to
/// numbers so that `T3 gt T2` evaluates as `3 > 2 == true`.
///
/// # Arguments
///
/// * `op` - Operator string: `"eq"`, `"neq"`, `"gt"`, or `"lt"`
/// * `actual` - The classification of the resource being evaluated
/// * `expected` - The classification value in the policy condition
///
/// # Returns
///
/// `true` if the comparison holds, `false` otherwise (including unknown operators)
fn compare_op_classification(op: &str, actual: &Classification, expected: &Classification) -> bool {
    match op {
        "eq" => actual == expected,
        "neq" => actual != expected,
        "gt" => classification_ord(actual) > classification_ord(expected),
        "lt" => classification_ord(actual) < classification_ord(expected),
        _ => false,
    }
}

/// Evaluates a MemberOf condition against the subject's group SID list.
///
/// - `"in"`: matches if ANY group SID in `subject_groups` equals `group_sid`
/// - `"not_in"`: matches if NO group SID in `subject_groups` equals `group_sid`
/// - `"eq"` / `"neq"`: scalar semantics (treat groups as single-element check)
/// - `"contains"`: case-sensitive substring match on the full SID string (per D-05)
fn memberof_matches(op: &str, target_sid: &str, subject_groups: &[String]) -> bool {
    match op {
        "in" => subject_groups.iter().any(|sid| sid == target_sid),
        "not_in" => subject_groups.iter().all(|sid| sid != target_sid),
        // Fall back to scalar semantics for eq/neq (treat as single-element list).
        "eq" => subject_groups.iter().any(|sid| sid == target_sid),
        "neq" => subject_groups.iter().all(|sid| sid != target_sid),
        // Case-sensitive substring match on the full SID string (per D-05).
        "contains" => subject_groups.iter().any(|sid| sid.contains(target_sid)),
        _ => false,
    }
}

/// Evaluates an application-identity condition against an optional [`AppIdentity`].
///
/// Returns `false` (fails closed) if `identity` is `None` — a missing application
/// identity cannot satisfy an identity-based condition (per D-03).
///
/// Supported operators:
/// - `"eq"` / `"ne"` — exact match on Publisher, ImagePath, or TrustTier
/// - `"contains"` — substring match on ImagePath only; returns `false` for other fields
///
/// # Arguments
///
/// * `field` - Which [`AppField`] to inspect on the identity
/// * `op` - Operator string: `"eq"`, `"ne"`, or `"contains"`
/// * `value` - The policy-authored value to compare against (string form)
/// * `identity` - The resolved [`AppIdentity`] from the evaluation context, or `None`
fn app_identity_matches(
    field: &AppField,
    op: &str,
    value: &str,
    identity: Option<&dlp_common::endpoint::AppIdentity>,
) -> bool {
    // D-03: None identity fails closed — no identity means the condition cannot be confirmed.
    let Some(app) = identity else {
        return false;
    };

    match field {
        AppField::Publisher => match op {
            "eq" => app.publisher == value,
            "ne" => app.publisher != value,
            // "contains" is not supported for Publisher (only ImagePath per D-03).
            _ => false,
        },
        AppField::ImagePath => match op {
            "eq" => app.image_path == value,
            "ne" => app.image_path != value,
            "contains" => app.image_path.contains(value),
            _ => false,
        },
        AppField::TrustTier => {
            // Compare value string against AppTrustTier's serde serialized form:
            // "trusted", "untrusted", "unknown"
            let tier_str = serde_json::to_string(&app.trust_tier)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string();
            match op {
                "eq" => tier_str == value,
                "ne" => tier_str != value,
                _ => false,
            }
        }
    }
}

/// Maps a Classification tier to its ordinal position (1–4).
///
/// T1 = 1 (lowest sensitivity), T4 = 4 (highest sensitivity).
/// Used only for `gt`/`lt` comparisons in `compare_op_classification`.
/// Lives here rather than on `Classification` itself to avoid coupling risk
/// from the shared dlp-common enum deriving `PartialOrd` (per D-03).
///
/// # Arguments
///
/// * `c` - A reference to a `Classification` variant
///
/// # Returns
///
/// The ordinal tier number: T1 → 1, T2 → 2, T3 → 3, T4 → 4
fn classification_ord(c: &Classification) -> u8 {
    match c {
        Classification::T1 => 1,
        Classification::T2 => 2,
        Classification::T3 => 3,
        Classification::T4 => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::abac::{
        AbacContext, AccessContext, AppField, DeviceTrust, EvaluateRequest, NetworkLocation,
        Subject,
    };

    /// Helper to build a minimal [`AbacContext`] with the given classification tier.
    ///
    /// Uses `EvaluateRequest::into()` so the `From` impl is exercised on every
    /// existing test — confirming the conversion path compiles and behaves correctly.
    fn make_request(classification: Classification) -> AbacContext {
        EvaluateRequest {
            subject: Subject {
                user_sid: "S-1-5-21-123".to_string(),
                user_name: "testuser".to_string(),
                groups: vec!["S-1-5-21-123-512".to_string()],
                device_trust: DeviceTrust::Managed,
                network_location: NetworkLocation::Corporate,
            },
            resource: dlp_common::abac::Resource {
                path: r"C:\Data\test.txt".to_string(),
                classification,
            },
            environment: dlp_common::abac::Environment {
                timestamp: chrono::Utc::now(),
                session_id: 1,
                access_context: AccessContext::Local,
            },
            action: dlp_common::abac::Action::COPY,
            agent: None,
            source_application: None,
            destination_application: None,
        }
        .into()
    }

    /// Helper to build a PolicyStore with an empty in-memory cache.
    fn empty_store() -> PolicyStore {
        // `db::new_pool` is infallible for `:memory:`.
        PolicyStore {
            cache: RwLock::new(Vec::new()),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        }
    }

    #[test]
    fn test_tiered_default_deny_t1() {
        let store = empty_store();
        let resp = store.evaluate(&make_request(Classification::T1));
        assert_eq!(resp.decision, Decision::ALLOW);
    }

    #[test]
    fn test_tiered_default_deny_t2() {
        let store = empty_store();
        let resp = store.evaluate(&make_request(Classification::T2));
        assert_eq!(resp.decision, Decision::ALLOW);
    }

    #[test]
    fn test_tiered_default_deny_t3() {
        let store = empty_store();
        let resp = store.evaluate(&make_request(Classification::T3));
        assert_eq!(resp.decision, Decision::DENY);
    }

    #[test]
    fn test_tiered_default_deny_t4() {
        let store = empty_store();
        let resp = store.evaluate(&make_request(Classification::T4));
        assert_eq!(resp.decision, Decision::DENY);
    }

    #[test]
    fn test_disabled_policy_skipped() {
        let disabled = Policy {
            id: "p1".to_string(),
            name: "disabled policy".to_string(),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::Classification {
                op: "eq".to_string(),
                value: Classification::T3,
            }],
            action: Decision::DENY,
            enabled: false,
            mode: PolicyMode::ALL,
            version: 1,
        };
        let store = PolicyStore {
            cache: RwLock::new(vec![disabled]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        let resp = store.evaluate(&make_request(Classification::T3));
        // Disabled policy should be skipped → falls through to default-deny (T3)
        assert_eq!(resp.decision, Decision::DENY);
    }

    #[test]
    fn test_memberof_matches_in() {
        // "in" matches if ANY group equals target
        assert!(memberof_matches(
            "in",
            "S-1-5-21-123-512",
            &["S-1-5-21-123-512".to_string()]
        ));
        assert!(memberof_matches(
            "in",
            "S-1-5-21-123-512",
            &[
                "S-1-5-21-123-513".to_string(),
                "S-1-5-21-123-512".to_string()
            ]
        ));
        assert!(!memberof_matches(
            "in",
            "S-1-5-21-123-512",
            &["S-1-5-21-123-513".to_string()]
        ));
    }

    #[test]
    fn test_memberof_matches_not_in() {
        // "not_in" matches if NO group equals target
        assert!(memberof_matches(
            "not_in",
            "S-1-5-21-123-512",
            &["S-1-5-21-123-513".to_string()]
        ));
        assert!(!memberof_matches(
            "not_in",
            "S-1-5-21-123-512",
            &["S-1-5-21-123-512".to_string()]
        ));
    }

    #[test]
    fn test_compare_op_eq() {
        assert!(compare_op("eq", &Classification::T3, &Classification::T3));
        assert!(!compare_op("eq", &Classification::T3, &Classification::T1));
    }

    #[test]
    fn test_compare_op_neq() {
        assert!(compare_op("neq", &Classification::T3, &Classification::T1));
        assert!(!compare_op("neq", &Classification::T3, &Classification::T3));
    }

    #[test]
    fn test_compare_op_in_not_applicable_to_scalars() {
        // "in"/"not_in" on scalar types (e.g. Classification) should return false
        assert!(!compare_op("in", &Classification::T3, &Classification::T3));
        assert!(!compare_op(
            "not_in",
            &Classification::T3,
            &Classification::T3
        ));
    }

    // --- Phase 20: new operator tests ---

    #[test]
    fn test_compare_op_classification_gt() {
        // T3 > T2 is true (ordinal: 3 > 2)
        assert!(compare_op_classification(
            "gt",
            &Classification::T3,
            &Classification::T2
        ));
        // T4 > T1 is true (ordinal: 4 > 1)
        assert!(compare_op_classification(
            "gt",
            &Classification::T4,
            &Classification::T1
        ));
        // T1 > T4 is false (ordinal: 1 > 4 is false — highest boundary, per D-01)
        assert!(!compare_op_classification(
            "gt",
            &Classification::T1,
            &Classification::T4
        ));
        // T3 > T3 is false (same tier)
        assert!(!compare_op_classification(
            "gt",
            &Classification::T3,
            &Classification::T3
        ));
    }

    #[test]
    fn test_compare_op_classification_lt() {
        // T1 < T2 is true (ordinal: 1 < 2)
        assert!(compare_op_classification(
            "lt",
            &Classification::T1,
            &Classification::T2
        ));
        // T2 < T4 is true (ordinal: 2 < 4)
        assert!(compare_op_classification(
            "lt",
            &Classification::T2,
            &Classification::T4
        ));
        // T4 < T1 is false (ordinal: 4 < 1 is false — highest boundary, per D-01)
        assert!(!compare_op_classification(
            "lt",
            &Classification::T4,
            &Classification::T1
        ));
        // T2 < T2 is false (same tier)
        assert!(!compare_op_classification(
            "lt",
            &Classification::T2,
            &Classification::T2
        ));
    }

    #[test]
    fn test_compare_op_classification_boundary() {
        // Per D-01: T1 is lowest, T4 is highest. These are the boundary assertions.
        assert!(!compare_op_classification(
            "gt",
            &Classification::T1,
            &Classification::T4
        ));
        assert!(compare_op_classification(
            "gt",
            &Classification::T4,
            &Classification::T1
        ));
        assert!(!compare_op_classification(
            "lt",
            &Classification::T4,
            &Classification::T1
        ));
        assert!(compare_op_classification(
            "lt",
            &Classification::T1,
            &Classification::T4
        ));
    }

    #[test]
    fn test_memberof_matches_contains() {
        // Substring anywhere in the SID matches (case-sensitive, per D-05).
        assert!(memberof_matches(
            "contains",
            "S-1-5-21-123",
            &[
                "S-1-5-21-123-512".to_string(),
                "S-1-5-21-123-513".to_string()
            ]
        ));
        // Partial prefix also matches.
        assert!(memberof_matches(
            "contains",
            "512",
            &["S-1-5-21-123-512".to_string()]
        ));
    }

    #[test]
    fn test_memberof_matches_contains_no_match() {
        // Substring absent from all SIDs returns false.
        assert!(!memberof_matches(
            "contains",
            "S-1-5-21-999",
            &[
                "S-1-5-21-123-512".to_string(),
                "S-1-5-21-123-513".to_string()
            ]
        ));
        // Case-sensitive: lowercase does NOT match uppercase SID prefix.
        assert!(!memberof_matches(
            "contains",
            "s-1-5-21-123",
            &["S-1-5-21-123-512".to_string()]
        ));
    }

    #[test]
    fn test_memberof_matches_neq() {
        // "neq" for MemberOf: matches if NO group equals target.
        assert!(memberof_matches(
            "neq",
            "S-1-5-21-123-512",
            &["S-1-5-21-123-513".to_string()]
        ));
        assert!(!memberof_matches(
            "neq",
            "S-1-5-21-123-512",
            &["S-1-5-21-123-512".to_string()]
        ));
    }

    #[test]
    fn test_first_match_wins_priority_order() {
        // First policy (lower priority) matches, returns ALLOW
        let p1 = Policy {
            id: "p1".to_string(),
            name: "low priority allow".to_string(),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::Classification {
                op: "eq".to_string(),
                value: Classification::T3,
            }],
            action: Decision::ALLOW,
            enabled: true,
            mode: PolicyMode::ALL,
            version: 1,
        };
        let p2 = Policy {
            id: "p2".to_string(),
            name: "high priority deny".to_string(),
            description: None,
            priority: 10,
            conditions: vec![PolicyCondition::Classification {
                op: "eq".to_string(),
                value: Classification::T3,
            }],
            action: Decision::DENY,
            enabled: true,
            mode: PolicyMode::ALL,
            version: 1,
        };
        let store = PolicyStore {
            cache: RwLock::new(vec![p1, p2]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        let resp = store.evaluate(&make_request(Classification::T3));
        assert_eq!(resp.decision, Decision::ALLOW);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("p1"));
    }

    // ---- Classification condition matching ----

    #[test]
    fn test_classification_eq_match() {
        let store = PolicyStore {
            cache: RwLock::new(vec![Policy {
                id: "p1".to_string(),
                name: "p1".to_string(),
                description: None,
                priority: 1,
                conditions: vec![PolicyCondition::Classification {
                    op: "eq".to_string(),
                    value: Classification::T3,
                }],
                action: Decision::DENY,
                enabled: true,
                mode: PolicyMode::ALL,
                version: 1,
            }]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        let resp = store.evaluate(&make_request(Classification::T3));
        assert_eq!(resp.decision, Decision::DENY);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("p1"));
    }

    #[test]
    fn test_classification_eq_no_match() {
        let store = PolicyStore {
            cache: RwLock::new(vec![Policy {
                id: "p1".to_string(),
                name: "p1".to_string(),
                description: None,
                priority: 1,
                conditions: vec![PolicyCondition::Classification {
                    op: "eq".to_string(),
                    value: Classification::T3,
                }],
                action: Decision::DENY,
                enabled: true,
                mode: PolicyMode::ALL,
                version: 1,
            }]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        // T1 request does NOT match T3 policy → default-allow (T1)
        let resp = store.evaluate(&make_request(Classification::T1));
        assert_eq!(resp.decision, Decision::ALLOW);
        assert!(resp.matched_policy_id.is_none());
    }

    #[test]
    fn test_classification_neq_match() {
        let store = PolicyStore {
            cache: RwLock::new(vec![Policy {
                id: "p1".to_string(),
                name: "p1".to_string(),
                description: None,
                priority: 1,
                conditions: vec![PolicyCondition::Classification {
                    op: "neq".to_string(),
                    value: Classification::T4,
                }],
                action: Decision::ALLOW,
                enabled: true,
                mode: PolicyMode::ALL,
                version: 1,
            }]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        // T1 is not T4 → policy matches
        let resp = store.evaluate(&make_request(Classification::T1));
        assert_eq!(resp.decision, Decision::ALLOW);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("p1"));
    }

    // ---- MemberOf condition matching ----

    #[test]
    fn test_memberof_in_match() {
        let store = PolicyStore {
            cache: RwLock::new(vec![Policy {
                id: "p1".to_string(),
                name: "p1".to_string(),
                description: None,
                priority: 1,
                conditions: vec![PolicyCondition::MemberOf {
                    op: "in".to_string(),
                    group_sid: "S-1-5-21-123-512".to_string(),
                }],
                action: Decision::DENY,
                enabled: true,
                mode: PolicyMode::ALL,
                version: 1,
            }]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        let request = make_request(Classification::T3);
        let resp = store.evaluate(&request);
        assert_eq!(resp.decision, Decision::DENY);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("p1"));
    }

    #[test]
    fn test_memberof_in_no_match() {
        let store = PolicyStore {
            cache: RwLock::new(vec![Policy {
                id: "p1".to_string(),
                name: "p1".to_string(),
                description: None,
                priority: 1,
                conditions: vec![PolicyCondition::MemberOf {
                    op: "in".to_string(),
                    group_sid: "S-1-5-21-999".to_string(),
                }],
                action: Decision::DENY,
                enabled: true,
                mode: PolicyMode::ALL,
                version: 1,
            }]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        let request = make_request(Classification::T3);
        let resp = store.evaluate(&request);
        // No matching policy, T3 → default-deny
        assert_eq!(resp.decision, Decision::DENY);
        assert!(resp.matched_policy_id.is_none());
    }

    #[test]
    fn test_memberof_not_in_match() {
        let store = PolicyStore {
            cache: RwLock::new(vec![Policy {
                id: "p1".to_string(),
                name: "p1".to_string(),
                description: None,
                priority: 1,
                conditions: vec![PolicyCondition::MemberOf {
                    op: "not_in".to_string(),
                    group_sid: "S-1-5-21-512".to_string(),
                }],
                action: Decision::ALLOW,
                enabled: true,
                mode: PolicyMode::ALL,
                version: 1,
            }]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        // Subject groups do NOT include S-1-5-21-512 → policy matches
        let request = make_request(Classification::T2);
        let resp = store.evaluate(&request);
        assert_eq!(resp.decision, Decision::ALLOW);
    }

    // ---- DeviceTrust / NetworkLocation / AccessContext conditions ----

    #[test]
    fn test_device_trust_match() {
        let store = PolicyStore {
            cache: RwLock::new(vec![Policy {
                id: "p1".to_string(),
                name: "p1".to_string(),
                description: None,
                priority: 1,
                conditions: vec![PolicyCondition::DeviceTrust {
                    op: "eq".to_string(),
                    value: DeviceTrust::Managed,
                }],
                action: Decision::ALLOW,
                enabled: true,
                mode: PolicyMode::ALL,
                version: 1,
            }]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        let resp = store.evaluate(&make_request(Classification::T2));
        assert_eq!(resp.decision, Decision::ALLOW);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("p1"));
    }

    #[test]
    fn test_network_location_match() {
        let store = PolicyStore {
            cache: RwLock::new(vec![Policy {
                id: "p1".to_string(),
                name: "p1".to_string(),
                description: None,
                priority: 1,
                conditions: vec![PolicyCondition::NetworkLocation {
                    op: "eq".to_string(),
                    value: NetworkLocation::Corporate,
                }],
                action: Decision::DENY,
                enabled: true,
                mode: PolicyMode::ALL,
                version: 1,
            }]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        let resp = store.evaluate(&make_request(Classification::T3));
        assert_eq!(resp.decision, Decision::DENY);
    }

    #[test]
    fn test_access_context_match() {
        let store = PolicyStore {
            cache: RwLock::new(vec![Policy {
                id: "p1".to_string(),
                name: "p1".to_string(),
                description: None,
                priority: 1,
                conditions: vec![PolicyCondition::AccessContext {
                    op: "eq".to_string(),
                    value: AccessContext::Smb,
                }],
                action: Decision::DENY,
                enabled: true,
                mode: PolicyMode::ALL,
                version: 1,
            }]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        let resp = store.evaluate(&make_request(Classification::T3));
        assert_eq!(resp.decision, Decision::DENY);
    }

    // ---- "in"/"not_in" on scalar conditions returns false ----

    #[test]
    fn test_in_op_on_classification_is_false() {
        let store = PolicyStore {
            cache: RwLock::new(vec![Policy {
                id: "p1".to_string(),
                name: "p1".to_string(),
                description: None,
                priority: 1,
                conditions: vec![PolicyCondition::Classification {
                    op: "in".to_string(),
                    value: Classification::T3,
                }],
                action: Decision::DENY,
                enabled: true,
                mode: PolicyMode::ALL,
                version: 1,
            }]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        let resp = store.evaluate(&make_request(Classification::T3));
        // "in" on Classification is not applicable → policy does not match → default-deny (T3)
        assert_eq!(resp.decision, Decision::DENY);
        assert!(resp.matched_policy_id.is_none());
    }

    // ---- refresh / invalidate reloads cache from DB ----

    #[test]
    fn test_invalidate_reloads_cache() {
        // NamedTempFile-backed pool so connections share the same persistent DB.
        // Using :memory: would isolate connections — each get() sees an empty DB,
        // causing invalidate() to silently reload zero policies (false-positive pass).
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(
            crate::db::new_pool(tmp.path().to_str().unwrap()).expect("pool from temp file"),
        );
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        assert_eq!(store.list_policies().len(), 0);

        // Insert a policy directly into the DB then invalidate.
        {
            let conn = pool.get().unwrap();
            conn.execute(
                "INSERT INTO policies (id, name, priority, conditions, action, enabled, version, updated_at) \
                 VALUES ('initial', 'initial', 1, '[]', 'Allow', 1, 1, '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }
        store.invalidate();
        assert_eq!(store.list_policies().len(), 1);

        // Insert another policy then invalidate.
        {
            let conn = pool.get().unwrap();
            conn.execute(
                "INSERT INTO policies (id, name, priority, conditions, action, enabled, version, updated_at) \
                 VALUES ('second', 'second', 2, '[]', 'Deny', 1, 1, '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }
        store.invalidate();
        assert_eq!(store.list_policies().len(), 2);
    }

    #[test]
    fn test_refresh_reloads_cache() {
        // NamedTempFile-backed pool — same rationale as test_invalidate_reloads_cache.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(
            crate::db::new_pool(tmp.path().to_str().unwrap()).expect("pool from temp file"),
        );
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        assert_eq!(store.list_policies().len(), 0);

        // Insert policies directly into the DB then refresh.
        {
            let conn = pool.get().unwrap();
            conn.execute(
                "INSERT INTO policies (id, name, priority, conditions, action, enabled, version, updated_at) \
                 VALUES ('first', 'first', 1, '[]', 'Allow', 1, 1, '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }
        store.refresh();
        assert_eq!(store.list_policies().len(), 1);

        {
            let conn = pool.get().unwrap();
            conn.execute(
                "INSERT INTO policies (id, name, priority, conditions, action, enabled, version, updated_at) \
                 VALUES ('second', 'second', 2, '[]', 'Deny', 1, 1, '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }
        store.refresh();
        assert_eq!(store.list_policies().len(), 2);
    }

    // ---- Boolean mode tests (POLICY-12) ----

    #[test]
    fn test_evaluate_all_mode_all_conditions_match() {
        let policy = Policy {
            id: "mode-all".to_string(),
            name: "mode all".to_string(),
            description: None,
            priority: 1,
            conditions: vec![
                PolicyCondition::Classification {
                    op: "eq".to_string(),
                    value: Classification::T3,
                },
                PolicyCondition::DeviceTrust {
                    op: "eq".to_string(),
                    value: DeviceTrust::Managed,
                },
            ],
            action: Decision::DENY,
            enabled: true,
            mode: PolicyMode::ALL,
            version: 1,
        };
        let store = PolicyStore {
            cache: RwLock::new(vec![policy]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        let resp = store.evaluate(&make_request(Classification::T3));
        assert_eq!(resp.decision, Decision::DENY);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("mode-all"));
    }

    #[test]
    fn test_evaluate_all_mode_one_condition_misses() {
        let policy = Policy {
            id: "mode-all".to_string(),
            name: "mode all".to_string(),
            description: None,
            priority: 1,
            conditions: vec![
                PolicyCondition::Classification {
                    op: "eq".to_string(),
                    value: Classification::T3,
                },
                PolicyCondition::DeviceTrust {
                    op: "eq".to_string(),
                    value: DeviceTrust::Managed,
                },
            ],
            action: Decision::DENY,
            enabled: true,
            mode: PolicyMode::ALL,
            version: 1,
        };
        let store = PolicyStore {
            cache: RwLock::new(vec![policy]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        // T1 + Managed → Classification misses → falls through to default-allow (T1)
        let resp = store.evaluate(&make_request(Classification::T1));
        assert_eq!(resp.decision, Decision::ALLOW);
        assert!(resp.matched_policy_id.is_none());
    }

    #[test]
    fn test_evaluate_any_mode_one_condition_matches() {
        let policy = Policy {
            id: "mode-any".to_string(),
            name: "mode any".to_string(),
            description: None,
            priority: 1,
            conditions: vec![
                PolicyCondition::Classification {
                    op: "eq".to_string(),
                    value: Classification::T3,
                },
                PolicyCondition::DeviceTrust {
                    op: "eq".to_string(),
                    value: DeviceTrust::Managed,
                },
            ],
            action: Decision::DENY,
            enabled: true,
            mode: PolicyMode::ANY,
            version: 1,
        };
        let store = PolicyStore {
            cache: RwLock::new(vec![policy]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        // T1 + Managed → Classification misses but DeviceTrust matches → policy hits
        let resp = store.evaluate(&make_request(Classification::T1));
        assert_eq!(resp.decision, Decision::DENY);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("mode-any"));
    }

    #[test]
    fn test_evaluate_any_mode_no_condition_matches() {
        let policy = Policy {
            id: "mode-any".to_string(),
            name: "mode any".to_string(),
            description: None,
            priority: 1,
            conditions: vec![
                PolicyCondition::Classification {
                    op: "eq".to_string(),
                    value: Classification::T3,
                },
                PolicyCondition::DeviceTrust {
                    op: "eq".to_string(),
                    value: DeviceTrust::Unmanaged,
                },
            ],
            action: Decision::DENY,
            enabled: true,
            mode: PolicyMode::ANY,
            version: 1,
        };
        let store = PolicyStore {
            cache: RwLock::new(vec![policy]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        // T1 + Managed (subject default) → neither condition matches → default-allow (T1)
        let resp = store.evaluate(&make_request(Classification::T1));
        assert_eq!(resp.decision, Decision::ALLOW);
        assert!(resp.matched_policy_id.is_none());
    }

    #[test]
    fn test_evaluate_none_mode_no_condition_matches() {
        let policy = Policy {
            id: "mode-none".to_string(),
            name: "mode none".to_string(),
            description: None,
            priority: 1,
            conditions: vec![
                PolicyCondition::Classification {
                    op: "eq".to_string(),
                    value: Classification::T3,
                },
                PolicyCondition::DeviceTrust {
                    op: "eq".to_string(),
                    value: DeviceTrust::Unmanaged,
                },
            ],
            action: Decision::ALLOW,
            enabled: true,
            mode: PolicyMode::NONE,
            version: 1,
        };
        let store = PolicyStore {
            cache: RwLock::new(vec![policy]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        // T1 + Managed (subject) → neither condition matches → policy hits
        let resp = store.evaluate(&make_request(Classification::T1));
        assert_eq!(resp.decision, Decision::ALLOW);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("mode-none"));
    }

    #[test]
    fn test_evaluate_none_mode_one_condition_matches() {
        let policy = Policy {
            id: "mode-none".to_string(),
            name: "mode none".to_string(),
            description: None,
            priority: 1,
            conditions: vec![
                PolicyCondition::Classification {
                    op: "eq".to_string(),
                    value: Classification::T3,
                },
                PolicyCondition::DeviceTrust {
                    op: "eq".to_string(),
                    value: DeviceTrust::Unmanaged,
                },
            ],
            action: Decision::ALLOW,
            enabled: true,
            mode: PolicyMode::NONE,
            version: 1,
        };
        let store = PolicyStore {
            cache: RwLock::new(vec![policy]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        // T3 + Managed → Classification matches → policy misses → default-deny (T3)
        let resp = store.evaluate(&make_request(Classification::T3));
        assert_eq!(resp.decision, Decision::DENY);
        assert!(resp.matched_policy_id.is_none());
    }

    // ---- Empty-conditions edge cases (D-13) ----

    #[test]
    fn test_evaluate_empty_conditions_all_mode_matches() {
        // ALL + []: vacuous truth — matches unconditionally.
        let policy = Policy {
            id: "empty-all".to_string(),
            name: "empty all".to_string(),
            description: None,
            priority: 1,
            conditions: vec![],
            action: Decision::DENY,
            enabled: true,
            mode: PolicyMode::ALL,
            version: 1,
        };
        let store = PolicyStore {
            cache: RwLock::new(vec![policy]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        let resp = store.evaluate(&make_request(Classification::T1));
        assert_eq!(resp.decision, Decision::DENY);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("empty-all"));
    }

    #[test]
    fn test_evaluate_empty_conditions_any_mode_does_not_match() {
        // ANY + []: zero conditions can ever be satisfied → never matches.
        let policy = Policy {
            id: "empty-any".to_string(),
            name: "empty any".to_string(),
            description: None,
            priority: 1,
            conditions: vec![],
            action: Decision::DENY,
            enabled: true,
            mode: PolicyMode::ANY,
            version: 1,
        };
        let store = PolicyStore {
            cache: RwLock::new(vec![policy]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        // Falls through to default-deny (T4)
        let resp = store.evaluate(&make_request(Classification::T4));
        assert_eq!(resp.decision, Decision::DENY);
        assert!(resp.matched_policy_id.is_none());
    }

    #[test]
    fn test_evaluate_empty_conditions_none_mode_matches() {
        // NONE + []: zero conditions are satisfied (vacuously true) → matches unconditionally.
        let policy = Policy {
            id: "empty-none".to_string(),
            name: "empty none".to_string(),
            description: None,
            priority: 1,
            conditions: vec![],
            action: Decision::ALLOW,
            enabled: true,
            mode: PolicyMode::NONE,
            version: 1,
        };
        let store = PolicyStore {
            cache: RwLock::new(vec![policy]),
            pool: Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool")),
        };
        let resp = store.evaluate(&make_request(Classification::T1));
        assert_eq!(resp.decision, Decision::ALLOW);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("empty-none"));
    }

    // ---- SourceApplication / DestinationApplication condition tests (Phase 26) ----

    /// Builds a minimal AbacContext with the given classification and app identities.
    fn make_ctx_with_apps(
        classification: Classification,
        source_app: Option<dlp_common::endpoint::AppIdentity>,
        dest_app: Option<dlp_common::endpoint::AppIdentity>,
    ) -> AbacContext {
        use dlp_common::endpoint::{AppTrustTier, SignatureState};
        let _ = (AppTrustTier::Trusted, SignatureState::Valid); // ensure types are in scope
        EvaluateRequest {
            subject: Subject {
                user_sid: "S-1-5-21-123".to_string(),
                user_name: "testuser".to_string(),
                groups: vec!["S-1-5-21-123-512".to_string()],
                device_trust: DeviceTrust::Managed,
                network_location: NetworkLocation::Corporate,
            },
            resource: dlp_common::abac::Resource {
                path: r"C:\Data\test.txt".to_string(),
                classification,
            },
            environment: dlp_common::abac::Environment {
                timestamp: chrono::Utc::now(),
                session_id: 1,
                access_context: AccessContext::Local,
            },
            action: dlp_common::abac::Action::COPY,
            agent: None,
            source_application: source_app,
            destination_application: dest_app,
        }
        .into()
    }

    fn make_app_identity(
        publisher: &str,
        image_path: &str,
        trusted: bool,
    ) -> dlp_common::endpoint::AppIdentity {
        use dlp_common::endpoint::{AppTrustTier, SignatureState};
        dlp_common::endpoint::AppIdentity {
            publisher: publisher.to_string(),
            image_path: image_path.to_string(),
            trust_tier: if trusted {
                AppTrustTier::Trusted
            } else {
                AppTrustTier::Untrusted
            },
            signature_state: SignatureState::Valid,
        }
    }

    #[test]
    fn test_source_app_publisher_eq_matches() {
        let microsoft_app = make_app_identity("Microsoft", r"C:\Windows\notepad.exe", true);
        let ctx = make_ctx_with_apps(Classification::T3, Some(microsoft_app), None);
        let condition = PolicyCondition::SourceApplication {
            field: AppField::Publisher,
            op: "eq".to_string(),
            value: "Microsoft".to_string(),
        };
        assert!(condition_matches(&condition, &ctx));
    }

    #[test]
    fn test_source_app_publisher_eq_none_fails_closed() {
        // D-03: None identity must NOT match even with eq operator.
        let ctx = make_ctx_with_apps(Classification::T3, None, None);
        let condition = PolicyCondition::SourceApplication {
            field: AppField::Publisher,
            op: "eq".to_string(),
            value: "Microsoft".to_string(),
        };
        assert!(!condition_matches(&condition, &ctx));
    }

    #[test]
    fn test_source_app_image_path_contains_matches() {
        let app = make_app_identity("Microsoft", r"C:\Program Files\App\app.exe", true);
        let ctx = make_ctx_with_apps(Classification::T3, Some(app), None);
        let condition = PolicyCondition::SourceApplication {
            field: AppField::ImagePath,
            op: "contains".to_string(),
            value: "Program Files".to_string(),
        };
        assert!(condition_matches(&condition, &ctx));
    }

    #[test]
    fn test_source_app_trust_tier_eq_trusted_matches() {
        let app = make_app_identity("Microsoft", r"C:\Windows\notepad.exe", true);
        let ctx = make_ctx_with_apps(Classification::T3, Some(app), None);
        let condition = PolicyCondition::SourceApplication {
            field: AppField::TrustTier,
            op: "eq".to_string(),
            value: "trusted".to_string(),
        };
        assert!(condition_matches(&condition, &ctx));
    }

    #[test]
    fn test_dest_app_trust_tier_ne_trusted_matches() {
        use dlp_common::endpoint::{AppTrustTier, SignatureState};
        let untrusted_dest = dlp_common::endpoint::AppIdentity {
            publisher: "Unknown".to_string(),
            image_path: r"C:\Temp\bad.exe".to_string(),
            trust_tier: AppTrustTier::Untrusted,
            signature_state: SignatureState::NotSigned,
        };
        let ctx = make_ctx_with_apps(Classification::T3, None, Some(untrusted_dest));
        let condition = PolicyCondition::DestinationApplication {
            field: AppField::TrustTier,
            op: "ne".to_string(),
            value: "trusted".to_string(),
        };
        assert!(condition_matches(&condition, &ctx));
    }

    #[test]
    fn test_dest_app_none_fails_closed() {
        // D-03: None destination identity must NOT match.
        let ctx = make_ctx_with_apps(Classification::T3, None, None);
        let condition = PolicyCondition::DestinationApplication {
            field: AppField::TrustTier,
            op: "ne".to_string(),
            value: "trusted".to_string(),
        };
        assert!(!condition_matches(&condition, &ctx));
    }

    // ---- Legacy v0.4.0 payload parity (D-25) ----

    #[test]
    fn test_legacy_v040_policy_without_mode_behaves_like_all() {
        // POLICY-12: A v0.4.0-shaped Policy (mode field defaulted via Default)
        // produces the same EvaluateResponse as an explicit PolicyMode::ALL policy.
        let conditions = vec![
            PolicyCondition::Classification {
                op: "eq".to_string(),
                value: Classification::T3,
            },
            PolicyCondition::DeviceTrust {
                op: "eq".to_string(),
                value: DeviceTrust::Managed,
            },
            PolicyCondition::NetworkLocation {
                op: "eq".to_string(),
                value: NetworkLocation::Corporate,
            },
        ];

        let policy_v040 = Policy {
            id: "v040-policy".to_string(),
            name: "v0.4.0 policy".to_string(),
            description: None,
            priority: 1,
            conditions: conditions.clone(),
            action: Decision::DENY,
            enabled: true,
            version: 1,
            // mode field defaulted — Policy::default() gives PolicyMode::ALL
            ..Default::default()
        };

        let policy_explicit_all = Policy {
            id: "explicit-all".to_string(),
            name: "explicit all".to_string(),
            description: None,
            priority: 1,
            conditions,
            action: Decision::DENY,
            enabled: true,
            mode: PolicyMode::ALL,
            version: 1,
        };

        let pool = Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool"));

        let store_v040 = PolicyStore {
            cache: RwLock::new(vec![policy_v040]),
            pool: Arc::clone(&pool),
        };
        let store_explicit = PolicyStore {
            cache: RwLock::new(vec![policy_explicit_all]),
            pool: Arc::clone(&pool),
        };

        let req = make_request(Classification::T3);
        let resp_v040 = store_v040.evaluate(&req);
        let resp_explicit = store_explicit.evaluate(&req);

        assert_eq!(resp_v040.decision, resp_explicit.decision);
        // matched_policy_id differs by id but both must be Some(_)
        assert!(resp_v040.matched_policy_id.is_some());
        assert!(resp_explicit.matched_policy_id.is_some());
    }
}
