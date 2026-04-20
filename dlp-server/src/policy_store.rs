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

use dlp_common::abac::{Decision, EvaluateRequest, EvaluateResponse, Policy, PolicyCondition, PolicyMode};
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

    /// Evaluates `request` against the cached policy set.
    ///
    /// Returns a decision for the first enabled policy whose conditions all
    /// match. If no policy matches, applies tiered default-deny (D-01):
    /// - T1 / T2 → `Decision::ALLOW`
    /// - T3 / T4 → `Decision::DENY`
    ///
    /// This is the **hot path** — it acquires only a read lock on the cache.
    pub fn evaluate(&self, request: &EvaluateRequest) -> EvaluateResponse {
        let cache = self.cache.read();

        for policy in cache.iter() {
            if !policy.enabled {
                continue;
            }
            if policy
                .conditions
                .iter()
                .all(|c| condition_matches(c, request))
            {
                return EvaluateResponse {
                    decision: policy.action,
                    matched_policy_id: Some(policy.id.clone()),
                    reason: format!("matched policy '{}'", policy.name),
                };
            }
        }

        // No policy matched — tiered default-deny (D-01).
        match request.resource.classification {
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
                    warn!(policy_id = %row.id, error = %e, "skipped policy with malformed conditions");
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
        _ => PolicyMode::ALL,
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

/// Evaluates a single condition against an evaluation request.
///
/// Returns `true` if the condition matches, `false` otherwise.
/// Operators `"in"` and `"not_in"` on non-MemberOf conditions return `false`
/// defensively (they only apply to group membership checks).
fn condition_matches(condition: &PolicyCondition, request: &EvaluateRequest) -> bool {
    match condition {
        PolicyCondition::Classification { op, value } => {
            compare_op(op, &request.resource.classification, value)
        }
        PolicyCondition::MemberOf { op, group_sid } => {
            memberof_matches(op, group_sid, &request.subject.groups)
        }
        PolicyCondition::DeviceTrust { op, value } => {
            compare_op(op, &request.subject.device_trust, value)
        }
        PolicyCondition::NetworkLocation { op, value } => {
            compare_op(op, &request.subject.network_location, value)
        }
        PolicyCondition::AccessContext { op, value } => {
            compare_op(op, &request.environment.access_context, value)
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

/// Evaluates a MemberOf condition against the subject's group SID list.
///
/// - `"in"`: matches if ANY group SID in `subject_groups` equals `group_sid`
/// - `"not_in"`: matches if NO group SID in `subject_groups` equals `group_sid`
/// - `"eq"` / `"neq"`: delegates to `compare_op` (single-value semantics)
fn memberof_matches(op: &str, target_sid: &str, subject_groups: &[String]) -> bool {
    match op {
        "in" => subject_groups.iter().any(|sid| sid == target_sid),
        "not_in" => subject_groups.iter().all(|sid| sid != target_sid),
        // Fall back to scalar semantics for eq/neq (treat as single-element list).
        "eq" => subject_groups.iter().any(|sid| sid == target_sid),
        "neq" => subject_groups.iter().all(|sid| sid != target_sid),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::abac::{AccessContext, DeviceTrust, NetworkLocation, Subject};

    /// Helper to build a minimal EvaluateRequest with the given classification tier.
    fn make_request(classification: Classification) -> EvaluateRequest {
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
        }
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
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("pool from temp file"));
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
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("pool from temp file"));
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
}
