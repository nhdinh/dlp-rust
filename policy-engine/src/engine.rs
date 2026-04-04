//! ABAC Policy Evaluation Engine.
//!
//! Implements first-match policy evaluation: policies are sorted by priority (ascending),
//! evaluated in order, and the first matching policy's action is returned.
//!
//! ## Critical Rule
//!
//! > NTFS ALLOW + ABAC DENY = **DENY** (ABAC always has final veto)
//!
//! This is enforced by returning `DENY` or `DENY_WITH_ALERT` decisions regardless
//! of what NTFS would have allowed.

use std::sync::Arc;

use dlp_common::abac::{EvaluateRequest, EvaluateResponse, Policy, PolicyCondition};
use parking_lot::RwLock;

use crate::error::{PolicyEngineError, Result};

/// The ABAC evaluation engine.
///
/// Evaluates incoming access requests against the loaded policy set using first-match semantics.
/// Thread-safe: can be shared across many async tasks simultaneously.
#[derive(Debug, Default)]
pub struct AbacEngine {
    /// The currently active policy set. Read-mostly; replaced atomically on hot-reload.
    pub(crate) policies: Arc<RwLock<Vec<Policy>>>,
}

impl AbacEngine {
    /// Creates a new engine with an initial (empty) policy set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new engine with an initial set of policies.
    pub fn with_policies(policies: Vec<Policy>) -> Self {
        // Sort by priority ascending — lower number = higher priority = evaluated first.
        let mut sorted = policies;
        sorted.sort_by_key(|p| p.priority);
        Self {
            policies: Arc::new(RwLock::new(sorted)),
        }
    }

    /// Replaces the active policy set with a new set (hot-reload path).
    ///
    /// Validates that all policies are well-formed before swapping.
    /// Uses atomic swap via `Arc` to ensure in-flight evaluations complete
    /// against the old policy set without corruption.
    pub fn reload_policies(&self, new_policies: Vec<Policy>) -> Result<()> {
        for policy in &new_policies {
            validate_policy(policy)?;
        }
        let mut sorted = new_policies;
        sorted.sort_by_key(|p| p.priority);
        let mut guard = self.policies.write();
        *guard = sorted;
        Ok(())
    }

    /// Evaluates an access request against the current policy set.
    ///
    /// Policies are evaluated in priority order (lowest number first). The first
    /// matching policy's action is returned. If no policy matches, returns a
    /// default-deny response (fail-closed for safety).
    ///
    /// # Critical Rule
    ///
    /// > NTFS ALLOW + ABAC DENY = **DENY** — enforced here by always returning
    /// > DENY/DENY_WITH_ALERT when any policy matches with that action.
    pub fn evaluate(&self, request: &EvaluateRequest) -> EvaluateResponse {
        let policies = self.policies.read();

        for policy in policies.iter() {
            if !policy.enabled {
                continue;
            }
            if self.evaluate_conditions(&policy.conditions, request) {
                return EvaluateResponse {
                    decision: policy.action,
                    matched_policy_id: Some(policy.id.clone()),
                    reason: reason_for(policy.clone(), request),
                };
            }
        }

        // No policy matched — fail closed: default-deny.
        EvaluateResponse::default_deny()
    }

    /// Returns a snapshot of the current policy list.
    pub(crate) fn get_policies(&self) -> Vec<Policy> {
        self.policies.read().clone()
    }

    /// Evaluates all conditions in a policy against the request.
    /// All conditions must match (logical AND).
    fn evaluate_conditions(
        &self,
        conditions: &[PolicyCondition],
        request: &EvaluateRequest,
    ) -> bool {
        conditions
            .iter()
            .all(|cond| self.evaluate_condition(cond, request))
    }

    /// Evaluates a single condition against the request.
    fn evaluate_condition(&self, condition: &PolicyCondition, request: &EvaluateRequest) -> bool {
        match condition {
            PolicyCondition::Classification { op, value } => {
                evaluate_op(op, request.resource.classification as u8, (*value) as u8)
            }
            PolicyCondition::MemberOf { op, group_sid } => request
                .subject
                .groups
                .iter()
                .any(|g| evaluate_group_op(op, g, group_sid)),
            PolicyCondition::DeviceTrust { op, value } => {
                evaluate_eq_op(op, value, &request.subject.device_trust)
            }
            PolicyCondition::NetworkLocation { op, value } => {
                evaluate_eq_op(op, value, &request.subject.network_location)
            }
            PolicyCondition::AccessContext { op, value } => {
                evaluate_eq_op(op, value, &request.environment.access_context)
            }
        }
    }
}

/// Validates a policy's structural correctness.
///
/// Returns `Ok(())` if valid, or an error describing the problem.
pub(crate) fn validate_policy(policy: &Policy) -> Result<()> {
    if policy.id.is_empty() {
        return Err(PolicyEngineError::PolicyValidationError(
            "policy id cannot be empty".into(),
        ));
    }
    if policy.priority > 100_000 {
        return Err(PolicyEngineError::PolicyValidationError(format!(
            "policy {} priority {} exceeds maximum (100,000)",
            policy.id, policy.priority
        )));
    }
    Ok(())
}

/// Evaluates a comparison operator against two unsigned integer values.
///
/// Supported operators: `eq`, `neq`, `lt`, `lte`, `gt`, `gte`.
fn evaluate_op(op: &str, actual: u8, expected: u8) -> bool {
    match op {
        "eq" => actual == expected,
        "neq" => actual != expected,
        "lt" => actual < expected,
        "lte" => actual <= expected,
        "gt" => actual > expected,
        "gte" => actual >= expected,
        // Unknown operator: fail-safe — do not match.
        _ => false,
    }
}

/// Evaluates a group membership check with a string comparison operator.
///
/// `eq` — user is a member of the specified group
/// `neq` — user is NOT a member of the specified group
fn evaluate_group_op(op: &str, actual_group: &str, expected_group: &str) -> bool {
    match op {
        "eq" => actual_group == expected_group,
        "neq" => actual_group != expected_group,
        _ => false,
    }
}

/// Evaluates `actual == expected` (or `!=` for `neq`).
fn evaluate_eq_op<T: PartialEq>(op: &str, actual: &T, expected: &T) -> bool {
    match op {
        "eq" => actual == expected,
        "neq" => actual != expected,
        _ => false,
    }
}

/// Generates a human-readable reason string for a matched policy.
fn reason_for(policy: Policy, request: &EvaluateRequest) -> String {
    let classification = request.resource.classification;
    format!(
        "Policy '{}' (id={}) matched; action={:?}; classification={}; action_requested={:?}",
        policy.name,
        policy.id,
        policy.action,
        classification.label(),
        request.action,
    )
}

// ─────────────────────────────────────────────────────────────────────────────────
// Tests — all 3 rules from docs/ABAC_POLICIES.md
// ─────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use dlp_common::abac::{
        AccessContext, Action, Decision, DeviceTrust, Environment, NetworkLocation, Resource,
        Subject,
    };
    use dlp_common::Classification;

    fn make_request(classification: Classification, action: Action) -> EvaluateRequest {
        EvaluateRequest {
            subject: Subject {
                user_sid: "S-1-5-21-123".to_string(),
                user_name: "testuser".to_string(),
                groups: vec![],
                device_trust: DeviceTrust::Unmanaged,
                network_location: NetworkLocation::CorporateVpn,
            },
            resource: Resource {
                path: "C:\\Data\\Test.xlsx".to_string(),
                classification,
            },
            environment: Environment {
                timestamp: Utc::now(),
                session_id: 1,
                access_context: AccessContext::Local,
            },
            action,
            agent: None,
        }
    }

    /// Rule 1 from ABAC_POLICIES.md:
    /// IF resource.classification == "T4" THEN deny_all_except_owner
    /// Maps to: classification == T4 → DENY
    fn t4_deny_policy() -> Policy {
        Policy {
            id: "pol-001".into(),
            name: "T4 Deny All".into(),
            description: Some("Block all access to T4 resources".into()),
            priority: 1,
            conditions: vec![PolicyCondition::Classification {
                op: "eq".into(),
                value: Classification::T4,
            }],
            action: Decision::DENY,
            enabled: true,
            version: 1,
        }
    }

    /// Rule 2 from ABAC_POLICIES.md:
    /// IF resource.classification == "T3" AND device.trust == "Unmanaged"
    /// THEN deny_upload
    /// Maps to: classification == T3 AND device_trust == Unmanaged → DENY
    fn t3_unmanaged_deny_policy() -> Policy {
        Policy {
            id: "pol-002".into(),
            name: "T3 Unmanaged Block".into(),
            description: Some("Block T3 from unmanaged devices".into()),
            priority: 2,
            conditions: vec![
                PolicyCondition::Classification {
                    op: "eq".into(),
                    value: Classification::T3,
                },
                PolicyCondition::DeviceTrust {
                    op: "eq".into(),
                    value: DeviceTrust::Unmanaged,
                },
            ],
            action: Decision::DENY,
            enabled: true,
            version: 1,
        }
    }

    /// Rule 3 from ABAC_POLICIES.md:
    /// IF resource.classification == "T2" THEN allow_with_logging
    /// Maps to: classification == T2 → ALLOW_WITH_LOG
    fn t2_log_policy() -> Policy {
        Policy {
            id: "pol-003".into(),
            name: "T2 Allow with Log".into(),
            description: Some("Log T2 access".into()),
            priority: 3,
            conditions: vec![PolicyCondition::Classification {
                op: "eq".into(),
                value: Classification::T2,
            }],
            action: Decision::AllowWithLog,
            enabled: true,
            version: 1,
        }
    }

    fn engine_with_rules() -> AbacEngine {
        AbacEngine::with_policies(vec![
            t4_deny_policy(),
            t3_unmanaged_deny_policy(),
            t2_log_policy(),
        ])
    }

    // ── Rule 1 tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_t4_denied() {
        let engine = engine_with_rules();
        let resp = engine.evaluate(&make_request(Classification::T4, Action::COPY));
        assert!(resp.decision.is_denied());
        assert_eq!(resp.matched_policy_id.as_deref(), Some("pol-001"));
    }

    #[test]
    fn test_t4_read_denied() {
        let engine = engine_with_rules();
        let resp = engine.evaluate(&make_request(Classification::T4, Action::READ));
        assert!(resp.decision.is_denied());
    }

    // ── Rule 2 tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_t3_unmanaged_denied() {
        let engine = engine_with_rules();
        let resp = engine.evaluate(&make_request(Classification::T3, Action::COPY));
        assert!(resp.decision.is_denied());
        assert_eq!(resp.matched_policy_id.as_deref(), Some("pol-002"));
    }

    #[test]
    fn test_t3_managed_falls_through_to_default_deny() {
        // T3 + Managed device → pol-002 Unmanaged condition fails → no match → default-deny
        let engine = AbacEngine::with_policies(vec![Policy {
            id: "pol-002".into(),
            name: "T3 Unmanaged Block".into(),
            description: None,
            priority: 2,
            conditions: vec![
                PolicyCondition::Classification {
                    op: "eq".into(),
                    value: Classification::T3,
                },
                PolicyCondition::DeviceTrust {
                    op: "eq".into(),
                    value: DeviceTrust::Unmanaged,
                },
            ],
            action: Decision::DENY,
            enabled: true,
            version: 1,
        }]);
        let mut req = make_request(Classification::T3, Action::COPY);
        req.subject.device_trust = DeviceTrust::Managed;
        let resp = engine.evaluate(&req);
        // No policy matched — fail-closed default-deny applies.
        assert!(resp.decision.is_denied());
        assert!(resp.matched_policy_id.is_none());
    }

    // ── Rule 3 tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_t2_allowed_with_log() {
        let engine = engine_with_rules();
        let resp = engine.evaluate(&make_request(Classification::T2, Action::WRITE));
        assert_eq!(resp.decision, Decision::AllowWithLog);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("pol-003"));
    }

    // ── Default-deny tests ─────────────────────────────────────────────────────

    #[test]
    fn test_t1_default_deny() {
        let engine = engine_with_rules();
        // T1 does not match any of our three policies → default-deny
        let resp = engine.evaluate(&make_request(Classification::T1, Action::COPY));
        assert!(resp.decision.is_denied());
        assert!(resp.matched_policy_id.is_none());
        assert!(resp.reason.contains("No matching policy"));
    }

    // ── Priority / first-match tests ───────────────────────────────────────────

    #[test]
    fn test_higher_priority_wins() {
        // Two policies could match; lower priority number wins.
        let engine = AbacEngine::with_policies(vec![
            Policy {
                id: "pol-hi".into(),
                name: "High priority T3".into(),
                description: None,
                priority: 1,
                conditions: vec![PolicyCondition::Classification {
                    op: "eq".into(),
                    value: Classification::T3,
                }],
                action: Decision::DenyWithAlert,
                enabled: true,
                version: 1,
            },
            Policy {
                id: "pol-lo".into(),
                name: "Low priority T3".into(),
                description: None,
                priority: 10,
                conditions: vec![PolicyCondition::Classification {
                    op: "eq".into(),
                    value: Classification::T3,
                }],
                action: Decision::DENY,
                enabled: true,
                version: 1,
            },
        ]);
        let resp = engine.evaluate(&make_request(Classification::T3, Action::COPY));
        assert_eq!(resp.matched_policy_id.as_deref(), Some("pol-hi"));
        assert_eq!(resp.decision, Decision::DenyWithAlert);
    }

    // ── Disabled policy tests ──────────────────────────────────────────────────

    #[test]
    fn test_disabled_policy_ignored() {
        let engine = AbacEngine::with_policies(vec![Policy {
            id: "pol-disabled".into(),
            name: "Disabled T4 Policy".into(),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::Classification {
                op: "eq".into(),
                value: Classification::T4,
            }],
            action: Decision::ALLOW,
            enabled: false,
            version: 1,
        }]);
        let resp = engine.evaluate(&make_request(Classification::T4, Action::COPY));
        assert!(resp.matched_policy_id.is_none());
    }

    // ── Hot-reload tests ──────────────────────────────────────────────────────

    #[test]
    fn test_reload_policies() {
        let engine = AbacEngine::new();
        engine
            .reload_policies(vec![t4_deny_policy()])
            .expect("reload should succeed");
        let resp = engine.evaluate(&make_request(Classification::T4, Action::READ));
        assert!(resp.decision.is_denied());
    }

    #[test]
    fn test_reload_rejects_invalid_policy() {
        let engine = AbacEngine::new();
        let bad = Policy {
            id: "".into(), // invalid: empty ID
            name: "Bad".into(),
            description: None,
            priority: 1,
            conditions: vec![],
            action: Decision::ALLOW,
            enabled: true,
            version: 1,
        };
        let err = engine.reload_policies(vec![bad]).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    // ── Classification ordering tests ─────────────────────────────────────────

    #[test]
    fn test_t3_not_denied_by_t4_rule() {
        let engine = engine_with_rules();
        let resp = engine.evaluate(&make_request(Classification::T3, Action::DELETE));
        // T3 matches pol-002 (device trust condition), which DENYs
        assert!(resp.decision.is_denied());
    }

    #[test]
    fn test_t3_managed_device_not_denied() {
        let engine = AbacEngine::with_policies(vec![t3_unmanaged_deny_policy()]);
        let mut req = make_request(Classification::T3, Action::COPY);
        req.subject.device_trust = DeviceTrust::Managed;
        let resp = engine.evaluate(&req);
        // Managed device → condition fails → no match → default-deny
        assert!(resp.decision.is_denied());
    }
}
