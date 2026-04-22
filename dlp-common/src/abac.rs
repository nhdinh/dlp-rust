//! ABAC types — Subject, Resource, Environment, Action, and Policy.
//!
//! These types define the attribute model used by the Policy Engine's
//! Attribute-Based Access Control evaluation layer.

use crate::endpoint::AppIdentity;
use serde::{Deserialize, Serialize};

/// The action the user is attempting to perform on a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Action {
    /// Read a file.
    #[default]
    READ,
    /// Write or modify a file.
    WRITE,
    /// Copy a file (e.g., to USB or network share).
    COPY,
    /// Delete a file.
    DELETE,
    /// Move a file (rename or relocate).
    MOVE,
    /// Paste from clipboard (copying text/data into an application).
    PASTE,
    /// Admin created a new policy via the admin API.
    PolicyCreate,
    /// Admin updated an existing policy via the admin API.
    PolicyUpdate,
    /// Admin deleted a policy via the admin API.
    PolicyDelete,
    /// Admin changed own password via the admin API.
    PasswordChange,
}

/// The access context describes how the file operation originated.
///
/// `local` — the file operation originates from a process running locally.
/// `smb` — the file operation originates from a remote client over SMB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AccessContext {
    /// Operation originates from the local process.
    #[default]
    Local,
    /// Operation originates from a remote SMB client.
    Smb,
}

/// The system action the ABAC engine returns after evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Decision {
    /// Permit the operation without additional logging.
    #[default]
    ALLOW,
    /// Block the operation and log the event.
    DENY,
    /// Permit the operation but emit an audit event.
    #[serde(rename = "ALLOW_WITH_LOG")]
    AllowWithLog,
    /// Block the operation, log the event, and trigger an immediate SIEM/admin alert.
    #[serde(rename = "DENY_WITH_ALERT")]
    DenyWithAlert,
}

impl Decision {
    /// Returns `true` if this decision blocks the operation.
    #[must_use]
    pub fn is_denied(self) -> bool {
        matches!(self, Self::DENY | Self::DenyWithAlert)
    }

    /// Returns `true` if this decision should trigger an alert.
    #[must_use]
    pub fn is_alert(self) -> bool {
        matches!(self, Self::DenyWithAlert)
    }

    /// Returns `true` if this decision requires an audit event to be emitted.
    #[must_use]
    pub fn requires_audit(self) -> bool {
        matches!(self, Self::DENY | Self::DenyWithAlert | Self::AllowWithLog)
    }
}

/// The trust level of the device the user is operating from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum DeviceTrust {
    /// Device is managed by the organization (e.g., domain-joined, MDM-enrolled).
    Managed,
    /// Device is not managed by the organization.
    #[default]
    Unmanaged,
    /// Device meets the organization's compliance requirements.
    Compliant,
    /// Device trust level is unknown or indeterminate.
    Unknown,
}

/// Network location inferred from the client's IP address or VPN status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum NetworkLocation {
    /// Device is on the corporate network (wired or wireless).
    Corporate,
    /// Device is connected via VPN.
    CorporateVpn,
    /// Device is on a guest or untrusted network.
    Guest,
    /// Location is unknown or could not be determined.
    #[default]
    Unknown,
}

/// The requesting user and their attributes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Subject {
    /// The user's Windows Security Identifier (e.g., "S-1-5-21-...").
    pub user_sid: String,
    /// The user's display name (e.g., "jsmith").
    pub user_name: String,
    /// The Windows Security Identifiers of all AD groups the user is a member of.
    pub groups: Vec<String>,
    /// The trust level of the device the user is operating from.
    #[serde(default)]
    pub device_trust: DeviceTrust,
    /// The network location of the device.
    #[serde(default)]
    pub network_location: NetworkLocation,
}

/// The file resource being accessed.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Resource {
    /// The full path to the file or directory (e.g., "C:\\Data\\Q4-Financials.xlsx").
    pub path: String,
    /// The classification tier of the resource.
    pub classification: crate::Classification,
}

/// The environmental context at the time of the access request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Environment {
    /// The current time on the endpoint.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// The session ID of the interactive session making the request.
    pub session_id: u32,
    /// Whether the request is originating from a remote SMB context.
    #[serde(default)]
    pub access_context: AccessContext,
}

/// Identity information about the requesting agent endpoint.
///
/// This is logged by the Policy Engine on every evaluation request to
/// identify which machine and user is making the request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentInfo {
    /// Machine hostname, e.g. "WORKSTATION-01".
    pub machine_name: Option<String>,
    /// The Windows username of the interactive session that triggered the request,
    /// e.g. "jsmith".
    pub current_user: Option<String>,
}

/// A complete ABAC evaluation request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EvaluateRequest {
    pub subject: Subject,
    pub resource: Resource,
    pub environment: Environment,
    pub action: Action,
    /// Agent endpoint identity — machine name and interactive user.
    /// Logged by the Policy Engine for request tracing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentInfo>,
    /// Resolved identity of the application that initiated the request
    /// (e.g. the process that copied clipboard content). Populated by
    /// Phase 25. `None` on requests from agents that predate Phase 25.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_application: Option<AppIdentity>,
    /// Resolved identity of the destination application (e.g. the
    /// paste target). Populated by Phase 25.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_application: Option<AppIdentity>,
}

/// Internal ABAC evaluation context.
///
/// Constructed from [`EvaluateRequest`] at the evaluate boundary in Phase 26.
/// Mirrors [`EvaluateRequest`] fields minus wire-only metadata: there is
/// deliberately no `agent` field (per Phase 22 D-10) because `AgentInfo`
/// is request-tracing metadata, not an ABAC attribute.
///
/// Defined in Phase 22 so downstream crates compile against the type
/// before Phase 26 wires it into [`crate::abac::EvaluateRequest`]-to-context
/// conversion at `PolicyStore::evaluate()`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AbacContext {
    pub subject: Subject,
    pub resource: Resource,
    pub environment: Environment,
    pub action: Action,
    /// Resolved identity of the application that initiated the operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_application: Option<AppIdentity>,
    /// Resolved identity of the destination application (paste target).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_application: Option<AppIdentity>,
}

/// A complete ABAC evaluation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResponse {
    /// The enforcement decision.
    pub decision: Decision,
    /// The ID of the policy that matched (if any).
    pub matched_policy_id: Option<String>,
    /// A human-readable reason string for the decision.
    pub reason: String,
}

impl EvaluateResponse {
    /// Constructs a default-deny response for when no policy matches.
    pub fn default_deny() -> Self {
        Self {
            decision: Decision::DENY,
            matched_policy_id: None,
            reason: "No matching policy; default deny".to_string(),
        }
    }

    /// Constructs a permit response for when no policy matches and the system is
    /// configured for default-allow on non-sensitive resources.
    #[must_use]
    pub fn default_allow() -> Self {
        Self {
            decision: Decision::ALLOW,
            matched_policy_id: None,
            reason: "No matching policy; default allow".to_string(),
        }
    }
}

/// The application-identity field targeted by a [`PolicyCondition`].
///
/// Used with `SourceApplication` and `DestinationApplication` condition variants
/// to select which field of [`crate::endpoint::AppIdentity`] to compare.
///
/// # Serde
///
/// Serializes as snake_case: `"publisher"`, `"image_path"`, `"trust_tier"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppField {
    /// Publisher common name from the Authenticode certificate (e.g., `"Microsoft Corporation"`).
    Publisher,
    /// Full NT image path of the process (e.g., `C:\Program Files\App\app.exe`).
    ImagePath,
    /// Application trust tier assigned by the Phase 25 publisher-verification pipeline.
    TrustTier,
}

impl From<EvaluateRequest> for AbacContext {
    /// Converts a wire [`EvaluateRequest`] into an internal [`AbacContext`].
    ///
    /// The `agent` field is intentionally dropped — `AgentInfo` is
    /// request-tracing metadata, not an ABAC attribute (Phase 22 D-10).
    ///
    /// # Arguments
    ///
    /// * `req` - The wire-format evaluation request to convert.
    ///
    /// # Returns
    ///
    /// An [`AbacContext`] with `subject`, `resource`, `environment`, `action`,
    /// `source_application`, and `destination_application` forwarded from `req`.
    fn from(req: EvaluateRequest) -> Self {
        Self {
            subject: req.subject,
            resource: req.resource,
            environment: req.environment,
            action: req.action,
            source_application: req.source_application,
            destination_application: req.destination_application,
        }
    }
}

/// A condition within an ABAC policy rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "attribute", rename_all = "snake_case")]
pub enum PolicyCondition {
    /// Match by resource classification tier.
    Classification {
        #[serde(rename = "op")]
        op: String,
        value: crate::Classification,
    },
    /// Match by AD group membership.
    MemberOf {
        #[serde(rename = "op")]
        op: String,
        group_sid: String,
    },
    /// Match by device trust level.
    DeviceTrust {
        #[serde(rename = "op")]
        op: String,
        value: DeviceTrust,
    },
    /// Match by network location.
    NetworkLocation {
        #[serde(rename = "op")]
        op: String,
        value: NetworkLocation,
    },
    /// Match by access context (local vs. SMB).
    AccessContext {
        #[serde(rename = "op")]
        op: String,
        value: AccessContext,
    },
    /// Match by the source application's identity (the process that initiated the operation).
    ///
    /// If `source_application` is `None` on the [`AbacContext`], this condition does NOT match
    /// (fails closed — no identity means the condition cannot be confirmed, per D-03).
    SourceApplication {
        /// Which field of [`crate::endpoint::AppIdentity`] to compare.
        field: AppField,
        /// Comparison operator: `"eq"`, `"ne"`, or `"contains"` (ImagePath only).
        #[serde(rename = "op")]
        op: String,
        /// The value to compare against (string form).
        value: String,
    },
    /// Match by the destination application's identity (the paste target process).
    ///
    /// If `destination_application` is `None` on the [`AbacContext`], this condition does NOT match
    /// (fails closed — no identity means the condition cannot be confirmed, per D-03).
    DestinationApplication {
        /// Which field of [`crate::endpoint::AppIdentity`] to compare.
        field: AppField,
        /// Comparison operator: `"eq"`, `"ne"`, or `"contains"` (ImagePath only).
        #[serde(rename = "op")]
        op: String,
        /// The value to compare against (string form).
        value: String,
    },
}

/// The boolean composition mode for a policy's condition list.
///
/// - `ALL`: every condition must match (implicit v0.4.0 behavior).
/// - `ANY`: at least one condition must match.
/// - `NONE`: no condition may match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PolicyMode {
    /// Every condition must match.
    #[default]
    ALL,
    /// At least one condition must match.
    ANY,
    /// No condition may match.
    NONE,
}

/// An ABAC policy rule.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    /// Unique identifier for this policy version.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Relative priority — lower numbers are evaluated first; first-match wins.
    pub priority: u32,
    /// The conditions that must all be satisfied for this policy to match.
    pub conditions: Vec<PolicyCondition>,
    /// The system action to apply when this policy matches.
    pub action: Decision,
    /// Whether this policy is currently active.
    pub enabled: bool,
    /// Boolean composition mode for the conditions list.
    #[serde(default)]
    pub mode: PolicyMode,
    /// Monotonically increasing version number.
    pub version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abac_context_default() {
        // Pitfall 1 prevention: AbacContext is public but not referenced in
        // library code during Phase 22 (Phase 26 wires it in). Constructing
        // the default here both prevents the dead_code warning and locks the
        // D-10 invariant: no `agent` field, both application fields None.
        let ctx = AbacContext::default();
        assert!(ctx.source_application.is_none());
        assert!(ctx.destination_application.is_none());
    }

    #[test]
    fn test_abac_context_round_trip() {
        use crate::endpoint::{AppIdentity, AppTrustTier, SignatureState};
        let ctx = AbacContext {
            source_application: Some(AppIdentity {
                image_path: r"C:\app.exe".to_string(),
                publisher: "Contoso".to_string(),
                trust_tier: AppTrustTier::Trusted,
                signature_state: SignatureState::Valid,
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let rt: AbacContext = serde_json::from_str(&json).unwrap();
        assert_eq!(
            rt.source_application.as_ref().map(|a| a.publisher.as_str()),
            Some("Contoso"),
        );
        assert!(rt.destination_application.is_none());
        // Destination app is None, so the key must be absent from JSON.
        assert!(!json.contains("destination_application"));
    }

    #[test]
    fn test_evaluate_request_app_identity_fields_round_trip() {
        use crate::endpoint::{AppIdentity, AppTrustTier, SignatureState};
        let req = EvaluateRequest {
            source_application: Some(AppIdentity {
                image_path: r"C:\src.exe".to_string(),
                publisher: "Adobe Inc.".to_string(),
                trust_tier: AppTrustTier::Trusted,
                signature_state: SignatureState::Valid,
            }),
            destination_application: Some(AppIdentity {
                image_path: r"C:\dst.exe".to_string(),
                publisher: "Unknown".to_string(),
                trust_tier: AppTrustTier::Untrusted,
                signature_state: SignatureState::NotSigned,
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&req).unwrap();
        let rt: EvaluateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(
            rt.source_application
                .as_ref()
                .map(|a| a.image_path.as_str()),
            Some(r"C:\src.exe"),
        );
        assert_eq!(
            rt.destination_application
                .as_ref()
                .map(|a| a.image_path.as_str()),
            Some(r"C:\dst.exe"),
        );
    }

    #[test]
    fn test_evaluate_request_omits_none_app_identity_fields() {
        // SC-3 observable truth: default EvaluateRequest serializes without
        // the two new keys when they are None, preserving wire-compat with
        // every agent running today (that does not send them).
        let req = EvaluateRequest::default();
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("source_application"), "json was: {json}");
        assert!(
            !json.contains("destination_application"),
            "json was: {json}"
        );
    }

    #[test]
    fn test_evaluate_request_backward_compat_missing_new_fields() {
        // SC-3: old payloads without the two new fields must still deserialize.
        // This is the exact shape dlp-agent emits today.
        let old_payload = r#"{
            "subject": {},
            "resource": {},
            "environment": {},
            "action": "READ"
        }"#;
        let req: EvaluateRequest = serde_json::from_str(old_payload).unwrap();
        assert!(req.source_application.is_none());
        assert!(req.destination_application.is_none());
    }

    #[test]
    fn test_decision_is_denied() {
        assert!(!Decision::ALLOW.is_denied());
        assert!(Decision::DENY.is_denied());
        assert!(!Decision::AllowWithLog.is_denied());
        assert!(Decision::DenyWithAlert.is_denied());
    }

    #[test]
    fn test_decision_is_alert() {
        assert!(!Decision::ALLOW.is_alert());
        assert!(!Decision::DENY.is_alert());
        assert!(!Decision::AllowWithLog.is_alert());
        assert!(Decision::DenyWithAlert.is_alert());
    }

    #[test]
    fn test_decision_requires_audit() {
        assert!(!Decision::ALLOW.requires_audit());
        assert!(Decision::DENY.requires_audit());
        assert!(Decision::AllowWithLog.requires_audit());
        assert!(Decision::DenyWithAlert.requires_audit());
    }

    #[test]
    fn test_evaluate_request_serde() {
        let req = EvaluateRequest {
            subject: Subject {
                user_sid: "S-1-5-21-123".to_string(),
                user_name: "jsmith".to_string(),
                groups: vec!["S-1-5-21-123-512".to_string()],
                device_trust: DeviceTrust::Managed,
                network_location: NetworkLocation::CorporateVpn,
            },
            resource: Resource {
                path: r"C:\Data\Report.xlsx".to_string(),
                classification: crate::Classification::T3,
            },
            environment: Environment {
                timestamp: chrono::Utc::now(),
                session_id: 2,
                access_context: AccessContext::Local,
            },
            action: Action::COPY,
            agent: None,
            ..Default::default()
        };
        let json = serde_json::to_string(&req).unwrap();
        let round_trip: EvaluateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(
            req.resource.classification,
            round_trip.resource.classification
        );
    }

    #[test]
    fn test_default_deny_response() {
        let resp = EvaluateResponse::default_deny();
        assert!(resp.decision.is_denied());
        assert!(resp.matched_policy_id.is_none());
    }

    #[test]
    fn test_decision_serde() {
        for decision in [
            Decision::ALLOW,
            Decision::DENY,
            Decision::AllowWithLog,
            Decision::DenyWithAlert,
        ] {
            let json = serde_json::to_string(&decision).unwrap();
            let rt: Decision = serde_json::from_str(&json).unwrap();
            assert_eq!(decision, rt);
        }
    }

    #[test]
    fn test_app_field_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&AppField::Publisher).unwrap(),
            "\"publisher\""
        );
        assert_eq!(
            serde_json::to_string(&AppField::ImagePath).unwrap(),
            "\"image_path\""
        );
        assert_eq!(
            serde_json::to_string(&AppField::TrustTier).unwrap(),
            "\"trust_tier\""
        );
    }

    #[test]
    fn test_policy_condition_source_application_round_trip() {
        // D-01 wire format: {"attribute": "source_application", "field": "publisher", "op": "eq", "value": "Microsoft"}
        let condition = PolicyCondition::SourceApplication {
            field: AppField::Publisher,
            op: "eq".to_string(),
            value: "Microsoft".to_string(),
        };
        let json = serde_json::to_string(&condition).unwrap();
        assert!(
            json.contains("\"attribute\":\"source_application\""),
            "json: {json}"
        );
        assert!(json.contains("\"field\":\"publisher\""), "json: {json}");
        let rt: PolicyCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(condition, rt);
    }

    #[test]
    fn test_policy_condition_destination_application_round_trip() {
        let condition = PolicyCondition::DestinationApplication {
            field: AppField::ImagePath,
            op: "contains".to_string(),
            value: r"Program Files".to_string(),
        };
        let json = serde_json::to_string(&condition).unwrap();
        assert!(
            json.contains("\"attribute\":\"destination_application\""),
            "json: {json}"
        );
        let rt: PolicyCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(condition, rt);
    }

    #[test]
    fn test_from_evaluate_request_for_abac_context_drops_agent() {
        use crate::endpoint::{AppIdentity, AppTrustTier, SignatureState};
        let req = EvaluateRequest {
            subject: Subject {
                user_sid: "S-1-5-21-999".to_string(),
                user_name: "alice".to_string(),
                ..Default::default()
            },
            action: Action::COPY,
            agent: Some(AgentInfo {
                machine_name: Some("PC-01".to_string()),
                current_user: Some("alice".to_string()),
            }),
            source_application: Some(AppIdentity {
                publisher: "Contoso".to_string(),
                image_path: r"C:\app.exe".to_string(),
                trust_tier: AppTrustTier::Trusted,
                signature_state: SignatureState::Valid,
            }),
            ..Default::default()
        };
        let ctx: AbacContext = req.into();
        // agent field is dropped — AbacContext has no agent field (Phase 22 D-10)
        assert_eq!(ctx.subject.user_sid, "S-1-5-21-999");
        assert_eq!(ctx.action, Action::COPY);
        assert_eq!(
            ctx.source_application
                .as_ref()
                .map(|a| a.publisher.as_str()),
            Some("Contoso")
        );
        assert!(ctx.destination_application.is_none());
    }

    #[test]
    fn test_from_evaluate_request_forwards_all_fields() {
        use crate::endpoint::{AppIdentity, AppTrustTier, SignatureState};
        let req = EvaluateRequest {
            subject: Subject {
                user_sid: "S-1-5-21-777".to_string(),
                user_name: "bob".to_string(),
                ..Default::default()
            },
            resource: Resource {
                path: r"C:\Data\file.txt".to_string(),
                classification: crate::Classification::T3,
            },
            action: Action::WRITE,
            destination_application: Some(AppIdentity {
                publisher: "Adobe Inc.".to_string(),
                image_path: r"C:\dst.exe".to_string(),
                trust_tier: AppTrustTier::Untrusted,
                signature_state: SignatureState::NotSigned,
            }),
            ..Default::default()
        };
        let ctx: AbacContext = req.into();
        assert_eq!(ctx.subject.user_name, "bob");
        assert_eq!(ctx.resource.path, r"C:\Data\file.txt");
        assert_eq!(ctx.action, Action::WRITE);
        assert!(ctx.source_application.is_none());
        assert_eq!(
            ctx.destination_application
                .as_ref()
                .map(|a| a.publisher.as_str()),
            Some("Adobe Inc.")
        );
    }
}
