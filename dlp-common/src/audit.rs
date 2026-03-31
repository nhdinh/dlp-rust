//! Audit event types and schemas.
//!
//! All dlp-agents emit structured JSON audit events for every intercepted file
//! operation. Events flow through dlp-server to SIEM. File content (payload) is
//! never included — only metadata.
//!
//! ## Event Flow
//!
//! ```text
//! dlp-agent (per endpoint)
//!   -> HTTPS POST /audit/events ---> dlp-server
//!                                         |- Append-only audit store
//!                                         +- SIEM relay (batched)
//!                                               +- Splunk HEC / ELK HTTP Ingest
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Action, Classification, Decision};

/// The type of audit event.
///
/// Each variant corresponds to a distinct security-relevant occurrence in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    /// A file was opened, read, or written.
    Access,
    /// An operation was blocked by an ABAC DENY decision.
    Block,
    /// A DENY_WITH_ALERT decision was triggered — also triggers SIEM alert.
    Alert,
    /// A policy or configuration was changed.
    ConfigChange,
    /// A user session logged off.
    SessionLogoff,
    /// An administrative action was performed via the dlp-admin-portal API.
    AdminAction,
    /// A dlp-agent service stop was attempted and failed after 3 wrong passwords.
    ServiceStopFailed,
    /// An ETW bypass was suspected — file op seen in ETW but not caught by hooks.
    EvasionSuspected,
}

impl EventType {
    /// Returns `true` if this event type should be routed to SIEM.
    #[must_use]
    pub fn routed_to_siem(self) -> bool {
        matches!(
            self,
            Self::Access
                | Self::Block
                | Self::Alert
                | Self::ConfigChange
                | Self::SessionLogoff
                | Self::AdminAction
                | Self::ServiceStopFailed
                | Self::EvasionSuspected
        )
    }

    /// Returns `true` if this event type should trigger a real-time user alert.
    #[must_use]
    pub fn triggers_alert(self) -> bool {
        matches!(self, Self::Alert | Self::ServiceStopFailed)
    }
}

/// The access context of the file operation.
///
/// `local` — the file operation originates from a process running locally on the endpoint.
/// `smb` — the file operation originates from a remote client over the SMB protocol
///          (i.e., the agent is deployed on a file server and intercepting a remote user's access).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuditAccessContext {
    /// Operation originates from the local process on the endpoint.
    #[default]
    Local,
    /// Operation originates from a remote SMB client on a file server.
    Smb,
}

impl From<super::AccessContext> for AuditAccessContext {
    fn from(ctx: super::AccessContext) -> Self {
        match ctx {
            super::AccessContext::Local => Self::Local,
            super::AccessContext::Smb => Self::Smb,
        }
    }
}

/// A structured audit event emitted by a dlp-agent.
///
/// All fields are non-optional except where noted. The JSON representation matches
/// the F-AUD-02 schema defined in SRS.md.
///
/// File content (payload) is **never** included — only metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// ISO 8601 timestamp with millisecond precision.
    pub timestamp: DateTime<Utc>,
    /// The type of event that occurred.
    pub event_type: EventType,
    /// The user's Windows Security Identifier (e.g., "S-1-5-21-123456789-...").
    pub user_sid: String,
    /// The user's display name (e.g., "jsmith").
    pub user_name: String,
    /// The full path to the resource involved in the event.
    pub resource_path: String,
    /// The classification tier of the resource at the time of the event.
    pub classification: Classification,
    /// The action the user attempted to perform.
    pub action_attempted: Action,
    /// The ABAC enforcement decision.
    pub decision: Decision,
    /// The ID of the policy that produced this decision (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// The human-readable name of the matched policy (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    /// The unique identifier of the dlp-agent that emitted this event.
    pub agent_id: String,
    /// The ID of the interactive session in which the event occurred.
    pub session_id: u32,
    /// The device trust level at the time of the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_trust: Option<String>,
    /// The network location at the time of the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_location: Option<String>,
    /// User-supplied justification for an override request (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    /// Whether an override was granted for this event (if an override was requested).
    #[serde(default)]
    pub override_granted: bool,
    /// Whether the operation originated locally or via SMB.
    #[serde(default)]
    pub access_context: AuditAccessContext,
    /// Optional session/connection ID for correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

impl AuditEvent {
    /// Constructs a new `AuditEvent` with a freshly generated timestamp and correlation ID.
    ///
    /// # Arguments
    ///
    /// * `event_type` — the type of event
    /// * `user_sid` — the requesting user's SID
    /// * `user_name` — the requesting user's display name
    /// * `resource_path` — the path to the resource
    /// * `classification` — the classification tier of the resource
    /// * `action_attempted` — the action the user attempted
    /// * `decision` — the ABAC enforcement decision
    /// * `agent_id` — the ID of the agent that generated this event
    /// * `session_id` — the interactive session ID
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_type: EventType,
        user_sid: String,
        user_name: String,
        resource_path: String,
        classification: Classification,
        action_attempted: Action,
        decision: Decision,
        agent_id: String,
        session_id: u32,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type,
            user_sid,
            user_name,
            resource_path,
            classification,
            action_attempted,
            decision,
            policy_id: None,
            policy_name: None,
            agent_id,
            session_id,
            device_trust: None,
            network_location: None,
            justification: None,
            override_granted: false,
            access_context: AuditAccessContext::Local,
            correlation_id: Some(Uuid::new_v4().to_string()),
        }
    }

    /// Sets the matched policy fields.
    pub fn with_policy(mut self, policy_id: String, policy_name: String) -> Self {
        self.policy_id = Some(policy_id);
        self.policy_name = Some(policy_name);
        self
    }

    /// Sets the access context.
    pub fn with_access_context(mut self, ctx: AuditAccessContext) -> Self {
        self.access_context = ctx;
        self
    }

    /// Sets the optional environmental fields.
    pub fn with_environment(
        mut self,
        device_trust: Option<String>,
        network_location: Option<String>,
    ) -> Self {
        self.device_trust = device_trust;
        self.network_location = network_location;
        self
    }

    /// Sets the override justification.
    pub fn with_justification(mut self, justification: String) -> Self {
        self.justification = Some(justification);
        self
    }

    /// Marks the event as an override-granted event.
    pub fn with_override_granted(mut self) -> Self {
        self.override_granted = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_siem_routing() {
        assert!(EventType::Block.routed_to_siem());
        assert!(EventType::Alert.routed_to_siem());
        assert!(EventType::Access.routed_to_siem());
    }

    #[test]
    fn test_event_type_triggers_alert() {
        assert!(EventType::Alert.triggers_alert());
        assert!(EventType::ServiceStopFailed.triggers_alert());
        assert!(!EventType::Block.triggers_alert());
    }

    #[test]
    fn test_audit_event_builder() {
        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            r"C:\Data\Report.xlsx".to_string(),
            Classification::T3,
            Action::COPY,
            Decision::DENY,
            "AGENT-WS02-001".to_string(),
            2,
        )
        .with_policy("pol-003".to_string(), "T3 USB Block".to_string())
        .with_access_context(AuditAccessContext::Local);

        assert_eq!(event.event_type, EventType::Block);
        assert_eq!(event.classification, Classification::T3);
        assert_eq!(event.decision, Decision::DENY);
        assert!(event.policy_id.is_some());
        assert!(event.correlation_id.is_some());
        assert!(event.justification.is_none());
        assert!(!event.override_granted);
    }

    #[test]
    fn test_audit_event_serde() {
        let event = AuditEvent::new(
            EventType::Access,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            r"C:\Public\Readme.txt".to_string(),
            Classification::T1,
            Action::READ,
            Decision::ALLOW,
            "AGENT-WS02-001".to_string(),
            1,
        );

        let json = serde_json::to_string(&event).unwrap();
        let round_trip: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.event_type, round_trip.event_type);
        assert_eq!(event.resource_path, round_trip.resource_path);
        assert_eq!(event.decision, round_trip.decision);
    }

    #[test]
    fn test_correlation_id_always_present() {
        let event = AuditEvent::new(
            EventType::Access,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            r"C:\Data\File.txt".to_string(),
            Classification::T2,
            Action::READ,
            Decision::ALLOW,
            "AGENT-WS02-001".to_string(),
            1,
        );
        assert!(event.correlation_id.is_some());
    }

    #[test]
    fn test_skip_serializing_none_fields() {
        let event = AuditEvent::new(
            EventType::Access,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            r"C:\Data\File.txt".to_string(),
            Classification::T2,
            Action::READ,
            Decision::ALLOW,
            "AGENT-WS02-001".to_string(),
            1,
        );
        let json = serde_json::to_string(&event).unwrap();
        // Optional fields should not appear when None
        assert!(!json.contains("\"policy_id\":null"));
        assert!(!json.contains("\"justification\":null"));
    }
}
