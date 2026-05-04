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
//!                                               |- Splunk HEC / ELK HTTP Ingest
//! ```

use crate::disk::DiskIdentity;
use crate::endpoint::{AppIdentity, DeviceIdentity};
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
    /// An administrative action was performed via the dlp-server admin API.
    AdminAction,
    /// A dlp-agent service stop was attempted and failed after 3 wrong passwords.
    ServiceStopFailed,
    /// Disk discovery event emitted at agent startup with all enumerated fixed disks.
    DiskDiscovery,
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
                | Self::DiskDiscovery
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
    /// The full path to the process that initiated the file operation.
    /// Populated via `GetModuleFileNameExW` on the process handle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_path: Option<String>,
    /// SHA-256 hex digest of the process executable.
    /// Populated via `CryptHashData` / `CryptGetHashParam` over the process image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_hash: Option<String>,
    /// The owner SID of the file resource.
    /// Populated via `GetNamedSecurityInfoW` + `ConvertSidToStringSidW`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_owner: Option<String>,
    /// Resolved identity of the application that initiated the operation
    /// (populated by Phase 25 for clipboard events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_application: Option<AppIdentity>,
    /// Resolved identity of the destination application (e.g. the paste target).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_application: Option<AppIdentity>,
    /// USB device identity for block events involving removable storage
    /// (populated by Phase 26/27 on USB blocks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_identity: Option<DeviceIdentity>,
    /// Source origin URL for Chrome Content Analysis clipboard events
    /// (populated by Phase 29 Chrome Enterprise Connector).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_origin: Option<String>,
    /// Destination origin URL for Chrome Content Analysis clipboard events
    /// (populated by Phase 29 Chrome Enterprise Connector).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_origin: Option<String>,
    /// Discovered fixed disks emitted during agent startup disk enumeration
    /// (populated by Phase 33 disk discovery).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_disks: Option<Vec<DiskIdentity>>,
    /// Fixed disk identity on block events from `DiskEnforcer` (AUDIT-02, Phase 36).
    ///
    /// Populated only for [`EventType::Block`] events emitted when an unregistered
    /// fixed disk is blocked at I/O time. Semantically distinct from
    /// [`AuditEvent::discovered_disks`] (which is populated for `DiskDiscovery`
    /// enumeration events). Allows SIEM rules to filter
    /// `event_type = BLOCK AND blocked_disk IS NOT NULL` for disk enforcement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_disk: Option<DiskIdentity>,
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
            application_path: None,
            application_hash: None,
            resource_owner: None,
            source_application: None,
            destination_application: None,
            device_identity: None,
            source_origin: None,
            destination_origin: None,
            discovered_disks: None,
            blocked_disk: None,
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

    /// Sets the application metadata (process path and hash).
    pub fn with_application(
        mut self,
        application_path: Option<String>,
        application_hash: Option<String>,
    ) -> Self {
        self.application_path = application_path;
        self.application_hash = application_hash;
        self
    }

    /// Sets the resource owner SID.
    pub fn with_resource_owner(mut self, resource_owner: Option<String>) -> Self {
        self.resource_owner = resource_owner;
        self
    }

    /// Sets the resolved identity of the application that initiated the operation.
    pub fn with_source_application(mut self, app: Option<AppIdentity>) -> Self {
        self.source_application = app;
        self
    }

    /// Sets the resolved identity of the destination application (paste target).
    pub fn with_destination_application(mut self, app: Option<AppIdentity>) -> Self {
        self.destination_application = app;
        self
    }

    /// Sets the USB device identity on block events involving removable storage.
    pub fn with_device_identity(mut self, device: Option<DeviceIdentity>) -> Self {
        self.device_identity = device;
        self
    }

    /// Sets the source origin for Chrome Content Analysis events.
    pub fn with_source_origin(mut self, origin: Option<String>) -> Self {
        self.source_origin = origin;
        self
    }

    /// Sets the destination origin for Chrome Content Analysis events.
    pub fn with_destination_origin(mut self, origin: Option<String>) -> Self {
        self.destination_origin = origin;
        self
    }

    /// Sets the discovered disks for a DiskDiscovery event.
    pub fn with_discovered_disks(mut self, disks: Option<Vec<DiskIdentity>>) -> Self {
        self.discovered_disks = disks;
        self
    }

    /// Sets the blocked disk identity on disk enforcement block events (AUDIT-02, Phase 36).
    ///
    /// # Arguments
    ///
    /// * `disk` - the [`DiskIdentity`] from the live `drive_letter_map` at enforcement time.
    ///
    /// # Returns
    ///
    /// `self` with `blocked_disk` set to `Some(disk)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use dlp_common::{Action, AuditEvent, BusType, Classification, Decision,
    ///     DiskIdentity, EventType};
    /// let disk = DiskIdentity {
    ///     instance_id: "USBSTOR\\Disk\\1".into(),
    ///     bus_type: BusType::Usb,
    ///     model: "Acme USB SSD".into(),
    ///     drive_letter: Some('E'),
    ///     ..Default::default()
    /// };
    /// let event = AuditEvent::new(
    ///     EventType::Block,
    ///     "S-1-5-21-1".into(),
    ///     "alice".into(),
    ///     "E:\\file.txt".into(),
    ///     Classification::T1,
    ///     Action::WRITE,
    ///     Decision::DENY,
    ///     "AGENT-1".into(),
    ///     1,
    /// )
    /// .with_blocked_disk(disk.clone());
    /// assert_eq!(event.blocked_disk, Some(disk));
    /// ```
    #[must_use]
    pub fn with_blocked_disk(mut self, disk: DiskIdentity) -> Self {
        self.blocked_disk = Some(disk);
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
        // New optional fields should also be skipped
        assert!(!json.contains("\"application_path\":null"));
        assert!(!json.contains("\"application_hash\":null"));
        assert!(!json.contains("\"resource_owner\":null"));
        // Phase 22 new fields must also be skipped when None (D-11, D-12, D-13).
        assert!(!json.contains("\"source_application\":null"));
        assert!(!json.contains("\"destination_application\":null"));
        assert!(!json.contains("\"device_identity\":null"));
        // Phase 29 new fields must also be skipped when None.
        assert!(!json.contains("\"source_origin\":null"));
        assert!(!json.contains("\"destination_origin\":null"));
    }

    #[test]
    fn test_audit_event_with_source_application() {
        use crate::endpoint::{AppIdentity, AppTrustTier, SignatureState};
        let app = AppIdentity {
            image_path: r"C:\src.exe".to_string(),
            publisher: "Contoso".to_string(),
            trust_tier: AppTrustTier::Trusted,
            signature_state: SignatureState::Valid,
        };
        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-1".to_string(),
            "jsmith".to_string(),
            r"C:\Data\x.txt".to_string(),
            Classification::T3,
            Action::PASTE,
            Decision::DENY,
            "AGENT-01".to_string(),
            1,
        )
        .with_source_application(Some(app.clone()));
        assert_eq!(
            event
                .source_application
                .as_ref()
                .map(|a| a.publisher.as_str()),
            Some("Contoso")
        );
        assert!(event.destination_application.is_none());
        assert!(event.device_identity.is_none());
    }

    #[test]
    fn test_audit_event_with_destination_application_and_device_identity() {
        use crate::endpoint::{AppIdentity, AppTrustTier, DeviceIdentity, SignatureState};
        let dest = AppIdentity {
            image_path: r"C:\dst.exe".to_string(),
            publisher: "Unknown".to_string(),
            trust_tier: AppTrustTier::Untrusted,
            signature_state: SignatureState::NotSigned,
        };
        let dev = DeviceIdentity {
            vid: "0951".to_string(),
            pid: "1666".to_string(),
            serial: "XYZ".to_string(),
            description: "Kingston DT 3.0".to_string(),
        };
        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-1".to_string(),
            "jsmith".to_string(),
            r"E:\payload.zip".to_string(),
            Classification::T3,
            Action::WRITE,
            Decision::DENY,
            "AGENT-01".to_string(),
            1,
        )
        .with_destination_application(Some(dest))
        .with_device_identity(Some(dev.clone()));
        assert!(event.destination_application.is_some());
        assert_eq!(
            event.device_identity.as_ref().map(|d| d.vid.as_str()),
            Some("0951")
        );
    }

    #[test]
    fn test_audit_event_app_and_device_serde_round_trip() {
        use crate::endpoint::{AppIdentity, AppTrustTier, DeviceIdentity, SignatureState};
        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-2".to_string(),
            "jsmith".to_string(),
            r"E:\doc.pdf".to_string(),
            Classification::T2,
            Action::COPY,
            Decision::DENY,
            "AGENT-02".to_string(),
            3,
        )
        .with_source_application(Some(AppIdentity {
            image_path: r"C:\src.exe".to_string(),
            publisher: "Contoso".to_string(),
            trust_tier: AppTrustTier::Trusted,
            signature_state: SignatureState::Valid,
        }))
        .with_device_identity(Some(DeviceIdentity {
            vid: "0951".to_string(),
            pid: "1666".to_string(),
            serial: "(none)".to_string(),
            description: "Kingston".to_string(),
        }));
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("source_application"));
        assert!(json.contains("device_identity"));
        assert!(!json.contains("destination_application"));
        let rt: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(
            rt.source_application.as_ref().map(|a| a.publisher.as_str()),
            Some("Contoso"),
        );
        assert_eq!(
            rt.device_identity.as_ref().map(|d| d.serial.as_str()),
            Some("(none)")
        );
    }

    #[test]
    fn test_audit_event_backward_compat_missing_new_fields() {
        // D-13: deserializing an AuditEvent JSON that predates Phase 22 must
        // still succeed — all three new fields default to None.
        let legacy = r#"{
            "timestamp": "2025-01-01T00:00:00Z",
            "event_type": "BLOCK",
            "user_sid": "S-1-5-21-1",
            "user_name": "jsmith",
            "resource_path": "C:\\Data\\x.txt",
            "classification": "T3",
            "action_attempted": "READ",
            "decision": "DENY",
            "agent_id": "AGENT-01",
            "session_id": 1,
            "override_granted": false,
            "access_context": "local"
        }"#;
        let event: AuditEvent = serde_json::from_str(legacy).unwrap();
        assert!(event.source_application.is_none());
        assert!(event.destination_application.is_none());
        assert!(event.device_identity.is_none());
    }

    #[test]
    fn test_audit_event_backward_compat_missing_origin_fields() {
        // Deserializing an AuditEvent JSON that predates Phase 29 must still
        // succeed — both new origin fields default to None.
        let legacy = r#"{
            "timestamp": "2025-01-01T00:00:00Z",
            "event_type": "BLOCK",
            "user_sid": "S-1-5-21-1",
            "user_name": "jsmith",
            "resource_path": "C:\\Data\\x.txt",
            "classification": "T3",
            "action_attempted": "READ",
            "decision": "DENY",
            "agent_id": "AGENT-01",
            "session_id": 1,
            "override_granted": false,
            "access_context": "local"
        }"#;
        let event: AuditEvent = serde_json::from_str(legacy).unwrap();
        assert!(event.source_origin.is_none());
        assert!(event.destination_origin.is_none());
    }

    #[test]
    fn test_with_application() {
        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            r"C:\Data\File.txt".to_string(),
            Classification::T2,
            Action::COPY,
            Decision::DENY,
            "AGENT-WS02-001".to_string(),
            1,
        )
        .with_application(
            Some(r"C:\Program Files\Notepadpp\notepad++.exe".to_string()),
            Some("a1b2c3d4e5f6".to_string()),
        )
        .with_resource_owner(Some("S-1-5-21-456".to_string()));

        assert_eq!(
            event.application_path,
            Some(r"C:\Program Files\Notepadpp\notepad++.exe".to_string())
        );
        assert_eq!(event.application_hash, Some("a1b2c3d4e5f6".to_string()));
        assert_eq!(event.resource_owner, Some("S-1-5-21-456".to_string()));
    }

    #[test]
    fn test_event_type_disk_discovery_routed_to_siem() {
        assert!(EventType::DiskDiscovery.routed_to_siem());
    }

    #[test]
    fn test_audit_event_with_discovered_disks() {
        use crate::disk::{BusType, DiskIdentity};
        let disks = vec![
            DiskIdentity {
                instance_id: "PCIIDE\\IDECHANNEL\\4&1234".to_string(),
                bus_type: BusType::Sata,
                model: "WDC WD10EZEX-00BN5A0".to_string(),
                drive_letter: Some('C'),
                serial: Some("WD-12345678".to_string()),
                size_bytes: Some(1_000_204_886_016),
                is_boot_disk: true,
                encryption_status: None,
                encryption_method: None,
                encryption_checked_at: None,
            },
            DiskIdentity {
                instance_id: "USB\\VID_1234&PID_5678&REV_0001".to_string(),
                bus_type: BusType::Usb,
                model: "USB External Drive".to_string(),
                drive_letter: Some('E'),
                serial: Some("EXT-001".to_string()),
                size_bytes: Some(500_000_000_000),
                is_boot_disk: false,
                encryption_status: None,
                encryption_method: None,
                encryption_checked_at: None,
            },
        ];
        let event = AuditEvent::new(
            EventType::DiskDiscovery,
            "S-1-5-21-1".to_string(),
            "jsmith".to_string(),
            "N/A".to_string(),
            Classification::T1,
            Action::READ,
            Decision::ALLOW,
            "AGENT-01".to_string(),
            1,
        )
        .with_discovered_disks(Some(disks));

        assert!(event.discovered_disks.is_some());
        let d = event.discovered_disks.as_ref().unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].bus_type, BusType::Sata);
        assert!(d[0].is_boot_disk);
        assert_eq!(d[1].bus_type, BusType::Usb);
        assert!(!d[1].is_boot_disk);

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("DISK_DISCOVERY"));
        assert!(json.contains("discovered_disks"));
        assert!(json.contains("WDC WD10EZEX-00BN5A0"));
        assert!(json.contains("USB External Drive"));
    }

    #[test]
    fn test_audit_event_backward_compat_missing_discovered_disks() {
        // Deserializing an AuditEvent JSON that predates Phase 33 must still
        // succeed -- discovered_disks defaults to None.
        let legacy = r#"{
            "timestamp": "2025-01-01T00:00:00Z",
            "event_type": "BLOCK",
            "user_sid": "S-1-5-21-1",
            "user_name": "jsmith",
            "resource_path": "C:\\Data\\x.txt",
            "classification": "T3",
            "action_attempted": "READ",
            "decision": "DENY",
            "agent_id": "AGENT-01",
            "session_id": 1,
            "override_granted": false,
            "access_context": "local"
        }"#;
        let event: AuditEvent = serde_json::from_str(legacy).unwrap();
        assert!(event.discovered_disks.is_none());
    }

    #[test]
    fn test_skip_serializing_none_discovered_disks() {
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
        assert!(!json.contains("\"discovered_disks\":null"));
    }

    /// AUDIT-02: with_blocked_disk populates the blocked_disk field with the given DiskIdentity.
    #[test]
    fn test_audit_event_with_blocked_disk() {
        use crate::BusType;
        let disk = DiskIdentity {
            instance_id: "USBSTOR\\Disk&Ven_Kingston\\001".to_string(),
            bus_type: BusType::Usb,
            model: "Kingston DT 50".to_string(),
            drive_letter: Some('E'),
            serial: Some("SN-001".to_string()),
            size_bytes: Some(64_000_000_000),
            is_boot_disk: false,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        };
        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-123".to_string(),
            "alice".to_string(),
            r"E:\\secret.docx".to_string(),
            Classification::T1,
            Action::WRITE,
            Decision::DENY,
            "AGENT-1".to_string(),
            1,
        )
        .with_blocked_disk(disk.clone());

        assert_eq!(event.blocked_disk, Some(disk.clone()));
        assert_eq!(event.event_type, EventType::Block);
        assert_eq!(event.decision, Decision::DENY);

        // Discovered disks must remain None -- these fields are semantically distinct.
        assert!(event.discovered_disks.is_none());
    }

    /// AUDIT-02: JSON serialization of a populated blocked_disk includes the
    /// DiskIdentity fields required by AUDIT-02 (instance_id, bus_type, model,
    /// drive_letter).
    #[test]
    fn test_blocked_disk_json_contains_identity_fields() {
        use crate::BusType;
        let disk = DiskIdentity {
            instance_id: "USBSTOR\\Disk&Ven_Kingston\\001".to_string(),
            bus_type: BusType::Usb,
            model: "Kingston DT 50".to_string(),
            drive_letter: Some('E'),
            serial: Some("SN-001".to_string()),
            size_bytes: Some(64_000_000_000),
            is_boot_disk: false,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        };
        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-123".to_string(),
            "alice".to_string(),
            r"E:\\secret.docx".to_string(),
            Classification::T1,
            Action::WRITE,
            Decision::DENY,
            "AGENT-1".to_string(),
            1,
        )
        .with_blocked_disk(disk);

        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains("\"blocked_disk\""),
            "JSON must contain blocked_disk: {json}"
        );
        assert!(json.contains("Kingston DT 50"), "model missing: {json}");
        assert!(json.contains("USBSTOR"), "instance_id missing: {json}");
        assert!(
            json.contains("\"bus_type\""),
            "bus_type field missing: {json}"
        );
        assert!(
            json.contains("\"drive_letter\""),
            "drive_letter field missing: {json}"
        );
    }

    /// AUDIT-02: skip_serializing_if removes blocked_disk from JSON when None.
    #[test]
    fn test_skip_serializing_none_blocked_disk() {
        let event = AuditEvent::new(
            EventType::Access,
            "S-1-5-21-123".to_string(),
            "alice".to_string(),
            r"C:\\Users\\alice\\file.txt".to_string(),
            Classification::T1,
            Action::READ,
            Decision::ALLOW,
            "AGENT-1".to_string(),
            1,
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("\"blocked_disk\""),
            "None blocked_disk must be omitted: {json}"
        );
        assert!(
            !json.contains("\"blocked_disk\":null"),
            "must not serialize as null: {json}"
        );
    }

    /// AUDIT-02: legacy JSON without blocked_disk deserializes successfully -- the
    /// field defaults to None for backward compatibility.
    #[test]
    fn test_backward_compat_missing_blocked_disk() {
        // Legacy JSON intentionally lacks blocked_disk to simulate audit logs
        // written by pre-Phase-36 agents.
        let legacy_json = r#"{
            "timestamp": "2026-04-01T00:00:00Z",
            "event_type": "BLOCK",
            "user_sid": "S-1-5-21-1",
            "user_name": "alice",
            "resource_path": "E:\\\\file.txt",
            "classification": "T1",
            "action_attempted": "WRITE",
            "decision": "DENY",
            "agent_id": "AGENT-1",
            "session_id": 1
        }"#;
        let event: AuditEvent = serde_json::from_str(legacy_json)
            .expect("legacy JSON without blocked_disk must deserialize");
        assert_eq!(event.event_type, EventType::Block);
        assert!(
            event.blocked_disk.is_none(),
            "missing blocked_disk must default to None"
        );
    }
}
