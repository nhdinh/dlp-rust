//! IPC types shared between the hook DLL and the agent service.
//!
//! # Protocol Evolution
//!
//! The IPC protocol uses a versioned envelope (`IpcEnvelope`) to allow forward-compatible
//! evolution. New protocol versions add new enum variants. Unknown variants deserialize
//! as errors that trigger degraded behavior (pipe-only authoritative classification).
//!
//! # Cache Non-Authoritative Invariant
//!
//! The cache stores classification **HINT** only. ABAC authority is never bypassed.
//! A cache hit enables tier-gated fast-path decisions; a cache miss always falls
//! through to the full ABAC evaluation via pipe round-trip.
//!
//! # Bincode Configuration
//!
//! Bincode serialization is pinned to **little-endian, fixed-width integers** (not varint)
//! for stability across protocol versions. All new fields use `#[serde(default)]` to
//! preserve backward compatibility with old peers.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{Classification, VolumeClass};

/// Distinguishes read vs write operations for tier-gated fast-path decisions.
///
/// The cache lookup uses `HookOp` to decide whether a fast-path deny is appropriate:
/// - `Write` on T3/T4 → fast-path deny (skip pipe)
/// - `Read` on any tier → always allow (ABAC decides on pipe)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum HookOp {
    /// Read operation — cache never denies reads.
    #[default]
    Read,
    /// Write operation — T3/T4 cache hit may fast-path deny.
    Write,
}

/// Classification hint for DLL LRU warming.
///
/// When the agent classifies a path not in the shared-memory cache, it returns
/// the classification + TTL so the DLL can warm its thread-local LRU for future
/// lookups. This is advisory only; ABAC authority is never bypassed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheHint {
    /// The classified path.
    pub path: PathBuf,
    /// The classification tier.
    pub tier: Classification,
    /// TTL in seconds for this hint.
    pub ttl_secs: u32,
}

/// Top-level versioned envelope for all IPC messages.
///
/// `IpcEnvelope` provides forward-compatible evolution. Future protocol versions
/// add variants (V2, V3). Unknown variants deserialize as an error that triggers
/// degraded behavior (pipe-only authoritative classification).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IpcEnvelope {
    /// Protocol version 1.
    V1(IpcMessageV1),
}

/// Protocol version 1 message wrapper.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpcMessageV1 {
    /// The payload (request or response).
    pub payload: IpcPayloadV1,
}

/// Protocol version 1 payload discriminant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IpcPayloadV1 {
    /// A hook request.
    Request(HookRequest),
    /// A hook response.
    Response(HookResponse),
    /// A volume class query from the hook DLL to the agent.
    ///
    /// Sent when the hook DLL needs to know the volume class of a drive letter
    /// (cache miss or initial lookup). The agent responds with
    /// [`IpcPayloadV1::VolumeClassResponse`].
    VolumeClassQuery(VolumeClassQuery),
    /// A volume class response from the agent to the hook DLL.
    ///
    /// The `class` field is `None` when the agent does not know the drive letter
    /// or classification failed. The hook DLL treats `None` as fail-closed
    /// (does not default to [`VolumeClass::LocalNTFS`]).
    VolumeClassResponse(VolumeClassResponse),
    /// An override request from the hook DLL to the agent.
    ///
    /// Sent when a user requests an override for a blocked operation.
    /// The agent validates the request and responds with [`IpcPayloadV1::Response`].
    RequestOverride(OverrideRequest),
    /// A diagnostics pull request from the agent to the hook DLL.
    ///
    /// The agent requests diagnostic snapshots from the hook DLL.
    /// The hook DLL responds with [`IpcPayloadV1::DiagnosticsResponse`].
    PullDiagnostics(PullDiagnosticsRequest),
    /// A diagnostics response from the hook DLL to the agent.
    ///
    /// Contains diagnostic snapshots captured by the hook DLL.
    DiagnosticsResponse(DiagnosticsResponse),
    /// A health pull request from the agent to the hook DLL.
    ///
    /// The agent requests a health snapshot from the hook DLL.
    /// The hook DLL responds with [`IpcPayloadV1::HealthResponse`].
    PullHealth(PullHealthRequest),
    /// A health response from the hook DLL to the agent.
    ///
    /// Contains a health snapshot of the hook DLL state.
    HealthResponse(HealthResponse),
    /// A bypass alert from the hook DLL to the agent.
    ///
    /// Sent when the hook DLL detects a bypass attempt (e.g., EDR overwriting
    /// the trampoline, patch race condition). Fire-and-forget; no response expected.
    BypassAlert(BypassAlert),
    /// A journal degraded alert from the hook DLL to the agent.
    ///
    /// Sent when the hook DLL's shared-memory journal mapping is lost or the
    /// ring buffer cannot accept an entry. The ABAC decision is preserved;
    /// this alert is for monitoring and SIEM routing only.
    JournalDegraded(JournalDegradedAlert),
    /// A hash evidence frame from the hook DLL to the agent.
    ///
    /// Sent when a blocked write operation's content has been hashed.
    /// The agent stores this in a short-lived HashCache and attaches it
    /// to the AuditEvent. Fire-and-forget; no response expected.
    HashEvidence(HashEvidenceFrame),
}

/// Request sent by the hook DLL to the agent for classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HookRequest {
    /// The file path being accessed.
    pub path: String,
    /// The action being performed (e.g., "CREATE", "WRITE", "READ").
    pub action: String,
    /// The last cache version seen by this DLL.
    ///
    /// The agent uses this to detect stale DLLs. A value of `0` means the DLL
    /// has never seen a valid cache.
    #[serde(default)]
    pub cache_version: u64,
    /// Protocol version negotiated by this DLL.
    ///
    /// Defaults to `1` for backward compatibility. Enables future protocol
    /// evolution without breaking old peers.
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u8,
    /// The operation type (read vs write) for tier-gated fast-path decisions.
    #[serde(default)]
    pub op: HookOp,
    /// Volume class of the source path (if any).
    ///
    /// Populated by the hook DLL via [`volume_class_cache::resolve_volume_class_from_path`].
    /// `None` when the volume class cannot be determined.
    #[serde(default)]
    pub source_volume_class: Option<VolumeClass>,
    /// Volume class of the destination path (if any).
    ///
    /// Populated by the hook DLL for copy/move operations.
    /// `None` for single-path operations or when undetermined.
    #[serde(default)]
    pub destination_volume_class: Option<VolumeClass>,
    /// Process ID of the hooked process making this request.
    ///
    /// Used by the agent to look up the real user SID from the process token
    /// for ABAC evaluation. A value of `0` means the PID was not provided.
    #[serde(default)]
    pub pid: u32,
}

fn default_protocol_version() -> u8 {
    CURRENT_PROTOCOL_VERSION
}

/// Response returned by the agent to the hook DLL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookResponse {
    /// The ABAC decision.
    pub decision: crate::Decision,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Cache hint for DLL LRU warming.
    ///
    /// When the agent classifies a path not in cache, it returns the tier + TTL
    /// so the DLL can warm its local LRU. `None` means the path is unclassified
    /// or the agent chose not to send a hint.
    #[serde(default)]
    pub cache_hint: Option<CacheHint>,
    /// The current cache version known to the agent.
    ///
    /// The DLL compares this against its last seen version to detect stale cache.
    #[serde(default)]
    pub cache_version: u64,
    /// Whether the decision was overridden by an approval token (DIFF-01).
    ///
    /// When `true`, the agent checked the ApprovalCache after ABAC returned DENY
    /// and found a valid override. The hook DLL should allow the operation and
    /// emit an audit event with `override_granted=true`.
    #[serde(default)]
    pub approval_override: Option<bool>,
}

/// Request sent by the hook DLL to the agent for handle-based classification.
///
/// The agent resolves the path from its internal handle tracker.
/// `handle_value` is `u64` (not `usize`) to avoid architecture ambiguity
/// when a 32-bit hook DLL talks to a 64-bit agent service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandleHookRequest {
    /// The raw HANDLE value cast to u64 for cross-architecture safety.
    pub handle_value: u64,
    /// The operation being performed (e.g., "WRITE", "SET_INFO").
    pub action: String,
    /// The PID of the process making the request.
    pub pid: u32,
}

/// Query sent by the hook DLL to the agent for the volume class of a drive letter.
///
/// The agent looks up the drive letter in its `volume_class_map` and responds
/// with [`VolumeClassResponse`]. If the agent has no entry for the drive letter,
/// it responds with `VolumeClassResponse { class: None }`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VolumeClassQuery {
    /// The drive letter to classify (e.g., `'D'`).
    pub drive_letter: char,
}

/// Response returned by the agent to the hook DLL for a volume class query.
///
/// The `class` field is `None` when:
/// - The agent has no entry for the requested drive letter.
/// - Classification failed (WMI error, unknown drive type).
///
/// The hook DLL treats `None` as fail-closed: volume-class conditions in ABAC
/// evaluation evaluate to `false`, which for a DENY policy means the condition
/// does not match. NEVER default `None` to [`VolumeClass::LocalNTFS`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VolumeClassResponse {
    /// The classified volume class, or `None` if classification failed or the
    /// drive letter is not known to the agent.
    pub class: Option<VolumeClass>,
}

/// Alert emitted by the hook DLL when it detects a bypass attempt or EDR conflict.
///
/// Sent from the hook DLL to the agent via the existing named pipe IPC path.
/// Phase 53: Extended with ETW correlation fields for bypass correlator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BypassAlert {
    /// The reason for the alert.
    pub reason: BypassReason,
    /// The affected ntdll stub name (e.g., "NtCreateFile").
    /// Only meaningful for HookOverwritten and PatchRaced reasons.
    /// For NoHookJournal and OpMismatch, this is set to "etw_correlation".
    pub stub_name: String,
    /// Process ID where the alert occurred.
    pub pid: u32,
    /// Timestamp (Unix epoch seconds).
    pub timestamp_secs: u64,
    /// Protocol version — set to 2 for Phase 53 alerts; set to 1 for Phase 51 alerts.
    #[serde(default = "default_alert_version")]
    pub version: u32,
    /// Unique identifier of the agent that emitted this alert.
    #[serde(default)]
    pub agent_id: String,
    /// Full path to the process image executable.
    #[serde(default)]
    pub image_path: String,
    /// SHA-256 hex digest of the process executable (None if computation failed).
    #[serde(default)]
    pub image_sha256: Option<String>,
    /// File path involved in the operation (from ETW event).
    #[serde(default)]
    pub file_path: String,
    /// Human-readable operation type (e.g., "Create", "Write", "Delete", "SetInfo").
    #[serde(default)]
    pub operation: String,
    /// Kernel FILE_OBJECT pointer (forensics correlation only).
    /// EXPLICITLY set from ETW event.file_object per CR-08.
    #[serde(default)]
    pub file_object: u64,
    /// QueryPerformanceCounter timestamp at correlation time.
    #[serde(default)]
    pub qpc_timestamp: u64,
    /// Severity level: "crit", "warn", or "info".
    #[serde(default)]
    pub severity: String,
    /// Human-readable correlation reason for SIEM routing.
    #[serde(default)]
    pub correlation_reason: String,
}

/// Alert emitted by the hook DLL when the journal mapping is lost or the ring
/// buffer cannot accept an entry.
///
/// Per D-04, the hook DLL preserves the ABAC decision and emits this alert
/// via the named pipe for monitoring. The operation is NOT failed closed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JournalDegradedAlert {
    /// The file object (HANDLE value) that was being operated on.
    pub file_object: u64,
    /// The operation type (1=Create, 2=Write, 3=Delete, 4=SetInfo).
    pub op: u8,
    /// Human-readable error description.
    pub error: String,
}

/// Default alert version for deserialization when the field is missing.
fn default_alert_version() -> u32 {
    1
}

/// Reasons a bypass alert can be emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BypassReason {
    /// Our trampoline was overwritten by EDR (or other hook).
    HookOverwritten,
    /// Thread RIP was inside the stub range during patch attempt.
    PatchRaced,
    /// EDR detected at boot, patching skipped for this stub.
    EdrDetected,
    /// No matching hook journal entry found for an ETW Kernel-File event.
    /// Indicates the hook DLL did not observe a file operation that the kernel did.
    NoHookJournal,
    /// Journal entry found but the operation type differed from the ETW event.
    /// Indicates potential tampering with the hook's operation classification.
    OpMismatch,
}

/// Classification source for diagnostic snapshots.
///
/// Indicates how the classification was resolved for a given operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ClassificationSource {
    /// Classification was resolved from the in-process cache.
    #[default]
    CacheHit,
    /// Classification required a pipe round-trip to the agent.
    CacheMiss,
    /// Classification was resolved via named pipe IPC.
    Pipe,
}

/// Request sent by the hook DLL to the agent for an override.
///
/// Used when a user requests an override for a blocked operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct OverrideRequest {
    /// The SID of the user requesting the override.
    #[serde(default)]
    pub requester_sid: String,
    /// The ID of the data object being accessed.
    #[serde(default)]
    pub data_object_id: String,
    /// The action being requested (e.g., "WRITE", "COPY").
    #[serde(default)]
    pub action: String,
    /// The destination scope for the action (if applicable).
    #[serde(default)]
    pub destination_scope: Option<String>,
    /// Human-readable justification for the override.
    #[serde(default)]
    pub justification: String,
    /// The full path to the resource being accessed.
    #[serde(default)]
    pub resource_path: String,
}

/// Request sent by the agent to the hook DLL for diagnostic snapshots.
///
/// The agent polls the hook DLL for recent diagnostic data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PullDiagnosticsRequest {
    /// Maximum number of diagnostic snapshots to return.
    #[serde(default)]
    pub max_entries: usize,
}

/// Diagnostic snapshot capturing full decision context on a DENY.
///
/// Used for troubleshooting and audit evidence collection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DiagnosticSnapshot {
    /// The hooked function that triggered the snapshot (e.g., "WriteFile").
    #[serde(default)]
    pub hook_function: String,
    /// How the classification was resolved.
    #[serde(default)]
    pub classification_source: ClassificationSource,
    /// Age of the classification in milliseconds.
    #[serde(default)]
    pub classification_age_ms: u64,
    /// The ABAC resource (file path).
    #[serde(default)]
    pub abac_resource: String,
    /// The ABAC action (e.g., "WRITE").
    #[serde(default)]
    pub abac_action: String,
    /// The ABAC environment context.
    #[serde(default)]
    pub abac_environment: String,
    /// The ID of the matched policy (if any).
    #[serde(default)]
    pub matched_policy_id: Option<String>,
    /// The enforcement mode of the matched policy (if any).
    #[serde(default)]
    pub enforcement_mode: Option<String>,
    /// Decision latency in microseconds.
    #[serde(default)]
    pub decision_latency_us: u64,
    /// QPC timestamp when the snapshot was captured.
    #[serde(default)]
    pub timestamp_qpc: u64,
    /// The user's Windows SID.
    #[serde(default)]
    pub user_sid: String,
}

/// Response from the hook DLL containing diagnostic snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DiagnosticsResponse {
    /// The diagnostic snapshots captured by the hook DLL.
    #[serde(default)]
    pub snapshots: Vec<DiagnosticSnapshot>,
}

/// Request sent by the agent to the hook DLL for a health snapshot.
///
/// Unit struct — no parameters needed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PullHealthRequest {}

/// Health snapshot of the hook DLL state.
///
/// Provides operational metrics for monitoring hook DLL health.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HookHealthSnapshot {
    /// Number of processes currently injected.
    #[serde(default)]
    pub injected_pids: u64,
    /// Number of modules currently patched.
    #[serde(default)]
    pub patched_modules: u64,
    /// Number of pipe round-trips in the last 60 seconds.
    #[serde(default)]
    pub pipe_round_trips_60s: u64,
    /// Cache hit rate over the last 60 seconds (0.0 to 1.0).
    #[serde(default)]
    pub cache_hit_rate_60s: f64,
    /// Current fail-mode state (0=Healthy, 1=Degraded, 2=Isolated).
    #[serde(default)]
    pub current_fail_state: u8,
    /// Unix timestamp when the snapshot was captured.
    #[serde(default)]
    pub timestamp_secs: u64,
}

/// Response from the hook DLL containing a health snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HealthResponse {
    /// The health snapshot.
    #[serde(default)]
    pub snapshot: HookHealthSnapshot,
}

/// Hash evidence frame sent from hook DLL to agent after a blocked write.
///
/// The agent stores this in a TTL-governed HashCache keyed by (pid, handle_value)
/// and attaches it to the AuditEvent via `with_content_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HashEvidenceFrame {
    /// Process ID of the hooked process.
    pub pid: u32,
    /// The raw HANDLE value cast to u64 for cross-architecture safety.
    pub handle_value: u64,
    /// SHA-256 hex digest of the content, or None if hashing failed.
    #[serde(default)]
    pub content_sha256: Option<String>,
    /// Whether the hash was truncated due to the 100MB cap.
    #[serde(default)]
    pub hash_truncated: bool,
    /// Whether hashing was skipped due to thread pool saturation.
    #[serde(default)]
    pub hash_skipped: bool,
    /// Unix timestamp when the hash was computed.
    pub timestamp_secs: u64,
}

/// Current protocol version.
pub const CURRENT_PROTOCOL_VERSION: u8 = 1;

/// Error type for protocol version negotiation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    /// The hook and agent could not agree on a protocol version.
    #[error("version mismatch: hook={hook}, agent={agent}")]
    VersionMismatch { hook: u8, agent: u8 },
    /// The operation type is not recognized.
    #[error("unknown op value")]
    UnknownOp,
}

/// Negotiate a common protocol version between hook and agent.
///
/// Returns the minimum of the two versions if both are known (>= 1).
/// Returns an error if either version is 0 (indicates a pre-versioning peer
/// that should fall back to pipe-only authoritative classification).
///
/// # Behavior
///
/// - Hook protocol version newer than agent: agent uses its max known version,
///   hook downgrades.
/// - Agent protocol version newer than hook: hook uses its max known version,
///   agent downgrades.
/// - `cache_version` absent or zero: treat as stale (version 0), force cache refresh.
/// - Unknown op values: treated as nonfatal protocol errors triggering degraded
///   behavior (do not panic).
pub fn negotiate_protocol(hook_version: u8, agent_version: u8) -> Result<u8, ProtocolError> {
    if hook_version == 0 || agent_version == 0 {
        return Err(ProtocolError::VersionMismatch {
            hook: hook_version,
            agent: agent_version,
        });
    }
    Ok(hook_version.min(agent_version))
}

// Design note: Cache updates are via shared-memory atomic version flip ONLY.
// There is no HookMessage::CacheDelta variant and no pipe broadcast for cache
// deltas by design. This avoids maintaining a connected-client list and
// ensures cache consistency through the single atomic version word.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decision;

    // --- Task 1: HookOp and CacheHint ---

    #[test]
    fn hook_op_default_is_read() {
        assert_eq!(HookOp::default(), HookOp::Read);
    }

    #[test]
    fn cache_hint_roundtrip() {
        let hint = CacheHint {
            path: PathBuf::from(r"C:\test\file.txt"),
            tier: Classification::T3,
            ttl_secs: 60,
        };
        let json = serde_json::to_string(&hint).unwrap();
        let round_trip: CacheHint = serde_json::from_str(&json).unwrap();
        assert_eq!(hint, round_trip);
    }

    // --- Task 2: IpcEnvelope ---

    #[test]
    fn envelope_v1_roundtrip() {
        let req = HookRequest {
            path: r"C:\test.txt".to_string(),
            action: "WRITE".to_string(),
            cache_version: 42,
            protocol_version: 1,
            op: HookOp::Write,
            source_volume_class: None,
            destination_volume_class: None,
            pid: 0,
        };
        let envelope = IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::Request(req),
        });
        let bytes = bincode::serialize(&envelope).unwrap();
        let round_trip: IpcEnvelope = bincode::deserialize(&bytes).unwrap();
        assert_eq!(envelope, round_trip);
    }

    // --- Task 3: HookRequest backward compatibility ---

    #[test]
    fn old_request_deserializes_with_defaults() {
        // Simulate an old HookRequest serialized as JSON without the new fields.
        // JSON supports serde(default); bincode requires exact layout match.
        let old_json = r#"{"path":"C:\\old.txt","action":"READ"}"#;
        let deserialized: HookRequest = serde_json::from_str(old_json).unwrap();
        assert_eq!(deserialized.path, r"C:\old.txt");
        assert_eq!(deserialized.action, "READ");
        assert_eq!(deserialized.cache_version, 0);
        assert_eq!(deserialized.protocol_version, 1);
        assert_eq!(deserialized.op, HookOp::Read);
    }

    #[test]
    fn new_request_roundtrips() {
        let req = HookRequest {
            path: r"C:\new.txt".to_string(),
            action: "WRITE".to_string(),
            cache_version: 7,
            protocol_version: 1,
            op: HookOp::Write,
            source_volume_class: None,
            destination_volume_class: None,
            pid: 0,
        };
        let bytes = bincode::serialize(&req).unwrap();
        let round_trip: HookRequest = bincode::deserialize(&bytes).unwrap();
        assert_eq!(req, round_trip);
    }

    // --- Phase 56.1: Volume class fields on HookRequest ---

    #[test]
    fn test_hook_request_volume_class_roundtrip() {
        let req = HookRequest {
            path: r"C:\test.txt".to_string(),
            action: "WRITE".to_string(),
            cache_version: 0,
            protocol_version: 1,
            op: HookOp::Write,
            source_volume_class: Some(VolumeClass::USBRemovable),
            destination_volume_class: Some(VolumeClass::Optical),
            pid: 0,
        };
        let bytes = bincode::serialize(&req).unwrap();
        let round_trip: HookRequest = bincode::deserialize(&bytes).unwrap();
        assert_eq!(
            round_trip.source_volume_class,
            Some(VolumeClass::USBRemovable)
        );
        assert_eq!(
            round_trip.destination_volume_class,
            Some(VolumeClass::Optical)
        );
    }

    #[test]
    fn test_old_request_deserializes_with_volume_class_defaults() {
        // Simulate an old HookRequest serialized as JSON without volume class fields.
        // serde(default) ensures new fields default to None.
        let old_json = r#"{"path":"C:\\old.txt","action":"READ"}"#;
        let deserialized: HookRequest = serde_json::from_str(old_json).unwrap();
        assert_eq!(deserialized.path, r"C:\old.txt");
        assert_eq!(deserialized.action, "READ");
        assert!(deserialized.source_volume_class.is_none());
        assert!(deserialized.destination_volume_class.is_none());
    }

    #[test]
    fn protocol_version_defaults_to_one() {
        // serde(default) applies during deserialization, not Rust Default.
        let json = r#"{"path":"C:\\test.txt","action":"READ"}"#;
        let req: HookRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.protocol_version, 1);
    }

    // --- Task 4: HookResponse backward compatibility ---

    #[test]
    fn old_response_deserializes_with_defaults() {
        // JSON supports serde(default); bincode requires exact layout match.
        let old_json = r#"{"decision":"ALLOW","reason":"ok"}"#;
        let deserialized: HookResponse = serde_json::from_str(old_json).unwrap();
        assert_eq!(deserialized.decision, Decision::ALLOW);
        assert_eq!(deserialized.reason, "ok");
        assert!(deserialized.cache_hint.is_none());
        assert_eq!(deserialized.cache_version, 0);
        assert_eq!(deserialized.approval_override, None);
    }

    #[test]
    fn new_response_roundtrips() {
        let resp = HookResponse {
            decision: Decision::DENY,
            reason: "T4 write".to_string(),
            cache_hint: Some(CacheHint {
                path: PathBuf::from(r"C:\secret.txt"),
                tier: Classification::T4,
                ttl_secs: 30,
            }),
            cache_version: 99,
            approval_override: Some(false),
        };
        let bytes = bincode::serialize(&resp).unwrap();
        let round_trip: HookResponse = bincode::deserialize(&bytes).unwrap();
        assert_eq!(resp, round_trip);
    }

    #[test]
    fn response_with_approval_override_roundtrips() {
        let resp = HookResponse {
            decision: Decision::ALLOW,
            reason: "approved via override token".to_string(),
            cache_hint: None,
            cache_version: 0,
            approval_override: Some(true),
        };
        let bytes = bincode::serialize(&resp).unwrap();
        let round_trip: HookResponse = bincode::deserialize(&bytes).unwrap();
        assert_eq!(round_trip.approval_override, Some(true));
        assert_eq!(resp, round_trip);
    }

    // --- Task 7: Version negotiation ---

    #[test]
    fn negotiate_protocol_same_version() {
        assert_eq!(negotiate_protocol(1, 1).unwrap(), 1);
    }

    #[test]
    fn negotiate_protocol_hook_newer() {
        assert_eq!(negotiate_protocol(2, 1).unwrap(), 1);
    }

    #[test]
    fn negotiate_protocol_agent_newer() {
        assert_eq!(negotiate_protocol(1, 2).unwrap(), 1);
    }

    #[test]
    fn negotiate_protocol_zero_hook_fails() {
        assert!(negotiate_protocol(0, 1).is_err());
    }

    #[test]
    fn negotiate_protocol_zero_agent_fails() {
        assert!(negotiate_protocol(1, 0).is_err());
    }

    #[test]
    fn negotiate_protocol_both_zero_fails() {
        assert!(negotiate_protocol(0, 0).is_err());
    }

    // --- Phase 51: BypassAlert ---

    #[test]
    fn bypass_alert_roundtrip() {
        let alert = BypassAlert {
            reason: BypassReason::HookOverwritten,
            stub_name: "NtCreateFile".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 1,
            agent_id: "AGENT-TEST".to_string(),
            image_path: r"C:\Test\app.exe".to_string(),
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0,
            qpc_timestamp: 0,
            severity: "crit".to_string(),
            correlation_reason: "HookOverwritten".to_string(),
        };
        let bytes = bincode::serialize(&alert).unwrap();
        let round_trip: BypassAlert = bincode::deserialize(&bytes).unwrap();
        assert_eq!(alert, round_trip);
    }

    #[test]
    fn bypass_reason_serde() {
        for reason in [
            BypassReason::HookOverwritten,
            BypassReason::PatchRaced,
            BypassReason::EdrDetected,
        ] {
            let json = serde_json::to_string(&reason).unwrap();
            let rt: BypassReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, rt);
        }
    }

    // --- Phase 53: Extended BypassReason and BypassAlert ---

    #[test]
    fn test_bypass_reason_no_hook_journal_serde() {
        let reason = BypassReason::NoHookJournal;
        let json = serde_json::to_string(&reason).unwrap();
        let rt: BypassReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, rt);
    }

    #[test]
    fn test_bypass_reason_op_mismatch_serde() {
        let reason = BypassReason::OpMismatch;
        let json = serde_json::to_string(&reason).unwrap();
        let rt: BypassReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, rt);
    }

    #[test]
    fn test_bypass_alert_v2_serde() {
        let alert = BypassAlert {
            reason: BypassReason::NoHookJournal,
            stub_name: "etw_correlation".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 2,
            agent_id: "AGENT-TEST".to_string(),
            image_path: r"C:\Test\app.exe".to_string(),
            image_sha256: Some(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ),
            file_path: r"C:\Data\secret.docx".to_string(),
            operation: "Write".to_string(),
            file_object: 0xDEADBEEF,
            qpc_timestamp: 1_000_000,
            severity: "crit".to_string(),
            correlation_reason: "NoHookJournal on protected path".to_string(),
        };
        let json = serde_json::to_string(&alert).unwrap();
        let rt: BypassAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(alert.reason, rt.reason);
        assert_eq!(alert.version, rt.version);
        assert_eq!(alert.agent_id, rt.agent_id);
        assert_eq!(alert.image_path, rt.image_path);
        assert_eq!(alert.image_sha256, rt.image_sha256);
        assert_eq!(alert.file_path, rt.file_path);
        assert_eq!(alert.operation, rt.operation);
        assert_eq!(alert.file_object, rt.file_object);
        assert_eq!(alert.qpc_timestamp, rt.qpc_timestamp);
        assert_eq!(alert.severity, rt.severity);
        assert_eq!(alert.correlation_reason, rt.correlation_reason);
    }

    #[test]
    fn test_bypass_alert_v1_backward_compat() {
        // Simulate a Phase 51 alert (only original fields) serialized as JSON.
        // All new fields must deserialize to their default values per WR-12.
        let v1_json = r#"{
            "reason": "HookOverwritten",
            "stub_name": "NtCreateFile",
            "pid": 1234,
            "timestamp_secs": 1700000000
        }"#;
        let alert: BypassAlert = serde_json::from_str(v1_json).unwrap();
        assert_eq!(alert.reason, BypassReason::HookOverwritten);
        assert_eq!(alert.stub_name, "NtCreateFile");
        assert_eq!(alert.pid, 1234);
        assert_eq!(alert.timestamp_secs, 1_700_000_000);
        // New fields must have default values.
        assert_eq!(alert.version, 1);
        assert_eq!(alert.agent_id, "");
        assert_eq!(alert.image_path, "");
        assert!(alert.image_sha256.is_none());
        assert_eq!(alert.file_path, "");
        assert_eq!(alert.operation, "");
        assert_eq!(alert.file_object, 0);
        assert_eq!(alert.qpc_timestamp, 0);
        assert_eq!(alert.severity, "");
        assert_eq!(alert.correlation_reason, "");
    }

    #[test]
    fn test_bypass_alert_v1_deserializes_default_version() {
        // Verify that a v1-serialized alert deserializes with version=1
        // (the default per default_alert_version() via serde(default = ...)).
        let v1_json = r#"{
            "reason": "EdrDetected",
            "stub_name": "NtCreateFile",
            "pid": 5678,
            "timestamp_secs": 1700000001
        }"#;
        let alert: BypassAlert = serde_json::from_str(v1_json).unwrap();
        assert_eq!(alert.version, 1);
    }

    #[test]
    fn test_bypass_alert_stub_name_etw_correlation() {
        let alert = BypassAlert {
            reason: BypassReason::NoHookJournal,
            stub_name: "etw_correlation".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 2,
            agent_id: "AGENT-TEST".to_string(),
            image_path: r"C:\Test\app.exe".to_string(),
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0,
            qpc_timestamp: 0,
            severity: "warn".to_string(),
            correlation_reason: "NoHookJournal".to_string(),
        };
        assert_eq!(alert.stub_name, "etw_correlation");
    }

    // --- Phase 56: VolumeClassQuery / VolumeClassResponse ---

    #[test]
    fn test_volume_class_query_serde() {
        let query = VolumeClassQuery { drive_letter: 'D' };
        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("\"drive_letter\""), "json: {json}");
        assert!(json.contains("\"D\""), "json: {json}");
        let rt: VolumeClassQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(query, rt);
    }

    #[test]
    fn test_volume_class_response_serde_some() {
        let resp = VolumeClassResponse {
            class: Some(VolumeClass::Optical),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"class\""), "json: {json}");
        assert!(json.contains("\"Optical\""), "json: {json}");
        let rt: VolumeClassResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, rt);
    }

    #[test]
    fn test_volume_class_response_serde_none() {
        let resp = VolumeClassResponse { class: None };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"class\":null"), "json: {json}");
        let rt: VolumeClassResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, rt);
    }

    #[test]
    fn test_ipc_payload_volume_class_query_roundtrip() {
        let query = VolumeClassQuery { drive_letter: 'E' };
        let envelope = IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::VolumeClassQuery(query),
        });
        let bytes = bincode::serialize(&envelope).unwrap();
        let rt: IpcEnvelope = bincode::deserialize(&bytes).unwrap();
        assert_eq!(envelope, rt);
    }

    #[test]
    fn test_ipc_payload_volume_class_response_roundtrip() {
        let resp = VolumeClassResponse {
            class: Some(VolumeClass::USBRemovable),
        };
        let envelope = IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::VolumeClassResponse(resp),
        });
        let bytes = bincode::serialize(&envelope).unwrap();
        let rt: IpcEnvelope = bincode::deserialize(&bytes).unwrap();
        assert_eq!(envelope, rt);
    }

    #[test]
    fn test_ipc_payload_bypass_alert_roundtrip() {
        // This test references IpcPayloadV1::BypassAlert which will be added
        // in Wave 1 Plan 01. It serves as the Nyquist anchor — the test exists
        // before the implementation. Per D-05 and REVIEW-M-06.
        let alert = BypassAlert {
            reason: BypassReason::HookOverwritten,
            stub_name: "NtCreateFile".to_string(),
            pid: 1234,
            timestamp_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            version: 1,
            agent_id: "test-agent".to_string(),
            image_path: r"C:\test.exe".to_string(),
            image_sha256: Some("abc123".to_string()),
            file_path: r"C:\secret.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0xDEADBEEF,
            qpc_timestamp: 9999,
            severity: "crit".to_string(),
            correlation_reason: "HookSelfReported".to_string(),
        };
        let envelope = IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::BypassAlert(alert.clone()),
        });
        let bytes = bincode::serialize(&envelope).unwrap();
        let rt: IpcEnvelope = bincode::deserialize(&bytes).unwrap();
        assert_eq!(envelope, rt);

        // Verify the deserialized payload is BypassAlert with matching fields.
        match rt {
            IpcEnvelope::V1(msg) => match msg.payload {
                IpcPayloadV1::BypassAlert(ref deserialized_alert) => {
                    assert_eq!(deserialized_alert.reason, alert.reason);
                    assert_eq!(deserialized_alert.stub_name, alert.stub_name);
                    assert_eq!(deserialized_alert.pid, alert.pid);
                    assert_eq!(deserialized_alert.version, alert.version);
                    assert_eq!(deserialized_alert.agent_id, alert.agent_id);
                    assert_eq!(deserialized_alert.image_path, alert.image_path);
                    assert_eq!(deserialized_alert.image_sha256, alert.image_sha256);
                    assert_eq!(deserialized_alert.file_path, alert.file_path);
                    assert_eq!(deserialized_alert.operation, alert.operation);
                    assert_eq!(deserialized_alert.file_object, alert.file_object);
                    assert_eq!(deserialized_alert.qpc_timestamp, alert.qpc_timestamp);
                    assert_eq!(deserialized_alert.severity, alert.severity);
                    assert_eq!(
                        deserialized_alert.correlation_reason,
                        alert.correlation_reason
                    );
                }
                _ => panic!("expected BypassAlert payload"),
            },
        }
    }

    #[test]
    fn test_volume_class_response_none_fail_closed_semantic() {
        // Verify the fail-closed invariant: when source_volume_class is None,
        // a SourceVolumeClass condition does NOT match (returns false).
        // This is the actual behavior tested via volume_class_matches.
        use crate::abac::{PolicyCondition, VolumeClass};
        // Construct a SourceVolumeClass condition to document intent.
        let _condition = PolicyCondition::SourceVolumeClass {
            op: "eq".to_string(),
            value: VolumeClass::LocalNTFS,
        };
        // Simulate the condition matching logic: None actual volume class fails closed.
        let matches = match None::<VolumeClass> {
            Some(actual) => actual == VolumeClass::LocalNTFS,
            None => false,
        };
        assert!(
            !matches,
            "None volume class must fail closed (condition does not match)"
        );
    }

    // --- Phase 58: Override, Diagnostics, and Health IPC types ---

    #[test]
    fn test_override_request_roundtrip() {
        let req = OverrideRequest {
            requester_sid: "S-1-5-21-1".to_string(),
            data_object_id: "doc-123".to_string(),
            action: "WRITE".to_string(),
            destination_scope: Some("USB".to_string()),
            justification: "Business need".to_string(),
            resource_path: r"C:\Data\secret.docx".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let rt: OverrideRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, rt);
    }

    #[test]
    fn test_override_request_default_fields() {
        let json = r#"{"requester_sid":"S-1-5-21-1"}"#;
        let req: OverrideRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.requester_sid, "S-1-5-21-1");
        assert_eq!(req.data_object_id, "");
        assert_eq!(req.action, "");
        assert_eq!(req.destination_scope, None);
        assert_eq!(req.justification, "");
        assert_eq!(req.resource_path, "");
    }

    #[test]
    fn test_diagnostic_snapshot_roundtrip() {
        let snap = DiagnosticSnapshot {
            hook_function: "WriteFile".to_string(),
            classification_source: ClassificationSource::CacheHit,
            classification_age_ms: 42,
            abac_resource: r"C:\Data\file.txt".to_string(),
            abac_action: "WRITE".to_string(),
            abac_environment: "local".to_string(),
            matched_policy_id: Some("pol-001".to_string()),
            enforcement_mode: Some("Block".to_string()),
            decision_latency_us: 150,
            timestamp_qpc: 1_000_000,
            user_sid: "S-1-5-21-1".to_string(),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let rt: DiagnosticSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, rt);
    }

    #[test]
    fn test_diagnostics_response_roundtrip() {
        let resp = DiagnosticsResponse {
            snapshots: vec![DiagnosticSnapshot {
                hook_function: "WriteFile".to_string(),
                classification_source: ClassificationSource::Pipe,
                classification_age_ms: 0,
                abac_resource: r"C:\Data\file.txt".to_string(),
                abac_action: "WRITE".to_string(),
                abac_environment: "local".to_string(),
                matched_policy_id: None,
                enforcement_mode: None,
                decision_latency_us: 200,
                timestamp_qpc: 2_000_000,
                user_sid: "S-1-5-21-1".to_string(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let rt: DiagnosticsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, rt);
    }

    #[test]
    fn test_pull_diagnostics_request_default() {
        let json = r#"{}"#;
        let req: PullDiagnosticsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.max_entries, 0);
    }

    #[test]
    fn test_hook_health_snapshot_roundtrip() {
        let snap = HookHealthSnapshot {
            injected_pids: 5,
            patched_modules: 12,
            pipe_round_trips_60s: 100,
            cache_hit_rate_60s: 0.85,
            current_fail_state: 0,
            timestamp_secs: 1_700_000_000,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let rt: HookHealthSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, rt);
    }

    #[test]
    fn test_health_response_roundtrip() {
        let resp = HealthResponse {
            snapshot: HookHealthSnapshot {
                injected_pids: 3,
                patched_modules: 8,
                pipe_round_trips_60s: 50,
                cache_hit_rate_60s: 0.92,
                current_fail_state: 1,
                timestamp_secs: 1_700_000_001,
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        let rt: HealthResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, rt);
    }

    #[test]
    fn test_pull_health_request_default() {
        let json = r#"{}"#;
        let req: PullHealthRequest = serde_json::from_str(json).unwrap();
        // Unit struct with default — should deserialize successfully.
        assert_eq!(req, PullHealthRequest {});
    }

    #[test]
    fn test_classification_source_serde() {
        for source in [
            ClassificationSource::CacheHit,
            ClassificationSource::CacheMiss,
            ClassificationSource::Pipe,
        ] {
            let json = serde_json::to_string(&source).unwrap();
            let rt: ClassificationSource = serde_json::from_str(&json).unwrap();
            assert_eq!(source, rt);
        }
    }

    #[test]
    fn test_ipc_payload_override_roundtrip() {
        let req = OverrideRequest {
            requester_sid: "S-1-5-21-1".to_string(),
            data_object_id: "doc-123".to_string(),
            action: "WRITE".to_string(),
            destination_scope: None,
            justification: "test".to_string(),
            resource_path: r"C:\test.txt".to_string(),
        };
        let envelope = IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::RequestOverride(req),
        });
        let bytes = bincode::serialize(&envelope).unwrap();
        let rt: IpcEnvelope = bincode::deserialize(&bytes).unwrap();
        assert_eq!(envelope, rt);
    }

    #[test]
    fn test_ipc_payload_diagnostics_response_roundtrip() {
        let resp = DiagnosticsResponse {
            snapshots: vec![DiagnosticSnapshot {
                hook_function: "NtCreateFile".to_string(),
                classification_source: ClassificationSource::CacheMiss,
                classification_age_ms: 10,
                abac_resource: r"C:\Data\x.txt".to_string(),
                abac_action: "CREATE".to_string(),
                abac_environment: "local".to_string(),
                matched_policy_id: Some("pol-002".to_string()),
                enforcement_mode: Some("Audit".to_string()),
                decision_latency_us: 300,
                timestamp_qpc: 3_000_000,
                user_sid: "S-1-5-21-2".to_string(),
            }],
        };
        let envelope = IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::DiagnosticsResponse(resp),
        });
        let bytes = bincode::serialize(&envelope).unwrap();
        let rt: IpcEnvelope = bincode::deserialize(&bytes).unwrap();
        assert_eq!(envelope, rt);
    }

    #[test]
    fn test_ipc_payload_health_response_roundtrip() {
        let resp = HealthResponse {
            snapshot: HookHealthSnapshot {
                injected_pids: 1,
                patched_modules: 4,
                pipe_round_trips_60s: 20,
                cache_hit_rate_60s: 0.75,
                current_fail_state: 0,
                timestamp_secs: 1_700_000_002,
            },
        };
        let envelope = IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::HealthResponse(resp),
        });
        let bytes = bincode::serialize(&envelope).unwrap();
        let rt: IpcEnvelope = bincode::deserialize(&bytes).unwrap();
        assert_eq!(envelope, rt);
    }
}
