//! IPC message types for the iced UI — mirrors dlp-agent/src/ipc/messages.rs.
//!
//! The UI connects to the same pipes as the agent and exchanges the same
//! message types.  Since dlp-agent and dlp-user-ui are separate crates,
//! the message types are duplicated here.

use dlp_common::AppIdentity;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Pipe 1 — DLPCommand (bidirectional)
// ─────────────────────────────────────────────────────────────────────────────

/// Messages sent FROM the agent TO the UI over Pipe 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Pipe1AgentMsg {
    BlockNotify {
        reason: String,
        classification: String,
        resource_path: String,
        policy_id: String,
    },
    OverrideRequest {
        request_id: String,
        reason: String,
        classification: String,
        resource_path: String,
        requester_sid: String,
        data_object_id: String,
        action: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        destination_scope: Option<String>,
        #[serde(default)]
        justification: String,
    },
    ClipboardRead {
        request_id: String,
    },
    PasswordDialog {
        request_id: String,
    },
    /// Heartbeat ping sent periodically to verify the UI is still responsive.
    Ping,
    /// An approval has been granted — UI should notify the user.
    ///
    /// Kept in sync with `dlp-agent/src/ipc/messages.rs::Pipe1AgentMsg`; an
    /// approval frame that fails to deserialize here would be silently dropped
    /// (WR-01).
    ApprovalGranted {
        /// The request ID that was approved.
        request_id: String,
        /// The signed JWT approval token.
        token: String,
        /// Human-readable expiry timestamp (ISO-8601).
        valid_until: String,
    },
    /// An approval has been rejected — UI should notify the user.
    ApprovalRejected {
        /// The request ID that was rejected.
        request_id: String,
        /// Optional reason for rejection.
        reason: Option<String>,
    },
}

/// Messages sent FROM the UI TO the agent over Pipe 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Pipe1UiMsg {
    RegisterSession {
        session_id: u32,
    },
    UserConfirmed {
        request_id: String,
        justification: String,
    },
    UserCancelled {
        request_id: String,
    },
    ClipboardData {
        request_id: String,
        data: String,
    },
    PasswordSubmit {
        request_id: String,
        password: String,
    },
    PasswordCancel {
        request_id: String,
    },
    /// Heartbeat pong in response to agent `Ping`.
    Pong,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipe 2 — DLPEventAgent2UI (agent → UI)
// ─────────────────────────────────────────────────────────────────────────────

/// Messages sent FROM the agent TO the UI over Pipe 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
#[allow(dead_code)]
pub enum Pipe2AgentMsg {
    Toast {
        title: String,
        body: String,
    },
    StatusUpdate {
        status: String,
    },
    HealthPing,
    UiRespawn {
        session_id: u32,
    },
    UiClosingSequence {
        session_id: u32,
    },
    /// Broadcast by the agent after each heartbeat attempt to dlp-server.
    /// The UI uses this to display Agent->Server connection state in the tray tooltip.
    ServerConnected {
        connected: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_connected_roundtrip() {
        let msg = Pipe2AgentMsg::ServerConnected { connected: true };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Pipe2AgentMsg = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Pipe2AgentMsg::ServerConnected { connected: true }
        ));
    }

    #[test]
    fn ping_roundtrip() {
        let msg = Pipe1AgentMsg::Ping;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"Ping\""), "json was: {json}");
        let decoded: Pipe1AgentMsg = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, Pipe1AgentMsg::Ping));
    }

    #[test]
    fn pong_roundtrip() {
        let msg = Pipe1UiMsg::Pong;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"Pong\""), "json was: {json}");
        let decoded: Pipe1UiMsg = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, Pipe1UiMsg::Pong));
    }

    #[test]
    fn approval_granted_roundtrip() {
        let msg = Pipe1AgentMsg::ApprovalGranted {
            request_id: "req-1".to_string(),
            token: "tok-abc".to_string(),
            valid_until: "2026-12-31T23:59:59Z".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Pipe1AgentMsg = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Pipe1AgentMsg::ApprovalGranted { ref request_id, .. } if request_id == "req-1"
        ));
    }

    #[test]
    fn approval_rejected_roundtrip() {
        let msg = Pipe1AgentMsg::ApprovalRejected {
            request_id: "req-2".to_string(),
            reason: Some("policy".to_string()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Pipe1AgentMsg = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            decoded,
            Pipe1AgentMsg::ApprovalRejected { ref request_id, .. } if request_id == "req-2"
        ));
    }

    /// Guards WR-01: the UI mirror must accept the exact JSON the agent emits
    /// for approval outcomes. Both enums use `#[serde(tag="type",
    /// content="payload")]` with identical field names, so an agent-shaped
    /// payload must deserialize cleanly; if a future change drifts the two
    /// enums apart, this test fails before an approval frame is silently
    /// dropped at runtime.
    #[test]
    fn approval_variants_deserialize_agent_shaped_json() {
        let granted = serde_json::json!({
            "type": "ApprovalGranted",
            "payload": {
                "request_id": "req-9",
                "token": "signed.jwt.token",
                "valid_until": "2026-12-31T23:59:59Z",
            }
        });
        let decoded: Pipe1AgentMsg =
            serde_json::from_value(granted).expect("agent ApprovalGranted must deserialize");
        assert!(matches!(decoded, Pipe1AgentMsg::ApprovalGranted { .. }));

        let rejected = serde_json::json!({
            "type": "ApprovalRejected",
            "payload": {
                "request_id": "req-10",
                "reason": "denied by board",
            }
        });
        let decoded: Pipe1AgentMsg =
            serde_json::from_value(rejected).expect("agent ApprovalRejected must deserialize");
        assert!(matches!(decoded, Pipe1AgentMsg::ApprovalRejected { .. }));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipe 3 — DLPEventUI2Agent (UI → agent)
// ─────────────────────────────────────────────────────────────────────────────

/// Messages sent FROM the UI TO the agent over Pipe 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
pub enum Pipe3UiMsg {
    HealthPong,
    UiReady {
        session_id: u32,
    },
    UiClosing {
        session_id: u32,
    },
    ClipboardAlert {
        session_id: u32,
        classification: String,
        preview: String,
        text_length: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_application: Option<AppIdentity>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        destination_application: Option<AppIdentity>,
    },
}
