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
    },
    ClipboardRead {
        request_id: String,
    },
    PasswordDialog {
        request_id: String,
    },
    /// Heartbeat ping sent periodically to verify the UI is still responsive.
    Ping,
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
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipe 3 — DLPEventUI2Agent (UI → agent)
// ─────────────────────────────────────────────────────────────────────────────

/// Messages sent FROM the UI TO the agent over Pipe 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
#[allow(dead_code)]
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
