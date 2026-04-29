//! IPC message types shared between the agent and UI.
//!
//! All messages are JSON-encoded and delimited by a 4-byte little-endian length prefix.
//! A frame is: `[u32:length][json:payload]` — exactly what `serde_json` produces when
//! combined with a manual length-prefix write/read.

use dlp_common::AppIdentity;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Pipe 1 — DLPCommand (bidirectional)
// ─────────────────────────────────────────────────────────────────────────────

/// Messages sent FROM the agent TO the UI over Pipe 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Pipe1AgentMsg {
    /// The agent blocked an operation — UI should display a notification.
    BlockNotify {
        reason: String,
        classification: String,
        resource_path: String,
        policy_id: String,
    },
    /// The user requested an override — UI should show a justification dialog.
    OverrideRequest {
        request_id: String,
        reason: String,
        classification: String,
        resource_path: String,
    },
    /// The agent needs to read the clipboard — UI should return the data.
    ClipboardRead { request_id: String },
    /// The agent is requesting a password (for service stop authorization).
    PasswordDialog { request_id: String },
    /// Heartbeat ping sent periodically to verify the UI is still responsive.
    /// The UI should respond with `Pong` or silently continue; missing pings
    /// trigger the watchdog self-terminate path.
    Ping,
}

/// Messages sent FROM the UI TO the agent over Pipe 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Pipe1UiMsg {
    /// The UI registered itself with its session ID (sent as the first message
    /// after connecting to Pipe 1).
    RegisterSession { session_id: u32 },
    /// The user confirmed the block (override granted).
    UserConfirmed { request_id: String },
    /// The user cancelled the override request.
    UserCancelled { request_id: String },
    /// The user's clipboard data.
    ClipboardData { request_id: String, data: String },
    /// The user's password submission (for service stop).
    PasswordSubmit {
        request_id: String,
        password: String,
    },
    /// The user cancelled the password dialog.
    PasswordCancel { request_id: String },
    /// Heartbeat pong in response to agent `Ping`.
    Pong,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipe 2 — DLPEventAgent2UI (agent → UI, fire-and-forget)
// ─────────────────────────────────────────────────────────────────────────────

/// Messages sent FROM the agent TO the UI over Pipe 2.
///
/// These are one-way notifications — the UI does not reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Pipe2AgentMsg {
    /// Display a toast notification.
    Toast { title: String, body: String },
    /// Update the agent status shown in the UI tray/icon.
    StatusUpdate { status: String },
    /// The UI should respond with HEALTH_PONG over Pipe 3.
    HealthPing,
    /// The UI process is unhealthy — the agent will kill and respawn it.
    UiRespawn { session_id: u32 },
    /// The session is ending — the UI should run its closing sequence and exit.
    UiClosingSequence { session_id: u32 },
    /// Broadcast by the agent after each heartbeat attempt to dlp-server.
    /// The UI uses this to display Agent->Server connection state in the tray tooltip.
    ServerConnected { connected: bool },
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipe 3 — DLPEventUI2Agent (UI → agent, one-way)
// ─────────────────────────────────────────────────────────────────────────────

/// Messages sent FROM the UI TO the agent over Pipe 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Pipe3UiMsg {
    /// The UI is alive — sent in response to HEALTH_PING or periodically.
    HealthPong,
    /// The UI is initialised and ready.
    UiReady { session_id: u32 },
    /// The UI is closing (user logged out or closed voluntarily).
    UiClosing { session_id: u32 },
    /// Clipboard paste detected with sensitive content.
    ClipboardAlert {
        /// Session ID where the paste occurred.
        session_id: u32,
        /// Classification tier of the pasted content.
        classification: String,
        /// Truncated preview of the pasted text.
        preview: String,
        /// Total length of the pasted text.
        text_length: usize,
        /// Identity of the application that initiated the clipboard operation
        /// (populated by Phase 25's source-resolver).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_application: Option<AppIdentity>,
        /// Identity of the application that received the paste
        /// (populated by Phase 25's destination-resolver).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        destination_application: Option<AppIdentity>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::endpoint::{AppIdentity, AppTrustTier, SignatureState};

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
    fn test_clipboard_alert_none_fields_skipped_in_json() {
        let msg = Pipe3UiMsg::ClipboardAlert {
            session_id: 1,
            classification: "T3".to_string(),
            preview: "x".to_string(),
            text_length: 1,
            source_application: None,
            destination_application: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(!json.contains("source_application"), "json was: {json}");
        assert!(
            !json.contains("destination_application"),
            "json was: {json}"
        );
    }

    #[test]
    fn test_clipboard_alert_round_trip_with_app_identity() {
        let src = AppIdentity {
            image_path: r"C:\src.exe".to_string(),
            publisher: "Contoso".to_string(),
            trust_tier: AppTrustTier::Trusted,
            signature_state: SignatureState::Valid,
        };
        let msg = Pipe3UiMsg::ClipboardAlert {
            session_id: 3,
            classification: "T4".to_string(),
            preview: "secret".to_string(),
            text_length: 6,
            source_application: Some(src),
            destination_application: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("source_application"));
        assert!(!json.contains("destination_application"));
        let rt: Pipe3UiMsg = serde_json::from_str(&json).unwrap();
        match rt {
            Pipe3UiMsg::ClipboardAlert {
                session_id,
                source_application,
                destination_application,
                ..
            } => {
                assert_eq!(session_id, 3);
                assert_eq!(
                    source_application.as_ref().map(|a| a.publisher.as_str()),
                    Some("Contoso"),
                );
                assert!(destination_application.is_none());
            }
            _ => panic!("expected ClipboardAlert variant"),
        }
    }

    #[test]
    fn test_clipboard_alert_deserializes_legacy_payload() {
        // Payload as emitted by pre-Phase-22 UI processes -- no new fields.
        // Must still deserialize successfully (D-15 backward compat).
        let legacy = r#"{
            "type": "ClipboardAlert",
            "payload": {
                "session_id": 2,
                "classification": "T3",
                "preview": "hello",
                "text_length": 5
            }
        }"#;
        let msg: Pipe3UiMsg = serde_json::from_str(legacy).unwrap();
        match msg {
            Pipe3UiMsg::ClipboardAlert {
                session_id,
                source_application,
                destination_application,
                ..
            } => {
                assert_eq!(session_id, 2);
                assert!(source_application.is_none());
                assert!(destination_application.is_none());
            }
            _ => panic!("expected ClipboardAlert variant"),
        }
    }

    #[test]
    fn test_pipe2_toast_unchanged() {
        // D-16: Toast does NOT carry app identity.
        let toast = Pipe2AgentMsg::Toast {
            title: "Blocked".to_string(),
            body: "Clipboard content blocked".to_string(),
        };
        let json = serde_json::to_string(&toast).unwrap();
        assert!(!json.contains("source_application"));
        assert!(!json.contains("destination_application"));
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
