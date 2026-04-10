//! IPC message types for the iced UI — mirrors dlp-agent/src/ipc/messages.rs.
//!
//! The UI connects to the same pipes as the agent and exchanges the same
//! message types.  Since dlp-agent and dlp-user-ui are separate crates,
//! the message types are duplicated here.

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
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipe 2 — DLPEventAgent2UI (agent → UI)
// ─────────────────────────────────────────────────────────────────────────────

/// Messages sent FROM the agent TO the UI over Pipe 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
#[allow(dead_code)]
pub enum Pipe2AgentMsg {
    Toast { title: String, body: String },
    StatusUpdate { status: String },
    HealthPing,
    UiRespawn { session_id: u32 },
    UiClosingSequence { session_id: u32 },
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
    UiReady { session_id: u32 },
    UiClosing { session_id: u32 },
    ClipboardAlert {
        session_id: u32,
        classification: String,
        preview: String,
        text_length: usize,
    },
}
