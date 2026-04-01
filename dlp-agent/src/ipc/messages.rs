//! IPC message types shared between the agent and UI.
//!
//! All messages are JSON-encoded and delimited by a 4-byte little-endian length prefix.
//! A frame is: `[u32:length][json:payload]` — exactly what `serde_json` produces when
//! combined with a manual length-prefix write/read.

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
}
