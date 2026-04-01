//! `dlp-agent` — Windows Service DLP enforcement component.
//!
//! ## Crate structure
//!
//! - [`service`] — Windows Service lifecycle (Sprint 4, T-10): SCM registration,
//!   Start/Stop/Pause/Resume states, single-instance mutex, graceful shutdown.
//! - [`ui_spawner`] — Multi-session UI spawner (Sprint 5, T-30):
//!   `WTSEnumerateSessionsW` + `CreateProcessAsUser` + session change handling.
//! - [`ipc`] — Named-pipe IPC servers (Sprint 6, T-31–T-34):
//!   Pipe 1 (command), Pipe 2 (agent-to-UI), Pipe 3 (UI-to-agent).
//! - [`health_monitor`] — Mutual health ping-pong (Sprint 7, T-35).
//! - [`session_monitor`] — Session logon/logoff handler (Sprint 7, T-36).
//! - [`protection`] — Process DACL hardening (Sprint 8, T-37).
//! - [`interception`] — File interception engine (Sprint 13, T-11).
//! - [`detection`] — USB, SMB share, ETW bypass detection (Sprint 14, T-13–T-15).
//! - [`offline`] — Offline mode with cached decisions (Sprint 15, T-18).
//! - [`audit_emitter`] — Append-only audit log (Sprint 15, T-19, T-26, T-27).
//! - [`clipboard`] — Clipboard hooks and content classifier (Sprint 16, T-20).

pub mod prelude {
    pub use dlp_common::*;
}

#[cfg(windows)]
pub mod service;

#[cfg(windows)]
pub mod ui_spawner;

#[cfg(windows)]
pub mod ipc;

#[cfg(windows)]
pub mod health_monitor;

#[cfg(windows)]
pub mod session_monitor;

#[cfg(windows)]
pub mod password_stop;
