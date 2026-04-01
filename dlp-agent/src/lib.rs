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
//! - [`identity`] — SMB impersonation resolution (Sprint 13, T-12).
//! - [`engine_client`] — HTTPS client to Policy Engine (Sprint 13, T-16).
//! - [`cache`] — Policy decision cache with TTL (Sprint 13, T-17).
//! - [`detection`] — USB, SMB share, ETW bypass detection (Sprint 14, T-13–T-15):
//!   - `detection::usb` — USB mass storage detection via `GetDriveTypeW`.
//!   - `detection::network_share` — SMB destination whitelisting.
//!   - `detection::etw_bypass` — Hook/ETW correlation for evasion detection.
//! - [`offline`] — Offline mode with fail-closed fallback (Sprint 15, T-18).
//! - [`audit_emitter`] — Append-only JSONL audit log with rotation (Sprint 15, T-19/T-26/T-27).
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

#[cfg(windows)]
pub mod interception;

#[cfg(windows)]
pub mod identity;

#[cfg(windows)]
pub mod engine_client;

#[cfg(windows)]
pub mod cache;

#[cfg(windows)]
pub mod detection;

#[cfg(windows)]
pub mod offline;

pub mod audit_emitter;
