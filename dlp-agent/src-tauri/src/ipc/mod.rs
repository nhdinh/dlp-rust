//! Named-pipe IPC client for the DLP Agent Tauri UI.
//!
//! Connects to three pipes exposed by the dlp-agent service:
//! - Pipe 1 (`\\.\pipe\DLPCommand`) — bidirectional command pipe (T-40).
//! - Pipe 3 (`\\.\pipe\DLPEventUI2Agent`) — UI → agent event pipe (T-42).
//!
//! Pipe 2 (`\\.\pipe\DLPEventAgent2UI`) — agent → UI events — is handled in
//! Sprint 11 (T-41).

pub mod frame;
pub mod messages;
pub mod pipe1;
pub mod pipe3;
