//! `dlp-admin-cli` — Library crate for the DLP administration TUI.
//!
//! This library exposes the internal modules so that integration tests
//! in `dlp-e2e` can construct `App` instances, inject events, and
//! inspect rendered buffers without spawning a real terminal.
//!
//! The binary entry point remains `src/main.rs`.

pub mod app;
pub mod client;
pub mod engine;
pub mod event;
pub mod login;
pub mod registry;
pub mod screens;
pub mod tui;
