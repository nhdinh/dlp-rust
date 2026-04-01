//! DLP Agent Tauri UI — library root (T-39).
//!
//! Exposes `run()` which builds and runs the Tauri application.

mod dialogs;
mod ipc;
pub mod tray;
pub mod ui_main;

pub use ui_main::run;
