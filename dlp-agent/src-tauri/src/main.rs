//! DLP Agent Tauri UI — entry point (T-39).
//!
//! In Tauri 2.x, `main.rs` is minimal — it just builds and runs the app.
//! All application logic lives in `ui_main.rs`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    dlp_agent_ui::run();
}
