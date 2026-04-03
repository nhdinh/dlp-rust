//! DLP Agent endpoint UI — iced native GUI.
//!
//! Provides system tray, toast notifications, block dialogs, clipboard
//! reading, password-protected service stop, and IPC communication with
//! the dlp-agent Windows Service via three named pipes.

mod app;
pub mod dialogs;
pub mod ipc;
mod notifications;
mod tray;

/// Runs the DLP Agent UI application.
///
/// Initialises structured logging, detects the current Windows session ID,
/// sets up the system tray, starts named-pipe IPC tasks, and enters the
/// iced event loop.
///
/// # Errors
///
/// Returns an error if the iced application fails to start.
pub fn run() -> iced::Result {
    app::run()
}
