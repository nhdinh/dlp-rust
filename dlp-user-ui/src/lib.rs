//! DLP Agent endpoint UI — iced native GUI.
//!
//! Provides system tray, toast notifications, block dialogs, clipboard
//! reading, password-protected service stop, and IPC communication with
//! the dlp-agent Windows Service via three named pipes.

mod app;
pub mod clipboard_monitor;
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

/// Lightweight stop-password mode.
///
/// Skips all iced / tray / IPC initialization.  Shows the Win32 password
/// dialog and writes the result to `response_path` as JSON.  The agent
/// polls this file to receive the response.
///
/// This avoids Pipe 1 entirely because synchronous `ReadFile`/`WriteFile`
/// on the same named-pipe handle deadlock (Windows serializes I/O on
/// synchronous handles).
///
/// # Arguments
///
/// * `request_id` - The password request ID (passed by the agent).
/// * `response_path` - File path where the result JSON is written.
///
/// # Errors
///
/// Returns an error if the dialog or file write fails.
pub fn run_stop_password(request_id: &str, response_path: &str) -> anyhow::Result<()> {
    // Show the password dialog (blocks until the user acts).
    // We use the dialog but extract the plaintext password directly
    // (no DPAPI), since the response file is only accessible by
    // SYSTEM/Admins and DPAPI user-context keys are not readable
    // by the SYSTEM service.
    let password_text = dialogs::stop_password::show_password_dialog_plaintext(request_id)?;

    let json = match password_text {
        Some(pw) => {
            // Base64-encode the UTF-8 password for safe JSON transport
            // (avoids escaping issues with special characters).
            let b64 = dialogs::stop_password::base64_encode(pw.as_bytes());
            format!(r#"{{"result":"submit","password":"{b64}","encoding":"base64-utf8"}}"#)
        }
        None => r#"{"result":"cancel"}"#.to_string(),
    };

    std::fs::write(response_path, json)?;

    Ok(())
}
