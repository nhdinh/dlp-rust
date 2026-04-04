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
    use ipc::messages::Pipe1UiMsg;

    // Show the password dialog (blocks until the user acts).
    let result = dialogs::stop_password::show_password_dialog(request_id)?;

    // Write the response as JSON to the file the agent is polling.
    let json = match result {
        Pipe1UiMsg::PasswordSubmit { password, .. } => {
            format!(r#"{{"result":"submit","password":"{}"}}"#, password)
        }
        _ => r#"{"result":"cancel"}"#.to_string(),
    };

    std::fs::write(response_path, json)?;

    Ok(())
}
