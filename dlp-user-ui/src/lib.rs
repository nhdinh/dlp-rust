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
/// dialog, connects to Pipe 1, sends the result (`PasswordSubmit` or
/// `PasswordCancel`), and exits.  Designed to be spawned by the agent
/// via `CreateProcessAsUserW` when `sc stop` is issued and no full UI
/// is running.
///
/// # Arguments
///
/// * `request_id` - The password request ID (passed by the agent).
///
/// # Errors
///
/// Returns an error if the pipe connection or dialog fails.
pub fn run_stop_password(request_id: &str) -> anyhow::Result<()> {
    use ipc::frame::write_frame;
    use ipc::messages::Pipe1UiMsg;

    // Step 1: resolve session ID.
    let session_id = unsafe {
        use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
        use windows::Win32::System::Threading::GetCurrentProcessId;
        let mut sid: u32 = 0;
        let _ = ProcessIdToSessionId(GetCurrentProcessId(), &mut sid);
        sid
    };

    // Step 2: connect to Pipe 1.
    let pipe = ipc::pipe1::open_pipe_pub()?;

    // Step 3: send RegisterSession so the agent recognises this client.
    let register = Pipe1UiMsg::RegisterSession { session_id };
    let register_json = serde_json::to_vec(&register)?;
    write_frame(pipe, &register_json)?;

    // Step 4: show the password dialog (blocks until user acts).
    let result = dialogs::stop_password::show_password_dialog(request_id)?;

    // Step 5: send the result over Pipe 1.
    let result_json = serde_json::to_vec(&result)?;
    write_frame(pipe, &result_json)?;

    // Step 6: close the pipe.
    ipc::frame::close_pipe(pipe);

    Ok(())
}
