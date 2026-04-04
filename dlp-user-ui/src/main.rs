#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> iced::Result {
    // --stop-password <request_id>: lightweight mode that shows only the
    // password dialog, sends the result over Pipe 1, and exits.
    // Used by the agent when no full UI is running during `sc stop`.
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--stop-password") {
        let request_id = args
            .get(pos + 1)
            .map(|s| s.as_str())
            .unwrap_or("stop-unknown");
        let response_path = args
            .get(pos + 2)
            .map(|s| s.as_str())
            .unwrap_or(r"C:\ProgramData\DLP\logs\stop-response.json");

        // Log to file since this runs from a SYSTEM-spawned process.
        let log = |msg: &str| {
            let _ = std::fs::create_dir_all(r"C:\ProgramData\DLP\logs");
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(r"C:\ProgramData\DLP\logs\stop-debug.log")
            {
                use std::io::Write;
                let _ = writeln!(f, "[UI] {msg}");
            }
        };

        log(&format!(
            "--stop-password started, request_id={request_id}, response_path={response_path}"
        ));

        match dlp_user_ui::run_stop_password(request_id, response_path) {
            Ok(()) => log("run_stop_password completed OK"),
            Err(e) => {
                log(&format!("run_stop_password FAILED: {e}"));
                eprintln!("[ERROR] stop-password failed: {e}");
            }
        }
        std::process::exit(0);
    }

    // --test-password-dialog: show the password dialog without IPC for
    // visual testing.
    if std::env::args().any(|a| a == "--test-password-dialog") {
        let request_id = "test-dialog-001";
        println!("Showing password dialog (request_id={request_id})...");
        println!("Type a password and click OK, or click Cancel.");
        match dlp_user_ui::dialogs::stop_password::show_password_dialog(request_id) {
            Ok(dlp_user_ui::ipc::messages::Pipe1UiMsg::PasswordSubmit {
                request_id: rid,
                password,
            }) => {
                println!("[OK] PasswordSubmit received");
                println!("  request_id: {rid}");
                println!("  password (DPAPI+base64): {} bytes", password.len());
            }
            Ok(dlp_user_ui::ipc::messages::Pipe1UiMsg::PasswordCancel {
                request_id: rid,
            }) => {
                println!("[CANCEL] PasswordCancel received (request_id={rid})");
            }
            Ok(other) => println!("[UNEXPECTED] {other:?}"),
            Err(e) => eprintln!("[ERROR] {e}"),
        }
        std::process::exit(0);
    }

    dlp_user_ui::run()
}
