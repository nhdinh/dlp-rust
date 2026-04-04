#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> iced::Result {
    // --test-password-dialog: show the password dialog without starting
    // the full iced application.  Useful for visual testing.
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
