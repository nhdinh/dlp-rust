//! DLP Agent UI dialogs (T-43, T-44, T-45).
//!
//! Shows block notifications, clipboard dialog, stop-password dialog, and
//! closing-sequence dialogs to the user.

pub mod clipboard;
pub mod stop_password;

use tauri_plugin_notification::NotificationExt;
use tracing::info;
use windows::core::PCWSTR;
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONINFORMATION, MB_ICONWARNING, MESSAGEBOX_RESULT,
};

thread_local! {
    static TAURI_APP: std::cell::RefCell<Option<tauri::AppHandle>> =
        const { std::cell::RefCell::new(None) };
}

/// Stores the Tauri app handle so dialogs can use the notification plugin.
/// Must be called once during app setup.
pub fn init(app_handle: tauri::AppHandle) {
    TAURI_APP.with(|cell| *cell.borrow_mut() = Some(app_handle));
}

/// Shows a Windows toast notification with the given title and body.
pub fn show_toast(title: &str, body: &str) {
    if let Some(app) = TAURI_APP.with(|cell| cell.borrow().clone()) {
        if let Err(e) = app.notification().builder().title(title).body(body).show() {
            tracing::error!(error = %e, "failed to send toast notification");
        }
    }
}

/// Shows the block notification modal dialog and returns the user's choice.
///
/// - `Confirmed` — user pressed OK (IDOK = 1)
/// - `Close` — user dismissed the dialog without confirming
pub fn show_block_dialog_with_result(classification: &str, resource_path: &str, policy_id: &str, reason: &str) -> BlockDialogResult {
    info!(classification, resource_path, "showing block dialog");

    let body = format!(
        "A DLP policy blocked access to this resource.\n\n\
         Classification: {}\n\
         Resource: {}\n\
         Policy ID: {}\n\n\
         Reason: {}",
        classification, resource_path, policy_id, reason
    );

    let body_wide: Vec<u16> = body.encode_utf16().chain([0]).collect();
    let title_wide: Vec<u16> = "DLP: Access Blocked".encode_utf16().chain([0]).collect();

    // SAFETY: both pointers are valid for the duration of the call and reference
    // owned Vec data that lives until MessageBoxW returns.
    let result: MESSAGEBOX_RESULT = unsafe {
        MessageBoxW(
            None,
            PCWSTR::from_raw(body_wide.as_ptr()),
            PCWSTR::from_raw(title_wide.as_ptr()),
            MB_ICONWARNING,
        )
    };

    // IDOK = 1; treat everything else (Cancel, close button, timeout) as Close.
    if result.0 as u32 == 1 {
        BlockDialogResult::Confirmed
    } else {
        BlockDialogResult::Close
    }
}

/// Result of the block dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockDialogResult {
    /// User confirmed / accepted the block notification.
    Confirmed,
    /// User dismissed / closed the dialog without confirming.
    Close,
}

/// Shows the closing sequence notification when the agent requests UI shutdown.
pub fn show_closing_sequence() {
    let body = "The DLP Agent is shutting down. You may close this window.";
    let title = "DLP Agent";

    let body_wide: Vec<u16> = body.encode_utf16().chain([0]).collect();
    let title_wide: Vec<u16> = title.encode_utf16().chain([0]).collect();

    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR::from_raw(body_wide.as_ptr()),
            PCWSTR::from_raw(title_wide.as_ptr()),
            MB_ICONINFORMATION,
        );
    }
}
