//! DLP Agent UI dialogs (T-43).
//!
//! Shows block notifications, override justification, and closing-sequence
//! dialogs to the user.  Uses Windows toast notifications via the Tauri
//! notification plugin, and blocking modal dialogs via `MessageBoxW`.

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

/// Retrieves the Tauri app handle from thread-local state.
fn get_tauri_app() -> Option<tauri::AppHandle> {
    TAURI_APP.with(|cell| cell.borrow().clone())
}

/// Stores the Tauri app handle so dialogs can use the notification plugin.
/// Must be called once during app setup.
pub fn init(app_handle: tauri::AppHandle) {
    TAURI_APP.with(|cell| *cell.borrow_mut() = Some(app_handle));
}

/// Shows a Windows toast notification with the given title and body.
pub fn show_toast(title: &str, body: &str) {
    if let Some(app) = get_tauri_app() {
        if let Err(e) = app.notification().builder().title(title).body(body).show() {
            tracing::error!(error = %e, "failed to send toast notification");
        }
    }
}

/// Shows the block notification modal dialog.
///
/// Displays policy info, classification level, and resource path.  Provides
/// "OK" button to acknowledge.
pub fn show_block_dialog(
    classification: &str,
    resource_path: &str,
    policy_name: &str,
    reason: &str,
) -> BlockDialogResult {
    info!(classification, resource_path, "showing block dialog");

    let body = format!(
        "A DLP policy blocked access to this resource.\n\n\
         Classification: {}\n\
         Resource: {}\n\
         Policy: {}\n\n\
         Reason: {}",
        classification, resource_path, policy_name, reason
    );
    let title = "DLP: Access Blocked";

    let body_wide: Vec<u16> = body.encode_utf16().chain(std::iter::once(0)).collect();
    let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();

    let result: MESSAGEBOX_RESULT = unsafe {
        MessageBoxW(
            None,
            PCWSTR::from_raw(body_wide.as_ptr()),
            PCWSTR::from_raw(title_wide.as_ptr()),
            MB_ICONWARNING,
        )
    };

    // Only IDOK (1) and IDCANCEL (2) are returned; both dismiss the dialog.
    let _ = result;
    BlockDialogResult::Close
}

/// Result of the block dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum BlockDialogResult {
    Close,
}

/// Shows the closing sequence notification when the agent requests UI shutdown.
pub fn show_closing_sequence() {
    let body = "The DLP Agent is shutting down. You may close this window.";
    let title = "DLP Agent";

    let body_wide: Vec<u16> = body.encode_utf16().chain(std::iter::once(0)).collect();
    let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR::from_raw(body_wide.as_ptr()),
            PCWSTR::from_raw(title_wide.as_ptr()),
            MB_ICONINFORMATION,
        );
    }
}
