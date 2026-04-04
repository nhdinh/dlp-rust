//! DLP Agent UI dialogs (T-43, T-44, T-45).
//!
//! Shows block notifications, clipboard dialog, stop-password dialog, and
//! closing-sequence dialogs to the user.

pub mod clipboard;
pub mod override_request;
pub mod stop_password;

use tracing::info;
use windows::core::PCWSTR;
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONINFORMATION, MB_ICONWARNING, MESSAGEBOX_RESULT,
};

/// Shows the block notification modal dialog and returns the user's
/// choice.
///
/// - `Confirmed` -- user pressed OK (IDOK = 1)
/// - `Close` -- user dismissed the dialog without confirming
///
/// # Arguments
///
/// * `classification` - Data classification tier (T1-T4)
/// * `resource_path` - Path to the blocked resource
/// * `policy_id` - ID of the policy that triggered the block
/// * `reason` - Human-readable reason for the block
pub fn show_block_dialog_with_result(
    classification: &str,
    resource_path: &str,
    policy_id: &str,
    reason: &str,
) -> BlockDialogResult {
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
    let title_wide: Vec<u16> =
        "DLP: Access Blocked".encode_utf16().chain([0]).collect();

    // SAFETY: both pointers are valid for the duration of the call
    // and reference owned Vec data that lives until MessageBoxW
    // returns.
    let result: MESSAGEBOX_RESULT = unsafe {
        MessageBoxW(
            None,
            PCWSTR::from_raw(body_wide.as_ptr()),
            PCWSTR::from_raw(title_wide.as_ptr()),
            MB_ICONWARNING,
        )
    };

    // IDOK = 1; treat everything else as Close.
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

/// Shows the closing sequence notification when the agent requests UI
/// shutdown.
pub fn show_closing_sequence() {
    let body =
        "The DLP Agent is shutting down. You may close this window.";
    let title = "DLP Agent";

    let body_wide: Vec<u16> = body.encode_utf16().chain([0]).collect();
    let title_wide: Vec<u16> =
        title.encode_utf16().chain([0]).collect();

    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR::from_raw(body_wide.as_ptr()),
            PCWSTR::from_raw(title_wide.as_ptr()),
            MB_ICONINFORMATION,
        );
    }
}
