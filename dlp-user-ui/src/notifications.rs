//! Toast notifications via the Windows Runtime notification API.
//!
//! Replaces the former Tauri notification plugin with `winrt-notification`
//! for displaying Windows 10/11 toast notifications.

/// Shows a Windows toast notification with the given title and body.
///
/// Uses the PowerShell App ID as the notification source, which is
/// always registered on Windows 10+.
///
/// # Arguments
///
/// * `title` - The notification title displayed in bold
/// * `body` - The notification body text
pub fn show_toast(title: &str, body: &str) {
    if let Err(e) =
        winrt_notification::Toast::new(
            winrt_notification::Toast::POWERSHELL_APP_ID,
        )
        .title(title)
        .text1(body)
        .show()
    {
        tracing::error!(
            error = %e,
            "failed to show toast notification"
        );
    }
}
