//! Pipe 3 client — connects to `\\.\pipe\DLPEventUI2Agent` (T-42).
//!
//! Sends UI-to-agent events: `UiReady`.

use anyhow::Result;
use dlp_common::AppIdentity;
use tracing::info;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_NO_BUFFERING, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::Storage::FileSystem::{OPEN_EXISTING, PIPE_ACCESS_OUTBOUND};

use super::frame::{flush, write_frame};
use super::messages::Pipe3UiMsg;

/// The default Win32 pipe name.
///
/// Tests may override this via the `DLP_PIPE3_NAME` environment variable
/// so they can point Pipe 3 at a mock named-pipe server on a unique name.
const PIPE_NAME_DEFAULT: &str = r"\\.\pipe\DLPEventUI2Agent";

/// Resolves the Pipe 3 name, allowing tests to override via `DLP_PIPE3_NAME`.
///
/// In production this always returns [`PIPE_NAME_DEFAULT`]. Integration
/// tests set `DLP_PIPE3_NAME` to a unique per-run name so they can spin
/// up a mock server without colliding with other tests or the real agent.
fn pipe_name() -> String {
    // Env var lookup is cheap (a single syscall) and only happens on the
    // short-lived connection open path — not inside any hot loop.
    std::env::var("DLP_PIPE3_NAME").unwrap_or_else(|_| PIPE_NAME_DEFAULT.to_string())
}

/// Opens a handle to Pipe 3.
fn open_pipe() -> Result<HANDLE> {
    let name = pipe_name();
    // Windows named-pipe paths are passed to Win32 as UTF-16 with a
    // trailing NUL terminator. Encode once here and keep the buffer
    // alive for the duration of the CreateFileW call.
    let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            PIPE_ACCESS_OUTBOUND.0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING,
            None,
        )
    };

    handle.map_err(|e| anyhow::anyhow!("CreateFileW on Pipe 3 failed: {}", e))
}

/// Connects to Pipe 3 and sends UiReady on the given session.
pub async fn send_ui_ready(session_id: u32) -> Result<()> {
    let handle = open_pipe()?;
    info!(session_id, "Pipe 3: connected, sending UiReady");

    let msg = Pipe3UiMsg::UiReady { session_id };
    let json = serde_json::to_vec(&msg).map_err(|e| anyhow::anyhow!("serialise UiReady: {}", e))?;
    write_frame(handle, &json)?;
    flush(handle)?;

    unsafe {
        let _ = CloseHandle(handle);
    }

    Ok(())
}

/// Sends a clipboard alert to the agent via Pipe 3.
///
/// Opens a new Pipe 3 connection for each alert (short-lived connection).
///
/// # Arguments
///
/// * `session_id` — Windows session ID.
/// * `classification` — Tier string: `"T2"`, `"T3"`, or `"T4"`.
/// * `preview` — First 80 chars of clipboard content.
/// * `text_length` — Full length of clipboard text in bytes.
/// * `source_application` — Resolved identity of the clipboard source app (APP-02).
///   `None` when `GetClipboardOwner` returned NULL.
/// * `destination_application` — Resolved identity of the paste-destination app (APP-01).
///   `None` when no foreground window was captured before this clipboard event.
///
/// # Errors
///
/// Returns an error if the Pipe 3 connection cannot be opened or the message
/// cannot be written.
pub fn send_clipboard_alert(
    session_id: u32,
    classification: &str,
    preview: &str,
    text_length: usize,
    source_application: Option<AppIdentity>,
    destination_application: Option<AppIdentity>,
) -> Result<()> {
    let handle = open_pipe()?;

    let msg = Pipe3UiMsg::ClipboardAlert {
        session_id,
        classification: classification.to_string(),
        preview: preview.to_string(),
        text_length,
        source_application,
        destination_application,
    };
    let json =
        serde_json::to_vec(&msg).map_err(|e| anyhow::anyhow!("serialise ClipboardAlert: {}", e))?;
    write_frame(handle, &json)?;
    flush(handle)?;

    unsafe {
        let _ = CloseHandle(handle);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::ipc::messages::Pipe3UiMsg;
    use dlp_common::{AppIdentity, AppTrustTier, SignatureState};

    #[test]
    fn test_clipboard_alert_with_identity_serializes_source_application_key() {
        // APP-05 validation: ClipboardAlert with Some(AppIdentity) must produce
        // JSON containing the "source_application" key.
        let alert = Pipe3UiMsg::ClipboardAlert {
            session_id: 1,
            classification: "T2".to_string(),
            preview: "test".to_string(),
            text_length: 4,
            source_application: Some(AppIdentity {
                image_path: "C:\\test.exe".to_string(),
                publisher: String::new(),
                trust_tier: AppTrustTier::Untrusted,
                signature_state: SignatureState::NotSigned,
            }),
            destination_application: None,
        };
        let json = serde_json::to_string(&alert).expect("serialization must not fail");
        assert!(
            json.contains("source_application"),
            "source_application key must appear in JSON when Some: got {json}"
        );
    }

    #[test]
    fn test_clipboard_alert_includes_identity_in_json() {
        // VALIDATION.md APP-05: full round-trip with both identity fields.
        let alert = Pipe3UiMsg::ClipboardAlert {
            session_id: 1,
            classification: "T2".to_string(),
            preview: "test".to_string(),
            text_length: 4,
            source_application: Some(AppIdentity {
                image_path: "C:\\test.exe".to_string(),
                publisher: String::new(),
                trust_tier: AppTrustTier::Untrusted,
                signature_state: SignatureState::NotSigned,
            }),
            destination_application: None,
        };
        let json = serde_json::to_string(&alert).expect("serialization must not fail");
        assert!(
            json.contains("source_application"),
            "source_application key must appear in JSON"
        );
    }

    #[test]
    fn test_clipboard_alert_without_identity_omits_source_application_key() {
        // skip_serializing_if = "Option::is_none": None fields must be absent from JSON.
        let alert = Pipe3UiMsg::ClipboardAlert {
            session_id: 1,
            classification: "T1".to_string(),
            preview: "hello".to_string(),
            text_length: 5,
            source_application: None,
            destination_application: None,
        };
        let json = serde_json::to_string(&alert).expect("serialization must not fail");
        assert!(
            !json.contains("source_application"),
            "source_application key must be absent when None: got {json}"
        );
    }
}
