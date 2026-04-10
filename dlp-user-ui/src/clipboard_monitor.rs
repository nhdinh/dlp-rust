//! Clipboard monitoring for the DLP UI process.
//!
//! Runs a dedicated thread that listens for clipboard changes using
//! `AddClipboardFormatListener`.  When clipboard text changes, it is
//! classified using [`dlp_common::classify_text`].  If the content is
//! sensitive (T2+), a [`ClipboardAlert`] is sent to the agent via Pipe 3.
//!
//! ## Why in the UI process?
//!
//! The agent runs as SYSTEM in session 0, which cannot access the
//! interactive user's clipboard.  The UI runs in the user session and
//! has direct access to the clipboard.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tracing::{debug, info, warn};

/// Maximum preview length sent in clipboard alerts.
const PREVIEW_MAX: usize = 80;

/// Starts the clipboard monitoring thread.
///
/// The thread creates a message-only window, registers for clipboard
/// changes, and runs a message loop.  When clipboard text changes and
/// is classified as T2+, a `ClipboardAlert` is sent to the agent.
///
/// Returns a stop flag — set it to `true` to signal the thread to exit.
pub fn start(session_id: u32) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    std::thread::Builder::new()
        .name("clipboard-monitor".into())
        .spawn(move || {
            if let Err(e) = run_monitor(session_id, stop_clone) {
                warn!(error = %e, "clipboard monitor exited with error");
            }
        })
        .expect("clipboard-monitor thread must spawn");

    info!(session_id, "clipboard monitor started");
    stop
}

/// The clipboard monitoring loop.
///
/// Uses `AddClipboardFormatListener` to receive `WM_CLIPBOARDUPDATE`
/// messages when the clipboard changes.
fn run_monitor(session_id: u32, stop: Arc<AtomicBool>) -> anyhow::Result<()> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::DataExchange::{
        AddClipboardFormatListener, RemoveClipboardFormatListener,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DispatchMessageW, RegisterClassW, TranslateMessage, CW_USEDEFAULT, HMENU,
        MSG, WINDOW_EX_STYLE, WM_CLIPBOARDUPDATE, WNDCLASSW, WS_OVERLAPPED,
    };

    let class_name_str = "DLPClipboardMonitor\0";
    let class_name: Vec<u16> = class_name_str.encode_utf16().collect();

    let wndclass = WNDCLASSW {
        lpfnWndProc: Some(wndproc),
        lpszClassName: windows::core::PCWSTR::from_raw(class_name.as_ptr()),
        ..Default::default()
    };

    let atom = unsafe { RegisterClassW(&wndclass) };
    if atom == 0 {
        anyhow::bail!("RegisterClassW failed for clipboard monitor");
    }

    // Create a message-only window (HWND_MESSAGE parent).
    let hwnd = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            windows::core::PCWSTR::from_raw(class_name.as_ptr()),
            windows::core::PCWSTR::null(),
            WS_OVERLAPPED,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            // HWND_MESSAGE = -3 makes it a message-only window.
            HWND(-3_isize as *mut _),
            HMENU::default(),
            None,
            None,
        )?
    };

    // Register for clipboard change notifications.
    let registered = unsafe { AddClipboardFormatListener(hwnd) };
    if let Err(e) = registered {
        warn!(error = %e, "AddClipboardFormatListener failed");
        anyhow::bail!("AddClipboardFormatListener failed: {e}");
    }

    debug!("clipboard format listener registered");

    // Track the last clipboard text to avoid duplicate alerts.
    let mut last_hash: u64 = 0;

    let mut msg = MSG::default();
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        // Use PeekMessage with PM_REMOVE + a short sleep to allow
        // checking the stop flag between messages.
        let has_msg = unsafe {
            windows::Win32::UI::WindowsAndMessaging::PeekMessageW(
                &mut msg,
                None,
                0,
                0,
                windows::Win32::UI::WindowsAndMessaging::PM_REMOVE,
            )
        };

        if has_msg.as_bool() {
            if msg.message == WM_CLIPBOARDUPDATE {
                handle_clipboard_change(session_id, &mut last_hash);
            }
            unsafe {
                let _ = TranslateMessage(&msg);
                let _ = DispatchMessageW(&msg);
            }
        } else {
            // No message — sleep briefly to avoid busy-wait.
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    let _ = unsafe { RemoveClipboardFormatListener(hwnd) };
    debug!("clipboard monitor exiting");
    Ok(())
}

/// Called when the clipboard content changes.
///
/// Reads the clipboard text, classifies it, and sends an alert to the
/// agent if the content is T2 or higher.
fn handle_clipboard_change(session_id: u32, last_hash: &mut u64) {
    let text = match crate::dialogs::clipboard::read_clipboard() {
        Ok(Some(t)) if !t.is_empty() => t,
        _ => return,
    };

    // Simple hash to detect duplicate clipboard content.
    let hash = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        text.hash(&mut h);
        h.finish()
    };
    if hash == *last_hash {
        return; // same content — skip duplicate alert
    }
    *last_hash = hash;

    if let Some(tier_str) = classify_and_alert(session_id, &text) {
        info!(
            session_id,
            classification = tier_str,
            text_length = text.len(),
            "clipboard contains sensitive content"
        );
    }
}

/// Classifies `text` and, if the result is T2 or higher, emits a
/// `ClipboardAlert` to the agent via Pipe 3.
///
/// This helper is factored out of [`handle_clipboard_change`] so integration
/// tests can drive the full classify -> Pipe 3 path directly without having
/// to run a Win32 message loop. It intentionally performs **no** dedup —
/// callers (the live monitor) handle dedup upstream via the hash compare.
///
/// # Arguments
///
/// * `session_id` - The Windows session ID to attribute the alert to.
/// * `text` - The clipboard text to classify.
///
/// # Returns
///
/// * `Some(tier)` where `tier` is `"T2"`, `"T3"`, or `"T4"` when an alert
///   was attempted (even if the Pipe 3 send itself failed — failures are
///   logged via `tracing::warn!`, matching the live monitor's semantics).
/// * `None` if the text is empty or classifies as T1 (public) and no alert
///   was sent.
pub fn classify_and_alert(session_id: u32, text: &str) -> Option<&'static str> {
    // Empty text should never have been scheduled for classification,
    // but guard defensively so tests and callers cannot trigger a
    // zero-length alert.
    if text.is_empty() {
        return None;
    }

    let classification = dlp_common::classify_text(text);

    // Only alert on T2+. `is_sensitive()` returns true for T3/T4, but
    // we also want to alert on T2 ("Internal"), so compare explicitly.
    if classification < dlp_common::Classification::T2 {
        return None;
    }

    // Rust note: `chars().take(N).collect::<String>()` clamps on a code-point
    // boundary — unlike `&text[..N]` which would panic on a non-ASCII cut.
    let preview: String = text.chars().take(PREVIEW_MAX).collect();
    let tier_str: &'static str = match classification {
        dlp_common::Classification::T4 => "T4",
        dlp_common::Classification::T3 => "T3",
        dlp_common::Classification::T2 => "T2",
        dlp_common::Classification::T1 => return None,
    };

    if let Err(e) =
        crate::ipc::pipe3::send_clipboard_alert(session_id, tier_str, &preview, text.len())
    {
        warn!(error = %e, "failed to send clipboard alert to agent");
    }

    Some(tier_str)
}

/// Minimal window procedure — required by Windows but all real work
/// happens in the message loop above.
unsafe extern "system" fn wndproc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    windows::Win32::UI::WindowsAndMessaging::DefWindowProcW(hwnd, msg, wparam, lparam)
}
