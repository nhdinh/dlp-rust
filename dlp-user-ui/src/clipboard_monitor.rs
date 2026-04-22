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

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use dlp_common::AppIdentity;
use tracing::{debug, info, warn};

/// Previous-foreground window slot for destination identity capture (D-01, APP-01).
///
/// Updated by `foreground_event_proc` on every `EVENT_SYSTEM_FOREGROUND` event.
/// Read-and-cleared atomically by the `WM_CLIPBOARDUPDATE` handler via `swap(0)`.
///
/// A value of 0 means no foreground window has been captured since the last
/// clipboard event (slot cleared or hook not yet fired). An `HWND` is a
/// `*mut c_void` (pointer-sized), which fits in `usize` on both 32-bit and 64-bit
/// Windows targets.
///
/// # Thread safety
///
/// The slot is written by `foreground_event_proc` (on the clipboard-monitor
/// thread, delivered via the WinEvent subsystem) and read by the
/// `WM_CLIPBOARDUPDATE` handler (also on the clipboard-monitor thread). Both
/// run on the same OS thread — `Relaxed` ordering is sufficient because there
/// is no cross-thread visibility requirement. The `AtomicUsize` provides
/// compile-time `Sync` without a `Mutex`.
static FOREGROUND_SLOT: AtomicUsize = AtomicUsize::new(0);

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
fn run_monitor(
    session_id: u32,
    stop: Arc<AtomicBool>,
) -> anyhow::Result<()> {
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

    // Register WinEvent hook for foreground window tracking (D-01, APP-01).
    //
    // WINEVENT_OUTOFCONTEXT: callback runs in our process without DLL injection.
    // WINEVENT_SKIPOWNPROCESS: prevents DLP UI's own focus events (e.g., dialogs)
    // from poisoning the destination slot (PITFALL-A3).
    //
    // Thread affinity: SetWinEventHook MUST be called on a thread with a message
    // loop — the clipboard-monitor thread satisfies this (PeekMessageW loop below).
    // The callback is delivered on this same thread. Do NOT call from tokio tasks.
    use windows::Win32::UI::Accessibility::{SetWinEventHook, UnhookWinEvent};
    use windows::Win32::UI::WindowsAndMessaging::{
        EVENT_SYSTEM_FOREGROUND, WINEVENT_OUTOFCONTEXT, WINEVENT_SKIPOWNPROCESS,
    };

    let winevent_hook = unsafe {
        SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND, // eventMin: only foreground changes
            EVENT_SYSTEM_FOREGROUND, // eventMax: same event
            None,                    // hmodWinEventProc: None for OUTOFCONTEXT
            Some(foreground_event_proc),
            0, // idProcess: 0 = all processes
            0, // idThread: 0 = all threads
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        )
    };
    debug!("WinEvent hook registered for foreground tracking");

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
                // Capture source identity synchronously — BEFORE handle_clipboard_change.
                // GetClipboardOwner must be called here (D-03, APP-02): the source
                // process may exit within milliseconds of setting clipboard data.
                // Returns windows_core::Result<HWND> — Err means NULL (no owner).
                let source_hwnd: Option<windows::Win32::Foundation::HWND> = unsafe {
                    windows::Win32::System::DataExchange::GetClipboardOwner().ok()
                };

                // Read-and-clear the foreground slot atomically (D-01, APP-01).
                // swap(0) returns the previous value and resets the slot to 0 in
                // one operation — no separate load + store needed.
                let dest_raw = FOREGROUND_SLOT.swap(0, Ordering::Relaxed);
                let dest_hwnd: Option<windows::Win32::Foundation::HWND> = if dest_raw != 0 {
                    // Reconstruct HWND from usize. The cast is the inverse of the
                    // store in foreground_event_proc (hwnd.0 as usize).
                    Some(windows::Win32::Foundation::HWND(
                        dest_raw as *mut core::ffi::c_void,
                    ))
                } else {
                    None
                };

                handle_clipboard_change(
                    session_id,
                    &mut last_hash,
                    source_hwnd,
                    dest_hwnd,
                );
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

    // Unhook the WinEvent hook before exiting — must be called on the same
    // thread that registered it (clipboard-monitor thread). Behavior is
    // undefined if called from a different thread.
    let _ = unsafe { UnhookWinEvent(winevent_hook) };
    let _ = unsafe { RemoveClipboardFormatListener(hwnd) };
    debug!("clipboard monitor exiting");
    Ok(())
}

/// WinEvent callback for `EVENT_SYSTEM_FOREGROUND`.
///
/// Invoked by the WinEvent subsystem when any window gains foreground focus.
/// Stores the newly-foreground HWND in `FOREGROUND_SLOT` so the next
/// `WM_CLIPBOARDUPDATE` handler can read it as the destination application.
///
/// # Thread affinity
///
/// Delivered on the same thread that called `SetWinEventHook` — the
/// clipboard-monitor thread — so no cross-thread synchronization is needed
/// beyond the `AtomicUsize` store.
///
/// # Safety
///
/// This is an `unsafe extern "system"` function required by the Windows
/// callback ABI. All parameters are Win32-provided and are only used for
/// the `HWND` value extraction. No owned resources are created.
#[cfg(windows)]
unsafe extern "system" fn foreground_event_proc(
    _hook: windows::Win32::UI::Accessibility::HWINEVENTHOOK,
    _event: u32,
    hwnd: windows::Win32::Foundation::HWND,
    _id_object: i32,
    _id_child: i32,
    _event_thread: u32,
    _event_time: u32,
) {
    // Store the HWND as usize. HWND is *mut c_void — `.0` accesses the raw
    // pointer field. This cast is valid on all Windows 32/64-bit targets.
    FOREGROUND_SLOT.store(hwnd.0 as usize, Ordering::Relaxed);
}

/// Called when the clipboard content changes.
///
/// Reads the clipboard text, classifies it, and sends an alert to the
/// agent if the content is T2 or higher.
fn handle_clipboard_change(
    session_id: u32,
    last_hash: &mut u64,
    source_hwnd: Option<windows::Win32::Foundation::HWND>,
    dest_hwnd: Option<windows::Win32::Foundation::HWND>,
) {
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

    // Resolve source and destination application identities (APP-01, APP-02).
    //
    // This runs on the dedicated clipboard-monitor std::thread — NOT a Tokio
    // async task — so calling blocking Win32 APIs (WinVerifyTrust) directly is
    // correct. There is no Tokio executor to starve here.
    let source_identity = crate::detection::app_identity::resolve_app_identity(source_hwnd);

    // D-02: Intra-app copy — if source and dest share the same PID, clone
    // source identity instead of making a second verify_and_cache call.
    let dest_identity = match dest_hwnd {
        None => None,
        Some(dh) => {
            let source_pid = source_hwnd
                .map(crate::detection::app_identity::hwnd_to_pid)
                .unwrap_or(0);
            let dest_pid = crate::detection::app_identity::hwnd_to_pid(dh);

            if source_pid != 0 && source_pid == dest_pid {
                source_identity.clone()
            } else {
                crate::detection::app_identity::resolve_app_identity(Some(dh))
            }
        }
    };

    if let Some(tier_str) = classify_and_alert(session_id, &text, source_identity, dest_identity) {
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
/// * `source_identity` - Resolved identity of the clipboard source application (APP-02).
///   `None` when `GetClipboardOwner` returned NULL.
/// * `dest_identity` - Resolved identity of the paste-destination application (APP-01).
///   `None` when no foreground window was captured in `FOREGROUND_SLOT`.
///
/// # Returns
///
/// * `Some(tier)` where `tier` is `"T2"`, `"T3"`, or `"T4"` when an alert
///   was attempted (even if the Pipe 3 send itself failed — failures are
///   logged via `tracing::warn!`, matching the live monitor's semantics).
/// * `None` if the text is empty or classifies as T1 (public) and no alert
///   was sent.
pub fn classify_and_alert(
    session_id: u32,
    text: &str,
    source_identity: Option<AppIdentity>,
    dest_identity: Option<AppIdentity>,
) -> Option<&'static str> {
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

    if let Err(e) = crate::ipc::pipe3::send_clipboard_alert(
        session_id,
        tier_str,
        &preview,
        text.len(),
        source_identity,
        dest_identity,
    ) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_foreground_slot_store_and_swap() {
        // Simulate foreground_event_proc storing a value.
        FOREGROUND_SLOT.store(0xDEAD_BEEF, Ordering::Relaxed);
        // WM_CLIPBOARDUPDATE read-and-clear.
        let prev = FOREGROUND_SLOT.swap(0, Ordering::Relaxed);
        assert_eq!(prev, 0xDEAD_BEEF, "swap must return stored HWND value");
        // Slot must be cleared after swap.
        assert_eq!(
            FOREGROUND_SLOT.load(Ordering::Relaxed),
            0,
            "slot must be 0 after swap(0)"
        );
    }

    #[test]
    fn test_foreground_slot_empty_gives_zero() {
        FOREGROUND_SLOT.store(0, Ordering::Relaxed);
        let val = FOREGROUND_SLOT.swap(0, Ordering::Relaxed);
        assert_eq!(val, 0, "empty slot must return 0");
    }

    #[test]
    fn test_classify_and_alert_with_none_identities_returns_tier_for_sensitive() {
        // Backward compat: None, None identities must not break classification.
        // "password: secret123" classifies as T3 in the existing classifier.
        let result = classify_and_alert(1, "password: secret123", None, None);
        assert!(result.is_some(), "T3 content must produce Some(tier)");
    }

    #[test]
    fn test_classify_and_alert_with_none_identities_returns_none_for_t1() {
        let result = classify_and_alert(1, "hello world", None, None);
        assert!(result.is_none(), "T1 content must produce None");
    }

    #[test]
    fn test_intraapp_copy_dest_equals_source_identity() {
        use dlp_common::{AppIdentity, AppTrustTier, SignatureState};
        // D-02: same PID -> dest identity = source identity clone.
        // We test the clone logic in isolation using AppIdentity directly.
        let source = AppIdentity {
            image_path: r"C:\Windows\System32\notepad.exe".to_string(),
            publisher: "Microsoft Corporation".to_string(),
            trust_tier: AppTrustTier::Trusted,
            signature_state: SignatureState::Valid,
        };
        let dest = source.clone();
        assert_eq!(source, dest, "intra-app dest must equal source clone");
    }
}
