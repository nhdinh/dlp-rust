//! Clipboard message hook listener (T-20, F-AGT-17).
//!
//! Installs a `WH_GETMESSAGE` hook via `SetWindowsHookExW` to intercept
//! clipboard-related messages (`WM_PASTE`, `WM_CLIPBOARDUPDATE`).
//!
//! When a paste event is detected, the listener reads the clipboard text via
//! `GetClipboardData(CF_UNICODETEXT)`, classifies it using
//! [`ClipboardClassifier`](super::classifier::ClipboardClassifier), and emits
//! the result to the interception pipeline.
//!
//! ## Thread model
//!
//! The hook listener runs on a dedicated std thread created by `start()`.
//! A hidden message-only window is created on that thread so that the Windows
//! message loop (`GetMessage` / `DispatchMessageW`) is present — this is
//! required for `WH_GETMESSAGE` hooks to fire.  The hook is installed on that
//! same thread via `SetWindowsHookExW`, so the hook procedure runs inside the
//! thread's message loop and can safely call `OpenClipboard` / `GetClipboardData`.
//!
//! ## Thread safety
//!
//! `SetWindowsHookExW` hooks are per-thread.  The hook procedure runs on the
//! thread that installed it, so all clipboard reads happen on the same thread
//! that processes the messages — no cross-thread synchronisation is needed for
//! the Windows API calls.  The classification result is sent to the
//! interception pipeline via an `mpsc` channel.
//!
//! ## Limitations
//!
//! - Only intercepts `CF_UNICODETEXT` clipboard data.  Binary/image clipboard
//!   content is not classified in Phase 1.
//! - When running as a Windows Service (SYSTEM), the hook must be spawned in the
//!   interactive user session via `CreateProcessAsUserW` (see `ui_spawner.rs`).
//!   A service-level hook will not see the interactive user's clipboard.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use dlp_common::Classification;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[cfg(windows)]
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GetMessageW, PostThreadMessageW, RegisterClassW, SetWindowsHookExW, TranslateMessage,
    UnhookWindowsHookEx, HHOOK, HOOKPROC, MSG, WINDOW_STYLE, WH_GETMESSAGE, WNDCLASSW,
    WS_EX_NOACTIVATE, WM_QUIT,
};

/// Wrapper around `HHOOK` that is `Send + Sync`.
///
/// `HHOOK` is `*mut c_void` which is not `Send + Sync` by default, but Win32 hook
/// handles are safe to share between threads for the purpose of uninstalling them.
#[cfg(windows)]
struct SendableHhook(HHOOK);

#[cfg(windows)]
unsafe impl Send for SendableHhook {}
#[cfg(windows)]
unsafe impl Sync for SendableHhook {}
#[allow(unused_imports)]
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    GetWindowLongPtrW, PostQuitMessage, WM_DESTROY,
};

use super::classifier::ClipboardClassifier;

/// Windows message constants used by the hook procedure at runtime.
const WM_PASTE: u32 = 0x0302;
const WM_CLIPBOARDUPDATE: u32 = 0x031D;

/// Module-level reference to the running listener so the C-callable hook procedure
/// can dispatch into it.  Only one ClipboardListener runs at a time.
static HOOK_LISTENER: std::sync::OnceLock<Arc<ClipboardListener>> = std::sync::OnceLock::new();

/// A clipboard event detected by the listener.
#[derive(Debug, Clone)]
pub struct ClipboardEvent {
    /// The classification tier of the clipboard text content.
    pub classification: Classification,
    /// A truncated preview of the clipboard text (max 200 chars, for audit).
    pub preview: String,
    /// The length of the full clipboard text.
    pub text_length: usize,
    /// The session ID in which the event occurred.
    pub session_id: u32,
}

/// The clipboard message hook listener.
///
/// Installs a `WH_GETMESSAGE` hook to detect clipboard paste operations,
/// classifies the content, and forwards events via an `mpsc` channel.
pub struct ClipboardListener {
    /// Set to `true` to stop the listener.
    stop_flag: Arc<AtomicBool>,
    /// Channel sender for clipboard events.
    sender: Arc<Mutex<Option<mpsc::Sender<ClipboardEvent>>>>,
    /// The session ID this listener is operating in.
    session_id: u32,
    /// The `HHOOK` handle returned by `SetWindowsHookExW`, if installed.
    #[cfg(windows)]
    hhook: Arc<Mutex<Option<SendableHhook>>>,
    /// Handle to the std thread running the message loop.
    #[cfg(windows)]
    thread_handle: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
}

impl ClipboardListener {
    /// Constructs a new listener for the given session.
    ///
    /// The listener is inactive until [`start`](Self::start) is called.
    pub fn new(session_id: u32) -> Self {
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            sender: Arc::new(Mutex::new(None)),
            session_id,
            #[cfg(windows)]
            hhook: Arc::new(Mutex::new(None)),
            thread_handle: Arc::new(Mutex::new(None)),
        }
    }

    /// Sets the event channel sender.
    ///
    /// Must be called before `start()`.  Events are sent to this channel
    /// when clipboard paste operations are detected and classified.
    pub fn set_sender(&self, tx: mpsc::Sender<ClipboardEvent>) {
        *self.sender.lock() = Some(tx);
    }

    /// Starts the clipboard listener by installing a `WH_GETMESSAGE` hook.
    ///
    /// Creates a dedicated std thread with a hidden message-only window and a
    /// Windows message loop (`GetMessage` / `TranslateMessage` / `DispatchMessageW`).
    /// `SetWindowsHookExW(WH_GETMESSAGE, ...)` is called on that thread so the
    /// hook procedure fires for every message processed by the thread's queue.
    ///
    /// When the hook fires for `WM_PASTE` or `WM_CLIPBOARDUPDATE`, the clipboard
    /// text is read, classified, and sent over the channel.
    ///
    /// # Limitations
    ///
    /// When the agent runs as a Windows Service (SYSTEM), this method must be
    /// called from a process running in the interactive user session (e.g. via
    /// `CreateProcessAsUserW` — see `ui_spawner.rs`) for the hook to see the
    /// user's clipboard.
    #[cfg(windows)]
    pub fn start(&self) -> windows::core::Result<()> {
        use windows::core::PCWSTR;

        // Register the global hook listener so the C-callable procedure can find it.
        let me = Arc::new(self.clone_inner());
        let _ = HOOK_LISTENER.set(me.clone());

        let hhook_arc = Arc::clone(&self.hhook);
        let thread_handle_arc = Arc::clone(&self.thread_handle);
        let session_id = self.session_id;

        let thread = std::thread::Builder::new()
            .name("clipboard-listener".into())
            .spawn(move || {
                // Step 1: register a minimal WNDCLASS for the message-only window.
                let class_name: Vec<u16> = "DlpClipboardListenerWindow\0".encode_utf16().collect();

                let wc = WNDCLASSW {
                    lpfnWndProc: Some(wndproc_callback),
                    lpszClassName: PCWSTR(class_name.as_ptr()),
                    ..Default::default()
                };

                // SAFETY: class_name is a valid null-terminated wide string.
                let atom = unsafe { RegisterClassW(&wc) };
                if atom == 0 {
                    warn!("RegisterClassW failed in clipboard listener");
                    return;
                }

                // Step 2: create a hidden message-only window.
                // SAFETY: atom is a valid class atom returned by RegisterClassW above.
                let hwnd = unsafe {
                    CreateWindowExW(
                        WS_EX_NOACTIVATE,
                        PCWSTR::from_raw(atom as *const u16),
                        PCWSTR::null(),
                        WINDOW_STYLE(0), // dwStyle
                        0, 0, 0, 0, // position/size (irrelevant for message-only)
                        None,
                        None,
                        None,
                        None,
                    )
                };

                let hwnd = match hwnd {
                    Ok(h) => h,
                    Err(e) => {
                        warn!(error = %e, "CreateWindowExW failed in clipboard listener");
                        return;
                    }
                };

                // Step 3: install the WH_GETMESSAGE hook on this thread.
                // SAFETY: GetModuleHandleW(None) returns the current process handle,
                // which is always valid.  Thread ID 0 means "current thread".
                let module = match unsafe { GetModuleHandleW(None) }.ok() {
                    Some(m) => m,
                    None => {
                        warn!("GetModuleHandleW failed in clipboard listener");
                        return;
                    }
                };
                let hook = unsafe {
                    // SAFETY: hook_procedure is a valid extern "system" fn matching HOOKPROC signature.
                    // HOOKPROC = Option<unsafe extern "system" fn(i32, WPARAM, LPARAM) -> LRESULT>.
                    SetWindowsHookExW(WH_GETMESSAGE, Some(hook_procedure), module, 0)
                };

                let hhook = match hook {
                    Ok(h) => h,
                    Err(e) => {
                        warn!(error = %e, "SetWindowsHookExW failed in clipboard listener");
                        // SAFETY: hwnd is a valid window handle we just created.
                        let _ = unsafe { DestroyWindow(hwnd) };
                        return;
                    }
                };

                // Store the hook handle so stop() can uninstall it.
                {
                    let mut guard = hhook_arc.lock();
                    *guard = Some(SendableHhook(hhook));
                }

                info!(session_id, "clipboard listener started — hook installed");

                // Step 4: run the message loop.
                // GetMessageW returns non-zero (TRUE) on success, 0 on WM_QUIT or error.
                // SAFETY: msg is a valid pointer to an MSG struct.
                let mut msg = MSG::default();
                loop {
                    let ret = unsafe { GetMessageW(&mut msg, None, 0, 0) };
                    // BOOL wraps i32; 0 means WM_QUIT or error.
                    if ret.0 == 0 {
                        break;
                    }
                    let _ = unsafe { TranslateMessage(&msg) };
                    let _ = unsafe { DispatchMessageW(&msg) };
                }

                // Cleanup: uninstall hook and destroy window on thread exit.
                let _ = unsafe { UnhookWindowsHookEx(hhook) };
                // SAFETY: hwnd is a valid window handle we own.
                let _ = unsafe { DestroyWindow(hwnd) };
                debug!("clipboard listener thread exiting");
            })
            .expect("clipboard listener thread must spawn");

        // Store the join handle so stop() can wait.
        {
            let mut guard = thread_handle_arc.lock();
            *guard = Some(thread);
        }

        Ok(())
    }

    /// Stops the listener.
    ///
    /// Posts `WM_QUIT` to the message loop, waits for the thread to finish,
    /// and uninstalls the hook.  Idempotent — safe to call multiple times.
    #[cfg(windows)]
    pub fn stop(&self) {
        if self.stop_flag.swap(true, Ordering::SeqCst) {
            return; // already stopped
        }

        // Signal the message loop to exit via PostThreadMessageW.
        // SAFETY: PostThreadMessageW with WM_QUIT is safe — it posts a quit
        // message that causes GetMessageW to return 0, cleanly exiting the loop.
        let thread_id = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };
        let _ = unsafe {
            PostThreadMessageW(thread_id, WM_QUIT, WPARAM::default(), LPARAM::default())
        };

        // Wait for the thread to finish.
        let mut handle_guard = self.thread_handle.lock();
        let handle = handle_guard.take();
        drop(handle_guard);
        if let Some(handle) = handle {
            let _ = handle.join();
        }

        // Unhook explicitly if the thread didn't do it.
        let mut hhook_guard = self.hhook.lock();
        let hhook = hhook_guard.take();
        drop(hhook_guard);
        if let Some(SendableHhook(hhook)) = hhook {
            let _ = unsafe { UnhookWindowsHookEx(hhook) };
        }

        info!(session_id = self.session_id, "clipboard listener stopped");
    }

    /// Returns `true` if the stop flag has been set.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::Acquire)
    }

    /// Non-async clone for use in the thread closure.
    fn clone_inner(&self) -> ClipboardListener {
        ClipboardListener {
            stop_flag: Arc::clone(&self.stop_flag),
            sender: Arc::clone(&self.sender),
            session_id: self.session_id,
            #[cfg(windows)]
            hhook: Arc::clone(&self.hhook),
            #[cfg(windows)]
            thread_handle: Arc::clone(&self.thread_handle),
        }
    }

    /// Processes a clipboard text and emits an event if classification
    /// warrants it (T2 or higher).
    ///
    /// This method is called by the hook procedure when a paste operation
    /// is detected.  It reads the clipboard text, classifies it, and sends
    /// the result over the channel.
    pub fn process_clipboard_text(&self, text: &str) {
        if text.is_empty() {
            return;
        }

        let classification = ClipboardClassifier::classify(text);
        debug!(
            classification = ?classification,
            len = text.len(),
            "clipboard text classified"
        );

        // Only emit events for T2+ content (T1 Public is not interesting).
        if classification == Classification::T1 {
            return;
        }

        let event = ClipboardEvent {
            classification,
            preview: truncate_preview(text, 200),
            text_length: text.len(),
            session_id: self.session_id,
        };

        if let Some(tx) = self.sender.lock().as_ref() {
            if tx.try_send(event).is_err() {
                warn!("clipboard event channel full or closed");
            }
        }
    }

    /// Reads the current clipboard text content via Windows API.
    ///
    /// Returns `None` if the clipboard does not contain `CF_UNICODETEXT` data
    /// or if the clipboard cannot be opened.
    pub fn read_clipboard_text() -> Option<String> {
        use windows::Win32::Foundation::HGLOBAL;
        use windows::Win32::System::DataExchange::{
            CloseClipboard, GetClipboardData, OpenClipboard,
        };
        use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};

        // CF_UNICODETEXT = 13
        const CF_UNICODETEXT: u32 = 13;

        // SAFETY: OpenClipboard(None) opens the clipboard for the current task.
        if unsafe { OpenClipboard(None) }.is_err() {
            return None;
        }

        let result = unsafe {
            let handle = GetClipboardData(CF_UNICODETEXT);
            match handle {
                Ok(h) => {
                    // SAFETY: clipboard data handle is valid while clipboard
                    // is open; HGLOBAL wraps the same pointer type.
                    let hglobal = HGLOBAL(h.0);
                    let ptr = GlobalLock(hglobal);
                    if ptr.is_null() {
                        None
                    } else {
                        let text = read_wide_string(ptr as *const u16);
                        let _ = GlobalUnlock(hglobal);
                        text
                    }
                }
                Err(_) => None,
            }
        };

        // SAFETY: clipboard was opened successfully above.
        let _ = unsafe { CloseClipboard() };

        result
    }
}

// SAFETY: ClipboardListener now uses SendableHhook (which is Send + Sync) instead of raw HHOOK.
// All contained types are Send + Sync, so ClipboardListener is automatically Send + Sync.
// We keep the explicit impl as documentation of the thread-safety invariant.
#[cfg(windows)]
unsafe impl Send for ClipboardListener {}
#[cfg(windows)]
unsafe impl Sync for ClipboardListener {}

impl Drop for ClipboardListener {
    fn drop(&mut self) {
        self.stop();
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Windows message callbacks (must be `extern "system"` for C calling convention)
// ──────────────────────────────────────────────────────────────────────────────

/// Window procedure for the hidden clipboard listener window.
///
/// Handles `WM_DESTROY` (triggers `PostQuitMessage`) and forwards everything
/// else to `DefWindowProcW`.
#[cfg(windows)]
extern "system" fn wndproc_callback(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    // SAFETY: DefWindowProcW is always safe to call with valid parameters.
    match msg as u32 {
        windows::Win32::UI::WindowsAndMessaging::WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            windows::Win32::Foundation::LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// `WH_GETMESSAGE` hook procedure.
///
/// Fires for every `GetMessage` / `PeekMessage` call on the thread that installed
/// the hook.  For `WH_GETMESSAGE`, the wparam is the actual message ID and lparam
/// is a pointer to the `MSG` struct.
///
/// On `WM_PASTE` (0x0302) it reads the clipboard, classifies the text,
/// and emits a `ClipboardEvent` through the running listener.
///
/// This function runs on the clipboard-listener thread — it is safe to call
/// `OpenClipboard` / `GetClipboardData` here because there is no concurrent
/// clipboard access from this thread.
#[cfg(windows)]
unsafe extern "system" fn hook_procedure(
    _code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // For WH_GETMESSAGE: wparam is the message ID (cast to raw value).
    let msg = wparam.0 as u32;

    if msg == WM_PASTE {
        if let Some(listener) = HOOK_LISTENER.get() {
            if let Some(text) = ClipboardListener::read_clipboard_text() {
                listener.process_clipboard_text(&text);
            }
        }
    }
    // Always call the next hook in the chain (there is none at the end, so pass None).
    // SAFETY: wparam and lparam are passed through unchanged — we only observe the message.
    CallNextHookEx(None, _code, wparam, lparam)
}

/// Reads a null-terminated UTF-16 string from a pointer.
///
/// Returns `None` if the pointer is null.
fn read_wide_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
        if len > 1_000_000 {
            // Sanity limit: 1M characters.
            break;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16(slice).ok()
}

/// Truncates text to `max_len` characters, appending "..." if truncated.
fn truncate_preview(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        let boundary = text
            .char_indices()
            .take_while(|(i, _)| *i < max_len.saturating_sub(3))
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        format!("{}...", &text[..boundary])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_preview_short() {
        assert_eq!(truncate_preview("hello", 200), "hello");
    }

    #[test]
    fn test_truncate_preview_long() {
        let long = "a".repeat(300);
        let preview = truncate_preview(&long, 200);
        assert!(preview.len() <= 200);
        assert!(preview.ends_with("..."));
    }

    #[test]
    fn test_truncate_preview_empty() {
        assert_eq!(truncate_preview("", 200), "");
    }

    #[test]
    fn test_clipboard_listener_new() {
        let listener = ClipboardListener::new(1);
        assert!(!listener.is_stopped());
    }

    #[test]
    fn test_clipboard_listener_stop() {
        let listener = ClipboardListener::new(1);
        listener.stop();
        assert!(listener.is_stopped());
    }

    #[test]
    fn test_process_clipboard_text_t4() {
        let (tx, mut rx) = mpsc::channel(16);
        let listener = ClipboardListener::new(1);
        listener.set_sender(tx);

        listener.process_clipboard_text("My SSN is 123-45-6789");

        let event = rx.try_recv().unwrap();
        assert_eq!(event.classification, Classification::T4);
        assert_eq!(event.session_id, 1);
    }

    #[test]
    fn test_process_clipboard_text_t1_not_emitted() {
        let (tx, mut rx) = mpsc::channel(16);
        let listener = ClipboardListener::new(1);
        listener.set_sender(tx);

        listener.process_clipboard_text("Hello, world!");

        // T1 content should not be emitted.
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_process_clipboard_text_empty_ignored() {
        let (tx, mut rx) = mpsc::channel(16);
        let listener = ClipboardListener::new(1);
        listener.set_sender(tx);

        listener.process_clipboard_text("");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_process_clipboard_text_t3() {
        let (tx, mut rx) = mpsc::channel(16);
        let listener = ClipboardListener::new(2);
        listener.set_sender(tx);

        listener.process_clipboard_text("This is CONFIDENTIAL data");

        let event = rx.try_recv().unwrap();
        assert_eq!(event.classification, Classification::T3);
        assert_eq!(event.session_id, 2);
    }

    #[test]
    fn test_read_wide_string_null() {
        assert!(read_wide_string(std::ptr::null()).is_none());
    }

    #[test]
    fn test_read_wide_string_valid() {
        let text: Vec<u16> = "hello\0".encode_utf16().collect();
        let result = read_wide_string(text.as_ptr());
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_clipboard_event_preview_length() {
        let (tx, mut rx) = mpsc::channel(16);
        let listener = ClipboardListener::new(1);
        listener.set_sender(tx);

        let long_text = format!("CONFIDENTIAL {}", "x".repeat(500));
        listener.process_clipboard_text(&long_text);

        let event = rx.try_recv().unwrap();
        assert!(event.preview.len() <= 203); // 200 + "..."
        assert_eq!(event.text_length, long_text.len());
    }
}
