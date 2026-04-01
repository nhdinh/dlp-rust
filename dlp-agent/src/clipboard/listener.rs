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
//! - The hook is installed per-session by the UI subprocess (`dlp-user-ui`),
//!   not by the agent service directly.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use dlp_common::Classification;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::classifier::ClipboardClassifier;

/// Windows message constants used by the hook procedure at runtime.
#[allow(dead_code)]
const WM_PASTE: u32 = 0x0302;
#[allow(dead_code)]
const WM_CLIPBOARDUPDATE: u32 = 0x031D;

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
}

impl ClipboardListener {
    /// Constructs a new listener for the given session.
    pub fn new(session_id: u32) -> Self {
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            sender: Arc::new(Mutex::new(None)),
            session_id,
        }
    }

    /// Sets the event channel sender.
    ///
    /// Must be called before `start()`.  Events are sent to this channel
    /// when clipboard paste operations are detected and classified.
    pub fn set_sender(&self, tx: mpsc::Sender<ClipboardEvent>) {
        *self.sender.lock() = Some(tx);
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

    /// Stops the listener.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        info!(session_id = self.session_id, "clipboard listener stopped");
    }

    /// Returns `true` if the stop flag has been set.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::Acquire)
    }
}

impl Drop for ClipboardListener {
    fn drop(&mut self) {
        self.stop();
    }
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
