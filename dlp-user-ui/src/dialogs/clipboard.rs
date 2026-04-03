//! Clipboard dialog — reads clipboard content and returns it to the agent (T-44).
//!
//! Triggered by `Pipe1AgentMsg::ClipboardRead`.  Reads the Windows clipboard
//! using the Unicode text format (`CF_UNICODETEXT`).

use anyhow::Result;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
use windows::Win32::System::Ole::CF_UNICODETEXT;

/// Reads the current Windows clipboard content as a UTF-8 string.
///
/// Returns `None` if the clipboard is empty or contains non-text data.
pub fn read_clipboard() -> Result<Option<String>> {
    // SAFETY: OpenClipboard/CloseClipboard are called as a pair; we always close.
    unsafe {
        if OpenClipboard(None).is_err() {
            return Ok(None);
        }
    }

    // SAFETY: clipboard is open; we hold it until CloseClipboard.
    let text = unsafe {
        let handle: HANDLE = GetClipboardData(CF_UNICODETEXT.0 as u32)?;
        if handle.is_invalid() {
            let _ = CloseClipboard();
            return Ok(None);
        }

        let ptr = handle.0 as *const u16;
        if ptr.is_null() {
            let _ = CloseClipboard();
            return Ok(None);
        }

        // Walk the null-terminated UTF-16 string.
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }

        let slice = std::slice::from_raw_parts(ptr, len);
        let text = String::from_utf16(slice).ok();
        let _ = CloseClipboard();
        text
    };

    Ok(text)
}
