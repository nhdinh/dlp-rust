//! Stop-password dialog -- prompts the admin for credentials (T-45).
//!
//! Triggered by `Pipe1AgentMsg::PasswordDialog`.  Uses `DialogBoxIndirectParamW`
//! with an in-memory `DLGTEMPLATE` to display a password field.  The password
//! bytes are DPAPI-wrapped (`CryptProtectData`) before being sent to the agent.
//!
//! ## Dialog layout
//!
//! ```text
//! +------------------------------------------+
//! | DLP Agent: Confirm Stop            [X]   |
//! |                                          |
//! |  Enter your DLP Admin password to stop   |
//! |  the service:                            |
//! |                                          |
//! |  [****************************]          |
//! |                                          |
//! |         [ OK ]    [ Cancel ]             |
//! +------------------------------------------+
//! ```

use std::cell::RefCell;
use std::ptr;

use windows::Win32::Foundation::{HMODULE, HWND, LPARAM, WPARAM};
use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows::Win32::UI::WindowsAndMessaging::{
    DialogBoxIndirectParamW, EndDialog, GetDlgItem, GetWindowTextLengthW, GetWindowTextW,
    DLGTEMPLATE, IDCANCEL, IDOK, WM_COMMAND, WM_INITDIALOG,
};

/// Control ID for the password edit field.
const IDC_PASSWORD: u16 = 100;

// -------- Thread-local state for the dialog procedure --------
//
// The `dlg_proc` callback runs on the same thread as `DialogBoxIndirectParamW`.
// We store the captured password here BEFORE calling `EndDialog`, because the
// dialog HWND becomes invalid after `EndDialog` destroys the window.

thread_local! {
    /// Password text captured from the edit control during WM_COMMAND/IDOK.
    static CAPTURED_PASSWORD: RefCell<Option<Vec<u16>>> = const { RefCell::new(None) };
}

// ---------- Dialog template builder ----------
//
// Builds a DLGTEMPLATE + 4 DLGITEMTEMPLATE items in a byte buffer.
// Memory layout follows the Win32 spec:
//   https://learn.microsoft.com/en-us/windows/win32/dlgbox/dlgtemplateex
//
// DLGITEMTEMPLATE struct (18 bytes):
//   style: u32, exstyle: u32, x: i16, y: i16, cx: i16, cy: i16, id: u16
// Followed by:
//   class (sz_Or_Ord), title (sz_Or_Ord), extraCount: u16

/// Builds the in-memory dialog template.
///
/// # Arguments
///
/// * `title` - Dialog window title
/// * `prompt` - Static text shown above the password field
fn build_dlgtemplate(title: &str, prompt: &str) -> Vec<u8> {
    let mut t = Vec::with_capacity(512);

    // -- DLGTEMPLATE header --
    // WS_POPUP (0x80000000) | WS_VISIBLE (0x10000000) | WS_CAPTION (0x00C00000)
    // | WS_SYSMENU (0x00080000) | DS_MODALFRAME (0x80) | DS_SETFONT (0x40)
    // | DS_CENTER (0x0800)
    push_u32(&mut t, 0x90C808C0);
    push_u32(&mut t, 0); // extended style
    push_u16(&mut t, 4); // number of controls
    push_i16(&mut t, 0); // x
    push_i16(&mut t, 0); // y
    push_i16(&mut t, 240); // cx (dialog units)
    push_i16(&mut t, 90); // cy (dialog units)
    push_u16(&mut t, 0); // menu (none)
    push_u16(&mut t, 0); // window class (default)
    push_wstr(&mut t, title);
    push_u16(&mut t, 9); // font point size
    push_wstr(&mut t, "Segoe UI");

    // -- Item 1: Static prompt label --
    align4(&mut t);
    push_u32(&mut t, 0x50000000 | 0x0001); // WS_CHILD | WS_VISIBLE | SS_CENTER
    push_u32(&mut t, 0); // exstyle
    push_i16(&mut t, 10); // x
    push_i16(&mut t, 10); // y
    push_i16(&mut t, 220); // cx
    push_i16(&mut t, 20); // cy
    push_u16(&mut t, 0xFFFF); // id (static -- don't care)
    push_u16(&mut t, 0xFFFF); // class atom prefix
    push_u16(&mut t, 0x0082); // STATIC class ordinal
    push_wstr(&mut t, prompt);
    push_u16(&mut t, 0); // extra count

    // -- Item 2: Password edit control --
    align4(&mut t);
    // WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL
    push_u32(&mut t, 0x50010000 | 0x00800000 | 0x00200000 | 0x20 | 0x80);
    push_u32(&mut t, 0x00000200); // WS_EX_CLIENTEDGE (sunken border)
    push_i16(&mut t, 20); // x
    push_i16(&mut t, 34); // y
    push_i16(&mut t, 200); // cx
    push_i16(&mut t, 14); // cy
    push_u16(&mut t, IDC_PASSWORD); // id = 100
    push_u16(&mut t, 0xFFFF); // class atom prefix
    push_u16(&mut t, 0x0081); // EDIT class ordinal
    push_u16(&mut t, 0); // title (empty)
    push_u16(&mut t, 0); // extra count

    // -- Item 3: OK button (IDOK = 1) --
    align4(&mut t);
    // WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON
    push_u32(&mut t, 0x50010000 | 0x0001);
    push_u32(&mut t, 0); // exstyle
    push_i16(&mut t, 50); // x
    push_i16(&mut t, 60); // y
    push_i16(&mut t, 60); // cx
    push_i16(&mut t, 14); // cy
    push_u16(&mut t, IDOK.0 as u16); // id = 1
    push_u16(&mut t, 0xFFFF); // class atom prefix
    push_u16(&mut t, 0x0080); // BUTTON class ordinal
    push_wstr(&mut t, "OK");
    push_u16(&mut t, 0); // extra count

    // -- Item 4: Cancel button (IDCANCEL = 2) --
    align4(&mut t);
    // WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON
    push_u32(&mut t, 0x50010000);
    push_u32(&mut t, 0); // exstyle
    push_i16(&mut t, 130); // x
    push_i16(&mut t, 60); // y
    push_i16(&mut t, 60); // cx
    push_i16(&mut t, 14); // cy
    push_u16(&mut t, IDCANCEL.0 as u16); // id = 2
    push_u16(&mut t, 0xFFFF); // class atom prefix
    push_u16(&mut t, 0x0080); // BUTTON class ordinal
    push_wstr(&mut t, "Cancel");
    push_u16(&mut t, 0); // extra count

    t
}

fn push_u16(v: &mut Vec<u8>, w: u16) {
    v.extend_from_slice(&w.to_le_bytes());
}

fn push_i16(v: &mut Vec<u8>, w: i16) {
    push_u16(v, w as u16);
}

fn push_u32(v: &mut Vec<u8>, w: u32) {
    v.extend_from_slice(&w.to_le_bytes());
}

fn push_wstr(v: &mut Vec<u8>, s: &str) {
    for c in s.encode_utf16() {
        push_u16(v, c);
    }
    push_u16(v, 0);
}

fn align4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

// ---------- Dialog procedure ----------

/// Reads the password text from the edit control and stores it in the
/// thread-local `CAPTURED_PASSWORD`.  Called from the `WM_COMMAND` handler
/// BEFORE `EndDialog` destroys the window.
unsafe fn capture_password_text(hwnd: HWND) {
    let Ok(edit) = GetDlgItem(hwnd, IDC_PASSWORD as i32) else {
        return;
    };

    let len = GetWindowTextLengthW(edit) as usize;
    if len == 0 {
        return;
    }

    // GetWindowTextW writes at most `len` chars + null terminator.
    let mut buf = vec![0u16; len + 1];
    let copied = GetWindowTextW(edit, &mut buf);
    if copied > 0 {
        buf.truncate(copied as usize);
        CAPTURED_PASSWORD.with(|cell| {
            *cell.borrow_mut() = Some(buf);
        });
    }
}

/// Win32 dialog procedure for the password dialog.
///
/// SAFETY: called by Windows on the thread that called
/// `DialogBoxIndirectParamW`.  All window handles are valid for the
/// duration of each message.
unsafe extern "system" fn dlg_proc(hwnd: HWND, msg: u32, wparam: WPARAM, _lparam: LPARAM) -> isize {
    match msg {
        WM_INITDIALOG => {
            // Focus the password edit control so the user can type immediately.
            if let Ok(edit_hwnd) = GetDlgItem(hwnd, IDC_PASSWORD as i32) {
                let _ = SetFocus(edit_hwnd);
            }
            // Return 0 because we set focus ourselves (returning 1 would let
            // the dialog manager set focus to the first WS_TABSTOP control).
            0
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as u16;
            if id == IDOK.0 as u16 {
                // Capture password BEFORE EndDialog destroys the window.
                capture_password_text(hwnd);
                let _ = EndDialog(hwnd, IDOK.0 as isize);
                1
            } else if id == IDCANCEL.0 as u16 {
                let _ = EndDialog(hwnd, IDCANCEL.0 as isize);
                1
            } else {
                0
            }
        }
        // Return 0 (FALSE) for unhandled messages — the dialog manager
        // handles them.  Do NOT call DefDlgProcW here: it re-invokes the
        // dialog procedure, causing infinite recursion / stack overflow.
        _ => 0,
    }
}

// ---------- DPAPI wrapper ----------

/// Encrypts the password bytes with DPAPI so they travel securely over
/// the named pipe to the agent.
///
/// The agent side calls `CryptUnprotectData` to recover the plaintext.
fn dpapi_protect(password: &[u16]) -> windows::core::Result<Vec<u8>> {
    let input = windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
        cbData: (password.len() * 2) as u32,
        pbData: password.as_ptr() as *mut u8,
    };
    let mut output = windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    unsafe {
        windows::Win32::Security::Cryptography::CryptProtectData(
            &input,
            None,
            None,
            None,
            None,
            0,
            &mut output,
        )?;
        let data = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
            output.pbData as *mut _,
        ));
        Ok(data)
    }
}

// ---------- Base64 ----------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes raw bytes to a base64 string (no external dependency).
pub fn base64_encode(input: &[u8]) -> String {
    let mut s = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        s.push(B64[((triple >> 18) & 0x3F) as usize] as char);
        s.push(B64[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            s.push(B64[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            s.push('=');
        }
        if chunk.len() > 2 {
            s.push(B64[(triple & 0x3F) as usize] as char);
        } else {
            s.push('=');
        }
    }
    s
}

// ---------- Public API ----------

/// Shows the password dialog.
///
/// Returns `PasswordSubmit` (with DPAPI-wrapped, base64-encoded password) on
/// OK, or `PasswordCancel` on Cancel / error / empty input.
///
/// # Errors
///
/// Returns an error if DPAPI encryption fails.
pub fn show_password_dialog(request_id: &str) -> anyhow::Result<crate::ipc::messages::Pipe1UiMsg> {
    // Clear any stale captured password from a previous invocation.
    CAPTURED_PASSWORD.with(|cell| cell.borrow_mut().take());

    let template = build_dlgtemplate(
        "DLP Agent: Confirm Stop",
        "Enter the DLP Admin password to stop the service:",
    );

    // SAFETY: template is a valid in-memory DLGTEMPLATE; hInstance is null
    // (the template is in-process); dlg_proc is a valid window procedure.
    let result = unsafe {
        DialogBoxIndirectParamW(
            HMODULE(ptr::null_mut()),
            template.as_ptr() as *const DLGTEMPLATE,
            None,
            Some(dlg_proc),
            LPARAM(0),
        )
    };

    if result == IDOK.0 as isize {
        // Retrieve password captured during WM_COMMAND (before EndDialog).
        if let Some(password_wide) = CAPTURED_PASSWORD.with(|cell| cell.borrow_mut().take()) {
            if !password_wide.is_empty() {
                let protected = dpapi_protect(&password_wide)?;
                return Ok(crate::ipc::messages::Pipe1UiMsg::PasswordSubmit {
                    request_id: request_id.to_owned(),
                    password: base64_encode(&protected),
                });
            }
        }
    }

    Ok(crate::ipc::messages::Pipe1UiMsg::PasswordCancel {
        request_id: request_id.to_owned(),
    })
}

/// Shows the password dialog and returns the plaintext password as a UTF-8 string.
///
/// Used by the file-based stop-password flow where DPAPI is not viable
/// (the UI runs under the user context but the agent runs as SYSTEM).
/// Returns `None` if the user cancelled or entered an empty password.
pub fn show_password_dialog_plaintext(_request_id: &str) -> anyhow::Result<Option<String>> {
    // Clear any stale captured password.
    CAPTURED_PASSWORD.with(|cell| cell.borrow_mut().take());

    let template = build_dlgtemplate(
        "DLP Agent: Confirm Stop",
        "Enter the DLP Admin password to stop the service:",
    );

    let result = unsafe {
        DialogBoxIndirectParamW(
            HMODULE(ptr::null_mut()),
            template.as_ptr() as *const DLGTEMPLATE,
            None,
            Some(dlg_proc),
            LPARAM(0),
        )
    };

    if result == IDOK.0 as isize {
        if let Some(password_wide) = CAPTURED_PASSWORD.with(|cell| cell.borrow_mut().take()) {
            if !password_wide.is_empty() {
                let password = String::from_utf16_lossy(&password_wide);
                return Ok(Some(password));
            }
        }
    }

    Ok(None)
}
