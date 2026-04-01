//! Stop-password dialog — prompts the admin for credentials (T-45).
//!
//! Triggered by `Pipe1AgentMsg::PasswordDialog`.  Uses `DialogBoxIndirectParamW`
//! with an in-memory `DLGTEMPLATE` to display a password field.  The password
//! bytes are DPAPI-wrapped (`CryptProtectData`) before being sent to the agent.

use std::cell::Cell;
use std::ptr;
use windows::Win32::Foundation::{LocalFree, HLOCAL, HMODULE, HWND, LPARAM, WPARAM};
use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};
use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows::Win32::UI::WindowsAndMessaging::DLGTEMPLATE;
use windows::Win32::UI::WindowsAndMessaging::{
    DefDlgProcW, DialogBoxIndirectParamW, EndDialog, GetDlgItem, GetWindowTextLengthW,
    GetWindowTextW, IDCANCEL, IDOK, WM_COMMAND, WM_INITDIALOG,
};

const WS_DEFAULT: u32 = 0x50010000; // WS_CHILD | WS_VISIBLE | WS_TABSTOP

thread_local! {
    static DLG_HWND: Cell<Option<HWND>> = const { Cell::new(None) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Dialog template builder
// ─────────────────────────────────────────────────────────────────────────────

fn build_dlgtemplate(title: &str, prompt: &str) -> Vec<u8> {
    let mut t = Vec::with_capacity(512);

    // DLGTEMPLATE — style: WS_POPUP | WS_VISIBLE | WS_CAPTION | WS_SYSMENU | DS_SETFONT
    push_u32(&mut t, 0x90C80080);
    push_u32(&mut t, 0); // extended style
    push_u16(&mut t, 4); // number of controls
    push_i16(&mut t, 0); // x
    push_i16(&mut t, 0); // y
    push_i16(&mut t, 260); // cx
    push_i16(&mut t, 108); // cy
    push_u16(&mut t, 0); // menu (none)
    push_u16(&mut t, 0); // window class (0 = dialog)
    push_wstr(&mut t, title);
    push_u16(&mut t, 8); // font point size
    push_wstr(&mut t, "Segoe UI");

    // ── Item 1: Static prompt (id = 0) ─────────────────────────────────────
    align4(&mut t);
    push_u32(&mut t, 0x00000002); // SS_LEFT
    push_u32(&mut t, 0);
    push_i16(&mut t, 7);
    push_i16(&mut t, 7);
    push_i16(&mut t, 246);
    push_i16(&mut t, 14);
    push_u16(&mut t, 0xFFFF); // atom prefix
    push_u16(&mut t, 0x0082); // STATIC class
    push_wstr(&mut t, prompt);
    push_u16(&mut t, 0); // extra count

    // ── Item 2: Password edit (id = 3) ─────────────────────────────────────
    align4(&mut t);
    // WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_PASSWORD
    push_u32(&mut t, WS_DEFAULT | 0x00200000 | 32); // WS_BORDER=0x00200000, ES_PASSWORD=32
    push_u32(&mut t, 0);
    push_i16(&mut t, 7);
    push_i16(&mut t, 25);
    push_i16(&mut t, 246);
    push_i16(&mut t, 14);
    push_u16(&mut t, 0xFFFF);
    push_u16(&mut t, 0x0081); // EDIT class
    push_u16(&mut t, 0); // no title
    push_u16(&mut t, 0); // extra count

    // ── Item 3: OK button (id = IDOK = 1) ─────────────────────────────────
    align4(&mut t);
    // BS_PUSHBUTTON = 0x00000000
    push_u32(&mut t, WS_DEFAULT); // WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON
    push_u32(&mut t, 0);
    push_i16(&mut t, 56);
    push_i16(&mut t, 46);
    push_i16(&mut t, 50);
    push_i16(&mut t, 14);
    push_u16(&mut t, 0xFFFF);
    push_u16(&mut t, 0x0080); // BUTTON class
    push_u16(&mut t, 0); // no title (use dialog font)
    push_u16(&mut t, 0);

    // ── Item 4: Cancel button (id = IDCANCEL = 2) ─────────────────────────
    align4(&mut t);
    push_u32(&mut t, WS_DEFAULT);
    push_u32(&mut t, 0);
    push_i16(&mut t, 114);
    push_i16(&mut t, 46);
    push_i16(&mut t, 50);
    push_i16(&mut t, 14);
    push_u16(&mut t, 0xFFFF);
    push_u16(&mut t, 0x0080); // BUTTON class
    push_u16(&mut t, 0);
    push_u16(&mut t, 0);

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

// ─────────────────────────────────────────────────────────────────────────────
// Dialog procedure — DLGPROC returns isize
// ─────────────────────────────────────────────────────────────────────────────

unsafe extern "system" fn dlg_proc(hwnd: HWND, msg: u32, wparam: WPARAM, _lparam: LPARAM) -> isize {
    match msg {
        WM_INITDIALOG => {
            DLG_HWND.with(|cell| cell.set(Some(hwnd)));
            // Focus the password edit control (id=3).
            if let Ok(edit_hwnd) = GetDlgItem(hwnd, 3) {
                let _ = SetFocus(edit_hwnd);
            }
            0
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as u16;
            if id == IDOK.0 as u16 {
                let _ = EndDialog(hwnd, IDOK.0 as isize);
                1
            } else if id == IDCANCEL.0 as u16 {
                let _ = EndDialog(hwnd, IDCANCEL.0 as isize);
                1
            } else {
                0
            }
        }
        _ => DefDlgProcW(hwnd, msg, wparam, _lparam).0 as isize,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DPAPI wrapper
// ─────────────────────────────────────────────────────────────────────────────

fn dpapi_protect(password: &[u16]) -> windows::core::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: (password.len() * 2) as u32,
        pbData: password.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    unsafe {
        CryptProtectData(&input, None, None, None, None, 0, &mut output)?;
        let data = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData as *mut _));
        Ok(data)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64 (no external dep)
// ─────────────────────────────────────────────────────────────────────────────

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut s = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        s.push(B64[(((b0 << 18) | (b1 << 12)) >> 18) as usize] as char);
        s.push(B64[(((b1 << 6) | b2) >> 12) as usize & 0x3F] as char);
        if chunk.len() > 1 {
            s.push(B64[((b2 << 2) >> 2) as usize & 0x3F] as char);
        } else {
            s.push('=');
        }
        if chunk.len() > 2 {
            s.push('=');
        }
    }
    s
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Shows the password dialog.  Returns `PasswordSubmit(dpapi_wrapped_b64)` on
/// OK, or `PasswordCancel` on Cancel / error.
pub fn show_password_dialog(request_id: &str) -> anyhow::Result<crate::ipc::messages::Pipe1UiMsg> {
    DLG_HWND.with(|cell| cell.set(None));

    let template = build_dlgtemplate(
        "DLP Agent: Confirm Stop",
        "Enter your DLP Admin password to stop the service:",
    );

    // SAFETY: template is a valid in-memory DLGTEMPLATE; hInstance is null so the
    // template is in-process; dlg_proc is a valid window procedure.
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
        // Retrieve HWND from thread-local and read the edit control (id=3).
        if let Some(hwnd) = DLG_HWND.with(|cell| cell.take()) {
            if let Ok(edit_hwnd) = unsafe { GetDlgItem(hwnd, 3) } {
                let len = unsafe { GetWindowTextLengthW(edit_hwnd) } as usize;
                if len > 0 {
                    let mut buf = vec![0u16; len + 1];
                    let copied = unsafe { GetWindowTextW(edit_hwnd, &mut buf[..len]) };
                    if copied > 0 {
                        buf.truncate(len);
                        let protected = dpapi_protect(&buf)?;
                        return Ok(crate::ipc::messages::Pipe1UiMsg::PasswordSubmit {
                            request_id: request_id.to_owned(),
                            password: base64_encode(&protected),
                        });
                    }
                }
            }
        }
    }

    Ok(crate::ipc::messages::Pipe1UiMsg::PasswordCancel {
        request_id: request_id.to_owned(),
    })
}
