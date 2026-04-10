//! Override justification dialog (T-43).
//!
//! Shows a dialog when a blocked operation can be overridden. The user
//! enters a business justification and clicks OK to request the override,
//! or Cancel to accept the block.
//!
//! Uses `DialogBoxIndirectParamW` with an in-memory `DLGTEMPLATE`.

use std::cell::RefCell;
use std::ptr;

use windows::Win32::Foundation::{HMODULE, HWND, LPARAM, WPARAM};
use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows::Win32::UI::WindowsAndMessaging::{
    DialogBoxIndirectParamW, EndDialog, GetDlgItem, GetWindowTextLengthW, GetWindowTextW,
    DLGTEMPLATE, IDCANCEL, IDOK, WM_COMMAND, WM_INITDIALOG,
};

/// Control ID for the justification text field.
const IDC_JUSTIFICATION: u16 = 101;

thread_local! {
    /// Justification text captured before EndDialog destroys the window.
    static CAPTURED_TEXT: RefCell<Option<String>> = const { RefCell::new(None) };
}

// ---------- Dialog template builder ----------

/// Builds the override justification dialog template.
fn build_dlgtemplate(title: &str, prompt: &str) -> Vec<u8> {
    let mut t = Vec::with_capacity(512);

    // DLGTEMPLATE header
    // WS_POPUP | WS_VISIBLE | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME |
    // DS_SETFONT | DS_CENTER
    push_u32(&mut t, 0x90C808C0);
    push_u32(&mut t, 0); // extended style
    push_u16(&mut t, 4); // number of controls
    push_i16(&mut t, 0); // x
    push_i16(&mut t, 0); // y
    push_i16(&mut t, 280); // cx (dialog units)
    push_i16(&mut t, 110); // cy (dialog units)
    push_u16(&mut t, 0); // menu
    push_u16(&mut t, 0); // class
    push_wstr(&mut t, title);
    push_u16(&mut t, 9); // font size
    push_wstr(&mut t, "Segoe UI");

    // Item 1: Static prompt
    align4(&mut t);
    push_u32(&mut t, 0x50000000 | 0x0001); // WS_CHILD | WS_VISIBLE | SS_CENTER
    push_u32(&mut t, 0);
    push_i16(&mut t, 10); // x
    push_i16(&mut t, 7); // y
    push_i16(&mut t, 260); // cx
    push_i16(&mut t, 24); // cy
    push_u16(&mut t, 0xFFFF); // id (don't care)
    push_u16(&mut t, 0xFFFF); // class atom prefix
    push_u16(&mut t, 0x0082); // STATIC
    push_wstr(&mut t, prompt);
    push_u16(&mut t, 0); // extra count

    // Item 2: Justification edit (multiline)
    align4(&mut t);
    // WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | WS_VSCROLL |
    // ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN
    push_u32(
        &mut t,
        0x50010000 | 0x00200000 | 0x00200000 | 0x04 | 0x40 | 0x1000,
    );
    push_u32(&mut t, 0x00000200); // WS_EX_CLIENTEDGE
    push_i16(&mut t, 10); // x
    push_i16(&mut t, 35); // y
    push_i16(&mut t, 260); // cx
    push_i16(&mut t, 40); // cy
    push_u16(&mut t, IDC_JUSTIFICATION);
    push_u16(&mut t, 0xFFFF); // class atom prefix
    push_u16(&mut t, 0x0081); // EDIT
    push_u16(&mut t, 0); // title (empty)
    push_u16(&mut t, 0); // extra count

    // Item 3: OK button
    align4(&mut t);
    push_u32(&mut t, 0x50010000 | 0x0001); // BS_DEFPUSHBUTTON
    push_u32(&mut t, 0);
    push_i16(&mut t, 80);
    push_i16(&mut t, 85);
    push_i16(&mut t, 50);
    push_i16(&mut t, 14);
    push_u16(&mut t, IDOK.0 as u16);
    push_u16(&mut t, 0xFFFF);
    push_u16(&mut t, 0x0080); // BUTTON
    push_wstr(&mut t, "Override");
    push_u16(&mut t, 0);

    // Item 4: Cancel button
    align4(&mut t);
    push_u32(&mut t, 0x50010000);
    push_u32(&mut t, 0);
    push_i16(&mut t, 150);
    push_i16(&mut t, 85);
    push_i16(&mut t, 50);
    push_i16(&mut t, 14);
    push_u16(&mut t, IDCANCEL.0 as u16);
    push_u16(&mut t, 0xFFFF);
    push_u16(&mut t, 0x0080); // BUTTON
    push_wstr(&mut t, "Cancel");
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

// ---------- Dialog procedure ----------

/// Captures text from the justification edit before EndDialog.
unsafe fn capture_justification(hwnd: HWND) {
    let Ok(edit) = GetDlgItem(hwnd, IDC_JUSTIFICATION as i32) else {
        return;
    };

    let len = GetWindowTextLengthW(edit) as usize;
    if len == 0 {
        return;
    }

    let mut buf = vec![0u16; len + 1];
    let copied = GetWindowTextW(edit, &mut buf);
    if copied > 0 {
        buf.truncate(copied as usize);
        let text = String::from_utf16_lossy(&buf);
        CAPTURED_TEXT.with(|cell| {
            *cell.borrow_mut() = Some(text);
        });
    }
}

unsafe extern "system" fn dlg_proc(hwnd: HWND, msg: u32, wparam: WPARAM, _lparam: LPARAM) -> isize {
    match msg {
        WM_INITDIALOG => {
            if let Ok(edit) = GetDlgItem(hwnd, IDC_JUSTIFICATION as i32) {
                let _ = SetFocus(edit);
            }
            0
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as u16;
            if id == IDOK.0 as u16 {
                capture_justification(hwnd);
                let _ = EndDialog(hwnd, IDOK.0 as isize);
                1
            } else if id == IDCANCEL.0 as u16 {
                let _ = EndDialog(hwnd, IDCANCEL.0 as isize);
                1
            } else {
                0
            }
        }
        _ => 0,
    }
}

// ---------- Public API ----------

/// The result of the override justification dialog.
#[derive(Debug, Clone)]
pub enum OverrideDialogResult {
    /// User provided justification and clicked Override.
    Approved {
        /// The business justification text entered by the user.
        justification: String,
    },
    /// User clicked Cancel or closed the dialog.
    Cancelled,
}

/// Shows the override justification dialog.
///
/// # Arguments
///
/// * `classification` - Data classification tier
/// * `resource_path` - Path to the blocked resource
/// * `reason` - Reason the operation was blocked
///
/// # Returns
///
/// [`OverrideDialogResult::Approved`] with the justification text, or
/// [`OverrideDialogResult::Cancelled`].
pub fn show_override_dialog(
    classification: &str,
    resource_path: &str,
    reason: &str,
) -> OverrideDialogResult {
    CAPTURED_TEXT.with(|cell| cell.borrow_mut().take());

    let prompt = format!(
        "Operation blocked: {} ({})\n\
         Resource: {}\n\n\
         Enter business justification to request an override:",
        reason, classification, resource_path,
    );

    let template = build_dlgtemplate("DLP Agent: Override Request", &prompt);

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
        if let Some(text) = CAPTURED_TEXT.with(|cell| cell.borrow_mut().take()) {
            if !text.trim().is_empty() {
                return OverrideDialogResult::Approved {
                    justification: text.trim().to_string(),
                };
            }
        }
    }

    OverrideDialogResult::Cancelled
}
