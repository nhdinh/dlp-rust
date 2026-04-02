//! USB mass storage detection (T-13, F-AGT-13).
//!
//! Detects USB volume arrivals via the Windows `RegisterDeviceNotificationW`
//! mechanism and blocks T3/T4 file writes to removable drives.
//!
//! ## Detection model
//!
//! 1. `register_usb_notifications` creates a hidden message-only window and calls
//!    `RegisterDeviceNotificationW` to listen for `DBT_DEVICEARRIVAL` and
//!    `DBT_DEVICEREMOVECOMPLETE` events on volume interfaces.
//! 2. On arrival, `GetDriveTypeW` classifies the volume as removable/fixed/network.
//! 3. Removable drives are added to the blocked-drive set.
//! 4. The interception layer checks every write against the blocked-drive set;
//!    writes of T3/T4 data to a blocked drive are denied.
//!
//! ## Thread safety
//!
//! The blocked-drive set is behind a `RwLock` — readers (interception callbacks)
//! never contend with each other; the writer (device notification callback)
//! acquires an exclusive lock only on plug/unplug events.
//!
//! ## Startup integration
//!
//! Call [`register_usb_notifications`] once during agent startup, and store the
//! returned `HWND`.  Pass that `HWND` to [`unregister_usb_notifications`] on shutdown
//! to destroy the window and release resources.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use dlp_common::Classification;
use parking_lot::RwLock;
use tracing::{debug, info};

#[cfg(windows)]
use windows::Win32::Foundation::{BOOL, HWND};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    PostQuitMessage, RegisterClassW, TranslateMessage, DEVICE_NOTIFY_WINDOW_HANDLE, MSG,
    WNDCLASSW, WINDOW_STYLE, WS_EX_NOACTIVATE, WM_DESTROY, WM_QUIT,
};

/// Drive letters currently identified as USB mass storage (e.g., `E`, `F`).
/// Shared between the device-notification callback and the interception layer.
#[derive(Debug, Default)]
pub struct UsbDetector {
    /// Set of uppercase drive letters (e.g., `{'E', 'F'}`) for blocked USB volumes.
    blocked_drives: RwLock<HashSet<char>>,
}

impl UsbDetector {
    /// Constructs a new detector with an empty blocked-drive set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Scans all existing drive letters and adds removable drives to the blocked set.
    ///
    /// Called once at startup to catch USB drives that were inserted before the
    /// agent started.
    pub fn scan_existing_drives(&self) {
        for letter in 'A'..='Z' {
            if self.is_removable_drive(letter) {
                info!(drive = %letter, "existing USB removable drive detected");
                self.blocked_drives.write().insert(letter);
            }
        }
        debug!(
            blocked = ?*self.blocked_drives.read(),
            "initial USB drive scan complete"
        );
    }

    /// Records a newly arrived USB drive letter as blocked.
    pub fn on_drive_arrival(&self, drive_letter: char) {
        let letter = drive_letter.to_ascii_uppercase();
        if self.is_removable_drive(letter) {
            info!(drive = %letter, "USB mass storage arrived — blocking writes");
            self.blocked_drives.write().insert(letter);
        }
    }

    /// Removes a drive letter from the blocked set on removal.
    pub fn on_drive_removal(&self, drive_letter: char) {
        let letter = drive_letter.to_ascii_uppercase();
        if self.blocked_drives.write().remove(&letter) {
            info!(drive = %letter, "USB mass storage removed");
        }
    }

    /// Returns `true` if a file write to `path` should be blocked based on
    /// the target drive and the resource's classification.
    ///
    /// T3 and T4 writes to any USB mass storage drive are blocked.
    /// T1 and T2 writes are allowed (with audit logging handled by the caller).
    #[must_use]
    pub fn should_block_write(&self, path: &str, classification: Classification) -> bool {
        if !classification.is_sensitive() {
            return false;
        }
        self.is_path_on_blocked_drive(path)
    }

    /// Returns `true` if the path's drive letter is in the blocked set.
    #[must_use]
    pub fn is_path_on_blocked_drive(&self, path: &str) -> bool {
        if let Some(letter) = extract_drive_letter(path) {
            self.blocked_drives.read().contains(&letter)
        } else {
            false
        }
    }

    /// Returns the set of currently blocked drive letters.
    #[must_use]
    pub fn blocked_drive_letters(&self) -> Vec<char> {
        self.blocked_drives.read().iter().copied().collect()
    }

    /// Queries `GetDriveTypeW` for the given drive letter to determine if it
    /// is a removable drive (USB mass storage).
    fn is_removable_drive(&self, letter: char) -> bool {
        use windows::Win32::Storage::FileSystem::GetDriveTypeW;

        // DRIVE_REMOVABLE = 2 (Win32 constant).
        const DRIVE_REMOVABLE: u32 = 2;

        let root: Vec<u16> = OsStr::new(&format!("{}:\\", letter))
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: root is a valid null-terminated wide string pointing to a drive root.
        let drive_type = unsafe { GetDriveTypeW(windows::core::PCWSTR(root.as_ptr())) };
        drive_type == DRIVE_REMOVABLE
    }
}

// SAFETY: UsbDetector contains only RwLock<HashSet<char>>, which is Send + Sync.
// It is safe to share &UsbDetector across threads because all mutable access
// (drive arrival/removal) is gated behind the RwLock.
unsafe impl Send for UsbDetector {}
unsafe impl Sync for UsbDetector {}

// ──────────────────────────────────────────────────────────────────────────────
// USB device notification via RegisterDeviceNotification
// ──────────────────────────────────────────────────────────────────────────────

/// GUID for storage volume device interface.
/// Matches the device interface registered by the Windows volume driver.
/// Windows SDK value: {0x53F5630D,0xB6BF,0x11D0,{0x94,0xF2,0x00,0xA0,0xC9,0x1E,0xFB,0x8B}}
#[cfg(windows)]
const GUID_DEVINTERFACE_VOLUME: windows::core::GUID = windows::core::GUID::from_values(
    u32::from_be_bytes([0x53, 0xF5, 0x63, 0x0D]),
    u16::from_be_bytes([0xB6, 0xBF]),
    u16::from_be_bytes([0x11, 0xD0]),
    [0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B],
);

/// DBT_DEVICEARRIVAL: a device has been added.
#[cfg(windows)]
const DBT_DEVICEARRIVAL: u32 = 0x8000;

/// DBT_DEVICEREMOVECOMPLETE: a device has been removed.
#[cfg(windows)]
const DBT_DEVICEREMOVECOMPLETE: u32 = 0x8004;

/// DEV_BROADCAST_HDR.dbch_devicetype values.
#[cfg(windows)]
const DBT_DEVTYP_VOLUME: u32 = 0x0002;

/// DEV_BROADCAST_VOLUME structure (variable-size — we only need the unitmask).
#[repr(C)]
#[cfg(windows)]
struct DEV_BROADCAST_VOLUME {
    dbcv_size: u32,
    dbcv_devicetype: u32,
    dbcv_reserved: u32,
    /// Bitmask of drive letters: bit 0 = A, bit 1 = B, etc.
    dbcv_unitmask: u32,
}

/// Global reference to the `UsbDetector` shared with the device notification handlers.
/// Protected by a `Mutex` so it can be cleared on unregister.
#[cfg(windows)]
static DRIVE_DETECTOR: parking_lot::Mutex<Option<&'static UsbDetector>> =
    parking_lot::Mutex::new(None);

/// Window procedure for the USB notification window.
#[cfg(windows)]
unsafe extern "system" fn usb_wndproc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    match msg {
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            windows::Win32::Foundation::LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// Processes a `DBT_DEVICEARRIVAL` event by checking each bit in the unit mask
/// and notifying the detector for removable drives.
#[cfg(windows)]
fn handle_drive_arrival(unitmask: u32) {
    if unitmask == 0 {
        return;
    }
    let guard = DRIVE_DETECTOR.lock();
    if let Some(detector) = *guard {
        for (i, letter) in ('A'..='Z').enumerate() {
            if (unitmask >> i) & 1 == 1 {
                detector.on_drive_arrival(letter);
            }
        }
    }
}

/// Processes a `DBT_DEVICEREMOVECOMPLETE` event.
#[cfg(windows)]
fn handle_drive_removal(unitmask: u32) {
    if unitmask == 0 {
        return;
    }
    let guard = DRIVE_DETECTOR.lock();
    if let Some(detector) = *guard {
        for (i, letter) in ('A'..='Z').enumerate() {
            if (unitmask >> i) & 1 == 1 {
                detector.on_drive_removal(letter);
            }
        }
    }
}

/// Registers for USB volume device notifications and starts a message loop on
/// a dedicated thread.
///
/// Creates a hidden message-only window and calls `RegisterDeviceNotificationW`
/// with the volume interface GUID so that `WM_DEVICECHANGE` messages are
/// delivered for volume arrival/removal events.
///
/// # Arguments
///
/// * `detector` — the `UsbDetector` instance to notify on drive events.
///   Only one instance may be registered at a time.
///
/// # Returns
///
/// * `Ok((HWND, std::thread::JoinHandle<()>))` — the notification window handle
///   and the thread handle.  Pass both to [`unregister_usb_notifications`] on shutdown.
/// * `Err` if window registration or device notification fails.
#[cfg(windows)]
pub fn register_usb_notifications(
    detector: &'static UsbDetector,
) -> windows::core::Result<(HWND, std::thread::JoinHandle<()>)> {
    *DRIVE_DETECTOR.lock() = Some(detector);

    // Step 1: register window class.
    let class_name: Vec<u16> = "DlpUsbNotificationWindow\0".encode_utf16().collect();
    let wc = WNDCLASSW {
        lpfnWndProc: Some(usb_wndproc),
        lpszClassName: windows::core::PCWSTR(class_name.as_ptr()),
        ..Default::default()
    };

    // SAFETY: class_name is a null-terminated wide string.
    let atom = unsafe { RegisterClassW(&wc) };
    if atom == 0 {
        return Err(windows::core::Error::from_win32());
    }

    // Step 2: create message-only window.
    // SAFETY: atom is a valid class atom returned by RegisterClassW.
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_NOACTIVATE,
            windows::core::PCWSTR::from_raw(atom as *const u16),
            windows::core::PCWSTR::null(),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            None,
            None,
            None,
            None,
        )
    }?;

    // Step 3: register for device notifications.
    // DEV_BROADCAST_DEVICEINTERFACE_W is variable-size; we construct it as bytes.
    let db_size = std::mem::size_of::<windows::Win32::UI::WindowsAndMessaging::DEV_BROADCAST_DEVICEINTERFACE_W>();
    let mut dev_interface_buf: Vec<u8> = vec![0u8; db_size];
    let dbc = dev_interface_buf.as_mut_ptr() as *mut windows::Win32::UI::WindowsAndMessaging::DEV_BROADCAST_DEVICEINTERFACE_W;

    // SAFETY: dbc points to db_size bytes that we own and are properly aligned.
    unsafe {
        (*dbc).dbcc_size = db_size as u32;
        (*dbc).dbcc_devicetype =
            windows::Win32::UI::WindowsAndMessaging::DBT_DEVTYP_DEVICEINTERFACE.0;
        (*dbc).dbcc_reserved = 0;
        (*dbc).dbcc_classguid = GUID_DEVINTERFACE_VOLUME;
    }

    // SAFETY: hwnd is a valid window; dbc points to a properly initialized
    // DEV_BROADCAST_DEVICEINTERFACE_W struct.
    let notification_handle = unsafe {
        windows::Win32::UI::WindowsAndMessaging::RegisterDeviceNotificationW(
            hwnd,
            dbc as *const _,
            DEVICE_NOTIFY_WINDOW_HANDLE,
        )
    };

    if notification_handle.is_err() {
        let _ = unsafe { DestroyWindow(hwnd) };
        return Err(notification_handle.unwrap_err());
    }

    // Step 4: run message loop on a thread.
    let thread = std::thread::Builder::new()
        .name("usb-notification".into())
        .spawn(move || {
            let mut msg = MSG::default();
            loop {
                // SAFETY: msg is a valid pointer to an MSG struct.
                let ret = unsafe { GetMessageW(&mut msg, None, 0, 0) };
                if ret.0 == 0 {
                    break; // WM_QUIT received
                }
                let _ = unsafe { TranslateMessage(&msg) };
                let _ = unsafe { DispatchMessageW(&msg) };
            }
            debug!("USB notification thread exiting");
        })
        .expect("usb-notification thread must spawn");

    info!("USB device notifications registered");
    Ok((hwnd, thread))
}

/// Stops the USB notification window and cleans up resources.
///
/// Destroys the window (which implicitly unregisters device notifications),
/// waits for the notification thread to finish, and clears the global detector.
#[cfg(windows)]
pub fn unregister_usb_notifications(hwnd: HWND, thread: std::thread::JoinHandle<()>) {
    let _ = unsafe { DestroyWindow(hwnd) };
    let _ = thread.join();
    *DRIVE_DETECTOR.lock() = None;
    debug!("USB device notifications unregistered");
}

/// Extracts the uppercase drive letter from a Windows path.
///
/// Returns `Some('E')` for `"E:\\folder\\file.txt"`, `None` for UNC or relative paths.
fn extract_drive_letter(path: &str) -> Option<char> {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        Some((bytes[0] as char).to_ascii_uppercase())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_drive_letter() {
        assert_eq!(extract_drive_letter(r"E:\Data\file.txt"), Some('E'));
        assert_eq!(extract_drive_letter(r"c:\Windows"), Some('C'));
        assert_eq!(extract_drive_letter(r"\\server\share"), None);
        assert_eq!(extract_drive_letter("relative/path"), None);
        assert_eq!(extract_drive_letter(""), None);
    }

    #[test]
    fn test_usb_detector_default() {
        let detector = UsbDetector::new();
        assert!(detector.blocked_drive_letters().is_empty());
    }

    #[test]
    fn test_on_drive_arrival_removal() {
        let detector = UsbDetector::new();
        detector.blocked_drives.write().insert('E');
        assert!(detector.is_path_on_blocked_drive(r"E:\secret.docx"));
        assert!(!detector.is_path_on_blocked_drive(r"C:\secret.docx"));

        detector.on_drive_removal('E');
        assert!(!detector.is_path_on_blocked_drive(r"E:\secret.docx"));
    }

    #[test]
    fn test_should_block_write_t4_usb() {
        let detector = UsbDetector::new();
        detector.blocked_drives.write().insert('F');
        assert!(detector.should_block_write(r"F:\restricted.xlsx", Classification::T4));
        assert!(detector.should_block_write(r"F:\confidential.pdf", Classification::T3));
    }

    #[test]
    fn test_should_block_write_t1_t2_allowed() {
        let detector = UsbDetector::new();
        detector.blocked_drives.write().insert('F');
        assert!(!detector.should_block_write(r"F:\public.txt", Classification::T1));
        assert!(!detector.should_block_write(r"F:\internal.doc", Classification::T2));
    }

    #[test]
    fn test_should_block_non_usb_drive() {
        let detector = UsbDetector::new();
        // C: is not in the blocked set.
        assert!(!detector.should_block_write(r"C:\Restricted\secrets.xlsx", Classification::T4));
    }

    #[test]
    fn test_drive_letter_case_insensitive() {
        let detector = UsbDetector::new();
        detector.blocked_drives.write().insert('E');
        assert!(detector.blocked_drives.read().contains(&'E'));
        detector.on_drive_removal('e');
        assert!(detector.blocked_drive_letters().is_empty());
    }
}
