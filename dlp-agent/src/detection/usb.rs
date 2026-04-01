//! USB mass storage detection (T-13, F-AGT-13).
//!
//! Detects USB volume arrivals via the Windows `SetupAPI` / device notification
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
use tracing::{debug, info, warn};

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
#[cfg(windows)]
use windows::Win32::System::Threading::GetCurrentThreadId;
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    PostQuitMessage, RegisterClassW, TranslateMessage, DEVICE_NOTIFY_WINDOW_HANDLE, MSG,
    WNDCLASSW, WS_EX_NOACTIVATE, WM_DESTROY, WM_DEVICECHANGE,
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
        for letter in b'A'..=b'Z' {
            let letter = letter as char;
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
        // Extract drive letter from paths like "E:\folder\file.txt"
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

        // DRIVE_REMOVABLE = 2 (Win32 constant from WindowsProgramming).
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

// ──────────────────────────────────────────────────────────────────────────────
// USB device notification via RegisterDeviceNotification
// ──────────────────────────────────────────────────────────────────────────────

/// GUID for storage volume device interface (GUID_DEVINTERFACE_VOLUME).
/// This matches the device interface registered by the Windows volume driver.
#[cfg(windows)]
const GUID_DEVINTERFACE_VOLUME: windows::core::GUID = windows::core::GUID::from_values(
    0x53F5630Du16,
    0xB6BFu16,
    0x11D0u16,
    [0x94u8, 0xF2u8, 0x00u8, 0xA0u8, 0xC9u8, 0x1Eu8, 0xFBu8, 0x8Bu8],
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

/// Window procedure for the USB notification window.
#[cfg(windows)]
unsafe extern "system" fn usb_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LPARAM {
    match msg {
        WM_DEVICECHANGE => {
            let event = lparam.0 as *const DEV_BROADCAST_VOLUME;
            if event.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            // SAFETY: event is only dereferenced when WM_DEVICECHANGE is received
            // and lparam points to a valid DEV_BROADCAST_HDR with devicetype DBT_DEVTYP_VOLUME.
            let broadcast = unsafe { &*event };
            if broadcast.dbcv_devicetype != DBT_DEVTYP_VOLUME {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            match wparam.0 as u32 {
                DBT_DEVICEARRIVAL => {
                    handle_drive_arrival(broadcast.dbcv_unitmask);
                }
                DBT_DEVICEREMOVECOMPLETE => {
                    handle_drive_removal(broadcast.dbcv_unitmask);
                }
                _ => {}
            }
            LPARAM(1) // Return value expected by DefWindowProc for WM_DEVICECHANGE.
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            LPARAM(0)
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
    for i in 0..26u32 {
        if (unitmask >> i) & 1 == 1 {
            let letter = (b'A' as u32 + i) as char;
            // SAFETY: DRIVE_DETECTOR is set once during register_usb_notifications
            // before the message loop starts, and cleared only during shutdown.
            if let Some(detector) = DRIVE_DETECTOR.get() {
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
    for i in 0..26u32 {
        if (unitmask >> i) & 1 == 1 {
            let letter = (b'A' as u32 + i) as char;
            // SAFETY: same as handle_drive_arrival.
            if let Some(detector) = DRIVE_DETECTOR.get() {
                detector.on_drive_removal(letter);
            }
        }
    }
}

/// Global reference to the `UsbDetector` shared with the window procedure.
static DRIVE_DETECTOR: std::sync::OnceLock<UsbDetector> = std::sync::OnceLock::new();

/// Registers for USB volume device notifications and starts a message loop on
/// a dedicated thread.
///
/// Creates a hidden message-only window and calls `RegisterDeviceNotificationW`
/// with the `GUID_DEVINTERFACE_VOLUME` interface class so that `WM_DEVICECHANGE`
/// messages are delivered for volume arrival/removal events.
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
    let _ = DRIVE_DETECTOR.set(detector);

    // Step 1: register window class.
    let class_name: Vec<u16> = "DlpUsbNotificationWindow\0".encode_utf16().collect();
    let wc = WNDCLASSW {
        lpfnWndProc: Some(usb_wndproc),
        lpszClassName: PCWSTR(class_name.as_ptr()),
        ..Default::default()
    };

    // SAFETY: class_name is a null-terminated wide string.
    let atom = unsafe { RegisterClassW(&wc) };
    if atom == 0 {
        return Err(windows::core::Error::from_win32());
    }

    // Step 2: create message-only window.
    // SAFETY: atom is a valid class atom.
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_NOACTIVATE,
            PCWSTR::from_raw(atom as *const u16),
            PCWSTR::null(),
            0,
            0, 0, 0, 0,
            None,
            None,
            None,
        )
    }?;

    // Step 3: fill in DEV_BROADCAST_DEVICEINTERFACE for volume interface.
    let volume_guid = GUID_DEVINTERFACE_VOLUME;
    let dev_interface = windows::Win32::UI::WindowsAndMessaging::DEV_BROADCAST_DEVICEINTERFACE_W {
        dbcc_size: std::mem::size_of::<
            windows::Win32::UI::WindowsAndMessaging::DEV_BROADCAST_DEVICEINTERFACE_W,
        >() as u32,
        dbcc_devicetype:
            windows::Win32::UI::WindowsAndMessaging::DBT_DEVTYP_DEVICEINTERFACE as u32,
        dbcc_reserved: 0,
        dbcc_classguid: volume_guid,
        dbcc_name: [0u16; 1],
    };

    // Step 4: register for device notifications.
    // SAFETY: hwnd is a valid window created above.
    let notification_handle = unsafe {
        windows::Win32::UI::WindowsAndMessaging::RegisterDeviceNotificationW(
            hwnd,
            &dev_interface as *const _ as *const std::ffi::c_void,
            DEVICE_NOTIFY_WINDOW_HANDLE,
        )
    };

    if notification_handle.is_err() {
        let _ = unsafe { DestroyWindow(hwnd) };
        return Err(notification_handle.unwrap_err());
    }

    // Step 5: run message loop on a thread.
    let thread = std::thread::Builder::new()
        .name("usb-notification".into())
        .spawn(move || {
            let mut msg = MSG::default();
            loop {
                // SAFETY: msg is a valid pointer.
                let ret = unsafe { GetMessageW(&mut msg, None, 0, 0) };
                if ret.is_err() || ret == 0 {
                    break;
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
    let _ = DRIVE_DETECTOR.take();
    debug!("USB device notifications unregistered");
}

/// Extracts the uppercase drive letter from a Windows path.
///
/// Returns `Some('E')` for `"E:\\folder\\file.txt"`, `None` for UNC or relative paths.
fn extract_drive_letter(path: &str) -> Option<char> {
    let bytes = path.as_bytes();
    // Pattern: single ASCII letter followed by ':' (and optionally '\')
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
        // Simulate a removable drive by directly manipulating the set.
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
        // Simulate arrival by directly inserting lowercase — on_drive_arrival
        // normalizes to uppercase before checking the drive type.
        detector.blocked_drives.write().insert('E');
        assert!(detector.blocked_drives.read().contains(&'E'));
        // on_drive_removal normalizes case.
        detector.on_drive_removal('e');
        assert!(detector.blocked_drive_letters().is_empty());
    }
}
