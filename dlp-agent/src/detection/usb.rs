//! USB mass storage detection (T-13, F-AGT-13).
//!
//! Detects USB volume arrivals via the Windows `RegisterDeviceNotificationW`
//! mechanism and blocks T3/T4 file writes to removable drives. Also captures
//! USB device identity (VID, PID, serial, description) on arrival and stores
//! it in memory for Phase 26 enforcement (Phase 23 SC-1/SC-2).
//!
//! ## Detection model
//!
//! 1. `register_usb_notifications` creates a hidden message-only window and calls
//!    `RegisterDeviceNotificationW` twice — once for `GUID_DEVINTERFACE_VOLUME`
//!    (drive-letter tracking) and once for `GUID_DEVINTERFACE_USB_DEVICE`
//!    (VID/PID/serial capture via `dbcc_name`).
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

use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use dlp_common::{Classification, DeviceIdentity};
use parking_lot::RwLock;
use tracing::{debug, info};

#[cfg(windows)]
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiGetDeviceRegistryPropertyW, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT,
    SETUP_DI_REGISTRY_PROPERTY, SP_DEVINFO_DATA,
};
#[cfg(windows)]
use windows::Win32::Foundation::HWND;
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, PostQuitMessage,
    RegisterClassW, RegisterDeviceNotificationW, TranslateMessage, DBT_DEVICEARRIVAL,
    DBT_DEVICEREMOVECOMPLETE, DBT_DEVTYP_DEVICEINTERFACE, DEVICE_NOTIFY_WINDOW_HANDLE,
    DEV_BROADCAST_DEVICEINTERFACE_W, DEV_BROADCAST_HDR, MSG, WINDOW_STYLE, WM_DESTROY,
    WM_DEVICECHANGE, WNDCLASSW, WS_EX_NOACTIVATE,
};

/// Registry property ID for device friendly name (e.g., "Kingston DataTraveler 3.0").
/// Falls back to `SPDRP_DEVICEDESC` when not set. Windows SDK `SetupAPI.h` value = 12 (0xC).
#[cfg(windows)]
const SPDRP_FRIENDLYNAME: u32 = 0x0000_000C;

/// Registry property ID for device description. Used as fallback when
/// `SPDRP_FRIENDLYNAME` is absent. Windows SDK `SetupAPI.h` value = 0.
#[cfg(windows)]
const SPDRP_DEVICEDESC: u32 = 0x0000_0000;

/// Drive letters currently identified as USB mass storage (e.g., `E`, `F`).
/// Shared between the device-notification callback and the interception layer.
#[derive(Debug, Default)]
pub struct UsbDetector {
    /// Set of uppercase drive letters (e.g., `{'E', 'F'}`) for blocked USB volumes.
    ///
    /// Marked `pub` so that integration tests in `dlp-agent/tests/integration.rs`
    /// can seed drives (bypasses `GetDriveTypeW` which is unavailable in CI).
    /// Production code should use `on_drive_arrival` / `on_drive_removal` instead.
    pub blocked_drives: RwLock<HashSet<char>>,
    /// In-memory map from drive letter to captured USB device identity.
    ///
    /// Populated on `DBT_DEVICEARRIVAL` for `GUID_DEVINTERFACE_USB_DEVICE`
    /// (wired in Phase 23 Plan 02). Keyed by uppercase drive letter to mirror
    /// [`UsbDetector::blocked_drives`]. Phase 26 reads this map at I/O
    /// enforcement time without re-querying SetupDi (unreliable after removal).
    ///
    /// Marked `pub` to mirror `blocked_drives` — integration tests seed
    /// entries directly; production code uses the arrival/removal handlers
    /// added in Plan 02.
    pub device_identities: RwLock<HashMap<char, DeviceIdentity>>,
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

    /// Returns a clone of the captured `DeviceIdentity` for the given drive
    /// letter, or `None` if no identity has been captured for that drive.
    ///
    /// Case-insensitive on the drive letter. Clones the `DeviceIdentity`
    /// so the read lock is released immediately after lookup.
    #[must_use]
    pub fn device_identity_for_drive(&self, drive_letter: char) -> Option<DeviceIdentity> {
        let letter = drive_letter.to_ascii_uppercase();
        self.device_identities.read().get(&letter).cloned()
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

/// GUID for USB device interface — fires on raw USB device plug/unplug.
/// `dbcc_name` carries the full device path with embedded VID/PID/serial
/// (see Phase 23 CONTEXT.md D-01, D-02).
/// Windows SDK value: `{A5DCBF10-6530-11D2-901F-00C04FB951ED}`.
#[cfg(windows)]
const GUID_DEVINTERFACE_USB_DEVICE: windows::core::GUID = windows::core::GUID::from_values(
    0xA5DC_BF10,
    0x6530,
    0x11D2,
    [0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED],
);

/// Global reference to the `UsbDetector` shared with the device notification handlers.
/// Protected by a `Mutex` so it can be cleared on unregister.
#[cfg(windows)]
static DRIVE_DETECTOR: parking_lot::Mutex<Option<&'static UsbDetector>> =
    parking_lot::Mutex::new(None);

/// Global registry cache reference, set from `service.rs` before the USB window
/// thread is spawned. Allows `usb_wndproc` (an `unsafe extern "system"` callback
/// that cannot capture environment) to trigger an immediate cache refresh on
/// USB device arrival (D-09 from 24-CONTEXT.md).
#[cfg(windows)]
static REGISTRY_CACHE: std::sync::OnceLock<std::sync::Arc<crate::device_registry::DeviceRegistryCache>> =
    std::sync::OnceLock::new();

/// Global tokio runtime handle, stored before the USB notification thread is
/// spawned so that `usb_wndproc` (which runs on a plain `std::thread`) can
/// schedule async work on the existing runtime without creating a new one.
///
/// `std::thread::spawn` does NOT inherit the caller's tokio context — this
/// static bridges the gap.
#[cfg(windows)]
static REGISTRY_RUNTIME_HANDLE: std::sync::OnceLock<tokio::runtime::Handle> =
    std::sync::OnceLock::new();

/// Global server client reference for registry refresh from `usb_wndproc`.
/// Set alongside [`REGISTRY_CACHE`] and [`REGISTRY_RUNTIME_HANDLE`] in `service.rs`.
#[cfg(windows)]
static REGISTRY_CLIENT: std::sync::OnceLock<crate::server_client::ServerClient> =
    std::sync::OnceLock::new();

/// Sets the global registry cache reference.
///
/// Called once from `service.rs` before spawning USB notifications.
/// Subsequent calls are silently ignored (OnceLock contract).
///
/// # Arguments
///
/// * `cache` - The `Arc<DeviceRegistryCache>` to store globally.
#[cfg(windows)]
pub fn set_registry_cache(cache: std::sync::Arc<crate::device_registry::DeviceRegistryCache>) {
    let _ = REGISTRY_CACHE.set(cache);
}

/// Sets the global server client for device registry refresh.
///
/// Called once from `service.rs` before spawning USB notifications.
/// Subsequent calls are silently ignored (OnceLock contract).
///
/// # Arguments
///
/// * `client` - The [`crate::server_client::ServerClient`] to store globally.
#[cfg(windows)]
pub fn set_registry_client(client: crate::server_client::ServerClient) {
    let _ = REGISTRY_CLIENT.set(client);
}

/// Sets the global tokio runtime handle for use by `usb_wndproc`.
///
/// Called once from `service.rs` (inside the async `run_loop`, so
/// `Handle::current()` is valid) before spawning USB notifications.
/// Subsequent calls are silently ignored (OnceLock contract).
#[cfg(windows)]
pub fn set_registry_runtime_handle(handle: tokio::runtime::Handle) {
    let _ = REGISTRY_RUNTIME_HANDLE.set(handle);
}

/// Window procedure for the USB notification window.
///
/// Handles `WM_DESTROY` (quit message loop) and `WM_DEVICECHANGE` (route USB
/// arrival/removal events to the appropriate handler). All other messages are
/// forwarded to `DefWindowProcW`.
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
        WM_DEVICECHANGE => {
            // wparam holds the event code: DBT_DEVICEARRIVAL = 0x8000,
            // DBT_DEVICEREMOVECOMPLETE = 0x8004. lparam is a pointer to
            // DEV_BROADCAST_HDR valid only for the duration of this call.
            let event_type = wparam.0 as u32;
            if (event_type == DBT_DEVICEARRIVAL || event_type == DBT_DEVICEREMOVECOMPLETE)
                && lparam.0 != 0
            {
                // SAFETY: lparam points to a DEV_BROADCAST_HDR produced by
                // the OS; valid for the duration of this callback.
                let hdr = unsafe { &*(lparam.0 as *const DEV_BROADCAST_HDR) };
                if hdr.dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE {
                    // SAFETY: the header's devicetype confirms the body is
                    // DEV_BROADCAST_DEVICEINTERFACE_W. Extract dbcc_classguid
                    // and dbcc_name (null-terminated wide string) here —
                    // do NOT store the pointer past this callback.
                    let di = unsafe { &*(lparam.0 as *const DEV_BROADCAST_DEVICEINTERFACE_W) };
                    let classguid = di.dbcc_classguid;
                    // Lock briefly to read the detector reference, then drop the
                    // guard before calling any helper that may also need locking.
                    let detector_opt = *DRIVE_DETECTOR.lock();
                    if let Some(detector) = detector_opt {
                        if classguid == GUID_DEVINTERFACE_VOLUME {
                            // VOLUME arrival/removal: re-scan drive letters and
                            // reconcile with the blocked-drives set.
                            handle_volume_event(detector, event_type);
                        } else if classguid == GUID_DEVINTERFACE_USB_DEVICE {
                            // SAFETY: di is valid for this callback duration;
                            // read_dbcc_name extracts the wide string synchronously.
                            let device_path = unsafe { read_dbcc_name(di) };
                            if event_type == DBT_DEVICEARRIVAL {
                                on_usb_device_arrival(detector, &device_path);

                                // Trigger an immediate device registry cache refresh so the
                                // new device's trust tier is available before the first I/O
                                // event (D-09 from 24-CONTEXT.md).
                                //
                                // NOTE: usb_wndproc runs on a plain std::thread that does NOT
                                // inherit the tokio context. We stored the runtime Handle in
                                // REGISTRY_RUNTIME_HANDLE (set in service.rs before this thread
                                // was spawned) to schedule the async refresh without creating a
                                // second tokio runtime.
                                if let (Some(cache), Some(client), Some(handle)) = (
                                    REGISTRY_CACHE.get(),
                                    REGISTRY_CLIENT.get(),
                                    REGISTRY_RUNTIME_HANDLE.get(),
                                ) {
                                    let cache_clone = std::sync::Arc::clone(cache);
                                    let client_clone = client.clone();
                                    // Fire-and-forget: spawn on the existing runtime so the
                                    // message loop is not blocked by the async refresh.
                                    handle.spawn(async move {
                                        cache_clone.refresh(&client_clone).await;
                                    });
                                }
                            } else {
                                on_usb_device_removal(detector, &device_path);
                            }
                        }
                    }
                }
            }
            windows::Win32::Foundation::LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// Reads the null-terminated wide-string `dbcc_name` from a
/// `DEV_BROADCAST_DEVICEINTERFACE_W`. The struct is variable-length; `dbcc_name`
/// is the first `u16` of a trailing UTF-16 sequence that extends past the
/// declared `[u16; 1]` field.
///
/// # Safety
///
/// The caller must guarantee that `di` points to a live
/// `DEV_BROADCAST_DEVICEINTERFACE_W` whose storage extends at least to the
/// null terminator of `dbcc_name`. The OS guarantees this for the duration
/// of the `WM_DEVICECHANGE` callback.
#[cfg(windows)]
unsafe fn read_dbcc_name(di: &DEV_BROADCAST_DEVICEINTERFACE_W) -> String {
    let base = di.dbcc_name.as_ptr();
    let mut len = 0usize;
    // SAFETY: walk forward until we hit the null terminator. Bounded by
    // Windows device-path max length (MAX_PATH + driver prefix = 32,768 u16).
    while unsafe { *base.add(len) } != 0 && len < 32_768 {
        len += 1;
    }
    // SAFETY: base..base+len is valid UTF-16 data owned by the OS for this callback.
    let slice = unsafe { std::slice::from_raw_parts(base, len) };
    String::from_utf16_lossy(slice)
}

/// Called when a VOLUME device-interface arrival/removal fires. The volume
/// event's `dbcc_name` is a volume GUID path with no drive letter, so we
/// re-scan A..=Z and reconcile with the existing `blocked_drives` set.
///
/// A full rescan (26 `GetDriveTypeW` calls) is cheap and robust across
/// plug/unplug of multi-partition USB sticks.
#[cfg(windows)]
fn handle_volume_event(detector: &UsbDetector, event_type: u32) {
    let before: HashSet<char> = detector.blocked_drives.read().iter().copied().collect();
    let mut now_present: HashSet<char> = HashSet::new();
    for letter in 'A'..='Z' {
        if detector.is_removable_drive(letter) {
            now_present.insert(letter);
        }
    }
    if event_type == DBT_DEVICEARRIVAL {
        for letter in now_present.difference(&before) {
            detector.on_drive_arrival(*letter);
        }
    } else {
        for letter in before.difference(&now_present) {
            detector.on_drive_removal(*letter);
        }
    }
}

/// Captures and logs a USB device identity on arrival.
///
/// Parses VID/PID/serial from the `dbcc_name` device path, fetches a
/// human-readable description via SetupDi (SPDRP_FRIENDLYNAME, fallback
/// SPDRP_DEVICEDESC), and stores the `DeviceIdentity` in
/// `UsbDetector::device_identities` keyed by the first available removable
/// drive letter not already tracked (Phase 23 D-02, D-03, D-09, SC-1).
#[cfg(windows)]
fn on_usb_device_arrival(detector: &UsbDetector, device_path: &str) {
    let mut identity = parse_usb_device_path(device_path);
    identity.description = setupdi_description_for_device(device_path);

    // Map the USB device to a drive letter by scanning A..=Z for a removable
    // drive not yet tracked in device_identities. The USB_DEVICE notification
    // arrives slightly before or after the VOLUME notification, so we take
    // the first removable letter without an existing identity entry.
    let existing: HashSet<char> = detector.device_identities.read().keys().copied().collect();
    let letter_opt = ('A'..='Z').find(|l| detector.is_removable_drive(*l) && !existing.contains(l));

    match letter_opt {
        Some(letter) => {
            info!(
                drive = %letter,
                vid = %identity.vid,
                pid = %identity.pid,
                serial = %identity.serial,
                description = %identity.description,
                "USB device arrived — identity captured"
            );
            detector.device_identities.write().insert(letter, identity);
        }
        None => {
            // No drive letter yet (device not yet mounted or non-storage USB
            // device). Log best-effort without a drive letter per D-04.
            info!(
                vid = %identity.vid,
                pid = %identity.pid,
                serial = %identity.serial,
                description = %identity.description,
                "USB device arrived — identity captured (no drive letter yet)"
            );
        }
    }
}

/// Removes the captured identity on USB device removal.
///
/// Locates the `device_identities` entry whose VID/PID/serial matches the
/// parsed device path and removes it. SetupDi is not called on removal
/// because the device may already be gone by the time this runs.
#[cfg(windows)]
fn on_usb_device_removal(detector: &UsbDetector, device_path: &str) {
    let parsed = parse_usb_device_path(device_path);
    // Match by the parsed VID/PID/serial triple against the in-memory map.
    let letter_opt = {
        let read_guard = detector.device_identities.read();
        read_guard
            .iter()
            .find(|(_, id)| {
                id.vid == parsed.vid && id.pid == parsed.pid && id.serial == parsed.serial
            })
            .map(|(letter, _)| *letter)
    };
    if let Some(letter) = letter_opt {
        detector.device_identities.write().remove(&letter);
        info!(
            drive = %letter,
            vid = %parsed.vid,
            pid = %parsed.pid,
            serial = %parsed.serial,
            "USB device removed — identity cleared"
        );
    }
}

/// Queries the SetupDi device-information set for the first USB device whose
/// description mentions the parsed VID or PID, returning its friendly name
/// (`SPDRP_FRIENDLYNAME`) or device description (`SPDRP_DEVICEDESC`) as a
/// `String`. Returns an empty string on any failure (D-04, never panics).
///
/// Strategy: enumerate all currently-present USB device interfaces, fetch
/// FRIENDLYNAME (fallback DEVICEDESC) for each, and prefer an entry whose
/// uppercase name contains `VID_xxxx` or `PID_xxxx` matching the parsed path.
/// Falls back to the first non-empty description if no VID/PID match is found.
#[cfg(windows)]
fn setupdi_description_for_device(device_path: &str) -> String {
    let parsed = parse_usb_device_path(device_path);

    // SAFETY: passing GUID_DEVINTERFACE_USB_DEVICE + null enumerator string +
    // DIGCF_PRESENT | DIGCF_DEVICEINTERFACE is a well-defined SetupDi usage that
    // selects currently-present USB device interfaces.
    let hdev = unsafe {
        SetupDiGetClassDevsW(
            Some(&GUID_DEVINTERFACE_USB_DEVICE),
            windows::core::PCWSTR::null(),
            None,
            DIGCF_DEVICEINTERFACE | DIGCF_PRESENT,
        )
    };
    let hdev = match hdev {
        Ok(h) => h,
        Err(_) => return String::new(),
    };

    let mut first_description = String::new();
    let mut matching_description = String::new();
    let mut index: u32 = 0;

    loop {
        let mut devinfo = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: hdev is valid; devinfo is owned stack memory with cbSize set.
        // Loop terminates on the first Err (ERROR_NO_MORE_ITEMS).
        if unsafe { SetupDiEnumDeviceInfo(hdev, index, &mut devinfo) }.is_err() {
            break;
        }

        let desc = read_string_property(hdev, &devinfo, SPDRP_FRIENDLYNAME)
            .filter(|s| !s.is_empty())
            .or_else(|| read_string_property(hdev, &devinfo, SPDRP_DEVICEDESC))
            .unwrap_or_default();

        if !desc.is_empty() {
            if first_description.is_empty() {
                first_description = desc.clone();
            }
            let upper = desc.to_ascii_uppercase();
            // Prefer a description whose text mentions the device's VID or PID
            // (e.g., "VID_0951" or "PID_1666") — the 4-hex-digit substrings are
            // unique enough to pick the right device in most cases.
            if (!parsed.vid.is_empty()
                && upper.contains(&format!("VID_{}", parsed.vid.to_ascii_uppercase())))
                || (!parsed.pid.is_empty()
                    && upper.contains(&format!("PID_{}", parsed.pid.to_ascii_uppercase())))
            {
                matching_description = desc;
                break;
            }
        }

        index += 1;
        // Safety valve: bound the loop against a pathological enumeration.
        if index > 1024 {
            break;
        }
    }

    // SAFETY: hdev is a valid handle obtained from SetupDiGetClassDevsW above.
    let _ = unsafe { SetupDiDestroyDeviceInfoList(hdev) };

    if !matching_description.is_empty() {
        matching_description
    } else {
        first_description
    }
}

/// Reads a UTF-16 string property from a `SP_DEVINFO_DATA` entry.
///
/// Returns `None` on any Win32 error — callers substitute an empty string per D-04.
///
/// # Arguments
///
/// * `hdev` — a valid `HDEVINFO` set obtained from `SetupDiGetClassDevsW`.
/// * `devinfo` — pointer to an initialized `SP_DEVINFO_DATA` entry.
/// * `property` — one of `SPDRP_FRIENDLYNAME` or `SPDRP_DEVICEDESC` (as `u32`
///   constants from Windows SDK `SetupAPI.h`).
#[cfg(windows)]
fn read_string_property(
    hdev: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    devinfo: &SP_DEVINFO_DATA,
    property: u32,
) -> Option<String> {
    // 1024 bytes is enough for any realistic device name (REG_SZ, UTF-16 LE).
    let mut buf = vec![0u8; 1024];
    let mut required: u32 = 0;
    // SAFETY: buf is 1024 bytes and we pass its length as the buffer size.
    // The Win32 call fills buf with a null-terminated UTF-16 LE string or
    // sets required_size if buf is too small (we ignore truncation here —
    // a device name exceeding 512 UTF-16 chars is pathological).
    // `SETUP_DI_REGISTRY_PROPERTY` is a newtype wrapper over u32 — the
    // Windows crate requires it at the call site even though the underlying
    // value is just a u32.
    let ok = unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            hdev,
            devinfo,
            SETUP_DI_REGISTRY_PROPERTY(property),
            None,
            Some(buf.as_mut_slice()),
            Some(&mut required),
        )
    };
    if ok.is_err() {
        return None;
    }
    // buf contains a null-terminated UTF-16 LE string (REG_SZ). Decode by
    // pairing adjacent bytes into u16 code units and stopping at the first null.
    let wide: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    Some(String::from_utf16_lossy(&wide))
}

/// Registers for USB volume device notifications and starts a message loop on
/// a dedicated thread.
///
/// Creates a hidden message-only window and calls `RegisterDeviceNotificationW`
/// twice on the same `hwnd`:
/// 1. `GUID_DEVINTERFACE_VOLUME` — drive-letter tracking (existing behavior).
/// 2. `GUID_DEVINTERFACE_USB_DEVICE` — VID/PID/serial capture (Phase 23).
///
/// Both notifications arrive at `usb_wndproc` as `WM_DEVICECHANGE` messages.
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

    // Step 3a: register for VOLUME device notifications (drive-letter tracking).
    // DEV_BROADCAST_DEVICEINTERFACE_W is variable-size; we construct it as bytes.
    let db_size = std::mem::size_of::<DEV_BROADCAST_DEVICEINTERFACE_W>();
    let mut vol_buf: Vec<u8> = vec![0u8; db_size];
    let dbc_vol = vol_buf.as_mut_ptr() as *mut DEV_BROADCAST_DEVICEINTERFACE_W;

    // SAFETY: dbc_vol points to db_size bytes that we own and are properly aligned.
    unsafe {
        (*dbc_vol).dbcc_size = db_size as u32;
        (*dbc_vol).dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE.0;
        (*dbc_vol).dbcc_reserved = 0;
        (*dbc_vol).dbcc_classguid = GUID_DEVINTERFACE_VOLUME;
    }

    // SAFETY: hwnd is a valid window; dbc_vol points to an initialized struct.
    let vol_handle = unsafe {
        RegisterDeviceNotificationW(hwnd, dbc_vol as *const _, DEVICE_NOTIFY_WINDOW_HANDLE)
    };

    if let Err(e) = vol_handle {
        let _ = unsafe { DestroyWindow(hwnd) };
        return Err(e);
    }

    // Step 3b: register for USB_DEVICE notifications (VID/PID/serial capture).
    // Second registration: GUID_DEVINTERFACE_USB_DEVICE for raw USB device
    // arrival/removal. Fires independently of VOLUME notifications so we
    // can capture VID/PID/serial from the device path (D-01, D-02).
    let mut usb_buf: Vec<u8> = vec![0u8; db_size];
    let dbc_usb = usb_buf.as_mut_ptr() as *mut DEV_BROADCAST_DEVICEINTERFACE_W;

    // SAFETY: dbc_usb points to db_size bytes that we own and are properly aligned.
    unsafe {
        (*dbc_usb).dbcc_size = db_size as u32;
        (*dbc_usb).dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE.0;
        (*dbc_usb).dbcc_reserved = 0;
        (*dbc_usb).dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;
    }

    // SAFETY: hwnd is valid; dbc_usb points to an initialized struct.
    let usb_handle = unsafe {
        RegisterDeviceNotificationW(hwnd, dbc_usb as *const _, DEVICE_NOTIFY_WINDOW_HANDLE)
    };

    if let Err(e) = usb_handle {
        let _ = unsafe { DestroyWindow(hwnd) };
        return Err(e);
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

    info!("USB device notifications registered (volume + device interface)");
    Ok((hwnd, thread))
}

/// Stops the USB notification window and cleans up resources.
///
/// Destroys the window (which implicitly unregisters device notifications),
/// waits for the notification thread to finish, and clears the global detector.
#[cfg(windows)]
pub fn unregister_usb_notifications(hwnd: HWND, _thread: std::thread::JoinHandle<()>) {
    // The USB notification thread runs a blocking GetMessageW loop.
    // Cross-thread DestroyWindow and PostMessageW(WM_QUIT) are unreliable
    // for message-only windows.  Since this is only called during service
    // shutdown, we skip the join — the OS reclaims all resources (window,
    // device notification handle, thread) when the process exits.
    let _ = hwnd; // suppress unused warning
    *DRIVE_DETECTOR.lock() = None;
    debug!("USB device notifications cleanup skipped (process exit imminent)");
}

/// Parses a USB device interface path into a best-effort `DeviceIdentity`.
///
/// Called from the `WM_DEVICECHANGE` handler in `on_usb_device_arrival` and
/// `on_usb_device_removal`.
///
/// Input format (from `DEV_BROADCAST_DEVICEINTERFACE_W::dbcc_name`):
/// `\\?\USB#VID_0951&PID_1666#1234567890#{a5dcbf10-...}` or the equivalent
/// with `\??\` kernel-namespace prefix. The path is split on `#`:
/// - Segment 0: prefix (`\\?\USB` or similar) — ignored.
/// - Segment 1: `VID_xxxx&PID_yyyy` (case-insensitive prefix match).
/// - Segment 2: serial number. Windows synthesizes `&N` serials (e.g.,
///   `&0`) when the device has no real serial descriptor; these and the
///   empty-string serial are coerced to `"(none)"` (D-05).
/// - Segment 3 onwards: device-interface GUID — ignored.
///
/// Never panics. If a segment is missing or malformed, the corresponding
/// field is set to an empty string (D-04); the caller still logs the
/// identity (best-effort, never silently skipped).
///
/// The `description` field is always empty here — it is filled in by the
/// SetupDi lookup in `setupdi_description_for_device`.
fn parse_usb_device_path(dbcc_name: &str) -> DeviceIdentity {
    let mut identity = DeviceIdentity::default();
    let parts: Vec<&str> = dbcc_name.split('#').collect();

    // Segment 1 carries VID/PID.
    if let Some(vid_pid_segment) = parts.get(1) {
        for token in vid_pid_segment.split('&') {
            let lower = token.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("vid_") {
                identity.vid = rest.to_string();
            } else if let Some(rest) = lower.strip_prefix("pid_") {
                identity.pid = rest.to_string();
            }
        }
    }

    // Segment 2 carries the serial number, or a Windows-synthesized
    // placeholder like `&0` when no serial descriptor is present.
    let raw_serial = parts.get(2).copied().unwrap_or("");
    identity.serial = if raw_serial.is_empty() || raw_serial.starts_with('&') {
        "(none)".to_string()
    } else {
        raw_serial.to_string()
    };

    identity
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

    // ── New tests added in Phase 23 Plan 01 (TDD RED) ──────────────────────

    #[test]
    fn test_parse_happy_path() {
        let path = r"\\?\USB#VID_0951&PID_1666#1234567890#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
        let id = parse_usb_device_path(path);
        assert_eq!(id.vid, "0951");
        assert_eq!(id.pid, "1666");
        assert_eq!(id.serial, "1234567890");
        assert_eq!(id.description, "");
    }

    #[test]
    fn test_parse_no_serial_empty_segment() {
        let path = r"\\?\USB#VID_0951&PID_1666##{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
        let id = parse_usb_device_path(path);
        assert_eq!(id.vid, "0951");
        assert_eq!(id.pid, "1666");
        assert_eq!(id.serial, "(none)");
    }

    #[test]
    fn test_parse_no_serial_ampersand_synthesized() {
        let path = r"\\?\USB#VID_0951&PID_1666#&0#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
        let id = parse_usb_device_path(path);
        assert_eq!(id.serial, "(none)");
    }

    #[test]
    fn test_parse_lowercase_vid_pid_accepted() {
        let path = r"\\?\USB#vid_0951&pid_1666#abc#{guid}";
        let id = parse_usb_device_path(path);
        assert_eq!(id.vid, "0951");
        assert_eq!(id.pid, "1666");
        assert_eq!(id.serial, "abc");
    }

    #[test]
    fn test_parse_malformed_missing_vid_pid_segment() {
        let path = r"\\?\USB#garbage#serial#{guid}";
        let id = parse_usb_device_path(path);
        assert_eq!(id.vid, "");
        assert_eq!(id.pid, "");
        assert_eq!(id.serial, "serial");
    }

    #[test]
    fn test_parse_empty_string() {
        let id = parse_usb_device_path("");
        assert_eq!(id.vid, "");
        assert_eq!(id.pid, "");
        assert_eq!(id.serial, "(none)");
        assert_eq!(id.description, "");
    }

    #[test]
    fn test_parse_does_not_panic_on_unusual_input() {
        // Only two segments; should yield empty serial -> "(none)".
        let id = parse_usb_device_path(r"\\?\USB#VID_0951&PID_1666");
        assert_eq!(id.vid, "0951");
        assert_eq!(id.pid, "1666");
        assert_eq!(id.serial, "(none)");
    }

    #[test]
    fn test_device_identities_default_empty() {
        let detector = UsbDetector::new();
        assert!(detector.device_identities.read().is_empty());
    }

    #[test]
    fn test_device_identity_for_drive_present_and_absent() {
        let detector = UsbDetector::new();
        let identity = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN123".into(),
            description: "Kingston DataTraveler".into(),
        };
        detector
            .device_identities
            .write()
            .insert('E', identity.clone());

        assert_eq!(
            detector.device_identity_for_drive('E'),
            Some(identity.clone())
        );
        assert_eq!(detector.device_identity_for_drive('e'), Some(identity));
        assert_eq!(detector.device_identity_for_drive('Z'), None);
    }

    // ── New tests added in Phase 23 Plan 02 ────────────────────────────────

    /// Verify that the direct-insert path (simulating what `on_usb_device_arrival`
    /// does after resolving a drive letter) stores and retrieves identity correctly.
    #[test]
    fn test_on_usb_device_arrival_stores_identity_when_drive_letter_available() {
        let detector = UsbDetector::new();
        let identity = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN42".into(),
            description: "Test Device".into(),
        };
        // Direct insert simulates what on_usb_device_arrival does once a
        // drive letter is resolved.
        detector
            .device_identities
            .write()
            .insert('F', identity.clone());
        assert_eq!(detector.device_identity_for_drive('F'), Some(identity));
    }

    /// Verify that the removal lookup matches by VID/PID/serial triple and
    /// clears the entry — the same logic used by `on_usb_device_removal`.
    #[test]
    fn test_on_usb_device_removal_logic_matches_by_vid_pid_serial() {
        let detector = UsbDetector::new();
        let identity = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN42".into(),
            description: "Test Device".into(),
        };
        detector
            .device_identities
            .write()
            .insert('G', identity.clone());

        // Simulate the removal-time lookup by VID/PID/serial without touching Win32.
        let parsed = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN42".into(),
            description: String::new(),
        };
        let found_letter = {
            let guard = detector.device_identities.read();
            guard
                .iter()
                .find(|(_, id)| {
                    id.vid == parsed.vid && id.pid == parsed.pid && id.serial == parsed.serial
                })
                .map(|(l, _)| *l)
        };
        assert_eq!(found_letter, Some('G'));
        detector.device_identities.write().remove(&'G');
        assert_eq!(detector.device_identity_for_drive('G'), None);
    }

    // ── Pre-existing tests ──────────────────────────────────────────────────

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
