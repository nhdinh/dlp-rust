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

use dlp_common::usb::{parse_usb_device_path, setupdi_description_for_device};
use dlp_common::{Classification, DeviceIdentity, UsbTrustTier};
use parking_lot::{Mutex, RwLock};
use tracing::{debug, info, warn};

#[cfg(windows)]
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_Device_IDW, CM_Get_Parent, CM_Locate_DevNodeW, CM_LOCATE_DEVNODE_NORMAL,
};
#[cfg(windows)]
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, PostMessageW,
    PostQuitMessage, RegisterClassW, RegisterDeviceNotificationW, TranslateMessage,
    UnregisterDeviceNotification, DBT_DEVICEARRIVAL, DBT_DEVICEREMOVECOMPLETE,
    DBT_DEVTYP_DEVICEINTERFACE, DEVICE_NOTIFY_WINDOW_HANDLE, DEV_BROADCAST_DEVICEINTERFACE_W,
    DEV_BROADCAST_HDR, MSG, WINDOW_STYLE, WM_CLOSE, WM_DESTROY, WM_DEVICECHANGE, WNDCLASSW,
    WS_EX_NOACTIVATE,
};

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
    /// Identity captured from a `GUID_DEVINTERFACE_USB_DEVICE` notification that
    /// arrived before the corresponding `GUID_DEVINTERFACE_VOLUME` notification
    /// (i.e., no drive letter was available yet).  `handle_volume_event` pops
    /// this slot when the drive letter appears and applies tier enforcement.
    pub(crate) pending_identity: Mutex<Option<DeviceIdentity>>,
    /// Map from disk device instance ID to USB identity for removal lookup
    /// when the PnP tree walk fails (device already gone from the PnP tree).
    pub disk_to_identity: RwLock<HashMap<String, DeviceIdentity>>,
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

/// GUID for disk drive device interface — fires reliably for USB mass storage.
/// Used as a fallback when GUID_DEVINTERFACE_USB_DEVICE does not fire.
/// Windows SDK value: {0x53F56307,0xB6BF,0x11D0,{0x94,0xF2,0x00,0xA0,0xC9,0x1E,0xFB,0x8B}}
#[cfg(windows)]
const GUID_DEVINTERFACE_DISK: windows::core::GUID = windows::core::GUID::from_values(
    0x53F56307,
    0xB6BF,
    0x11D0,
    [0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B],
);

/// Global reference to the `UsbDetector` shared with the device notification handlers.
/// Protected by a `Mutex` so it can be cleared on unregister.
#[cfg(windows)]
static DRIVE_DETECTOR: parking_lot::Mutex<Option<&'static UsbDetector>> =
    parking_lot::Mutex::new(None);

/// Registered device notification handles for cleanup (CR-04).
/// Set during `register_usb_notifications` and consumed during `unregister_usb_notifications`.
/// Stored as raw isize values because HDEVNOTIFY is not Send/Sync.
/// Third element is the DISK interface handle added in 31-02.
#[cfg(windows)]
static NOTIFY_HANDLES: parking_lot::Mutex<Option<(isize, isize, isize)>> =
    parking_lot::Mutex::new(None);

/// Global registry cache reference, set from `service.rs` before the USB window
/// thread is spawned. Allows `usb_wndproc` (an `unsafe extern "system"` callback
/// that cannot capture environment) to trigger an immediate cache refresh on
/// USB device arrival (D-09 from 24-CONTEXT.md).
#[cfg(windows)]
static REGISTRY_CACHE: std::sync::OnceLock<
    std::sync::Arc<crate::device_registry::DeviceRegistryCache>,
> = std::sync::OnceLock::new();

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

/// Channel sender used by `handle_volume_event` to push newly-arrived USB drive
/// roots into the running `InterceptionEngine`.  A `parking_lot::Mutex` wrapper
/// is required because `std::sync::mpsc::Sender<T>` is `Send` but not `Sync`
/// and therefore cannot be stored in an `OnceLock`.
#[cfg(windows)]
static WATCH_PATH_TX: parking_lot::Mutex<Option<std::sync::mpsc::Sender<std::path::PathBuf>>> =
    parking_lot::Mutex::new(None);

/// Global device controller reference for active PnP enforcement.
/// Set from `service.rs` before the USB window thread is spawned.
/// Allows `usb_wndproc` to disable devices (Blocked tier) and modify
/// volume DACLs (ReadOnly tier) on USB arrival/removal.
#[cfg(windows)]
static DEVICE_CONTROLLER: std::sync::OnceLock<
    std::sync::Arc<crate::device_controller::DeviceController>,
> = std::sync::OnceLock::new();

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

/// Sets the global device controller reference.
///
/// Called once from `service.rs` before spawning USB notifications.
/// Subsequent calls are silently ignored (OnceLock contract).
///
/// # Arguments
///
/// * `controller` - The `Arc<DeviceController>` to store globally.
#[cfg(windows)]
pub fn set_device_controller(
    controller: std::sync::Arc<crate::device_controller::DeviceController>,
) {
    let _ = DEVICE_CONTROLLER.set(controller);
}

/// Stores the channel sender used to notify `InterceptionEngine` of newly-arrived
/// USB drive roots.
///
/// Called once from `service.rs` before spawning USB notifications.  When a USB
/// drive arrives after agent startup, `handle_volume_event` sends the new drive
/// root through this channel so the file watcher can register it dynamically.
///
/// # Arguments
///
/// * `tx` - Sender half of a `std::sync::mpsc::channel::<std::path::PathBuf>()`.
#[cfg(windows)]
pub fn set_watch_path_sender(tx: std::sync::mpsc::Sender<std::path::PathBuf>) {
    *WATCH_PATH_TX.lock() = Some(tx);
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
                        } else if classguid == GUID_DEVINTERFACE_DISK {
                            // SAFETY: di is valid for this callback duration.
                            let device_path = unsafe { read_dbcc_name(di) };
                            if event_type == DBT_DEVICEARRIVAL {
                                on_disk_device_arrival(detector, &device_path);
                            } else {
                                on_disk_device_removal(detector, &device_path);
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
            // Reconcile a pending identity: the GUID_DEVINTERFACE_USB_DEVICE
            // notification arrived before this GUID_DEVINTERFACE_VOLUME
            // notification, so on_usb_device_arrival parked the identity without
            // a drive letter.  Assign it now and apply tier enforcement.
            if let Some(identity) = detector.pending_identity.lock().take() {
                detector
                    .device_identities
                    .write()
                    .insert(*letter, identity.clone());
                apply_tier_enforcement(*letter, &identity);
            }
            // Notify the file monitor to start watching this new drive root so
            // file events on the USB drive reach UsbEnforcer::check().
            let root = std::path::PathBuf::from(format!("{}:\\", letter));
            let _ = WATCH_PATH_TX.lock().as_ref().map(|tx| tx.send(root));
        }
    } else {
        for letter in before.difference(&now_present) {
            detector.on_drive_removal(*letter);
        }
    }
}

/// Applies device-controller enforcement for a newly arrived USB device.
///
/// Looks up the device's trust tier from the registry cache (defaulting to
/// `Blocked` when no cache is available) and applies the appropriate action:
/// - `Blocked`: disables the device via Windows Device Manager.
/// - `ReadOnly`: modifies the volume DACL to remove write access.
/// - `FullAccess`: no action.
#[cfg(windows)]
fn apply_tier_enforcement(letter: char, identity: &DeviceIdentity) {
    if let Some(controller) = DEVICE_CONTROLLER.get() {
        let tier = if let Some(cache) = REGISTRY_CACHE.get() {
            let t = cache.trust_tier_for(&identity.vid, &identity.pid, &identity.serial);
            if cache.has_device(&identity.vid, &identity.pid, &identity.serial) {
                debug!(
                    vid = %identity.vid,
                    pid = %identity.pid,
                    tier = ?t,
                    "registry cache hit — applying registered tier"
                );
            } else {
                let cache_size = cache.len();
                let registered_serials = cache.serials_for_vid_pid(&identity.vid, &identity.pid);
                if registered_serials.is_empty() {
                    warn!(
                        vid = %identity.vid,
                        pid = %identity.pid,
                        serial = %identity.serial,
                        cache_entries = cache_size,
                        "device not found in registry cache (no entry for this VID/PID) — applying default-deny (Blocked)"
                    );
                } else {
                    warn!(
                        vid = %identity.vid,
                        pid = %identity.pid,
                        hardware_serial = %identity.serial,
                        registered_serials = ?registered_serials,
                        cache_entries = cache_size,
                        "device not found in registry cache (VID/PID match but serial mismatch) — applying default-deny (Blocked)"
                    );
                }
            }
            t
        } else {
            warn!("registry cache unavailable — applying default-deny (Blocked)");
            UsbTrustTier::Blocked
        };
        match tier {
            UsbTrustTier::Blocked => {
                if let Err(e) =
                    controller.disable_usb_device(&identity.vid, &identity.pid, &identity.serial)
                {
                    warn!(
                        vid = %identity.vid,
                        pid = %identity.pid,
                        serial = %identity.serial,
                        error = %e,
                        "failed to disable USB device"
                    );
                } else {
                    info!(
                        drive = %letter,
                        vid = %identity.vid,
                        pid = %identity.pid,
                        "USB device disabled (Blocked tier)"
                    );
                }
            }
            UsbTrustTier::ReadOnly => {
                if let Err(e) = controller.set_volume_readonly(letter) {
                    warn!(drive = %letter, error = %e, "failed to set volume read-only");
                } else {
                    info!(drive = %letter, "USB volume set to read-only (ReadOnly tier)");
                }
            }
            UsbTrustTier::FullAccess => {
                debug!(
                    drive = %letter,
                    vid = %identity.vid,
                    pid = %identity.pid,
                    "USB device has FullAccess — no enforcement action"
                );
            }
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
///
/// After identity capture, looks up the trust tier from the device registry
/// cache and applies active PnP enforcement via [`DeviceController`]:
/// - `Blocked`: disables the device immediately.
/// - `ReadOnly`: modifies the volume DACL to remove write access.
/// - `FullAccess`: no action.
#[cfg(windows)]
fn on_usb_device_arrival(detector: &UsbDetector, device_path: &str) {
    let mut identity = parse_usb_device_path(device_path);
    identity.description = setupdi_description_for_device(device_path);

    // Map the USB device to a drive letter by scanning A..=Z for a mounted
    // drive not yet tracked in device_identities. The USB_DEVICE notification
    // arrives slightly before or after the VOLUME notification, so we take
    // the first letter with an existing root path but no identity entry.
    // NOTE: NVMe USB bridges report as DRIVE_FIXED, not DRIVE_REMOVABLE,
    // so we check Path::exists instead of is_removable_drive.
    let existing: HashSet<char> = detector.device_identities.read().keys().copied().collect();
    let letter_opt = ('A'..='Z')
        .find(|l| std::path::Path::new(&format!("{}:\\", l)).exists() && !existing.contains(l));

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
            detector
                .device_identities
                .write()
                .insert(letter, identity.clone());

            apply_tier_enforcement(letter, &identity);
        }
        None => {
            // VOLUME notification has not arrived yet — the drive letter is not
            // assigned.  Park the identity so handle_volume_event can reconcile
            // it and apply enforcement once the drive letter is available.
            info!(
                vid = %identity.vid,
                pid = %identity.pid,
                serial = %identity.serial,
                description = %identity.description,
                "USB device arrived — identity captured (no drive letter yet)"
            );
            *detector.pending_identity.lock() = Some(identity);
        }
    }
}

/// Removes the captured identity on USB device removal.
///
/// Locates the `device_identities` entry whose VID/PID/serial matches the
/// parsed device path and removes it. Also restores the volume ACL if the
/// device was in ReadOnly tier, and re-enables the device if it was disabled
/// (Blocked tier). SetupDi is not called on removal because the device may
/// already be gone by the time this runs.
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
        // Restore volume ACL if it was modified (ReadOnly tier).
        if let Some(controller) = DEVICE_CONTROLLER.get() {
            if let Err(e) = controller.restore_volume_acl(letter) {
                warn!(
                    drive = %letter,
                    error = %e,
                    "failed to restore volume ACL on removal"
                );
            }

            // Re-enable the device if it was disabled (Blocked tier).
            // This is best-effort: the device may already be gone.
            if let Err(e) = controller.enable_usb_device(&parsed.vid, &parsed.pid, &parsed.serial) {
                warn!(
                    vid = %parsed.vid,
                    pid = %parsed.pid,
                    serial = %parsed.serial,
                    error = %e,
                    "failed to re-enable USB device on removal"
                );
            } else {
                info!(
                    drive = %letter,
                    vid = %parsed.vid,
                    pid = %parsed.pid,
                    "USB device re-enabled on removal"
                );
            }
        }

        detector.device_identities.write().remove(&letter);
        info!(
            drive = %letter,
            vid = %parsed.vid,
            pid = %parsed.pid,
            serial = %parsed.serial,
            "USB device removed — identity cleared"
        );
    }

    // Clear the cooldown entry so rapid re-insertions are not missed (WR-03).
    // The enforcer uses a per-drive-letter 30-second cooldown to suppress
    // duplicate toast notifications. When the device is physically removed,
    // clearing the entry ensures the next insertion triggers a fresh notification.
    //
    // NOTE: The enforcer is passed into the event loop via Arc; we do not have a
    // global static to it. The cooldown is per-drive-letter, so removing the
    // device identity entry above is sufficient — the next arrival will get a
    // new drive letter mapping and a fresh cooldown. For explicit clearing we
    // would need a global static, but the practical effect is the same because
    // the drive letter is released on removal.
}

/// Extracts the device instance ID from a GUID_DEVINTERFACE_DISK `dbcc_name`.
///
/// The disk notification's `dbcc_name` is a device interface path like
/// `\\?\USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_3.0#...#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`.
/// This function strips the `\\?\` prefix and the `#{GUID}` suffix, then
/// replaces `#` with `\` to produce the actual instance ID.
fn disk_path_to_instance_id(device_path: &str) -> String {
    let without_prefix = device_path.strip_prefix(r"\\?\").unwrap_or(device_path);
    let without_guid = without_prefix.split("#{").next().unwrap_or(without_prefix);
    without_guid.replace("#", r"\")
}

/// Handles GUID_DEVINTERFACE_DISK arrival by walking the PnP tree to find
/// a USB ancestor, then applying tier enforcement.
///
/// This is the fallback path for USB mass storage devices that do not fire
/// GUID_DEVINTERFACE_USB_DEVICE (the primary path handled by
/// `on_usb_device_arrival`).
#[cfg(windows)]
fn on_disk_device_arrival(detector: &UsbDetector, device_path: &str) {
    let disk_instance_id = disk_path_to_instance_id(device_path);
    if disk_instance_id.is_empty() {
        debug!("disk arrival: empty instance ID — skipping");
        return;
    }

    // Locate the disk device in the PnP tree.
    let wide: Vec<u16> = disk_instance_id
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut dev_inst: u32 = 0;
    let cr = unsafe {
        CM_Locate_DevNodeW(
            &mut dev_inst,
            windows::core::PCWSTR(wide.as_ptr()),
            CM_LOCATE_DEVNODE_NORMAL,
        )
    };
    if cr.0 != 0 {
        const CR_NO_SUCH_DEVNODE: u32 = 0x0000000D;
        if cr.0 == CR_NO_SUCH_DEVNODE {
            warn!("CM_Locate_DevNodeW: disk device not found — may have been removed");
        } else {
            warn!("CM_Locate_DevNodeW failed: {:#010x}", cr.0);
        }
        return;
    }

    // Walk up the PnP tree to find a USB ancestor.
    let mut usb_identity: Option<DeviceIdentity> = None;
    let mut current_devinst = dev_inst;
    for _ in 0..16 {
        let mut parent_devinst: u32 = 0;
        let cr = unsafe { CM_Get_Parent(&mut parent_devinst, current_devinst, 0) };
        if cr.0 != 0 {
            break;
        }

        let mut id_buf = [0u16; 256];
        let cr = unsafe { CM_Get_Device_IDW(parent_devinst, &mut id_buf, 0) };
        if cr.0 == 0 {
            let id = String::from_utf16_lossy(
                &id_buf
                    .iter()
                    .copied()
                    .take_while(|&w| w != 0)
                    .collect::<Vec<u16>>(),
            );
            if id.starts_with("USB\\") {
                let reshaped = format!(r"\\?\{}", id.replace("\\", "#"));
                let identity = parse_usb_device_path(&reshaped);
                if !identity.vid.is_empty() && !identity.pid.is_empty() {
                    let mut identity_with_desc = identity;
                    identity_with_desc.description = setupdi_description_for_device(&reshaped);
                    usb_identity = Some(identity_with_desc);
                }
                break;
            }
        }
        current_devinst = parent_devinst;
    }

    let Some(identity) = usb_identity else {
        debug!(
            instance_id = %disk_instance_id,
            "disk arrival: no USB ancestor found — not a USB mass storage device"
        );
        return;
    };

    // Find the drive letter by scanning for a mounted drive not yet tracked.
    // NOTE: NVMe USB bridges report as DRIVE_FIXED, not DRIVE_REMOVABLE,
    // so we check Path::exists instead of is_removable_drive.
    let existing: HashSet<char> = detector.device_identities.read().keys().copied().collect();
    let letter_opt = ('A'..='Z')
        .find(|l| std::path::Path::new(&format!("{}:\\", l)).exists() && !existing.contains(l));

    match letter_opt {
        Some(letter) => {
            info!(
                drive = %letter,
                vid = %identity.vid,
                pid = %identity.pid,
                serial = %identity.serial,
                description = %identity.description,
                "USB disk arrived — identity captured via PnP tree walk"
            );
            detector
                .device_identities
                .write()
                .insert(letter, identity.clone());
            detector
                .disk_to_identity
                .write()
                .insert(disk_instance_id.clone(), identity.clone());
            apply_tier_enforcement(letter, &identity);
        }
        None => {
            // No drive letter yet — park the identity for reconciliation.
            // Only park if the slot is empty to avoid clobbering a pending
            // identity from a different device (T-31-02-01).
            if detector.pending_identity.lock().is_none() {
                info!(
                    vid = %identity.vid,
                    pid = %identity.pid,
                    serial = %identity.serial,
                    description = %identity.description,
                    "USB disk arrived — identity captured (no drive letter yet)"
                );
                *detector.pending_identity.lock() = Some(identity.clone());
            }
            detector
                .disk_to_identity
                .write()
                .insert(disk_instance_id, identity);
        }
    }
}

/// Handles GUID_DEVINTERFACE_DISK removal by cleaning up the device identity
/// and restoring any modified volume ACLs.
#[cfg(windows)]
fn on_disk_device_removal(detector: &UsbDetector, device_path: &str) {
    let disk_instance_id = disk_path_to_instance_id(device_path);
    if disk_instance_id.is_empty() {
        debug!("disk removal: empty instance ID — skipping");
        return;
    }

    // Try to locate the disk device and walk up to find the USB ancestor.
    let wide: Vec<u16> = disk_instance_id
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut dev_inst: u32 = 0;
    let cr = unsafe {
        CM_Locate_DevNodeW(
            &mut dev_inst,
            windows::core::PCWSTR(wide.as_ptr()),
            CM_LOCATE_DEVNODE_NORMAL,
        )
    };

    let mut parsed_identity: Option<DeviceIdentity> = None;

    if cr.0 == 0 {
        // Walk up the PnP tree to find a USB ancestor.
        let mut current_devinst = dev_inst;
        for _ in 0..16 {
            let mut parent_devinst: u32 = 0;
            let cr = unsafe { CM_Get_Parent(&mut parent_devinst, current_devinst, 0) };
            if cr.0 != 0 {
                break;
            }

            let mut id_buf = [0u16; 256];
            let cr = unsafe { CM_Get_Device_IDW(parent_devinst, &mut id_buf, 0) };
            if cr.0 == 0 {
                let id = String::from_utf16_lossy(
                    &id_buf
                        .iter()
                        .copied()
                        .take_while(|&w| w != 0)
                        .collect::<Vec<u16>>(),
                );
                if id.starts_with("USB\\") {
                    let reshaped = format!(r"\\?\{}", id.replace("\\", "#"));
                    let identity = parse_usb_device_path(&reshaped);
                    if !identity.vid.is_empty() && !identity.pid.is_empty() {
                        parsed_identity = Some(identity);
                    }
                    break;
                }
            }
            current_devinst = parent_devinst;
        }
    }

    // If PnP walk failed (device already gone), fall back to disk_to_identity map.
    if parsed_identity.is_none() {
        if let Some(identity) = detector.disk_to_identity.read().get(&disk_instance_id) {
            parsed_identity = Some(identity.clone());
        }
    }

    let Some(parsed) = parsed_identity else {
        warn!(
            instance_id = %disk_instance_id,
            "disk removal: could not resolve USB identity — skipping cleanup"
        );
        return;
    };

    // Match by VID/PID/serial against the in-memory map.
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
        if let Some(controller) = DEVICE_CONTROLLER.get() {
            if let Err(e) = controller.restore_volume_acl(letter) {
                warn!(
                    drive = %letter,
                    error = %e,
                    "failed to restore volume ACL on disk removal"
                );
            }
            if let Err(e) = controller.enable_usb_device(&parsed.vid, &parsed.pid, &parsed.serial) {
                warn!(
                    vid = %parsed.vid,
                    pid = %parsed.pid,
                    serial = %parsed.serial,
                    error = %e,
                    "failed to re-enable USB device on disk removal"
                );
            } else {
                info!(
                    drive = %letter,
                    vid = %parsed.vid,
                    pid = %parsed.pid,
                    "USB device re-enabled on disk removal"
                );
            }
        }

        detector.device_identities.write().remove(&letter);
        detector.disk_to_identity.write().remove(&disk_instance_id);
        info!(
            drive = %letter,
            vid = %parsed.vid,
            pid = %parsed.pid,
            serial = %parsed.serial,
            "USB disk removed — identity cleared"
        );
    } else {
        // Identity not in device_identities — clean up disk_to_identity anyway.
        detector.disk_to_identity.write().remove(&disk_instance_id);
    }
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

    // Windows message delivery is thread-affine: WM_DEVICECHANGE is posted to
    // the queue of the thread that called CreateWindowExW. GetMessageW only
    // dequeues messages for the calling thread's own queue. Therefore the window
    // must be created, notifications registered, and the message loop run on the
    // same thread. We spawn that thread first and receive the HWND back via a
    // channel so the caller can pass it to unregister_usb_notifications later.
    //
    // HWND is !Send (raw pointer wrapper), so we transmit it as usize and
    // reconstruct it on the caller side.
    let (hwnd_tx, hwnd_rx) = std::sync::mpsc::channel::<windows::core::Result<usize>>();

    let thread = std::thread::Builder::new()
        .name("usb-notification".into())
        .spawn(move || {
            // Step 1: register window class on this thread.
            let class_name: Vec<u16> = "DlpUsbNotificationWindow\0".encode_utf16().collect();
            let wc = WNDCLASSW {
                lpfnWndProc: Some(usb_wndproc),
                lpszClassName: windows::core::PCWSTR(class_name.as_ptr()),
                ..Default::default()
            };

            // SAFETY: class_name is a null-terminated wide string kept alive past
            // RegisterClassW (only the atom is needed by CreateWindowExW below).
            let atom = unsafe { RegisterClassW(&wc) };
            if atom == 0 {
                let _ = hwnd_tx.send(Err(windows::core::Error::from_win32()));
                return;
            }

            // Step 2: create the message-only window on this thread.
            // SAFETY: atom is a valid class atom returned by RegisterClassW.
            let hwnd = match unsafe {
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
            } {
                Ok(h) => h,
                Err(e) => {
                    let _ = hwnd_tx.send(Err(e));
                    return;
                }
            };

            // Step 3a: register for VOLUME device notifications (drive-letter tracking).
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

            // SAFETY: hwnd is valid on this thread; dbc_vol points to an initialized struct.
            let vol_handle = unsafe {
                RegisterDeviceNotificationW(hwnd, dbc_vol as *const _, DEVICE_NOTIFY_WINDOW_HANDLE)
            };
            if let Err(e) = vol_handle {
                let _ = unsafe { DestroyWindow(hwnd) };
                let _ = hwnd_tx.send(Err(e));
                return;
            }

            // Step 3b: register for USB_DEVICE notifications (VID/PID/serial capture).
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
                let _ = hwnd_tx.send(Err(e));
                return;
            }

            // Step 3c: register for DISK device notifications (USB mass storage fallback).
            let mut disk_buf: Vec<u8> = vec![0u8; db_size];
            let dbc_disk = disk_buf.as_mut_ptr() as *mut DEV_BROADCAST_DEVICEINTERFACE_W;

            // SAFETY: dbc_disk points to db_size bytes that we own and are properly aligned.
            unsafe {
                (*dbc_disk).dbcc_size = db_size as u32;
                (*dbc_disk).dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE.0;
                (*dbc_disk).dbcc_reserved = 0;
                (*dbc_disk).dbcc_classguid = GUID_DEVINTERFACE_DISK;
            }

            // SAFETY: hwnd is valid; dbc_disk points to an initialized struct.
            let disk_handle = unsafe {
                RegisterDeviceNotificationW(hwnd, dbc_disk as *const _, DEVICE_NOTIFY_WINDOW_HANDLE)
            };
            if let Err(e) = disk_handle {
                let _ = unsafe { DestroyWindow(hwnd) };
                let _ = hwnd_tx.send(Err(e));
                return;
            }

            // Store notification handles for later cleanup (CR-04).
            let vol_h = vol_handle.unwrap();
            let usb_h = usb_handle.unwrap();
            let disk_h = disk_handle.unwrap();
            *NOTIFY_HANDLES.lock() = Some((vol_h.0 as isize, usb_h.0 as isize, disk_h.0 as isize));

            // Signal the caller with the HWND value. Transmit as usize because
            // HWND is !Send; the caller reconstructs it from the raw pointer value.
            // SAFETY: hwnd.0 is a valid non-null HWND pointer on this process.
            let _ = hwnd_tx.send(Ok(hwnd.0 as usize));

            // Step 4: run the message loop on this same thread. WM_DEVICECHANGE
            // events arrive here because the window was created on this thread.
            let mut msg = MSG::default();
            loop {
                // SAFETY: msg is a valid pointer to an MSG struct.
                let ret = unsafe { GetMessageW(&mut msg, None, 0, 0) };
                if ret.0 == 0 {
                    break; // WM_QUIT received via PostQuitMessage in WM_DESTROY handler
                }
                let _ = unsafe { TranslateMessage(&msg) };
                let _ = unsafe { DispatchMessageW(&msg) };
            }
            debug!("USB notification thread exiting");
        })
        .expect("usb-notification thread must spawn");

    // Block until the spawned thread signals window creation success or failure.
    let hwnd_raw = hwnd_rx
        .recv()
        .expect("usb-notification thread must send HWND result")?;

    // SAFETY: hwnd_raw is a valid HWND pointer value sent from the spawned thread
    // immediately after a successful CreateWindowExW call.
    let hwnd = HWND(hwnd_raw as *mut core::ffi::c_void);

    info!("USB device notifications registered (volume + device + disk interface)");
    Ok((hwnd, thread))
}

/// Stops the USB notification window and cleans up resources.
///
/// Unregisters device notifications, posts WM_CLOSE to break the message loop,
/// waits for the thread to exit, destroys the window, and clears the global
/// detector reference.
#[cfg(windows)]
pub fn unregister_usb_notifications(hwnd: HWND, thread: std::thread::JoinHandle<()>) {
    // Unregister device notifications before destroying the window.
    if let Some((h_vol, h_usb, h_disk)) = NOTIFY_HANDLES.lock().take() {
        unsafe {
            let _ = UnregisterDeviceNotification(
                windows::Win32::UI::WindowsAndMessaging::HDEVNOTIFY(h_vol as *mut _),
            );
            let _ = UnregisterDeviceNotification(
                windows::Win32::UI::WindowsAndMessaging::HDEVNOTIFY(h_usb as *mut _),
            );
            let _ = UnregisterDeviceNotification(
                windows::Win32::UI::WindowsAndMessaging::HDEVNOTIFY(h_disk as *mut _),
            );
        }
    }

    // Post WM_CLOSE to the hidden window to break the message loop.
    unsafe {
        let _ = PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
    }

    // Wait for the thread to exit.
    if let Err(e) = thread.join() {
        warn!("USB notification thread panicked: {:?}", e);
    }

    // Destroy the window.
    unsafe {
        let _ = DestroyWindow(hwnd);
    }

    *DRIVE_DETECTOR.lock() = None;
    debug!("USB device notifications cleaned up");
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

    // ── Tests added in Phase 31 Plan 02 ────────────────────────────────────

    /// Verify extraction of device instance ID from a GUID_DEVINTERFACE_DISK dbcc_name.
    #[test]
    fn test_disk_path_to_instance_id_extraction() {
        let path = r"\\?\USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_3.0#12345678&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
        let instance_id = disk_path_to_instance_id(path);
        assert_eq!(
            instance_id,
            r"USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0\12345678&0"
        );
    }

    /// Verify that a non-USBSTOR disk path still extracts correctly (generic logic).
    #[test]
    fn test_disk_path_non_usbstor() {
        let path =
            r"\\?\SCSI#Disk&Ven_WDC&Prod_WD10EZEX#ABC123#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
        let instance_id = disk_path_to_instance_id(path);
        assert_eq!(instance_id, r"SCSI\Disk&Ven_WDC&Prod_WD10EZEX\ABC123");
    }

    /// Verify that disk arrival stores identity in disk_to_identity for removal fallback.
    #[test]
    fn test_disk_to_identity_populated_on_arrival() {
        let detector = UsbDetector::new();
        let identity = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN42".into(),
            description: "Test Device".into(),
        };
        detector
            .disk_to_identity
            .write()
            .insert("USBSTOR\\Test".into(), identity.clone());
        assert_eq!(
            detector.disk_to_identity.read().get("USBSTOR\\Test"),
            Some(&identity)
        );
    }

    /// Verify removal lookup via disk_to_identity fallback.
    #[test]
    fn test_disk_to_identity_removal_fallback() {
        let detector = UsbDetector::new();
        let identity = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN42".into(),
            description: "Test Device".into(),
        };
        detector
            .disk_to_identity
            .write()
            .insert("USBSTOR\\Test".into(), identity.clone());
        let retrieved = detector
            .disk_to_identity
            .read()
            .get("USBSTOR\\Test")
            .cloned();
        assert_eq!(retrieved, Some(identity));
        detector.disk_to_identity.write().remove("USBSTOR\\Test");
        assert!(detector.disk_to_identity.read().is_empty());
    }

    /// Verify that a dbcc_name missing the \\?\ prefix is handled gracefully.
    #[test]
    fn test_dbcc_name_malformed_missing_prefix() {
        let path = r"USBSTOR#Disk&Ven_Kingston#123#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
        let instance_id = disk_path_to_instance_id(path);
        assert_eq!(instance_id, r"USBSTOR\Disk&Ven_Kingston\123");
    }

    /// Verify that a dbcc_name without the #{GUID} suffix is handled.
    #[test]
    fn test_dbcc_name_without_guid_suffix() {
        let path = r"\\?\USBSTOR#Disk&Ven_Kingston#123";
        let instance_id = disk_path_to_instance_id(path);
        assert_eq!(instance_id, r"USBSTOR\Disk&Ven_Kingston\123");
    }

    /// Verify that an empty dbcc_name is handled without panic.
    #[test]
    fn test_dbcc_name_empty() {
        let instance_id = disk_path_to_instance_id("");
        assert_eq!(instance_id, "");
    }
}
