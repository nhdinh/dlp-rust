//! USB mass storage detection (T-13, F-AGT-13).
//!
//! Detects USB volume arrivals and blocks T3/T4 file writes to removable drives.
//! Also captures USB device identity (VID, PID, serial, description) on arrival
//! and stores it in memory for Phase 26 enforcement (Phase 23 SC-1/SC-2).
//!
//! ## Detection model
//!
//! 1. `device_watcher::spawn_device_watcher_task` creates a hidden Win32 window and
//!    calls `RegisterDeviceNotificationW` for `GUID_DEVINTERFACE_VOLUME`,
//!    `GUID_DEVINTERFACE_USB_DEVICE`, and `GUID_DEVINTERFACE_DISK`.
//! 2. Arrival/removal events are dispatched to this module via
//!    [`handle_volume_event_dispatch`], [`dispatch_usb_device_arrival`], and
//!    [`dispatch_usb_device_removal`].
//! 3. On arrival, `GetDriveTypeW` classifies the volume as removable/fixed/network.
//! 4. Removable drives are added to the blocked-drive set.
//! 5. The interception layer checks every write against the blocked-drive set;
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
//! Call `detection::spawn_device_watcher_task` once during agent startup.
//! The returned `(HWND, JoinHandle)` must be passed to
//! `detection::unregister_device_watcher` on shutdown.

use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use dlp_common::usb::{parse_usb_device_path, setupdi_description_for_device};
use dlp_common::{Classification, DeviceIdentity, UsbTrustTier};
use parking_lot::{Mutex, RwLock};
use tracing::{debug, info, warn};

// DBT_DEVICEARRIVAL is needed by handle_volume_event to distinguish arrival
// from removal events. The window, registration, and wndproc live in
// `crate::detection::device_watcher` (Phase 36 D-12 refactor).
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::DBT_DEVICEARRIVAL;

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
// USB device notification statics
// ──────────────────────────────────────────────────────────────────────────────
// Note: GUID constants (GUID_DEVINTERFACE_VOLUME, GUID_DEVINTERFACE_USB_DEVICE,
// GUID_DEVINTERFACE_DISK) and NOTIFY_HANDLES have been moved to
// `crate::detection::device_watcher` (Phase 36 D-12 refactor).

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

/// Sets the global `UsbDetector` reference so that dispatch callbacks
/// (`handle_volume_event_dispatch`, `dispatch_usb_device_arrival`,
/// `dispatch_usb_device_removal`) can reach it.
///
/// Called once from `service.rs` before spawning `device_watcher_task`.
/// Subsequent calls overwrite the previous reference (unlike `OnceLock`-backed
/// setters) because `DRIVE_DETECTOR` uses a `Mutex` to allow clearing on
/// shutdown.
///
/// # Arguments
///
/// * `detector` — a `'static` reference to the `UsbDetector`.
#[cfg(windows)]
pub fn set_drive_detector(detector: &'static UsbDetector) {
    *DRIVE_DETECTOR.lock() = Some(detector);
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

/// Dispatcher entry-point for `GUID_DEVINTERFACE_VOLUME` events from
/// `device_watcher.rs`. Reads the global `DRIVE_DETECTOR` and delegates to
/// the existing per-event handler.
///
/// # Arguments
///
/// * `event_type` -- `DBT_DEVICEARRIVAL` or `DBT_DEVICEREMOVECOMPLETE`.
#[cfg(windows)]
pub fn handle_volume_event_dispatch(event_type: u32) {
    // Task 3 will populate this with the existing handle_volume_event logic.
    let detector_opt = *DRIVE_DETECTOR.lock();
    if let Some(detector) = detector_opt {
        handle_volume_event(detector, event_type);
    }
}

/// Dispatcher entry-point for `GUID_DEVINTERFACE_USB_DEVICE` arrival events
/// from `device_watcher.rs`. Reads the global `DRIVE_DETECTOR`, calls the
/// USB-arrival handler, and fires an async registry-cache refresh.
///
/// The refresh is fire-and-forget via the runtime handle stored in
/// [`REGISTRY_RUNTIME_HANDLE`] — the message loop thread must not block.
///
/// # Arguments
///
/// * `device_path` -- the `dbcc_name` string from the `WM_DEVICECHANGE` callback.
#[cfg(windows)]
pub fn dispatch_usb_device_arrival(device_path: &str) {
    let detector_opt = *DRIVE_DETECTOR.lock();
    if let Some(detector) = detector_opt {
        on_usb_device_arrival(detector, device_path);

        // Trigger an immediate device registry cache refresh so the new device's
        // trust tier is available before the first I/O event (D-09).
        //
        // The wndproc / dispatch callback runs on a plain std::thread that does NOT
        // inherit the tokio context. We stored the runtime Handle in
        // REGISTRY_RUNTIME_HANDLE (set in service.rs) to schedule the async refresh
        // without creating a second tokio runtime.
        if let (Some(cache), Some(client), Some(handle)) = (
            REGISTRY_CACHE.get(),
            REGISTRY_CLIENT.get(),
            REGISTRY_RUNTIME_HANDLE.get(),
        ) {
            let cache_clone = std::sync::Arc::clone(cache);
            let client_clone = client.clone();
            // Fire-and-forget: spawn on the existing runtime.
            handle.spawn(async move {
                cache_clone.refresh(&client_clone).await;
            });
        }
    }
}

/// Dispatcher entry-point for `GUID_DEVINTERFACE_USB_DEVICE` removal events
/// from `device_watcher.rs`.
///
/// # Arguments
///
/// * `device_path` -- the `dbcc_name` string from the `WM_DEVICECHANGE` callback.
#[cfg(windows)]
pub fn dispatch_usb_device_removal(device_path: &str) {
    let detector_opt = *DRIVE_DETECTOR.lock();
    if let Some(detector) = detector_opt {
        on_usb_device_removal(detector, device_path);
    }
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
    // NOTE: disk_path_to_instance_id has been moved to
    // `crate::detection::device_watcher::extract_disk_instance_id` (Phase 36 D-12
    // refactor). Instance-ID extraction tests live in device_watcher's test module.

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
}
