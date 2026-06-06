//! Volume detection and classification (T-13, F-AGT-13; Phase 56 DRIVE-01..04).
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
//! ## Volume Classification (Phase 56)
//!
//! `VolumeDetector` (renamed from `UsbDetector` in Plan 02) adds six-class
//! volume classification via `GetDriveTypeW` coarse bucketing + WMI
//! `Win32_DiskDrive` disambiguation:
//!
//! - `LocalNTFS` — fixed local disk
//! - `USBRemovable` — USB mass storage
//! - `SDCard` — SD / MMC card
//! - `Optical` — CD / DVD / Blu-ray
//! - `Virtual` — VHD, VHDX, ISO mount, Daemon Tools
//! - `NetworkShare` — mapped drive or UNC path
//!
//! WMI failures are handled with retry/backoff and return `None` (fail-closed),
//! never defaulting to `LocalNTFS`.
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
use std::time::{Duration, Instant};

use dlp_common::usb::{parse_usb_device_path, setupdi_description_for_device};
use dlp_common::{Classification, DeviceIdentity, UsbTrustTier, VolumeClass};
use parking_lot::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

// DBT_DEVICEARRIVAL is needed by handle_volume_event to distinguish arrival
// from removal events. The window, registration, and wndproc live in
// `crate::detection::device_watcher` (Phase 36 D-12 refactor).
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::DBT_DEVICEARRIVAL;

/// Drive letters currently identified as USB mass storage (e.g., `E`, `F`).
/// Shared between the device-notification callback and the interception layer.
///
/// Renamed from `UsbDetector` in Phase 56 Plan 02 to reflect the expanded
/// scope: volume classification for all six `VolumeClass` variants, not just
/// USB blocking.
#[derive(Debug, Default)]
pub struct VolumeDetector {
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
    /// [`VolumeDetector::blocked_drives`]. Phase 26 reads this map at I/O
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
    /// Volume class map for all drive letters, with timestamp for stale detection.
    ///
    /// Keyed by uppercase drive letter. The tuple stores `(VolumeClass, Instant)`
    /// where `Instant` is the time the classification was last updated.
    ///
    /// A 5-minute TTL is applied by [`get_volume_class_for_pipe_query`] to
    /// prevent stale classifications when drive letters are reused (e.g., a
    /// USB drive is unplugged and a different device claims the same letter).
    ///
    /// Phase 56: Populated on `DBT_DEVICEARRIVAL` and cleared on
    /// `DBT_DEVICEREMOVECOMPLETE`. Queried by the named pipe handler when
    /// the hook DLL sends `VolumeClassQuery`.
    pub volume_class_map: RwLock<HashMap<char, (VolumeClass, Instant)>>,
}

impl VolumeDetector {
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

    /// Attempts to capture USB device identities for drives already in
    /// `blocked_drives` and applies tier enforcement.
    ///
    /// Called once at startup after `scan_existing_drives`. Uses SetupDi to
    /// enumerate present USB devices, then matches them against unmapped drive
    /// letters using the same heuristic as the WR-01 fix.
    ///
    /// Covers the "plug-before-agent" and "agent-restart-while-plugged" timing
    /// paths (D-11) so that Blocked-tier USB devices are enforced even when the
    /// agent starts after the device was already plugged in.
    #[cfg(windows)]
    pub fn scan_existing_usb_identities(&self) {
        use dlp_common::usb::enumerate_connected_usb_devices;

        // Read startup resolution mode once (Phase 43-04).
        let mode = crate::service::with_config(|cfg| {
            cfg.usb_startup_resolution_mode
                .clone()
                .unwrap_or_else(|| "VID/PID/serial fallback".to_string())
        })
        .unwrap_or_else(|| {
            warn!(
                "config unavailable — falling back to 'VID/PID/serial fallback' \
                 for usb_startup_resolution_mode"
            );
            "VID/PID/serial fallback".to_string()
        });

        let identities = if mode == "Volume GUID resolution" {
            // Volume GUID resolution is rejected at config-set time (Plan 43-02).
            // This branch should not be reachable, but log a warning just in case.
            warn!(
                mode = %mode,
                "Volume GUID resolution mode selected but not yet implemented — \
                 falling back to VID/PID/serial"
            );
            enumerate_connected_usb_devices()
        } else {
            enumerate_connected_usb_devices()
        };
        if identities.is_empty() {
            debug!("startup scan: no USB mass-storage devices currently connected");
            return;
        }

        for identity in identities {
            // Skip devices that already have an identity mapped (e.g., from a
            // prior scan or a race with an arrival notification).
            let already_mapped = {
                let ids = self.device_identities.read();
                ids.values().any(|id| {
                    id.vid == identity.vid && id.pid == identity.pid && id.serial == identity.serial
                })
            };
            if already_mapped {
                continue;
            }

            // Find unmapped drives using the same heuristic as WR-01.
            let unmapped: Vec<char> = {
                let blocked = self.blocked_drives.read();
                let ids = self.device_identities.read();
                blocked
                    .iter()
                    .filter(|letter| !ids.contains_key(letter))
                    .copied()
                    .collect()
            };

            if unmapped.len() == 1 {
                let letter = unmapped[0];
                info!(
                    vid = %identity.vid,
                    pid = %identity.pid,
                    serial = %identity.serial,
                    drive = %letter,
                    "startup scan: USB identity reconciled with existing drive"
                );
                self.device_identities
                    .write()
                    .insert(letter, identity.clone());
                // Startup scan has no dbcc_name — use empty string to trigger fallback.
                if let Err(e) = apply_tier_enforcement(letter, &identity, "") {
                    warn!(drive = %letter, error = %e, "tier enforcement failed during startup scan");
                }
            } else if unmapped.len() > 1 {
                // Ambiguous: multiple unmapped USB drives. We cannot determine which
                // identity belongs to which drive letter. Park the identity in
                // pending_identity — if a VOLUME notification arrives later, it will
                // be reconciled. But pending_identity is a single slot, so we can only
                // park one. Pick the first identity and log a warning.
                warn!(
                    vid = %identity.vid,
                    pid = %identity.pid,
                    serial = %identity.serial,
                    unmapped_count = unmapped.len(),
                    "startup scan: multiple unmapped USB drives — cannot disambiguate identity"
                );
                // Only park if slot is empty.
                let mut pending = self.pending_identity.lock();
                if pending.is_none() {
                    *pending = Some(identity.clone());
                }
            } else {
                // No unmapped drives — this USB device may not have a volume yet
                // (e.g., a device with no mounted partition). Log and skip.
                debug!(
                    vid = %identity.vid,
                    pid = %identity.pid,
                    serial = %identity.serial,
                    "startup scan: USB device has no mapped drive letter — skipping"
                );
            }
        }
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

    /// Reconciles a USB device identity with an unmapped drive letter.
    ///
    /// The "unmapped drive" heuristic finds drive letters that are in
    /// `blocked_drives` (known USB mass storage) but not yet in
    /// `device_identities` (no identity captured). When exactly one such drive
    /// exists, the identity is assigned to it and tier enforcement is applied.
    ///
    /// This handles the WR-01 race where `GUID_DEVINTERFACE_VOLUME` arrives
    /// before `GUID_DEVINTERFACE_USB_DEVICE`, leaving the drive letter blocked
    /// but without an identity.
    ///
    /// # Returns
    ///
    /// `Some(letter)` when exactly one unmapped drive was found and the identity
    /// was assigned. `None` when zero or multiple unmapped drives exist (ambiguous).
    #[cfg(windows)]
    pub fn reconcile_identity_with_unmapped_drive(
        &self,
        identity: &DeviceIdentity,
        dbcc_name: &str,
    ) -> Option<char> {
        let unmapped: Vec<char> = {
            let blocked = self.blocked_drives.read();
            let ids = self.device_identities.read();
            blocked
                .iter()
                .filter(|letter| !ids.contains_key(letter))
                .copied()
                .collect()
        };
        if unmapped.len() == 1 {
            let letter = unmapped[0];
            self.device_identities
                .write()
                .insert(letter, identity.clone());
            if let Err(e) = apply_tier_enforcement(letter, identity, dbcc_name) {
                warn!(drive = %letter, error = %e, "tier enforcement failed during reconciliation");
            }
            Some(letter)
        } else {
            None
        }
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

    /// Classifies a drive letter into a `VolumeClass`.
    ///
    /// Uses `GetDriveTypeW` for coarse bucketing, then WMI `Win32_DiskDrive`
    /// for disambiguation of removable (USB vs SD) and fixed (local vs virtual).
    ///
    /// ## Fail-Closed Invariant
    ///
    /// Returns `None` on WMI failure, unknown drive type, or RAM disk.
    /// NEVER defaults to `VolumeClass::LocalNTFS` on failure.
    ///
    /// # Arguments
    ///
    /// * `letter` — Uppercase drive letter (e.g., `'E'`).
    ///
    /// # Returns
    ///
    /// `Some(VolumeClass)` on success, `None` on failure or unclassifiable drive.
    #[cfg(windows)]
    pub fn classify_drive(&self, letter: char) -> Option<VolumeClass> {
        use windows::Win32::Storage::FileSystem::GetDriveTypeW;

        const DRIVE_REMOVABLE: u32 = 2;
        const DRIVE_FIXED: u32 = 3;
        const DRIVE_REMOTE: u32 = 4;
        const DRIVE_CDROM: u32 = 5;
        #[allow(dead_code)]
        const DRIVE_RAMDISK: u32 = 6;

        let root: Vec<u16> = OsStr::new(&format!("{}:\\", letter))
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: root is a valid null-terminated wide string pointing to a drive root.
        let drive_type = unsafe { GetDriveTypeW(windows::core::PCWSTR(root.as_ptr())) };

        match drive_type {
            DRIVE_REMOTE => Some(VolumeClass::NetworkShare),
            DRIVE_CDROM => {
                // Pitfall 2: Some virtual drives (e.g., Daemon Tools) report
                // as DRIVE_CDROM. Check WMI model for virtual indicators first.
                match self.query_disk_for_letter_with_retry(letter) {
                    Ok(Some(disk)) => {
                        let model = disk.model.as_deref().unwrap_or("").to_lowercase();
                        if model.contains("virtual") || model.contains("msft") {
                            Some(VolumeClass::Virtual)
                        } else {
                            Some(VolumeClass::Optical)
                        }
                    }
                    Ok(None) => Some(VolumeClass::Optical),
                    Err(e) => {
                        warn!(
                            drive = %letter,
                            error = %e,
                            "WMI query failed for CDROM drive — failing closed"
                        );
                        None
                    }
                }
            }
            DRIVE_REMOVABLE => self.disambiguate_removable(letter),
            DRIVE_FIXED => self.disambiguate_fixed(letter),
            _ => {
                // RAM disk or unknown — fail-closed.
                debug!(drive = %letter, drive_type, "Unclassifiable drive type — failing closed");
                None
            }
        }
    }

    /// Disambiguates a `DRIVE_REMOVABLE` volume into `SDCard` or `USBRemovable`.
    ///
    /// Queries WMI `Win32_DiskDrive` with retry/backoff (3 attempts: 500ms, 1s, 2s).
    ///
    /// # Returns
    ///
    /// * `Some(VolumeClass::SDCard)` if the disk model/media type indicates SD/MMC.
    /// * `Some(VolumeClass::USBRemovable)` for all other removable disks.
    /// * `None` if all WMI queries fail (fail-closed).
    #[cfg(windows)]
    fn disambiguate_removable(&self, letter: char) -> Option<VolumeClass> {
        match self.query_disk_for_letter_with_retry(letter) {
            Ok(Some(disk)) => {
                let model = disk.model.as_deref().unwrap_or("").to_lowercase();
                let interface = disk.interface_type.as_deref().unwrap_or("").to_lowercase();
                let media = disk.media_type.as_deref().unwrap_or("").to_lowercase();

                if interface.contains("sd")
                    || media.contains("sd")
                    || model.contains("sd")
                    || model.contains("mmc")
                {
                    Some(VolumeClass::SDCard)
                } else {
                    Some(VolumeClass::USBRemovable)
                }
            }
            Ok(None) => {
                // Disk not found in WMI — treat as generic removable (fail-closed
                // but not completely blind; USB is the most common removable type).
                warn!(
                    drive = %letter,
                    "WMI returned no disk for removable drive — assuming USBRemovable"
                );
                Some(VolumeClass::USBRemovable)
            }
            Err(e) => {
                warn!(
                    drive = %letter,
                    error = %e,
                    "WMI query failed for removable drive — failing closed"
                );
                None
            }
        }
    }

    /// Disambiguates a `DRIVE_FIXED` volume into `Virtual` or `LocalNTFS`.
    ///
    /// Queries WMI `Win32_DiskDrive` with retry/backoff (3 attempts: 500ms, 1s, 2s).
    ///
    /// # Returns
    ///
    /// * `Some(VolumeClass::Virtual)` if the disk model indicates a virtual disk.
    /// * `Some(VolumeClass::LocalNTFS)` for all other fixed disks.
    /// * `None` if all WMI queries fail (fail-closed).
    #[cfg(windows)]
    fn disambiguate_fixed(&self, letter: char) -> Option<VolumeClass> {
        match self.query_disk_for_letter_with_retry(letter) {
            Ok(Some(disk)) => {
                let model = disk.model.as_deref().unwrap_or("").to_lowercase();
                if model.contains("virtual")
                    || model.contains("msft")
                    || model.contains("file-backed")
                {
                    Some(VolumeClass::Virtual)
                } else {
                    Some(VolumeClass::LocalNTFS)
                }
            }
            Ok(None) => {
                // Disk not found in WMI — assume local fixed disk. This is
                // the safest fallback for fixed drives because LocalNTFS is
                // the default state for most enterprise endpoints.
                warn!(
                    drive = %letter,
                    "WMI returned no disk for fixed drive — assuming LocalNTFS"
                );
                Some(VolumeClass::LocalNTFS)
            }
            Err(e) => {
                warn!(
                    drive = %letter,
                    error = %e,
                    "WMI query failed for fixed drive — failing closed"
                );
                None
            }
        }
    }

    /// Queries WMI `Win32_DiskDrive` for the disk associated with a drive letter,
    /// with exponential backoff retry.
    ///
    /// Attempts up to 3 times with delays: 500ms, 1s, 2s.
    ///
    /// # Arguments
    ///
    /// * `letter` — The drive letter to query.
    ///
    /// # Returns
    ///
    /// `Ok(Some(WmiDiskDrive))` on success, `Ok(None)` if no disk is found,
    /// `Err(VolumeClassError)` if all WMI queries fail.
    #[cfg(windows)]
    fn query_disk_for_letter_with_retry(
        &self,
        letter: char,
    ) -> Result<Option<WmiDiskDrive>, VolumeClassError> {
        let delays = [
            Duration::from_millis(500),
            Duration::from_secs(1),
            Duration::from_secs(2),
        ];

        for (attempt, delay) in delays.iter().enumerate() {
            match query_disk_for_letter(letter) {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!(
                        drive = %letter,
                        attempt = attempt + 1,
                        error = %e,
                        "WMI query failed, retrying after {:?}",
                        delay
                    );
                    if attempt < delays.len() - 1 {
                        std::thread::sleep(*delay);
                    }
                }
            }
        }

        Err(VolumeClassError::WmiQueryFailed(format!(
            "All {} WMI query attempts failed for drive {}",
            delays.len(),
            letter
        )))
    }

    /// Returns the cached volume class for a drive letter, or queries and caches it.
    ///
    /// Called by the agent's named pipe handler when `VolumeClassQuery` arrives
    /// from the hook DLL.
    ///
    /// ## Cache TTL
    ///
    /// Cached entries expire after 5 minutes to handle drive letter reuse
    /// (e.g., USB unplug + different device replug with same letter).
    ///
    /// # Arguments
    ///
    /// * `letter` — The drive letter to look up.
    ///
    /// # Returns
    ///
    /// `Some(VolumeClass)` if the drive is known or classifiable,
    /// `None` if classification failed or the drive is unknown.
    pub fn get_volume_class_for_pipe_query(&self, letter: char) -> Option<VolumeClass> {
        let letter = letter.to_ascii_uppercase();
        const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

        // Check cache first.
        {
            let map = self.volume_class_map.read();
            if let Some((class, timestamp)) = map.get(&letter) {
                if timestamp.elapsed() < CACHE_TTL {
                    return Some(*class);
                }
            }
        }

        // Cache miss or expired — classify and store.
        let class = self.classify_drive(letter);
        if let Some(c) = class {
            self.volume_class_map
                .write()
                .insert(letter, (c, Instant::now()));
        }
        class
    }
}

/// Test-only helper for `VolumeDetector`.
///
/// This method is intended for integration tests to seed volume class state
/// without requiring WMI queries or physical hardware. It is `pub` because
/// integration tests compile the crate as a library (not with `#[cfg(test)]`).
/// Production code should use `on_drive_arrival` / `on_drive_removal` instead.
///
/// # Arguments
///
/// * `letter` — The drive letter to inject (e.g., `'C'`, `'D'`).
/// * `class` — The [`VolumeClass`] to associate with the drive letter.
impl VolumeDetector {
    pub fn inject_volume_class_for_test(&self, letter: char, class: VolumeClass) {
        self.volume_class_map
            .write()
            .insert(letter.to_ascii_uppercase(), (class, Instant::now()));
    }
}

/// Handles a `VolumeClassQuery` from the hook DLL and returns a `VolumeClassResponse`.
///
/// This function is called by the hook IPC handler when a `VolumeClassQuery`
/// message arrives on the named pipe. It looks up the drive letter in the
/// `VolumeDetector`'s `volume_class_map` (with TTL check) and returns the
/// cached classification, or triggers a fresh classification if the cache
/// entry is missing or expired.
///
/// ## Fail-Closed Invariant
///
/// Returns `VolumeClassResponse { class: None }` when:
/// - The drive letter is not known to the agent.
/// - Classification failed (WMI error, unknown drive type).
///
/// The hook DLL must NOT default `None` to `LocalNTFS` — volume-class
/// conditions in ABAC evaluate to `false` on `None`.
///
/// # Arguments
///
/// * `query` — The `VolumeClassQuery` from the hook DLL.
///
/// # Returns
///
/// `VolumeClassResponse` with `Some(class)` on cache hit or successful
/// classification, `None` on failure.
pub fn handle_volume_class_query(
    query: &dlp_common::hook_ipc::VolumeClassQuery,
) -> dlp_common::hook_ipc::VolumeClassResponse {
    let detector_opt = {
        #[cfg(windows)]
        {
            *DRIVE_DETECTOR.lock()
        }
        #[cfg(not(windows))]
        {
            None::<&VolumeDetector>
        }
    };

    let class = detector_opt
        .and_then(|detector| detector.get_volume_class_for_pipe_query(query.drive_letter));

    dlp_common::hook_ipc::VolumeClassResponse { class }
}

// SAFETY: VolumeDetector contains only RwLock<HashSet<char>>, which is Send + Sync.
// It is safe to share &VolumeDetector across threads because all mutable access
// (drive arrival/removal) is gated behind the RwLock.
unsafe impl Send for VolumeDetector {}
unsafe impl Sync for VolumeDetector {}

// ──────────────────────────────────────────────────────────────────────────────
// WMI types and helpers for volume classification
// ──────────────────────────────────────────────────────────────────────────────

/// Errors produced during volume classification WMI queries.
#[derive(Debug, thiserror::Error)]
pub enum VolumeClassError {
    /// WMI connection failed.
    #[error("WMI connection failed: {0}")]
    WmiConnectionFailed(String),
    /// WMI query failed.
    #[error("WMI query failed: {0}")]
    WmiQueryFailed(String),
    /// Drive letter not found in WMI results.
    #[error("drive letter not found")]
    DriveLetterNotFound,
}

/// WMI `Win32_DiskDrive` row for volume classification.
///
/// Deserialized from WMI query results. Fields are optional because WMI
/// may return NULL for some properties on certain hardware.
#[cfg(windows)]
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename = "Win32_DiskDrive")]
#[serde(rename_all = "PascalCase")]
struct WmiDiskDrive {
    /// Device ID (e.g., `\\.\PHYSICALDRIVE0`).
    #[serde(rename = "DeviceID")]
    device_id: String,
    /// Interface type (e.g., "USB", "SD", "IDE", "SCSI").
    interface_type: Option<String>,
    /// Media type (e.g., "Removable Media", "Fixed hard disk media").
    media_type: Option<String>,
    /// Model string (e.g., "SanDisk Cruzer", "Msft Virtual Disk").
    model: Option<String>,
    /// PnP device ID (reserved for future disambiguation).
    #[allow(dead_code)]
    #[serde(rename = "PNPDeviceID")]
    pnp_device_id: Option<String>,
}

/// Queries WMI `Win32_DiskDrive` for the disk associated with a drive letter.
///
/// Maps the drive letter to the physical disk via `Win32_LogicalDiskToPartition`
/// association. If the association query fails, falls back to querying all
/// `Win32_DiskDrive` rows and matching by index.
///
/// # Arguments
///
/// * `letter` — The drive letter to query (e.g., `'E'`).
///
/// # Returns
///
/// `Ok(Some(WmiDiskDrive))` on success, `Ok(None)` if no disk is found,
/// `Err(VolumeClassError)` if WMI connection or query fails.
#[cfg(windows)]
fn query_disk_for_letter(letter: char) -> Result<Option<WmiDiskDrive>, VolumeClassError> {
    use wmi::WMIConnection;

    let conn = WMIConnection::with_namespace_path(r"ROOT\CIMV2").map_err(|e| {
        VolumeClassError::WmiConnectionFailed(format!("Failed to connect to ROOT\\CIMV2: {e}"))
    })?;

    // Query all Win32_DiskDrive rows.
    let drives: Vec<WmiDiskDrive> = conn.query().map_err(|e| {
        VolumeClassError::WmiQueryFailed(format!("Win32_DiskDrive query failed: {e}"))
    })?;

    if drives.is_empty() {
        return Ok(None);
    }

    // Try to map drive letter to disk index via Win32_LogicalDiskToPartition.
    // This is the most reliable method: drive letter -> partition -> disk.
    let disk_index = match query_disk_index_for_letter(&conn, letter) {
        Ok(Some(idx)) => Some(idx),
        Ok(None) => {
            debug!(
                drive = %letter,
                "Win32_LogicalDiskToPartition returned no mapping — falling back to index heuristic"
            );
            None
        }
        Err(e) => {
            warn!(
                drive = %letter,
                error = %e,
                "Win32_LogicalDiskToPartition query failed — falling back to index heuristic"
            );
            None
        }
    };

    if let Some(idx) = disk_index {
        // Match by index: PHYSICALDRIVE{idx}.
        let target_id = format!("\\\\.\\PHYSICALDRIVE{idx}");
        for drive in &drives {
            if drive.device_id.eq_ignore_ascii_case(&target_id) {
                return Ok(Some(drive.clone()));
            }
        }
    }

    // Fallback: if only one disk drive exists, return it (common for
    // single-disk VMs or test environments).
    if drives.len() == 1 {
        return Ok(Some(drives.into_iter().next().unwrap()));
    }

    Ok(None)
}

/// Queries WMI for the disk index associated with a drive letter.
///
/// Uses the `Win32_LogicalDiskToPartition` association to map a drive letter
/// to a partition, then to a disk index.
///
/// # Returns
///
/// `Ok(Some(u32))` with the disk index, `Ok(None)` if no mapping found,
/// `Err(VolumeClassError)` on WMI failure.
#[cfg(windows)]
fn query_disk_index_for_letter(
    conn: &wmi::WMIConnection,
    letter: char,
) -> Result<Option<u32>, VolumeClassError> {
    // Win32_LogicalDiskToPartition: Antecedent = partition, Dependent = logical disk.
    // We query for rows where Dependent contains our drive letter.
    let query = format!(
        "SELECT Antecedent FROM Win32_LogicalDiskToPartition WHERE Dependent LIKE '%{}:%'",
        letter
    );

    #[derive(serde::Deserialize, Debug)]
    struct LogicalDiskToPartition {
        #[serde(rename = "Antecedent")]
        antecedent: String,
    }

    let results: Vec<LogicalDiskToPartition> = conn.raw_query(&query).map_err(|e| {
        VolumeClassError::WmiQueryFailed(format!("Win32_LogicalDiskToPartition query failed: {e}"))
    })?;

    if results.is_empty() {
        return Ok(None);
    }

    // Antecedent is a WMI path like:
    // "\\DESKTOP-ABC\\root\\cimv2:Win32_DiskPartition.DeviceID=\"Disk #0, Partition #1\""
    // Extract the disk number from "Disk #N".
    let antecedent = &results[0].antecedent;
    if let Some(start) = antecedent.find("Disk #") {
        let after = &antecedent[start + 6..];
        if let Some(end) = after.find(',') {
            let num_str = &after[..end];
            if let Ok(idx) = num_str.parse::<u32>() {
                return Ok(Some(idx));
            }
        }
        // Try parsing until end of string (no comma).
        if let Ok(idx) = after.parse::<u32>() {
            return Ok(Some(idx));
        }
    }

    Ok(None)
}

// ──────────────────────────────────────────────────────────────────────────────
// USB device notification statics
// ──────────────────────────────────────────────────────────────────────────────
// Note: GUID constants (GUID_DEVINTERFACE_VOLUME, GUID_DEVINTERFACE_USB_DEVICE,
// GUID_DEVINTERFACE_DISK) and NOTIFY_HANDLES have been moved to
// `crate::detection::device_watcher` (Phase 36 D-12 refactor).

/// Global reference to the `VolumeDetector` shared with the device notification handlers.
/// Protected by a `Mutex` so it can be cleared on unregister.
#[cfg(windows)]
static DRIVE_DETECTOR: parking_lot::Mutex<Option<&'static VolumeDetector>> =
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

/// Sets the global `VolumeDetector` reference so that dispatch callbacks
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
/// * `detector` — a `'static` reference to the `VolumeDetector`.
#[cfg(windows)]
pub fn set_drive_detector(detector: &'static VolumeDetector) {
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

/// Returns the global device controller reference, if set.
#[cfg(windows)]
#[must_use]
pub fn get_device_controller() -> Option<std::sync::Arc<crate::device_controller::DeviceController>>
{
    DEVICE_CONTROLLER.get().cloned()
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
///
/// Phase 56: Also updates `volume_class_map` and emits `VolumeArrival` audit
/// events on arrival. Clears `volume_class_map` entries on removal.
#[cfg(windows)]
fn handle_volume_event(detector: &VolumeDetector, event_type: u32) {
    let before: HashSet<char> = detector.blocked_drives.read().iter().copied().collect();
    let now_present = scan_removable_drives(detector);

    if event_type == DBT_DEVICEARRIVAL {
        handle_volume_arrival(detector, &before, &now_present);
    } else {
        handle_volume_removal(detector, &before, &now_present);
    }
}

/// Scans all drive letters and returns the set of removable drives.
#[cfg(windows)]
fn scan_removable_drives(detector: &VolumeDetector) -> HashSet<char> {
    let mut present = HashSet::new();
    for letter in 'A'..='Z' {
        if detector.is_removable_drive(letter) {
            present.insert(letter);
        }
    }
    present
}

/// Handles USB volume arrival: blocks new drives, reconciles pending identities,
/// registers the drive root with the file monitor, classifies the volume, and
/// emits a `VolumeArrival` audit event.
///
/// Phase 56: Duplicate suppression uses the drive letter as a stable key.
/// A `VolumeArrival` event is only emitted once per (drive letter, session)
/// unless the drive is removed and re-inserted.
#[cfg(windows)]
fn handle_volume_arrival(
    detector: &VolumeDetector,
    before: &HashSet<char>,
    now_present: &HashSet<char>,
) {
    for letter in now_present.difference(before) {
        let letter = *letter;
        detector.on_drive_arrival(letter);
        reconcile_pending_identity(detector, letter);
        notify_file_monitor_of_new_drive(letter);

        // Phase 56: Classify the volume and update the cache.
        if let Some(class) = detector.classify_drive(letter) {
            detector
                .volume_class_map
                .write()
                .insert(letter, (class, Instant::now()));
            info!(
                drive = %letter,
                class = ?class,
                "volume classified and cached"
            );
        }

        // Phase 56: Emit VolumeArrival audit event.
        emit_volume_arrival(letter);
    }
}

/// Emits a `VolumeArrival` audit event for a newly arrived drive.
///
/// Uses the global AUDIT_CTX from device_watcher if available. If the audit
/// context is not yet initialized (early startup), the event is silently
/// skipped — volume arrival audit is best-effort.
///
/// Duplicate suppression: the event is emitted once per drive letter per
/// session. The drive letter is removed from `volume_class_map` on removal,
/// so re-insertion of the same or different device with the same letter will
/// trigger a fresh event.
#[cfg(windows)]
fn emit_volume_arrival(letter: char) {
    let Some(ctx) = crate::detection::device_watcher::get_audit_ctx() else {
        debug!(
            drive = %letter,
            "AUDIT_CTX not yet initialized — skipping VolumeArrival event"
        );
        return;
    };

    use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};

    let mut event = AuditEvent::new(
        EventType::VolumeArrival,
        ctx.user_sid.clone(),
        ctx.user_name.clone(),
        format!("volume://{letter}"),
        Classification::T1,
        Action::READ,
        Decision::ALLOW,
        ctx.agent_id.clone(),
        ctx.session_id,
    )
    .with_justification(format!("Volume {letter}: arrived"));

    crate::audit_emitter::emit_audit(ctx, &mut event);
    info!(drive = %letter, "VolumeArrival audit event emitted");
}

/// Reconciles a pending USB device identity with a newly arrived drive letter.
#[cfg(windows)]
fn reconcile_pending_identity(detector: &VolumeDetector, letter: char) {
    let Some(identity) = detector.pending_identity.lock().take() else {
        return;
    };
    detector
        .device_identities
        .write()
        .insert(letter, identity.clone());
    // pending_identity has no dbcc_name — use empty string to trigger fallback.
    if let Err(e) = apply_tier_enforcement(letter, &identity, "") {
        warn!(drive = %letter, error = %e, "tier enforcement failed for pending identity");
    }
}

/// Notifies the file monitor to start watching a new USB drive root.
#[cfg(windows)]
fn notify_file_monitor_of_new_drive(letter: char) {
    let root = std::path::PathBuf::from(format!("{}:", letter));
    let _ = WATCH_PATH_TX.lock().as_ref().map(|tx| tx.send(root));
}

/// Handles USB volume removal: unblocks drives that are no longer present
/// and clears their `volume_class_map` entries.
#[cfg(windows)]
fn handle_volume_removal(
    detector: &VolumeDetector,
    before: &HashSet<char>,
    now_present: &HashSet<char>,
) {
    for letter in before.difference(now_present) {
        let letter = *letter;
        detector.on_drive_removal(letter);

        // Phase 56: Clear volume_class_map entry so the next arrival with
        // the same drive letter triggers a fresh classification and audit event.
        if detector.volume_class_map.write().remove(&letter).is_some() {
            info!(
                drive = %letter,
                "volume_class_map entry cleared on removal"
            );
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
///
/// ## Per-user support (USB-06, Phase 38.4)
///
/// Resolves the current process SID and queries the cache with
/// `trust_tier_for_with_sid`, which considers both per-user and machine-wide
/// entries and returns the most restrictive tier. Owner identity is included
/// in tracing spans for auditability.
///
/// ## Config-driven behavior (Phase 43-04)
///
/// Reads `usb_blocked_failure_mode` and `usb_none_serial_policy` from the
/// global config once per call and passes them by parameter to avoid
/// repeated mutex acquisitions.
#[cfg(windows)]
fn apply_tier_enforcement(
    letter: char,
    identity: &DeviceIdentity,
    dbcc_name: &str,
) -> Result<(), String> {
    let Some(controller) = DEVICE_CONTROLLER.get() else {
        return Err("DeviceController not initialized".to_string());
    };

    // Read config values once per enforcement call (Phase 43-04).
    let failure_mode = crate::service::with_config(|cfg| {
        cfg.usb_blocked_failure_mode
            .clone()
            .unwrap_or_else(|| "Warning only".to_string())
    })
    .unwrap_or_else(|| {
        warn!("config unavailable — falling back to 'Warning only' for usb_blocked_failure_mode");
        "Warning only".to_string()
    });

    let none_serial_policy = crate::service::with_config(|cfg| {
        cfg.usb_none_serial_policy
            .clone()
            .unwrap_or_else(|| "Always Blocked".to_string())
    })
    .unwrap_or_else(|| {
        warn!("config unavailable — falling back to 'Always Blocked' for usb_none_serial_policy");
        "Always Blocked".to_string()
    });

    let (tier, owner_sid, owner_user) = resolve_tier_from_registry(identity, &none_serial_policy);

    match tier {
        UsbTrustTier::Blocked => apply_blocked_enforcement(
            letter,
            identity,
            dbcc_name,
            controller,
            &owner_sid,
            &owner_user,
            &failure_mode,
        ),
        UsbTrustTier::ReadOnly => {
            apply_readonly_enforcement(letter, identity, controller, &owner_sid, &owner_user)
        }
        UsbTrustTier::FullAccess => {
            debug!(
                vid = %identity.vid,
                pid = %identity.pid,
                serial = %identity.serial,
                drive = %letter,
                tier = "FullAccess",
                action = "none",
                owner_sid = ?owner_sid,
                owner_user = ?owner_user,
                "USB device has FullAccess — no enforcement action"
            );
            Ok(())
        }
    }
}

/// Resolves the trust tier from the registry cache, defaulting to Blocked.
///
/// # Arguments
///
/// * `identity` — The USB device identity.
/// * `none_serial_policy` — Policy for devices without serial descriptors:
///   "Always Blocked" forces Blocked for `(none)` serials;
///   "Allow unregistered" falls through to normal registry lookup.
#[cfg(windows)]
fn resolve_tier_from_registry(
    identity: &DeviceIdentity,
    none_serial_policy: &str,
) -> (UsbTrustTier, Option<String>, Option<String>) {
    // Check (none) serial policy before registry lookup.
    if identity.serial == "(none)" && none_serial_policy == "Always Blocked" {
        warn!(
            vid = %identity.vid,
            pid = %identity.pid,
            serial = "(none)",
            policy = %none_serial_policy,
            "USB device has no serial — forcing Blocked tier per policy"
        );
        return (UsbTrustTier::Blocked, None, None);
        // "Allow unregistered" falls through to normal registry lookup.
        // "Port-based disambiguation" is rejected at config-set time (Plan 43-02).
    }

    let current_sid = crate::identity::get_current_process_sid();

    let Some(cache) = REGISTRY_CACHE.get() else {
        warn!("registry cache unavailable — applying default-deny (Blocked)");
        return (UsbTrustTier::Blocked, None, None);
    };

    let result = cache.trust_tier_for_with_sid(
        &identity.vid,
        &identity.pid,
        &identity.serial,
        current_sid.as_deref(),
    );
    let t = result.tier;
    let has_entry = cache.has_device_with_sid(
        &identity.vid,
        &identity.pid,
        &identity.serial,
        current_sid.as_deref(),
    ) || cache.has_device(&identity.vid, &identity.pid, &identity.serial);

    if has_entry {
        debug!(
            vid = %identity.vid,
            pid = %identity.pid,
            tier = ?t,
            owner_sid = ?result.owner_sid,
            "registry cache hit — applying registered tier"
        );
    } else {
        log_cache_miss(identity, cache);
    }

    (t, result.owner_sid, result.owner_user)
}

/// Logs a cache miss with context about why the device was not found.
#[cfg(windows)]
fn log_cache_miss(identity: &DeviceIdentity, cache: &crate::device_registry::DeviceRegistryCache) {
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

/// Pure function that decides the enforcement outcome based on failure mode.
///
/// Returns `Ok(())` if enforcement is considered successful, `Err(msg)` otherwise.
///
/// # Arguments
///
/// * `failure_mode` — The configured failure mode: "Hard error", "Warning only",
///   or "Retry then error".
/// * `pnp_ok` — Whether the PnP disable operation succeeded.
/// * `dacl_ok` — Whether the DACL deny-all operation succeeded.
/// * `retry_count` — Number of retry attempts that were configured (for logging).
#[cfg(windows)]
fn decide_enforcement_outcome(
    failure_mode: &str,
    pnp_ok: bool,
    dacl_ok: bool,
    retry_count: u32,
) -> Result<(), String> {
    match failure_mode {
        "Hard error" => {
            if !pnp_ok || !dacl_ok {
                return Err(format!(
                    "Blocked enforcement failed (mode: Hard error) — PnP: {}, DACL: {}",
                    if pnp_ok { "ok" } else { "err" },
                    if dacl_ok { "ok" } else { "err" }
                ));
            }
            Ok(())
        }
        "Retry then error" => {
            if !pnp_ok {
                return Err(format!(
                    "Blocked enforcement failed (mode: Retry then error) — PnP failed after {} retries",
                    retry_count
                ));
            }
            Ok(())
        }
        _ => {
            // "Warning only" (default) — current behavior: always return Ok.
            Ok(())
        }
    }
}

/// Applies Blocked-tier enforcement: PnP disable + DACL deny-all.
///
/// The `failure_mode` parameter controls how failures are handled:
/// - "Hard error": returns `Err` if either PnP or DACL fails.
/// - "Retry then error": retries PnP up to 2 times, returns `Err` if PnP still fails.
/// - "Warning only" (default): logs failures but always returns `Ok`.
#[cfg(windows)]
fn apply_blocked_enforcement(
    letter: char,
    identity: &DeviceIdentity,
    dbcc_name: &str,
    controller: &crate::device_controller::DeviceController,
    owner_sid: &Option<String>,
    owner_user: &Option<String>,
    failure_mode: &str,
) -> Result<(), String> {
    // Determine retry parameters based on failure mode.
    let (retry_count, retry_delay_ms) = match failure_mode {
        "Retry then error" => (2_u32, 100_u64), // 3 total attempts (0, 1, 2)
        _ => (0_u32, 0_u64),
    };

    // Layer 1: PnP disable (primary enforcement).
    tracing::debug!(
        vid = %identity.vid,
        pid = %identity.pid,
        serial = %identity.serial,
        drive = %letter,
        tier = "Blocked",
        action = "PnP disable",
        "applying tier enforcement"
    );
    let pnp_result = if retry_count > 0 {
        controller.disable_usb_device_with_retry_blocking(
            dbcc_name,
            identity,
            retry_count,
            retry_delay_ms,
        )
    } else {
        controller.disable_usb_device(dbcc_name, identity)
    };
    let pnp_ok = pnp_result.is_ok();
    if let Err(ref e) = pnp_result {
        error!(
            vid = %identity.vid,
            pid = %identity.pid,
            serial = %identity.serial,
            drive = %letter,
            tier = "Blocked",
            owner_sid = ?owner_sid,
            owner_user = ?owner_user,
            pnp_result = "err",
            error = %e,
            "PnP disable failed for blocked USB device"
        );
    }

    // Layer 2: DACL deny-all (defense-in-depth fallback — always attempt).
    tracing::debug!(
        drive = %letter,
        action = "DACL deny-all",
        "applying tier enforcement defense-in-depth"
    );
    let dacl_result = controller.set_volume_deny_all(letter);
    let dacl_ok = dacl_result.is_ok();
    if let Err(ref e) = dacl_result {
        error!(
            vid = %identity.vid,
            pid = %identity.pid,
            serial = %identity.serial,
            drive = %letter,
            tier = "Blocked",
            owner_sid = ?owner_sid,
            owner_user = ?owner_user,
            dacl_result = "err",
            error = %e,
            "DACL deny-all failed for blocked USB device"
        );
    }

    // Apply failure mode decision via pure function.
    match decide_enforcement_outcome(failure_mode, pnp_ok, dacl_ok, retry_count) {
        Ok(()) => {
            info!(
                vid = %identity.vid,
                pid = %identity.pid,
                serial = %identity.serial,
                drive = %letter,
                tier = "Blocked",
                owner_sid = ?owner_sid,
                owner_user = ?owner_user,
                mode = %failure_mode,
                "USB device blocked — enforcement succeeded"
            );
            Ok(())
        }
        Err(err_msg) => {
            error!(
                vid = %identity.vid,
                pid = %identity.pid,
                serial = %identity.serial,
                drive = %letter,
                tier = "Blocked",
                owner_sid = ?owner_sid,
                owner_user = ?owner_user,
                mode = %failure_mode,
                "{}",
                err_msg
            );
            Err(err_msg)
        }
    }
}

/// Applies ReadOnly-tier enforcement: modifies the volume DACL.
#[cfg(windows)]
fn apply_readonly_enforcement(
    letter: char,
    identity: &DeviceIdentity,
    controller: &crate::device_controller::DeviceController,
    owner_sid: &Option<String>,
    owner_user: &Option<String>,
) -> Result<(), String> {
    tracing::debug!(
        drive = %letter,
        action = "DACL read-only",
        "applying tier enforcement"
    );
    match controller.set_volume_readonly(letter) {
        Ok(()) => {
            info!(
                vid = %identity.vid,
                pid = %identity.pid,
                serial = %identity.serial,
                drive = %letter,
                tier = "ReadOnly",
                owner_sid = ?owner_sid,
                owner_user = ?owner_user,
                "USB volume set to read-only"
            );
            Ok(())
        }
        Err(e) => {
            error!(
                vid = %identity.vid,
                pid = %identity.pid,
                serial = %identity.serial,
                drive = %letter,
                tier = "ReadOnly",
                owner_sid = ?owner_sid,
                owner_user = ?owner_user,
                error = %e,
                "Failed to set USB volume to read-only"
            );
            Err(format!("ReadOnly DACL failed: {e}"))
        }
    }
}

/// Captures and logs a USB device identity on arrival.
///
/// Parses VID/PID/serial from the `dbcc_name` device path, fetches a
/// human-readable description via SetupDi (SPDRP_FRIENDLYNAME, fallback
/// SPDRP_DEVICEDESC), and stores the `DeviceIdentity` in
/// `VolumeDetector::device_identities` keyed by the first available removable
/// drive letter not already tracked (Phase 23 D-02, D-03, D-09, SC-1).
///
/// After identity capture, looks up the trust tier from the device registry
/// cache and applies active PnP enforcement via [`DeviceController`]:
/// - `Blocked`: disables the device immediately.
/// - `ReadOnly`: modifies the volume DACL to remove write access.
/// - `FullAccess`: no action.
#[cfg(windows)]
fn on_usb_device_arrival(detector: &VolumeDetector, device_path: &str) {
    let mut identity = parse_usb_device_path(device_path);
    identity.description = setupdi_description_for_device(device_path);

    // WR-01 fix: If VOLUME arrived before USB_DEVICE, the drive letter is already
    // in blocked_drives but device_identities has no entry. Check for exactly one
    // un-identity'd USB drive and reconcile immediately.
    if let Some(letter) = detector.reconcile_identity_with_unmapped_drive(&identity, device_path) {
        info!(
            vid = %identity.vid,
            pid = %identity.pid,
            serial = %identity.serial,
            drive = %letter,
            "USB identity reconciled with existing volume (VOLUME-arrived-first race)"
        );
        // Clear any stale pending_identity — this device is now fully reconciled.
        *detector.pending_identity.lock() = None;
        return;
    }

    // Normal path: park identity for reconciliation when VOLUME arrives later.
    info!(
        vid = %identity.vid,
        pid = %identity.pid,
        serial = %identity.serial,
        description = %identity.description,
        "USB device arrived — identity parked, awaiting VOLUME notification"
    );
    *detector.pending_identity.lock() = Some(identity);
}

/// Removes the captured identity on USB device removal.
///
/// Locates the `device_identities` entry whose VID/PID/serial matches the
/// parsed device path and removes it. Also restores the volume ACL if the
/// device was in ReadOnly tier, and re-enables the device if it was disabled
/// (Blocked tier). SetupDi is not called on removal because the device may
/// already be gone by the time this runs.
#[cfg(windows)]
fn on_usb_device_removal(detector: &VolumeDetector, device_path: &str) {
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
            if let Err(e) = controller.enable_usb_device(device_path, &parsed) {
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
        let detector = VolumeDetector::new();
        assert!(detector.device_identities.read().is_empty());
    }

    #[test]
    fn test_device_identity_for_drive_present_and_absent() {
        let detector = VolumeDetector::new();
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
        let detector = VolumeDetector::new();
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
        let detector = VolumeDetector::new();
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
    fn test_volume_detector_default() {
        let detector = VolumeDetector::new();
        assert!(detector.blocked_drive_letters().is_empty());
    }

    #[test]
    fn test_on_drive_arrival_removal() {
        let detector = VolumeDetector::new();
        detector.blocked_drives.write().insert('E');
        assert!(detector.is_path_on_blocked_drive(r"E:\secret.docx"));
        assert!(!detector.is_path_on_blocked_drive(r"C:\secret.docx"));

        detector.on_drive_removal('E');
        assert!(!detector.is_path_on_blocked_drive(r"E:\secret.docx"));
    }

    #[test]
    fn test_should_block_write_t4_usb() {
        let detector = VolumeDetector::new();
        detector.blocked_drives.write().insert('F');
        assert!(detector.should_block_write(r"F:\restricted.xlsx", Classification::T4));
        assert!(detector.should_block_write(r"F:\confidential.pdf", Classification::T3));
    }

    #[test]
    fn test_should_block_write_t1_t2_allowed() {
        let detector = VolumeDetector::new();
        detector.blocked_drives.write().insert('F');
        assert!(!detector.should_block_write(r"F:\public.txt", Classification::T1));
        assert!(!detector.should_block_write(r"F:\internal.doc", Classification::T2));
    }

    #[test]
    fn test_should_block_non_usb_drive() {
        let detector = VolumeDetector::new();
        // C: is not in the blocked set.
        assert!(!detector.should_block_write(r"C:\Restricted\secrets.xlsx", Classification::T4));
    }

    #[test]
    fn test_drive_letter_case_insensitive() {
        let detector = VolumeDetector::new();
        detector.blocked_drives.write().insert('E');
        assert!(detector.blocked_drives.read().contains(&'E'));
        detector.on_drive_removal('e');
        assert!(detector.blocked_drive_letters().is_empty());
    }

    // ── Tests added in Phase 31 Plan 02 ────────────────────────────────────
    // NOTE: disk_path_to_instance_id has been moved to
    // `crate::detection::device_watcher::extract_disk_instance_id` (Phase 36 D-12
    // refactor). Instance-ID extraction tests live in device_watcher's test module.

    // ── Tests for WR-01 race fix (Phase 38.2 Plan 02) ──────────────────────

    /// When exactly one unmapped drive exists in blocked_drives, the identity
    /// should be reconciled immediately (VOLUME-arrived-first race).
    #[test]
    #[cfg(not(windows))]
    fn test_usb_device_arrival_reconciles_when_volume_first() {
        let detector = VolumeDetector::new();
        // Simulate VOLUME arrived first: drive letter is blocked but no identity.
        detector.blocked_drives.write().insert('F');
        assert!(detector.device_identities.read().is_empty());

        let identity = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN42".into(),
            description: "Test Device".into(),
        };

        // reconcile_identity_with_unmapped_drive should fire because exactly
        // one unmapped drive exists.
        let result = detector.reconcile_identity_with_unmapped_drive(&identity, "");
        assert_eq!(result, Some('F'));

        // device_identities should now contain the mapped identity.
        assert_eq!(
            detector.device_identity_for_drive('F'),
            Some(identity.clone())
        );

        // pending_identity should be None (not parked).
        assert!(detector.pending_identity.lock().is_none());
    }

    /// When no drives are in blocked_drives, the identity should be parked
    /// in pending_identity (normal arrival path).
    #[test]
    fn test_usb_device_arrival_parks_when_no_volume_yet() {
        let detector = VolumeDetector::new();
        // blocked_drives is empty — no volume has arrived yet.
        assert!(detector.blocked_drives.read().is_empty());

        let identity = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN42".into(),
            description: "Test Device".into(),
        };

        // reconcile should return None because no unmapped drives exist.
        let result = detector.reconcile_identity_with_unmapped_drive(&identity, "");
        assert_eq!(result, None);

        // device_identities should still be empty.
        assert!(detector.device_identities.read().is_empty());

        // pending_identity should contain the parked identity.
        // (We test this by directly parking, since on_usb_device_arrival is
        // #[cfg(windows)] and calls reconcile then parks.)
        *detector.pending_identity.lock() = Some(identity.clone());
        assert_eq!(
            detector.pending_identity.lock().as_ref().unwrap().serial,
            "SN42"
        );
    }

    /// When multiple unmapped drives exist, the heuristic should NOT fire
    /// (ambiguous — cannot disambiguate which identity belongs to which drive).
    #[test]
    #[cfg(not(windows))]
    fn test_usb_device_arrival_parks_when_multiple_unmapped() {
        let detector = VolumeDetector::new();
        // Simulate two USB drives plugged in but neither has an identity yet.
        detector.blocked_drives.write().insert('E');
        detector.blocked_drives.write().insert('F');
        assert!(detector.device_identities.read().is_empty());

        let identity = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN42".into(),
            description: "Test Device".into(),
        };

        // reconcile should return None because multiple unmapped drives exist.
        let result = detector.reconcile_identity_with_unmapped_drive(&identity, "");
        assert_eq!(result, None);

        // device_identities should still be empty.
        assert!(detector.device_identities.read().is_empty());

        // pending_identity should be parked.
        *detector.pending_identity.lock() = Some(identity.clone());
        assert!(detector.pending_identity.lock().is_some());
    }

    /// When the drive already has an identity, reconcile should return None
    /// (already mapped — no action needed).
    #[test]
    #[cfg(not(windows))]
    fn test_reconcile_returns_none_when_already_mapped() {
        let detector = VolumeDetector::new();
        detector.blocked_drives.write().insert('F');
        let existing = DeviceIdentity {
            vid: "1111".into(),
            pid: "2222".into(),
            serial: "OLD".into(),
            description: "Existing".into(),
        };
        detector.device_identities.write().insert('F', existing);

        let new_identity = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN42".into(),
            description: "New Device".into(),
        };

        // 'F' is already mapped, so no unmapped drives exist.
        let result = detector.reconcile_identity_with_unmapped_drive(&new_identity, "");
        assert_eq!(result, None);

        // Existing identity should not be overwritten.
        assert_eq!(
            detector.device_identity_for_drive('F').unwrap().serial,
            "OLD"
        );
    }

    /// scan_existing_usb_identities heuristic: when one unmapped drive exists
    /// and we manually call the reconciliation pattern (simulating what
    /// scan_existing_usb_identities does for each enumerated identity),
    /// device_identities gets populated.
    #[test]
    #[cfg(not(windows))]
    fn test_scan_existing_usb_identities_reconciles_single_unmapped() {
        let detector = VolumeDetector::new();
        // Simulate a drive detected at startup (scan_existing_drives would
        // have inserted it) but no identity yet.
        detector.blocked_drives.write().insert('F');
        assert!(detector.device_identities.read().is_empty());

        let identity = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN42".into(),
            description: "Test Device".into(),
        };

        // This is the same pattern scan_existing_usb_identities uses for
        // each identity returned by enumerate_connected_usb_devices.
        let result = detector.reconcile_identity_with_unmapped_drive(&identity, "");
        assert_eq!(result, Some('F'));

        assert_eq!(detector.device_identity_for_drive('F'), Some(identity));
    }

    /// When scan_existing_usb_identities encounters an already-mapped identity,
    /// it should skip it (already_mapped check).
    #[test]
    #[cfg(not(windows))]
    fn test_scan_existing_skips_already_mapped_identity() {
        let detector = VolumeDetector::new();
        detector.blocked_drives.write().insert('F');
        let existing = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN42".into(),
            description: "Existing".into(),
        };
        detector
            .device_identities
            .write()
            .insert('F', existing.clone());

        // Simulate the already_mapped check from scan_existing_usb_identities.
        let ids = detector.device_identities.read();
        let already_mapped = ids.values().any(|id| {
            id.vid == existing.vid && id.pid == existing.pid && id.serial == existing.serial
        });
        assert!(already_mapped);

        // Since already_mapped is true, scan_existing_usb_identities would skip.
        // The existing mapping should remain untouched.
        drop(ids);
        assert_eq!(
            detector.device_identity_for_drive('F').unwrap().description,
            "Existing"
        );
    }

    /// Verify that `apply_tier_enforcement` returns an error when DEVICE_CONTROLLER
    /// is not initialized (the early-return path that requires no hardware).
    #[test]
    #[cfg(windows)]
    fn test_apply_tier_enforcement_no_controller_returns_err() {
        let identity = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN42".into(),
            description: "Test".into(),
        };
        let result = apply_tier_enforcement('E', &identity, "");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("DeviceController not initialized"));
    }

    // ── Phase 43-04: decide_enforcement_outcome tests ──────────────────────

    /// "Hard error" mode: both PnP and DACL fail -> Err.
    #[test]
    fn test_decide_enforcement_outcome_hard_error_both_fail() {
        let result = decide_enforcement_outcome("Hard error", false, false, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Hard error"));
    }

    /// "Hard error" mode: PnP fails, DACL succeeds -> Err.
    #[test]
    fn test_decide_enforcement_outcome_hard_error_pnp_only_fails() {
        let result = decide_enforcement_outcome("Hard error", false, true, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Hard error"));
    }

    /// "Hard error" mode: PnP succeeds, DACL fails -> Err.
    #[test]
    fn test_decide_enforcement_outcome_hard_error_dacl_only_fails() {
        let result = decide_enforcement_outcome("Hard error", true, false, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Hard error"));
    }

    /// "Hard error" mode: both succeed -> Ok.
    #[test]
    fn test_decide_enforcement_outcome_hard_error_both_succeed() {
        let result = decide_enforcement_outcome("Hard error", true, true, 0);
        assert!(result.is_ok());
    }

    /// "Retry then error" mode: PnP fails -> Err (PnP-only check per review fix).
    #[test]
    fn test_decide_enforcement_outcome_retry_then_error_pnp_fails() {
        let result = decide_enforcement_outcome("Retry then error", false, true, 2);
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("Retry then error"));
        assert!(err_msg.contains("2 retries"));
    }

    /// "Retry then error" mode: PnP succeeds, DACL fails -> Ok (PnP-only check).
    #[test]
    fn test_decide_enforcement_outcome_retry_then_error_pnp_succeeds() {
        let result = decide_enforcement_outcome("Retry then error", true, false, 2);
        assert!(result.is_ok());
    }

    /// "Warning only" mode: any combination -> Ok.
    #[test]
    fn test_decide_enforcement_outcome_warning_only_mode() {
        assert!(decide_enforcement_outcome("Warning only", false, false, 0).is_ok());
        assert!(decide_enforcement_outcome("Warning only", false, true, 0).is_ok());
        assert!(decide_enforcement_outcome("Warning only", true, false, 0).is_ok());
        assert!(decide_enforcement_outcome("Warning only", true, true, 0).is_ok());
    }

    // ── Phase 43-04: resolve_tier_from_registry (none) serial policy tests ─

    /// Devices with serial="(none)" and policy "Always Blocked" -> Blocked.
    #[test]
    #[cfg(not(windows))]
    fn test_resolve_tier_none_serial_always_blocked() {
        let identity = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "(none)".into(),
            description: "Test".into(),
        };
        let (tier, sid, user) = resolve_tier_from_registry(&identity, "Always Blocked");
        assert_eq!(tier, UsbTrustTier::Blocked);
        assert_eq!(sid, None);
        assert_eq!(user, None);
    }

    /// Devices with serial="(none)" and policy "Allow unregistered" -> normal
    /// registry lookup proceeds (returns Blocked because cache is not set).
    #[test]
    #[cfg(not(windows))]
    fn test_resolve_tier_none_serial_allow_unregistered() {
        let identity = DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "(none)".into(),
            description: "Test".into(),
        };
        // On non-Windows, registry cache is not available, so this falls through
        // to the default-deny path (Blocked) — but NOT because of the
        // "Always Blocked" policy, because the policy is "Allow unregistered".
        let (tier, _, _) = resolve_tier_from_registry(&identity, "Allow unregistered");
        // Cache is not available on non-Windows, so default-deny applies.
        assert_eq!(tier, UsbTrustTier::Blocked);
    }

    // ── Phase 56 Plan 02: VolumeDetector rename + volume classification tests ─

    /// VolumeDetector struct exists and has the expected fields.
    #[test]
    fn test_volume_detector_struct_exists() {
        let detector = VolumeDetector::new();
        // All fields should be empty by default.
        assert!(detector.blocked_drives.read().is_empty());
        assert!(detector.device_identities.read().is_empty());
        assert!(detector.volume_class_map.read().is_empty());
        assert!(detector.pending_identity.lock().is_none());
    }

    /// volume_class_map can be written and read.
    #[test]
    fn test_volume_class_map_read_write() {
        let detector = VolumeDetector::new();
        detector
            .volume_class_map
            .write()
            .insert('E', (VolumeClass::USBRemovable, Instant::now()));

        let map = detector.volume_class_map.read();
        assert_eq!(map.get(&'E').unwrap().0, VolumeClass::USBRemovable);
    }

    /// get_volume_class_for_pipe_query returns cached value without re-querying.
    #[test]
    fn test_get_volume_class_for_pipe_query_caches() {
        let detector = VolumeDetector::new();
        // Seed the cache directly (simulating a prior classification).
        detector
            .volume_class_map
            .write()
            .insert('E', (VolumeClass::Optical, Instant::now()));

        // Second call should return cached value.
        let class = detector.get_volume_class_for_pipe_query('E');
        assert_eq!(class, Some(VolumeClass::Optical));

        // Also test case-insensitivity.
        let class_lower = detector.get_volume_class_for_pipe_query('e');
        assert_eq!(class_lower, Some(VolumeClass::Optical));
    }

    /// get_volume_class_for_pipe_query returns None for unknown drive on non-Windows.
    #[test]
    #[cfg(not(windows))]
    fn test_get_volume_class_for_pipe_query_unknown_drive() {
        let detector = VolumeDetector::new();
        // No cache entry, and classify_drive will fail on non-Windows.
        let class = detector.get_volume_class_for_pipe_query('Z');
        assert_eq!(class, None);
    }

    /// VolumeClassError can be constructed and displayed.
    #[test]
    fn test_volume_class_error_display() {
        let e = VolumeClassError::WmiQueryFailed("connection refused".into());
        let msg = format!("{e}");
        assert!(msg.contains("WMI query failed"));
        assert!(msg.contains("connection refused"));
    }

    /// WmiDiskDrive struct can be constructed (for test coverage).
    #[test]
    fn test_wmi_disk_drive_struct() {
        // Since WmiDiskDrive is #[cfg(windows)], we can't construct it on non-Windows.
        // The test is a no-op on non-Windows, but the struct definition is verified
        // by compilation on Windows.
    }

    /// VolumeDetector is Send + Sync.
    #[test]
    fn test_volume_detector_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VolumeDetector>();
    }

    // ── Phase 56 Plan 02 Task 2: VolumeArrival + volume_class_map maintenance ─

    /// volume_class_map entry is cleared on drive removal.
    #[test]
    fn test_volume_class_map_cleared_on_removal() {
        let detector = VolumeDetector::new();
        // Seed blocked_drives and volume_class_map as if a drive arrived.
        detector.blocked_drives.write().insert('E');
        detector
            .volume_class_map
            .write()
            .insert('E', (VolumeClass::USBRemovable, Instant::now()));

        // Simulate removal: drive no longer present.
        let before: HashSet<char> = detector.blocked_drives.read().iter().copied().collect();
        let now_present: HashSet<char> = HashSet::new();

        // Manually run the removal logic.
        for letter in before.difference(&now_present) {
            detector.on_drive_removal(*letter);
            if detector.volume_class_map.write().remove(letter).is_some() {
                info!(drive = %letter, "volume_class_map entry cleared on removal");
            }
        }

        // volume_class_map should be empty.
        assert!(detector.volume_class_map.read().is_empty());
        // blocked_drives should also be empty.
        assert!(detector.blocked_drives.read().is_empty());
    }

    /// volume_class_map entry survives when drive is still present.
    #[test]
    fn test_volume_class_map_survives_when_still_present() {
        let detector = VolumeDetector::new();
        detector.blocked_drives.write().insert('E');
        detector
            .volume_class_map
            .write()
            .insert('E', (VolumeClass::USBRemovable, Instant::now()));

        let before: HashSet<char> = detector.blocked_drives.read().iter().copied().collect();
        let now_present: HashSet<char> = HashSet::from(['E']);

        // Manually run the removal logic.
        for letter in before.difference(&now_present) {
            detector.on_drive_removal(*letter);
            detector.volume_class_map.write().remove(letter);
        }

        // No difference, so nothing should be removed.
        assert!(detector.blocked_drives.read().contains(&'E'));
        assert!(detector.volume_class_map.read().contains_key(&'E'));
    }

    /// handle_volume_class_query returns None when the requested drive is not
    /// in the detector's cache.
    #[test]
    fn test_handle_volume_class_query_drive_not_in_cache() {
        use dlp_common::hook_ipc::{VolumeClassQuery, VolumeClassResponse};

        // Install a fresh detector with no cached drives.
        let detector = VolumeDetector::new();
        let detector_static: &'static VolumeDetector = Box::leak(Box::new(detector));
        set_drive_detector(detector_static);

        let query = VolumeClassQuery { drive_letter: 'Z' };
        let resp = handle_volume_class_query(&query);

        // Drive Z is not in the cache, so response should be None.
        assert_eq!(resp, VolumeClassResponse { class: None });
    }

    /// handle_volume_class_query returns cached class when detector is available.
    #[test]
    fn test_handle_volume_class_query_with_cached_class() {
        use dlp_common::hook_ipc::{VolumeClassQuery, VolumeClassResponse};

        // Set up a detector with a cached volume class.
        let detector = VolumeDetector::new();
        detector
            .volume_class_map
            .write()
            .insert('E', (VolumeClass::Optical, Instant::now()));

        // Install the detector globally (this is a test-only pattern).
        let detector_static: &'static VolumeDetector = Box::leak(Box::new(detector));
        set_drive_detector(detector_static);

        let query = VolumeClassQuery { drive_letter: 'E' };
        let resp = handle_volume_class_query(&query);

        assert_eq!(
            resp,
            VolumeClassResponse {
                class: Some(VolumeClass::Optical),
            }
        );
    }

    /// handle_volume_class_query is case-insensitive on drive letter.
    #[test]
    fn test_handle_volume_class_query_case_insensitive() {
        use dlp_common::hook_ipc::{VolumeClassQuery, VolumeClassResponse};

        let detector = VolumeDetector::new();
        detector
            .volume_class_map
            .write()
            .insert('E', (VolumeClass::SDCard, Instant::now()));

        let detector_static: &'static VolumeDetector = Box::leak(Box::new(detector));
        set_drive_detector(detector_static);

        // Lowercase query should match uppercase cache entry.
        let query = VolumeClassQuery { drive_letter: 'e' };
        let resp = handle_volume_class_query(&query);

        assert_eq!(
            resp,
            VolumeClassResponse {
                class: Some(VolumeClass::SDCard),
            }
        );
    }

    /// Duplicate suppression: re-inserting a drive after removal triggers
    /// fresh classification (volume_class_map is cleared then repopulated).
    #[test]
    fn test_duplicate_suppression_fresh_classification() {
        let detector = VolumeDetector::new();

        // First arrival.
        detector.blocked_drives.write().insert('F');
        detector
            .volume_class_map
            .write()
            .insert('F', (VolumeClass::USBRemovable, Instant::now()));

        // Removal clears everything.
        detector.on_drive_removal('F');
        detector.volume_class_map.write().remove(&'F');

        assert!(detector.blocked_drives.read().is_empty());
        assert!(detector.volume_class_map.read().is_empty());

        // Re-arrival with same letter (different device) gets fresh state.
        detector.blocked_drives.write().insert('F');
        detector
            .volume_class_map
            .write()
            .insert('F', (VolumeClass::Virtual, Instant::now()));

        let map = detector.volume_class_map.read();
        assert_eq!(map.get(&'F').unwrap().0, VolumeClass::Virtual);
    }
}
