//! USB enforcement layer (USB-03, USB-04).
//!
//! [`UsbEnforcer`] bridges the Phase 23 drive-letter map ([`UsbDetector`])
//! and the Phase 24 trust-tier cache ([`DeviceRegistryCache`]) to enforce
//! USB device trust tiers at file I/O time.
//!
//! ## Decision logic
//!
//! 1. Extract the drive letter from the file path (first character, must be ASCII alpha).
//! 2. Look up the [`DeviceIdentity`] for that drive letter in the USB detector's map.
//! 3. Look up the [`UsbTrustTier`] from the device registry using the VID/PID/serial.
//! 4. Return a [`UsbBlockResult`] carrying the decision, identity, tier, and toast flag:
//!    - [`UsbTrustTier::Blocked`]: return `None` — device is disabled at the PnP
//!      level by [`DeviceController`](crate::device_controller::DeviceController),
//!      so no file events are expected.
//!    - [`UsbTrustTier::ReadOnly`]: return `None` — volume DACL is modified by
//!      [`DeviceController`](crate::device_controller::DeviceController) on arrival,
//!      so NTFS enforces the restriction.
//!    - [`UsbTrustTier::FullAccess`]: return `None` (fall through to ABAC engine).
//!
//! UNC paths (`\\server\share\...`) are not USB drives and return `None` immediately.
//! Paths on drives not present in the USB detector return `None` (not a USB drive).
//!
//! ## Architecture note (Phase 31)
//!
//! Active blocking (device disable for Blocked, DACL modification for ReadOnly)
//! is now handled by [`DeviceController`](crate::device_controller::DeviceController)
//! firing from `usb_wndproc` on device arrival. This module only handles the
//! fallback case: unregistered devices (unknown VID/PID/serial) still default
//! to deny at the file I/O level as a defence-in-depth measure.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dlp_common::{Decision, DeviceIdentity, UsbTrustTier};
use parking_lot::Mutex;

use crate::detection::UsbDetector;
use crate::device_registry::DeviceRegistryCache;
use crate::interception::FileAction;

/// Result returned by [`UsbEnforcer::check`] when a USB operation is blocked.
///
/// Carries all data needed by the interception event loop to emit an audit event
/// and — when `notify` is true — broadcast a toast notification to the UI.
///
/// `notify` is `false` when a per-drive-letter 30-second cooldown is active.
/// The block decision (`Decision::DENY`) is always applied regardless of `notify`.
#[derive(Debug, Clone, PartialEq)]
pub struct UsbBlockResult {
    /// The enforcement decision — currently always `Decision::DENY`.
    pub decision: Decision,
    /// The device identity for the blocked drive (VID, PID, serial, description).
    pub identity: DeviceIdentity,
    /// The USB trust tier that triggered the block.
    pub tier: UsbTrustTier,
    /// `true` if the UI should display a toast; `false` when cooldown suppresses it.
    pub notify: bool,
}

/// Bridges USB device identity (Phase 23) and trust-tier registry (Phase 24)
/// to enforce device trust policies at file I/O time.
///
/// Held behind `Arc` so it can be shared between the event loop and future
/// USB notification handlers without cloning the underlying caches.
pub struct UsbEnforcer {
    detector: Arc<UsbDetector>,
    registry: Arc<DeviceRegistryCache>,
    /// Per-drive-letter timestamp of the last toast broadcast.
    /// Used to enforce the 30-second cooldown (D-02).
    last_toast: Mutex<HashMap<char, Instant>>,
}

impl UsbEnforcer {
    /// Constructs a new [`UsbEnforcer`] backed by the given caches.
    ///
    /// # Arguments
    ///
    /// * `detector` - Shared USB detector holding the drive-letter → [`DeviceIdentity`] map.
    /// * `registry` - Shared device registry cache holding VID/PID/serial → [`UsbTrustTier`].
    pub fn new(detector: Arc<UsbDetector>, registry: Arc<DeviceRegistryCache>) -> Self {
        Self {
            detector,
            registry,
            last_toast: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` and updates `last_toast` if the drive's cooldown has expired
    /// (or the drive has never fired a toast). Returns `false` during the 30-second
    /// cooldown window. The block decision is NOT affected by this return value.
    fn should_notify(&self, drive: char) -> bool {
        const COOLDOWN: Duration = Duration::from_secs(30);
        let mut map = self.last_toast.lock();
        let now = Instant::now();
        // `is_none_or` treats a missing entry as "expired" so the first call always
        // returns true. `duration_since` is safe here because `now` is always >= stored
        // `last`; both are monotonic `Instant` values from the same clock.
        let expired = map
            .get(&drive)
            .is_none_or(|last| now.duration_since(*last) >= COOLDOWN);
        if expired {
            map.insert(drive, now);
        }
        expired
    }

    /// Evaluates whether the given file operation should be blocked based on the
    /// USB trust tier of the drive the file resides on.
    ///
    /// Returns `Some(UsbBlockResult)` only for unregistered devices (default-deny
    /// fallback). All registered devices return `None` because active enforcement
    /// is now handled at the PnP level by [`DeviceController`](crate::device_controller::DeviceController):
    /// - `Blocked` devices are disabled on arrival and generate no file events.
    /// - `ReadOnly` devices have their volume DACL modified on arrival; NTFS
    ///   enforces the restriction.
    /// - `FullAccess` devices fall through to ABAC evaluation.
    ///
    /// # Arguments
    ///
    /// * `path` - Full file path of the operation (e.g., `E:\secret.docx`).
    /// * `action` - The [`FileAction`] being evaluated.
    ///
    /// # Returns
    ///
    /// - `Some(UsbBlockResult)` — unregistered device; default-deny at I/O level.
    /// - `None` — not a USB path, or registered device; proceed to ABAC or OS-level enforcement.
    #[must_use]
    pub fn check(&self, path: &str, _action: &FileAction) -> Option<UsbBlockResult> {
        // D-09: Extract drive letter — first character, must be ASCII alphabetic.
        // UNC paths start with `\\` and have no drive letter; return None immediately.
        let drive = extract_drive_letter(path)?;

        // Look up the DeviceIdentity for this drive letter.
        // If the drive is not in the USB detector's map, it is not a USB drive.
        let identity = {
            let map = self.detector.device_identities.read();
            map.get(&drive).cloned()
        };
        let identity = match identity {
            Some(id) => id,
            None => {
                // Defence-in-depth: a drive letter may be known as USB (via
                // `scan_existing_drives` at startup or a missed identity-capture
                // race) without an associated VID/PID/serial. In that case, we
                // cannot consult the device registry — but treating the drive as
                // "not a USB" and falling through to ABAC would violate the
                // default-deny posture (Zero Trust, CLAUDE.md §3.1). If the drive
                // is in `blocked_drives`, treat it as a known-USB-without-identity
                // and DENY all operations with tier=Blocked.
                if self.detector.blocked_drives.read().contains(&drive) {
                    let notify = self.should_notify(drive);
                    return Some(UsbBlockResult {
                        decision: Decision::DENY,
                        identity: DeviceIdentity {
                            vid: "unknown".into(),
                            pid: "unknown".into(),
                            serial: "unknown".into(),
                            description: format!("USB drive {} (identity not captured)", drive),
                        },
                        tier: UsbTrustTier::Blocked,
                        notify,
                    });
                }
                return None;
            }
        };

        // Check if the device is explicitly registered in the device registry.
        // Registered devices are handled at the PnP level by DeviceController
        // (disable for Blocked, DACL modification for ReadOnly). Unregistered
        // devices default to deny at the I/O level as defence-in-depth.
        let is_registered =
            self.registry
                .has_device(&identity.vid, &identity.pid, &identity.serial);

        if is_registered {
            // Registered device: active enforcement is handled by DeviceController.
            // Blocked → disabled on arrival; ReadOnly → DACL modified on arrival;
            // FullAccess → no action. All cases return None.
            None
        } else {
            // Unregistered device: default deny at the I/O level (fail-safe).
            let notify = self.should_notify(drive);
            Some(UsbBlockResult {
                decision: Decision::DENY,
                identity,
                tier: UsbTrustTier::Blocked,
                notify,
            })
        }
    }

}

/// Extracts the uppercase drive letter from a Windows file path.
///
/// Returns `Some('E')` for `E:\data\file.txt` and `None` for:
/// - UNC paths (`\\server\share\...`)
/// - Paths that do not start with an ASCII alphabetic character
/// - Empty paths
fn extract_drive_letter(path: &str) -> Option<char> {
    // UNC paths start with `\\` — they are never local USB drives.
    if path.starts_with("\\\\") {
        return None;
    }
    let first = path.chars().next()?;
    if first.is_ascii_alphabetic() {
        Some(first.to_ascii_uppercase())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    use dlp_common::DeviceIdentity;
    use parking_lot::RwLock;

    /// Builds a UsbDetector with specific drive-letter to DeviceIdentity mappings.
    fn make_detector(entries: Vec<(char, &str, &str, &str)>) -> Arc<UsbDetector> {
        let mut map = HashMap::new();
        let mut blocked = HashSet::new();
        for (drive, vid, pid, serial) in entries {
            map.insert(
                drive,
                DeviceIdentity {
                    vid: vid.to_string(),
                    pid: pid.to_string(),
                    serial: serial.to_string(),
                    description: "Test Device".to_string(),
                },
            );
            blocked.insert(drive);
        }
        Arc::new(UsbDetector {
            blocked_drives: RwLock::new(blocked),
            device_identities: RwLock::new(map),
            ..Default::default()
        })
    }

    /// Builds a DeviceRegistryCache pre-seeded with the given trust tier.
    fn make_registry(
        vid: &str,
        pid: &str,
        serial: &str,
        tier: UsbTrustTier,
    ) -> Arc<DeviceRegistryCache> {
        let cache = Arc::new(DeviceRegistryCache::new());
        cache.seed_for_test(vid, pid, serial, tier);
        cache
    }

    fn written_action() -> FileAction {
        FileAction::Written {
            path: "E:\\file.txt".to_string(),
            process_id: 1,
            related_process_id: 1,
            byte_count: 100,
        }
    }

    fn created_action() -> FileAction {
        FileAction::Created {
            path: "E:\\file.txt".to_string(),
            process_id: 1,
            related_process_id: 1,
        }
    }

    fn deleted_action() -> FileAction {
        FileAction::Deleted {
            path: "E:\\file.txt".to_string(),
            process_id: 1,
            related_process_id: 1,
        }
    }

    fn moved_action() -> FileAction {
        FileAction::Moved {
            old_path: "E:\\a.txt".to_string(),
            new_path: "E:\\b.txt".to_string(),
            process_id: 1,
            related_process_id: 1,
        }
    }

    fn read_action() -> FileAction {
        FileAction::Read {
            path: "E:\\file.txt".to_string(),
            process_id: 1,
            related_process_id: 1,
            byte_count: 0,
        }
    }

    #[test]
    fn test_blocked_device_returns_none() {
        // Phase 31: Blocked devices are disabled at the PnP level by DeviceController.
        // UsbEnforcer::check() returns None for all registered tiers.
        let detector = make_detector(vec![('E', "0951", "1666", "SN001")]);
        let registry = make_registry("0951", "1666", "SN001", UsbTrustTier::Blocked);
        let enforcer = UsbEnforcer::new(detector, registry);

        assert_eq!(enforcer.check("E:\\file.txt", &written_action()), None);
        assert_eq!(enforcer.check("E:\\file.txt", &read_action()), None);
        assert_eq!(enforcer.check("E:\\file.txt", &created_action()), None);
        assert_eq!(enforcer.check("E:\\file.txt", &deleted_action()), None);
        assert_eq!(enforcer.check("E:\\file.txt", &moved_action()), None);
    }

    #[test]
    fn test_readonly_device_returns_none() {
        // Phase 31: ReadOnly devices have volume DACL modified by DeviceController.
        // UsbEnforcer::check() returns None for all registered tiers.
        let detector = make_detector(vec![('E', "0951", "1666", "SN001")]);
        let registry = make_registry("0951", "1666", "SN001", UsbTrustTier::ReadOnly);
        let enforcer = UsbEnforcer::new(detector, registry);

        assert_eq!(enforcer.check("E:\\file.txt", &written_action()), None);
        assert_eq!(enforcer.check("E:\\file.txt", &read_action()), None);
        assert_eq!(enforcer.check("E:\\file.txt", &created_action()), None);
        assert_eq!(enforcer.check("E:\\file.txt", &deleted_action()), None);
        assert_eq!(enforcer.check("E:\\file.txt", &moved_action()), None);
    }

    #[test]
    fn test_full_access_device_returns_none() {
        let detector = make_detector(vec![('E', "0951", "1666", "SN001")]);
        let registry = make_registry("0951", "1666", "SN001", UsbTrustTier::FullAccess);
        let enforcer = UsbEnforcer::new(detector, registry);

        assert_eq!(enforcer.check("E:\\file.txt", &written_action()), None);
        assert_eq!(enforcer.check("E:\\file.txt", &read_action()), None);
    }

    #[test]
    fn test_unc_path_returns_none() {
        let detector = make_detector(vec![]);
        let registry = Arc::new(DeviceRegistryCache::new());
        let enforcer = UsbEnforcer::new(detector, registry);

        // UNC paths have no drive letter — USB enforcement skipped.
        assert_eq!(
            enforcer.check("\\\\server\\share\\file.txt", &written_action()),
            None
        );
    }

    #[test]
    fn test_non_usb_drive_returns_none() {
        // Drive C is not in the USB detector's device_identities map.
        let detector = make_detector(vec![('E', "0951", "1666", "SN001")]);
        let registry = make_registry("0951", "1666", "SN001", UsbTrustTier::Blocked);
        let enforcer = UsbEnforcer::new(detector, registry);

        // C drive is not a USB drive, returns None.
        assert_eq!(
            enforcer.check("C:\\Users\\data\\file.txt", &written_action()),
            None
        );
    }

    #[test]
    fn test_extract_drive_letter_valid() {
        assert_eq!(extract_drive_letter("E:\\file.txt"), Some('E'));
        // Lowercase drive letter is normalized to uppercase (T-26-12 mitigation).
        assert_eq!(extract_drive_letter("e:\\file.txt"), Some('E'));
        assert_eq!(extract_drive_letter("C:\\Windows"), Some('C'));
    }

    #[test]
    fn test_extract_drive_letter_unc_returns_none() {
        assert_eq!(extract_drive_letter("\\\\server\\share"), None);
    }

    #[test]
    fn test_extract_drive_letter_empty_returns_none() {
        assert_eq!(extract_drive_letter(""), None);
    }

    /// T-26-14: Unregistered device defaults to Blocked (fail-safe).
    ///
    /// The device triple is present in the USB detector's drive-letter map
    /// (the drive letter IS known), but the VID/PID/serial are NOT in the
    /// device registry cache. `trust_tier_for` returns `Blocked` as the
    /// default — all operations are denied (CLAUDE.md section 3.1, Zero Trust).
    #[test]
    fn test_unregistered_device_defaults_to_blocked() {
        // Detector knows about drive E (device identity present), but the
        // registry has never been seeded with this VID/PID/serial.
        let detector = make_detector(vec![('E', "DEAD", "BEEF", "UNREGISTERED")]);
        // Empty registry — no seed_for_test call.
        let registry = Arc::new(DeviceRegistryCache::new());
        let enforcer = UsbEnforcer::new(detector, registry);

        // Write must be denied.
        let result = enforcer.check("E:\\secret.docx", &written_action());
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);

        // Read must also be denied (default-deny for unknown devices).
        let result = enforcer.check("E:\\file.txt", &read_action()).unwrap();
        assert_eq!(result.decision, Decision::DENY);
        assert_eq!(result.tier, UsbTrustTier::Blocked);
    }

    /// D-09: path starting with a non-ASCII-alphabetic character returns None.
    ///
    /// Linux-style paths (e.g., `/usr/local/file.txt`) start with `/` which
    /// is not an ASCII alphabetic character. No drive letter can be extracted,
    /// so USB enforcement is skipped entirely.
    #[test]
    fn test_non_alpha_path_returns_none() {
        let detector = make_detector(vec![]);
        let registry = Arc::new(DeviceRegistryCache::new());
        let enforcer = UsbEnforcer::new(detector, registry);

        // Path starting with `/` (Linux-style) has no Windows drive letter.
        assert_eq!(
            enforcer.check("/usr/local/file.txt", &written_action()),
            None
        );
    }

    /// Defence-in-depth: a drive letter known to be USB (via `scan_existing_drives`)
    /// but missing from `device_identities` (VID/PID/serial never captured) must still
    /// be denied on all operations. Without this guard, the enforcer would return `None`
    /// and fall through to ABAC, which allows the operation — the Phase 28 UAT bug.
    ///
    /// Precondition: `blocked_drives` contains the letter; `device_identities` is empty.
    #[test]
    fn test_known_usb_without_identity_is_denied() {
        // Build a detector with E in blocked_drives but nothing in device_identities —
        // simulating a USB plugged in before the agent started (scan_existing_drives
        // captures the drive letter but not the VID/PID/serial).
        let mut blocked = HashSet::new();
        blocked.insert('E');
        let detector = Arc::new(UsbDetector {
            blocked_drives: RwLock::new(blocked),
            device_identities: RwLock::new(HashMap::new()),
            ..Default::default()
        });
        let registry = Arc::new(DeviceRegistryCache::new());
        let enforcer = UsbEnforcer::new(detector, registry);

        for action in [
            written_action(),
            read_action(),
            created_action(),
            deleted_action(),
            moved_action(),
        ] {
            let result = enforcer.check("E:\\file.txt", &action);
            let r = result.expect("known USB without identity must be denied, not allowed");
            assert_eq!(r.decision, Decision::DENY, "action {action:?} must DENY");
            assert_eq!(
                r.tier,
                UsbTrustTier::Blocked,
                "action {action:?} must report Blocked tier"
            );
        }
    }

    /// Blocked drive without identity: returns default-deny with Blocked tier.
    ///
    /// When a drive is in `blocked_drives` but has no `DeviceIdentity` entry,
    /// the enforcer still denies all operations with a default identity
    /// (empty strings) as a defence-in-depth fallback.
    #[test]
    fn test_blocked_drive_without_identity_returns_blocked() {
        let detector = Arc::new(UsbDetector {
            blocked_drives: RwLock::new(HashSet::from(['E'])),
            device_identities: RwLock::new(HashMap::new()),
            ..Default::default()
        });
        let registry = Arc::new(DeviceRegistryCache::new());
        let enforcer = UsbEnforcer::new(detector, registry);
        let result = enforcer.check("E:\\file.txt", &written_action());
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.decision, Decision::DENY);
        assert_eq!(r.tier, UsbTrustTier::Blocked);
        assert_eq!(r.identity.vid, "unknown");
        assert_eq!(r.identity.pid, "unknown");
        assert_eq!(r.identity.serial, "unknown");
        assert!(r.identity.description.contains("USB drive E"));
        assert!(r.notify); // first call
    }

    /// FullAccess device: all actions are allowed (fall through to ABAC).
    ///
    /// Verifies that Written, Read, and Created actions all return None
    /// when the device trust tier is FullAccess.
    #[test]
    fn test_full_access_device_all_actions_allowed() {
        let detector = make_detector(vec![('E', "0951", "1666", "SN001")]);
        let registry = make_registry("0951", "1666", "SN001", UsbTrustTier::FullAccess);
        let enforcer = UsbEnforcer::new(detector, registry);
        assert_eq!(enforcer.check("E:\\file.txt", &written_action()), None);
        assert_eq!(enforcer.check("E:\\file.txt", &read_action()), None);
        assert_eq!(enforcer.check("E:\\file.txt", &created_action()), None);
    }

    /// Per-drive isolation: different drives can have different trust tiers.
    ///
    /// Drive E is unregistered (default Blocked → I/O-level deny), drive F is FullAccess.
    /// Operations on each drive must be evaluated independently.
    #[test]
    fn test_per_drive_isolation() {
        let mut map = HashMap::new();
        let mut blocked = HashSet::new();
        map.insert(
            'E',
            DeviceIdentity {
                vid: "0951".into(),
                pid: "1666".into(),
                serial: "SN001".into(),
                description: "Test".into(),
            },
        );
        map.insert(
            'F',
            DeviceIdentity {
                vid: "0951".into(),
                pid: "1667".into(),
                serial: "SN002".into(),
                description: "Test2".into(),
            },
        );
        blocked.insert('E');
        blocked.insert('F');
        let detector = Arc::new(UsbDetector {
            blocked_drives: RwLock::new(blocked),
            device_identities: RwLock::new(map),
            ..Default::default()
        });
        let registry = Arc::new(DeviceRegistryCache::new());
        // E is NOT seeded → default-deny at I/O level (unregistered device fallback).
        registry.seed_for_test("0951", "1667", "SN002", UsbTrustTier::FullAccess);
        let enforcer = UsbEnforcer::new(detector, registry);
        // E is unregistered → default deny (defence-in-depth).
        assert!(enforcer.check("E:\\file.txt", &written_action()).is_some());
        // F is FullAccess → fall through to ABAC.
        assert_eq!(enforcer.check("F:\\file.txt", &written_action()), None);
    }
}
