//! USB enforcement layer (USB-03).
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
//! 4. Return a [`Decision`]:
//!    - [`UsbTrustTier::Blocked`]: deny all operations.
//!    - [`UsbTrustTier::ReadOnly`]: deny write-class operations; allow reads.
//!    - [`UsbTrustTier::FullAccess`]: return `None` (fall through to ABAC engine).
//!
//! UNC paths (`\\server\share\...`) are not USB drives and return `None` immediately.
//! Paths on drives not present in the USB detector return `None` (not a USB drive).

use std::sync::Arc;

use dlp_common::{Decision, UsbTrustTier};

use crate::device_registry::DeviceRegistryCache;
use crate::detection::UsbDetector;
use crate::interception::FileAction;

/// Bridges USB device identity (Phase 23) and trust-tier registry (Phase 24)
/// to enforce device trust policies at file I/O time.
///
/// Held behind `Arc` so it can be shared between the event loop and future
/// USB notification handlers without cloning the underlying caches.
pub struct UsbEnforcer {
    detector: Arc<UsbDetector>,
    registry: Arc<DeviceRegistryCache>,
}

impl UsbEnforcer {
    /// Constructs a new [`UsbEnforcer`] backed by the given caches.
    ///
    /// # Arguments
    ///
    /// * `detector` - Shared USB detector holding the drive-letter → [`DeviceIdentity`] map.
    /// * `registry` - Shared device registry cache holding VID/PID/serial → [`UsbTrustTier`].
    pub fn new(detector: Arc<UsbDetector>, registry: Arc<DeviceRegistryCache>) -> Self {
        Self { detector, registry }
    }

    /// Evaluates whether the given file operation should be blocked based on the
    /// USB trust tier of the drive the file resides on.
    ///
    /// Returns `Some(Decision::DENY)` if the operation must be blocked.
    /// Returns `None` if the path is not on a USB drive or the device has full access
    /// (caller should proceed to ABAC evaluation).
    ///
    /// # Arguments
    ///
    /// * `path` - Full file path of the operation (e.g., `E:\secret.docx`).
    /// * `action` - The [`FileAction`] being evaluated.
    ///
    /// # Returns
    ///
    /// - `Some(Decision::DENY)` — operation must be blocked.
    /// - `None` — not a USB path, or USB path with full access; proceed to ABAC.
    #[must_use]
    pub fn check(&self, path: &str, action: &FileAction) -> Option<Decision> {
        // D-09: Extract drive letter — first character, must be ASCII alphabetic.
        // UNC paths start with `\\` and have no drive letter; return None immediately.
        let drive = extract_drive_letter(path)?;

        // Look up the DeviceIdentity for this drive letter.
        // If the drive is not in the USB detector's map, it is not a USB drive.
        let identity = {
            let map = self.detector.device_identities.read();
            map.get(&drive).cloned()
        };
        let identity = identity?;

        // Look up the trust tier from the device registry using the device triple.
        let tier = self
            .registry
            .trust_tier_for(&identity.vid, &identity.pid, &identity.serial);

        match tier {
            // Blocked: deny all operations regardless of action type.
            UsbTrustTier::Blocked => Some(Decision::DENY),
            // ReadOnly: deny write-class operations; allow reads (D-08).
            UsbTrustTier::ReadOnly => {
                if is_write_class(action) {
                    Some(Decision::DENY)
                } else {
                    None
                }
            }
            // FullAccess: no USB-level enforcement; fall through to ABAC engine.
            UsbTrustTier::FullAccess => None,
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

/// Returns `true` if the [`FileAction`] is a write-class operation (D-08).
///
/// Write-class operations are blocked on `ReadOnly` USB devices.
/// The only allowed action on a `ReadOnly` device is `Read`.
///
/// D-08 write-class variants: `Written`, `Created`, `Deleted`, `Moved` (Renamed).
fn is_write_class(action: &FileAction) -> bool {
    matches!(
        action,
        FileAction::Written { .. }
            | FileAction::Created { .. }
            | FileAction::Deleted { .. }
            | FileAction::Moved { .. }
    )
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
    fn test_blocked_device_denies_all_actions() {
        let detector = make_detector(vec![('E', "0951", "1666", "SN001")]);
        let registry = make_registry("0951", "1666", "SN001", UsbTrustTier::Blocked);
        let enforcer = UsbEnforcer::new(detector, registry);

        assert_eq!(
            enforcer.check("E:\\file.txt", &written_action()),
            Some(Decision::DENY)
        );
        assert_eq!(
            enforcer.check("E:\\file.txt", &read_action()),
            Some(Decision::DENY)
        );
        assert_eq!(
            enforcer.check("E:\\file.txt", &created_action()),
            Some(Decision::DENY)
        );
        assert_eq!(
            enforcer.check("E:\\file.txt", &deleted_action()),
            Some(Decision::DENY)
        );
        assert_eq!(
            enforcer.check("E:\\file.txt", &moved_action()),
            Some(Decision::DENY)
        );
    }

    #[test]
    fn test_readonly_device_denies_write_class() {
        let detector = make_detector(vec![('E', "0951", "1666", "SN001")]);
        let registry = make_registry("0951", "1666", "SN001", UsbTrustTier::ReadOnly);
        let enforcer = UsbEnforcer::new(detector, registry);

        assert_eq!(
            enforcer.check("E:\\file.txt", &written_action()),
            Some(Decision::DENY)
        );
        assert_eq!(
            enforcer.check("E:\\file.txt", &created_action()),
            Some(Decision::DENY)
        );
        assert_eq!(
            enforcer.check("E:\\file.txt", &deleted_action()),
            Some(Decision::DENY)
        );
        assert_eq!(
            enforcer.check("E:\\file.txt", &moved_action()),
            Some(Decision::DENY)
        );
    }

    #[test]
    fn test_readonly_device_allows_read() {
        let detector = make_detector(vec![('E', "0951", "1666", "SN001")]);
        let registry = make_registry("0951", "1666", "SN001", UsbTrustTier::ReadOnly);
        let enforcer = UsbEnforcer::new(detector, registry);

        assert_eq!(enforcer.check("E:\\file.txt", &read_action()), None);
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
}
