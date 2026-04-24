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
//!    - [`UsbTrustTier::Blocked`]: deny all operations; `notify` per 30-second cooldown.
//!    - [`UsbTrustTier::ReadOnly`]: deny write-class operations; `notify` per cooldown.
//!    - [`UsbTrustTier::FullAccess`]: return `None` (fall through to ABAC engine).
//!
//! UNC paths (`\\server\share\...`) are not USB drives and return `None` immediately.
//! Paths on drives not present in the USB detector return `None` (not a USB drive).

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
    /// Returns `Some(UsbBlockResult)` if the operation must be blocked, carrying
    /// the decision, device identity, trust tier, and a toast notification flag.
    /// Returns `None` if the path is not on a USB drive or the device has full access
    /// (caller should proceed to ABAC evaluation).
    ///
    /// The `notify` field in the result is `true` on the first block within a
    /// 30-second window for a given drive letter; subsequent calls within the same
    /// window return `notify: false`. The block decision is always `DENY` regardless.
    ///
    /// # Arguments
    ///
    /// * `path` - Full file path of the operation (e.g., `E:\secret.docx`).
    /// * `action` - The [`FileAction`] being evaluated.
    ///
    /// # Returns
    ///
    /// - `Some(UsbBlockResult)` — operation must be blocked; see struct fields for detail.
    /// - `None` — not a USB path, or USB path with full access; proceed to ABAC.
    #[must_use]
    pub fn check(&self, path: &str, action: &FileAction) -> Option<UsbBlockResult> {
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
                        identity: DeviceIdentity::default(),
                        tier: UsbTrustTier::Blocked,
                        notify,
                    });
                }
                return None;
            }
        };

        // Look up the trust tier from the device registry using the device triple.
        let tier = self
            .registry
            .trust_tier_for(&identity.vid, &identity.pid, &identity.serial);

        match tier {
            // Blocked: deny all operations regardless of action type.
            UsbTrustTier::Blocked => {
                let notify = self.should_notify(drive);
                Some(UsbBlockResult {
                    decision: Decision::DENY,
                    identity,
                    tier: UsbTrustTier::Blocked,
                    notify,
                })
            }
            // ReadOnly: deny write-class operations; allow reads (D-08).
            UsbTrustTier::ReadOnly => {
                if is_write_class(action) {
                    let notify = self.should_notify(drive);
                    Some(UsbBlockResult {
                        decision: Decision::DENY,
                        identity,
                        tier: UsbTrustTier::ReadOnly,
                        notify,
                    })
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

        // Written — blocked tier, first call so notify=true.
        let result = enforcer.check("E:\\file.txt", &written_action());
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.decision, Decision::DENY);
        assert_eq!(r.tier, UsbTrustTier::Blocked);
        assert_eq!(r.identity.description, "Test Device");

        // Read — same drive, cooldown window active, notify=false but still DENY.
        let result = enforcer.check("E:\\file.txt", &read_action());
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);

        let result = enforcer.check("E:\\file.txt", &created_action());
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);

        let result = enforcer.check("E:\\file.txt", &deleted_action());
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);

        let result = enforcer.check("E:\\file.txt", &moved_action());
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);
    }

    #[test]
    fn test_readonly_device_denies_write_class() {
        let detector = make_detector(vec![('E', "0951", "1666", "SN001")]);
        let registry = make_registry("0951", "1666", "SN001", UsbTrustTier::ReadOnly);
        let enforcer = UsbEnforcer::new(detector, registry);

        // Written — first write, notify=true, decision DENY.
        let result = enforcer.check("E:\\file.txt", &written_action());
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.decision, Decision::DENY);
        assert_eq!(r.tier, UsbTrustTier::ReadOnly);

        let result = enforcer.check("E:\\file.txt", &created_action());
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);

        let result = enforcer.check("E:\\file.txt", &deleted_action());
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);

        let result = enforcer.check("E:\\file.txt", &moved_action());
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);
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

    /// T-26-14: Unregistered device defaults to Blocked (fail-safe).
    ///
    /// The device triple is present in the USB detector's drive-letter map
    /// (the drive letter IS known), but the VID/PID/serial are NOT in the
    /// device registry cache. `trust_tier_for` returns `Blocked` as the
    /// default-deny value (D-10). All operations must be denied.
    #[test]
    fn test_unregistered_device_defaults_to_blocked() {
        // Detector knows about drive E (device identity present), but the
        // registry has never been seeded with this VID/PID/serial.
        let detector = make_detector(vec![('E', "DEAD", "BEEF", "UNREGISTERED")]);
        // Empty registry — no seed_for_test call.
        let registry = Arc::new(DeviceRegistryCache::new());
        let enforcer = UsbEnforcer::new(detector, registry);

        // Default-deny: unregistered device treated as Blocked.
        let result = enforcer.check("E:\\secret.docx", &written_action());
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);

        let result = enforcer.check("E:\\file.txt", &read_action());
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);
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

    /// D-02 (USB-04): Per-drive cooldown suppresses repeat toasts without
    /// suppressing the block decision.
    ///
    /// First call within a 30-second window: notify=true, decision=DENY.
    /// Second call within the same window: notify=false, decision=DENY.
    /// The block is always enforced; only the toast is gated by the cooldown.
    #[test]
    fn test_cooldown_suppresses_second_toast() {
        let detector = make_detector(vec![('E', "0951", "1666", "SN001")]);
        let registry = make_registry("0951", "1666", "SN001", UsbTrustTier::Blocked);
        let enforcer = UsbEnforcer::new(detector, registry);

        // First call: cooldown map is empty, so notify=true.
        let first = enforcer
            .check("E:\\file.txt", &written_action())
            .expect("first check must return Some for Blocked device");
        assert_eq!(first.decision, Decision::DENY, "first call must still deny");
        assert!(first.notify, "first call must request toast notification");

        // Immediate second call: cooldown is active (< 30s elapsed), notify=false.
        let second = enforcer
            .check("E:\\file.txt", &written_action())
            .expect("second check must return Some for Blocked device");
        assert_eq!(
            second.decision,
            Decision::DENY,
            "second call must still deny"
        );
        assert!(
            !second.notify,
            "second call within cooldown window must suppress toast"
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
}
