//! Fixed-disk enforcement layer (DISK-04, Phase 36).
//!
//! [`DiskEnforcer`] bridges the Phase 33-35 [`DiskEnumerator`] (frozen
//! `instance_id_map` allowlist + live `drive_letter_map`) and the
//! [`run_event_loop`](crate::interception::run_event_loop) write-path
//! to enforce the disk allowlist at file I/O time.
//!
//! ## Decision logic (per 36-CONTEXT.md D-06, D-07)
//!
//! 1. Action filter: only `Created`, `Written`, `Moved` are intercepted (DISK-04).
//!    `Read` and `Deleted` always return `None`.
//! 2. Fail-closed: if [`get_disk_enumerator`] returns `None` or
//!    [`DiskEnumerator::is_ready`] is false, ALL fixed-disk writes are blocked
//!    with a placeholder identity (D-06).
//! 3. Drive-letter resolution: extract the first ASCII alpha character of the
//!    path; reject UNC paths and non-alpha leading characters.
//! 4. Live-disk lookup: `disk_for_drive_letter(letter)` returns `None` when the
//!    drive is not a tracked fixed disk -> pass through to ABAC.
//! 5. Allowlist check: `disk_for_instance_id(live.instance_id)` -> if `None`,
//!    block with the live identity.
//! 6. Compound serial check (D-11 physical-swap closure): when both registered
//!    and live serials are `Some(...)` and differ, block with the live identity.
//! 7. Otherwise, return `None` (fall through to ABAC).
//!
//! ## Cooldown semantics (D-02)
//!
//! `last_toast: parking_lot::Mutex<HashMap<char, Instant>>` enforces a
//! 30-second per-drive-letter toast cooldown. The block decision is ALWAYS
//! applied; only the toast/notify side-effect is suppressed during cooldown.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use dlp_common::{Decision, DiskIdentity};
use parking_lot::Mutex;

use crate::detection::disk::get_disk_enumerator;
use crate::interception::FileAction;

/// Result returned by [`DiskEnforcer::check`] when a fixed-disk write is blocked.
///
/// Carries the [`Decision`], the live [`DiskIdentity`] that triggered the block,
/// and a `notify` flag indicating whether the per-drive 30-second toast cooldown
/// has elapsed. The block decision is always applied regardless of `notify`.
#[derive(Debug, Clone, PartialEq)]
pub struct DiskBlockResult {
    /// The enforcement decision -- currently always [`Decision::DENY`].
    pub decision: Decision,
    /// The live [`DiskIdentity`] from `drive_letter_map` at enforcement time.
    /// For the fail-closed startup-window case (D-06), only `drive_letter` is
    /// populated and other fields use `Default` values.
    pub disk: DiskIdentity,
    /// `true` if the UI should display a toast; `false` when the 30-second
    /// per-drive cooldown is active.
    pub notify: bool,
}

/// Enforces the disk allowlist at file I/O time (DISK-04, Phase 36).
///
/// Wraps the global [`DiskEnumerator`] (Phase 33-35) internally via
/// [`get_disk_enumerator`] -- the enumerator must be installed via
/// `set_disk_enumerator` before [`DiskEnforcer::check`] is called.
/// Held behind `Arc` so it can be shared between the event loop and other
/// subsystems without cloning the cooldown map.
pub struct DiskEnforcer {
    /// Per-drive-letter timestamp of the last toast broadcast.
    /// Enforces the 30-second cooldown per CONTEXT.md D-02.
    last_toast: Mutex<HashMap<char, Instant>>,
}

impl DiskEnforcer {
    /// Constructs a new [`DiskEnforcer`] with an empty cooldown map.
    ///
    /// The enforcer wraps [`get_disk_enumerator`] internally; the global
    /// `DiskEnumerator` must be installed via `set_disk_enumerator`
    /// (typically in `service.rs` startup) before [`Self::check`] is called.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_toast: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` and updates `last_toast` if the drive's cooldown has
    /// expired (or the drive has never fired a toast). Returns `false` during
    /// the 30-second cooldown window. The block decision is NOT affected by
    /// this return value (D-02).
    fn should_notify(&self, drive: char) -> bool {
        const COOLDOWN: Duration = Duration::from_secs(30);
        let mut map = self.last_toast.lock();
        let now = Instant::now();
        // `is_none_or` treats a missing entry as "expired" so the first call
        // always returns true. `duration_since` is safe because both Instants
        // are monotonic from the same clock.
        let expired = map
            .get(&drive)
            .is_none_or(|last| now.duration_since(*last) >= COOLDOWN);
        if expired {
            map.insert(drive, now);
        }
        expired
    }

    /// Evaluates whether the given file operation should be blocked based on
    /// the disk allowlist (per CONTEXT.md D-04 through D-07).
    ///
    /// Returns `Some(DiskBlockResult)` when the operation must be blocked;
    /// returns `None` when the operation is allowed to fall through to ABAC.
    ///
    /// # Arguments
    ///
    /// * `path` - Full file path of the operation (e.g., `E:\\file.txt`).
    /// * `action` - The [`FileAction`] being evaluated.
    ///
    /// # Returns
    ///
    /// - `None` for `FileAction::Read` or `FileAction::Deleted` (DISK-04 scope).
    /// - `None` for paths whose drive letter is not a tracked fixed disk.
    /// - `None` for allowlisted disks with matching serials.
    /// - `Some(DiskBlockResult)` when the disk is unregistered, the serial mismatches,
    ///   or the enumerator is not yet ready (D-06 fail-closed).
    #[must_use]
    pub fn check(&self, path: &str, action: &FileAction) -> Option<DiskBlockResult> {
        // DISK-04 action filter: only intercept write-path actions.
        // FileAction::Read (DLP design: read is allowed) and FileAction::Deleted
        // (metadata operation, not a write per CONTEXT.md D-04) both pass through.
        if !matches!(
            action,
            FileAction::Created { .. } | FileAction::Written { .. } | FileAction::Moved { .. }
        ) {
            return None;
        }

        // D-06 fail-closed: if the enumerator has not yet been installed in the
        // global OnceLock, the agent is in its startup window. Block ALL fixed-
        // disk writes with a placeholder identity carrying only the drive letter.
        //
        // Pitfall 3 (RESEARCH.md): the `?` operator on `get_disk_enumerator()`
        // would mean "no disk context = pass through" -- WRONG. Handle the None
        // case explicitly as fail-closed.
        let enumerator = match get_disk_enumerator() {
            Some(e) => e,
            None => {
                // WR-06: when the drive letter cannot be resolved (UNC, empty,
                // or malformed path), do not insert the '?' sentinel into the
                // per-drive cooldown map.  All unresolvable paths share the
                // same sentinel which would suppress toast notifications for
                // distinct paths after the first 30-second window.  Use
                // notify:false instead — the user cannot act on a path-less
                // notification anyway.
                let letter_opt = drive_letter_from_path(path);
                return Some(DiskBlockResult {
                    decision: Decision::DENY,
                    disk: DiskIdentity {
                        drive_letter: letter_opt,
                        ..Default::default()
                    },
                    notify: letter_opt.map_or(false, |l| self.should_notify(l)),
                });
            }
        };

        // D-06 fail-closed: enumeration not yet complete -- block all writes.
        if !enumerator.is_ready() {
            let letter_opt = drive_letter_from_path(path);
            return Some(DiskBlockResult {
                decision: Decision::DENY,
                disk: DiskIdentity {
                    drive_letter: letter_opt,
                    ..Default::default()
                },
                notify: letter_opt.map_or(false, |l| self.should_notify(l)),
            });
        }

        // D-09: extract drive letter; UNC and non-alpha leading characters mean
        // we cannot identify a fixed disk -- pass through.
        let letter = drive_letter_from_path(path)?;

        // D-07 step 2: if the drive letter is not in drive_letter_map, the path
        // is not on a tracked fixed disk -- pass through to ABAC.
        let live_disk = enumerator.disk_for_drive_letter(letter)?;

        // D-07 step 3: check the frozen allowlist (instance_id_map).
        let registered = enumerator.disk_for_instance_id(&live_disk.instance_id);

        // D-07 step 4 / D-11: compound serial check closes the physical-swap
        // bypass. Both stored and live serials must be `Some(...)` for a
        // mismatch to fire; if either is `None`, defer to allowlist presence.
        let serial_mismatch = registered
            .as_ref()
            .and_then(|r| r.serial.as_ref())
            .zip(live_disk.serial.as_ref())
            .map(|(stored, live)| stored != live)
            .unwrap_or(false);

        if registered.is_none() || serial_mismatch {
            let notify = self.should_notify(letter);
            return Some(DiskBlockResult {
                decision: Decision::DENY,
                disk: live_disk,
                notify,
            });
        }

        // D-07 step 5: allowlisted with matching (or both-None) serial -- ABAC.
        None
    }
}

impl Default for DiskEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

/// Extracts the uppercase drive letter from a Windows file path.
///
/// Returns `Some('E')` for `E:\\data\\file.txt` and `None` for:
/// - UNC paths (`\\\\server\\share\\...`)
/// - Paths that do not start with an ASCII alphabetic character
/// - Empty paths
///
/// Identical contract to `extract_drive_letter` in `usb_enforcer.rs`; kept
/// as a private free function so the disk enforcer remains independent of
/// USB code (the two modules are sibling enforcers, not a shared abstraction).
fn drive_letter_from_path(path: &str) -> Option<char> {
    // UNC paths start with `\\` -- never local fixed drives.
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
    use std::sync::Arc;
    use std::sync::OnceLock;

    use dlp_common::{BusType, DiskIdentity};

    use crate::detection::disk::{get_disk_enumerator, set_disk_enumerator, DiskEnumerator};
    // Shared process-wide lock that serializes all tests touching the global
    // DiskEnumerator OnceLock (disk_enforcer::tests + detection::disk::tests).
    use crate::test_helpers::DISK_TEST_LOCK;

    /// Returns the global DiskEnumerator, installing one if absent.
    ///
    /// We never construct a fresh enumerator per test (OnceLock allows only
    /// one set call). Instead we reuse the singleton and reset its fields.
    fn ensure_enumerator() -> Arc<DiskEnumerator> {
        static FALLBACK: OnceLock<Arc<DiskEnumerator>> = OnceLock::new();
        if let Some(e) = get_disk_enumerator() {
            return e;
        }
        let fresh = FALLBACK
            .get_or_init(|| Arc::new(DiskEnumerator::new()))
            .clone();
        set_disk_enumerator(Arc::clone(&fresh));
        fresh
    }

    /// Resets the enumerator's locked state to "not ready, empty maps".
    /// Caller must hold TEST_LOCK.
    fn reset_enumerator(enumerator: &DiskEnumerator) {
        enumerator.discovered_disks.write().clear();
        enumerator.drive_letter_map.write().clear();
        enumerator.instance_id_map.write().clear();
        *enumerator.enumeration_complete.write() = false;
    }

    /// Marks the enumerator as ready and seeds `drive_letter_map` /
    /// `instance_id_map` with the provided pairs. Caller holds TEST_LOCK.
    fn seed_enumerator(
        enumerator: &DiskEnumerator,
        drive_letter_pairs: &[(char, DiskIdentity)],
        instance_id_pairs: &[(String, DiskIdentity)],
    ) {
        {
            let mut dlm = enumerator.drive_letter_map.write();
            for (letter, disk) in drive_letter_pairs {
                dlm.insert(*letter, disk.clone());
            }
        }
        {
            let mut iim = enumerator.instance_id_map.write();
            for (id, disk) in instance_id_pairs {
                iim.insert(id.clone(), disk.clone());
            }
        }
        *enumerator.enumeration_complete.write() = true;
    }

    /// Builds a DiskIdentity test fixture with all fields specified.
    fn make_disk(
        instance_id: &str,
        drive_letter: Option<char>,
        serial: Option<&str>,
    ) -> DiskIdentity {
        DiskIdentity {
            instance_id: instance_id.to_string(),
            bus_type: BusType::Sata,
            model: format!("Model-{instance_id}"),
            drive_letter,
            serial: serial.map(|s| s.to_string()),
            size_bytes: Some(500_000_000_000),
            is_boot_disk: false,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        }
    }

    fn write_action(path: &str) -> FileAction {
        FileAction::Written {
            path: path.to_string(),
            process_id: 100,
            related_process_id: 100,
            byte_count: 100,
        }
    }

    fn create_action(path: &str) -> FileAction {
        FileAction::Created {
            path: path.to_string(),
            process_id: 100,
            related_process_id: 100,
        }
    }

    fn move_action(old_path: &str, new_path: &str) -> FileAction {
        FileAction::Moved {
            old_path: old_path.to_string(),
            new_path: new_path.to_string(),
            process_id: 100,
            related_process_id: 100,
        }
    }

    fn read_action(path: &str) -> FileAction {
        FileAction::Read {
            path: path.to_string(),
            process_id: 100,
            related_process_id: 100,
            byte_count: 100,
        }
    }

    fn delete_action(path: &str) -> FileAction {
        FileAction::Deleted {
            path: path.to_string(),
            process_id: 100,
            related_process_id: 100,
        }
    }

    // ---------- DISK-04: Read action passes through ----------
    #[test]
    fn test_read_action_returns_none() {
        let _guard = DISK_TEST_LOCK.lock();
        let enumerator = ensure_enumerator();
        reset_enumerator(&enumerator);
        // Even with an unregistered disk on E:, Read must pass through.
        let live = make_disk("ID-UNREGISTERED", Some('E'), Some("SN-LIVE"));
        seed_enumerator(&enumerator, &[('E', live)], &[]);

        let enforcer = DiskEnforcer::new();
        assert_eq!(
            enforcer.check(r"E:\file.txt", &read_action(r"E:\file.txt")),
            None
        );
    }

    // ---------- DISK-04: Deleted action passes through ----------
    #[test]
    fn test_deleted_action_returns_none() {
        let _guard = DISK_TEST_LOCK.lock();
        let enumerator = ensure_enumerator();
        reset_enumerator(&enumerator);
        let live = make_disk("ID-UNREGISTERED", Some('E'), Some("SN-LIVE"));
        seed_enumerator(&enumerator, &[('E', live)], &[]);

        let enforcer = DiskEnforcer::new();
        assert_eq!(
            enforcer.check(r"E:\file.txt", &delete_action(r"E:\file.txt")),
            None
        );
    }

    // ---------- D-06: enumerator absent -> fail-closed ----------
    // NOTE: cannot test the "OnceLock empty" case directly because the
    // global may already be installed by a prior test in the same binary.
    // We simulate the equivalent state by setting enumeration_complete = false.
    // The "enumerator absent" branch is structurally identical (same error
    // result construction); both arms are exercised by code review of the
    // `match get_disk_enumerator()` block. The not-ready branch is the
    // operationally relevant case at runtime: enumerator installed but
    // not yet ready in the 4-second startup window per Phase 33 D-04.
    #[test]
    fn test_write_blocked_when_not_ready_fail_closed() {
        let _guard = DISK_TEST_LOCK.lock();
        let enumerator = ensure_enumerator();
        reset_enumerator(&enumerator); // enumeration_complete = false

        let enforcer = DiskEnforcer::new();
        let result = enforcer
            .check(r"E:\secret.docx", &write_action(r"E:\secret.docx"))
            .expect("fail-closed: write must block when not ready");
        assert_eq!(result.decision, Decision::DENY);
        assert_eq!(result.disk.drive_letter, Some('E'));
        // Placeholder identity has empty instance_id and model.
        assert!(result.disk.instance_id.is_empty());
        assert!(result.notify, "first call -> notify must be true");
    }

    // ---------- D-07 step 2: not-tracked drive letter -> pass through ----------
    #[test]
    fn test_path_not_in_drive_letter_map_passes() {
        let _guard = DISK_TEST_LOCK.lock();
        let enumerator = ensure_enumerator();
        reset_enumerator(&enumerator);
        // Seed E only; enforcer is asked about Z.
        let e_disk = make_disk("ID-E", Some('E'), Some("SN-E"));
        seed_enumerator(
            &enumerator,
            &[('E', e_disk.clone())],
            &[("ID-E".into(), e_disk)],
        );

        let enforcer = DiskEnforcer::new();
        assert_eq!(
            enforcer.check(r"Z:\file.txt", &write_action(r"Z:\file.txt")),
            None
        );
    }

    // ---------- D-07 step 3: unregistered disk -> block ----------
    #[test]
    fn test_unregistered_disk_blocked_on_create_write_move() {
        let _guard = DISK_TEST_LOCK.lock();
        let enumerator = ensure_enumerator();
        reset_enumerator(&enumerator);
        // E is in drive_letter_map but instance_id_map is empty -- unregistered.
        let live = make_disk("ID-LIVE", Some('E'), Some("SN-LIVE"));
        seed_enumerator(&enumerator, &[('E', live.clone())], &[]);

        let enforcer = DiskEnforcer::new();

        for action in [
            create_action(r"E:\new.txt"),
            write_action(r"E:\file.txt"),
            move_action(r"E:\a.txt", r"E:\b.txt"),
        ] {
            let result = enforcer
                .check(r"E:\file.txt", &action)
                .unwrap_or_else(|| panic!("unregistered disk must block {action:?}"));
            assert_eq!(result.decision, Decision::DENY);
            assert_eq!(result.disk.instance_id, "ID-LIVE");
            assert_eq!(result.disk.drive_letter, Some('E'));
        }
    }

    // ---------- D-07 step 4: serial mismatch (physical-swap) -> block ----------
    #[test]
    fn test_serial_mismatch_blocked() {
        let _guard = DISK_TEST_LOCK.lock();
        let enumerator = ensure_enumerator();
        reset_enumerator(&enumerator);
        // Same instance_id but different serial -- physical swap.
        let registered = make_disk("ID-SHARED", Some('E'), Some("SN-REGISTERED"));
        let live = make_disk("ID-SHARED", Some('E'), Some("SN-DIFFERENT"));
        seed_enumerator(
            &enumerator,
            &[('E', live.clone())],
            &[("ID-SHARED".into(), registered)],
        );

        let enforcer = DiskEnforcer::new();
        let result = enforcer
            .check(r"E:\file.txt", &write_action(r"E:\file.txt"))
            .expect("serial mismatch must block");
        assert_eq!(result.decision, Decision::DENY);
        // Live disk identity is the one carried in the result (D-16).
        assert_eq!(result.disk.serial, Some("SN-DIFFERENT".to_string()));
    }

    // ---------- D-07 step 5: allowlisted, serials match -> pass through ----------
    #[test]
    fn test_allowlisted_disk_passes() {
        let _guard = DISK_TEST_LOCK.lock();
        let enumerator = ensure_enumerator();
        reset_enumerator(&enumerator);
        let registered = make_disk("ID-MATCH", Some('E'), Some("SN-MATCH"));
        let live = registered.clone();
        seed_enumerator(
            &enumerator,
            &[('E', live)],
            &[("ID-MATCH".into(), registered)],
        );

        let enforcer = DiskEnforcer::new();
        assert_eq!(
            enforcer.check(r"E:\file.txt", &write_action(r"E:\file.txt")),
            None
        );
        // Both serials None also passes (no mismatch when either side missing).
        reset_enumerator(&enumerator);
        let registered_no_serial = make_disk("ID-NS", Some('E'), None);
        let live_no_serial = make_disk("ID-NS", Some('E'), None);
        seed_enumerator(
            &enumerator,
            &[('E', live_no_serial)],
            &[("ID-NS".into(), registered_no_serial)],
        );
        assert_eq!(
            enforcer.check(r"E:\file.txt", &write_action(r"E:\file.txt")),
            None
        );
    }

    // ---------- D-02: 30-second cooldown per drive letter ----------
    #[test]
    fn test_should_notify_cooldown() {
        let _guard = DISK_TEST_LOCK.lock();
        let enumerator = ensure_enumerator();
        reset_enumerator(&enumerator);
        // Force a block path so should_notify is exercised by check.
        let live = make_disk("ID-CD", Some('F'), Some("SN-CD"));
        seed_enumerator(&enumerator, &[('F', live)], &[]);

        let enforcer = DiskEnforcer::new();
        let first = enforcer
            .check(r"F:\1.txt", &write_action(r"F:\1.txt"))
            .expect("first block fires");
        assert!(first.notify, "first block on drive must notify");

        let second = enforcer
            .check(r"F:\2.txt", &write_action(r"F:\2.txt"))
            .expect("second block also fires");
        assert!(!second.notify, "second block within 30s must NOT notify");

        // Different drive letter has its own cooldown -- still notifies.
        reset_enumerator(&enumerator);
        let live_g = make_disk("ID-G", Some('G'), None);
        seed_enumerator(&enumerator, &[('G', live_g)], &[]);
        let g_first = enforcer
            .check(r"G:\1.txt", &write_action(r"G:\1.txt"))
            .expect("first block on G fires");
        assert!(g_first.notify, "different drive letter must notify");
    }

    // ---------- UNC path passes through ----------
    #[test]
    fn test_unc_path_returns_none() {
        let _guard = DISK_TEST_LOCK.lock();
        let enumerator = ensure_enumerator();
        reset_enumerator(&enumerator);
        *enumerator.enumeration_complete.write() = true; // ready, but UNC has no letter

        let enforcer = DiskEnforcer::new();
        assert_eq!(
            enforcer.check(
                r"\\server\share\file.txt",
                &write_action(r"\\server\share\file.txt")
            ),
            None
        );
    }

    // ---------- Helper sanity: drive_letter_from_path ----------
    #[test]
    fn test_drive_letter_helpers() {
        assert_eq!(drive_letter_from_path(r"E:\file.txt"), Some('E'));
        assert_eq!(drive_letter_from_path(r"e:\file.txt"), Some('E'));
        assert_eq!(drive_letter_from_path(r"\\server\share"), None);
        assert_eq!(drive_letter_from_path("/usr/local"), None);
        assert_eq!(drive_letter_from_path(""), None);
    }
}
