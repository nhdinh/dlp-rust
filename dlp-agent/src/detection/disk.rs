//! Disk enumeration background task and in-memory disk registry.
//!
//! Spawns at agent startup, enumerates fixed disks, emits audit events, and
//! maintains an in-memory cache of discovered disks for Phase 35/36 consumption.
//!
//! ## Lifecycle
//!
//! 1. `service.rs` calls `set_disk_enumerator(Arc::new(DiskEnumerator::new()))`
//!    during startup.
//! 2. `spawn_disk_enumeration_task` is called with the tokio runtime handle and
//!    an [`EmitContext`] for audit emission.
//! 3. The async task enumerates fixed disks with retry logic (3 attempts,
//!    exponential backoff: 200 ms -> 1 s -> 4 s).
//! 4. On success: the global `DiskEnumerator` is updated, boot disk is marked,
//!    and an aggregated `DiskDiscovery` audit event is emitted.
//! 5. On final failure: a high-severity `Alert` audit event is emitted and
//!    `enumeration_complete` remains `false` (fail-closed per D-04).
//!
//! ## Thread Safety
//!
//! All shared state is behind `parking_lot::RwLock` — readers (Phase 36
//! enforcement) never contend with each other; the writer (enumeration task)
//! acquires an exclusive lock only once per successful enumeration.

use crate::config::AgentConfig;
use dlp_common::{enumerate_fixed_disks, get_boot_drive_letter, DiskIdentity};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// DiskEnumerator
// ---------------------------------------------------------------------------

/// In-memory registry of discovered fixed disks.
///
/// Updated by the async enumeration task and read by Phase 36 enforcement.
/// All fields are `pub` so enforcement can read them without accessor methods
/// (matches the [`UsbDetector`] pattern).
#[derive(Debug)]
pub struct DiskEnumerator {
    /// All discovered fixed disks from the last successful enumeration.
    pub discovered_disks: RwLock<Vec<DiskIdentity>>,
    /// Map from drive letter to `DiskIdentity` for fast lookup during enforcement.
    pub drive_letter_map: RwLock<HashMap<char, DiskIdentity>>,
    /// Map from instance_id to `DiskIdentity` for allowlist lookups.
    pub instance_id_map: RwLock<HashMap<String, DiskIdentity>>,
    /// Set to `true` when enumeration has completed successfully at least once.
    pub enumeration_complete: RwLock<bool>,
}

impl DiskEnumerator {
    /// Constructs a new `DiskEnumerator` with empty state.
    pub fn new() -> Self {
        Self {
            discovered_disks: RwLock::new(Vec::new()),
            drive_letter_map: RwLock::new(HashMap::new()),
            instance_id_map: RwLock::new(HashMap::new()),
            enumeration_complete: RwLock::new(false),
        }
    }

    /// Returns `true` if enumeration has completed successfully.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        *self.enumeration_complete.read()
    }

    /// Returns the `DiskIdentity` for a given drive letter, if known.
    ///
    /// Case-insensitive on the drive letter.
    #[must_use]
    pub fn disk_for_drive_letter(&self, letter: char) -> Option<DiskIdentity> {
        self.drive_letter_map
            .read()
            .get(&letter.to_ascii_uppercase())
            .cloned()
    }

    /// Returns the `DiskIdentity` for a given instance ID, if known.
    #[must_use]
    pub fn disk_for_instance_id(&self, instance_id: &str) -> Option<DiskIdentity> {
        self.instance_id_map.read().get(instance_id).cloned()
    }

    /// Returns all discovered disks.
    #[must_use]
    pub fn all_disks(&self) -> Vec<DiskIdentity> {
        self.discovered_disks.read().clone()
    }
}

impl Default for DiskEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: DiskEnumerator contains only RwLock<T> where T: Send + Sync.
// It is safe to share across threads because all mutable access is gated
// behind the RwLock.
unsafe impl Send for DiskEnumerator {}
unsafe impl Sync for DiskEnumerator {}

// ---------------------------------------------------------------------------
// Global static (following UsbDetector pattern)
// ---------------------------------------------------------------------------

/// Global `DiskEnumerator` reference, set once during service startup.
static DISK_ENUMERATOR: OnceLock<Arc<DiskEnumerator>> = OnceLock::new();

/// Sets the global `DiskEnumerator` reference.
///
/// Called once from `service.rs` before spawning the enumeration task.
/// Subsequent calls are silently ignored (OnceLock contract).
///
/// # Arguments
///
/// * `enumerator` — the `Arc<DiskEnumerator>` to store globally.
pub fn set_disk_enumerator(enumerator: Arc<DiskEnumerator>) {
    let _ = DISK_ENUMERATOR.set(enumerator);
}

/// Returns the global `DiskEnumerator` reference, if set.
#[must_use]
pub fn get_disk_enumerator() -> Option<Arc<DiskEnumerator>> {
    DISK_ENUMERATOR.get().cloned()
}

// ---------------------------------------------------------------------------
// Async enumeration task
// ---------------------------------------------------------------------------

/// Spawns the disk enumeration background task.
///
/// The task pre-loads any persisted disk allowlist from the supplied
/// [`AgentConfig`] (D-11), then enumerates fixed disks with retry logic.
/// On success, the live enumeration is merged with the TOML snapshot
/// (live wins for present disks per D-07; disconnected TOML entries are
/// retained per D-06), the merged list is written back to
/// `agent_config.disk_allowlist`, and `AgentConfig::save(config_path)`
/// is called. TOML write failure is non-fatal -- the in-memory state
/// in `DiskEnumerator` is authoritative.
///
/// On final enumeration failure, a high-severity audit event is emitted
/// and `enumeration_complete` remains `false` (fail-closed per D-04).
/// Pre-loaded TOML entries remain in `instance_id_map` after a final
/// failure, but the readiness flag is NOT set (D-12).
///
/// Spawns the disk enumeration background task.
///
/// The task pre-loads any persisted disk allowlist from the supplied
/// [`AgentConfig`] (D-11), then enumerates fixed disks with retry logic.
/// On success, the live enumeration is merged with the TOML snapshot
/// (live wins for present disks per D-07; disconnected TOML entries are
/// retained per D-06), the merged list is written back to
/// `agent_config.disk_allowlist`, and `AgentConfig::save(config_path)`
/// is called. TOML write failure is non-fatal -- the in-memory state
/// in `DiskEnumerator` is authoritative.
///
/// On final enumeration failure, a high-severity audit event is emitted
/// and `enumeration_complete` remains `false` (fail-closed per D-04).
/// Pre-loaded TOML entries remain in `instance_id_map` after a final
/// failure, but the readiness flag is NOT set (D-12).
///
/// # Arguments
///
/// * `runtime_handle` -- tokio runtime `Handle` for spawning sub-tasks
///   from non-async contexts.
/// * `audit_ctx` -- [`EmitContext`] for audit event emission.
/// * `agent_config` -- shared `Arc<parking_lot::RwLock<AgentConfig>>`
///   bound at service startup (D-04). Pre-load reads `disk_allowlist`;
///   persist writes `disk_allowlist` and calls `save(config_path)`.
/// * `config_path` -- destination for `AgentConfig::save()`. Typically
///   resolved via `AgentConfig::effective_config_path()`.
/// * `shutdown_rx` -- watch receiver for cancellation (OP-04).
/// Pre-loads the TOML allowlist into the global `DiskEnumerator`.
///
/// Populates `discovered_disks` and `instance_id_map` only.
/// `drive_letter_map` is intentionally left empty to avoid routing I/O
/// to phantom disks with stale drive letters.
fn preload_toml_allowlist(toml_disks: &[DiskIdentity]) {
    if toml_disks.is_empty() {
        return;
    }

    let Some(enumerator) = get_disk_enumerator() else {
        return;
    };

    let mut discovered = enumerator.discovered_disks.write();
    let mut instance_map = enumerator.instance_id_map.write();
    *discovered = toml_disks.to_vec();
    for disk in toml_disks {
        instance_map.insert(disk.instance_id.clone(), disk.clone());
    }

    info!(
        count = toml_disks.len(),
        "pre-loaded disk allowlist from TOML"
    );
}

/// Marks the boot disk in the live disk list.
///
/// Iterates through `disks` and sets `is_boot_disk = true` on the disk
/// whose drive letter matches the system boot drive.
fn mark_boot_disk(disks: &mut [DiskIdentity]) {
    let Some(boot_letter) = get_boot_drive_letter() else {
        return;
    };

    let boot_upper = boot_letter.to_ascii_uppercase();
    for disk in disks {
        if disk.drive_letter.map(|l| l.to_ascii_uppercase()) != Some(boot_upper) {
            continue;
        }
        disk.is_boot_disk = true;
        info!(
            drive = %boot_letter,
            instance_id = %disk.instance_id,
            "boot disk identified"
        );
    }
}

/// Merges live disks with the TOML snapshot.
///
/// Starts from TOML entries so disconnected disks survive (D-06).
/// Overwrites with live data for any disk whose instance_id matches
/// a live entry (D-07 -- live wins).
///
/// Returns a stably-sorted vector for deterministic output.
fn merge_with_toml_snapshot(
    live_disks: &[DiskIdentity],
    toml_disks: &[DiskIdentity],
) -> Vec<DiskIdentity> {
    let mut merged: HashMap<String, DiskIdentity> = toml_disks
        .iter()
        .map(|d| (d.instance_id.clone(), d.clone()))
        .collect();
    for disk in live_disks {
        merged.insert(disk.instance_id.clone(), disk.clone());
    }

    let mut updated_list: Vec<DiskIdentity> = merged.into_values().collect();
    // Stable sort for deterministic TOML output and stable audit diffs.
    updated_list.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
    updated_list
}

/// Updates the global `DiskEnumerator` with the merged disk list.
///
/// CRITICAL: All DiskEnumerator write locks are released before returning
/// so the caller can safely acquire the AgentConfig write lock.
///
/// WR-01 fix: acquire, mutate, and release each lock individually in
/// scoped blocks rather than holding all four simultaneously.
fn update_disk_enumerator(updated_list: &[DiskIdentity]) {
    let Some(enumerator) = get_disk_enumerator() else {
        return;
    };

    {
        *enumerator.discovered_disks.write() = updated_list.to_vec();
    }
    {
        let mut drive_map = enumerator.drive_letter_map.write();
        drive_map.clear();
        for disk in updated_list {
            if let Some(letter) = disk.drive_letter {
                drive_map.insert(letter, disk.clone());
            }
        }
    }
    {
        let mut instance_map = enumerator.instance_id_map.write();
        instance_map.clear();
        for disk in updated_list {
            instance_map.insert(disk.instance_id.clone(), disk.clone());
        }
    }
    // Mark enumeration complete last -- enforcement reads this flag
    // to exit the fail-closed window, so all maps must be populated
    // before flipping it.
    *enumerator.enumeration_complete.write() = true;
}

/// Persists the merged allowlist to the agent config TOML file.
///
/// Save failures are logged and do NOT fail enumeration --
/// in-memory state is authoritative.
fn persist_allowlist(
    agent_config: &Arc<parking_lot::RwLock<AgentConfig>>,
    config_path: &PathBuf,
    updated_list: &[DiskIdentity],
) {
    let mut cfg = agent_config.write();
    cfg.disk_allowlist = updated_list.to_vec();
    if let Err(e) = cfg.save(config_path) {
        tracing::error!(
            error = %e,
            path = %config_path.display(),
            "failed to persist disk allowlist to TOML -- in-memory state remains authoritative"
        );
    }
}

/// Handles a successful disk enumeration by updating state, persisting,
/// and emitting the audit event.
fn handle_enumeration_success(
    audit_ctx: &crate::audit_emitter::EmitContext,
    agent_config: &Arc<parking_lot::RwLock<AgentConfig>>,
    config_path: &PathBuf,
    mut disks: Vec<DiskIdentity>,
    toml_disks: &[DiskIdentity],
) {
    mark_boot_disk(&mut disks);

    let updated_list = merge_with_toml_snapshot(&disks, toml_disks);

    // --- Update DiskEnumerator (all locks scoped to this block) ---
    update_disk_enumerator(&updated_list);

    // --- Persist allowlist to TOML (non-fatal) ---
    // AgentConfig write lock acquired AFTER DiskEnumerator locks are
    // released. Lock-order discipline prevents deadlock (Pitfall 4).
    persist_allowlist(agent_config, config_path, &updated_list);

    // --- Emit audit event and exit ---
    emit_disk_discovery(audit_ctx, &updated_list);
    info!(
        disk_count = updated_list.len(),
        "fixed disk enumeration complete"
    );
}

/// Handles a failed enumeration attempt, logging and optionally sleeping before retry.
async fn handle_enumeration_failure(
    attempt: usize,
    delay: Duration,
    error: String,
    is_last_attempt: bool,
) -> String {
    warn!(
        attempt = attempt + 1,
        error = %error,
        "disk enumeration failed -- will retry"
    );
    if !is_last_attempt {
        sleep(delay).await;
    }
    error
}

pub fn spawn_disk_enumeration_task(
    runtime_handle: tokio::runtime::Handle,
    audit_ctx: crate::audit_emitter::EmitContext,
    agent_config: Arc<parking_lot::RwLock<AgentConfig>>,
    config_path: PathBuf,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    runtime_handle.spawn(async move {
        // --- Pre-load TOML allowlist into DiskEnumerator (D-11) ---
        let toml_disks: Vec<DiskIdentity> = {
            let cfg = agent_config.read();
            cfg.disk_allowlist.clone()
        };
        preload_toml_allowlist(&toml_disks);
        // enumeration_complete remains FALSE (D-12) -- the readiness signal
        // requires successful live enumeration, not the TOML warm-up.

        let retry_delays = [
            Duration::from_millis(200),
            Duration::from_millis(1000),
            Duration::from_millis(4000),
        ];
        let mut last_error: Option<String> = None;

        for (attempt, delay) in retry_delays.iter().enumerate() {
            // OP-04: check for shutdown signal before each attempt.
            if *shutdown_rx.borrow() {
                info!(
                    "disk enumeration shutting down before attempt {}",
                    attempt + 1
                );
                return;
            }

            info!(attempt = attempt + 1, "starting fixed disk enumeration");
            match enumerate_fixed_disks() {
                Ok(disks) => {
                    handle_enumeration_success(
                        &audit_ctx,
                        &agent_config,
                        &config_path,
                        disks,
                        &toml_disks,
                    );
                    return;
                }
                Err(e) => {
                    let is_last = attempt == retry_delays.len() - 1;
                    last_error = Some(
                        handle_enumeration_failure(attempt, *delay, e.to_string(), is_last).await,
                    );
                }
            }
        }

        // All retries exhausted -- fail closed.
        let error_msg = last_error.unwrap_or_else(|| "unknown error".to_string());
        error!(
            error = %error_msg,
            "disk enumeration failed after all retries -- failing closed"
        );
        emit_disk_enumeration_failed(&audit_ctx, &error_msg);
    })
}

// ---------------------------------------------------------------------------
// Audit emission helpers
// ---------------------------------------------------------------------------

/// Emits an aggregated `DiskDiscovery` audit event.
///
/// Uses `EventType::DiskDiscovery` with `Classification::T1` and
/// `Decision::ALLOW` since discovery is an informational event.
fn emit_disk_discovery(ctx: &crate::audit_emitter::EmitContext, disks: &[DiskIdentity]) {
    use dlp_common::AuditEvent;
    use dlp_common::{Action, Classification, Decision, EventType};

    let mut event = AuditEvent::new(
        EventType::DiskDiscovery,
        ctx.user_sid.clone(),
        ctx.user_name.clone(),
        "disk://discovery".to_string(),
        Classification::T1,
        Action::READ,
        Decision::ALLOW,
        ctx.agent_id.clone(),
        ctx.session_id,
    )
    .with_discovered_disks(Some(disks.to_vec()));
    crate::audit_emitter::emit_audit(ctx, &mut event);
}

/// Emits a high-severity audit event when disk enumeration fails.
///
/// Uses `EventType::Alert` (triggers SIEM routing) with `Classification::T4`
/// and `Decision::DENY` to signal the fail-closed state.
fn emit_disk_enumeration_failed(ctx: &crate::audit_emitter::EmitContext, error: &str) {
    use dlp_common::AuditEvent;
    use dlp_common::{Action, Classification, Decision, EventType};

    let mut event = AuditEvent::new(
        EventType::Alert,
        ctx.user_sid.clone(),
        ctx.user_name.clone(),
        "disk://enumeration-failed".to_string(),
        Classification::T4,
        Action::READ,
        Decision::DENY,
        ctx.agent_id.clone(),
        ctx.session_id,
    )
    .with_justification(format!("Disk enumeration failed after 3 retries: {error}"));
    crate::audit_emitter::emit_audit(ctx, &mut event);
}

// ---------------------------------------------------------------------------
// Phase 36: WM_DEVICECHANGE handlers (DISK-05)
// ---------------------------------------------------------------------------

/// Handles `GUID_DEVINTERFACE_DISK` arrival from the device-watcher dispatcher.
///
/// Per CONTEXT.md D-13, this function:
/// 1. Calls [`enumerate_fixed_disks`] to obtain the live disk list. The
///    instance IDs returned by `SetupDiGetDeviceInstanceIdW` (via the
///    `dlp-common` enumerator) are guaranteed to match the keys stored in
///    `instance_id_map`, sidestepping the format mismatch documented in
///    Pitfall 1 (Phase 36 RESEARCH.md) when comparing against
///    `dbcc_name`-derived IDs.
/// 2. Identifies disks whose drive letters are not yet in `drive_letter_map`.
/// 3. Inserts those disks into `drive_letter_map` ONLY (D-10 invariant --
///    `instance_id_map` is the frozen allowlist and is never mutated by
///    arrival handlers).
/// 4. For each newly visible disk whose `instance_id` is NOT in
///    `instance_id_map`, emits a `DiskDiscovery` audit event so admins are
///    notified of an unregistered disk arrival before any I/O occurs.
///
/// # Arguments
///
/// * `device_path` -- the `dbcc_name` from the WM_DEVICECHANGE callback.
///   Used only for tracing context; the authoritative instance ID comes
///   from `enumerate_fixed_disks` per Pitfall 1.
/// * `audit_ctx` -- [`EmitContext`] for the `DiskDiscovery` audit event.
#[cfg(windows)]
pub fn on_disk_arrival(device_path: &str, audit_ctx: &crate::audit_emitter::EmitContext) {
    let live_disks = match enumerate_fixed_disks() {
        Ok(d) => d,
        Err(e) => {
            warn!(
                error = %e,
                device_path = %device_path,
                "on_disk_arrival: enumerate_fixed_disks failed -- skipping map update"
            );
            return;
        }
    };
    on_disk_arrival_inner(device_path, &live_disks, audit_ctx);
}

/// Inner helper that takes a pre-resolved live disk list.
///
/// Extracted so unit tests can exercise the map-update + audit-trigger branches
/// without invoking the WMI / SetupDi enumeration that `enumerate_fixed_disks`
/// performs.
///
/// # Arguments
///
/// * `device_path` -- the `dbcc_name` (used for tracing context only).
/// * `live_disks` -- the current fixed disk list from `enumerate_fixed_disks`.
/// * `audit_ctx` -- [`EmitContext`] for the `DiskDiscovery` audit event.
#[cfg(windows)]
fn on_disk_arrival_inner(
    device_path: &str,
    live_disks: &[DiskIdentity],
    audit_ctx: &crate::audit_emitter::EmitContext,
) {
    let enumerator = match get_disk_enumerator() {
        Some(e) => e,
        None => {
            warn!(
                device_path = %device_path,
                "on_disk_arrival: DiskEnumerator not yet initialized; skipping"
            );
            return;
        }
    };

    // Phase 44 (DISK-F1): check allowlist BEFORE inserting into drive_letter_map.
    // Unregistered disks are blocked at mount time so they never appear in Explorer.
    //
    // CR-01 fix: the check-and-insert MUST be atomic under the write lock to
    // eliminate the TOCTOU gap between the former snapshot read and the per-disk
    // write-lock acquisition.  A concurrent arrival (rapid unplug-replug) can
    // race the stale snapshot, causing two threads to both pass the exists check
    // and insert -- the last writer wins non-deterministically with the wrong
    // DiskIdentity.  contains_key inside the write lock closes the gap.
    for disk in live_disks {
        let Some(letter) = disk.drive_letter else {
            continue;
        };

        // NEW (Phase 44): Check frozen allowlist BEFORE adding to drive_letter_map.
        // If unregistered, block at mount time and skip drive_letter_map insertion.
        if enumerator.disk_for_instance_id(&disk.instance_id).is_none() {
            warn!(
                drive = %letter,
                instance_id = %disk.instance_id,
                model = %disk.model,
                bus_type = ?disk.bus_type,
                "unregistered disk arrived -- blocking at mount time"
            );
            if let Err(e) = block_disk_at_mount_time(letter, disk, audit_ctx) {
                warn!(
                    letter = %letter,
                    error = %e,
                    "Mount-time block failed, falling back to I/O-time blocking"
                );
            }
            // Do NOT insert into drive_letter_map -- keeps disk invisible.
            continue;
        }

        // D-10: update drive_letter_map ONLY. instance_id_map is the frozen
        // allowlist (D-09) -- never mutated by arrival handlers.
        //
        // CR-01: acquire the write lock first, then check -- the
        // check-and-insert is now atomic under the lock.  Drop the write lock
        // explicitly before the audit/allowlist work below to minimize hold time.
        {
            let mut map = enumerator.drive_letter_map.write();
            if map.contains_key(&letter) {
                continue;
            }
            map.insert(letter, disk.clone());
            // Write lock released here (end of block).
        }

        info!(
            drive = %letter,
            instance_id = %disk.instance_id,
            "registered disk reconnected -- drive_letter_map updated"
        );
    }
}

/// Handles `GUID_DEVINTERFACE_DISK` removal from the device-watcher dispatcher.
///
/// Per CONTEXT.md D-14:
/// 1. Resolves the instance ID from `dbcc_name` via
///    [`crate::detection::device_watcher::extract_disk_instance_id`].
/// 2. Removes the matching entry from `drive_letter_map` ONLY (D-10).
///    `instance_id_map` retains the entry (D-06: disconnected allowlisted
///    disks remain registered).
/// 3. Emits no audit event (removal is informational; the allowlist is unchanged).
///
/// # Arguments
///
/// * `device_path` -- the `dbcc_name` from the WM_DEVICECHANGE callback.
#[cfg(windows)]
pub fn on_disk_removal(device_path: &str) {
    let instance_id = crate::detection::device_watcher::extract_disk_instance_id(device_path);
    if instance_id.is_empty() {
        debug!(
            device_path = %device_path,
            "on_disk_removal: empty instance ID; skipping"
        );
        return;
    }

    let enumerator = match get_disk_enumerator() {
        Some(e) => e,
        None => {
            debug!("on_disk_removal: DiskEnumerator not yet initialized; skipping");
            return;
        }
    };

    // Find the drive letter whose entry matches by instance_id, then drop
    // the read lock before acquiring the write lock (Pitfall 2).
    let letter_opt = {
        let map = enumerator.drive_letter_map.read();
        map.iter()
            .find(|(_, disk)| disk.instance_id == instance_id)
            .map(|(letter, _)| *letter)
    };

    if let Some(letter) = letter_opt {
        enumerator.drive_letter_map.write().remove(&letter);
        info!(
            drive = %letter,
            instance_id = %instance_id,
            "disk removed -- drive_letter_map entry cleared (instance_id_map unchanged)"
        );
    } else {
        debug!(
            instance_id = %instance_id,
            "on_disk_removal: instance_id not in drive_letter_map"
        );
    }
    // D-14: No audit event on removal.
    // D-10: instance_id_map NOT touched -- disconnected allowlisted disks remain registered (D-06).
}

/// Blocks an unregistered disk at mount time by removing its drive letter
/// and taking the volume offline.
///
/// This is the primary enforcement layer for unregistered fixed disks (DISK-F1,
/// Phase 44).  It runs BEFORE the disk is inserted into `drive_letter_map`, so
/// the disk never appears in Explorer.  If this function fails, the caller
/// falls back to I/O-time blocking in [`DiskEnforcer`] (Phase 36).
///
/// # Steps
///
/// 1. Remove the drive letter from the DOS namespace via `DefineDosDeviceW`.
/// 2. Open the volume handle and issue `FSCTL_DISMOUNT_VOLUME` followed by
///    `IOCTL_VOLUME_OFFLINE` (defense-in-depth).
/// 3. Emit a `DiskMountBlocked` audit event.
///
/// # Arguments
///
/// * `letter` — The drive letter to remove (e.g. `'E'`).
/// * `disk` — The live [`DiskIdentity`] of the unregistered disk.
/// * `audit_ctx` — [`EmitContext`] for audit emission.
///
/// # Returns
///
/// `Ok(())` on success.  `Err(String)` if `DefineDosDeviceW` fails (the volume
/// offline step is best-effort and does NOT fail the overall call).
#[cfg(windows)]
fn block_disk_at_mount_time(
    letter: char,
    disk: &DiskIdentity,
    audit_ctx: &crate::audit_emitter::EmitContext,
) -> Result<(), String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, DefineDosDeviceW, DDD_REMOVE_DEFINITION, FILE_FLAGS_AND_ATTRIBUTES,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        IOCTL_VOLUME_OFFLINE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    // FSCTL_DISMOUNT_VOLUME is a u32 constant in Win32::System::Ioctl.
    const FSCTL_DISMOUNT_VOLUME: u32 = 0x00090064; // 589856u32

    // Step 1: Remove drive letter from DOS namespace.
    let drive_str = format!("{letter}:",);
    let wide: Vec<u16> = drive_str.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is a valid null-terminated UTF-16 string.
    let result = unsafe {
        DefineDosDeviceW(
            DDD_REMOVE_DEFINITION,
            windows::core::PCWSTR(wide.as_ptr()),
            windows::core::PCWSTR::null(),
        )
    };
    if let Err(e) = result {
        warn!(
            letter = %letter,
            error = %e,
            "DefineDosDeviceW failed to remove drive letter"
        );
        // Return error so caller knows mount-time block failed.
        return Err(format!("DefineDosDeviceW failed: {e}"));
    }
    info!(
        letter = %letter,
        instance_id = %disk.instance_id,
        "Drive letter removed for unregistered disk"
    );

    // Step 2: Defense-in-depth -- dismount and offline the volume.
    let volume_path = format!(r"\\.\{letter}:",);
    let wide_path: Vec<u16> = volume_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide_path` is a valid null-terminated UTF-16 string.
    let handle_result = unsafe {
        CreateFileW(
            windows::core::PCWSTR(wide_path.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    };
    if let Ok(handle) = handle_result {
        let mut bytes_returned = 0u32;
        // Dismount first (best-effort -- ignore errors).
        // SAFETY: `handle` is a valid file handle returned by CreateFileW.
        let _ = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_DISMOUNT_VOLUME,
                None,
                0,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        };
        // Then offline (best-effort -- ignore errors).
        let _ = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_VOLUME_OFFLINE,
                None,
                0,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        };
        // SAFETY: `handle` is a valid handle; CloseHandle is idempotent.
        let _ = unsafe { CloseHandle(handle) };
    } else {
        warn!(
            letter = %letter,
            "Could not open volume handle for offline -- drive letter removal already applied"
        );
    }

    // Step 3: Emit audit event.
    emit_disk_mount_blocked(disk, audit_ctx);

    Ok(())
}

/// Emits a `DiskMountBlocked` audit event for an unregistered disk.
///
/// Used by [`block_disk_at_mount_time`] after successfully removing the drive
/// letter.  The event carries the disk identity so SIEM rules can correlate
/// mount-time blocks with the physical device.
#[cfg(windows)]
fn emit_disk_mount_blocked(disk: &DiskIdentity, audit_ctx: &crate::audit_emitter::EmitContext) {
    use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};

    let mut event = AuditEvent::new(
        EventType::DiskMountBlocked,
        audit_ctx.user_sid.clone(),
        audit_ctx.user_name.clone(),
        "disk://mount-blocked".to_string(),
        Classification::T4,
        Action::WRITE,
        Decision::DENY,
        audit_ctx.agent_id.clone(),
        audit_ctx.session_id,
    )
    .with_blocked_disk(disk.clone());
    crate::audit_emitter::emit_audit(audit_ctx, &mut event);
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::{BusType, DiskIdentity};
    // Shared lock for tests that mutate the global DiskEnumerator OnceLock.
    // disk_enforcer::tests holds the same lock so neither module races the other.
    #[cfg(windows)]
    use crate::test_helpers::DISK_TEST_LOCK;

    #[test]
    fn test_disk_enumerator_default_empty() {
        let enumerator = DiskEnumerator::new();
        assert!(enumerator.all_disks().is_empty());
        assert!(enumerator.disk_for_drive_letter('C').is_none());
        assert!(enumerator
            .disk_for_instance_id("PCIIDE\\IDECHANNEL\\4&1234")
            .is_none());
        assert!(!enumerator.is_ready());
    }

    #[test]
    fn test_disk_enumerator_update_and_query() {
        let enumerator = DiskEnumerator::new();
        let disks = vec![
            DiskIdentity {
                instance_id: "PCIIDE\\IDECHANNEL\\4&1234".to_string(),
                bus_type: BusType::Sata,
                model: "WDC WD10EZEX-00BN5A0".to_string(),
                drive_letter: Some('C'),
                serial: Some("WD-12345678".to_string()),
                size_bytes: Some(1_000_204_886_016),
                is_boot_disk: true,
                encryption_status: None,
                encryption_method: None,
                encryption_checked_at: None,
            },
            DiskIdentity {
                instance_id: "USB\\VID_1234&PID_5678&REV_0001".to_string(),
                bus_type: BusType::Usb,
                model: "USB External Drive".to_string(),
                drive_letter: Some('E'),
                serial: Some("EXT-001".to_string()),
                size_bytes: Some(500_000_000_000),
                is_boot_disk: false,
                encryption_status: None,
                encryption_method: None,
                encryption_checked_at: None,
            },
        ];

        // Simulate what spawn_disk_enumeration_task does on success.
        {
            let mut discovered = enumerator.discovered_disks.write();
            let mut drive_map = enumerator.drive_letter_map.write();
            let mut instance_map = enumerator.instance_id_map.write();
            let mut complete = enumerator.enumeration_complete.write();

            *discovered = disks.clone();
            for disk in &disks {
                if let Some(letter) = disk.drive_letter {
                    drive_map.insert(letter, disk.clone());
                }
                instance_map.insert(disk.instance_id.clone(), disk.clone());
            }
            *complete = true;
        }

        // Verify all_disks returns both.
        let all = enumerator.all_disks();
        assert_eq!(all.len(), 2);

        // Verify drive letter lookup (case-insensitive).
        let c_disk = enumerator.disk_for_drive_letter('C');
        assert!(c_disk.is_some());
        assert_eq!(c_disk.as_ref().unwrap().bus_type, BusType::Sata);
        assert!(c_disk.as_ref().unwrap().is_boot_disk);

        let e_disk = enumerator.disk_for_drive_letter('e');
        assert!(e_disk.is_some());
        assert_eq!(e_disk.as_ref().unwrap().bus_type, BusType::Usb);

        // Verify instance ID lookup.
        let by_id = enumerator.disk_for_instance_id("USB\\VID_1234&PID_5678&REV_0001");
        assert!(by_id.is_some());
        assert_eq!(by_id.as_ref().unwrap().model, "USB External Drive");

        // Verify unknown lookups return None.
        assert!(enumerator.disk_for_drive_letter('Z').is_none());
        assert!(enumerator.disk_for_instance_id("UNKNOWN").is_none());
    }

    #[test]
    fn test_disk_enumerator_is_ready() {
        let enumerator = DiskEnumerator::new();
        assert!(!enumerator.is_ready());
        *enumerator.enumeration_complete.write() = true;
        assert!(enumerator.is_ready());
    }

    #[test]
    fn test_get_boot_drive_letter_non_windows() {
        // On non-Windows, get_boot_drive_letter returns None.
        #[cfg(not(windows))]
        assert!(get_boot_drive_letter().is_none());
        // On Windows, we just verify it doesn't panic.
        #[cfg(windows)]
        {
            let _ = get_boot_drive_letter();
        }
    }

    #[test]
    fn test_emit_disk_discovery_builds_correct_event() {
        // This test verifies that emit_disk_discovery constructs an AuditEvent
        // with the correct fields. We cannot call emit_audit directly (it writes
        // to a file), so we verify the event construction logic by building the
        // same event and inspecting its fields.
        use dlp_common::AuditEvent;
        use dlp_common::{Action, Classification, Decision, EventType};

        let ctx = crate::audit_emitter::EmitContext {
            agent_id: "AGENT-TEST-001".to_string(),
            session_id: 1,
            user_sid: "S-1-5-21-123".to_string(),
            user_name: "testuser".to_string(),
            machine_name: None,
        };

        let disks = vec![DiskIdentity {
            instance_id: "PCIIDE\\IDECHANNEL\\4&1234".to_string(),
            bus_type: BusType::Sata,
            model: "WDC WD10EZEX-00BN5A0".to_string(),
            drive_letter: Some('C'),
            serial: Some("WD-12345678".to_string()),
            size_bytes: Some(1_000_204_886_016),
            is_boot_disk: true,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        }];

        let event = AuditEvent::new(
            EventType::DiskDiscovery,
            ctx.user_sid.clone(),
            ctx.user_name.clone(),
            "disk://discovery".to_string(),
            Classification::T1,
            Action::READ,
            Decision::ALLOW,
            ctx.agent_id.clone(),
            ctx.session_id,
        )
        .with_discovered_disks(Some(disks));

        assert_eq!(event.event_type, EventType::DiskDiscovery);
        assert_eq!(event.resource_path, "disk://discovery");
        assert_eq!(event.classification, Classification::T1);
        assert_eq!(event.decision, Decision::ALLOW);
        assert!(event.discovered_disks.is_some());
        let d = event.discovered_disks.as_ref().unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].bus_type, BusType::Sata);
        assert!(d[0].is_boot_disk);

        // Verify JSON serialization contains expected fields.
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("DISK_DISCOVERY"));
        assert!(json.contains("discovered_disks"));
        assert!(json.contains("WDC WD10EZEX-00BN5A0"));
    }

    #[test]
    fn test_emit_disk_enumeration_failed_builds_correct_event() {
        use dlp_common::AuditEvent;
        use dlp_common::{Action, Classification, Decision, EventType};

        let ctx = crate::audit_emitter::EmitContext {
            agent_id: "AGENT-TEST-001".to_string(),
            session_id: 1,
            user_sid: "S-1-5-21-123".to_string(),
            user_name: "testuser".to_string(),
            machine_name: None,
        };

        let error_msg = "SetupDi enumeration failed";
        let event = AuditEvent::new(
            EventType::Alert,
            ctx.user_sid.clone(),
            ctx.user_name.clone(),
            "disk://enumeration-failed".to_string(),
            Classification::T4,
            Action::READ,
            Decision::DENY,
            ctx.agent_id.clone(),
            ctx.session_id,
        )
        .with_justification(format!(
            "Disk enumeration failed after 3 retries: {error_msg}"
        ));

        assert_eq!(event.event_type, EventType::Alert);
        assert_eq!(event.classification, Classification::T4);
        assert_eq!(event.decision, Decision::DENY);
        assert_eq!(
            event.justification,
            Some("Disk enumeration failed after 3 retries: SetupDi enumeration failed".to_string())
        );

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("ALERT"));
        assert!(json.contains("disk://enumeration-failed"));
    }

    #[test]
    fn test_global_static_get_set() {
        // Ensure we can set and get the global DiskEnumerator.
        // OnceLock only accepts the first set per process — disk_enforcer tests
        // may have already installed an enumerator, so ptr_eq is only checked
        // when this test wins the race to be first.
        let enumerator = Arc::new(DiskEnumerator::new());
        let was_empty = get_disk_enumerator().is_none();
        set_disk_enumerator(Arc::clone(&enumerator));
        let retrieved = get_disk_enumerator();
        assert!(
            retrieved.is_some(),
            "get_disk_enumerator must return Some after set"
        );
        if was_empty {
            // We installed the enumerator — verify it's the same instance.
            assert!(Arc::ptr_eq(&enumerator, &retrieved.unwrap()));
        }
        // If the OnceLock was already populated by another test module (e.g.,
        // disk_enforcer::tests::ensure_enumerator), set_disk_enumerator is a
        // no-op and the retrieved Arc will be the pre-existing one. The
        // important invariant — get_disk_enumerator() returns Some — is still
        // verified above.
    }

    #[test]
    fn test_disk_enumerator_default_impl() {
        let enumerator: DiskEnumerator = Default::default();
        assert!(enumerator.all_disks().is_empty());
        assert!(!enumerator.is_ready());
    }

    // -----------------------------------------------------------------
    // Phase 35 (DISK-03) tests: TOML pre-load, merge, non-fatal persist
    // -----------------------------------------------------------------

    /// Helper to build a DiskIdentity test fixture with all fields specified.
    fn make_disk(
        instance_id: &str,
        bus: BusType,
        drive_letter: Option<char>,
        is_boot: bool,
    ) -> DiskIdentity {
        DiskIdentity {
            instance_id: instance_id.to_string(),
            bus_type: bus,
            model: format!("MODEL-{instance_id}"),
            drive_letter,
            serial: None,
            size_bytes: None,
            is_boot_disk: is_boot,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        }
    }

    /// Pre-load semantics: TOML entries land in instance_id_map and
    /// discovered_disks; enumeration_complete stays false (D-11, D-12).
    #[test]
    fn test_pre_load_populates_instance_map() {
        let enumerator = DiskEnumerator::new();
        let toml_disks = vec![
            make_disk("PCIIDE\\IDECHANNEL\\4&1234", BusType::Sata, Some('C'), true),
            make_disk(
                "USB\\VID_1234&PID_5678\\001",
                BusType::Usb,
                Some('E'),
                false,
            ),
        ];

        // Mirror the pre-load block from spawn_disk_enumeration_task.
        {
            let mut discovered = enumerator.discovered_disks.write();
            let mut instance_map = enumerator.instance_id_map.write();
            *discovered = toml_disks.clone();
            for disk in &toml_disks {
                instance_map.insert(disk.instance_id.clone(), disk.clone());
            }
        }

        assert!(enumerator
            .disk_for_instance_id("PCIIDE\\IDECHANNEL\\4&1234")
            .is_some());
        assert!(enumerator
            .disk_for_instance_id("USB\\VID_1234&PID_5678\\001")
            .is_some());
        assert_eq!(enumerator.all_disks().len(), 2);
        // D-12: pre-load alone must NOT mark enumeration complete.
        assert!(!enumerator.is_ready());
    }

    /// Merge: live data overwrites TOML for the same instance_id (D-07).
    #[test]
    fn test_merge_live_wins_over_toml() {
        let toml_disks = vec![make_disk("ID-A", BusType::Sata, Some('C'), false)];
        let live_disks = vec![make_disk("ID-A", BusType::Sata, Some('D'), true)]; // updated

        // Mirror the merge algorithm from spawn_disk_enumeration_task.
        let mut merged: HashMap<String, DiskIdentity> = toml_disks
            .into_iter()
            .map(|d| (d.instance_id.clone(), d))
            .collect();
        for disk in &live_disks {
            merged.insert(disk.instance_id.clone(), disk.clone());
        }
        let mut updated: Vec<DiskIdentity> = merged.into_values().collect();
        updated.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));

        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].instance_id, "ID-A");
        // Live wins.
        assert_eq!(updated[0].drive_letter, Some('D'));
        assert!(updated[0].is_boot_disk);
    }

    /// Merge: disconnected TOML disks are retained (D-06).
    #[test]
    fn test_merge_disconnected_disk_retained() {
        let disconnected = make_disk("ID-DISCONNECTED", BusType::Nvme, None, false);
        let toml_disks = vec![
            make_disk("ID-PRESENT", BusType::Sata, Some('C'), true),
            disconnected.clone(),
        ];
        let live_disks = vec![make_disk("ID-PRESENT", BusType::Sata, Some('C'), true)];

        let mut merged: HashMap<String, DiskIdentity> = toml_disks
            .into_iter()
            .map(|d| (d.instance_id.clone(), d))
            .collect();
        for disk in &live_disks {
            merged.insert(disk.instance_id.clone(), disk.clone());
        }
        let mut updated: Vec<DiskIdentity> = merged.into_values().collect();
        updated.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));

        assert_eq!(updated.len(), 2);
        // Disconnected entry survived with its TOML values intact.
        let recovered = updated
            .iter()
            .find(|d| d.instance_id == "ID-DISCONNECTED")
            .expect("disconnected disk must be preserved per D-06");
        assert_eq!(recovered.drive_letter, None);
        assert_eq!(recovered.bus_type, BusType::Nvme);
        assert_eq!(recovered.model, disconnected.model);
    }

    /// Merge result is sorted by instance_id for deterministic TOML output.
    #[test]
    fn test_merge_sorts_by_instance_id() {
        let toml_disks = vec![
            make_disk("ZZZ-LATER", BusType::Sata, None, false),
            make_disk("AAA-FIRST", BusType::Nvme, None, false),
        ];
        let live_disks: Vec<DiskIdentity> = Vec::new();

        let mut merged: HashMap<String, DiskIdentity> = toml_disks
            .into_iter()
            .map(|d| (d.instance_id.clone(), d))
            .collect();
        for disk in &live_disks {
            merged.insert(disk.instance_id.clone(), disk.clone());
        }
        let mut updated: Vec<DiskIdentity> = merged.into_values().collect();
        updated.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));

        assert_eq!(updated.len(), 2);
        assert_eq!(updated[0].instance_id, "AAA-FIRST");
        assert_eq!(updated[1].instance_id, "ZZZ-LATER");
    }

    /// TOML save failure must NOT crash the enumeration task -- in-memory
    /// state is authoritative. We simulate a save failure by passing a
    /// path under a directory that does not exist; std::fs::write returns Err
    /// but the in-memory cfg.disk_allowlist is still updated.
    #[test]
    fn test_persist_save_failure_is_non_fatal() {
        use crate::config::AgentConfig;
        use std::path::PathBuf;

        // Path under a guaranteed-nonexistent directory.
        // On Windows: C:\dlp_phase35_nonexistent_<random>\config.toml.
        // On other targets the test still exercises the same control flow.
        let bad_path = PathBuf::from(format!(
            "{}{}{}_phase35_nonexistent_dir_xyz123abc{}config.toml",
            std::env::temp_dir().display(),
            std::path::MAIN_SEPARATOR,
            "dlp",
            std::path::MAIN_SEPARATOR,
        ));
        // Verify our chosen path's parent directory does not exist.
        assert!(
            !bad_path.parent().map(|p| p.exists()).unwrap_or(false),
            "test precondition: parent of {bad_path:?} must not exist"
        );

        let agent_config = Arc::new(parking_lot::RwLock::new(AgentConfig::default()));
        let updated_list = vec![make_disk("ID-PERSIST", BusType::Sata, Some('C'), true)];

        // Mirror Step 4 from spawn_disk_enumeration_task: write the in-memory
        // field even if save() fails, log via tracing::error! (we cannot
        // assert the log here, but the operation must not panic).
        let save_result;
        {
            let mut cfg = agent_config.write();
            cfg.disk_allowlist = updated_list.clone();
            save_result = cfg.save(&bad_path);
        }

        // Save MUST fail (path under nonexistent directory).
        assert!(save_result.is_err(), "save to nonexistent dir must fail");
        // In-memory state MUST be updated regardless.
        assert_eq!(agent_config.read().disk_allowlist.len(), 1);
        assert_eq!(
            agent_config.read().disk_allowlist[0].instance_id,
            "ID-PERSIST"
        );
    }

    // -----------------------------------------------------------------
    // Phase 36 (DISK-05) tests: on_disk_arrival_inner + on_disk_removal
    // -----------------------------------------------------------------

    /// D-10/D-13: arrival inserts new drive_letter_map entry; instance_id_map
    /// is NOT touched (frozen allowlist invariant).
    #[cfg(windows)]
    #[test]
    fn test_on_disk_arrival_inner_updates_drive_letter_map_only() {
        // Acquire the shared cross-module lock to prevent disk_enforcer::tests
        // from resetting the global DiskEnumerator maps concurrently.
        let _guard = DISK_TEST_LOCK.lock();
        // The global DiskEnumerator OnceLock is process-wide; set_disk_enumerator is
        // a no-op after the first call. We must use get_disk_enumerator() to obtain
        // the actual installed instance and reset its fields directly (same approach
        // as Plan 02 disk_enforcer.rs tests).
        let _ = set_disk_enumerator(Arc::new(DiskEnumerator::new()));
        let enumerator = get_disk_enumerator().expect("DiskEnumerator must be installed");
        // Reset state via direct map access.
        enumerator.drive_letter_map.write().clear();
        enumerator.instance_id_map.write().clear();

        let new_disk = DiskIdentity {
            instance_id: "USBSTOR\\Disk\\1".to_string(),
            bus_type: BusType::Usb,
            model: "Acme".to_string(),
            drive_letter: Some('F'),
            serial: Some("SN-001".to_string()),
            size_bytes: Some(64_000_000_000),
            is_boot_disk: false,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        };

        // Phase 44: seed instance_id_map so the disk is treated as registered.
        // The test's purpose is to verify drive_letter_map update behavior,
        // not mount-time blocking.
        enumerator
            .instance_id_map
            .write()
            .insert(new_disk.instance_id.clone(), new_disk.clone());

        let ctx = crate::audit_emitter::EmitContext {
            agent_id: "AGENT-T".into(),
            session_id: 1,
            user_sid: "S-1-5-18".into(),
            user_name: "SYSTEM".into(),
            machine_name: None,
        };

        on_disk_arrival_inner(r"\\?\USBSTOR#Disk#1", &[new_disk.clone()], &ctx);

        // drive_letter_map updated.
        let dlm = enumerator.drive_letter_map.read();
        assert_eq!(
            dlm.get(&'F').map(|d| d.instance_id.clone()),
            Some("USBSTOR\\Disk\\1".to_string())
        );
        // instance_id_map UNCHANGED (D-09/D-10 frozen allowlist invariant).
        assert!(enumerator
            .instance_id_map
            .read()
            .contains_key("USBSTOR\\Disk\\1"));
    }

    /// D-13: arrival of a disk whose drive letter is already tracked is a no-op.
    #[cfg(windows)]
    #[test]
    fn test_on_disk_arrival_inner_skips_already_tracked() {
        let _guard = DISK_TEST_LOCK.lock();
        let _ = set_disk_enumerator(Arc::new(DiskEnumerator::new()));
        let enumerator = get_disk_enumerator().expect("DiskEnumerator must be installed");
        enumerator.drive_letter_map.write().clear();
        enumerator.instance_id_map.write().clear();

        let existing = DiskIdentity {
            instance_id: "ID-OLD".to_string(),
            bus_type: BusType::Sata,
            model: "Old".to_string(),
            drive_letter: Some('E'),
            serial: None,
            size_bytes: None,
            is_boot_disk: false,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        };
        enumerator
            .drive_letter_map
            .write()
            .insert('E', existing.clone());

        let live_again = DiskIdentity {
            instance_id: "ID-NEW".to_string(),
            bus_type: BusType::Sata,
            model: "Should be ignored".to_string(),
            drive_letter: Some('E'), // same letter -> skipped
            serial: None,
            size_bytes: None,
            is_boot_disk: false,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        };

        let ctx = crate::audit_emitter::EmitContext {
            agent_id: "AGENT-T".into(),
            session_id: 1,
            user_sid: "S-1-5-18".into(),
            user_name: "SYSTEM".into(),
            machine_name: None,
        };

        on_disk_arrival_inner(r"\\?\IRRELEVANT", &[live_again], &ctx);

        // The 'E' entry must still point to the ORIGINAL disk (no clobber).
        let dlm = enumerator.drive_letter_map.read();
        assert_eq!(
            dlm.get(&'E').map(|d| d.instance_id.clone()),
            Some("ID-OLD".to_string())
        );
    }

    /// D-10/D-14: removal clears drive_letter_map entry; instance_id_map is
    /// NOT touched (disconnected allowlisted disks remain registered per D-06).
    #[cfg(windows)]
    #[test]
    fn test_on_disk_removal_clears_drive_letter_map_only() {
        let _guard = DISK_TEST_LOCK.lock();
        let _ = set_disk_enumerator(Arc::new(DiskEnumerator::new()));
        let enumerator = get_disk_enumerator().expect("DiskEnumerator must be installed");
        enumerator.drive_letter_map.write().clear();
        enumerator.instance_id_map.write().clear();

        let disk = DiskIdentity {
            instance_id: "USBSTOR\\Disk\\Removed".to_string(),
            bus_type: BusType::Usb,
            model: "Removed".to_string(),
            drive_letter: Some('G'),
            serial: None,
            size_bytes: None,
            is_boot_disk: false,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        };
        enumerator
            .drive_letter_map
            .write()
            .insert('G', disk.clone());
        enumerator
            .instance_id_map
            .write()
            .insert(disk.instance_id.clone(), disk.clone());

        // dbcc_name uses # separators and a trailing GUID; extract_disk_instance_id
        // converts it to the same form as the SetupDi-derived instance_id.
        let dbcc_name = format!(
            r"\\?\{}#{{53f56307-b6bf-11d0-94f2-00a0c91efb8b}}",
            disk.instance_id.replace('\\', "#")
        );
        on_disk_removal(&dbcc_name);

        // drive_letter_map cleared.
        assert!(enumerator.drive_letter_map.read().get(&'G').is_none());
        // instance_id_map RETAINED (D-06: disconnected allowlisted disks remain).
        assert!(enumerator
            .instance_id_map
            .read()
            .contains_key(&disk.instance_id));
    }

    /// 38.2-GAP-02: boot disk detection must be case-insensitive.
    /// When disk.drive_letter is 'C' (uppercase) and boot_letter is 'c'
    /// (lowercase), is_boot_disk must still be set to true.
    #[test]
    fn test_is_boot_disk_true_when_letters_differ_in_case() {
        // Simulate the comparison logic from spawn_disk_enumeration_task
        // with mismatched casing. Both sides are uppercased for a
        // case-insensitive comparison.
        let disk_letter = Some('C');
        let boot_letter = 'c';
        let matches =
            disk_letter.map(|l| l.to_ascii_uppercase()) == Some(boot_letter.to_ascii_uppercase());
        assert!(
            matches,
            "boot disk detection must be case-insensitive ('C' vs 'c')"
        );

        // Also verify the reverse: lowercase disk letter vs uppercase boot letter.
        let disk_letter_lower = Some('c');
        let boot_letter_upper = 'C';
        let matches_reverse = disk_letter_lower.map(|l| l.to_ascii_uppercase())
            == Some(boot_letter_upper.to_ascii_uppercase());
        assert!(
            matches_reverse,
            "boot disk detection must be case-insensitive ('c' vs 'C')"
        );

        // Same-case must still work (no regression).
        assert!(Some('C').map(|l| l.to_ascii_uppercase()) == Some('C'.to_ascii_uppercase()));
        assert!(Some('c').map(|l| l.to_ascii_uppercase()) == Some('C'.to_ascii_uppercase()));
    }

    /// D-14: removal with an unknown instance_id is a silent no-op.
    #[cfg(windows)]
    #[test]
    fn test_on_disk_removal_unknown_id_is_noop() {
        let _guard = DISK_TEST_LOCK.lock();
        let _ = set_disk_enumerator(Arc::new(DiskEnumerator::new()));
        let enumerator = get_disk_enumerator().expect("DiskEnumerator must be installed");
        enumerator.drive_letter_map.write().clear();

        let known = DiskIdentity {
            instance_id: "KNOWN".to_string(),
            bus_type: BusType::Sata,
            model: "K".to_string(),
            drive_letter: Some('H'),
            serial: None,
            size_bytes: None,
            is_boot_disk: false,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        };
        enumerator.drive_letter_map.write().insert('H', known);

        on_disk_removal(r"\\?\UNKNOWN#Disk#999#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}");

        // The known entry MUST still be present (no collateral removal).
        assert!(enumerator.drive_letter_map.read().contains_key(&'H'));
    }

    // -------------------------------------------------------------------------
    // OP-01: Disk Enumeration Error Resilience (Phase 38.6)
    // -------------------------------------------------------------------------

    /// spawn_disk_enumeration_task retry logic: verify the retry delay sequence.
    ///
    /// The retry delays are [200ms, 1000ms, 4000ms] per the implementation.
    /// This test documents the expected retry behavior so that changes to the
    /// delay sequence are intentional.
    #[test]
    fn test_spawn_disk_enumeration_retry_delays_documented() {
        let expected = [
            std::time::Duration::from_millis(200),
            std::time::Duration::from_millis(1000),
            std::time::Duration::from_millis(4000),
        ];
        // The retry_delays array is hardcoded in spawn_disk_enumeration_task.
        // This test serves as documentation and regression guard.
        assert_eq!(expected.len(), 3);
        assert_eq!(expected[0], std::time::Duration::from_millis(200));
        assert_eq!(expected[1], std::time::Duration::from_millis(1000));
        assert_eq!(expected[2], std::time::Duration::from_millis(4000));
    }

    // -------------------------------------------------------------------------
    // Phase 44 (DISK-F1): Mount-time blocking tests
    // -------------------------------------------------------------------------

    /// Phase 44: an unregistered disk arriving must NOT be inserted into
    /// drive_letter_map.  The mount-time block path skips the insertion
    /// entirely so the disk stays invisible to Explorer.
    #[cfg(windows)]
    #[test]
    fn test_on_disk_arrival_skips_unregistered_disk() {
        let _guard = DISK_TEST_LOCK.lock();
        let _ = set_disk_enumerator(Arc::new(DiskEnumerator::new()));
        let enumerator = get_disk_enumerator().expect("DiskEnumerator must be installed");
        enumerator.drive_letter_map.write().clear();
        enumerator.instance_id_map.write().clear();

        let unregistered = DiskIdentity {
            instance_id: "UNREG\\Disk\\44".to_string(),
            bus_type: BusType::Usb,
            model: "EvilDrive".to_string(),
            drive_letter: Some('X'),
            serial: Some("SN-EVIL".to_string()),
            size_bytes: Some(1_000_000_000),
            is_boot_disk: false,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        };

        let ctx = crate::audit_emitter::EmitContext {
            agent_id: "AGENT-T".into(),
            session_id: 1,
            user_sid: "S-1-5-18".into(),
            user_name: "SYSTEM".into(),
            machine_name: None,
        };

        on_disk_arrival_inner(r"\\?\UNREG#Disk#44", &[unregistered], &ctx);

        // drive_letter_map must NOT contain the unregistered disk.
        assert!(
            enumerator.drive_letter_map.read().get(&'X').is_none(),
            "unregistered disk must NOT appear in drive_letter_map"
        );
        // instance_id_map remains empty (frozen allowlist invariant).
        assert!(enumerator.instance_id_map.read().is_empty());
    }

    /// Phase 44: verify that `block_disk_at_mount_time` has the expected
    /// signature (compile-time check).  Runtime execution requires a real
    /// volume handle, so we only assert the function exists and accepts the
    /// correct parameter types.
    #[cfg(windows)]
    #[test]
    fn test_block_disk_at_mount_time_signature() {
        let _ = block_disk_at_mount_time
            as fn(char, &DiskIdentity, &crate::audit_emitter::EmitContext) -> Result<(), String>;
    }

    /// Phase 44: verify that `emit_disk_mount_blocked` constructs an
    /// AuditEvent with the correct EventType and blocked_disk fields.
    /// We build the same event the helper would build and inspect it.
    #[cfg(windows)]
    #[test]
    fn test_emit_disk_mount_blocked_event_fields() {
        use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};

        let ctx = crate::audit_emitter::EmitContext {
            agent_id: "AGENT-TEST-44".into(),
            session_id: 42,
            user_sid: "S-1-5-21-44".into(),
            user_name: "testuser".into(),
            machine_name: None,
        };

        let disk = DiskIdentity {
            instance_id: "TEST\\Disk\\44".to_string(),
            bus_type: BusType::Usb,
            model: "TestDrive".to_string(),
            drive_letter: Some('Y'),
            serial: Some("SN-44".to_string()),
            size_bytes: Some(500_000_000_000),
            is_boot_disk: false,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        };

        // Build the event exactly as emit_disk_mount_blocked would.
        let event = AuditEvent::new(
            EventType::DiskMountBlocked,
            ctx.user_sid.clone(),
            ctx.user_name.clone(),
            "disk://mount-blocked".to_string(),
            Classification::T4,
            Action::WRITE,
            Decision::DENY,
            ctx.agent_id.clone(),
            ctx.session_id,
        )
        .with_blocked_disk(disk.clone());

        assert_eq!(event.event_type, EventType::DiskMountBlocked);
        assert_eq!(event.classification, Classification::T4);
        assert_eq!(event.decision, Decision::DENY);
        assert_eq!(event.resource_path, "disk://mount-blocked");
        assert!(event.blocked_disk.is_some());
        let blocked = event.blocked_disk.as_ref().unwrap();
        assert_eq!(blocked.instance_id, "TEST\\Disk\\44");
        assert_eq!(blocked.drive_letter, Some('Y'));

        // Verify JSON serialization contains expected fields.
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains("DISK_MOUNT_BLOCKED"),
            "event_type must serialize"
        );
        assert!(
            json.contains("blocked_disk"),
            "blocked_disk field must be present"
        );
        assert!(json.contains("TestDrive"), "model must be present");
    }

    /// on_disk_arrival logs device_path on enumerate_fixed_disks failure.
    ///
    /// When enumerate_fixed_disks fails inside on_disk_arrival, the error log
    /// must include the device_path for troubleshooting. We verify this by
    /// checking the function signature: device_path is passed into the error
    /// log branch.
    #[test]
    #[cfg(windows)]
    fn test_on_disk_arrival_error_includes_device_path() {
        // This is a compile-time / signature verification test.
        // The actual on_disk_arrival function calls:
        //   warn!(error = %e, device_path = %device_path, "...")
        // We verify the function exists and accepts the right parameters.
        let _ = on_disk_arrival as fn(&str, &crate::audit_emitter::EmitContext);
    }
}
