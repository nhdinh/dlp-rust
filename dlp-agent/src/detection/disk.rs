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

use dlp_common::{enumerate_fixed_disks, get_boot_drive_letter, DiskIdentity};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

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
/// The task enumerates fixed disks with retry logic, then emits an aggregated
/// `DiskDiscovery` audit event. On final failure, it emits a high-severity
/// failure event and leaves `enumeration_complete` as `false` (fail-closed per
/// D-04).
///
/// # Arguments
///
/// * `runtime_handle` — tokio runtime `Handle` for spawning sub-tasks from
///   non-async contexts.
/// * `audit_ctx` — [`EmitContext`] for audit event emission.
/// * `_agent_config_path` — Optional path to existing allowlist TOML (Phase 35
///   will use this).
pub fn spawn_disk_enumeration_task(
    runtime_handle: tokio::runtime::Handle,
    audit_ctx: crate::audit_emitter::EmitContext,
    _agent_config_path: Option<String>,
) {
    runtime_handle.spawn(async move {
        let retry_delays = [
            Duration::from_millis(200),
            Duration::from_millis(1000),
            Duration::from_millis(4000),
        ];
        let mut last_error: Option<String> = None;

        for (attempt, delay) in retry_delays.iter().enumerate() {
            info!(attempt = attempt + 1, "starting fixed disk enumeration");
            match enumerate_fixed_disks() {
                Ok(mut disks) => {
                    // Mark boot disk.
                    if let Some(boot_letter) = get_boot_drive_letter() {
                        for disk in &mut disks {
                            if disk.drive_letter == Some(boot_letter) {
                                disk.is_boot_disk = true;
                                info!(
                                    drive = %boot_letter,
                                    instance_id = %disk.instance_id,
                                    "boot disk identified"
                                );
                            }
                        }
                    }

                    // Update the global DiskEnumerator.
                    if let Some(enumerator) = get_disk_enumerator() {
                        let mut discovered = enumerator.discovered_disks.write();
                        let mut drive_map = enumerator.drive_letter_map.write();
                        let mut instance_map = enumerator.instance_id_map.write();
                        let mut complete = enumerator.enumeration_complete.write();

                        *discovered = disks.clone();
                        drive_map.clear();
                        instance_map.clear();
                        for disk in &disks {
                            if let Some(letter) = disk.drive_letter {
                                drive_map.insert(letter, disk.clone());
                            }
                            instance_map.insert(disk.instance_id.clone(), disk.clone());
                        }
                        *complete = true;
                    }

                    // Emit aggregated disk discovery audit event.
                    emit_disk_discovery(&audit_ctx, &disks);

                    info!(disk_count = disks.len(), "fixed disk enumeration complete");
                    return;
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                    warn!(
                        attempt = attempt + 1,
                        error = %e,
                        "disk enumeration failed -- will retry"
                    );
                    if attempt < retry_delays.len() - 1 {
                        sleep(*delay).await;
                    }
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
    });
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
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::{BusType, DiskIdentity};

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
        let enumerator = Arc::new(DiskEnumerator::new());
        set_disk_enumerator(Arc::clone(&enumerator));
        let retrieved = get_disk_enumerator();
        assert!(retrieved.is_some());
        // Verify it points to the same instance by checking Arc pointer equality.
        assert!(Arc::ptr_eq(&enumerator, &retrieved.unwrap()));
    }

    #[test]
    fn test_disk_enumerator_default_impl() {
        let enumerator: DiskEnumerator = Default::default();
        assert!(enumerator.all_disks().is_empty());
        assert!(!enumerator.is_ready());
    }
}
