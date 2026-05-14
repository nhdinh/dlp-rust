//! Append-only audit log emitter (T-19, T-26, T-27).
//!
//! Writes structured JSON audit events to a local log file. Every intercepted
//! file operation generates an [`AuditEvent`] that is serialised to a single
//! JSON line and flushed immediately.
//!
//! ## Design
//!
//! - **Append-only**: file opened with `FILE_APPEND_DATA` only.
//! - **One JSON object per line** (JSONL) for easy SIEM ingestion.
//! - **Size-based rotation**: configurable max bytes, 9 generations.
//! - **No file content**: metadata only — never the actual file payload.
//!
//! ## Global Emitter
//!
//! The emitter is exposed as a lazily-initialised global singleton via
//! [`EMITTER`].  All call sites share this instance so there is exactly one
//! writer open at a time.  Errors during emission are logged but never block
//! the calling thread — audit failures are never allowed to interfere with
//! DLP enforcement.
//!
//! ## Audit Enrichment
//!
//! [`get_application_metadata`] resolves the process image path via
//! `OpenProcess` + `GetModuleFileNameExW`.  [`get_resource_owner`] reads the
//! file owner SID via `GetNamedSecurityInfoW` + `ConvertSidToStringSidW`.
//! Both return `None` on failure so audit emission is never blocked by
//! enrichment errors.  SHA-256 hashing of the process executable is deferred
//! to Phase 2.

/// Audit enrichment — resolves process metadata and resource ownership.
#[cfg(windows)]
mod audit_enrichment {
    use tracing::debug;

    /// Returns `(application_path, application_hash)` for the given PID.
    ///
    /// `application_path` is resolved via `GetModuleFileNameExW`.
    /// `application_hash` is not yet implemented (returns `None`).
    ///
    /// Returns `(None, None)` if the process cannot be opened (e.g., PID 0
    /// from the `notify` crate which does not provide real PIDs).
    ///
    /// NOTE: UWP AUMID resolution is handled by `dlp-user-ui`'s `resolve_app_identity()`
    /// for clipboard events. File/USB audit enrichment uses Win32 image path only.
    pub fn get_application_metadata(pid: u32) -> (Option<String>, Option<String>) {
        if pid == 0 {
            return (None, None);
        }

        let path = get_process_image_path(pid);
        // TODO (Phase 5, N-SEC-07): compute SHA-256 hash of the executable
        // as part of the append-only hash chain on the audit log.
        (path, None)
    }

    /// Returns the owner SID of the file at `path`.
    ///
    /// Uses `GetNamedSecurityInfoW` to read the file's owner from the
    /// security descriptor, then `ConvertSidToStringSidW` to produce a
    /// string SID (e.g., "S-1-5-21-...").
    ///
    /// Returns `None` if the file does not exist or the owner cannot be read.
    pub fn get_resource_owner(path: &str) -> Option<String> {
        get_file_owner_sid(path)
    }

    /// Resolves the executable image path for a process via
    /// `OpenProcess` + `GetModuleFileNameExW`.
    fn get_process_image_path(pid: u32) -> Option<String> {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut buf = [0u16; 520];
            let len = GetModuleFileNameExW(Some(handle), Some(HMODULE::default()), &mut buf);
            let _ = CloseHandle(handle);

            if len == 0 {
                debug!(pid, "GetModuleFileNameExW returned 0");
                return None;
            }
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    /// Reads the owner SID string from a file's security descriptor.
    fn get_file_owner_sid(path: &str) -> Option<String> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::LocalFree;
        use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

        let path_wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let mut owner_sid = PSID::default();
            let mut sd = PSECURITY_DESCRIPTOR::default();

            let err = GetNamedSecurityInfoW(
                PCWSTR::from_raw(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&mut owner_sid),
                None,
                None,
                None,
                &mut sd,
            );

            if err.is_err() {
                debug!(path, "GetNamedSecurityInfoW failed");
                return None;
            }

            // ConvertSidToStringSidW is in Win32_Security_Authorization.
            let mut sid_str = windows::core::PWSTR::null();
            let ok = windows::Win32::Security::Authorization::ConvertSidToStringSidW(
                owner_sid,
                &mut sid_str,
            )
            .ok();

            // Free the security descriptor allocated by GetNamedSecurityInfoW.
            if !sd.0.is_null() {
                let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(sd.0)));
            }

            if ok.is_none() {
                debug!(path, "ConvertSidToStringSidW failed");
                return None;
            }

            let result = sid_str.to_string().ok();

            // Free the SID string allocated by ConvertSidToStringSidW.
            if !sid_str.is_null() {
                let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                    sid_str.as_ptr() as *mut _
                )));
            }

            result
        }
    }
}

/// Fallback audit enrichment for non-Windows platforms (tests).
#[cfg(not(windows))]
mod audit_enrichment {
    pub fn get_application_metadata(_pid: u32) -> (Option<String>, Option<String>) {
        (None, None)
    }

    pub fn get_resource_owner(_path: &str) -> Option<String> {
        None
    }
}

pub use audit_enrichment::{get_application_metadata, get_resource_owner};

use dlp_common::endpoint::AppIdentity;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use dlp_common::endpoint::agent_unknown_app;
use dlp_common::AuditEvent;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// In-process event capture sink (Option C per Plan 34-05 §Step D)
// ---------------------------------------------------------------------------
//
// Always compiled so integration tests (separate Rust binaries that do NOT
// inherit `cfg(test)` from the library crate) can call `enable_test_capture`
// and `drain_test_events` without a cargo feature flag.
//
// Production code never calls `enable_test_capture`, so `TEST_CAPTURE_ENABLED`
// stays `false` forever.  The only overhead on the hot emit path is a single
// `Relaxed` atomic load -- effectively free.

/// Whether the in-process capture sink is active.  `false` by default.
static TEST_CAPTURE_ENABLED: AtomicBool = AtomicBool::new(false);

/// In-process event capture buffer.
static TEST_EVENT_SINK: Lazy<Mutex<Vec<AuditEvent>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// Enable the in-process audit event capture sink.
///
/// Call at the start of any test that needs to assert on emitted events.
/// No production code path calls this function, so the sink is disabled in
/// all production service runs.  Call [`drain_test_events`] to retrieve and
/// reset the accumulated events.
pub fn enable_test_capture() {
    TEST_CAPTURE_ENABLED.store(true, AtomicOrdering::SeqCst);
}

/// Drain and return all events captured since the last [`enable_test_capture`].
///
/// Disables the capture sink before draining so the next `emit_audit` call
/// reverts to the fast-path `Relaxed` load.  Returns an empty `Vec` if
/// capture was never enabled or no events were emitted during the window.
pub fn drain_test_events() -> Vec<AuditEvent> {
    TEST_CAPTURE_ENABLED.store(false, AtomicOrdering::SeqCst);
    TEST_EVENT_SINK.lock().drain(..).collect()
}

#[cfg(windows)]
use crate::server_client::AuditBuffer;

/// Global audit buffer for relaying events to dlp-server.
///
/// Set once during startup via [`set_audit_buffer`]. If not set,
/// events are only written to the local JSONL file (the primary path).
/// Server relay is always best-effort.
#[cfg(windows)]
static AUDIT_BUFFER: once_cell::sync::OnceCell<Arc<AuditBuffer>> = once_cell::sync::OnceCell::new();

/// Installs the global audit buffer for server relay.
///
/// Called once during agent startup after `ServerClient` is created.
/// Subsequent calls are silently ignored.
///
/// # Arguments
///
/// * `buffer` -- the shared `AuditBuffer` instance
#[cfg(windows)]
pub fn set_audit_buffer(buffer: Arc<AuditBuffer>) {
    if AUDIT_BUFFER.set(buffer).is_err() {
        warn!("audit buffer already set -- ignoring duplicate call");
    }
}

const DEFAULT_LOG_DIR: &str = r"C:\ProgramData\DLP\logs";
const DEFAULT_LOG_NAME: &str = "audit.jsonl";
const DEFAULT_MAX_BYTES: u64 = 50 * 1024 * 1024;
const MAX_ROTATED_FILES: u32 = 9;

/// The process-wide global audit emitter.
///
/// Lazily opened on first use.  Errors during emission are logged and
/// silently swallowed so audit failures never interfere with DLP enforcement.
pub static EMITTER: Lazy<Arc<AuditEmitter>> = Lazy::new(|| {
    Arc::new(AuditEmitter::open_default().unwrap_or_else(|e| {
        // Log the error but create a no-op emitter so the rest of the
        // service continues — audit failures must never crash the agent.
        warn!(error = %e, "failed to open audit log — audit events will not be persisted");
        // Open in the current directory so we at least attempt to write.
        AuditEmitter::open(Path::new("."), DEFAULT_LOG_NAME, DEFAULT_MAX_BYTES)
            .expect("audit emitter must be constructable even in fallback mode")
    }))
});

/// Shared context required to build an [`AuditEvent`].
///
/// Passed to every [`emit_audit`] call so call sites don't need to repeat
/// agent-wide fields (agent_id, session_id).
#[derive(Debug, Clone)]
pub struct EmitContext {
    /// The unique ID of this agent (e.g. "AGENT-WS02-001").
    pub agent_id: String,
    /// The interactive session in which the event occurred.
    pub session_id: u32,
    /// The user's Windows Security Identifier.
    pub user_sid: String,
    /// The user's display name.
    pub user_name: String,
    /// Machine hostname, set once at startup.
    pub machine_name: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("failed to open audit log: {0}")]
    OpenFailed(#[from] std::io::Error),
    #[error("failed to serialise audit event: {0}")]
    SerializationFailed(#[from] serde_json::Error),
    #[error("log directory does not exist: {0}")]
    DirectoryCreateFailed(String),
}

/// Low-level audit emission.
///
/// Called by [`emit_audit`].  Returns `Ok(())` on success; callers must handle
/// errors themselves.  This is the right choice for callers that want to
/// propagate failures (e.g. during startup validation).
pub fn emit(event: &AuditEvent) -> Result<(), AuditError> {
    EMITTER.emit(event)
}

/// High-level audit emission helper.
///
/// Enriches `event` with the shared fields in `ctx` (agent_id, session_id).
/// User identity fields (`user_sid`, `user_name`) are only filled from `ctx`
/// when the event does not already carry a resolved identity — this allows
/// the interception pipeline to set the real interactive user via
/// [`SessionIdentityMap`] before calling this function.
///
/// Errors are logged and silently dropped — audit emission failures must
/// never interfere with DLP enforcement.
pub fn emit_audit(ctx: &EmitContext, event: &mut AuditEvent) {
    event.agent_id.clone_from(&ctx.agent_id);
    event.session_id = ctx.session_id;

    // Only fill user identity from ctx if the event doesn't already have one.
    if event.user_sid.is_empty() {
        event.user_sid.clone_from(&ctx.user_sid);
    }
    if event.user_name.is_empty() {
        event.user_name.clone_from(&ctx.user_name);
    }

    // AUDIT-04 (Phase 42): Guarantee app identity fields are always present.
    ensure_app_identity_fields(event);

    if let Err(e) = EMITTER.emit(event) {
        // Log but do not propagate -- audit failures must never block DLP enforcement.
        error!(
            error = %e,
            event_type = ?event.event_type,
            path = %event.resource_path,
            "audit emission failed -- event dropped"
        );
    }

    // In-process capture sink. Enabled only when a test calls
    // `enable_test_capture()`. The atomic check is a single relaxed load on
    // the production hot path -- negligible overhead when disabled.
    if TEST_CAPTURE_ENABLED.load(AtomicOrdering::Relaxed) {
        TEST_EVENT_SINK.lock().push(event.clone());
    }

    // Best-effort relay to dlp-server via the audit buffer.
    // The buffer is flushed periodically by a background task.
    // If the buffer is not set (server client not configured), fall
    // back to the offline audit queue so the event is not lost.
    #[cfg(windows)]
    if let Some(buffer) = AUDIT_BUFFER.get() {
        buffer.enqueue(event.clone());
    } else if let Some(mutex) = crate::service::agent_db() {
        // Server client not configured — enqueue to offline queue for later relay.
        if let Ok(conn) = mutex.lock() {
            match crate::offline_audit_queue::enqueue_with_overflow_event(
                &conn,
                event,
                crate::offline_audit_queue::DEFAULT_MAX_QUEUE_SIZE,
            ) {
                Ok(()) => {}
                Err(crate::offline_audit_queue::OfflineQueueError::AtCapacity { max_size }) => {
                    // R-62-16: Emit a synthetic queue_overflow audit event.
                    warn!(
                        max_size,
                        "offline audit queue at capacity — emitting synthetic queue_overflow event"
                    );
                    let overflow = dlp_common::AuditEvent::new(
                        dlp_common::EventType::AdminAction,
                        "SYSTEM".to_string(),
                        "SYSTEM".to_string(),
                        "queue_overflow".to_string(),
                        dlp_common::Classification::T1,
                        dlp_common::Action::WRITE,
                        dlp_common::Decision::ALLOW,
                        event.agent_id.clone(),
                        event.session_id,
                    );
                    // Write the synthetic event to JSONL only (do not re-queue).
                    if let Err(e) = EMITTER.emit(&overflow) {
                        warn!(error = %e, "failed to emit synthetic queue_overflow event to JSONL");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "failed to enqueue audit event to offline queue");
                }
            }
        }
    }
}

/// Enriches an AuditEvent with source application identity from a PID.
///
/// Resolves the process image path from `pid` via `get_application_metadata`,
/// then sets `source_application` on the event. If resolution fails,
/// uses the AGENT-UNKNOWN sentinel.
///
/// # Arguments
///
/// * `event` — the audit event to enrich (mutated in place)
/// * `pid` — the process ID of the operation initiator
pub fn enrich_audit_with_app_identity(event: &mut AuditEvent, pid: u32) {
    let (app_path, _app_hash) = get_application_metadata(pid);
    let app_identity = app_path
        .map(|path| {
            let name = std::path::Path::new(&path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            AppIdentity {
                image_path: path,
                publisher: name,
                trust_tier: dlp_common::endpoint::AppTrustTier::Unknown,
                signature_state: dlp_common::endpoint::SignatureState::Unknown,
                aumid: None,
                package_family_name: None,
                is_uwp: false,
            }
        })
        .unwrap_or_else(agent_unknown_app);
    event.source_application = Some(app_identity);
}

/// Sets destination_application on an AuditEvent.
///
/// Used when the destination is known (e.g., copy to a specific path,
/// paste to a specific application). If None, sets AGENT-UNKNOWN.
pub fn set_destination_application(event: &mut AuditEvent, dest: Option<AppIdentity>) {
    event.destination_application = Some(dest.unwrap_or_else(agent_unknown_app));
}

/// Ensures `source_application` and `destination_application` are never None.
///
/// Called by `emit_audit` before writing the event. If either field is None,
/// replaces it with the AGENT-UNKNOWN sentinel. This guarantees that every
/// audit event in the log has resolvable app identity fields (even if the
/// identity itself indicates "unknown").
///
/// AUDIT-04 (Phase 42): Audit schema guarantee for app identity fields.
pub fn ensure_app_identity_fields(event: &mut AuditEvent) {
    if event.source_application.is_none() {
        event.source_application = Some(agent_unknown_app());
        tracing::debug!(correlation_id = %event.correlation_id.as_deref().unwrap_or("none"), "AuditEvent source_application was None — set to AGENT-UNKNOWN");
    }
    if event.destination_application.is_none() {
        event.destination_application = Some(agent_unknown_app());
        tracing::debug!(correlation_id = %event.correlation_id.as_deref().unwrap_or("none"), "AuditEvent destination_application was None — set to AGENT-UNKNOWN");
    }
}

/// Returns the path of the active audit log file.
#[must_use]
pub fn log_path() -> std::path::PathBuf {
    EMITTER.log_path().to_path_buf()
}

/// Returns `true` if the global emitter is healthy (i.e., the file is open).
///
/// Used by the health monitor to report audit subsystem status.
#[must_use]
pub fn is_healthy() -> bool {
    !EMITTER.log_path().is_relative()
}

pub struct AuditEmitter {
    writer: Mutex<BufWriter<File>>,
    log_path: PathBuf,
    max_bytes: u64,
    events_since_check: Mutex<u64>,
}

impl AuditEmitter {
    pub fn open_default() -> Result<Self, AuditError> {
        Self::open(
            Path::new(DEFAULT_LOG_DIR),
            DEFAULT_LOG_NAME,
            DEFAULT_MAX_BYTES,
        )
    }

    pub fn open(dir: &Path, name: &str, max_bytes: u64) -> Result<Self, AuditError> {
        fs::create_dir_all(dir)
            .map_err(|e| AuditError::DirectoryCreateFailed(format!("{}: {e}", dir.display())))?;
        let log_path = dir.join(name);
        let file = open_append(&log_path)?;
        info!(path = %log_path.display(), "audit log opened");
        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
            log_path,
            max_bytes,
            events_since_check: Mutex::new(0),
        })
    }

    pub fn emit(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let json = serde_json::to_string(event)?;
        let mut writer = self.writer.lock();
        writeln!(writer, "{json}")?;
        writer.flush()?;
        debug!(
            event_type = ?event.event_type,
            path = %event.resource_path,
            decision = ?event.decision,
            "audit event emitted"
        );
        let mut count = self.events_since_check.lock();
        *count += 1;
        if *count >= 100 {
            *count = 0;
            drop(writer);
            self.maybe_rotate();
        }
        Ok(())
    }

    #[must_use]
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    fn maybe_rotate(&self) {
        let size = fs::metadata(&self.log_path).map(|m| m.len()).unwrap_or(0);
        if size >= self.max_bytes {
            if let Err(e) = self.rotate() {
                error!(error = %e, "audit log rotation failed");
            }
        }
    }

    pub fn rotate(&self) -> Result<(), AuditError> {
        let mut writer = self.writer.lock();
        writer.flush()?;
        let dir = self.log_path.parent().unwrap_or(Path::new("."));
        let stem = self
            .log_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("audit");
        let ext = self
            .log_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("jsonl");
        for i in (1..=MAX_ROTATED_FILES).rev() {
            let src = dir.join(format!("{stem}.{i}.{ext}"));
            if src.exists() {
                if i == MAX_ROTATED_FILES {
                    let _ = fs::remove_file(&src);
                } else {
                    let dst = dir.join(format!("{stem}.{}.{ext}", i + 1));
                    let _ = fs::rename(&src, &dst);
                }
            }
        }
        let rotated = dir.join(format!("{stem}.1.{ext}"));
        let _ = fs::rename(&self.log_path, &rotated);
        let new_file = open_append(&self.log_path)?;
        *writer = BufWriter::new(new_file);
        info!(rotated_to = %rotated.display(), "audit log rotated");
        Ok(())
    }
}

fn open_append(path: &Path) -> Result<File, AuditError> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(AuditError::OpenFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::{Action, Classification, Decision, EventType};

    fn make_event() -> AuditEvent {
        AuditEvent::new(
            EventType::Access,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            r"C:\Data\report.xlsx".to_string(),
            Classification::T2,
            Action::WRITE,
            Decision::ALLOW,
            "AGENT-WS02-001".to_string(),
            1,
        )
    }

    #[test]
    fn test_emit_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let emitter = AuditEmitter::open(dir.path(), "test.jsonl", DEFAULT_MAX_BYTES).unwrap();
        emitter.emit(&make_event()).unwrap();
        let contents = fs::read_to_string(emitter.log_path()).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.event_type, EventType::Access);
        assert_eq!(parsed.decision, Decision::ALLOW);
    }

    #[test]
    fn test_multiple_events() {
        let dir = tempfile::tempdir().unwrap();
        let emitter = AuditEmitter::open(dir.path(), "test.jsonl", DEFAULT_MAX_BYTES).unwrap();
        for _ in 0..5 {
            emitter.emit(&make_event()).unwrap();
        }
        let contents = fs::read_to_string(emitter.log_path()).unwrap();
        assert_eq!(contents.lines().count(), 5);
    }

    #[test]
    fn test_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 100).unwrap();
        for _ in 0..5 {
            emitter.emit(&make_event()).unwrap();
        }
        emitter.rotate().unwrap();
        let rotated = dir.path().join("audit.1.jsonl");
        assert!(rotated.exists());
    }

    #[test]
    fn test_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b/c");
        let emitter = AuditEmitter::open(&nested, "audit.jsonl", DEFAULT_MAX_BYTES);
        assert!(emitter.is_ok());
    }

    // -- Drag-and-drop audit tests (APP-08.3, AUDIT-04.3) --------------------

    #[test]
    fn test_drag_drop_audit_event_has_app_identity() {
        use dlp_common::endpoint::{AppIdentity, AppTrustTier, SignatureState};

        let src = AppIdentity {
            image_path: r"C:\Source\app.exe".to_string(),
            publisher: "Contoso Ltd".to_string(),
            trust_tier: AppTrustTier::Trusted,
            signature_state: SignatureState::Valid,
            aumid: None,
            package_family_name: None,
            is_uwp: false,
        };
        let dest = AppIdentity {
            image_path: r"C:\Dest\app.exe".to_string(),
            publisher: "Fabrikam Inc".to_string(),
            trust_tier: AppTrustTier::Untrusted,
            signature_state: SignatureState::NotSigned,
            aumid: None,
            package_family_name: None,
            is_uwp: false,
        };

        let mut event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            "dragdrop://session1".to_string(),
            Classification::T3,
            Action::DRAG_DROP,
            Decision::DENY,
            "AGENT-WS02-001".to_string(),
            1,
        )
        .with_source_application(Some(src))
        .with_destination_application(Some(dest));

        let ctx = EmitContext {
            agent_id: "AGENT-TEST".to_string(),
            session_id: 1,
            user_sid: "S-1-5-21-TEST".to_string(),
            user_name: "testuser".to_string(),
            machine_name: None,
        };

        emit_audit(&ctx, &mut event);

        // Verify the event has both app identities after emission.
        assert!(event.source_application.is_some());
        assert!(event.destination_application.is_some());
        let src = event.source_application.unwrap();
        let dest = event.destination_application.unwrap();
        assert_eq!(src.image_path, r"C:\Source\app.exe");
        assert_eq!(src.publisher, "Contoso Ltd");
        assert_eq!(dest.image_path, r"C:\Dest\app.exe");
        assert_eq!(dest.publisher, "Fabrikam Inc");
        assert_eq!(event.action_attempted, Action::DRAG_DROP);
        assert_eq!(event.decision, Decision::DENY);
    }

    #[test]
    fn test_drag_drop_audit_event_applies_agent_unknown_when_missing() {
        // AUDIT-05: When app identity is missing, emit_audit replaces it
        // with the AGENT-UNKNOWN sentinel.
        let mut event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-123".to_string(),
            "jsmith".to_string(),
            "dragdrop://session1".to_string(),
            Classification::T3,
            Action::DRAG_DROP,
            Decision::DENY,
            "AGENT-WS02-001".to_string(),
            1,
        );
        // Deliberately do NOT set source/destination application.

        let ctx = EmitContext {
            agent_id: "AGENT-TEST".to_string(),
            session_id: 1,
            user_sid: "S-1-5-21-TEST".to_string(),
            user_name: "testuser".to_string(),
            machine_name: None,
        };

        emit_audit(&ctx, &mut event);

        // Both should be AGENT-UNKNOWN.
        let src = event.source_application.expect("source must be set");
        let dest = event.destination_application.expect("dest must be set");
        assert_eq!(src.image_path, "AGENT-UNKNOWN");
        assert_eq!(dest.image_path, "AGENT-UNKNOWN");
    }

    // -- Phase 42 enrichment helper tests (AUDIT-04) -----------------------

    fn make_test_event() -> AuditEvent {
        AuditEvent::new(
            EventType::Access,
            "S-1-5-18".to_string(),
            "SYSTEM".to_string(),
            r"C:\test.txt".to_string(),
            Classification::T3,
            Action::READ,
            Decision::DENY,
            "AGENT-TEST".to_string(),
            1,
        )
    }

    #[test]
    fn test_enrich_audit_with_app_identity_sets_source() {
        let mut event = make_test_event();
        enrich_audit_with_app_identity(&mut event, std::process::id());
        assert!(event.source_application.is_some());
        // Current process should have a valid path
        assert!(event.source_application.as_ref().unwrap().image_path.len() > 0);
    }

    #[test]
    fn test_enrich_audit_with_app_identity_uses_agent_unknown_for_invalid_pid() {
        let mut event = make_test_event();
        enrich_audit_with_app_identity(&mut event, 99999); // non-existent PID
        assert!(event.source_application.is_some());
        assert_eq!(
            event.source_application.as_ref().unwrap().image_path,
            "AGENT-UNKNOWN"
        );
    }

    #[test]
    fn test_set_destination_application_with_some() {
        let mut event = make_test_event();
        let dest = dlp_common::AppIdentity {
            image_path: r"C:\Windows\notepad.exe".to_string(),
            publisher: "Notepad".to_string(),
            trust_tier: dlp_common::endpoint::AppTrustTier::Unknown,
            signature_state: dlp_common::endpoint::SignatureState::Unknown,
            aumid: None,
            package_family_name: None,
            is_uwp: false,
        };
        set_destination_application(&mut event, Some(dest));
        assert_eq!(
            event.destination_application.as_ref().unwrap().image_path,
            r"C:\Windows\notepad.exe"
        );
    }

    #[test]
    fn test_set_destination_application_with_none_uses_agent_unknown() {
        let mut event = make_test_event();
        set_destination_application(&mut event, None);
        assert_eq!(
            event.destination_application.as_ref().unwrap().image_path,
            "AGENT-UNKNOWN"
        );
    }

    #[test]
    fn test_emit_audit_guarantees_source_application() {
        let mut event = make_test_event();
        // Deliberately leave source_application as None
        event.source_application = None;

        let ctx = EmitContext {
            agent_id: "AGENT-TEST".to_string(),
            session_id: 1,
            user_sid: "S-1-5-18".to_string(),
            user_name: "SYSTEM".to_string(),
            machine_name: None,
        };

        emit_audit(&ctx, &mut event);
        assert!(event.source_application.is_some());
        assert_eq!(
            event.source_application.as_ref().unwrap().image_path,
            "AGENT-UNKNOWN"
        );
    }

    #[test]
    fn test_emit_audit_guarantees_destination_application() {
        let mut event = make_test_event();
        event.destination_application = None;

        let ctx = EmitContext {
            agent_id: "AGENT-TEST".to_string(),
            session_id: 1,
            user_sid: "S-1-5-18".to_string(),
            user_name: "SYSTEM".to_string(),
            machine_name: None,
        };

        emit_audit(&ctx, &mut event);
        assert!(event.destination_application.is_some());
        assert_eq!(
            event.destination_application.as_ref().unwrap().image_path,
            "AGENT-UNKNOWN"
        );
    }

    #[test]
    fn test_emit_audit_preserves_resolved_identity() {
        let mut event = make_test_event();
        let app = dlp_common::AppIdentity {
            image_path: r"C:\Windows\notepad.exe".to_string(),
            publisher: "notepad.exe".to_string(),
            trust_tier: dlp_common::endpoint::AppTrustTier::Unknown,
            signature_state: dlp_common::endpoint::SignatureState::Unknown,
            aumid: None,
            package_family_name: None,
            is_uwp: false,
        };
        event.source_application = Some(app.clone());
        event.destination_application = Some(app.clone());

        let ctx = EmitContext {
            agent_id: "AGENT-TEST".to_string(),
            session_id: 1,
            user_sid: "S-1-5-18".to_string(),
            user_name: "SYSTEM".to_string(),
            machine_name: None,
        };

        emit_audit(&ctx, &mut event);
        assert_eq!(
            event.source_application.as_ref().unwrap().image_path,
            r"C:\Windows\notepad.exe"
        );
        assert_eq!(
            event.destination_application.as_ref().unwrap().image_path,
            r"C:\Windows\notepad.exe"
        );
    }
}
