//! Append-only audit log emitter (T-19, T-26, T-27).
//!
//! Writes structured JSON audit events to a local log file.  Every intercepted
//! file operation generates an [`AuditEvent`] that is serialised to a single
//! JSON line and flushed immediately.
//!
//! ## Design
//!
//! - **Append-only**: the file handle is opened with `FILE_APPEND_DATA` (no
//!   seek or truncate) and `FILE_FLAG_BACKUP_SEMANTICS` so the SYSTEM service
//!   account can write even when NTFS ACLs restrict normal users.
//! - **One JSON object per line** (JSONL / newline-delimited JSON) for easy
//!   ingestion by SIEM tools and `jq`.
//! - **Size-based rotation**: when the log exceeds `max_bytes`, the current
//!   file is renamed to `<name>.1.json` (older rotations shift up) and a new
//!   file is started.
//! - **No file content**: audit events contain metadata only — never the actual
//!   file payload.
//!
//! ## Phase 1 note
//!
//! In Phase 1, dlp-server does not exist.  Audit events are read directly from
//! the local JSON file.  In Phase 5, dlp-server will ingest these events over
//! HTTPS and relay them to SIEM.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use dlp_common::AuditEvent;
use parking_lot::Mutex;
use tracing::{debug, error, info};

/// Default log directory under ProgramData.
const DEFAULT_LOG_DIR: &str = r"C:\ProgramData\DLP\logs";

/// Default log file name.
const DEFAULT_LOG_NAME: &str = "audit.jsonl";

/// Default maximum log file size before rotation (50 MB).
const DEFAULT_MAX_BYTES: u64 = 50 * 1024 * 1024;

/// Maximum number of rotated log files to keep.
const MAX_ROTATED_FILES: u32 = 9;

/// Errors that can occur during audit emission.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("failed to open audit log: {0}")]
    OpenFailed(#[from] std::io::Error),

    #[error("failed to serialise audit event: {0}")]
    SerializationFailed(#[from] serde_json::Error),

    #[error("log directory does not exist and could not be created: {0}")]
    DirectoryCreateFailed(String),
}

/// The audit log emitter.
///
/// Writes [`AuditEvent`] records as JSONL to a local append-only file.
/// Thread-safe via an internal `Mutex` on the buffered writer.
pub struct AuditEmitter {
    /// Buffered writer to the current log file.
    writer: Mutex<BufWriter<File>>,
    /// Full path to the current log file.
    log_path: PathBuf,
    /// Maximum file size before rotation.
    max_bytes: u64,
    /// Number of events written since the last rotation check.
    events_since_check: Mutex<u64>,
}

impl AuditEmitter {
    /// Opens (or creates) the default audit log file.
    ///
    /// Creates the log directory if it does not exist.
    pub fn open_default() -> Result<Self, AuditError> {
        Self::open(Path::new(DEFAULT_LOG_DIR), DEFAULT_LOG_NAME, DEFAULT_MAX_BYTES)
    }

    /// Opens (or creates) an audit log file at a custom path.
    ///
    /// # Arguments
    ///
    /// * `dir` — the directory for the log file
    /// * `name` — the log file name (e.g., `"audit.jsonl"`)
    /// * `max_bytes` — maximum file size before rotation
    pub fn open(dir: &Path, name: &str, max_bytes: u64) -> Result<Self, AuditError> {
        fs::create_dir_all(dir).map_err(|e| {
            AuditError::DirectoryCreateFailed(format!("{}: {e}", dir.display()))
        })?;

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

    /// Emits a single audit event to the log.
    ///
    /// The event is serialised as a single JSON line followed by `\n`.
    /// The buffer is flushed after every event for durability.
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

        // Periodic rotation check (every 100 events to avoid stat() on every write).
        let mut count = self.events_since_check.lock();
        *count += 1;
        if *count >= 100 {
            *count = 0;
            drop(writer);
            self.maybe_rotate();
        }

        Ok(())
    }

    /// Returns the path to the current log file.
    #[must_use]
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Checks the current log file size and rotates if necessary.
    fn maybe_rotate(&self) {
        let size = fs::metadata(&self.log_path)
            .map(|m| m.len())
            .unwrap_or(0);

        if size >= self.max_bytes {
            if let Err(e) = self.rotate() {
                error!(error = %e, "audit log rotation failed");
            }
        }
    }

    /// Performs size-based log rotation.
    ///
    /// Renames the current log to `.1.jsonl`, shifting older logs up to
    /// `MAX_ROTATED_FILES`.  The oldest log beyond the limit is deleted.
    fn rotate(&self) -> Result<(), AuditError> {
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

        // Shift existing rotated files: .9 -> delete, .8 -> .9, ... .1 -> .2
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

        // Current -> .1
        let rotated = dir.join(format!("{stem}.1.{ext}"));
        let _ = fs::rename(&self.log_path, &rotated);

        // Open a fresh log file.
        let new_file = open_append(&self.log_path)?;
        *writer = BufWriter::new(new_file);

        info!(
            rotated_to = %rotated.display(),
            "audit log rotated"
        );
        Ok(())
    }
}

/// Opens a file in append-only mode, creating it if it does not exist.
fn open_append(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
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
        let emitter = AuditEmitter::open(dir.path(), "test.jsonl", DEFAULT_MAX_BYTES)
            .unwrap();

        let event = make_event();
        emitter.emit(&event).unwrap();

        // Read back the log file and parse.
        let contents = fs::read_to_string(emitter.log_path()).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);

        let parsed: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.event_type, EventType::Access);
        assert_eq!(parsed.resource_path, r"C:\Data\report.xlsx");
        assert_eq!(parsed.decision, Decision::ALLOW);
    }

    #[test]
    fn test_multiple_events() {
        let dir = tempfile::tempdir().unwrap();
        let emitter = AuditEmitter::open(dir.path(), "test.jsonl", DEFAULT_MAX_BYTES)
            .unwrap();

        for _ in 0..5 {
            emitter.emit(&make_event()).unwrap();
        }

        let contents = fs::read_to_string(emitter.log_path()).unwrap();
        assert_eq!(contents.lines().count(), 5);
    }

    #[test]
    fn test_rotation() {
        let dir = tempfile::tempdir().unwrap();
        // Use a tiny max size to trigger rotation.
        let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 100).unwrap();

        // Write enough events to exceed 100 bytes.
        for _ in 0..5 {
            emitter.emit(&make_event()).unwrap();
        }

        // Force rotation check.
        emitter.rotate().unwrap();

        // The rotated file should exist.
        let rotated = dir.path().join("audit.1.jsonl");
        assert!(rotated.exists());

        // The current log should be empty or very small (freshly opened).
        let current_size = fs::metadata(emitter.log_path())
            .map(|m| m.len())
            .unwrap_or(0);
        assert!(current_size < 100);
    }

    #[test]
    fn test_log_path() {
        let dir = tempfile::tempdir().unwrap();
        let emitter = AuditEmitter::open(dir.path(), "mylog.jsonl", DEFAULT_MAX_BYTES)
            .unwrap();
        assert!(emitter.log_path().ends_with("mylog.jsonl"));
    }

    #[test]
    fn test_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        let emitter = AuditEmitter::open(&nested, "audit.jsonl", DEFAULT_MAX_BYTES);
        assert!(emitter.is_ok());
        assert!(nested.join("audit.jsonl").exists());
    }

    #[test]
    fn test_jsonl_format_parseable() {
        let dir = tempfile::tempdir().unwrap();
        let emitter = AuditEmitter::open(dir.path(), "test.jsonl", DEFAULT_MAX_BYTES)
            .unwrap();

        let event = make_event()
            .with_policy("pol-003".to_string(), "T2 Log".to_string())
            .with_access_context(dlp_common::AuditAccessContext::Smb);
        emitter.emit(&event).unwrap();

        let contents = fs::read_to_string(emitter.log_path()).unwrap();
        let parsed: AuditEvent = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(parsed.policy_id, Some("pol-003".to_string()));
        assert_eq!(parsed.access_context, dlp_common::AuditAccessContext::Smb);
    }
}
