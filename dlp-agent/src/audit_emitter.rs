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
//! ## Audit Enrichment
//!
//! [`get_application_metadata`] and [`get_resource_owner`] are stubbed in this build
//! pending resolution of the correct `windows` crate feature paths. They return `None`
//! so audit emission is never blocked by enrichment failures.

/// Stubbed audit enrichment — returns None until windows crate features are resolved.
mod audit_enrichment {
    /// Returns `(None, None)` — enrichment not yet wired.
    pub fn get_application_metadata(_pid: u32) -> (Option<String>, Option<String>) {
        (None, None)
    }

    /// Returns `None` — enrichment not yet wired.
    pub fn get_resource_owner(_path: &str) -> Option<String> {
        None
    }
}

pub use audit_enrichment::{get_application_metadata, get_resource_owner};

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use dlp_common::AuditEvent;
use parking_lot::Mutex;
use tracing::{debug, error, info};

const DEFAULT_LOG_DIR: &str = r"C:\ProgramData\DLP\logs";
const DEFAULT_LOG_NAME: &str = "audit.jsonl";
const DEFAULT_MAX_BYTES: u64 = 50 * 1024 * 1024;
const MAX_ROTATED_FILES: u32 = 9;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("failed to open audit log: {0}")]
    OpenFailed(#[from] std::io::Error),
    #[error("failed to serialise audit event: {0}")]
    SerializationFailed(#[from] serde_json::Error),
    #[error("log directory does not exist: {0}")]
    DirectoryCreateFailed(String),
}

pub struct AuditEmitter {
    writer: Mutex<BufWriter<File>>,
    log_path: PathBuf,
    max_bytes: u64,
    events_since_check: Mutex<u64>,
}

impl AuditEmitter {
    pub fn open_default() -> Result<Self, AuditError> {
        Self::open(Path::new(DEFAULT_LOG_DIR), DEFAULT_LOG_NAME, DEFAULT_MAX_BYTES)
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

    fn rotate(&self) -> Result<(), AuditError> {
        let mut writer = self.writer.lock();
        writer.flush()?;
        let dir = self.log_path.parent().unwrap_or(Path::new("."));
        let stem = self.log_path.file_stem().and_then(|s| s.to_str()).unwrap_or("audit");
        let ext = self.log_path.extension().and_then(|s| s.to_str()).unwrap_or("jsonl");
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
        for _ in 0..5 { emitter.emit(&make_event()).unwrap(); }
        let contents = fs::read_to_string(emitter.log_path()).unwrap();
        assert_eq!(contents.lines().count(), 5);
    }

    #[test]
    fn test_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 100).unwrap();
        for _ in 0..5 { emitter.emit(&make_event()).unwrap(); }
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
}
