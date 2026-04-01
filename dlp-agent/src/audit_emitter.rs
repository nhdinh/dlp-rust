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
//!
//! ## Audit enrichment helpers
//!
//! [`get_application_metadata`] and [`get_resource_owner`] are provided for
//! call sites that construct [`AuditEvent`]s.  They use Windows APIs
//! (`GetModuleFileNameExW`, the Windows Crypto API for SHA-256,
//! `GetNamedSecurityInfoW` + `ConvertSidToStringSidW`) and return `None`
//! gracefully on any failure, so audit emission is never blocked by enrichment.

#[cfg(windows)]
mod audit_enrichment {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, OWNER_SECURITY_INFORMATION,
    };
    use windows::Win32::Security::Cryptography::{
        CryptAcquireContextW, CryptCreateHash, CryptDestroyHash, CryptGetHashParam,
        CryptHashData, CryptReleaseContext, CALG_SHA_256, CRYPT_VERIFYCONTEXT,
        HP_HASHVAL, HCRYPTHASH, HCRYPTPROV, PROV_RSA_FULL,
    };
    use windows::Win32::System::Threading::{
        GetModuleFileNameExW, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_VM_READ,
    };

    /// Returns the full path and SHA-256 hex digest of the executable for `pid`.
    ///
    /// Uses `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)`,
    /// `GetModuleFileNameExW`, and the Windows Crypto API for hashing.
    /// Returns `(None, None)` on any failure so callers always make progress.
    pub fn get_application_metadata(
        pid: u32,
    ) -> (Option<String>, Option<String>) {
        // Open the target process.
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            )
        };

        let Some(handle) = process.ok() else {
            return (None, None);
        };

        // SAFETY: handle is a valid process handle from OpenProcess; we close it below.
        let path = get_process_path(handle);
        let hash = get_process_hash(handle);

        let _ = unsafe { CloseHandle(handle) };

        (path, hash)
    }

    /// Returns the owner SID string for a file at `path` via
    /// `GetNamedSecurityInfoW` + `ConvertSidToStringSidW`.
    pub fn get_resource_owner(path: &str) -> Option<String> {
        use windows::Win32::Foundation::HLOCAL;
        use windows::Win32::Security::SE_FILE_OBJECT;

        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        // SAFETY: path_wide is a valid null-terminated UTF-16 string.
        let mut owner_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let result = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR::from_raw(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut owner_ptr,
            )
        };

        if result.is_err() {
            return None;
        }

        // SAFETY: GetNamedSecurityInfoW allocated a SID via LocalAlloc on success.
        let sid_ptr = windows::Win32::Security::PSID(owner_ptr);
        let sid_str = unsafe { sid_to_string(sid_ptr) };
        let _ = unsafe { LocalFree(HLOCAL(owner_ptr)) };

        sid_str
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// Reads the process executable path via `GetModuleFileNameExW`.
    fn get_process_path(handle: HANDLE) -> Option<String> {
        let mut buf = vec![0u16; 512];

        // SAFETY: handle is a valid process handle; buf has capacity.
        let len = unsafe {
            GetModuleFileNameExW(
                handle,
                None,
                windows::core::PWSTR(buf.as_mut_ptr()),
                buf.len() as u32,
            )
        };

        if len == 0 {
            return None;
        }

        let result = String::from_utf16_lossy(&buf[..len as usize]);
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    /// Computes SHA-256 of the process image bytes.
    fn get_process_hash(handle: HANDLE) -> Option<String> {

        // Acquire a crypto context (no key container needed for hashing).
        // SAFETY: no key container is modified; this is read-only hashing.
        let mut prov: HCRYPTPROV = HCRYPTPROV::default();
        let acquired = unsafe {
            CryptAcquireContextW(
                &mut prov,
                None,
                None,
                PROV_RSA_FULL,
                CRYPT_VERIFYCONTEXT,
            )
        };
        if acquired.is_err() {
            return None;
        }

        let hash = compute_module_hash(handle, prov);

        // SAFETY: prov was obtained from CryptAcquireContextW above.
        let _ = unsafe { CryptReleaseContext(prov, 0) };

        hash
    }

    /// Reads the PE headers via `ReadProcessMemory` to find the image size,
    /// then reads the image and hashes it.
    fn compute_module_hash(handle: HANDLE, prov: HCRYPTPROV) -> Option<String> {
        use windows::Win32::System::Memory::ReadProcessMemory;

        // Read the DOS header to get the PE offset.
        let mut dos_header = [0u8; 64];
        let mut bytes_read = 0usize;

        // SAFETY: handle is a valid process handle; dos_header is valid for writes.
        if unsafe {
            ReadProcessMemory(
                handle,
                Some(std::ptr::null_mut().cast()),
                dos_header.as_mut_ptr().cast(),
                dos_header.len(),
                Some(&mut bytes_read),
            )
        }
        .is_err()
        {
            return None;
        }

        // e_lfanew at offset 0x3C.
        let pe_offset = u32::from_le_bytes([dos_header[0x3C], dos_header[0x3D], dos_header[0x3E], dos_header[0x3F]]);

        // Read the PE signature and Optional Header size.
        let mut pe_header_buf = [0u8; 24];
        if unsafe {
            ReadProcessMemory(
                handle,
                Some((pe_offset as usize).cast()),
                pe_header_buf.as_mut_ptr().cast(),
                pe_header_buf.len(),
                Some(&mut bytes_read),
            )
        }
        .is_err()
        {
            return None;
        }

        // Signature (4 bytes) + COFF header (20 bytes) + Optional Header magic (2 bytes).
        let optional_header_size = u32::from_le_bytes([pe_header_buf[20], pe_header_buf[21], pe_header_buf[22], pe_header_buf[23]]);

        // Optional header size field is at offset 0x14 within the optional header.
        let mut size_of_image_buf = [0u8; 2];
        if unsafe {
            ReadProcessMemory(
                handle,
                Some(((pe_offset + 24 + 0x14) as usize).cast()),
                size_of_image_buf.as_mut_ptr().cast(),
                2,
                Some(&mut bytes_read),
            )
        }
        .is_err()
        {
            return None;
        }

        // SizeOfImage is at offset 0x50 in the PE+ (64-bit) optional header.
        // For PE32 (32-bit) it's at 0x38.  We try PE+ first (more common for 64-bit agents).
        let size_of_image_offset = pe_offset + 24 + 0x50; // PE+ offset
        let mut size_of_image = 0u32;

        if unsafe {
            ReadProcessMemory(
                handle,
                Some((size_of_image_offset as usize).cast()),
                (&mut size_of_image as *mut u32).cast(),
                4,
                Some(&mut bytes_read),
            )
        }
        .is_err()
        {
            // Try PE32 offset as fallback.
            let size_of_image_offset32 = pe_offset + 24 + 0x38;
            if unsafe {
                ReadProcessMemory(
                    handle,
                    Some((size_of_image_offset32 as usize).cast()),
                    (&mut size_of_image as *mut u32).cast(),
                    4,
                    Some(&mut bytes_read),
                )
            }
            .is_err()
            {
                return None;
            }
        }

        // Read the full image into a buffer (up to 64 MB to limit memory use).
        let image_size = size_of_image.min(64 * 1024 * 1024);
        let mut image_buf = vec![0u8; image_size as usize];

        // SAFETY: handle is valid; image_buf is valid for writes.
        if unsafe {
            ReadProcessMemory(
                handle,
                Some(std::ptr::null_mut().cast()),
                image_buf.as_mut_ptr().cast(),
                image_size,
                Some(&mut bytes_read),
            )
        }
        .is_err()
        {
            return None;
        }

        // Create a SHA-256 hash and hash the image bytes.
        let mut hash_handle: HCRYPTHASH = HCRYPTHASH::default();
        // SAFETY: prov is a valid crypto context from CryptAcquireContextW.
        if unsafe { CryptCreateHash(prov, CALG_SHA_256, None, 0, &mut hash_handle) }.is_err() {
            return None;
        }

        let result = hash_and_encode(&mut hash_handle, &image_buf[..bytes_read]);

        // SAFETY: hash_handle was created by CryptCreateHash above.
        let _ = unsafe { CryptDestroyHash(hash_handle) };

        result
    }

    /// Adds data to a hash and returns the hex string.
    fn hash_and_encode(hash: &mut HCRYPTHASH, data: &[u8]) -> Option<String> {
        // SAFETY: hash is a valid hash handle from CryptCreateHash; data is valid.
        if unsafe { CryptHashData(*hash, data, None) }.is_err() {
            return None;
        }

        // Get the hash value.
        let mut hash_bytes = [0u8; 64]; // SHA-256 = 32 bytes; SHA-1 = 20 bytes.
        let mut hash_len = hash_bytes.len() as u32;

        // SAFETY: hash is valid; hash_bytes has capacity for any standard hash.
        if unsafe {
            CryptGetHashParam(
                *hash,
                HP_HASHVAL,
                Some(hash_bytes.as_mut_ptr()),
                &mut hash_len,
                0,
            )
        }
        .is_err()
        {
            return None;
        }

        Some(hex_encode(&hash_bytes[..hash_len as usize]))
    }

    /// Converts a `PSID` to a string via `ConvertSidToStringSidW`.
    fn sid_to_string(psid: windows::Win32::Security::PSID) -> Option<String> {
        let mut buf = vec![0u16; 512];

        // SAFETY: psid is a valid SID; buf has capacity for any SID string.
        let ok = unsafe {
            ConvertSidToStringSidW(psid, &mut windows::core::PWSTR(buf.as_mut_ptr())).is_ok()
        };

        if !ok {
            return None;
        }

        let result = String::from_utf16_lossy(&buf)
            .trim_end_matches('\0')
            .to_string();
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    /// Lowercase hex encoding (matching Windows Crypto API output convention).
    fn hex_encode(bytes: &[u8]) -> String {
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut acc, &b| {
                acc.push_str(&format!("{:02x}", b));
                acc
            })
    }
}

#[cfg(not(windows))]
mod audit_enrichment {
    /// No-op on non-Windows platforms.
    pub fn get_application_metadata(_pid: u32) -> (Option<String>, Option<String>) {
        (None, None)
    }

    /// No-op on non-Windows platforms.
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
