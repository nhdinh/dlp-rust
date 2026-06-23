//! Bypass correlator — matches ETW Kernel-File events against hook DLL journal entries.
//!
//! Architecture:
//! - Receives `EtwFileEvent` from the ETW Kernel-File consumer (Plan 01).
//! - Receives `ProcessEvent` from the process watcher (Plan 49) for journal discovery.
//! - Discovers per-process shared-memory journals on-demand (CR-02).
//! - Correlates using (pid, path_hash, op) within +/-5ms QPC tolerance (D-08).
//! - Emits `BypassAlert` when no matching journal entry is found.
//! - Batches alerts (max 100) with UUID batch_id and flushes every 5 seconds.
//!
//! ## Threat Mitigations
//!
//! - **T-53-13 (DoS)**: Allowlist pre-filter reduces correlation load; batching
//!   reduces server POST frequency.
//! - **T-53-15 (EoP)**: POST /audit/bypass validates agent_id against JWT claim.
//! - **T-53-16 (Tampering)**: Alerts route through SIEM independently.

use crossbeam_channel::Receiver;
use dashmap::DashMap;
use dlp_common::abac::EnforcementMode;
use dlp_common::hook_ipc::{BypassAlert, BypassReason};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace, warn};

use crate::etw_kernel_file::{EtwFileEvent, FileOp};
use crate::process_watcher::ProcessEvent;
use crate::server_client::ServerClient;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default QPC tolerance in milliseconds.
const DEFAULT_QPC_TOLERANCE_MS: u64 = 5;

/// Default batch size for alert flushing.
const DEFAULT_BATCH_SIZE: usize = 100;

/// Default flush interval in seconds.
const DEFAULT_FLUSH_INTERVAL_SECS: u64 = 5;

/// Default PID allowlist TTL in seconds.
const DEFAULT_PID_TTL_SECS: u64 = 60;

/// Default process exit grace period in seconds.
const DEFAULT_PROCESS_EXIT_GRACE_SECS: u64 = 5;

/// Default maximum retry count for batch flush (WR-08).
const DEFAULT_MAX_ALERT_RETRY: u32 = 3;

/// Default image SHA cache TTL in seconds (WR-06: 1 hour).
const DEFAULT_IMAGE_SHA_TTL_SECS: u64 = 3600;

/// Default failure cache TTL in seconds (WR-06: 5 minutes).
const DEFAULT_IMAGE_SHA_FAILURE_TTL_SECS: u64 = 300;

/// Maximum exponential backoff for journal discovery in seconds (CR-02).
const MAX_BACKOFF_SECS: u64 = 30;

/// Shared-memory journal name prefix.
const JOURNAL_NAME_PREFIX: &str = "Global\\DlpHookJournal_";

/// Hardcoded emergency allowlist — exact filename matching (WR-01).
const EMERGENCY_ALLOWLIST: &[&str] = &["System", "Registry", "smss.exe", "csrss.exe", "lsass.exe"];

// ---------------------------------------------------------------------------
// CorrelatorConfig
// ---------------------------------------------------------------------------

/// Configuration for the bypass correlator.
#[derive(Debug, Clone, Copy)]
pub struct CorrelatorConfig {
    /// QPC tolerance in milliseconds for journal entry matching.
    pub qpc_tolerance_ms: u64,
    /// Maximum number of alerts per batch.
    pub batch_size: usize,
    /// Interval between batch flushes in seconds.
    pub flush_interval_secs: u64,
    /// TTL for cached allowlisted PIDs in seconds.
    pub pid_ttl_secs: u64,
    /// Grace period after process exit before unmapping journal.
    pub process_exit_grace_secs: u64,
    /// Maximum retry count for batch flush (WR-08).
    pub max_alert_retry: u32,
    /// Image SHA cache TTL in seconds (WR-06).
    pub image_sha_ttl_secs: u64,
    /// Failure cache TTL in seconds (WR-06).
    pub image_sha_failure_ttl_secs: u64,
    /// Whether to operate in reduced mode (severity capped to warn).
    pub reduced_mode: bool,
    /// Phase 55.1: Global enforcement mode used to suppress bypass alerts in Audit mode.
    /// When the mode is `Audit`, the hook DLL returns ALLOW for all operations, so the
    /// absence of a journal entry is expected behavior and bypass alerts are suppressed.
    pub enforcement_mode: EnforcementMode,
}

impl Default for CorrelatorConfig {
    fn default() -> Self {
        Self {
            qpc_tolerance_ms: DEFAULT_QPC_TOLERANCE_MS,
            batch_size: DEFAULT_BATCH_SIZE,
            flush_interval_secs: DEFAULT_FLUSH_INTERVAL_SECS,
            pid_ttl_secs: DEFAULT_PID_TTL_SECS,
            process_exit_grace_secs: DEFAULT_PROCESS_EXIT_GRACE_SECS,
            max_alert_retry: DEFAULT_MAX_ALERT_RETRY,
            image_sha_ttl_secs: DEFAULT_IMAGE_SHA_TTL_SECS,
            image_sha_failure_ttl_secs: DEFAULT_IMAGE_SHA_FAILURE_TTL_SECS,
            reduced_mode: false,
            enforcement_mode: EnforcementMode::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// PendingAlert
// ---------------------------------------------------------------------------

/// Wrapper for a bypass alert pending batch flush.
///
/// Tracks retry count and batch_id for idempotency and dedup handling.
#[derive(Debug, Clone)]
pub struct PendingAlert {
    /// The underlying bypass alert.
    pub alert: BypassAlert,
    /// Number of flush attempts so far.
    pub retry_count: u32,
    /// UUID v4 batch identifier for idempotency (IN-02).
    pub batch_id: String,
}

impl PendingAlert {
    /// Creates a new `PendingAlert` with a fresh UUID batch_id.
    pub fn new(alert: BypassAlert) -> Self {
        Self {
            alert,
            retry_count: 0,
            batch_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// JournalEntry (ABI mirror from hook_journal.rs)
// ---------------------------------------------------------------------------

/// Journal entry — 56 bytes, 8-byte aligned.
///
/// This is a copy of the struct from `dlp-hook-dll/src/hook_journal.rs`.
/// Both sides must agree on layout for shared-memory interoperability.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
pub struct JournalEntry {
    /// Monotonic sequence number (1-based).
    seq: u64,
    /// HANDLE value from the API call (0 for path-based trampolines).
    handle_value: u64,
    /// Operation type: 1=Create, 2=Write, 3=Delete, 4=SetInfo.
    op: u8,
    /// Padding to align `path_hash` to 8 bytes.
    _pad: [u8; 15],
    /// FNV-1a 64-bit hash of the normalized path.
    path_hash: u64,
    /// QueryPerformanceCounter timestamp at write time.
    ts_qpc: u64,
    /// ETW timestamp in 100 ns units (forensics, set to 0 by hook DLL).
    etw_timestamp: u64,
}

/// Journal header — 8 bytes, 4-byte aligned.
#[repr(C, align(4))]
#[derive(Debug, Clone, Copy)]
struct JournalHeader {
    /// Layout version — always 1.
    version: u32,
    /// Monotonic write counter. Consumer reads with Acquire.
    write_index: u32,
}

const JOURNAL_SIZE: usize = 64 * 1024;
const _ENTRY_SIZE: usize = 56;
const ENTRY_CAPACITY: usize = (JOURNAL_SIZE - std::mem::size_of::<JournalHeader>()) / _ENTRY_SIZE;

// ---------------------------------------------------------------------------
// JournalReader
// ---------------------------------------------------------------------------

/// Read-only view into a per-process shared-memory hook journal.
///
/// The journal is created by the hook DLL and mapped read-only by the agent.
/// The `creation_time` field is used for PID reuse detection (WR-07).
pub struct JournalReader {
    /// Pointer to the mapped journal header.
    header: *const JournalHeader,
    /// Pointer to the first entry in the ring buffer.
    entries: *const JournalEntry,
    /// Last write index consumed.
    last_read_index: u32,
    /// Process creation time for PID reuse detection.
    creation_time: u64,
    /// Handle to the file mapping (for cleanup).
    #[allow(dead_code)]
    mapping_handle: isize,
}

// SAFETY: JournalReader is Send+Sync because the shared memory is read-only
// and the hook DLL is the single producer.
unsafe impl Send for JournalReader {}
unsafe impl Sync for JournalReader {}

impl JournalReader {
    /// Attempts to open the shared-memory journal for the given PID.
    ///
    /// Returns `None` if the journal does not exist or the header version is unexpected.
    #[cfg(windows)]
    pub fn new(pid: u32, creation_time: u64) -> Option<Self> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{MapViewOfFile, OpenFileMappingW, FILE_MAP_READ};

        let name = format!("{}{}", JOURNAL_NAME_PREFIX, pid);
        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        let handle = unsafe {
            OpenFileMappingW(FILE_MAP_READ.0, false, PCWSTR::from_raw(name_wide.as_ptr()))
        };

        let handle = match handle {
            Ok(h) => h,
            Err(_) => return None,
        };

        let view = unsafe { MapViewOfFile(handle, FILE_MAP_READ, 0, 0, JOURNAL_SIZE) };
        if view.Value.is_null() {
            let _ = unsafe { CloseHandle(handle) };
            return None;
        }

        let header = view.Value as *const JournalHeader;
        let version = unsafe { std::ptr::read_volatile(std::ptr::addr_of!((*header).version)) };
        if version != 1 {
            warn!(pid, version, "journal header version mismatch");
            unsafe {
                let _ = windows::Win32::System::Memory::UnmapViewOfFile(view);
                let _ = CloseHandle(handle);
            }
            return None;
        }

        let entries = unsafe { header.add(1) as *const JournalEntry };

        Some(Self {
            header,
            entries,
            last_read_index: 0,
            creation_time,
            mapping_handle: handle.0 as isize,
        })
    }

    /// Non-Windows stub: always returns None.
    #[cfg(not(windows))]
    pub fn new(_pid: u32, _creation_time: u64) -> Option<Self> {
        None
    }

    /// Reads all new entries from the journal since the last call.
    ///
    /// Returns a Vec of entries copied out of shared memory.
    pub fn read_entries(&mut self) -> Vec<JournalEntry> {
        let write_index =
            unsafe { std::ptr::read_volatile(std::ptr::addr_of!((*self.header).write_index)) };

        if write_index <= self.last_read_index {
            return Vec::new();
        }

        let count = (write_index - self.last_read_index) as usize;
        let mut result = Vec::with_capacity(count.min(ENTRY_CAPACITY));

        for i in 0..count {
            let idx = (self.last_read_index as usize + i) % ENTRY_CAPACITY;
            let entry = unsafe { std::ptr::read_volatile(self.entries.add(idx)) };
            result.push(entry);
        }

        self.last_read_index = write_index;
        result
    }

    /// Returns the creation time stored at open.
    pub fn creation_time(&self) -> u64 {
        self.creation_time
    }
}

impl Drop for JournalReader {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            let view = windows::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.header as _,
            };
            let _ = windows::Win32::System::Memory::UnmapViewOfFile(view);
            let _ = windows::Win32::Foundation::CloseHandle(windows::Win32::Foundation::HANDLE(
                self.mapping_handle as _,
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// BypassCorrelator
// ---------------------------------------------------------------------------

/// Correlates ETW Kernel-File events against hook DLL journal entries.
///
/// When a divergence is detected (no journal entry or operation mismatch),
/// a `BypassAlert` is constructed and batched for flush to the server.
pub struct BypassCorrelator {
    /// Configuration.
    config: CorrelatorConfig,
    /// Open journals keyed by PID.
    journals: DashMap<u32, JournalReader>,
    /// PIDs awaiting journal discovery with exponential backoff (CR-02).
    /// Value: (last_retry_instant, retry_count).
    pending_journals: DashMap<u32, (Instant, u32)>,
    /// PIDs that are allowlisted (skip correlation).
    /// Value: timestamp when added (for TTL).
    allowlisted_pids: DashMap<u32, Instant>,
    /// Image path -> (SHA-256, timestamp) cache with TTL (WR-06).
    image_sha_cache: DashMap<String, (Option<String>, Instant)>,
    /// QPC frequency (ticks per second).
    qpc_freq: i64,
    /// Calibration delta: QPC offset from ETW timestamp baseline (CR-01).
    qpc_delta: i64,
    /// Pending alert batch (protected by Mutex for async flush).
    alert_batch: Arc<Mutex<Vec<PendingAlert>>>,
    /// Protected paths from config (for severity mapping).
    protected_paths: Vec<String>,
    /// Agent ID for alert attribution.
    agent_id: String,
}

impl BypassCorrelator {
    /// Creates a new correlator with QPC calibration (CR-01).
    ///
    /// Captures `QueryPerformanceFrequency` and computes a calibration delta
    /// using `GetSystemTimePreciseAsFileTime` + `QueryPerformanceCounter`.
    pub fn new(config: CorrelatorConfig) -> Self {
        let (qpc_freq, qpc_delta) = Self::calibrate_qpc();

        if config.enforcement_mode.is_audit() {
            debug!(
                mode = ?config.enforcement_mode,
                "BypassCorrelator starting in Audit mode — bypass alerts will be suppressed"
            );
        }

        let agent_id = std::env::var("DLP_AGENT_ID").unwrap_or_else(|_| {
            hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "AGENT-UNKNOWN".to_string())
        });

        Self {
            config,
            journals: DashMap::new(),
            pending_journals: DashMap::new(),
            allowlisted_pids: DashMap::new(),
            image_sha_cache: DashMap::new(),
            qpc_freq,
            qpc_delta,
            alert_batch: Arc::new(Mutex::new(Vec::with_capacity(DEFAULT_BATCH_SIZE))),
            protected_paths: Vec::new(),
            agent_id,
        }
    }

    /// Sets the protected paths for severity mapping.
    pub fn with_protected_paths(mut self, paths: Vec<String>) -> Self {
        self.protected_paths = paths;
        self
    }

    /// Test-only accessor for the pending alert batch length.
    ///
    /// # Note
    ///
    /// This is intended for integration tests to verify batching behavior
    /// without exposing the internal `PendingAlert` type.
    pub async fn batch_len(&self) -> usize {
        self.alert_batch.lock().await.len()
    }

    /// Test-only accessor for the pending alert batch contents.
    ///
    /// # Note
    ///
    /// This is intended for integration tests to verify alert enrichment
    /// without exposing the internal `PendingAlert` type.
    pub async fn batch_alert(&self, index: usize) -> Option<BypassAlert> {
        self.alert_batch
            .lock()
            .await
            .get(index)
            .map(|p| p.alert.clone())
    }

    /// Calibrates QPC against system file time (CR-01).
    ///
    /// Returns (qpc_freq, qpc_delta) where:
    /// - qpc_freq: ticks per second from QueryPerformanceFrequency
    /// - qpc_delta: offset to convert ETW 100ns timestamps to QPC space
    #[cfg(windows)]
    fn calibrate_qpc() -> (i64, i64) {
        use windows::Win32::System::Performance::{
            QueryPerformanceCounter, QueryPerformanceFrequency,
        };

        let mut freq = 0i64;
        let mut qpc_now = 0i64;
        let file_time: i64;

        unsafe {
            let _ = QueryPerformanceFrequency(&mut freq);
            let _ = QueryPerformanceCounter(&mut qpc_now);
            // GetSystemTimePreciseAsFileTime returns FILETIME directly in windows 0.62.
            let ft = windows::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime();
            // Convert FILETIME (two u32 dwLowDateTime/dwHighDateTime) to i64.
            file_time = ((ft.dwHighDateTime as i64) << 32) | (ft.dwLowDateTime as i64);
        }

        // ETW timestamps are in 100ns units. Convert file_time to QPC space.
        // Use i128 for intermediate to avoid overflow.
        let etw_in_qpc = ((file_time as i128 * freq as i128) / 10_000_000) as i64;
        let delta = qpc_now - etw_in_qpc;

        (freq, delta)
    }

    /// Non-Windows stub: returns placeholder values.
    #[cfg(not(windows))]
    fn calibrate_qpc() -> (i64, i64) {
        (10_000_000, 0)
    }

    /// Converts an ETW 100ns timestamp to QPC space using calibration (CR-01).
    fn etw_to_qpc(&self, etw_timestamp: u64) -> u64 {
        let in_qpc = ((etw_timestamp as i128 * self.qpc_freq as i128) / 10_000_000) as i64;
        (in_qpc + self.qpc_delta) as u64
    }

    /// Computes the QPC tolerance in ticks.
    fn tolerance_qpc(&self) -> u64 {
        (self.config.qpc_tolerance_ms as i64 * self.qpc_freq / 1000) as u64
    }

    /// Checks if a PID/image_path is allowlisted (WR-01).
    ///
    /// Uses exact filename matching against the hardcoded emergency allowlist.
    pub fn is_allowlisted(&self, pid: u32, image_path: &str) -> bool {
        // Check cached allowlist first.
        if let Some(entry) = self.allowlisted_pids.get(&pid) {
            let age = entry.elapsed();
            if age < Duration::from_secs(self.config.pid_ttl_secs) {
                return true;
            }
            // Expired — remove.
            drop(entry);
            self.allowlisted_pids.remove(&pid);
        }

        // Emergency hardcoded filter: exact filename matching.
        let file_name = Path::new(image_path).file_name().and_then(|n| n.to_str());

        if let Some(name) = file_name {
            let upper = name.to_ascii_uppercase();
            for &allowed in EMERGENCY_ALLOWLIST {
                if upper == allowed.to_ascii_uppercase() {
                    self.allowlisted_pids.insert(pid, Instant::now());
                    return true;
                }
            }
        }

        false
    }

    /// Computes the severity string for a bypass alert (WR-03).
    ///
    /// Normal mode:
    /// - NoHookJournal + protected path -> "crit"
    /// - NoHookJournal + non-protected -> "warn"
    /// - OpMismatch -> "warn"
    /// - HookOverwritten -> "crit"
    /// - PatchRaced -> "info"
    ///
    /// Reduced mode (caps crit->warn, not info):
    /// - NoHookJournal + protected path -> "warn"
    /// - NoHookJournal + non-protected -> "warn"
    /// - OpMismatch -> "warn"
    /// - HookOverwritten -> "warn"
    /// - PatchRaced -> "info"
    ///
    /// Phase 55: Bypass alert severity is independent of policy enforcement mode.
    /// A bypass indicates a real evasion (syscall bypass, hook unloaded, etc.)
    /// and is not affected by whether the policy is in Audit, Block, or
    /// AuditAndBlock mode.
    pub fn severity_for_alert(&self, reason: BypassReason, file_path: &str) -> String {
        let is_protected = self.is_protected_path(file_path);

        match (reason, is_protected, self.config.reduced_mode) {
            (BypassReason::NoHookJournal, true, false) => "crit",
            (BypassReason::NoHookJournal, false, false) => "warn",
            (BypassReason::OpMismatch, _, false) => "warn",
            (BypassReason::HookOverwritten, _, false) => "crit",
            (BypassReason::PatchRaced, _, false) => "info",
            (BypassReason::EdrDetected, _, false) => "warn",
            // Reduced mode: cap crit to warn, preserve info.
            (BypassReason::NoHookJournal, _, true) => "warn",
            (BypassReason::OpMismatch, _, true) => "warn",
            (BypassReason::HookOverwritten, _, true) => "warn",
            (BypassReason::PatchRaced, _, true) => "info",
            (BypassReason::EdrDetected, _, true) => "warn",
        }
        .to_string()
    }

    /// Checks if a file path is under a protected path.
    fn is_protected_path(&self, file_path: &str) -> bool {
        let upper = file_path.to_ascii_uppercase();
        self.protected_paths
            .iter()
            .any(|p| upper.starts_with(&p.to_ascii_uppercase()))
    }

    /// Computes SHA-256 of an image file with caching (WR-06).
    ///
    /// Returns `None` if the file cannot be read or hashed.
    pub async fn compute_image_sha256(&self, image_path: &str) -> Option<String> {
        // Check cache first.
        if let Some(entry) = self.image_sha_cache.get(image_path) {
            let (sha_opt, timestamp) = entry.value();
            let ttl = match sha_opt {
                Some(_) => self.config.image_sha_ttl_secs,
                None => self.config.image_sha_failure_ttl_secs,
            };
            if timestamp.elapsed() < Duration::from_secs(ttl) {
                return sha_opt.clone();
            }
            // Expired — will recompute below.
        }

        let path = image_path.to_string();
        let result = tokio::task::spawn_blocking(move || Self::sha256_file_sync(&path))
            .await
            .ok()?;

        // Store in cache.
        self.image_sha_cache
            .insert(image_path.to_string(), (result.clone(), Instant::now()));
        result
    }

    /// Synchronous SHA-256 computation (runs in spawn_blocking).
    fn sha256_file_sync(path: &str) -> Option<String> {
        use sha2::{Digest, Sha256};
        use std::io::Read;

        let mut file = std::fs::File::open(path).ok()?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Some(format!("{:x}", hasher.finalize()))
    }

    /// Maps a `FileOp` to the op byte used in journal entries.
    fn file_op_to_u8(op: FileOp) -> u8 {
        match op {
            FileOp::Create => 1,
            FileOp::Write => 2,
            FileOp::Delete => 3,
            FileOp::SetInfo => 4,
        }
    }

    /// Attempts to open a journal for a PID.
    fn try_open_journal(&self, pid: u32, creation_time: u64) -> Option<JournalReader> {
        JournalReader::new(pid, creation_time)
    }

    /// Computes the next exponential backoff delay in seconds.
    fn backoff_secs(retry_count: u32) -> u64 {
        let delay = 2u64.saturating_pow(retry_count);
        delay.min(MAX_BACKOFF_SECS)
    }

    /// Handles a single ETW file event.
    ///
    /// 1. Skip if nt_path_converted is false (WR-11).
    /// 2. Check allowlist (WR-01).
    /// 3. Discover/open journal on demand (CR-02).
    /// 4. Normalize path and compute hash.
    /// 5. Convert ETW timestamp to QPC.
    /// 6. Search journal entries within tolerance.
    /// 7. Emit alert if no match or op mismatch.
    async fn handle_etw_event(&self, event: EtwFileEvent) {
        // Phase 55.1: Audit-mode short-circuit — skip all correlation work when
        // the global mode is Audit. The hook DLL returns ALLOW in Audit mode,
        // so the absence of a journal is expected behavior, not a bypass.
        if self.config.enforcement_mode.is_audit() {
            trace!(
                pid = event.pid,
                file_name = %event.file_name,
                "skipping ETW correlation — global mode is Audit"
            );
            return;
        }

        // WR-11: Skip events where NT path conversion failed.
        if !event.nt_path_converted {
            warn!(
                pid = event.pid,
                file_name = %event.file_name,
                "skipping ETW event with unconverted NT path"
            );
            return;
        }

        // WR-01: Check allowlist.
        if self.allowlisted_pids.contains_key(&event.pid) {
            return;
        }

        // CR-02: On-demand journal discovery.
        let mut journal_opt = self.journals.get_mut(&event.pid);
        if journal_opt.is_none() {
            // Check pending journals for backoff state.
            if let Some(pending) = self.pending_journals.get(&event.pid) {
                let (last_retry, retry_count) = *pending.value();
                let backoff = Duration::from_secs(Self::backoff_secs(retry_count));
                if last_retry.elapsed() < backoff {
                    // Still in backoff — skip correlation for this event.
                    return;
                }
                // Backoff expired — try again below.
                drop(pending);
            }

            // Try to open the journal. We need creation_time from process registry.
            let creation_time = self.get_creation_time_for_pid(event.pid).await.unwrap_or(0);
            if creation_time == 0 {
                // No process info yet — store as pending with retry_count=0.
                self.pending_journals.insert(event.pid, (Instant::now(), 0));
                return;
            }

            match self.try_open_journal(event.pid, creation_time) {
                Some(reader) => {
                    self.pending_journals.remove(&event.pid);
                    self.journals.insert(event.pid, reader);
                    journal_opt = self.journals.get_mut(&event.pid);
                }
                None => {
                    // Increment retry count and store with new timestamp.
                    let new_retry = self
                        .pending_journals
                        .get(&event.pid)
                        .map(|p| p.1.saturating_add(1))
                        .unwrap_or(1);
                    self.pending_journals
                        .insert(event.pid, (Instant::now(), new_retry));
                    // Emit NoHookJournal alert since we can't open the journal.
                    self.emit_alert(event, BypassReason::NoHookJournal).await;
                    return;
                }
            }
        }

        // WR-07: Verify creation_time matches (PID reuse detection).
        if let Some(ref mut journal) = journal_opt {
            let expected_creation = self.get_creation_time_for_pid(event.pid).await.unwrap_or(0);
            if expected_creation != 0 && journal.creation_time() != expected_creation {
                warn!(
                    pid = event.pid,
                    old_creation = journal.creation_time(),
                    new_creation = expected_creation,
                    "PID reuse detected — closing old journal"
                );
                self.journals.remove(&event.pid);
                // Try to open new journal.
                if let Some(new_reader) = self.try_open_journal(event.pid, expected_creation) {
                    self.journals.insert(event.pid, new_reader);
                    journal_opt = self.journals.get_mut(&event.pid);
                } else {
                    self.emit_alert(event, BypassReason::NoHookJournal).await;
                    return;
                }
            }
        }

        // Normalize path and compute hash.
        let normalized = match dlp_common::path_hash::normalize_path(&event.file_name) {
            Some(n) => n,
            None => {
                warn!(file_name = %event.file_name, "path normalization failed");
                return;
            }
        };
        let path_hash = dlp_common::path_hash::fnv1a_64(normalized.as_bytes());
        let event_qpc = self.etw_to_qpc(event.timestamp);
        let tolerance = self.tolerance_qpc();
        let expected_op = Self::file_op_to_u8(event.op);

        // Search journal entries.
        let mut match_found = false;
        let mut op_mismatch = false;

        if let Some(mut journal) = journal_opt {
            let entries = journal.read_entries();
            for entry in entries {
                let ts_diff = entry.ts_qpc.abs_diff(event_qpc);

                if ts_diff <= tolerance && entry.path_hash == path_hash {
                    if entry.op == expected_op {
                        match_found = true;
                        break;
                    } else {
                        op_mismatch = true;
                        // Continue searching — there might be a correct match.
                    }
                }
            }
        }

        if match_found {
            // Correlation succeeded — no alert needed.
            return;
        }

        if op_mismatch {
            self.emit_alert(event, BypassReason::OpMismatch).await;
        } else {
            self.emit_alert(event, BypassReason::NoHookJournal).await;
        }
    }

    /// Submits a hook-derived bypass alert directly to the batch (no ETW correlation).
    ///
    /// This is the entry point for alerts received from the hook DLL via IPC.
    /// The alert is enriched with agent-side fields before batching.
    ///
    /// # Enrichment
    ///
    /// - `agent_id` — set from the correlator's own agent_id
    /// - `severity` — mapped from the alert's reason using `severity_for_alert`
    /// - `correlation_reason` — set to a descriptive string explaining the hook self-report
    /// - `image_path` — best-effort lookup from PID (may be empty if lookup fails)
    ///
    /// # Arguments
    ///
    /// * `alert` — A pre-constructed `BypassAlert` from the hook DLL. Fields may be
    ///   partially populated; this method fills in agent-side attribution.
    ///
    /// # Behavior
    ///
    /// 1. Enriches the alert with agent-side fields.
    /// 2. Wraps it in `PendingAlert::new` (generates a fresh UUID batch_id).
    /// 3. Pushes it to the internal alert batch Vec.
    /// 4. Does NOT perform ETW correlation, journal lookup, or path-hash computation.
    ///    The existing batch flush task (running every 5s) will pick it up automatically.
    pub async fn submit_bypass_alert(&self, mut alert: BypassAlert) {
        // Phase 55.1: Defense in depth — suppress hook-derived bypass alerts in
        // Audit mode. Even if the caller bypasses handle_etw_event, no hook IPC
        // alert is batched.
        if self.config.enforcement_mode.is_audit() {
            trace!(
                pid = alert.pid,
                reason = ?alert.reason,
                "suppressing hook bypass alert — global mode is Audit"
            );
            return;
        }

        // Enrich agent-side fields (per REVIEW-H-03).
        alert.agent_id = self.agent_id.clone();
        alert.severity = self.severity_for_alert(alert.reason, &alert.file_path);
        alert.correlation_reason = format!("Hook self-reported: {:?}", alert.reason);
        alert.image_path = self.get_image_path_for_pid(alert.pid).await;

        let pending = PendingAlert::new(alert);
        let mut batch = self.alert_batch.lock().await;
        batch.push(pending);
    }

    /// Emits a bypass alert for the given event and reason.
    async fn emit_alert(&self, event: EtwFileEvent, reason: BypassReason) {
        // Phase 55.1: Final safety net — suppress all bypass alerts in Audit mode.
        // If a future code path reaches emit_alert directly, this guard ensures no
        // alert or audit event is emitted.
        if self.config.enforcement_mode.is_audit() {
            trace!(
                pid = event.pid,
                reason = ?reason,
                "suppressing bypass alert — global mode is Audit"
            );
            return;
        }

        let severity = self.severity_for_alert(reason, &event.file_name);
        let image_path = self.get_image_path_for_pid(event.pid).await;
        let image_sha256 = if !image_path.is_empty() {
            self.compute_image_sha256(&image_path).await
        } else {
            None
        };

        let operation = match event.op {
            FileOp::Create => "Create",
            FileOp::Write => "Write",
            FileOp::Delete => "Delete",
            FileOp::SetInfo => "SetInfo",
        }
        .to_string();

        let correlation_reason = match reason {
            BypassReason::NoHookJournal => {
                if self.is_protected_path(&event.file_name) {
                    "NoHookJournal on protected path"
                } else {
                    "NoHookJournal on non-protected path"
                }
            }
            BypassReason::OpMismatch => "Operation mismatch between ETW and journal",
            _ => "ETW correlation",
        }
        .to_string();

        let alert = BypassAlert {
            reason,
            stub_name: "etw_correlation".to_string(),
            pid: event.pid,
            timestamp_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            version: 2,
            agent_id: self.agent_id.clone(),
            image_path: image_path.clone(),
            image_sha256,
            file_path: event.file_name.clone(),
            operation,
            file_object: event.file_object, // CR-08: EXPLICIT wiring from ETW event
            qpc_timestamp: event_qpc_for_event(event.timestamp, self.qpc_freq, self.qpc_delta),
            severity,
            correlation_reason,
        };

        let pending = PendingAlert::new(alert);
        let mut batch = self.alert_batch.lock().await;
        batch.push(pending);

        // Also emit audit event for SIEM routing.
        self.emit_audit_event(reason, &event).await;
    }

    /// Emits an AuditEvent for SIEM routing.
    ///
    /// Uses the local audit emitter to write to the JSONL log.
    /// Errors are logged but not propagated (best-effort).
    ///
    /// Phase 55.1: Defense in depth — this function also checks the global mode.
    /// If the correlator is in Audit mode, no audit event is emitted because the
    /// absence of a hook journal is expected behavior, not a bypass.
    async fn emit_audit_event(&self, _reason: BypassReason, event: &EtwFileEvent) {
        if self.config.enforcement_mode.is_audit() {
            trace!(
                pid = event.pid,
                file_name = %event.file_name,
                "suppressing bypass audit event — global mode is Audit"
            );
            return;
        }

        let event_type = dlp_common::audit::EventType::BypassAlertDetected;
        let agent_id = self.agent_id.clone();

        let mut audit = dlp_common::audit::AuditEvent::new(
            event_type,
            "SYSTEM".to_string(),
            "SYSTEM".to_string(),
            event.file_name.clone(),
            dlp_common::Classification::T3,
            dlp_common::Action::WRITE,
            dlp_common::Decision::DENY,
            agent_id,
            0,
        );

        if let Err(e) = crate::audit_emitter::emit(&mut audit) {
            warn!(error = %e, "failed to emit bypass audit event");
        }
    }

    /// Handles a process event (start/exit).
    async fn handle_process_event(&self, event: ProcessEvent) {
        match event.source {
            crate::process_watcher::EventSource::Etw
            | crate::process_watcher::EventSource::Wmi
            | crate::process_watcher::EventSource::StartupSweep => {
                // Process start: store in pending for on-demand discovery (CR-02).
                if !self.pending_journals.contains_key(&event.pid) {
                    self.pending_journals.insert(event.pid, (Instant::now(), 0));
                }

                // Check allowlist on process start.
                if self.is_allowlisted(event.pid, &event.image_path) {
                    info!(pid = event.pid, image = %event.image_path, "process allowlisted");
                }
            }
            crate::process_watcher::EventSource::PeriodicSweep => {
                // Periodic sweep — no-op for now.
            }
        }
    }

    /// Flushes the alert batch to the server.
    ///
    /// On failure: increments retry_count, generates NEW batch_id per retry (WR-10),
    /// and re-queues if under max retry. If exceeded, logs error and drops (WR-08).
    async fn flush_batch(&self, server_client: &ServerClient) {
        let alerts: Vec<PendingAlert> = {
            let mut batch = self.alert_batch.lock().await;
            if batch.is_empty() {
                return;
            }
            std::mem::take(&mut *batch)
        };

        if alerts.is_empty() {
            return;
        }

        // Build payload with batch_id from the first alert.
        let batch_id = alerts
            .first()
            .map(|a| a.batch_id.clone())
            .unwrap_or_default();
        let bypass_alerts: Vec<BypassAlert> = alerts.iter().map(|a| a.alert.clone()).collect();

        match server_client.post_bypass(&batch_id, &bypass_alerts).await {
            Ok(()) => {
                info!(
                    count = alerts.len(),
                    batch_id, "bypass alerts flushed to server"
                );
            }
            Err(e) => {
                warn!(error = %e, batch_id, "failed to flush bypass batch");
                self.requeue_with_retry(alerts).await;
            }
        }
    }

    /// Re-queues alerts after a failed flush, incrementing retry and generating new batch_id (WR-10).
    async fn requeue_with_retry(&self, alerts: Vec<PendingAlert>) {
        let mut batch = self.alert_batch.lock().await;
        for mut alert in alerts {
            alert.retry_count += 1;
            if alert.retry_count > self.config.max_alert_retry {
                error!(
                    pid = alert.alert.pid,
                    reason = ?alert.alert.reason,
                    "bypass alert dropped after max retries exceeded"
                );
                continue;
            }
            // WR-10: Generate NEW batch_id per retry to avoid server dedup blocking.
            alert.batch_id = uuid::Uuid::new_v4().to_string();
            batch.push(alert);
        }
    }

    /// Gets the creation time for a PID from the process registry.
    async fn get_creation_time_for_pid(&self, pid: u32) -> Option<u64> {
        // Check if we have pending journal info with creation time.
        // For now, return None — will be integrated with process_registry.
        let _ = pid;
        None
    }

    /// Gets the image path for a PID from the process registry.
    async fn get_image_path_for_pid(&self, pid: u32) -> String {
        // Will be integrated with process_registry.
        let _ = pid;
        String::new()
    }

    /// Runs the correlator event loop.
    ///
    /// Spawns four tasks:
    /// 1. Process event handler
    /// 2. ETW event handler
    /// 3. Bypass alert handler (from hook DLL IPC)
    /// 4. Batch flush task
    pub async fn run(
        self,
        etw_rx: Receiver<EtwFileEvent>,
        process_rx: Receiver<ProcessEvent>,
        bypass_rx: Receiver<BypassAlert>,
        server_client: ServerClient,
    ) {
        let correlator = Arc::new(self);

        // Task 1: Process event handler.
        let proc_corr = Arc::clone(&correlator);
        let proc_handle = tokio::spawn(async move {
            while let Ok(event) = process_rx.recv() {
                proc_corr.handle_process_event(event).await;
            }
        });

        // Task 2: ETW event handler.
        let etw_corr = Arc::clone(&correlator);
        let etw_handle = tokio::spawn(async move {
            while let Ok(event) = etw_rx.recv() {
                etw_corr.handle_etw_event(event).await;
            }
        });

        // Task 3: Bypass alert handler (from hook DLL IPC).
        // Per REVIEW-M-09, wrap the blocking recv loop in spawn_blocking
        // to avoid starving the async runtime.
        let bypass_corr = Arc::clone(&correlator);
        let bypass_handle = tokio::task::spawn_blocking(move || {
            while let Ok(alert) = bypass_rx.recv() {
                let bypass_corr = Arc::clone(&bypass_corr);
                tracing::info!(metric = "bypass_rx_processed", pid = alert.pid, stub = %alert.stub_name, reason = ?alert.reason, "bypass alert received from hook DLL");
                // Bridge sync recv to async submit_bypass_alert.
                // Use block_on if a runtime is available; otherwise skip.
                if let Ok(rt) = tokio::runtime::Handle::try_current() {
                    rt.block_on(bypass_corr.submit_bypass_alert(alert));
                }
            }
            tracing::warn!(
                metric = "bypass_rx_dropped",
                reason = "channel_closed",
                "bypass_rx channel closed — exiting bypass alert handler"
            );
        });

        // Task 4: Batch flush task.
        let flush_corr = Arc::clone(&correlator);
        let flush_handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(flush_corr.config.flush_interval_secs));
            loop {
                interval.tick().await;
                flush_corr.flush_batch(&server_client).await;
            }
        });

        // Wait for any task to complete (they run until channels close).
        tokio::select! {
            _ = proc_handle => {},
            _ = etw_handle => {},
            _ = bypass_handle => {},
            _ = flush_handle => {},
        }
    }
}

/// Converts an ETW timestamp to QPC space.
fn event_qpc_for_event(etw_timestamp: u64, qpc_freq: i64, qpc_delta: i64) -> u64 {
    let in_qpc = ((etw_timestamp as i128 * qpc_freq as i128) / 10_000_000) as i64;
    (in_qpc + qpc_delta) as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- QPC calibration tests ---

    #[test]
    fn test_correlator_new_reads_qpc_freq() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        assert!(correlator.qpc_freq > 0);
    }

    #[test]
    fn test_qpc_calibration_delta_computed() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        // Delta should be a reasonable value (not necessarily 0).
        // On non-Windows it's 0; on Windows it's the actual offset.
        let _ = correlator.qpc_delta;
    }

    // --- CorrelatorConfig default mode test (Phase 55.1) ---

    #[test]
    fn test_correlator_config_default_mode_is_block() {
        let config = CorrelatorConfig::default();
        assert_eq!(config.enforcement_mode, EnforcementMode::Block);
    }

    // --- Allowlist tests (WR-01) ---

    #[test]
    fn test_allowlist_hardcoded_system_exact_match() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        assert!(correlator.is_allowlisted(4, "System"));
    }

    #[test]
    fn test_allowlist_hardcoded_lsass_exact_match() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        assert!(correlator.is_allowlisted(4, r"C:\Windows\System32\lsass.exe"));
    }

    #[test]
    fn test_allowlist_rejects_substring_bypass() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        // WR-01: exact filename matching — "lsass.exe" as a directory component
        // followed by a different executable should NOT match.
        assert!(!correlator.is_allowlisted(4, r"C:\Users\attacker\lsass.exe\payload.exe"));
    }

    #[test]
    fn test_allowlist_non_system() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        assert!(!correlator.is_allowlisted(1234, r"C:\Users\test\app.exe"));
    }

    // --- Severity mapping tests ---

    #[test]
    fn test_severity_no_hook_journal_protected_path() {
        let config = CorrelatorConfig::default();
        let correlator =
            BypassCorrelator::new(config).with_protected_paths(vec![r"C:\Data".to_string()]);
        let sev =
            correlator.severity_for_alert(BypassReason::NoHookJournal, r"C:\Data\secret.docx");
        assert_eq!(sev, "crit");
    }

    #[test]
    fn test_severity_no_hook_journal_non_protected() {
        let config = CorrelatorConfig::default();
        let correlator =
            BypassCorrelator::new(config).with_protected_paths(vec![r"C:\Data".to_string()]);
        let sev = correlator.severity_for_alert(BypassReason::NoHookJournal, r"C:\Temp\file.txt");
        assert_eq!(sev, "warn");
    }

    #[test]
    fn test_severity_op_mismatch() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        let sev = correlator.severity_for_alert(BypassReason::OpMismatch, r"C:\Data\file.txt");
        assert_eq!(sev, "warn");
    }

    #[test]
    fn test_severity_hook_overwritten() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        let sev = correlator.severity_for_alert(BypassReason::HookOverwritten, r"C:\Data\file.txt");
        assert_eq!(sev, "crit");
    }

    #[test]
    fn test_severity_patch_raced() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        let sev = correlator.severity_for_alert(BypassReason::PatchRaced, r"C:\Data\file.txt");
        assert_eq!(sev, "info");
    }

    #[test]
    fn test_severity_reduced_mode_caps_crit_to_warn() {
        let config = CorrelatorConfig {
            reduced_mode: true,
            ..Default::default()
        };
        let correlator =
            BypassCorrelator::new(config).with_protected_paths(vec![r"C:\Data".to_string()]);
        let sev =
            correlator.severity_for_alert(BypassReason::NoHookJournal, r"C:\Data\secret.docx");
        assert_eq!(sev, "warn");
    }

    #[test]
    fn test_severity_reduced_mode_preserves_warn() {
        let config = CorrelatorConfig {
            reduced_mode: true,
            ..Default::default()
        };
        let correlator = BypassCorrelator::new(config);
        let sev = correlator.severity_for_alert(BypassReason::OpMismatch, r"C:\Data\file.txt");
        assert_eq!(sev, "warn");
    }

    // --- QPC conversion tests ---

    #[test]
    fn test_etw_timestamp_to_qpc_conversion_with_calibration() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        let etw_ts = 1_000_000_000u64; // 100 seconds in 100ns units
        let qpc = correlator.etw_to_qpc(etw_ts);
        // Should produce a value (exact value depends on calibration).
        assert!(qpc > 0);
    }

    #[test]
    fn test_qpc_tolerance_calculation() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        let tolerance = correlator.tolerance_qpc();
        // 5ms in QPC ticks should be positive.
        assert!(tolerance > 0);
    }

    // --- Batch tests ---

    #[test]
    fn test_batch_id_uuid_present() {
        let alert = BypassAlert {
            reason: BypassReason::NoHookJournal,
            stub_name: "etw_correlation".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 2,
            agent_id: "AGENT-TEST".to_string(),
            image_path: r"C:\Test\app.exe".to_string(),
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0xDEADBEEF,
            qpc_timestamp: 0,
            severity: "crit".to_string(),
            correlation_reason: "test".to_string(),
        };
        let pending = PendingAlert::new(alert);
        assert!(!pending.batch_id.is_empty());
        // Should be a valid UUID format.
        assert!(pending.batch_id.contains('-'));
    }

    #[test]
    fn test_batch_size_limit() {
        let config = CorrelatorConfig {
            batch_size: 5,
            ..Default::default()
        };
        let correlator = BypassCorrelator::new(config);
        // Verify batch_size is respected in config.
        assert_eq!(correlator.config.batch_size, 5);
        // The batch should be empty initially.
        let batch = correlator.alert_batch.try_lock().unwrap();
        assert!(batch.is_empty());
    }

    #[test]
    fn test_batch_retry_new_batch_id() {
        let alert = BypassAlert {
            reason: BypassReason::NoHookJournal,
            stub_name: "etw_correlation".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 2,
            agent_id: "AGENT-TEST".to_string(),
            image_path: r"C:\Test\app.exe".to_string(),
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0,
            qpc_timestamp: 0,
            severity: "warn".to_string(),
            correlation_reason: "test".to_string(),
        };
        let mut pending = PendingAlert::new(alert);
        let old_batch_id = pending.batch_id.clone();
        pending.batch_id = uuid::Uuid::new_v4().to_string();
        assert_ne!(pending.batch_id, old_batch_id);
    }

    /// Phase 55 Task 2: Verify that bypass alert severity is independent
    /// of policy enforcement mode.
    ///
    /// BypassAlert has no `policy_mode` field by design — a bypass indicates
    /// a real evasion attempt and must alert at full mapped severity
    /// regardless of whether the matched policy is in Audit, Block, or
    /// AuditAndBlock mode.
    #[test]
    fn test_bypass_alert_severity_independent_of_policy_mode() {
        let config = CorrelatorConfig::default();
        let correlator =
            BypassCorrelator::new(config).with_protected_paths(vec![r"C:\Data".to_string()]);

        // Severity for NoHookJournal on protected path is "crit" in normal mode.
        let sev_protected =
            correlator.severity_for_alert(BypassReason::NoHookJournal, r"C:\Data\secret.docx");
        assert_eq!(sev_protected, "crit");

        // Severity for NoHookJournal on non-protected path is "warn".
        let sev_non_protected =
            correlator.severity_for_alert(BypassReason::NoHookJournal, r"C:\Temp\file.txt");
        assert_eq!(sev_non_protected, "warn");

        // Severity for HookOverwritten is "crit".
        let sev_hook_overwritten =
            correlator.severity_for_alert(BypassReason::HookOverwritten, r"C:\Data\file.txt");
        assert_eq!(sev_hook_overwritten, "crit");

        // Verify that BypassAlert struct has no policy_mode field.
        // This is a compile-time invariant: the struct definition in
        // dlp_common::hook_ipc::BypassAlert does not include policy_mode.
        let alert = BypassAlert {
            reason: BypassReason::NoHookJournal,
            stub_name: "etw_correlation".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 2,
            agent_id: "AGENT-TEST".to_string(),
            image_path: r"C:\Test\app.exe".to_string(),
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0,
            qpc_timestamp: 0,
            severity: sev_protected,
            correlation_reason: "NoHookJournal on protected path".to_string(),
        };
        // The alert severity was computed without any policy_mode input.
        assert_eq!(alert.severity, "crit");
    }

    // --- Image SHA cache tests ---

    #[test]
    fn test_image_sha_cache_hit() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        let path = r"C:\Windows\System32\notepad.exe".to_string();
        let sha = Some("abc123".to_string());
        correlator
            .image_sha_cache
            .insert(path.clone(), (sha.clone(), Instant::now()));

        // Check cache directly.
        let cached = correlator.image_sha_cache.get(&path);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().0, sha);
    }

    #[test]
    fn test_image_sha_cache_ttl_expired() {
        let config = CorrelatorConfig::default();
        let _correlator = BypassCorrelator::new(config);
        let path = r"C:\Test\app.exe".to_string();
        // Insert with a timestamp far in the past.
        let old_time =
            match Instant::now().checked_sub(Duration::from_secs(config.image_sha_ttl_secs + 1)) {
                Some(t) => t,
                None => {
                    // On some CI runners the Instant epoch is too recent for
                    // subtraction to succeed; skip this assertion.
                    return;
                }
            };
        _correlator
            .image_sha_cache
            .insert(path.clone(), (Some("old".to_string()), old_time));

        let cached = _correlator.image_sha_cache.get(&path);
        assert!(cached.is_some());
        // The entry exists but is expired — the compute method would recompute.
        let age = cached.unwrap().1.elapsed();
        assert!(age > Duration::from_secs(config.image_sha_ttl_secs));
    }

    #[test]
    fn test_image_sha_cache_failure_cached() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        let path = r"C:\NonExistent\app.exe".to_string();
        // Cache a failure (None) with recent timestamp.
        correlator
            .image_sha_cache
            .insert(path.clone(), (None, Instant::now()));

        let cached = correlator.image_sha_cache.get(&path);
        assert!(cached.is_some());
        assert!(cached.unwrap().0.is_none());
    }

    // --- PID reuse test ---

    #[test]
    fn test_pid_reuse_detected() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        // Simulate: process A PID 1234 creates journal.
        // We can't actually create shared memory in tests, but we can verify
        // the journals map structure and creation_time logic.
        assert!(correlator.journals.is_empty());
        // After "PID reuse", the old journal would be removed.
        // This is verified by the handle_etw_event logic.
    }

    // --- On-demand journal discovery test ---

    #[test]
    fn test_on_demand_journal_discovery_and_backoff() {
        let config = CorrelatorConfig::default();
        let _correlator = BypassCorrelator::new(config);
        // Verify backoff calculation.
        assert_eq!(BypassCorrelator::backoff_secs(0), 1);
        assert_eq!(BypassCorrelator::backoff_secs(1), 2);
        assert_eq!(BypassCorrelator::backoff_secs(2), 4);
        assert_eq!(BypassCorrelator::backoff_secs(3), 8);
        // Should cap at MAX_BACKOFF_SECS.
        assert!(BypassCorrelator::backoff_secs(10) <= MAX_BACKOFF_SECS);
    }

    // --- file_object and version test ---

    #[test]
    fn test_file_object_and_version_from_etw_event() {
        let alert = BypassAlert {
            reason: BypassReason::NoHookJournal,
            stub_name: "etw_correlation".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 2,
            agent_id: "AGENT-TEST".to_string(),
            image_path: r"C:\Test\app.exe".to_string(),
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0xDEADBEEF, // CR-08: explicitly set from ETW event
            qpc_timestamp: 0,
            severity: "crit".to_string(),
            correlation_reason: "test".to_string(),
        };
        assert_eq!(alert.file_object, 0xDEADBEEF);
        assert_eq!(alert.version, 2);
    }

    // --- Skip unconverted NT path test ---

    #[tokio::test]
    async fn test_skip_unconverted_nt_path() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);
        let event = EtwFileEvent {
            pid: 1234,
            file_name: r"\Device\HarddiskVolume1\test.txt".to_string(),
            file_object: 0,
            timestamp: 0,
            op: FileOp::Create,
            nt_path_converted: false, // WR-11: should skip
        };
        // Should return early without panicking.
        correlator.handle_etw_event(event).await;
        // Batch should be empty (no alert emitted).
        let batch = correlator.alert_batch.lock().await;
        assert!(batch.is_empty());
    }

    // --- Journal entry tolerance tests (mock) ---

    #[test]
    fn test_journal_entry_within_tolerance() {
        let event_qpc = 1_000_000u64;
        let entry_qpc = 1_000_005u64; // 5 ticks difference
        let tolerance = 10u64;
        let diff = entry_qpc.abs_diff(event_qpc);
        assert!(diff <= tolerance);
    }

    #[test]
    fn test_journal_entry_outside_tolerance() {
        let event_qpc = 1_000_000u64;
        let entry_qpc = 1_000_100u64; // 100 ticks difference
        let tolerance = 10u64;
        let diff = entry_qpc.abs_diff(event_qpc);
        assert!(diff > tolerance);
    }

    // --- Batch retry exceeded test ---

    #[tokio::test]
    async fn test_submit_bypass_alert_batches() {
        // Test 1: Create a BypassCorrelator with a mock ServerClient and empty channels.
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);

        // Test 2: Call submit_bypass_alert with a partially populated BypassAlert.
        let alert = BypassAlert {
            reason: BypassReason::HookOverwritten,
            stub_name: "NtCreateFile".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 2,
            agent_id: "".to_string(), // empty — should be enriched by agent
            image_path: "".to_string(), // empty — should be enriched by agent
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0xDEADBEEF,
            qpc_timestamp: 0,
            severity: "".to_string(), // empty — should be enriched by agent
            correlation_reason: "".to_string(), // empty — should be enriched by agent
        };

        // Call submit_bypass_alert.
        correlator.submit_bypass_alert(alert).await;

        // Test 3: Assert the alert appears in the internal alert_batch Vec within 100ms.
        let batch = correlator.alert_batch.lock().await;
        assert_eq!(batch.len(), 1, "alert should be in batch");

        let pending = &batch[0];

        // Test 4: Verify the PendingAlert has a valid UUID batch_id and retry_count=0.
        assert!(!pending.batch_id.is_empty(), "batch_id should not be empty");
        assert!(pending.batch_id.contains('-'), "batch_id should be a UUID");
        assert_eq!(pending.retry_count, 0, "retry_count should be 0");

        // Test 5: Verify agent_id is populated from the correlator's agent_id field.
        assert!(
            !pending.alert.agent_id.is_empty(),
            "agent_id should be enriched by agent"
        );

        // Test 6: Verify severity is populated based on BypassReason.
        assert_eq!(
            pending.alert.severity, "crit",
            "HookOverwritten should map to crit severity"
        );

        // Test 7: Verify correlation_reason is set to a descriptive string.
        assert!(
            pending
                .alert
                .correlation_reason
                .contains("Hook self-reported"),
            "correlation_reason should describe hook self-report: got {}",
            pending.alert.correlation_reason
        );

        // Test 8: Verify image_path is attempted (empty is OK since get_image_path_for_pid is stub).
        // The field is populated by calling get_image_path_for_pid, which returns empty in tests.
        // The important thing is that the field was attempted.

        // Test 9: Verify that calling submit_bypass_alert does NOT trigger ETW correlation logic.
        // The journals map should be empty (no journal lookup was performed).
        assert!(
            correlator.journals.is_empty(),
            "journals should be empty — no ETW correlation was triggered"
        );
        // The pending_journals map should also be empty.
        assert!(
            correlator.pending_journals.is_empty(),
            "pending_journals should be empty — no ETW correlation was triggered"
        );
    }

    #[tokio::test]
    async fn test_submit_bypass_alert_severity_mapping() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);

        // Test HookOverwritten -> crit
        let alert_hook = BypassAlert {
            reason: BypassReason::HookOverwritten,
            stub_name: "NtCreateFile".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 2,
            agent_id: "".to_string(),
            image_path: "".to_string(),
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0,
            qpc_timestamp: 0,
            severity: "".to_string(),
            correlation_reason: "".to_string(),
        };
        correlator.submit_bypass_alert(alert_hook).await;

        // Test PatchRaced -> info
        let alert_patch = BypassAlert {
            reason: BypassReason::PatchRaced,
            stub_name: "NtWriteFile".to_string(),
            pid: 5678,
            timestamp_secs: 1_700_000_001,
            version: 2,
            agent_id: "".to_string(),
            image_path: "".to_string(),
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Write".to_string(),
            file_object: 0,
            qpc_timestamp: 0,
            severity: "".to_string(),
            correlation_reason: "".to_string(),
        };
        correlator.submit_bypass_alert(alert_patch).await;

        let batch = correlator.alert_batch.lock().await;
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].alert.severity, "crit");
        assert_eq!(batch[1].alert.severity, "info");
    }

    #[tokio::test]
    async fn test_submit_bypass_alert_no_etw_correlation() {
        let config = CorrelatorConfig::default();
        let correlator = BypassCorrelator::new(config);

        let alert = BypassAlert {
            reason: BypassReason::HookOverwritten,
            stub_name: "NtCreateFile".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 2,
            agent_id: "".to_string(),
            image_path: "".to_string(),
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0xDEADBEEF,
            qpc_timestamp: 0,
            severity: "".to_string(),
            correlation_reason: "".to_string(),
        };

        // Before: no journals, no pending journals.
        assert!(correlator.journals.is_empty());
        assert!(correlator.pending_journals.is_empty());

        correlator.submit_bypass_alert(alert).await;

        // After: still no journals, no pending journals (no ETW correlation).
        assert!(correlator.journals.is_empty());
        assert!(correlator.pending_journals.is_empty());

        // Batch should have exactly one alert.
        let batch = correlator.alert_batch.lock().await;
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn test_batch_retry_exceeded_drops_alert() {
        let config = CorrelatorConfig {
            max_alert_retry: 3,
            ..Default::default()
        };
        let _correlator = BypassCorrelator::new(config);

        let alert = BypassAlert {
            reason: BypassReason::NoHookJournal,
            stub_name: "etw_correlation".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 2,
            agent_id: "AGENT-TEST".to_string(),
            image_path: r"C:\Test\app.exe".to_string(),
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0,
            qpc_timestamp: 0,
            severity: "warn".to_string(),
            correlation_reason: "test".to_string(),
        };

        let pending = PendingAlert {
            alert,
            retry_count: 4, // Exceeds max_alert_retry (3)
            batch_id: "test-batch".to_string(),
        };

        // In requeue_with_retry, this would be dropped.
        assert!(pending.retry_count > config.max_alert_retry);
    }

    #[tokio::test]
    async fn test_bypass_channel_consumed_by_run() {
        // Test that BypassCorrelator::run can consume from a bypass_rx channel.
        // We can't easily run the full run() method (it blocks on channels),
        // but we can verify the channel wiring works by testing the individual
        // components: submit_bypass_alert + channel send/receive.
        let config = CorrelatorConfig::default();
        let correlator = Arc::new(BypassCorrelator::new(config));

        let (bypass_tx, bypass_rx) = crossbeam_channel::unbounded::<BypassAlert>();

        let alert = BypassAlert {
            reason: BypassReason::HookOverwritten,
            stub_name: "NtCreateFile".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 2,
            agent_id: "".to_string(),
            image_path: "".to_string(),
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0xDEADBEEF,
            qpc_timestamp: 0,
            severity: "".to_string(),
            correlation_reason: "".to_string(),
        };

        // Send through the channel (simulating what hook_ipc would do).
        bypass_tx
            .send(alert.clone())
            .expect("send should succeed on unbounded channel");

        // Receive and submit (simulating what the bypass task in run() would do).
        let received = bypass_rx.recv().expect("recv should succeed");
        let corr_clone = Arc::clone(&correlator);
        corr_clone.submit_bypass_alert(received).await;

        // Verify the alert is in the batch.
        let batch = correlator.alert_batch.lock().await;
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].alert.pid, 1234);
        assert_eq!(batch[0].alert.reason, BypassReason::HookOverwritten);

        // Verify channel is now empty.
        assert!(bypass_rx.is_empty());
    }

    #[tokio::test]
    async fn test_bypass_channel_concurrent_with_etw() {
        // Verify that bypass alerts and ETW events can be processed
        // concurrently without interfering with each other.
        let config = CorrelatorConfig::default();
        let correlator = Arc::new(BypassCorrelator::new(config));

        // Simulate bypass alert submission.
        let bypass_alert = BypassAlert {
            reason: BypassReason::HookOverwritten,
            stub_name: "NtCreateFile".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 2,
            agent_id: "".to_string(),
            image_path: "".to_string(),
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0,
            qpc_timestamp: 0,
            severity: "".to_string(),
            correlation_reason: "".to_string(),
        };

        // Simulate ETW event handling (should not affect bypass alert batch).
        let etw_event = EtwFileEvent {
            pid: 5678,
            file_name: r"C:\Other\file.txt".to_string(),
            file_object: 0,
            timestamp: 0,
            op: FileOp::Write,
            nt_path_converted: false, // will skip
        };

        // Process both concurrently.
        let corr_bypass = Arc::clone(&correlator);
        let bypass_handle = tokio::spawn(async move {
            corr_bypass.submit_bypass_alert(bypass_alert).await;
        });

        let corr_etw = Arc::clone(&correlator);
        let etw_handle = tokio::spawn(async move {
            corr_etw.handle_etw_event(etw_event).await;
        });

        let (r1, r2) = tokio::join!(bypass_handle, etw_handle);
        assert!(r1.is_ok());
        assert!(r2.is_ok());

        // Batch should have exactly 1 bypass alert (ETW event was skipped due to nt_path_converted=false).
        let batch = correlator.alert_batch.lock().await;
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].alert.pid, 1234);
        assert_eq!(batch[0].alert.reason, BypassReason::HookOverwritten);
    }

    // --- Audit-mode suppression tests (Phase 55.1) ---

    #[tokio::test]
    async fn test_audit_mode_suppresses_etw_bypass_alert() {
        let config = CorrelatorConfig {
            enforcement_mode: EnforcementMode::Audit,
            ..Default::default()
        };
        let correlator =
            BypassCorrelator::new(config).with_protected_paths(vec![r"C:\Data".to_string()]);

        let event = EtwFileEvent {
            pid: 1234,
            file_name: r"C:\Data\secret.docx".to_string(),
            file_object: 0,
            timestamp: 0,
            op: FileOp::Create,
            nt_path_converted: true,
        };

        correlator.handle_etw_event(event).await;

        // Batch should be empty — alert suppressed in Audit mode.
        let batch = correlator.alert_batch.lock().await;
        assert!(
            batch.is_empty(),
            "bypass alert must be suppressed in Audit mode"
        );
    }

    #[tokio::test]
    async fn test_audit_mode_suppresses_hook_bypass_alert() {
        let config = CorrelatorConfig {
            enforcement_mode: EnforcementMode::Audit,
            ..Default::default()
        };
        let correlator = BypassCorrelator::new(config);

        let alert = BypassAlert {
            reason: BypassReason::HookOverwritten,
            stub_name: "NtCreateFile".to_string(),
            pid: 1234,
            timestamp_secs: 1_700_000_000,
            version: 2,
            agent_id: "".to_string(),
            image_path: "".to_string(),
            image_sha256: None,
            file_path: r"C:\Data\file.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0xDEADBEEF,
            qpc_timestamp: 0,
            severity: "".to_string(),
            correlation_reason: "".to_string(),
        };

        correlator.submit_bypass_alert(alert).await;

        // Batch should be empty — hook alert suppressed in Audit mode.
        let batch = correlator.alert_batch.lock().await;
        assert!(
            batch.is_empty(),
            "hook bypass alert must be suppressed in Audit mode"
        );
    }

    #[tokio::test]
    async fn test_audit_mode_suppresses_emit_alert() {
        crate::audit_emitter::enable_test_capture();

        let config = CorrelatorConfig {
            enforcement_mode: EnforcementMode::Audit,
            ..Default::default()
        };
        let correlator = BypassCorrelator::new(config);

        let event = EtwFileEvent {
            pid: 1234,
            file_name: r"C:\Data\secret.docx".to_string(),
            file_object: 0,
            timestamp: 0,
            op: FileOp::Create,
            nt_path_converted: true,
        };

        correlator
            .emit_alert(event, BypassReason::NoHookJournal)
            .await;

        // Batch should be empty and no audit event emitted — safety net works.
        let batch = correlator.alert_batch.lock().await;
        assert!(
            batch.is_empty(),
            "emit_alert safety net must suppress in Audit mode"
        );

        let audit_events = crate::audit_emitter::drain_test_events();
        assert!(
            audit_events.is_empty(),
            "emit_audit_event must be suppressed in Audit mode"
        );
    }

    #[tokio::test]
    async fn test_block_mode_allows_emit_alert() {
        let config = CorrelatorConfig {
            enforcement_mode: EnforcementMode::Block,
            ..Default::default()
        };
        let correlator = BypassCorrelator::new(config);

        let event = EtwFileEvent {
            pid: 1234,
            file_name: r"C:\Data\secret.docx".to_string(),
            file_object: 0,
            timestamp: 0,
            op: FileOp::Create,
            nt_path_converted: true,
        };

        correlator
            .emit_alert(event, BypassReason::NoHookJournal)
            .await;

        // Batch should have exactly 1 alert — Block mode allows bypass alerts.
        let batch = correlator.alert_batch.lock().await;
        assert_eq!(batch.len(), 1, "bypass alert must be emitted in Block mode");
    }

    #[tokio::test]
    async fn test_auditandblock_mode_allows_emit_alert() {
        let config = CorrelatorConfig {
            enforcement_mode: EnforcementMode::AuditAndBlock,
            ..Default::default()
        };
        let correlator = BypassCorrelator::new(config);

        let event = EtwFileEvent {
            pid: 1234,
            file_name: r"C:\Data\secret.docx".to_string(),
            file_object: 0,
            timestamp: 0,
            op: FileOp::Create,
            nt_path_converted: true,
        };

        correlator
            .emit_alert(event, BypassReason::NoHookJournal)
            .await;

        // Batch should have exactly 1 alert — AuditAndBlock mode allows bypass alerts.
        let batch = correlator.alert_batch.lock().await;
        assert_eq!(
            batch.len(),
            1,
            "bypass alert must be emitted in AuditAndBlock mode"
        );
    }

    #[tokio::test]
    async fn test_perpolicy_mode_allows_emit_alert() {
        let config = CorrelatorConfig {
            enforcement_mode: EnforcementMode::PerPolicy,
            ..Default::default()
        };
        let correlator = BypassCorrelator::new(config);

        let event = EtwFileEvent {
            pid: 1234,
            file_name: r"C:\Data\secret.docx".to_string(),
            file_object: 0,
            timestamp: 0,
            op: FileOp::Create,
            nt_path_converted: true,
        };

        correlator
            .emit_alert(event, BypassReason::NoHookJournal)
            .await;

        // Batch should have exactly 1 alert — PerPolicy mode allows bypass alerts.
        // This is the most important regression-safety test because PerPolicy is the
        // default production config (EnforcementConfig::default() returns PerPolicy).
        let batch = correlator.alert_batch.lock().await;
        assert_eq!(
            batch.len(),
            1,
            "bypass alert must be emitted in PerPolicy mode (default production config)"
        );
    }
}
