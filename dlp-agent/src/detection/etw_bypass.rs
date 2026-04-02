//! ETW bypass detection (T-15, F-AGT-18).
//!
//! Subscribes to the `Microsoft-Windows-FileSystem-ETW` provider and compares
//! observed file operations against a set of operations that the interception
//! hooks have already processed.  Any ETW event for an operation the hooks
//! **did not** intercept is logged as `EVASION_SUSPECTED`.
//!
//! ## Design
//!
//! ```text
//! ┌────────────────────────────────────┐
//! │   Interception hooks (CreateFileW, │
//! │   WriteFile, etc.)                 │──── record op in HookLog
//! └────────────────────────────────────┘
//!
//! ┌────────────────────────────────────┐
//! │   ETW FileSystem-ETW subscriber    │──── compare against HookLog
//! │                                    │     if not found → EVASION_SUSPECTED
//! └────────────────────────────────────┘
//! ```
//!
//! ## Limitations
//!
//! - ETW delivers events *after* the operation succeeds.  Blocked operations
//!   never appear in ETW.
//! - The comparison window is time-bounded (default 5 s).  Operations older
//!   than the window are pruned to prevent unbounded memory growth.
//! - High-frequency file operations (e.g., temp file churn) may produce false
//!   positives.  A configurable ignore list filters known noisy paths.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{debug, warn};

/// Default time window for correlating hooks with ETW events.
const CORRELATION_WINDOW: Duration = Duration::from_secs(5);

/// Maximum number of hook records retained in the correlation buffer.
/// Prevents unbounded growth under heavy I/O.
const MAX_HOOK_RECORDS: usize = 10_000;

/// A record of a file operation intercepted by the API hooks.
#[derive(Debug, Clone)]
struct HookRecord {
    /// Lowercase path of the file involved.
    path: String,
    /// The process ID that performed the operation.
    process_id: u32,
    /// Timestamp when the hook intercepted the operation.
    timestamp: Instant,
}

/// An evasion signal emitted when ETW reports an operation not seen by hooks.
#[derive(Debug, Clone)]
pub struct EvasionSignal {
    /// The file path from the ETW event.
    pub path: String,
    /// The process ID from the ETW event.
    pub process_id: u32,
    /// The ETW operation name or event ID string.
    pub etw_operation: String,
}

/// Detects file operations that bypass the interception hooks by correlating
/// hook records against ETW file-system events.
#[derive(Debug)]
pub struct EtwBypassDetector {
    /// Ring buffer of recently intercepted hook operations.
    hook_log: Mutex<VecDeque<HookRecord>>,
    /// Time window for correlation.
    window: Duration,
    /// Path prefixes to ignore (e.g., temp directories, system paths).
    ignore_prefixes: Vec<String>,
}

impl EtwBypassDetector {
    /// Constructs a new detector with the default correlation window.
    pub fn new() -> Self {
        Self {
            hook_log: Mutex::new(VecDeque::with_capacity(MAX_HOOK_RECORDS)),
            window: CORRELATION_WINDOW,
            ignore_prefixes: default_ignore_prefixes(),
        }
    }

    /// Constructs a detector with a custom correlation window.
    #[must_use]
    pub fn with_window(window: Duration) -> Self {
        Self {
            hook_log: Mutex::new(VecDeque::with_capacity(MAX_HOOK_RECORDS)),
            window,
            ignore_prefixes: default_ignore_prefixes(),
        }
    }

    /// Adds a path prefix to the ignore list.
    ///
    /// Operations on paths matching any ignore prefix are not flagged as evasion.
    pub fn add_ignore_prefix(&mut self, prefix: &str) {
        self.ignore_prefixes.push(prefix.to_lowercase());
    }

    /// Records a file operation intercepted by the hooks.
    ///
    /// Called by the interception layer for every operation it catches.
    /// This populates the correlation buffer so that ETW events for the same
    /// operation are not flagged as evasion.
    pub fn record_hook_intercept(&self, path: &str, process_id: u32) {
        let mut log = self.hook_log.lock();

        // Prune expired entries from the front of the deque.
        let cutoff = Instant::now() - self.window;
        while log.front().is_some_and(|r| r.timestamp < cutoff) {
            log.pop_front();
        }

        // Enforce capacity limit.
        if log.len() >= MAX_HOOK_RECORDS {
            log.pop_front();
        }

        log.push_back(HookRecord {
            path: path.to_lowercase(),
            process_id,
            timestamp: Instant::now(),
        });
    }

    /// Checks an ETW event against the hook log.
    ///
    /// Returns `Some(EvasionSignal)` if the operation was not intercepted by
    /// the hooks (potential bypass).  Returns `None` if the operation was
    /// already recorded by the hooks or is in the ignore list.
    ///
    /// # Arguments
    ///
    /// * `path` — the file path from the ETW event
    /// * `process_id` — the PID from the ETW event
    /// * `etw_operation` — the ETW operation name/ID for the audit event
    pub fn check_etw_event(
        &self,
        path: &str,
        process_id: u32,
        etw_operation: &str,
    ) -> Option<EvasionSignal> {
        let lower_path = path.to_lowercase();

        // Skip ignored paths.
        if self.is_ignored(&lower_path) {
            return None;
        }

        let mut log = self.hook_log.lock();
        let cutoff = Instant::now() - self.window;

        // Prune expired entries.
        while log.front().is_some_and(|r| r.timestamp < cutoff) {
            log.pop_front();
        }

        // Search for a matching hook record.
        let found = log
            .iter()
            .any(|r| r.path == lower_path && r.process_id == process_id);

        if found {
            debug!(path, process_id, "ETW event matched hook record");
            None
        } else {
            warn!(
                path,
                process_id,
                etw_operation,
                "EVASION_SUSPECTED: ETW event with no matching hook intercept"
            );
            Some(EvasionSignal {
                path: path.to_string(),
                process_id,
                etw_operation: etw_operation.to_string(),
            })
        }
    }

    /// Returns the number of active (non-expired) hook records.
    #[must_use]
    pub fn hook_record_count(&self) -> usize {
        let log = self.hook_log.lock();
        let cutoff = Instant::now() - self.window;
        log.iter().filter(|r| r.timestamp >= cutoff).count()
    }

    /// Returns `true` if the path matches any ignore prefix.
    fn is_ignored(&self, lower_path: &str) -> bool {
        self.ignore_prefixes
            .iter()
            .any(|prefix| lower_path.starts_with(prefix))
    }
}

impl Default for EtwBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the default set of path prefixes to ignore.
///
/// These are high-churn system paths that produce false positives.
fn default_ignore_prefixes() -> Vec<String> {
    vec![
        r"c:\windows\temp\".to_string(),
        r"c:\windows\prefetch\".to_string(),
        r"c:\windows\system32\config\".to_string(),
        r"c:\$recycle.bin\".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_recorded_no_evasion() {
        let detector = EtwBypassDetector::new();
        detector.record_hook_intercept(r"C:\Data\report.xlsx", 1234);

        let result = detector.check_etw_event(r"C:\Data\report.xlsx", 1234, "WriteFile");
        assert!(result.is_none(), "should not flag when hook was recorded");
    }

    #[test]
    fn test_no_hook_triggers_evasion() {
        let detector = EtwBypassDetector::new();
        // No hook recorded — ETW event should trigger evasion.
        let result = detector.check_etw_event(r"C:\Data\secret.docx", 5678, "NtWriteFile");
        assert!(result.is_some());
        let signal = result.unwrap();
        assert_eq!(signal.path, r"C:\Data\secret.docx");
        assert_eq!(signal.process_id, 5678);
        assert_eq!(signal.etw_operation, "NtWriteFile");
    }

    #[test]
    fn test_case_insensitive_path_matching() {
        let detector = EtwBypassDetector::new();
        detector.record_hook_intercept(r"C:\DATA\Report.XLSX", 100);

        // ETW delivers the path in different case — should still match.
        let result = detector.check_etw_event(r"c:\data\report.xlsx", 100, "WriteFile");
        assert!(result.is_none());
    }

    #[test]
    fn test_different_pid_triggers_evasion() {
        let detector = EtwBypassDetector::new();
        detector.record_hook_intercept(r"C:\Data\file.txt", 100);

        // Same path but different PID — potential injection.
        let result = detector.check_etw_event(r"C:\Data\file.txt", 999, "WriteFile");
        assert!(result.is_some());
    }

    #[test]
    fn test_ignored_path_not_flagged() {
        let detector = EtwBypassDetector::new();
        // System temp path is in the default ignore list.
        let result = detector.check_etw_event(r"C:\Windows\Temp\cache.tmp", 100, "CreateFile");
        assert!(result.is_none());
    }

    #[test]
    fn test_expired_records_pruned() {
        // Use a very short window to test expiry.
        let detector = EtwBypassDetector::with_window(Duration::from_millis(1));
        detector.record_hook_intercept(r"C:\Data\old.txt", 100);

        // Sleep past the window.
        std::thread::sleep(Duration::from_millis(10));

        // The record should have expired — ETW event triggers evasion.
        let result = detector.check_etw_event(r"C:\Data\old.txt", 100, "WriteFile");
        assert!(result.is_some());
    }

    #[test]
    fn test_hook_record_count() {
        let detector = EtwBypassDetector::new();
        assert_eq!(detector.hook_record_count(), 0);

        detector.record_hook_intercept(r"C:\a.txt", 1);
        detector.record_hook_intercept(r"C:\b.txt", 2);
        assert_eq!(detector.hook_record_count(), 2);
    }

    #[test]
    fn test_add_ignore_prefix() {
        let mut detector = EtwBypassDetector::new();
        detector.add_ignore_prefix(r"D:\Logs\");

        let result = detector.check_etw_event(r"D:\Logs\app.log", 100, "WriteFile");
        assert!(result.is_none());
    }

    #[test]
    fn test_capacity_limit() {
        let detector = EtwBypassDetector::with_window(Duration::from_secs(60));
        // Fill beyond capacity.
        for i in 0..MAX_HOOK_RECORDS + 100 {
            detector.record_hook_intercept(&format!(r"C:\Data\file{i}.txt"), i as u32);
        }
        // The log should not exceed MAX_HOOK_RECORDS.
        assert!(detector.hook_log.lock().len() <= MAX_HOOK_RECORDS);
    }
}
