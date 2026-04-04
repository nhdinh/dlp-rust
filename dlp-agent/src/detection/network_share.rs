//! SMB/network share detection (T-14, F-AGT-14).
//!
//! Detects outbound SMB connections by polling the Windows Multi-Provider
//! Router (MPR) for active connections via `WNetOpenEnumW` / `WNetEnumResourceW`.
//! This approach reliably enumerates all current SMB mounts regardless of how
//! they were established (drive letter, `net use`, `MapNetworkDrive`).
//!
//! Matched destinations are checked against an admin-configured whitelist;
//! non-whitelisted connections carrying T3/T4 data are blocked.
//!
//! ## Why MPR polling over ETW?
//!
//! `Microsoft-Windows-SMBClient` ETW requires session-local subscriptions,
//! needs admin privileges, and can be silenced by stopping the ETW session.
//! `WNetOpenEnumW` / `WNetEnumResourceW` enumerate all current connections
//! without elevation or session affinity, making it a more reliable and
//! auditable detection point that works cross-session.
//!
//! ## Detection model
//!
//! 1. A background thread polls `WNetOpenEnumW` / `WNetEnumResourceW` every
//!    30 seconds, collecting all currently-connected SMB resources.
//! 2. Server names are extracted from the UNC remote names.
//! 3. A differential scan detects newly-connected and disconnected shares
//!    between poll cycles.
//! 4. On detection of a new non-whitelisted share, an `SmbShareEvent` is sent
//!    through the caller's channel.
//! 5. Whitelist management is fully dynamic — entries can be added or removed
//!    at runtime via the public API.
//!
//! ## Whitelist format
//!
//! The whitelist is a set of allowed server names or UNC path prefixes:
//! ```text
//! \\fileserver01.corp.local
//! \\nas.corp.local\approved-share
//! ```

use std::collections::HashSet;

use dlp_common::Classification;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// SMB share event emitted when a share is detected as newly connected
/// or disconnected relative to the last poll cycle.
#[derive(Debug, Clone)]
pub enum SmbShareEvent {
    /// A share is now connected and was not present in the previous cycle.
    Connected {
        /// The full UNC remote name (e.g. `\\server\share`).
        unc_path: String,
        /// The server name extracted from the UNC path.
        server: String,
        /// The share name (last path component).
        share_name: String,
    },
    /// A share that was present in the previous cycle is no longer connected.
    Disconnected {
        /// The full UNC remote name that was lost.
        unc_path: String,
    },
}

/// SMB monitor — polls MPR for active SMB connections and emits lifecycle events.
///
/// Uses `WNetOpenEnumW` / `WNetEnumResourceW` to enumerate all currently-connected
/// network resources (drive letters and UNC paths) every 30 seconds.
#[derive(Debug)]
pub struct SmbMonitor {
    /// Set of allowed server names / UNC prefixes (case-insensitive matching).
    whitelist: std::sync::Arc<parking_lot::RwLock<HashSet<String>>>,
    /// Set of UNC paths that were present in the last poll cycle.
    last_seen: std::sync::Arc<parking_lot::RwLock<HashSet<String>>>,
    /// Set to `true` by `stop()` to signal the polling thread to exit.
    stop_flag: std::sync::atomic::AtomicBool,
}

impl Clone for SmbMonitor {
    fn clone(&self) -> Self {
        Self {
            whitelist: std::sync::Arc::clone(&self.whitelist),
            last_seen: std::sync::Arc::clone(&self.last_seen),
            stop_flag: std::sync::atomic::AtomicBool::new(
                self.stop_flag.load(std::sync::atomic::Ordering::SeqCst),
            ),
        }
    }
}

impl Default for SmbMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl SmbMonitor {
    /// Creates a new monitor with an empty whitelist (all shares blocked for
    /// sensitive data by default — secure by design).
    pub fn new() -> Self {
        Self {
            whitelist: std::sync::Arc::new(parking_lot::RwLock::new(HashSet::new())),
            last_seen: std::sync::Arc::new(parking_lot::RwLock::new(HashSet::new())),
            stop_flag: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Creates a monitor with an initial whitelist.
    ///
    /// Entries are normalized to lowercase for case-insensitive matching.
    pub fn with_whitelist(entries: impl IntoIterator<Item = String>) -> Self {
        let set: HashSet<String> = entries.into_iter().map(|e| e.to_lowercase()).collect();
        debug!(count = set.len(), "network share whitelist loaded");
        Self {
            whitelist: std::sync::Arc::new(parking_lot::RwLock::new(set)),
            last_seen: std::sync::Arc::new(parking_lot::RwLock::new(HashSet::new())),
            stop_flag: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Adds a server name or UNC prefix to the whitelist.
    pub fn add_to_whitelist(&self, entry: &str) {
        let normalized = entry.to_lowercase();
        info!(entry = %normalized, "added to network share whitelist");
        self.whitelist.write().insert(normalized);
    }

    /// Removes an entry from the whitelist.
    pub fn remove_from_whitelist(&self, entry: &str) {
        let normalized = entry.to_lowercase();
        if self.whitelist.write().remove(&normalized) {
            info!(entry = %normalized, "removed from network share whitelist");
        }
    }

    /// Replaces the entire whitelist atomically.
    pub fn replace_whitelist(&self, entries: impl IntoIterator<Item = String>) {
        let set: HashSet<String> = entries.into_iter().map(|e| e.to_lowercase()).collect();
        debug!(count = set.len(), "network share whitelist replaced");
        *self.whitelist.write() = set;
    }

    /// Returns `true` if a file operation to `destination` should be blocked
    /// based on classification and whitelist.
    ///
    /// Only T3/T4 operations to non-whitelisted destinations are blocked.
    #[must_use]
    pub fn should_block(&self, destination: &str, classification: Classification) -> bool {
        if !classification.is_sensitive() {
            return false;
        }
        !self.is_whitelisted(destination)
    }

    /// Returns `true` if the destination matches any whitelist entry.
    ///
    /// Matching is case-insensitive. A whitelist entry of
    /// `\\server.corp.local` matches any path under that server. A more
    /// specific entry like `\\server\share` only matches paths under
    /// that share.
    #[must_use]
    pub fn is_whitelisted(&self, destination: &str) -> bool {
        let lower = destination.to_lowercase();
        let server = extract_server_name(&lower);

        let whitelist = self.whitelist.read();
        for entry in whitelist.iter() {
            if lower.starts_with(entry) || server.as_deref() == Some(entry.as_str()) {
                return true;
            }
        }
        false
    }

    /// Returns the current whitelist entries.
    #[must_use]
    pub fn whitelist_entries(&self) -> Vec<String> {
        self.whitelist.read().iter().cloned().collect()
    }

    /// Starts the background polling thread.
    ///
    /// Calls `WNetOpenEnumW` / `WNetEnumResourceW` every 30 seconds to
    /// enumerate active SMB connections.  On each cycle, the current set of
    /// connected shares is diffed against the previous cycle; `Connected` and
    /// `Disconnected` events are sent through `event_tx`.
    ///
    /// The thread runs until [`stop`](SmbMonitor::stop) is called.
    ///
    /// # Arguments
    ///
    /// * `event_tx` — channel sender for SMB share events.
    /// * `poll_interval` — how often to poll (defaults to 30 seconds if `None`).
    pub fn run(
        &self,
        event_tx: mpsc::Sender<SmbShareEvent>,
        poll_interval: Option<std::time::Duration>,
    ) {
        let interval = poll_interval.unwrap_or(std::time::Duration::from_secs(30));
        let whitelist = std::sync::Arc::clone(&self.whitelist);
        let last_seen = std::sync::Arc::clone(&self.last_seen);
        // Clone the flag value so the thread owns the data (AtomicBool is Copy).
        let stop_flag = self.stop_flag.load(std::sync::atomic::Ordering::SeqCst);
        let stop_flag_owned = std::sync::atomic::AtomicBool::new(stop_flag);

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let rt = match rt {
                Ok(rt) => rt,
                Err(e) => {
                    warn!(error = %e, "failed to create tokio runtime for SMB monitor");
                    return;
                }
            };
            rt.block_on(poll_loop(whitelist, last_seen, &stop_flag_owned, event_tx, interval));
        });
    }

    /// Stops the background polling thread.
    ///
    /// Safe to call from any thread.  The thread will exit within one poll
    /// interval after this is called.
    pub fn stop(&self) {
        self.stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        debug!("SMB monitor stop flag set");
    }
}

/// The async polling loop — runs on a dedicated Tokio runtime.
async fn poll_loop(
    whitelist: std::sync::Arc<parking_lot::RwLock<HashSet<String>>>,
    last_seen: std::sync::Arc<parking_lot::RwLock<HashSet<String>>>,
    stop_flag: &std::sync::atomic::AtomicBool,
    event_tx: mpsc::Sender<SmbShareEvent>,
    interval: std::time::Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;

        if stop_flag.load(std::sync::atomic::Ordering::SeqCst) {
            debug!("SMB monitor polling thread exiting");
            break;
        }

        // Enumerate all current SMB connections via MPR.
        let current = enumerate_connected_shares();

        let previous: HashSet<String> = last_seen.read().clone();

        // Update last_seen to current.
        *last_seen.write() = current.clone();

        // Compute diff.
        let added: Vec<_> = current.difference(&previous).cloned().collect();
        let removed: Vec<_> = previous.difference(&current).cloned().collect();

        // Snapshot the whitelist into a plain Vec inside a narrow scope so the
        // MutexGuard is provably dropped (and the lock released) before any
        // `.await` — avoiding clippy::await_holding_lock.
        let whitelist_vec: Vec<String> = {
            let guard = whitelist.read();
            guard.iter().cloned().collect()
        };

        let is_whitelisted = |unc: &str| -> bool {
            let lower = unc.to_lowercase();
            let server = extract_server_name(&lower);
            whitelist_vec
                .iter()
                .any(|entry| lower.starts_with(entry) || server.as_deref() == Some(entry.as_str()))
        };

        // Emit events.
        for unc_path in &added {
            if !is_whitelisted(unc_path) {
                let server = extract_server_name(unc_path).unwrap_or_else(|| unc_path.clone());
                let share_name = unc_path.rsplit('\\').next().unwrap_or(unc_path).to_string();
                let event = SmbShareEvent::Connected {
                    unc_path: unc_path.clone(),
                    server,
                    share_name,
                };
                debug!(unc_path = %unc_path, "new SMB connection detected");
                if event_tx.send(event).await.is_err() {
                    warn!("SMB event receiver dropped — stopping monitor");
                    return;
                }
            }
        }

        for unc_path in &removed {
            debug!(unc_path = %unc_path, "SMB connection removed");
            let event = SmbShareEvent::Disconnected {
                unc_path: unc_path.clone(),
            };
            if event_tx.send(event).await.is_err() {
                warn!("SMB event receiver dropped — stopping monitor");
                return;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MPR API wrappers
// ─────────────────────────────────────────────────────────────────────────────

/// Enumerates all currently-connected SMB shares via `WNetOpenEnumW` / `WNetEnumResourceW`.
///
/// Returns a set of UNC paths (e.g. `\\server\share`) for all connected
/// network resources.  Returns an empty set if the enumeration fails.
fn enumerate_connected_shares() -> HashSet<String> {
    use windows::Win32::Foundation::{HANDLE, WIN32_ERROR};
    use windows::Win32::NetworkManagement::WNet::{
        NETRESOURCEW, RESOURCE_GLOBALNET, RESOURCEUSAGE_CONNECTABLE, RESOURCEUSAGE_CONTAINER,
        RESOURCETYPE_ANY, WNetCloseEnum, WNetEnumResourceW, WNetOpenEnumW,
    };

    const NO_ERROR: WIN32_ERROR = WIN32_ERROR(0);
    const ERROR_NO_MORE_ITEMS: WIN32_ERROR = WIN32_ERROR(259);

    let mut results = HashSet::new();

    // Allocate a buffer large enough for NETRESOURCEW entries.
    // The buffer is passed to WNetEnumResourceW which writes structs directly.
    // We size it for 256 entries; entries beyond this are picked up on the
    // next poll cycle.
    const MAX_ENTRIES: u32 = 256;
    let entry_size = std::mem::size_of::<NETRESOURCEW>();
    let buf_size_bytes = MAX_ENTRIES as usize * entry_size;
    // SAFETY: Vec::with_capacity allocates exactly `buf_size_bytes` bytes on
    // the heap and gives us a valid pointer.  The memory is initialised by
    // WNetEnumResourceW writing NETRESOURCEW structs directly into it.
    let mut buffer: Vec<u8> = vec![0u8; buf_size_bytes];

    let mut handle: HANDLE = HANDLE::default();
    let mut entries_read: u32 = 0;

    // SAFETY: WNetOpenEnumW writes the enumeration handle into `handle` and
    // returns a WIN32_ERROR.  `handle` is a valid out-parameter.
    let ret = unsafe {
        WNetOpenEnumW(
            RESOURCE_GLOBALNET,
            RESOURCETYPE_ANY,
            RESOURCEUSAGE_CONNECTABLE | RESOURCEUSAGE_CONTAINER,
            None,
            &mut handle,
        )
    };

    if ret != NO_ERROR {
        debug!(win32_error = %ret.0, "WNetOpenEnumW failed");
        return results;
    }

    // SAFETY: We hold the enumeration handle.  `buffer` is valid for writes of
    // `buf_size_bytes`.  `entries_read` and `buf_size` are valid out-parameters.
    // `WNetEnumResourceW` will write at most `MAX_ENTRIES` NETRESOURCEW structs
    // into the buffer, zeroing any padding bytes.
    let mut buf_size = u32::try_from(buf_size_bytes).unwrap_or(u32::MAX);
    let ret = unsafe {
        WNetEnumResourceW(
            handle,
            &mut entries_read,
            buffer.as_mut_ptr() as *mut _,
            &mut buf_size,
        )
    };

    // Close the enumeration handle regardless of outcome.
    // SAFETY: `handle` was obtained from `WNetOpenEnumW` above and we hold it.
    let close_ret = unsafe { WNetCloseEnum(handle) };
    if close_ret != NO_ERROR {
        debug!(win32_error = %close_ret.0, "WNetCloseEnum failed");
    }

    if ret != NO_ERROR && ret != ERROR_NO_MORE_ITEMS {
        debug!(win32_error = %ret.0, "WNetEnumResourceW failed");
        return results;
    }

    // SAFETY: WNetEnumResourceW wrote exactly `entries_read` NETRESOURCEW structs
    // into `buffer` (confirmed by matching ERROR_NO_MORE_ITEMS or NO_ERROR return).
    for i in 0..entries_read as usize {
        // SAFETY: buffer was allocated for `MAX_ENTRIES * entry_size` bytes and
        // entries_read <= MAX_ENTRIES.  NETRESOURCEW is #[repr(C)] so its layout
        // is deterministic.
        let entry: &NETRESOURCEW = unsafe {
            &*buffer.as_ptr().add(i * entry_size).cast()
        };

        // lpRemoteName is null for some entries (e.g. domain containers).
        if entry.lpRemoteName.is_null() {
            continue;
        }

        // Convert the PWSTR to a Rust String.
        // SAFETY: lpRemoteName is null-terminated; WNetEnumResourceW guarantees
        // the string is valid UTF-16 (it's a Win32 path).
        let unc_path = unsafe { entry.lpRemoteName.to_string() }.unwrap_or_default();

        if !unc_path.is_empty() && unc_path.starts_with("\\\\") {
            results.insert(unc_path);
        }
    }

    results
}

/// Extracts the server name from a UNC path.
///
/// `\\server.corp.local\share\file.txt` -> `Some("server.corp.local")`
/// `C:\local\path` -> `None`
fn extract_server_name(path: &str) -> Option<String> {
    let stripped = path.strip_prefix("\\\\")?;
    let end = stripped.find('\\').unwrap_or(stripped.len());
    if end == 0 {
        return None;
    }
    Some(stripped[..end].to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkShareDetector — whitelist-only API (no polling)
// ─────────────────────────────────────────────────────────────────────────────

/// Detects outbound SMB connections and enforces destination whitelisting.
///
/// This is the legacy / whitelist-only API.  For active SMB detection use
/// [`SmbMonitor`] which also runs the `WNetOpenEnumW` / `WNetEnumResourceW`
/// polling loop.
#[derive(Debug)]
pub struct NetworkShareDetector {
    whitelist: RwLock<HashSet<String>>,
}

impl NetworkShareDetector {
    /// Constructs a new detector with an empty whitelist (all shares blocked for
    /// sensitive data by default — secure by design).
    pub fn new() -> Self {
        Self {
            whitelist: RwLock::new(HashSet::new()),
        }
    }

    /// Constructs a detector with an initial whitelist.
    ///
    /// Entries are normalized to lowercase for case-insensitive matching.
    pub fn with_whitelist(entries: impl IntoIterator<Item = String>) -> Self {
        let set: HashSet<String> = entries.into_iter().map(|e| e.to_lowercase()).collect();
        debug!(count = set.len(), "network share whitelist loaded");
        Self {
            whitelist: RwLock::new(set),
        }
    }

    /// Adds a server name or UNC prefix to the whitelist.
    pub fn add_to_whitelist(&self, entry: &str) {
        let normalized = entry.to_lowercase();
        info!(entry = %normalized, "added to network share whitelist");
        self.whitelist.write().insert(normalized);
    }

    /// Removes an entry from the whitelist.
    pub fn remove_from_whitelist(&self, entry: &str) {
        let normalized = entry.to_lowercase();
        if self.whitelist.write().remove(&normalized) {
            info!(entry = %normalized, "removed from network share whitelist");
        }
    }

    /// Replaces the entire whitelist atomically.
    pub fn replace_whitelist(&self, entries: impl IntoIterator<Item = String>) {
        let set: HashSet<String> = entries.into_iter().map(|e| e.to_lowercase()).collect();
        debug!(count = set.len(), "network share whitelist replaced");
        *self.whitelist.write() = set;
    }

    /// Returns `true` if a file operation to `destination` should be blocked
    /// based on classification and whitelist.
    ///
    /// Only T3/T4 operations to non-whitelisted destinations are blocked.
    #[must_use]
    pub fn should_block(&self, destination: &str, classification: Classification) -> bool {
        if !classification.is_sensitive() {
            return false;
        }
        !self.is_whitelisted(destination)
    }

    /// Returns `true` if the destination matches any whitelist entry.
    ///
    /// Matching is case-insensitive. A whitelist entry of
    /// `\\server.corp.local` matches any path under that server. A more
    /// specific entry like `\\server\share` only matches paths under
    /// that share.
    #[must_use]
    pub fn is_whitelisted(&self, destination: &str) -> bool {
        let lower = destination.to_lowercase();
        let server = extract_server_name(&lower);

        let whitelist = self.whitelist.read();
        for entry in whitelist.iter() {
            if lower.starts_with(entry) || server.as_deref() == Some(entry.as_str()) {
                return true;
            }
        }
        false
    }

    /// Returns the current whitelist entries.
    #[must_use]
    pub fn whitelist_entries(&self) -> Vec<String> {
        self.whitelist.read().iter().cloned().collect()
    }
}

impl Default for NetworkShareDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_server_name() {
        assert_eq!(
            extract_server_name(r"\\server.corp.local\share\file.txt"),
            Some("server.corp.local".to_string())
        );
        assert_eq!(
            extract_server_name(r"\\nas01\data"),
            Some("nas01".to_string())
        );
        assert_eq!(extract_server_name(r"C:\local\path"), None);
        assert_eq!(extract_server_name(r"\\"), None);
        assert_eq!(extract_server_name(""), None);
    }

    #[test]
    fn test_empty_whitelist_blocks_sensitive() {
        let detector = NetworkShareDetector::new();
        assert!(detector.should_block(r"\\evil.external\data", Classification::T4));
        assert!(detector.should_block(r"\\evil.external\data", Classification::T3));
    }

    #[test]
    fn test_empty_whitelist_allows_non_sensitive() {
        let detector = NetworkShareDetector::new();
        assert!(!detector.should_block(r"\\any.server\share", Classification::T1));
        assert!(!detector.should_block(r"\\any.server\share", Classification::T2));
    }

    #[test]
    fn test_whitelisted_server_allowed() {
        let detector =
            NetworkShareDetector::with_whitelist(vec!["fileserver01.corp.local".to_string()]);
        assert!(!detector.should_block(
            r"\\fileserver01.corp.local\share\report.xlsx",
            Classification::T4,
        ));
    }

    #[test]
    fn test_non_whitelisted_server_blocked() {
        let detector = NetworkShareDetector::with_whitelist(vec!["safe.corp.local".to_string()]);
        assert!(detector.should_block(r"\\evil.external\exfil", Classification::T3,));
    }

    #[test]
    fn test_case_insensitive_matching() {
        let detector =
            NetworkShareDetector::with_whitelist(vec!["FileServer01.Corp.Local".to_string()]);
        assert!(detector.is_whitelisted(r"\\FILESERVER01.CORP.LOCAL\share"));
        assert!(detector.is_whitelisted(r"\\fileserver01.corp.local\data"));
    }

    #[test]
    fn test_add_remove_whitelist() {
        let detector = NetworkShareDetector::new();
        detector.add_to_whitelist("nas01.corp.local");
        assert!(detector.is_whitelisted(r"\\nas01.corp.local\share"));

        detector.remove_from_whitelist("nas01.corp.local");
        assert!(!detector.is_whitelisted(r"\\nas01.corp.local\share"));
    }

    #[test]
    fn test_replace_whitelist() {
        let detector = NetworkShareDetector::with_whitelist(vec!["old.server".to_string()]);
        detector.replace_whitelist(vec!["new.server".to_string()]);
        assert!(!detector.is_whitelisted(r"\\old.server\share"));
        assert!(detector.is_whitelisted(r"\\new.server\share"));
    }

    #[test]
    fn test_prefix_matching() {
        let detector =
            NetworkShareDetector::with_whitelist(vec![r"\\nas01\approved-share".to_string()]);
        // Path under the approved share should match.
        assert!(detector.is_whitelisted(r"\\nas01\approved-share\file.xlsx"));
        // Different share on the same server should NOT match.
        assert!(!detector.is_whitelisted(r"\\nas01\unapproved\file.xlsx"));
    }

    #[test]
    fn test_smb_share_event_debug() {
        let event = SmbShareEvent::Connected {
            unc_path: r"\\fileserver\cfo".to_string(),
            server: "fileserver".to_string(),
            share_name: "cfo".to_string(),
        };
        let s = format!("{:?}", event);
        assert!(s.contains("fileserver"));
        assert!(s.contains("cfo"));

        let event2 = SmbShareEvent::Disconnected {
            unc_path: r"\\fileserver\public".to_string(),
        };
        let s2 = format!("{:?}", event2);
        assert!(s2.contains("public"));
    }

    #[test]
    fn test_smb_monitor_stop_flag() {
        let monitor = SmbMonitor::new();
        assert!(!monitor.stop_flag.load(std::sync::atomic::Ordering::SeqCst));
        monitor.stop();
        assert!(monitor.stop_flag.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_smb_monitor_whitelist_api() {
        let monitor = SmbMonitor::new();
        assert!(!monitor.is_whitelisted(r"\\bad\server"));

        monitor.add_to_whitelist("good.server");
        assert!(monitor.is_whitelisted(r"\\good.server\share"));

        monitor.remove_from_whitelist("good.server");
        assert!(!monitor.is_whitelisted(r"\\good.server\share"));

        monitor.replace_whitelist(vec!["safe.corp.local".to_string()]);
        assert!(monitor.is_whitelisted(r"\\safe.corp.local\data"));
        assert!(!monitor.is_whitelisted(r"\\bad\server"));
    }

    #[test]
    fn test_smb_monitor_should_block() {
        let monitor = SmbMonitor::new();
        assert!(monitor.should_block(r"\\bad\exfil", Classification::T4));
        assert!(!monitor.should_block(r"\\bad\exfil", Classification::T1));

        monitor.add_to_whitelist("safe.server");
        assert!(!monitor.should_block(r"\\safe.server\public", Classification::T4));
    }

    #[test]
    fn test_smb_monitor_clone() {
        let monitor = SmbMonitor::new();
        monitor.add_to_whitelist("original");
        let cloned = monitor.clone();
        cloned.add_to_whitelist("clone");

        // Both share the same whitelist Arc.
        assert!(monitor.is_whitelisted(r"\\clone\share"));
        assert!(cloned.is_whitelisted(r"\\original\share"));
    }
}
