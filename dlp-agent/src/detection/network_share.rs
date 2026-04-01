//! SMB/network share detection (T-14, F-AGT-14).
//!
//! Detects outbound SMB connections by monitoring the
//! `Microsoft-Windows-SMBClient` ETW provider for tree-connect events.
//! Matched destinations are checked against an admin-configured whitelist;
//! connections to non-whitelisted shares carrying T3/T4 data are blocked.
//!
//! ## Detection model
//!
//! 1. Subscribe to `Microsoft-Windows-SMBClient` ETW trace.
//! 2. Capture `TreeConnect` events (Event ID 30803) containing the server name.
//! 3. Check destination against the whitelist.
//! 4. If not whitelisted and data classification is T3/T4, block + emit audit.
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
use tracing::{debug, info};

/// Well-known GUID for the Microsoft-Windows-SMBClient ETW provider.
#[allow(dead_code)]
const SMB_CLIENT_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0x988c59c5,
    0x0a1c,
    0x45b6,
    [0xa5, 0x55, 0x0c, 0x62, 0x27, 0x6e, 0x32, 0x7e],
);

/// ETW event ID for SMB TreeConnect (outbound connection to a share).
#[allow(dead_code)]
const SMB_TREE_CONNECT_EVENT_ID: u16 = 30803;

/// Detects outbound SMB connections and enforces destination whitelisting.
#[derive(Debug)]
pub struct NetworkShareDetector {
    /// Set of allowed server names / UNC prefixes (case-insensitive matching).
    /// Entries are stored in lowercase for comparison.
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
    ///
    /// # Arguments
    ///
    /// * `entry` — a server name (e.g., `fileserver01.corp.local`) or UNC
    ///   prefix (e.g., `\\\\nas.corp.local\\approved-share`)
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
    pub fn should_block(
        &self,
        destination: &str,
        classification: Classification,
    ) -> bool {
        if !classification.is_sensitive() {
            return false;
        }
        !self.is_whitelisted(destination)
    }

    /// Returns `true` if the destination matches any whitelist entry.
    ///
    /// Matching is case-insensitive. A whitelist entry of
    /// `\\\\server.corp.local` matches any path under that server. A more
    /// specific entry like `\\\\server\\share` only matches paths under
    /// that share.
    #[must_use]
    pub fn is_whitelisted(&self, destination: &str) -> bool {
        let lower = destination.to_lowercase();
        // Extract the server name from a UNC path for matching.
        let server = extract_server_name(&lower);

        let whitelist = self.whitelist.read();
        for entry in whitelist.iter() {
            // Match if destination starts with the whitelist entry (prefix match)
            // or if the server name matches.
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

/// Extracts the server name from a UNC path.
///
/// `\\\\server.corp.local\\share\\file.txt` -> `Some("server.corp.local")`
/// `C:\\local\\path` -> `None`
fn extract_server_name(path: &str) -> Option<String> {
    // UNC paths start with \\ (two backslashes).
    let stripped = path.strip_prefix("\\\\")?;
    // The server name ends at the next backslash (or end of string).
    let end = stripped.find('\\').unwrap_or(stripped.len());
    if end == 0 {
        return None;
    }
    Some(stripped[..end].to_string())
}

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
        let detector = NetworkShareDetector::with_whitelist(
            vec!["fileserver01.corp.local".to_string()],
        );
        assert!(!detector.should_block(
            r"\\fileserver01.corp.local\share\report.xlsx",
            Classification::T4,
        ));
    }

    #[test]
    fn test_non_whitelisted_server_blocked() {
        let detector = NetworkShareDetector::with_whitelist(
            vec!["safe.corp.local".to_string()],
        );
        assert!(detector.should_block(
            r"\\evil.external\exfil",
            Classification::T3,
        ));
    }

    #[test]
    fn test_case_insensitive_matching() {
        let detector = NetworkShareDetector::with_whitelist(
            vec!["FileServer01.Corp.Local".to_string()],
        );
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
        let detector = NetworkShareDetector::with_whitelist(
            vec!["old.server".to_string()],
        );
        detector.replace_whitelist(vec!["new.server".to_string()]);
        assert!(!detector.is_whitelisted(r"\\old.server\share"));
        assert!(detector.is_whitelisted(r"\\new.server\share"));
    }

    #[test]
    fn test_prefix_matching() {
        let detector = NetworkShareDetector::with_whitelist(
            vec![r"\\nas01\approved-share".to_string()],
        );
        // Path under the approved share should match.
        assert!(detector.is_whitelisted(r"\\nas01\approved-share\file.xlsx"));
        // Different share on the same server should NOT match.
        assert!(!detector.is_whitelisted(r"\\nas01\unapproved\file.xlsx"));
    }
}
