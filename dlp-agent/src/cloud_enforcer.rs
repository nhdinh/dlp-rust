//! Cloud sync enforcement layer (M017/S01).
//!
//! [`CloudEnforcer`] bridges the file interception event loop and cloud sync
//! folder detection to enforce DLP policies on files stored in sync client
//! folders (OneDrive, Google Drive, Dropbox, etc.).
//!
//! ## Decision logic
//!
//! 1. Check if the file path is inside a known sync folder.
//! 2. If the action is a write/create/move that targets a T3/T4 file inside a
//!    sync folder, return a [`CloudBlockResult`] with `Decision::DENY`.
//! 3. Otherwise return `None` (fall through to ABAC).
//!
//! ## Sync folder detection
//!
//! Phase S01 uses a placeholder path-prefix check. Phase S02 will replace this
//! with a registry-based dynamic discovery that resolves the actual sync-folder
//! paths for each user session.

use dlp_common::{Classification, Decision};

use crate::interception::FileAction;

/// Result returned by [`CloudEnforcer::check`] when a cloud sync operation is
/// blocked.
#[derive(Debug, Clone, PartialEq)]
pub struct CloudBlockResult {
    /// The enforcement decision — currently always `Decision::DENY`.
    pub decision: Decision,
    /// Human-readable reason for the block.
    pub reason: String,
    /// The detected sync provider (e.g., "OneDrive").
    pub provider: String,
    /// `true` if the UI should display a toast.
    pub notify: bool,
}

/// Enforces DLP policies on file operations inside cloud sync folders.
///
/// Held behind `Arc` so it can be shared between the event loop and future
/// cloud notification handlers without cloning the underlying state.
pub struct CloudEnforcer {
    /// Placeholder list of sync folder path prefixes (S01).
    /// Phase S02 will replace this with dynamic registry discovery.
    sync_paths: Vec<String>,
}

impl CloudEnforcer {
    /// Constructs a new [`CloudEnforcer`] with default placeholder sync paths.
    pub fn new() -> Self {
        Self {
            sync_paths: vec![
                // Placeholder paths for S01 — real resolver comes in S02.
                r"C:\Users".to_string(),
            ],
        }
    }

    /// Constructs a new [`CloudEnforcer`] with explicit sync folder prefixes.
    ///
    /// Primarily used by tests to inject mock paths without relying on the
    /// hardcoded defaults.
    pub fn with_paths(paths: Vec<String>) -> Self {
        Self {
            sync_paths: paths,
        }
    }

    /// Evaluates whether the given file operation should be blocked based on
    /// cloud sync folder policies.
    ///
    /// Returns `Some(CloudBlockResult)` for T3/T4 write operations inside a
    /// sync folder. All other operations return `None` (fall through to ABAC).
    ///
    /// # Arguments
    ///
    /// * `path` - Full file path of the operation (e.g., `C:\Users\Alice\OneDrive\secret.docx`).
    /// * `action` - The [`FileAction`] being evaluated.
    ///
    /// # Returns
    ///
    /// - `Some(CloudBlockResult)` — T3/T4 file in sync folder; block.
    /// - `None` — not a sync path, or non-sensitive classification; proceed to ABAC.
    #[must_use]
    pub fn check(&self, path: &str, action: &FileAction) -> Option<CloudBlockResult> {
        // Only intercept write-like operations. Reads and deletes are not
        // cloud-upload events.
        if !is_write_like_action(action) {
            return None;
        }

        // Check if path is inside a known sync folder.
        let provider = self.detect_sync_provider(path)?;

        // Placeholder classification for S01: paths under \Users\*\OneDrive
        // are treated as the sync-folder tier. Real classification will come
        // from ABAC when we fall through, but for the cloud-upload case we
        // need to block T3/T4 proactively.
        let classification = provisional_sync_classification(path);

        if classification.is_sensitive() {
            tracing::info!(
                path = %path,
                provider = %provider,
                classification = ?classification,
                decision = ?Decision::DENY,
                "cloud enforcer decision"
            );
            Some(CloudBlockResult {
                decision: Decision::DENY,
                reason: format!(
                    "Cloud sync blocked: {classification} file in {provider} folder"
                ),
                provider,
                notify: true,
            })
        } else {
            tracing::info!(
                path = %path,
                provider = %provider,
                classification = ?classification,
                decision = ?Decision::ALLOW,
                "cloud enforcer decision"
            );
            None
        }
    }

    /// Detects whether `path` resides inside a known sync folder.
    ///
    /// Returns the provider name (e.g., "OneDrive") if matched, or `None`.
    fn detect_sync_provider(&self, path: &str) -> Option<String> {
        let lower = path.to_lowercase();
        for prefix in &self.sync_paths {
            if lower.starts_with(&prefix.to_lowercase()) {
                // Placeholder heuristic: if the path contains "onedrive",
                // report OneDrive. Otherwise report generic "CloudSync".
                if lower.contains("onedrive") {
                    return Some("OneDrive".to_string());
                }
                return Some("CloudSync".to_string());
            }
        }
        None
    }
}

/// Returns `true` for actions that represent a file being written or created
/// in a way that could trigger a cloud upload.
fn is_write_like_action(action: &FileAction) -> bool {
    matches!(
        action,
        FileAction::Created { .. }
            | FileAction::Written { .. }
            | FileAction::Moved { .. }
    )
}

/// Placeholder classification heuristic for sync-folder paths.
///
/// In S01 we use a simple path-based heuristic:
/// - Paths containing "restricted" → T4
/// - Paths containing "confidential" → T3
/// - Everything else → T2
///
/// Phase S02 will integrate with the real ABAC classification engine.
fn provisional_sync_classification(path: &str) -> Classification {
    let lower = path.to_lowercase();
    if lower.contains(r"\restricted\") || lower.contains("restricted") {
        Classification::T4
    } else if lower.contains(r"\confidential\") || lower.contains("confidential") {
        Classification::T3
    } else {
        Classification::T2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written_action(path: &str) -> FileAction {
        FileAction::Written {
            path: path.to_string(),
            process_id: 1,
            related_process_id: 1,
            byte_count: 100,
        }
    }

    fn created_action(path: &str) -> FileAction {
        FileAction::Created {
            path: path.to_string(),
            process_id: 1,
            related_process_id: 1,
        }
    }

    fn read_action(path: &str) -> FileAction {
        FileAction::Read {
            path: path.to_string(),
            process_id: 1,
            related_process_id: 1,
            byte_count: 0,
        }
    }

    fn moved_action(old: &str, new: &str) -> FileAction {
        FileAction::Moved {
            old_path: old.to_string(),
            new_path: new.to_string(),
            process_id: 1,
            related_process_id: 1,
        }
    }

    #[test]
    fn test_empty_path_returns_none() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        assert_eq!(enforcer.check("", &written_action("")), None);
    }

    #[test]
    fn test_unc_path_returns_none() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        assert_eq!(
            enforcer.check(r"\\server\share\file.txt", &written_action(r"\\server\share\file.txt")),
            None
        );
    }

    #[test]
    fn test_path_outside_sync_folder_returns_none() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        assert_eq!(
            enforcer.check(r"C:\Windows\file.txt", &written_action(r"C:\Windows\file.txt")),
            None
        );
    }

    #[test]
    fn test_read_action_returns_none() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        assert_eq!(
            enforcer.check(r"C:\Users\Alice\OneDrive\secret.txt", &read_action(r"C:\Users\Alice\OneDrive\secret.txt")),
            None
        );
    }

    #[test]
    fn test_t1_file_in_sync_folder_returns_none() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        // Path without "confidential" or "restricted" → T2 → not sensitive → None.
        assert_eq!(
            enforcer.check(r"C:\Users\Alice\OneDrive\public.txt", &written_action(r"C:\Users\Alice\OneDrive\public.txt")),
            None
        );
    }

    #[test]
    fn test_t3_file_in_sync_folder_blocked() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        let result = enforcer.check(
            r"C:\Users\Alice\OneDrive\confidential.docx",
            &written_action(r"C:\Users\Alice\OneDrive\confidential.docx"),
        );
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.decision, Decision::DENY);
        assert_eq!(r.provider, "OneDrive");
        assert!(r.reason.contains("Cloud sync blocked"));
        assert!(r.notify);
    }

    #[test]
    fn test_t4_file_in_sync_folder_blocked() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        let result = enforcer.check(
            r"C:\Users\Alice\OneDrive\Restricted\secret.xlsx",
            &written_action(r"C:\Users\Alice\OneDrive\Restricted\secret.xlsx"),
        );
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.decision, Decision::DENY);
        assert_eq!(r.provider, "OneDrive");
    }

    #[test]
    fn test_created_action_blocked() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        let result = enforcer.check(
            r"C:\Users\Alice\OneDrive\confidential.docx",
            &created_action(r"C:\Users\Alice\OneDrive\confidential.docx"),
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);
    }

    #[test]
    fn test_moved_action_blocked() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        let result = enforcer.check(
            r"C:\Users\Alice\OneDrive\confidential.docx",
            &moved_action(
                r"C:\Data\confidential.docx",
                r"C:\Users\Alice\OneDrive\confidential.docx",
            ),
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::DENY);
    }

    #[test]
    fn test_custom_sync_path() {
        let enforcer = CloudEnforcer::with_paths(vec![r"D:\GoogleDrive".to_string()]);
        let result = enforcer.check(
            r"D:\GoogleDrive\confidential.docx",
            &written_action(r"D:\GoogleDrive\confidential.docx"),
        );
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.decision, Decision::DENY);
        assert_eq!(r.provider, "CloudSync");
    }

    #[test]
    fn test_deleted_action_returns_none() {
        let enforcer = CloudEnforcer::with_paths(vec![r"C:\Users".to_string()]);
        let action = FileAction::Deleted {
            path: r"C:\Users\Alice\OneDrive\confidential.docx".to_string(),
            process_id: 1,
            related_process_id: 1,
        };
        assert_eq!(
            enforcer.check(r"C:\Users\Alice\OneDrive\confidential.docx", &action),
            None
        );
    }
}
