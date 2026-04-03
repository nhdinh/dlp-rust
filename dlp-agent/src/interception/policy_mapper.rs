//! Maps [`FileAction`] events to ABAC [`Action`] and classification tiers (T-11).
//!
//! The mapper translates file system operation events into the ABAC evaluation
//! model.  It applies a simple extension-layer heuristic: path patterns are
//! checked against a set of sensitive-directory prefixes (e.g., `C:\Data\`,
//! `C:\Restricted\`) to assign a provisional classification tier when the
//! Policy Engine is unreachable.

use dlp_common::Action;
use tracing::debug;

use super::FileAction;

/// A sensitive-directory rule for the extension-layer classifier.
///
/// Each rule maps a path prefix to a minimum classification tier.
// TODO (Phase 2): load from policy-engine sync or config file.
const DEFAULT_SENSITIVE_PREFIXES: &[(&str, dlp_common::Classification)] = &[
    ("C:\\Restricted\\", dlp_common::Classification::T4),
    ("C:\\Confidential\\", dlp_common::Classification::T3),
    ("C:\\Data\\", dlp_common::Classification::T2),
    ("C:\\Public\\", dlp_common::Classification::T1),
];

/// Maps [`FileAction`] events to ABAC [`Action`] variants.
pub struct PolicyMapper;

impl PolicyMapper {
    /// Converts a [`FileAction`] variant to the corresponding ABAC [`Action`].
    #[must_use]
    pub fn action_for(action: &FileAction) -> Action {
        match action {
            FileAction::Created { .. } => Action::WRITE,
            FileAction::Written { .. } => Action::WRITE,
            FileAction::Deleted { .. } => Action::DELETE,
            FileAction::Moved { .. } => Action::MOVE,
            FileAction::Read { .. } => Action::READ,
        }
    }

    /// Returns the minimum required classification for the given file path.
    ///
    /// Uses the `DEFAULT_SENSITIVE_PREFIXES` table.  When the Policy Engine
    /// is reachable, the engine provides the authoritative classification;
    /// this method is only used as a provisional fallback in offline mode.
    ///
    /// Returns `Classification::T1` (Public) for any path not matching a prefix.
    #[must_use]
    pub fn provisional_classification(path: &str) -> dlp_common::Classification {
        for (prefix, tier) in DEFAULT_SENSITIVE_PREFIXES {
            if path.starts_with(prefix) {
                debug!(path, tier = ?tier, "provisional classification from path prefix");
                return *tier;
            }
        }
        dlp_common::Classification::T1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_for_created() {
        let action = FileAction::Created {
            path: r"C:\Data\report.xlsx".to_string(),
            process_id: 100,
            related_process_id: 0,
        };
        assert_eq!(PolicyMapper::action_for(&action), Action::WRITE);
    }

    #[test]
    fn test_action_for_deleted() {
        let action = FileAction::Deleted {
            path: r"C:\Temp\junk.txt".to_string(),
            process_id: 200,
            related_process_id: 0,
        };
        assert_eq!(PolicyMapper::action_for(&action), Action::DELETE);
    }

    #[test]
    fn test_action_for_read() {
        let action = FileAction::Read {
            path: r"C:\Public\readme.txt".to_string(),
            process_id: 300,
            related_process_id: 0,
            byte_count: 256,
        };
        assert_eq!(PolicyMapper::action_for(&action), Action::READ);
    }

    #[test]
    fn test_provisional_classification_t4() {
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\Restricted\secrets.xlsx"),
            dlp_common::Classification::T4
        );
    }

    #[test]
    fn test_provisional_classification_t3() {
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\Confidential\report.docx"),
            dlp_common::Classification::T3
        );
    }

    #[test]
    fn test_provisional_classification_t2() {
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\Data\spreadsheet.csv"),
            dlp_common::Classification::T2
        );
    }

    #[test]
    fn test_provisional_classification_t1_default() {
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\Windows\System32\config.sys"),
            dlp_common::Classification::T1
        );
    }

    #[test]
    fn test_provisional_classification_public() {
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\Public\readme.txt"),
            dlp_common::Classification::T1
        );
    }
}
