//! Maps [`FileAction`] events to ABAC [`Action`] and classification tiers (T-11).
//!
//! The mapper translates file system operation events into the ABAC evaluation
//! model.  It applies a simple extension-layer heuristic: path patterns are
//! checked against a set of sensitive-directory prefixes (e.g., `C:\Data\`,
//! `C:\Restricted\`) to assign a provisional classification tier when the
//! Policy Engine is unreachable.

use std::io::Read;

use dlp_common::{Action, Classification};
use tracing::debug;

use super::FileAction;
use crate::clipboard::ContentClassifier;

/// A sensitive-directory rule for the extension-layer classifier.
///
/// Each rule maps a path prefix (lowercase) to a minimum classification tier.
// TODO (Phase 2): load from policy-engine sync or config file.
const DEFAULT_SENSITIVE_PREFIXES: &[(&str, Classification)] = &[
    (r"c:\restricted\", Classification::T4),
    (r"c:\confidential\", Classification::T3),
    (r"c:\data\", Classification::T2),
    (r"c:\public\", Classification::T1),
];

/// Maximum number of bytes to read from a file for content classification.
///
/// 8 KB is enough to capture document headers, keywords, and short
/// structured data patterns (SSN, credit card numbers) without
/// introducing significant I/O latency.
const CONTENT_SCAN_MAX_BYTES: usize = 8 * 1024;

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

    /// Returns the provisional classification for the given file path.
    ///
    /// Uses a two-tier strategy:
    ///
    /// 1. **Path prefix** — checks the path against
    ///    `DEFAULT_SENSITIVE_PREFIXES` (case-insensitive).
    /// 2. **Content scan** — if the path is not in a known sensitive
    ///    directory, reads the first 8 KB of the file and classifies
    ///    the text using [`ContentClassifier`] (SSN, credit card,
    ///    keyword patterns).
    ///
    /// When the Policy Engine is reachable, the engine provides the
    /// authoritative classification; this method is only used as a
    /// provisional fallback in offline mode.
    ///
    /// Returns `Classification::T1` (Public) if neither strategy
    /// produces a higher tier.
    #[must_use]
    pub fn provisional_classification(path: &str) -> Classification {
        // Tier 1: path prefix lookup (fast, no I/O, case-insensitive).
        let path_tier = path_classification(path);
        if path_tier > Classification::T1 {
            return path_tier;
        }

        // Tier 2: content scan (reads first 8 KB of the file).
        content_classification(path).unwrap_or(Classification::T1)
    }
}

/// Classifies a file path against the sensitive-directory prefix table.
///
/// Comparison is case-insensitive.  Returns `Classification::T1` if no
/// prefix matches.
fn path_classification(path: &str) -> Classification {
    let lower = path.to_lowercase();
    for (prefix, tier) in DEFAULT_SENSITIVE_PREFIXES {
        if lower.starts_with(prefix) {
            debug!(
                path,
                tier = ?tier,
                "provisional classification from path prefix"
            );
            return *tier;
        }
    }
    Classification::T1
}

/// Reads the first [`CONTENT_SCAN_MAX_BYTES`] of a file and classifies
/// the content using [`ContentClassifier`].
///
/// Returns `None` if the file cannot be opened or read (locked, binary,
/// permissions).  The caller should treat `None` as T1.
fn content_classification(path: &str) -> Option<Classification> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; CONTENT_SCAN_MAX_BYTES];
    let n = file.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    buf.truncate(n);

    // Lossy UTF-8 conversion handles binary content gracefully.
    let text = String::from_utf8_lossy(&buf);
    let tier = ContentClassifier::classify(&text);

    if tier > Classification::T1 {
        debug!(
            path,
            tier = ?tier,
            "content-based classification from file scan"
        );
    }

    Some(tier)
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
            Classification::T4
        );
    }

    #[test]
    fn test_provisional_classification_t3() {
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\Confidential\report.docx"),
            Classification::T3
        );
    }

    #[test]
    fn test_provisional_classification_t2() {
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\Data\spreadsheet.csv"),
            Classification::T2
        );
    }

    #[test]
    fn test_provisional_classification_t1_default() {
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\Windows\System32\config.sys"),
            Classification::T1
        );
    }

    #[test]
    fn test_provisional_classification_public() {
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\Public\readme.txt"),
            Classification::T1
        );
    }

    // -- Case-insensitive path matching ------------------------------------

    #[test]
    fn test_path_classification_case_insensitive() {
        assert_eq!(
            path_classification(r"c:\restricted\secrets.xlsx"),
            Classification::T4
        );
        assert_eq!(
            path_classification(r"C:\CONFIDENTIAL\Report.docx"),
            Classification::T3
        );
    }

    // -- Content-based classification --------------------------------------

    #[test]
    fn test_content_classification_confidential_keyword() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memo.txt");
        std::fs::write(&path, "This is CONFIDENTIAL data").unwrap();

        let tier = content_classification(path.to_str().unwrap());
        assert_eq!(tier, Some(Classification::T3));
    }

    #[test]
    fn test_content_classification_ssn() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pii.txt");
        std::fs::write(&path, "Employee SSN: 123-45-6789").unwrap();

        let tier = content_classification(path.to_str().unwrap());
        assert_eq!(tier, Some(Classification::T4));
    }

    #[test]
    fn test_content_classification_plain_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        std::fs::write(&path, "Hello, world!").unwrap();

        let tier = content_classification(path.to_str().unwrap());
        assert_eq!(tier, Some(Classification::T1));
    }

    #[test]
    fn test_content_classification_nonexistent_file() {
        let tier = content_classification(r"C:\nonexistent\file.txt");
        assert_eq!(tier, None);
    }

    #[test]
    fn test_content_classification_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, "").unwrap();

        let tier = content_classification(path.to_str().unwrap());
        assert_eq!(tier, None);
    }

    #[test]
    fn test_provisional_with_content_fallback() {
        // File NOT in a known sensitive directory but containing
        // confidential keywords — should be classified via content scan.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.txt");
        std::fs::write(&path, "This report is CONFIDENTIAL").unwrap();

        let tier = PolicyMapper::provisional_classification(
            path.to_str().unwrap(),
        );
        assert_eq!(tier, Classification::T3);
    }
}
