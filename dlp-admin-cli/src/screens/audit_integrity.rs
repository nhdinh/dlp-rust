//! Shared constants for the audit integrity screens.
//!
//! Used by both `render.rs` (draw) and `dispatch.rs` (event handling).

/// Footer hint for AuditIntegrityList screen.
#[allow(dead_code)]
pub const AUDIT_INTEGRITY_LIST_HINTS: &str =
    "[f] Filter Agent  [r] Refresh  [Enter] Detail  [PgUp/PgDn] Page  [Esc] Back";
/// Empty state message for AuditIntegrityList.
#[allow(dead_code)]
pub const AUDIT_INTEGRITY_LIST_EMPTY: &str = "No audit integrity data found.";
/// Footer hint for AuditIntegrityDetail screen.
#[allow(dead_code)]
pub const AUDIT_INTEGRITY_DETAIL_HINTS: &str = "[Enter/Esc] Back to list";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_integrity_list_hints_present() {
        assert!(AUDIT_INTEGRITY_LIST_HINTS.contains("[f] Filter Agent"));
        assert!(AUDIT_INTEGRITY_LIST_HINTS.contains("[r] Refresh"));
        assert!(AUDIT_INTEGRITY_LIST_HINTS.contains("[Enter] Detail"));
        assert!(AUDIT_INTEGRITY_LIST_HINTS.contains("PgUp/PgDn"));
        assert!(AUDIT_INTEGRITY_LIST_HINTS.contains("[Esc] Back"));
    }

    #[test]
    fn test_audit_integrity_list_empty_message_present() {
        assert_eq!(AUDIT_INTEGRITY_LIST_EMPTY, "No audit integrity data found.");
    }

    #[test]
    fn test_audit_integrity_detail_hints_present() {
        assert!(AUDIT_INTEGRITY_DETAIL_HINTS.contains("[Enter/Esc]"));
    }
}
