//! Shared constants for the approval workflow screens.
//!
//! Used by both `render.rs` (draw) and `dispatch.rs` (event handling).

/// Footer hint for ApprovalList screen.
pub const APPROVAL_LIST_HINTS: &str =
    "[g] Grant  [r] Revoke  [v] View  [f] Filter  [PgUp/PgDn] Page  [Esc] Back";
/// Footer hint for ApprovalGrant screen.
pub const APPROVAL_GRANT_HINTS: &str = "[Enter] Grant  [Esc] Cancel";
/// Empty state message for ApprovalList.
pub const APPROVAL_LIST_EMPTY: &str = "No approvals found.";
/// Expiry duration options for the grant form: (hours, human-readable label).
pub const EXPIRY_OPTIONS: [(u32, &str); 4] = [
    (1, "1 hour"),
    (4, "4 hours"),
    (8, "8 hours"),
    (24, "24 hours"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_list_hints_present() {
        assert!(APPROVAL_LIST_HINTS.contains("[g] Grant"));
        assert!(APPROVAL_LIST_HINTS.contains("[r] Revoke"));
        assert!(APPROVAL_LIST_HINTS.contains("[v] View"));
        assert!(APPROVAL_LIST_HINTS.contains("[f] Filter"));
        assert!(APPROVAL_LIST_HINTS.contains("PgUp/PgDn"));
    }

    #[test]
    fn approval_grant_hints_present() {
        assert!(APPROVAL_GRANT_HINTS.contains("[Enter] Grant"));
        assert!(APPROVAL_GRANT_HINTS.contains("[Esc] Cancel"));
    }

    #[test]
    fn expiry_options_has_four_choices() {
        assert_eq!(EXPIRY_OPTIONS.len(), 4);
        assert_eq!(EXPIRY_OPTIONS[0], (1, "1 hour"));
        assert_eq!(EXPIRY_OPTIONS[3], (24, "24 hours"));
    }
}
