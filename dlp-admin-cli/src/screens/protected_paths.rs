//! Shared constants for the protected paths screens.
//!
//! Used by both `render.rs` (draw) and `dispatch.rs` (event handling).

/// Footer hint for ProtectedPathList screen.
#[allow(dead_code)]
pub const PROTECTED_PATH_LIST_HINTS: &str =
    "[a] Add  [d] Delete  [s] Sync  [r] Refresh  [PgUp/PgDn] Page  [Esc] Back";
/// Empty state message for ProtectedPathList.
#[allow(dead_code)]
pub const PROTECTED_PATH_LIST_EMPTY: &str = "No protected paths configured. Press [a] to add one.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_path_list_hints_present() {
        assert!(PROTECTED_PATH_LIST_HINTS.contains("[a] Add"));
        assert!(PROTECTED_PATH_LIST_HINTS.contains("[d] Delete"));
        assert!(PROTECTED_PATH_LIST_HINTS.contains("[s] Sync"));
        assert!(PROTECTED_PATH_LIST_HINTS.contains("[r] Refresh"));
        assert!(PROTECTED_PATH_LIST_HINTS.contains("PgUp/PgDn"));
        assert!(PROTECTED_PATH_LIST_HINTS.contains("[Esc] Back"));
    }

    #[test]
    fn protected_path_list_empty_has_add_hint() {
        assert!(PROTECTED_PATH_LIST_EMPTY.contains("[a]"));
    }
}
