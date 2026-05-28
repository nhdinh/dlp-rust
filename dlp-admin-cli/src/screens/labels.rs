//! Shared constants for the label management screens.
//!
//! Used by both `render.rs` (draw) and `dispatch.rs` (event handling).

/// Footer hint for LabelList screen.
pub const LABEL_LIST_HINTS: &str =
    "[n] New  [e] Edit  [d] Delete  [v] View  [f] Filter  [x] Expire  [PgUp/PgDn] Page  [Esc] Back";
/// Footer hint for LabelReviewQueue screen.
pub const LABEL_REVIEW_HINTS: &str =
    "[c] Confirm  [r] Reject  [d] Dept Filter  [↑/↓] Navigate  [Esc] Back";
/// Empty state message for LabelList.
pub const LABEL_LIST_EMPTY: &str = "No labels found. Press [n] to create one.";
/// Empty state message for LabelReviewQueue.
pub const LABEL_REVIEW_EMPTY: &str = "No temporary labels pending review.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_list_hints_present() {
        assert!(LABEL_LIST_HINTS.contains("[n] New"));
        assert!(LABEL_LIST_HINTS.contains("[e] Edit"));
        assert!(LABEL_LIST_HINTS.contains("[d] Delete"));
        assert!(LABEL_LIST_HINTS.contains("[v] View"));
        assert!(LABEL_LIST_HINTS.contains("[f] Filter"));
        assert!(LABEL_LIST_HINTS.contains("[x] Expire"));
        assert!(LABEL_LIST_HINTS.contains("[PgUp/PgDn] Page"));
    }

    #[test]
    fn label_review_hints_present() {
        assert!(LABEL_REVIEW_HINTS.contains("[c] Confirm"));
        assert!(LABEL_REVIEW_HINTS.contains("[r] Reject"));
    }

    #[test]
    fn test_label_detail_non_recursive() {
        // If LabelDetail had a Screen-typed field, this would not compile.
        let detail = crate::app::Screen::LabelDetail {
            label: serde_json::json!({}),
        };
        assert!(matches!(detail, crate::app::Screen::LabelDetail { .. }));
    }
}
