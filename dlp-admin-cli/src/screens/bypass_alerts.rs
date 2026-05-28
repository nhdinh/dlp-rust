//! Shared constants for the bypass alerts screens.
//!
//! Used by both `render.rs` (draw) and `dispatch.rs` (event handling).

/// Footer hint for BypassAlertList screen.
#[allow(dead_code)]
pub const BYPASS_ALERT_LIST_HINTS: &str =
    "[a] Ack  [f] Filter Severity  [h] Hide Ack'd  [r] Refresh  [Enter] Detail  [PgUp/PgDn] Page  [Esc] Back";
/// Empty state message for BypassAlertList.
#[allow(dead_code)]
pub const BYPASS_ALERT_LIST_EMPTY: &str = "No bypass alerts found.";
/// Footer hint for BypassAlertDetail screen.
#[allow(dead_code)]
pub const BYPASS_ALERT_DETAIL_HINTS: &str = "[Enter/Esc] Back to list";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bypass_alert_list_hints_present() {
        assert!(BYPASS_ALERT_LIST_HINTS.contains("[a] Ack"));
        assert!(BYPASS_ALERT_LIST_HINTS.contains("[f] Filter Severity"));
        assert!(BYPASS_ALERT_LIST_HINTS.contains("[h] Hide Ack'd"));
        assert!(BYPASS_ALERT_LIST_HINTS.contains("[r] Refresh"));
        assert!(BYPASS_ALERT_LIST_HINTS.contains("[Enter] Detail"));
        assert!(BYPASS_ALERT_LIST_HINTS.contains("PgUp/PgDn"));
        assert!(BYPASS_ALERT_LIST_HINTS.contains("[Esc] Back"));
    }

    #[test]
    fn bypass_alert_detail_hints_present() {
        assert!(BYPASS_ALERT_DETAIL_HINTS.contains("[Enter/Esc]"));
    }

    #[test]
    fn bypass_alert_list_empty_message_present() {
        assert_eq!(BYPASS_ALERT_LIST_EMPTY, "No bypass alerts found.");
    }
}
