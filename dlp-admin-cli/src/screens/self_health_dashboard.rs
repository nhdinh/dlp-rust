//! Shared constants for the self-health dashboard screen.
//!
//! Used by both `render.rs` (draw) and `dispatch.rs` (event handling).

/// Footer hint for SelfHealthDashboard screen.
#[allow(dead_code)]
pub const SELF_HEALTH_HINTS: &str = "[r] Refresh  [Esc] Back to System Menu";
/// Empty state message for SelfHealthDashboard.
#[allow(dead_code)]
pub const SELF_HEALTH_EMPTY: &str = "No health data available.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_health_hints_present() {
        assert!(SELF_HEALTH_HINTS.contains("[r] Refresh"));
        assert!(SELF_HEALTH_HINTS.contains("[Esc] Back to System Menu"));
    }

    #[test]
    fn self_health_empty_message_present() {
        assert_eq!(SELF_HEALTH_EMPTY, "No health data available.");
    }
}
