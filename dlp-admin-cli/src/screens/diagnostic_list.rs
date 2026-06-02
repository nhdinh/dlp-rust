//! Shared constants for the diagnostic events screens.
//!
//! Used by both `render.rs` (draw) and `dispatch.rs` (event handling).

/// Footer hint for DiagnosticList screen.
#[allow(dead_code)]
pub const DIAGNOSTIC_LIST_HINTS: &str =
    "[Enter] Detail  [f] Filter Severity  [h] Hide Ack'd  [r] Refresh  [PgUp/PgDn] Page  [Esc] Back";
/// Empty state message for DiagnosticList.
#[allow(dead_code)]
pub const DIAGNOSTIC_LIST_EMPTY: &str = "No diagnostic events found.";
/// Footer hint for DiagnosticDetail screen.
#[allow(dead_code)]
pub const DIAGNOSTIC_DETAIL_HINTS: &str = "[Enter/Esc] Back to list";

/// Filter state for the DiagnosticList screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub enum DiagnosticSeverityFilter {
    #[default]
    All,
    Crit,
    Warn,
    Info,
}

#[allow(dead_code)]
impl DiagnosticSeverityFilter {
    /// Cycles to the next filter state.
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Crit,
            Self::Crit => Self::Warn,
            Self::Warn => Self::Info,
            Self::Info => Self::All,
        }
    }

    /// Returns the wire-format query parameter value, or None for "all".
    pub fn as_str(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::Crit => Some("crit"),
            Self::Warn => Some("warn"),
            Self::Info => Some("info"),
        }
    }

    /// Returns the human-readable display label.
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Crit => "Critical",
            Self::Warn => "Warning",
            Self::Info => "Info",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_list_hints_present() {
        assert!(DIAGNOSTIC_LIST_HINTS.contains("[Enter] Detail"));
        assert!(DIAGNOSTIC_LIST_HINTS.contains("[f] Filter Severity"));
        assert!(DIAGNOSTIC_LIST_HINTS.contains("[h] Hide Ack'd"));
        assert!(DIAGNOSTIC_LIST_HINTS.contains("[r] Refresh"));
        assert!(DIAGNOSTIC_LIST_HINTS.contains("PgUp/PgDn"));
        assert!(DIAGNOSTIC_LIST_HINTS.contains("[Esc] Back"));
    }

    #[test]
    fn diagnostic_detail_hints_present() {
        assert!(DIAGNOSTIC_DETAIL_HINTS.contains("[Enter/Esc]"));
    }

    #[test]
    fn diagnostic_list_empty_message_present() {
        assert_eq!(DIAGNOSTIC_LIST_EMPTY, "No diagnostic events found.");
    }

    #[test]
    fn diagnostic_severity_filter_next_cycles() {
        assert_eq!(
            DiagnosticSeverityFilter::All.next(),
            DiagnosticSeverityFilter::Crit
        );
        assert_eq!(
            DiagnosticSeverityFilter::Crit.next(),
            DiagnosticSeverityFilter::Warn
        );
        assert_eq!(
            DiagnosticSeverityFilter::Warn.next(),
            DiagnosticSeverityFilter::Info
        );
        assert_eq!(
            DiagnosticSeverityFilter::Info.next(),
            DiagnosticSeverityFilter::All
        );
    }

    #[test]
    fn diagnostic_severity_filter_as_str() {
        assert_eq!(DiagnosticSeverityFilter::All.as_str(), None);
        assert_eq!(DiagnosticSeverityFilter::Crit.as_str(), Some("crit"));
        assert_eq!(DiagnosticSeverityFilter::Warn.as_str(), Some("warn"));
        assert_eq!(DiagnosticSeverityFilter::Info.as_str(), Some("info"));
    }

    #[test]
    fn diagnostic_severity_filter_label() {
        assert_eq!(DiagnosticSeverityFilter::All.label(), "All");
        assert_eq!(DiagnosticSeverityFilter::Crit.label(), "Critical");
        assert_eq!(DiagnosticSeverityFilter::Warn.label(), "Warning");
        assert_eq!(DiagnosticSeverityFilter::Info.label(), "Info");
    }
}
