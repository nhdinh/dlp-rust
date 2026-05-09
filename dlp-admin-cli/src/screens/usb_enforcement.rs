//! Shared constants for the USB enforcement config screen.
//!
//! Used by both `render.rs` (draw) and `dispatch.rs` (event handling).
//!
//! NOTE: Unimplemented options are EXCLUDED from the picker to prevent admin
//! confusion. When "Volume GUID resolution" or "Port-based disambiguation" are
//! implemented, add them to the appropriate slice here.

/// JSON keys for the USB enforcement config form, indexed by row.
pub const USB_ENFORCEMENT_KEYS: [&str; 3] = [
    "usb_blocked_failure_mode",
    "usb_startup_resolution_mode",
    "usb_none_serial_policy",
];

/// Value options for each picker field, indexed by row.
/// Uses `&[&[&str]]` for self-documenting variable-length rows (no empty-string padding).
pub const USB_ENFORCEMENT_OPTIONS: &[&[&str]] = &[
    &["Hard error", "Warning only", "Retry then error"],
    // "Volume GUID resolution" excluded — not yet implemented.
    &["VID/PID/serial fallback"],
    // "Port-based disambiguation" excluded — not yet implemented.
    &["Always Blocked", "Allow unregistered"],
];

/// Row index of the Save button.
pub const USB_ENFORCEMENT_SAVE_ROW: usize = 3;
/// Row index of the Back button.
pub const USB_ENFORCEMENT_BACK_ROW: usize = 4;
/// Total number of rows in the USB enforcement config form.
pub const USB_ENFORCEMENT_ROW_COUNT: usize = 5;

/// Human-readable labels for each picker field.
pub const USB_ENFORCEMENT_LABELS: [&str; 3] =
    ["Failure Mode", "Startup Resolution", "(none) Serial Policy"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_enforcement_keys_are_three() {
        assert_eq!(USB_ENFORCEMENT_KEYS.len(), 3);
        assert_eq!(USB_ENFORCEMENT_KEYS[0], "usb_blocked_failure_mode");
        assert_eq!(USB_ENFORCEMENT_KEYS[1], "usb_startup_resolution_mode");
        assert_eq!(USB_ENFORCEMENT_KEYS[2], "usb_none_serial_policy");
    }

    #[test]
    fn usb_enforcement_options_match_keys_length() {
        assert_eq!(USB_ENFORCEMENT_OPTIONS.len(), USB_ENFORCEMENT_KEYS.len());
    }

    #[test]
    fn usb_enforcement_options_excludes_unimplemented() {
        // Row 0: failure mode — all 3 options are implemented.
        assert_eq!(USB_ENFORCEMENT_OPTIONS[0].len(), 3);
        assert!(USB_ENFORCEMENT_OPTIONS[0].contains(&"Hard error"));
        assert!(USB_ENFORCEMENT_OPTIONS[0].contains(&"Warning only"));
        assert!(USB_ENFORCEMENT_OPTIONS[0].contains(&"Retry then error"));

        // Row 1: resolution mode — "Volume GUID resolution" excluded.
        assert_eq!(USB_ENFORCEMENT_OPTIONS[1].len(), 1);
        assert_eq!(USB_ENFORCEMENT_OPTIONS[1][0], "VID/PID/serial fallback");

        // Row 2: none-serial policy — "Port-based disambiguation" excluded.
        assert_eq!(USB_ENFORCEMENT_OPTIONS[2].len(), 2);
        assert_eq!(USB_ENFORCEMENT_OPTIONS[2][0], "Always Blocked");
        assert_eq!(USB_ENFORCEMENT_OPTIONS[2][1], "Allow unregistered");
    }

    #[test]
    fn usb_enforcement_row_constants_are_consistent() {
        assert_eq!(USB_ENFORCEMENT_ROW_COUNT, 5);
        assert_eq!(USB_ENFORCEMENT_SAVE_ROW, 3);
        assert_eq!(USB_ENFORCEMENT_BACK_ROW, 4);
        assert!(USB_ENFORCEMENT_SAVE_ROW < USB_ENFORCEMENT_ROW_COUNT);
        assert!(USB_ENFORCEMENT_BACK_ROW < USB_ENFORCEMENT_ROW_COUNT);
    }

    #[test]
    fn usb_enforcement_labels_match_keys() {
        assert_eq!(USB_ENFORCEMENT_LABELS.len(), USB_ENFORCEMENT_KEYS.len());
        assert_eq!(USB_ENFORCEMENT_LABELS[0], "Failure Mode");
        assert_eq!(USB_ENFORCEMENT_LABELS[1], "Startup Resolution");
        assert_eq!(USB_ENFORCEMENT_LABELS[2], "(none) Serial Policy");
    }
}
