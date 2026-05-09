//! Shared constants and field predicates for the Print Config admin CLI screen.
//!
//! Used by both `render.rs` (draw) and `dispatch.rs` (event handling).
//!
//! Row layout:
//!   0: print_enabled          (bool toggle)
//!   1: print_xps_timeout_ms   (numeric)
//!   2: print_unclassifiable_action (picker: "Block" / "Allow")
//!   3: print_max_pages        (numeric)
//!   4: [ Save ]
//!   5: [ Back ]

/// JSON keys for the print config form, indexed by row.
pub const PRINT_CONFIG_KEYS: [&str; 4] = [
    "print_enabled",
    "print_xps_timeout_ms",
    "print_unclassifiable_action",
    "print_max_pages",
];

/// Human-readable labels for each field.
pub const PRINT_CONFIG_LABELS: [&str; 4] = [
    "Print Enabled",
    "XPS Timeout (ms)",
    "Unclassifiable Action",
    "Max Pages",
];

/// Picker options for `print_unclassifiable_action` (row 2).
pub const PRINT_UNCLASSIFIABLE_OPTIONS: &[&str] = &["Block", "Allow"];

/// Row index of the Save button.
pub const PRINT_CONFIG_SAVE_ROW: usize = 4;
/// Row index of the Back button.
pub const PRINT_CONFIG_BACK_ROW: usize = 5;
/// Total number of rows in the print config form (4 fields + Save + Back).
pub const PRINT_CONFIG_ROW_COUNT: usize = 6;

/// Returns `true` when `index` corresponds to `print_enabled` (the bool toggle at row 0).
pub fn is_print_bool(index: usize) -> bool {
    index == 0
}

/// Returns `true` when `index` corresponds to a numeric field (rows 1 and 3).
pub fn is_print_numeric(index: usize) -> bool {
    matches!(index, 1 | 3)
}

/// Returns `true` when `index` corresponds to the picker field `print_unclassifiable_action` (row 2).
pub fn is_print_picker(index: usize) -> bool {
    index == 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_config_keys_length_is_four() {
        assert_eq!(PRINT_CONFIG_KEYS.len(), 4);
        assert_eq!(PRINT_CONFIG_KEYS[0], "print_enabled");
        assert_eq!(PRINT_CONFIG_KEYS[1], "print_xps_timeout_ms");
        assert_eq!(PRINT_CONFIG_KEYS[2], "print_unclassifiable_action");
        assert_eq!(PRINT_CONFIG_KEYS[3], "print_max_pages");
    }

    #[test]
    fn print_config_labels_match_keys_length() {
        assert_eq!(PRINT_CONFIG_LABELS.len(), PRINT_CONFIG_KEYS.len());
    }

    #[test]
    fn print_config_row_constants_are_consistent() {
        assert_eq!(PRINT_CONFIG_ROW_COUNT, 6);
        assert_eq!(PRINT_CONFIG_SAVE_ROW, 4);
        assert_eq!(PRINT_CONFIG_BACK_ROW, 5);
        assert!(PRINT_CONFIG_SAVE_ROW < PRINT_CONFIG_ROW_COUNT);
        assert!(PRINT_CONFIG_BACK_ROW < PRINT_CONFIG_ROW_COUNT);
        assert!(PRINT_CONFIG_SAVE_ROW < PRINT_CONFIG_BACK_ROW);
    }

    #[test]
    fn is_print_bool_only_matches_row_0() {
        for i in 0..PRINT_CONFIG_ROW_COUNT {
            assert_eq!(is_print_bool(i), i == 0, "row {i}");
        }
    }

    #[test]
    fn is_print_numeric_matches_rows_1_and_3() {
        for i in 0..PRINT_CONFIG_ROW_COUNT {
            assert_eq!(is_print_numeric(i), matches!(i, 1 | 3), "row {i}");
        }
    }

    #[test]
    fn is_print_picker_only_matches_row_2() {
        for i in 0..PRINT_CONFIG_ROW_COUNT {
            assert_eq!(is_print_picker(i), i == 2, "row {i}");
        }
    }

    #[test]
    fn print_unclassifiable_options_are_block_and_allow() {
        assert_eq!(PRINT_UNCLASSIFIABLE_OPTIONS.len(), 2);
        assert_eq!(PRINT_UNCLASSIFIABLE_OPTIONS[0], "Block");
        assert_eq!(PRINT_UNCLASSIFIABLE_OPTIONS[1], "Allow");
    }
}
