//! Shared constants for the Cloud Config admin CLI screen.
//!
//! Used by both `render.rs` (draw) and `dispatch.rs` (event handling).
//! The cloud hook is a single boolean: `cloud_hook_enabled`.

/// JSON key for the cloud hook config field.
pub const CLOUD_CONFIG_KEYS: [&str; 1] = ["cloud_hook_enabled"];

/// Human-readable label for the cloud hook field.
pub const CLOUD_CONFIG_LABELS: [&str; 1] = ["Cloud Hook"];

/// Row index of the Save button.
pub const CLOUD_CONFIG_SAVE_ROW: usize = 1;
/// Row index of the Back button.
pub const CLOUD_CONFIG_BACK_ROW: usize = 2;
/// Total number of rows in the cloud config form (1 field + Save + Back).
pub const CLOUD_CONFIG_ROW_COUNT: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_config_keys_length_is_one() {
        assert_eq!(CLOUD_CONFIG_KEYS.len(), 1);
        assert_eq!(CLOUD_CONFIG_KEYS[0], "cloud_hook_enabled");
    }

    #[test]
    fn cloud_config_labels_match_keys_length() {
        assert_eq!(CLOUD_CONFIG_LABELS.len(), CLOUD_CONFIG_KEYS.len());
        assert_eq!(CLOUD_CONFIG_LABELS[0], "Cloud Hook");
    }

    #[test]
    fn cloud_config_row_constants_are_consistent() {
        assert_eq!(CLOUD_CONFIG_ROW_COUNT, 3);
        assert_eq!(CLOUD_CONFIG_SAVE_ROW, 1);
        assert_eq!(CLOUD_CONFIG_BACK_ROW, 2);
        const _: () = assert!(CLOUD_CONFIG_SAVE_ROW < CLOUD_CONFIG_ROW_COUNT);
        const _: () = assert!(CLOUD_CONFIG_BACK_ROW < CLOUD_CONFIG_ROW_COUNT);
        const _: () = assert!(CLOUD_CONFIG_SAVE_ROW < CLOUD_CONFIG_BACK_ROW);
    }
}
