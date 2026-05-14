//! Syslog forwarder configuration screen.
//!
//! Mirrors the SiemConfig screen pattern with picker cycling for select fields.
//! 13 editable config fields + Test Connection + Save + Back = 16 rows total.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

use crate::app::{App, Screen, StatusKind};

// ---------------------------------------------------------------------------
// Row layout constants
// ---------------------------------------------------------------------------

/// JSON keys for the 13 editable config fields, indexed by row.
const SYSLOG_KEYS: [&str; 13] = [
    "host",
    "port",
    "enabled",
    "protocol",
    "facility_code",
    "format",
    "batching_enabled",
    "severity_alert",
    "severity_block",
    "severity_audit",
    "queue_policy",
    "queue_max_size",
    "tls_min_version",
];

/// Row index of the [Test Connection] action button.
const SYSLOG_TEST_ROW: usize = 13;
/// Row index of the [Save] action button.
const SYSLOG_SAVE_ROW: usize = 14;
/// Row index of the [Back] action button.
const SYSLOG_BACK_ROW: usize = 15;
/// Total number of rows in the syslog config form.
pub const SYSLOG_ROW_COUNT: usize = 16;

// ---------------------------------------------------------------------------
// Picker options
// ---------------------------------------------------------------------------

const PROTOCOL_OPTIONS: [&str; 1] = ["tls"];
const FACILITY_OPTIONS: [&str; 8] = [
    "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7",
];
const FORMAT_OPTIONS: [&str; 1] = ["json"];
const QUEUE_POLICY_OPTIONS: [&str; 3] = ["fifo_tail_drop", "fifo_head_drop", "ring_buffer"];
const TLS_VERSION_OPTIONS: [&str; 2] = ["1.2", "1.3"];

/// Fields that use picker cycling instead of text edit mode.
const PICKER_FIELDS: [&str; 5] = [
    "protocol",
    "facility_code",
    "format",
    "queue_policy",
    "tls_min_version",
];

/// Fields that are boolean toggles.
#[allow(dead_code)]
const BOOL_FIELDS: [&str; 2] = ["enabled", "batching_enabled"];

/// Fields that are numeric.
#[allow(dead_code)]
const NUMERIC_FIELDS: [&str; 6] = [
    "port",
    "facility_code",
    "severity_alert",
    "severity_block",
    "severity_audit",
    "queue_max_size",
];

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

const SYSLOG_FIELD_LABELS: [&str; 16] = [
    "Host",
    "Port",
    "Enabled",
    "Protocol",
    "Facility",
    "Format",
    "Batching",
    "Severity (Alert)",
    "Severity (Block)",
    "Severity (Audit)",
    "Queue Policy",
    "Max Queue Size",
    "TLS Min Version",
    "[ Test Connection ]",
    "[ Save ]",
    "[ Back ]",
];

// ---------------------------------------------------------------------------
// Event handling
// ---------------------------------------------------------------------------

/// Routes key events to the syslog config screen handler.
pub fn handle_syslog_config(app: &mut App, key: KeyEvent) {
    let (selected, editing) = match &app.screen {
        Screen::SyslogConfig {
            selected, editing, ..
        } => (*selected, *editing),
        _ => return,
    };

    if editing {
        handle_syslog_config_editing(app, key, selected);
    } else {
        handle_syslog_config_nav(app, key, selected);
    }
}

fn handle_syslog_config_nav(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Up => {
            if let Screen::SyslogConfig { selected: sel, .. } = &mut app.screen {
                *sel = sel.checked_sub(1).unwrap_or(SYSLOG_ROW_COUNT - 1);
            }
        }
        KeyCode::Down => {
            if let Screen::SyslogConfig { selected: sel, .. } = &mut app.screen {
                *sel = (*sel + 1) % SYSLOG_ROW_COUNT;
            }
        }
        KeyCode::Enter => {
            match selected {
                SYSLOG_TEST_ROW => action_test_syslog_config(app),
                SYSLOG_SAVE_ROW => action_save_syslog_config(app),
                SYSLOG_BACK_ROW => app.screen = Screen::SystemMenu { selected: 2 },
                _ => {
                    let key_str = SYSLOG_KEYS[selected];
                    if PICKER_FIELDS.contains(&key_str) {
                        cycle_picker_value(app, key_str);
                    } else if is_syslog_bool(selected) {
                        // Toggle bool in place
                        if let Screen::SyslogConfig { config, .. } = &mut app.screen {
                            let cur = config[key_str].as_bool().unwrap_or(false);
                            config[key_str] = serde_json::Value::Bool(!cur);
                        }
                    } else {
                        // Enter text edit mode
                        if let Screen::SyslogConfig {
                            config,
                            editing,
                            buffer,
                            ..
                        } = &mut app.screen
                        {
                            *buffer = config[key_str].as_str().unwrap_or("").to_string();
                            *editing = true;
                        }
                    }
                }
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::SystemMenu { selected: 2 };
        }
        _ => {}
    }
}

fn handle_syslog_config_editing(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Char(c) => {
            if let Screen::SyslogConfig { buffer, .. } = &mut app.screen {
                buffer.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Screen::SyslogConfig { buffer, .. } = &mut app.screen {
                buffer.pop();
            }
        }
        KeyCode::Enter => {
            if let Screen::SyslogConfig {
                config,
                selected: _,
                editing,
                buffer,
                ..
            } = &mut app.screen
            {
                let key_str = SYSLOG_KEYS[selected];
                let value = match key_str {
                    "port" => {
                        let port = buffer.parse::<i64>().unwrap_or_default();
                        if !(1..=65535).contains(&port) {
                            app.set_status("Port must be 1-65535".to_string(), StatusKind::Error);
                            return;
                        }
                        serde_json::json!(port)
                    }
                    "facility_code" => {
                        let code = buffer.parse::<i64>().unwrap_or_default();
                        if !(16..=23).contains(&code) {
                            app.set_status(
                                "Facility must be 16-23 (LOCAL0-LOCAL7)".to_string(),
                                StatusKind::Error,
                            );
                            return;
                        }
                        serde_json::json!(code)
                    }
                    "severity_alert" | "severity_block" | "severity_audit" => {
                        let sev = buffer.parse::<i64>().unwrap_or_default();
                        if !(0..=7).contains(&sev) {
                            app.set_status("Severity must be 0-7".to_string(), StatusKind::Error);
                            return;
                        }
                        serde_json::json!(sev)
                    }
                    "queue_max_size" => {
                        let size = buffer.parse::<i64>().unwrap_or_default();
                        serde_json::json!(size)
                    }
                    _ => serde_json::Value::String(buffer.clone()),
                };
                config[key_str] = value;
                buffer.clear();
                *editing = false;
            }
        }
        KeyCode::Esc => {
            if let Screen::SyslogConfig {
                buffer, editing, ..
            } = &mut app.screen
            {
                buffer.clear();
                *editing = false;
            }
        }
        _ => {}
    }
}

fn cycle_picker_value(app: &mut App, key_str: &str) {
    if let Screen::SyslogConfig { config, .. } = &mut app.screen {
        let options: &[&str] = match key_str {
            "protocol" => &PROTOCOL_OPTIONS,
            "facility_code" => &FACILITY_OPTIONS,
            "format" => &FORMAT_OPTIONS,
            "queue_policy" => &QUEUE_POLICY_OPTIONS,
            "tls_min_version" => &TLS_VERSION_OPTIONS,
            _ => return,
        };

        let current = config[key_str].as_str().unwrap_or("");
        let current_idx = options.iter().position(|&o| o == current).unwrap_or(0);
        let next_idx = (current_idx + 1) % options.len();
        let next_value = options[next_idx];

        // For facility_code, store numeric code (16-23) but display LOCAL0-LOCAL7
        let value = if key_str == "facility_code" {
            let code = 16 + next_idx as i64;
            serde_json::json!(code)
        } else {
            serde_json::Value::String(next_value.to_string())
        };

        config[key_str] = value;
    }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// Fetches the current syslog config from the server and switches to the
/// `SyslogConfig` screen.
pub fn action_load_syslog_config(app: &mut App) {
    match app
        .rt
        .block_on(app.client.get::<serde_json::Value>("admin/syslog-config"))
    {
        Ok(config) => {
            app.screen = Screen::SyslogConfig {
                config,
                selected: 0,
                editing: false,
                buffer: String::new(),
            };
        }
        Err(e) => app.set_status(
            format!("Failed to load syslog config: {e}"),
            StatusKind::Error,
        ),
    }
}

/// Persists the in-memory syslog config to the server.
pub fn action_save_syslog_config(app: &mut App) {
    let payload = match &app.screen {
        Screen::SyslogConfig { config, .. } => config.clone(),
        _ => return,
    };
    match app.rt.block_on(
        app.client
            .put::<serde_json::Value, _>("admin/syslog-config", &payload),
    ) {
        Ok(_) => {
            app.set_status("Syslog config saved", StatusKind::Success);
            app.screen = Screen::SystemMenu { selected: 2 };
        }
        Err(e) => app.set_status(format!("Failed to save: {e}"), StatusKind::Error),
    }
}

/// Sends a test connection request to the server.
pub fn action_test_syslog_config(app: &mut App) {
    match app.rt.block_on(
        app.client
            .post::<serde_json::Value, _>("admin/syslog-config/test", &serde_json::json!({})),
    ) {
        Ok(response) => {
            let status = response
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let message = response
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if status == "ok" {
                app.set_status(format!("Test OK: {message}"), StatusKind::Success);
            } else {
                app.set_status(format!("Test failed: {message}"), StatusKind::Error);
            }
        }
        Err(e) => app.set_status(format!("Test request failed: {e}"), StatusKind::Error),
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Draws the syslog configuration form.
pub fn draw_syslog_config(
    frame: &mut Frame,
    area: Rect,
    config: &serde_json::Value,
    selected: usize,
    editing: bool,
    buffer: &str,
) {
    let mut items: Vec<ListItem> = Vec::with_capacity(SYSLOG_FIELD_LABELS.len());

    for (i, label) in SYSLOG_FIELD_LABELS.iter().enumerate() {
        let line = if i < SYSLOG_KEYS.len() {
            let key = SYSLOG_KEYS[i];
            let value_display =
                format_syslog_field_value(config, key, i, selected, editing, buffer);
            format!("{label}: {value_display}")
        } else {
            (*label).to_string()
        };
        items.push(ListItem::new(Line::from(line)));
    }

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Syslog Forwarder Config ")
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = ListState::default();
    state.select(Some(selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn format_syslog_field_value(
    config: &serde_json::Value,
    key: &str,
    index: usize,
    selected: usize,
    editing: bool,
    buffer: &str,
) -> String {
    if editing && index == selected {
        return format!("[{buffer}_]");
    }
    if is_syslog_bool(index) {
        let b = config[key].as_bool().unwrap_or(false);
        return if b {
            "[x]".to_string()
        } else {
            "[ ]".to_string()
        };
    }
    if key == "facility_code" {
        return config
            .get(key)
            .and_then(|v| v.as_i64())
            .map(|code| {
                let idx = (code - 16).clamp(0, 7) as usize;
                FACILITY_OPTIONS.get(idx).unwrap_or(&"UNKNOWN").to_string()
            })
            .unwrap_or_default();
    }
    if is_syslog_numeric(index) {
        let n = config[key].as_i64().unwrap_or(0);
        return n.to_string();
    }
    let v = config[key].as_str().unwrap_or("");
    if v.is_empty() {
        "(empty)".to_string()
    } else {
        v.to_string()
    }
}

fn is_syslog_bool(index: usize) -> bool {
    matches!(index, 2 | 6)
}

fn is_syslog_numeric(index: usize) -> bool {
    matches!(index, 1 | 4 | 7 | 8 | 9 | 11)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syslog_row_count_matches_keys_plus_actions() {
        assert_eq!(SYSLOG_KEYS.len() + 3, SYSLOG_ROW_COUNT);
    }

    #[test]
    fn test_field_labels_count_matches_row_count() {
        assert_eq!(SYSLOG_FIELD_LABELS.len(), SYSLOG_ROW_COUNT);
    }

    #[test]
    fn test_is_syslog_bool_matches_enabled_and_batching() {
        assert!(is_syslog_bool(2)); // enabled
        assert!(is_syslog_bool(6)); // batching_enabled
        assert!(!is_syslog_bool(0)); // host
        assert!(!is_syslog_bool(1)); // port
    }

    #[test]
    fn test_is_syslog_numeric_matches_expected_indices() {
        assert!(is_syslog_numeric(1)); // port
        assert!(is_syslog_numeric(4)); // facility_code
        assert!(is_syslog_numeric(7)); // severity_alert
        assert!(is_syslog_numeric(11)); // queue_max_size
        assert!(!is_syslog_numeric(0)); // host
        assert!(!is_syslog_numeric(2)); // enabled
    }

    #[test]
    fn test_facility_display_mapping() {
        let config = serde_json::json!({"facility_code": 20});
        let display = format_syslog_field_value(&config, "facility_code", 4, 0, false, "");
        assert_eq!(display, "LOCAL4");
    }

    #[test]
    fn test_facility_display_clamps_out_of_range() {
        let config = serde_json::json!({"facility_code": 99});
        let display = format_syslog_field_value(&config, "facility_code", 4, 0, false, "");
        assert_eq!(display, "LOCAL7");
    }

    #[test]
    fn test_bool_display_checked_and_unchecked() {
        let config_true = serde_json::json!({"enabled": true});
        let display_true = format_syslog_field_value(&config_true, "enabled", 2, 0, false, "");
        assert_eq!(display_true, "[x]");

        let config_false = serde_json::json!({"enabled": false});
        let display_false = format_syslog_field_value(&config_false, "enabled", 2, 0, false, "");
        assert_eq!(display_false, "[ ]");
    }

    #[test]
    fn test_numeric_display() {
        let config = serde_json::json!({"port": 514});
        let display = format_syslog_field_value(&config, "port", 1, 0, false, "");
        assert_eq!(display, "514");
    }

    #[test]
    fn test_text_display_with_value() {
        let config = serde_json::json!({"host": "syslog.example.com"});
        let display = format_syslog_field_value(&config, "host", 0, 0, false, "");
        assert_eq!(display, "syslog.example.com");
    }

    #[test]
    fn test_text_display_empty_fallback() {
        let config = serde_json::json!({"host": ""});
        let display = format_syslog_field_value(&config, "host", 0, 0, false, "");
        assert_eq!(display, "(empty)");
    }

    #[test]
    fn test_editing_buffer_display() {
        let config = serde_json::json!({"host": "old"});
        let display = format_syslog_field_value(&config, "host", 0, 0, true, "new");
        assert_eq!(display, "[new_]");
    }

    #[test]
    fn test_picker_fields_list_complete() {
        assert_eq!(PICKER_FIELDS.len(), 5);
        assert!(PICKER_FIELDS.contains(&"protocol"));
        assert!(PICKER_FIELDS.contains(&"facility_code"));
        assert!(PICKER_FIELDS.contains(&"format"));
        assert!(PICKER_FIELDS.contains(&"queue_policy"));
        assert!(PICKER_FIELDS.contains(&"tls_min_version"));
    }
}
