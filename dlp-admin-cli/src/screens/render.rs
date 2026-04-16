//! Renders the current [`Screen`] to the terminal frame.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table, Wrap,
};
use ratatui::Frame;

use crate::app::{App, ConditionAttribute, Screen, StatusKind, ACTION_OPTIONS, ATTRIBUTES};
use crate::screens::dispatch::condition_display;

/// Top-level draw function dispatched from the event loop.
pub fn draw(app: &App, frame: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(frame.area());

    draw_screen(app, frame, chunks[0]);
    draw_status_bar(app, frame, chunks[1]);
}

/// Renders the current screen into the main area.
fn draw_screen(app: &App, frame: &mut Frame, area: Rect) {
    match &app.screen {
        Screen::MainMenu { selected } => {
            draw_menu(
                frame,
                area,
                "dlp-admin-cli",
                &["Password Management", "Policy Management", "System", "Exit"],
                *selected,
            );
        }
        Screen::PasswordMenu { selected } => {
            draw_menu(
                frame,
                area,
                "Password Management",
                &[
                    "Change Admin Password",
                    "Set Agent Password",
                    "Verify Agent Password",
                    "Back",
                ],
                *selected,
            );
        }
        Screen::PolicyMenu { selected } => {
            draw_menu(
                frame,
                area,
                "Policy Management",
                &[
                    "List Policies",
                    "Get Policy",
                    "Create Policy",
                    "Update Policy",
                    "Delete Policy",
                    "Back",
                ],
                *selected,
            );
        }
        Screen::SystemMenu { selected } => {
            draw_menu(
                frame,
                area,
                "System",
                &[
                    "Server Status",
                    "Agent List",
                    "SIEM Config",
                    "Alert Config",
                    "Back",
                ],
                *selected,
            );
        }
        Screen::PolicyList { policies, selected } => {
            draw_policy_list(frame, area, policies, *selected);
        }
        Screen::PolicyDetail { policy } => {
            draw_json_detail(frame, area, "Policy Detail", policy);
        }
        Screen::TextInput { prompt, input, .. } => {
            draw_input(frame, area, prompt, input, false);
        }
        Screen::PasswordInput { prompt, input, .. } => {
            draw_input(frame, area, prompt, input, true);
        }
        Screen::Confirm {
            message,
            yes_selected,
            ..
        } => {
            draw_confirm(frame, area, message, *yes_selected);
        }
        Screen::ServerStatus { health, ready } => {
            let text = format!("Health: {health}\nReady:  {ready}");
            draw_result(frame, area, "Server Status", &text);
        }
        Screen::AgentList { agents, selected } => {
            draw_agent_list(frame, area, agents, *selected);
        }
        Screen::ResultView { title, body } => {
            draw_result(frame, area, title, body);
        }
        Screen::SiemConfig {
            config,
            selected,
            editing,
            buffer,
        } => {
            draw_siem_config(frame, area, config, *selected, *editing, buffer);
        }
        Screen::AlertConfig {
            config,
            selected,
            editing,
            buffer,
        } => {
            draw_alert_config(frame, area, config, *selected, *editing, buffer);
        }
        Screen::ConditionsBuilder {
            step,
            selected_attribute,
            selected_operator,
            pending,
            buffer,
            pending_focused,
            pending_state,
            picker_state,
            ..
        } => {
            draw_conditions_builder(
                frame,
                area,
                *step,
                selected_attribute.as_ref(),
                selected_operator.as_deref(),
                pending,
                buffer,
                *pending_focused,
                pending_state,
                picker_state,
            );
        }
        Screen::PolicyCreate {
            form,
            selected,
            editing,
            buffer,
            validation_error,
        } => {
            draw_policy_create(
                frame,
                area,
                form,
                *selected,
                *editing,
                buffer,
                validation_error.as_deref(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Conditions builder helpers and render function
// ---------------------------------------------------------------------------

/// Step 3 value labels for Classification (per D-11).
const CLASSIFICATION_VALUES: [&str; 4] = [
    "T1: Public",
    "T2: Internal",
    "T3: Confidential",
    "T4: Restricted",
];

/// Step 3 value labels for DeviceTrust (per D-13).
const DEVICE_TRUST_VALUES: [&str; 4] = ["Managed", "Unmanaged", "Compliant", "Unknown"];

/// Step 3 value labels for NetworkLocation (per D-14).
const NETWORK_LOCATION_VALUES: [&str; 4] = ["Corporate", "CorporateVpn", "Guest", "Unknown"];

/// Step 3 value labels for AccessContext (per D-15).
const ACCESS_CONTEXT_VALUES: [&str; 2] = ["Local", "Smb"];

/// Step 2 operator labels for all attributes (only `eq` is enforced today).
const OPERATOR_EQ: [(&str, bool); 1] = [("eq", true)];

/// Builds the step breadcrumb line with mixed styles.
///
/// Current step is White+BOLD; completed steps are DarkGray.
fn build_breadcrumb(step: u8) -> Line<'static> {
    let completed = Style::default().fg(Color::DarkGray);
    let current = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let sep = Style::default().fg(Color::DarkGray);

    let s1 = if step == 1 { current } else { completed };
    let s2 = if step == 2 { current } else { completed };
    let s3 = if step == 3 { current } else { completed };

    Line::from(vec![
        Span::styled("Step 1: Attribute", s1),
        Span::styled(" > ", sep),
        Span::styled("Step 2: Operator", s2),
        Span::styled(" > ", sep),
        Span::styled("Step 3: Value", s3),
    ])
}

/// Returns the step indicator label shown above the picker list.
fn step_label(step: u8, selected_attribute: Option<&ConditionAttribute>) -> Line<'static> {
    let attr_name = selected_attribute.map(|a| a.label()).unwrap_or("");
    match step {
        1 => Line::styled(
            "Step 1: Attribute",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        2 => Line::styled(
            format!("Step 2: Operator  [{attr_name}]"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        3 => Line::styled(
            format!("Step 3 of 3 -- Value  [{attr_name}]"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        _ => Line::raw(""),
    }
}

/// Returns the list items for the step picker at the given step.
fn picker_items(
    step: u8,
    selected_attribute: Option<&ConditionAttribute>,
) -> Vec<ListItem<'static>> {
    match step {
        1 => ATTRIBUTES
            .iter()
            .map(|a| ListItem::new(a.label().to_string()))
            .collect(),
        2 => OPERATOR_EQ
            .iter()
            .map(|(op, enforced)| {
                if *enforced {
                    ListItem::new(op.to_string())
                } else {
                    ListItem::new(Line::from(vec![
                        Span::raw(op.to_string()),
                        Span::styled("  (not enforced)", Style::default().fg(Color::DarkGray)),
                    ]))
                }
            })
            .collect(),
        3 => {
            let attr = match selected_attribute {
                Some(a) => a,
                None => return vec![],
            };
            match attr {
                ConditionAttribute::Classification => CLASSIFICATION_VALUES
                    .iter()
                    .map(|v| ListItem::new(v.to_string()))
                    .collect(),
                ConditionAttribute::MemberOf => vec![], // text input, not a list
                ConditionAttribute::DeviceTrust => DEVICE_TRUST_VALUES
                    .iter()
                    .map(|v| ListItem::new(v.to_string()))
                    .collect(),
                ConditionAttribute::NetworkLocation => NETWORK_LOCATION_VALUES
                    .iter()
                    .map(|v| ListItem::new(v.to_string()))
                    .collect(),
                ConditionAttribute::AccessContext => ACCESS_CONTEXT_VALUES
                    .iter()
                    .map(|v| ListItem::new(v.to_string()))
                    .collect(),
            }
        }
        _ => vec![],
    }
}

/// Renders the conditions builder modal overlay.
///
/// Draws a centered 60%-width, 22-row modal with:
/// - Breadcrumb header (2 rows)
/// - Pending conditions list (6 rows, scrollable)
/// - Divider (1 row)
/// - Step picker (remaining rows)
/// - Hints bar (1 row, inside modal bottom)
///
/// # Arguments
///
/// * `frame` - ratatui frame to render into
/// * `area` - full terminal area (modal is centered within this)
/// * `step` - current step number (1, 2, or 3)
/// * `selected_attribute` - attribute chosen in Step 1 (None until completed)
/// * `selected_operator` - operator chosen in Step 2 (None until completed)
/// * `pending` - conditions already added this session
/// * `buffer` - text buffer for MemberOf Step 3 free-text input
/// * `pending_focused` - true when the pending list has keyboard focus
/// * `pending_state` - scroll position for the pending list
/// * `picker_state` - scroll position for the step picker list
#[allow(clippy::too_many_arguments)]
fn draw_conditions_builder(
    frame: &mut Frame,
    area: Rect,
    step: u8,
    selected_attribute: Option<&ConditionAttribute>,
    // Operator is resolved for future steps; accepted here for completeness.
    _selected_operator: Option<&str>,
    pending: &[dlp_common::abac::PolicyCondition],
    buffer: &str,
    pending_focused: bool,
    pending_state: &ListState,
    picker_state: &ListState,
) {
    // Full-frame Clear to overlay parent content (matches draw_hints pattern).
    frame.render_widget(Clear, area);

    // Center a 60%-width, 22-row modal box.
    let modal_width = area.width * 60 / 100;
    let modal_height = 22_u16.min(area.height);
    let modal_x = area.x + (area.width.saturating_sub(modal_width)) / 2;
    let modal_y = area.y + (area.height.saturating_sub(modal_height)) / 2;
    let modal_area = Rect {
        x: modal_x,
        y: modal_y,
        width: modal_width,
        height: modal_height,
    };

    let modal_block = Block::default()
        .title(" Conditions Builder ")
        .borders(Borders::ALL);
    // CRITICAL: compute inner BEFORE rendering; inner() borrows &self so must be
    // called before the block is moved into render_widget (Pitfall 3 from PATTERNS.md).
    let inner = modal_block.inner(modal_area);
    frame.render_widget(modal_block, modal_area);

    // Split interior into sub-areas per UI-SPEC area allocations.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // header / breadcrumb
            Constraint::Length(6), // pending list
            Constraint::Length(1), // divider
            Constraint::Min(0),    // step picker (fills remaining)
        ])
        .split(inner);

    let header_area = chunks[0];
    let pending_area = chunks[1];
    let divider_area = chunks[2];
    let picker_area = chunks[3];

    // --- Header: breadcrumb ---
    let breadcrumb = build_breadcrumb(step);
    frame.render_widget(Paragraph::new(breadcrumb), header_area);

    // --- Divider ---
    // Use a Block with only a top border so ratatui draws the separator line
    // without allocating a String on every render tick.
    let divider = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    frame.render_widget(divider, divider_area);

    // --- Pending conditions list ---
    if pending.is_empty() {
        // Per D-19: empty state placeholder in DarkGray.
        let empty = Paragraph::new(Line::from(
            "No conditions added. Use the picker below to add conditions.",
        ))
        .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(empty, pending_area);
    } else {
        let pending_highlight = if pending_focused {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };

        let items: Vec<ListItem> = pending
            .iter()
            .map(|c| {
                let display = condition_display(c);
                ListItem::new(Line::from(vec![
                    Span::raw(display),
                    Span::styled("  [d]", Style::default().fg(Color::DarkGray)),
                ]))
            })
            .collect();

        let pending_list = List::new(items)
            .block(
                Block::default()
                    .title(" Pending Conditions ")
                    .borders(Borders::ALL),
            )
            .highlight_style(pending_highlight)
            .highlight_symbol("> ");

        // Clone ListState into a mutable local; render path must not mutate the
        // canonical state stored in the Screen variant (read-only borrow in draw_screen).
        let mut ps = pending_state.clone();
        frame.render_stateful_widget(pending_list, pending_area, &mut ps);
    }

    // --- Step picker ---
    // Split picker area: step label (1 row) + options list (remaining).
    let picker_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(picker_area);

    let label = step_label(step, selected_attribute);
    frame.render_widget(Paragraph::new(label), picker_chunks[0]);

    // Step 3 MemberOf: text input instead of a selection list (per D-12).
    let is_member_of_step3 = step == 3 && selected_attribute == Some(&ConditionAttribute::MemberOf);

    if is_member_of_step3 {
        // Free-text input for the AD group SID; trailing `_` acts as a cursor.
        let input_display = format!("[{buffer}_]");
        let input_paragraph = Paragraph::new(input_display).block(
            Block::default()
                .title(" AD Group SID ")
                .borders(Borders::ALL),
        );
        frame.render_widget(input_paragraph, picker_chunks[1]);
    } else {
        let items = picker_items(step, selected_attribute);
        if !items.is_empty() {
            let picker_highlight = if pending_focused {
                // Picker is not focused; show selection in plain White.
                Style::default().fg(Color::White)
            } else {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            };

            let picker_list = List::new(items)
                .highlight_style(picker_highlight)
                .highlight_symbol("> ");

            // Clone picker ListState for the same reason as pending_state above.
            let mut pk = picker_state.clone();
            frame.render_stateful_widget(picker_list, picker_chunks[1], &mut pk);
        }
    }

    // --- Hints bar (inside modal bottom, NOT at terminal bottom) ---
    // Pass modal_area so draw_hints computes y = modal_area.y + modal_area.height - 1.
    let hints = if pending_focused {
        "Up/Down Navigate  d: Delete  Tab: Switch to Picker  Esc: Close"
    } else if is_member_of_step3 {
        "Type SID  Enter: Add  Esc: Back  Tab: Switch to Pending"
    } else {
        "Up/Down Navigate  Enter: Select  Esc: Back/Close  Tab: Switch to Pending"
    };
    draw_hints(frame, modal_area, hints);
}

/// Labels for each row of the SIEM config form (in display order).
const SIEM_FIELD_LABELS: [&str; 9] = [
    "Splunk URL",
    "Splunk Token",
    "Splunk Enabled",
    "ELK URL",
    "ELK Index",
    "ELK API Key",
    "ELK Enabled",
    "[ Save ]",
    "[ Back ]",
];

/// Returns `true` when a row index corresponds to a secret field that
/// should be masked outside of edit mode.
fn is_siem_secret(index: usize) -> bool {
    matches!(index, 1 | 5)
}

/// Returns `true` when a row index corresponds to a boolean field.
fn is_siem_bool(index: usize) -> bool {
    matches!(index, 2 | 6)
}

/// Labels for each row of the Alert Config form (in display order).
///
/// 10 editable fields + Save + Test Connection + Back = 13 total rows.
const ALERT_FIELD_LABELS: [&str; 13] = [
    "SMTP Host",
    "SMTP Port",
    "SMTP Username",
    "SMTP Password",
    "SMTP From",
    "SMTP To",
    "SMTP Enabled",
    "Webhook URL",
    "Webhook Secret",
    "Webhook Enabled",
    "[ Save ]",
    "[ Test Connection ]",
    "[ Back ]",
];

/// Returns `true` when a row index corresponds to a secret field that
/// should be masked outside of edit mode.
fn is_alert_secret(index: usize) -> bool {
    matches!(index, 3 | 8) // smtp_password, webhook_secret
}

/// Returns `true` when a row index corresponds to a boolean field.
fn is_alert_bool(index: usize) -> bool {
    matches!(index, 6 | 9) // smtp_enabled, webhook_enabled
}

/// Returns `true` when a row index corresponds to a numeric field.
fn is_alert_numeric(index: usize) -> bool {
    matches!(index, 1) // smtp_port
}

/// Display labels for each row in the PolicyCreate form (7 rows, indices 0-6).
const POLICY_FIELD_LABELS: [&str; 7] = [
    "Name",
    "Description",
    "Priority",
    "Action",
    "[Add Conditions]",
    "Conditions",
    "[Submit]",
];

/// Draws the SIEM configuration form.
fn draw_siem_config(
    frame: &mut Frame,
    area: Rect,
    config: &serde_json::Value,
    selected: usize,
    editing: bool,
    buffer: &str,
) {
    // Map row index -> JSON key for editable fields.
    const KEYS: [&str; 7] = [
        "splunk_url",
        "splunk_token",
        "splunk_enabled",
        "elk_url",
        "elk_index",
        "elk_api_key",
        "elk_enabled",
    ];

    let mut items: Vec<ListItem> = Vec::with_capacity(SIEM_FIELD_LABELS.len());
    for (i, label) in SIEM_FIELD_LABELS.iter().enumerate() {
        let line = if i < KEYS.len() {
            let key = KEYS[i];
            let value_display = if editing && i == selected {
                // Show buffer with trailing cursor.
                format!("[{buffer}_]")
            } else if is_siem_bool(i) {
                let b = config[key].as_bool().unwrap_or(false);
                if b {
                    "[x]".to_string()
                } else {
                    "[ ]".to_string()
                }
            } else if is_siem_secret(i) {
                let v = config[key].as_str().unwrap_or("");
                if v.is_empty() {
                    "(empty)".to_string()
                } else {
                    "*****".to_string()
                }
            } else {
                let v = config[key].as_str().unwrap_or("");
                if v.is_empty() {
                    "(empty)".to_string()
                } else {
                    v.to_string()
                }
            };
            format!("{label}: {value_display}")
        } else {
            // Save / Back action rows.
            (*label).to_string()
        };
        items.push(ListItem::new(Line::from(line)));
    }

    let list = List::new(items)
        .block(
            Block::default()
                .title(" SIEM Config ")
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

    let hints = if editing {
        "Type to edit | Enter: commit | Esc: cancel"
    } else {
        "Up/Down: navigate | Enter: edit/toggle | Esc: back"
    };
    draw_hints(frame, area, hints);
}

/// Draws the alert router configuration form.
///
/// # Arguments
///
/// * `frame` - ratatui frame to render into
/// * `area` - screen area allocated to the form
/// * `config` - current config payload as a JSON object (loaded from the server)
/// * `selected` - index of the currently highlighted row (0..=12)
/// * `editing` - `true` when the highlighted text/numeric field is in edit mode
/// * `buffer` - edit buffer contents (only meaningful when `editing` is `true`)
fn draw_alert_config(
    frame: &mut Frame,
    area: Rect,
    config: &serde_json::Value,
    selected: usize,
    editing: bool,
    buffer: &str,
) {
    // Map row index -> JSON key for editable fields. The 10 keys here match
    // the on-wire `AlertRouterConfigPayload` field names from
    // `dlp-server/src/admin_api.rs` exactly.
    const KEYS: [&str; 10] = [
        "smtp_host",
        "smtp_port",
        "smtp_username",
        "smtp_password",
        "smtp_from",
        "smtp_to",
        "smtp_enabled",
        "webhook_url",
        "webhook_secret",
        "webhook_enabled",
    ];

    let mut items: Vec<ListItem> = Vec::with_capacity(ALERT_FIELD_LABELS.len());
    for (i, label) in ALERT_FIELD_LABELS.iter().enumerate() {
        let line = if i < KEYS.len() {
            let key = KEYS[i];
            let value_display = if editing && i == selected {
                // Show buffer with trailing cursor marker.
                format!("[{buffer}_]")
            } else if is_alert_bool(i) {
                let b = config[key].as_bool().unwrap_or(false);
                if b {
                    "[x]".to_string()
                } else {
                    "[ ]".to_string()
                }
            } else if is_alert_numeric(i) {
                // smtp_port is stored as a JSON number; default to 587 if absent.
                let n = config[key].as_i64().unwrap_or(587);
                n.to_string()
            } else if is_alert_secret(i) {
                let v = config[key].as_str().unwrap_or("");
                if v.is_empty() {
                    "(empty)".to_string()
                } else {
                    "*****".to_string()
                }
            } else {
                let v = config[key].as_str().unwrap_or("");
                if v.is_empty() {
                    "(empty)".to_string()
                } else {
                    v.to_string()
                }
            };
            format!("{label}: {value_display}")
        } else {
            // Save / Back action rows.
            (*label).to_string()
        };
        items.push(ListItem::new(Line::from(line)));
    }

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Alert Config ")
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

    let hints = if editing {
        "Type to edit | Enter: commit | Esc: cancel"
    } else {
        "Up/Down: navigate | Enter: edit/toggle | Esc: back"
    };
    draw_hints(frame, area, hints);
}

/// Draws the Policy Create multi-field form.
///
/// # Arguments
///
/// * `frame` - ratatui frame
/// * `area` - screen area allocated to the form
/// * `form` - current form state (fields + conditions)
/// * `selected` - index of the highlighted row (0..=6)
/// * `editing` - true when a text field is in edit mode
/// * `buffer` - text input buffer (only meaningful when `editing` is true)
/// * `validation_error` - inline error shown below Submit row, or None
fn draw_policy_create(
    frame: &mut Frame,
    area: Rect,
    form: &crate::app::PolicyFormState,
    selected: usize,
    editing: bool,
    buffer: &str,
    validation_error: Option<&str>,
) {
    // Build 7 ListItems — one per row.
    let mut items: Vec<ListItem> = Vec::with_capacity(POLICY_FIELD_LABELS.len());

    for (i, label) in POLICY_FIELD_LABELS.iter().enumerate() {
        let line = match i {
            0 => {
                // Name (text, required)
                if editing && selected == 0 {
                    Line::from(format!("{label}:              [{buffer}_]"))
                } else if form.name.is_empty() {
                    Line::from(vec![
                        Span::raw(format!("{label}:              ")),
                        Span::styled("(empty)", Style::default().fg(Color::DarkGray)),
                    ])
                } else {
                    Line::from(format!("{label}:              {}", form.name))
                }
            }
            1 => {
                // Description (text, optional)
                if editing && selected == 1 {
                    Line::from(format!("{label}:       [{buffer}_]"))
                } else if form.description.is_empty() {
                    Line::from(vec![
                        Span::raw(format!("{label}:       ")),
                        Span::styled("(empty)", Style::default().fg(Color::DarkGray)),
                    ])
                } else {
                    Line::from(format!("{label}:       {}", form.description))
                }
            }
            2 => {
                // Priority (numeric text)
                if editing && selected == 2 {
                    Line::from(format!("{label}:          [{buffer}_]"))
                } else if form.priority.is_empty() {
                    Line::from(vec![
                        Span::raw(format!("{label}:          ")),
                        Span::styled("(empty)", Style::default().fg(Color::DarkGray)),
                    ])
                } else {
                    Line::from(format!("{label}:          {}", form.priority))
                }
            }
            3 => {
                // Action (select index — cycles on Enter, no edit mode)
                let action_label = ACTION_OPTIONS[form.action];
                Line::from(format!("{label}:            {action_label}"))
            }
            4 => {
                // [Add Conditions] action row
                Line::from(format!("  {label}"))
            }
            5 => {
                // Conditions summary (read-only)
                let n = form.conditions.len();
                if n == 0 {
                    // DarkGray empty state (per D-18)
                    Line::from(vec![
                        Span::raw(format!("{label} ({n}):    ")),
                        Span::styled("No conditions added.", Style::default().fg(Color::DarkGray)),
                    ])
                } else {
                    // Comma-separated summary of conditions
                    let summary = form
                        .conditions
                        .iter()
                        .map(condition_display)
                        .collect::<Vec<_>>()
                        .join(", ");
                    Line::from(vec![
                        Span::raw(format!("{n} condition(s):    ")),
                        Span::styled(summary, Style::default().fg(Color::DarkGray)),
                    ])
                }
            }
            6 => {
                // [Submit] action row
                Line::from(format!("  {label}"))
            }
            _ => Line::from(""),
        };
        items.push(ListItem::new(line));
    }

    // Render list with same highlight style used by all existing TUI screens.
    let list = List::new(items)
        .block(
            Block::default()
                .title(" Create Policy ")
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

    // Validation error overlay below the Submit row (not a list item).
    if let Some(err) = validation_error {
        // Position: bottom-2 row (above hints bar at bottom-1).
        if area.height >= 4 {
            let err_area = Rect {
                x: area.x + 2,
                y: area.y + area.height - 2,
                width: area.width.saturating_sub(4),
                height: 1,
            };
            let err_para = Paragraph::new(err).style(Style::default().fg(Color::Red));
            frame.render_widget(err_para, err_area);
        }
    }

    // Key hints bar (contextual based on editing mode).
    let hints = if editing {
        "Type to edit | Enter: commit | Esc: cancel"
    } else {
        "Up/Down: navigate | Enter: edit/toggle/open | Esc: back"
    };
    draw_hints(frame, area, hints);
}

/// Draws a navigable menu list.
fn draw_menu(frame: &mut Frame, area: Rect, title: &str, items: &[&str], selected: usize) {
    let list_items: Vec<ListItem> = items
        .iter()
        .map(|s| ListItem::new(Line::from(*s)))
        .collect();

    let list = List::new(list_items)
        .block(
            Block::default()
                .title(format!(" {title} "))
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

    draw_hints(
        frame,
        area,
        "Up/Down: navigate | Enter: select | Esc/Q: back",
    );
}

/// Draws a text/password input box.
fn draw_input(frame: &mut Frame, area: Rect, prompt: &str, input: &str, masked: bool) {
    let display = if masked {
        "*".repeat(input.len())
    } else {
        input.to_string()
    };

    // Show a cursor indicator.
    let text = format!("{display}_");

    let block = Block::default()
        .title(format!(" {prompt} "))
        .borders(Borders::ALL);
    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);

    draw_hints(frame, area, "Type to enter | Enter: confirm | Esc: cancel");
}

/// Draws a confirmation dialog.
fn draw_confirm(frame: &mut Frame, area: Rect, message: &str, yes_selected: bool) {
    let yes_style = if yes_selected {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let no_style = if !yes_selected {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Red)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };

    let lines = vec![
        Line::from(message),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [ Yes ]  ", yes_style),
            Span::raw("    "),
            Span::styled("  [ No ]  ", no_style),
        ]),
    ];

    let block = Block::default().title(" Confirm ").borders(Borders::ALL);
    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);

    draw_hints(
        frame,
        area,
        "Left/Right: select | Enter: confirm | Esc: cancel",
    );
}

/// Draws a scrollable policy table.
fn draw_policy_list(
    frame: &mut Frame,
    area: Rect,
    policies: &[serde_json::Value],
    selected: usize,
) {
    let header = Row::new(vec!["ID", "Name", "Priority", "Enabled", "Version"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = policies
        .iter()
        .map(|p| {
            Row::new(vec![
                p["id"].as_str().unwrap_or("-").to_string(),
                p["name"].as_str().unwrap_or("-").to_string(),
                p["priority"].to_string(),
                p["enabled"].to_string(),
                p["version"].to_string(),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(20),
        Constraint::Percentage(30),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
        Constraint::Percentage(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" Policies ({}) ", policies.len()))
                .borders(Borders::ALL),
        )
        .row_highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = ratatui::widgets::TableState::default();
    state.select(Some(selected));
    frame.render_stateful_widget(table, area, &mut state);

    draw_hints(frame, area, "Up/Down: navigate | Enter: view | Esc: back");
}

/// Draws a scrollable agent table.
fn draw_agent_list(frame: &mut Frame, area: Rect, agents: &[serde_json::Value], selected: usize) {
    let header = Row::new(vec![
        "Hostname",
        "IP",
        "Status",
        "Version",
        "Last Heartbeat",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .bottom_margin(1);

    let rows: Vec<Row> = agents
        .iter()
        .map(|a| {
            Row::new(vec![
                a["hostname"].as_str().unwrap_or("-").to_string(),
                a["ip"].as_str().unwrap_or("-").to_string(),
                a["status"].as_str().unwrap_or("-").to_string(),
                a["agent_version"].as_str().unwrap_or("-").to_string(),
                a["last_heartbeat"].as_str().unwrap_or("-").to_string(),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(20),
        Constraint::Percentage(15),
        Constraint::Percentage(10),
        Constraint::Percentage(10),
        Constraint::Percentage(45),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" Agents ({}) ", agents.len()))
                .borders(Borders::ALL),
        )
        .row_highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = ratatui::widgets::TableState::default();
    state.select(Some(selected));
    frame.render_stateful_widget(table, area, &mut state);

    draw_hints(frame, area, "Up/Down: navigate | Esc: back");
}

/// Draws a JSON detail view.
fn draw_json_detail(frame: &mut Frame, area: Rect, title: &str, value: &serde_json::Value) {
    let pretty = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    draw_result(frame, area, title, &pretty);
}

/// Draws a read-only result / info screen.
fn draw_result(frame: &mut Frame, area: Rect, title: &str, body: &str) {
    let block = Block::default()
        .title(format!(" {title} "))
        .borders(Borders::ALL);
    let paragraph = Paragraph::new(body.to_string())
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);

    draw_hints(frame, area, "Enter/Esc: back");
}

/// Draws a hint line overlaid at the bottom of the given area.
fn draw_hints(frame: &mut Frame, area: Rect, hints: &str) {
    if area.height < 3 {
        return;
    }
    let hint_area = Rect {
        x: area.x + 1,
        y: area.y + area.height - 1,
        width: area.width.saturating_sub(2),
        height: 1,
    };
    frame.render_widget(Clear, hint_area);
    let line = Paragraph::new(Line::from(hints).style(Style::default().fg(Color::DarkGray)));
    frame.render_widget(line, hint_area);
}

/// Draws the status bar at the bottom of the screen.
fn draw_status_bar(app: &App, frame: &mut Frame, area: Rect) {
    let (text, style) = match &app.status {
        Some((msg, StatusKind::Info)) => (msg.clone(), Style::default().fg(Color::Cyan)),
        Some((msg, StatusKind::Success)) => (msg.clone(), Style::default().fg(Color::Green)),
        Some((msg, StatusKind::Error)) => (msg.clone(), Style::default().fg(Color::Red)),
        None => (String::new(), Style::default()),
    };
    let paragraph = Paragraph::new(Line::from(text).style(style));
    frame.render_widget(paragraph, area);
}
