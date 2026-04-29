//! Renders the current [`Screen`] to the terminal frame.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table, Wrap,
};
use ratatui::Frame;

use crate::app::{
    App, ConditionAttribute, ImportState, Screen, SimulateFormState, SimulateOutcome, StatusKind,
    UsbScanEntry, ACTION_OPTIONS, ATTRIBUTES, SIMULATE_ACCESS_CONTEXT_OPTIONS,
    SIMULATE_ACTION_OPTIONS, SIMULATE_CLASSIFICATION_OPTIONS, SIMULATE_DEVICE_TRUST_OPTIONS,
    SIMULATE_NETWORK_LOCATION_OPTIONS,
};
use crate::screens::dispatch::condition_display;
use crate::screens::dispatch::operators_for;
use dlp_common::abac::PolicyMode;

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
                &[
                    "Password Management",
                    "Policy Management",
                    "System",
                    "Devices & Origins",
                    "Simulate Policy",
                    "Exit",
                ],
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
                    "Simulate Policy",
                    "Import Policies...",
                    "Export Policies...",
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
            selected_field,
            selected_operator,
            pending,
            buffer,
            pending_focused,
            pending_state,
            picker_state,
            edit_index,
            ..
        } => {
            draw_conditions_builder(
                frame,
                area,
                *step,
                selected_attribute.as_ref(),
                *selected_field,
                selected_operator.as_deref(),
                pending,
                buffer,
                *pending_focused,
                pending_state,
                picker_state,
                *edit_index,
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
        Screen::PolicyEdit {
            id: _,
            form,
            selected,
            editing,
            buffer,
            validation_error,
        } => {
            draw_policy_edit(
                frame,
                area,
                &form.name,
                form,
                *selected,
                *editing,
                buffer,
                validation_error.as_deref(),
            );
        }
        Screen::PolicySimulate {
            form,
            selected,
            editing,
            buffer,
            result,
            ..
        } => {
            draw_policy_simulate(frame, area, form, *selected, *editing, buffer, result);
        }
        Screen::ImportConfirm {
            policies,
            conflicting_count,
            non_conflicting_count,
            selected,
            state,
            ..
        } => {
            draw_import_confirm(
                frame,
                area,
                policies.len(),
                *conflicting_count,
                *non_conflicting_count,
                *selected,
                state,
            );
        }
        Screen::DevicesMenu { selected } => {
            draw_menu(
                frame,
                area,
                "Devices & Origins",
                &["Device Registry", "Managed Origins", "Scan & Register USB"],
                *selected,
            );
            draw_hints(frame, area, "Enter: Open   Esc: Main Menu");
        }
        Screen::DeviceList { devices, selected } => {
            draw_device_list(frame, area, devices, *selected);
        }
        Screen::DeviceTierPicker { selected, .. } => {
            draw_menu(
                frame,
                area,
                "Select Trust Tier",
                &["blocked", "read_only", "full_access"],
                *selected,
            );
            draw_hints(frame, area, "Enter: Confirm   Esc: Back");
        }
        Screen::UsbScan { devices, selected } => {
            draw_usb_scan(frame, area, devices, *selected);
        }
        Screen::ManagedOriginList { origins, selected } => {
            draw_managed_origin_list(frame, area, origins, *selected);
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

/// Step 3 value labels for AppField::TrustTier (app-identity conditions, per D-14).
/// Index 0 = "trusted", 1 = "untrusted", 2 = "unknown" — matches build_condition mapping.
const TRUST_TIER_VALUES: [&str; 3] = ["trusted", "untrusted", "unknown"];

/// AppField sub-picker labels (Step 1.5, per D-12).
/// Index 0 = Publisher, 1 = ImagePath, 2 = TrustTier — matches APP_FIELD_LABELS in dispatch.rs.
const APP_FIELD_LABELS: [&str; 3] = ["publisher", "image_path", "trust_tier"];

/// Step 2 operator list — driven by the attribute chosen in Step 1.
///
/// The list is built by calling `operators_for`, which returns the correct
/// operators for the attribute. Enforced operators are shown verbatim;
/// advisory-only operators are annotated "(not enforced)".
///
/// # Arguments
///
/// * `attr` - Condition attribute being built.
/// * `field` - For app-identity attributes: the AppField selected in the sub-step.
///   Pass `None` for other attributes or when field is not yet resolved.
fn pick_operators(
    attr: ConditionAttribute,
    field: Option<dlp_common::abac::AppField>,
) -> Vec<ListItem<'static>> {
    operators_for(attr, field)
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
        .collect()
}

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
///
/// # Arguments
///
/// * `step` - Current step number (1, 2, or 3). Step 1.5 (app-field sub-picker) is rendered
///   by the caller directly using `APP_FIELD_LABELS`.
/// * `selected_attribute` - Attribute selected in Step 1 (None until Step 1 completed).
/// * `selected_field` - For app-identity attributes, the AppField selected in the sub-step.
///   Required for Step 2 operator list; used in Step 3 to switch between picker and text input.
fn picker_items(
    step: u8,
    selected_attribute: Option<&ConditionAttribute>,
    selected_field: Option<dlp_common::abac::AppField>,
) -> Vec<ListItem<'static>> {
    use dlp_common::abac::AppField;
    match step {
        1 => ATTRIBUTES
            .iter()
            .map(|a| ListItem::new(a.label().to_string()))
            .collect(),
        2 => {
            let attr = match selected_attribute {
                Some(a) => a,
                None => return vec![],
            };
            pick_operators(*attr, selected_field)
        }
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
                ConditionAttribute::SourceApplication
                | ConditionAttribute::DestinationApplication => {
                    match selected_field {
                        // TrustTier uses a picker; Publisher/ImagePath use text input (returns []).
                        Some(AppField::TrustTier) => TRUST_TIER_VALUES
                            .iter()
                            .map(|v| ListItem::new(v.to_string()))
                            .collect(),
                        _ => vec![], // Publisher/ImagePath: free-text input path
                    }
                }
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
/// - Step picker (remaining rows): attribute list (Step 1), AppField sub-picker (Step 1.5),
///   operator list (Step 2), or value picker / text input (Step 3)
/// - Hints bar (1 row, inside modal bottom)
///
/// # Arguments
///
/// * `frame` - ratatui frame to render into
/// * `area` - full terminal area (modal is centered within this)
/// * `step` - current step number (1, 2, or 3)
/// * `selected_attribute` - attribute chosen in Step 1 (None until completed)
/// * `selected_field` - AppField chosen in sub-step (None until sub-step completed, or for
///   non-app-identity attributes)
/// * `selected_operator` - operator chosen in Step 2 (None until completed)
/// * `pending` - conditions already added this session
/// * `buffer` - text buffer for MemberOf and app-identity Publisher/ImagePath Step 3 input
/// * `pending_focused` - true when the pending list has keyboard focus
/// * `pending_state` - scroll position for the pending list
/// * `picker_state` - scroll position for the step picker list
/// * `edit_index` - Some(i) when editing an existing condition at index i
#[allow(clippy::too_many_arguments)]
fn draw_conditions_builder(
    frame: &mut Frame,
    area: Rect,
    step: u8,
    selected_attribute: Option<&ConditionAttribute>,
    selected_field: Option<dlp_common::abac::AppField>,
    // Operator is resolved for future steps; accepted here for completeness.
    _selected_operator: Option<&str>,
    pending: &[dlp_common::abac::PolicyCondition],
    buffer: &str,
    pending_focused: bool,
    pending_state: &ListState,
    picker_state: &ListState,
    edit_index: Option<usize>,
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

    let modal_title = if edit_index.is_some() {
        " Edit Condition "
    } else {
        " Conditions Builder "
    };
    let modal_block = Block::default().title(modal_title).borders(Borders::ALL);
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

    use dlp_common::abac::AppField;

    // Determine the rendering mode for the picker area.
    // Sub-step (Step 1.5): step==1, app-identity attribute selected, field not yet chosen.
    let in_app_field_sub_step = step == 1
        && matches!(
            selected_attribute,
            Some(ConditionAttribute::SourceApplication)
                | Some(ConditionAttribute::DestinationApplication)
        )
        && selected_field.is_none();

    // Render the step label above the picker list (skipped for sub-step which has its own label).
    if !in_app_field_sub_step {
        let label = step_label(step, selected_attribute);
        frame.render_widget(Paragraph::new(label), picker_chunks[0]);
    }

    // Text-input paths: MemberOf SID, or app-identity Publisher/ImagePath value.
    let is_member_of_step3 = step == 3 && selected_attribute == Some(&ConditionAttribute::MemberOf);
    let is_app_text_step3 = step == 3
        && matches!(
            selected_attribute,
            Some(ConditionAttribute::SourceApplication)
                | Some(ConditionAttribute::DestinationApplication)
        )
        && matches!(
            selected_field,
            Some(AppField::Publisher) | Some(AppField::ImagePath)
        );
    let is_text_input_step3 = is_member_of_step3 || is_app_text_step3;

    if in_app_field_sub_step {
        // --- Step 1.5: AppField sub-picker ---
        // Override the step label to communicate the sub-step to the admin.
        let sub_label = Line::styled(
            "Step 1.5: Select Application Field",
            Style::default().add_modifier(Modifier::BOLD),
        );
        frame.render_widget(Paragraph::new(sub_label), picker_chunks[0]);

        let sub_items: Vec<ListItem> = APP_FIELD_LABELS
            .iter()
            .map(|f| ListItem::new(f.to_string()))
            .collect();

        let picker_highlight = if pending_focused {
            Style::default().fg(Color::White)
        } else {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        };

        let sub_picker = List::new(sub_items)
            .highlight_style(picker_highlight)
            .highlight_symbol("> ");

        let mut pk = picker_state.clone();
        frame.render_stateful_widget(sub_picker, picker_chunks[1], &mut pk);
    } else if is_text_input_step3 {
        // --- Step 3 text input (MemberOf SID or Publisher/ImagePath value) ---
        let title = if is_member_of_step3 {
            " AD Group SID (partial match) "
        } else {
            " Application Value "
        };
        // Trailing `_` acts as a simple cursor indicator.
        let input_display = format!("[{buffer}_]");
        let input_paragraph = Paragraph::new(input_display)
            .block(Block::default().title(title).borders(Borders::ALL));
        frame.render_widget(input_paragraph, picker_chunks[1]);
    } else {
        let items = picker_items(step, selected_attribute, selected_field);
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
        "Up/Down Navigate  d: Delete  e: Edit  Tab: Switch to Picker  Esc: Close"
    } else if in_app_field_sub_step {
        "Enter: Select   Esc: Back to attribute"
    } else if is_text_input_step3 {
        "Type value  Enter: Add  Esc: Back  Tab: Switch to Pending"
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

/// Display labels for each row in the PolicyCreate/PolicyEdit form (9 rows, indices 0-8).
const POLICY_FIELD_LABELS: [&str; 9] = [
    "Name",
    "Description",
    "Priority",
    "Action",
    "Enabled",
    "Mode",
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
/// * `selected` - index of the highlighted row (0..=7)
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
    // Build 8 ListItems — one per row.
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
                // Enabled (bool toggle — Enter toggles, no edit mode)
                let enabled_val = if form.enabled { "Yes" } else { "No" };
                Line::from(format!("{label}:              {enabled_val}"))
            }
            5 => {
                // Mode (select enum — cycles on Enter/Space, no edit mode).
                let mode_label = match form.mode {
                    PolicyMode::ALL => "ALL",
                    PolicyMode::ANY => "ANY",
                    PolicyMode::NONE => "NONE",
                };
                Line::from(format!("{label}:              {mode_label}"))
            }
            6 => {
                // [Add Conditions] action row
                Line::from(format!("  {label}"))
            }
            7 => {
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
            8 => {
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

    // Empty-conditions mode advisory (Phase 19 D-04). Shown in the same
    // bottom-2 row slot as the validation_error overlay (see below); errors
    // take priority, so this block is gated on `validation_error.is_none()`.
    if validation_error.is_none()
        && form.mode != PolicyMode::ALL
        && form.conditions.is_empty()
        && area.height >= 4
    {
        let hint = match form.mode {
            PolicyMode::ANY => "Note: mode=ANY with no conditions will never match.",
            PolicyMode::NONE => "Note: mode=NONE with no conditions matches every request.",
            // Unreachable given the `form.mode != PolicyMode::ALL` guard above,
            // but Rust requires an exhaustive match on the three-variant enum.
            PolicyMode::ALL => "",
        };
        let hint_area = Rect {
            x: area.x + 2,
            y: area.y + area.height - 2,
            width: area.width.saturating_sub(4),
            height: 1,
        };
        let hint_para = Paragraph::new(hint).style(Style::default().fg(Color::DarkGray));
        frame.render_widget(hint_para, hint_area);
    }

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
        "Up/Down: navigate | Enter: select/toggle | Esc: back"
    };
    draw_hints(frame, area, hints);
}

/// Draws the Policy Edit multi-field form.
///
/// Identical to `draw_policy_create` except for the block title and the final
/// action row label ("[Save]" instead of "[Submit]").
///
/// # Arguments
///
/// * `frame` - ratatui frame
/// * `area` - screen area allocated to the form
/// * `policy_name` - current policy name for the block title
/// * `form` - current form state (fields + conditions, pre-populated from GET)
/// * `selected` - index of the highlighted row (0..=7)
/// * `editing` - true when a text field is in edit mode
/// * `buffer` - text input buffer (only meaningful when `editing` is true)
/// * `validation_error` - inline error shown below Save row, or None
#[allow(clippy::too_many_arguments)]
fn draw_policy_edit(
    frame: &mut Frame,
    area: Rect,
    policy_name: &str,
    form: &crate::app::PolicyFormState,
    selected: usize,
    editing: bool,
    buffer: &str,
    validation_error: Option<&str>,
) {
    // Build 9 ListItems — one per row (Phase 19: 9 rows).
    let mut items: Vec<ListItem> = Vec::with_capacity(POLICY_FIELD_LABELS.len());

    for (i, label) in POLICY_FIELD_LABELS.iter().enumerate() {
        let line = match i {
            0 => {
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
                let action_label = ACTION_OPTIONS[form.action];
                Line::from(format!("{label}:            {action_label}"))
            }
            4 => {
                let enabled_val = if form.enabled { "Yes" } else { "No" };
                Line::from(format!("{label}:              {enabled_val}"))
            }
            5 => {
                // Mode (select enum — cycles on Enter/Space, no edit mode).
                let mode_label = match form.mode {
                    PolicyMode::ALL => "ALL",
                    PolicyMode::ANY => "ANY",
                    PolicyMode::NONE => "NONE",
                };
                Line::from(format!("{label}:              {mode_label}"))
            }
            6 => Line::from(format!("  {label}")),
            7 => {
                let n = form.conditions.len();
                if n == 0 {
                    Line::from(vec![
                        Span::raw(format!("{label} ({n}):    ")),
                        Span::styled("No conditions added.", Style::default().fg(Color::DarkGray)),
                    ])
                } else {
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
            8 => {
                // [Save] — hardcoded label (UI-SPEC D-03).
                Line::from("  [Save]")
            }
            _ => Line::from(""),
        };
        items.push(ListItem::new(line));
    }

    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(" Edit Policy: {policy_name} "))
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

    // Empty-conditions mode advisory (Phase 19 D-04). Shown in the same
    // bottom-2 row slot as the validation_error overlay (see below); errors
    // take priority, so this block is gated on `validation_error.is_none()`.
    if validation_error.is_none()
        && form.mode != PolicyMode::ALL
        && form.conditions.is_empty()
        && area.height >= 4
    {
        let hint = match form.mode {
            PolicyMode::ANY => "Note: mode=ANY with no conditions will never match.",
            PolicyMode::NONE => "Note: mode=NONE with no conditions matches every request.",
            // Unreachable given the `form.mode != PolicyMode::ALL` guard above,
            // but Rust requires an exhaustive match on the three-variant enum.
            PolicyMode::ALL => "",
        };
        let hint_area = Rect {
            x: area.x + 2,
            y: area.y + area.height - 2,
            width: area.width.saturating_sub(4),
            height: 1,
        };
        let hint_para = Paragraph::new(hint).style(Style::default().fg(Color::DarkGray));
        frame.render_widget(hint_para, hint_area);
    }

    if let Some(err) = validation_error {
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

    let hints = if editing {
        "Type to edit | Enter: commit | Esc: cancel"
    } else {
        "Up/Down: navigate | Enter: select/toggle | Esc: back"
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

    draw_hints(frame, area, "Left/Right/y: confirm | n/Esc: cancel");
}

/// Draws a scrollable policy table.
fn draw_policy_list(
    frame: &mut Frame,
    area: Rect,
    policies: &[serde_json::Value],
    selected: usize,
) {
    let header = Row::new(vec!["Priority", "Name", "Action", "Enabled"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = policies
        .iter()
        .map(|p| {
            let priority = p["priority"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(u32::MAX);
            let action = p["action"].as_str().unwrap_or("-");
            let enabled = if p["enabled"].as_bool().unwrap_or(false) {
                "Yes"
            } else {
                "No"
            };
            Row::new(vec![
                priority.to_string(),
                p["name"].as_str().unwrap_or("-").to_string(),
                action.to_string(),
                enabled.to_string(),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(15), // Priority
        Constraint::Percentage(45), // Name
        Constraint::Percentage(20), // Action
        Constraint::Percentage(20), // Enabled
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

    draw_hints(
        frame,
        area,
        "n: new | e: edit | d: delete | Enter: view | Esc: back",
    );
}

/// Maps an editable `selected` index (0..=9) to the render-list position.
///
/// Section headers are interspersed at fixed render positions, so the editable
/// `selected` index (0..=9) does not match the render list position 1:1.
/// This lookup table is the single source of truth for the render/dispatch pair.
const EDITABLE_TO_RENDER: [usize; 10] = [
    0,  // User SID
    1,  // User Name
    2,  // Groups
    4,  // Device Trust  (render row 3 = "--- Subject ---" header)
    5,  // Network Location
    7,  // Path          (render row 6 = "--- Resource ---" header)
    8,  // Classification
    10, // Action        (render row 9 = "--- Environment ---" header)
    11, // Access Context
    13, // [Simulate]    (render row 12 = "--- Submit ---" header)
];

/// Builds the full render list (14 ListItems) for the simulate form.
fn build_simulate_items(
    form: &SimulateFormState,
    selected: usize,
    editing: bool,
    buffer: &str,
) -> Vec<ListItem<'static>> {
    let mut items = Vec::with_capacity(14);

    // Section header helper.
    let push_header = |label: &'static str, items: &mut Vec<_>| {
        let line = Line::styled(
            format!("  {label}"),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );
        items.push(ListItem::new(line));
    };

    // Editable text/select row helper.
    let push_row =
        |label: &str, value: &str, items: &mut Vec<_>, is_selected: bool, is_editing: bool| {
            let line = if is_selected && is_editing {
                Line::from(format!("{label:<22}[{buffer}_]"))
            } else if value.is_empty() {
                Line::from(vec![
                    Span::raw(format!("{label:<22}")),
                    Span::styled("(empty)", Style::default().fg(Color::DarkGray)),
                ])
            } else {
                Line::from(format!("{label:<22}{value}"))
            };
            items.push(ListItem::new(line));
        };

    // Select row helper.
    let push_select = |label: &str, option_label: &str, items: &mut Vec<_>| {
        let line = Line::from(format!("{label:<22}{option_label}"));
        items.push(ListItem::new(line));
    };

    // Action row helper (non-editable, e.g. [Simulate]).
    let push_action = |label: &str, items: &mut Vec<_>| {
        items.push(ListItem::new(Line::from(format!("  {label}"))));
    };

    // --- Row 0: User SID ---
    push_row(
        "User SID:",
        &form.user_sid,
        &mut items,
        selected == 0,
        editing,
    );

    // --- Row 1: User Name ---
    push_row(
        "User Name:",
        &form.user_name,
        &mut items,
        selected == 1,
        editing,
    );

    // --- Row 2: Groups ---
    push_row(
        "Groups (comma-SIDs):",
        &form.groups_raw,
        &mut items,
        selected == 2,
        editing,
    );

    // --- Row 3: "--- Subject ---" header ---
    push_header("--- Subject ---", &mut items);

    // --- Row 4: Device Trust (select) ---
    let dt = SIMULATE_DEVICE_TRUST_OPTIONS
        .get(form.device_trust)
        .unwrap_or(&"Unknown");
    push_select("Device Trust:", dt, &mut items);

    // --- Row 5: Network Location (select) ---
    let nl = SIMULATE_NETWORK_LOCATION_OPTIONS
        .get(form.network_location)
        .unwrap_or(&"Unknown");
    push_select("Network Location:", nl, &mut items);

    // --- Row 6: "--- Resource ---" header ---
    push_header("--- Resource ---", &mut items);

    // --- Row 7: Path ---
    push_row("Path:", &form.path, &mut items, selected == 5, editing);

    // --- Row 8: Classification (select) ---
    let cl = SIMULATE_CLASSIFICATION_OPTIONS
        .get(form.classification)
        .unwrap_or(&"T1");
    push_select("Classification:", cl, &mut items);

    // --- Row 9: "--- Environment ---" header ---
    push_header("--- Environment ---", &mut items);

    // --- Row 10: Action (select) ---
    let ac = SIMULATE_ACTION_OPTIONS.get(form.action).unwrap_or(&"READ");
    push_select("Action:", ac, &mut items);

    // --- Row 11: Access Context (select) ---
    let cx = SIMULATE_ACCESS_CONTEXT_OPTIONS
        .get(form.access_context)
        .unwrap_or(&"Local");
    push_select("Access Context:", cx, &mut items);

    // --- Row 12: "--- Submit ---" header ---
    push_header("--- Submit ---", &mut items);

    // --- Row 13: [Simulate] button ---
    push_action("[Simulate]", &mut items);

    items
}

/// Draws the Policy Simulate multi-field form with an inline result block.
fn draw_policy_simulate(
    frame: &mut Frame,
    area: Rect,
    form: &SimulateFormState,
    selected: usize,
    editing: bool,
    buffer: &str,
    result: &SimulateOutcome,
) {
    let items = build_simulate_items(form, selected, editing, buffer);
    let render_selected = *EDITABLE_TO_RENDER.get(selected).unwrap_or(&0);

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Policy Simulate ")
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
    state.select(Some(render_selected));
    frame.render_stateful_widget(list, area, &mut state);

    // Inline result block: positioned at the bottom of the form area.
    const RESULT_HEIGHT: u16 = 5;
    if area.height > RESULT_HEIGHT + 2 {
        let result_area = Rect {
            x: area.x + 2,
            y: area
                .y
                .saturating_add(area.height)
                .saturating_sub(RESULT_HEIGHT + 1),
            width: area.width.saturating_sub(4),
            height: RESULT_HEIGHT,
        };

        match result {
            SimulateOutcome::None => {
                // Nothing to render — form only.
            }
            SimulateOutcome::Success(resp) => {
                let decision_color = if resp.decision.is_denied() {
                    Color::Red
                } else {
                    Color::Green
                };
                let matched = resp.matched_policy_id.as_deref().unwrap_or("none");
                let lines = vec![
                    Line::from(format!("Matched policy:  {matched}")),
                    Line::from(vec![
                        Span::raw("Decision:        "),
                        Span::styled(
                            format!("{:?}", resp.decision),
                            Style::default().fg(decision_color),
                        ),
                    ]),
                    Line::from(format!("Reason:          {}", resp.reason)),
                ];
                let block = Block::default()
                    .title(" Result ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green));
                frame.render_widget(Paragraph::new(lines).block(block), result_area);
            }
            SimulateOutcome::Error(msg) => {
                let block = Block::default()
                    .title(" Error ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red));
                frame.render_widget(
                    Paragraph::new(msg.as_str())
                        .style(Style::default().fg(Color::Red))
                        .block(block),
                    result_area,
                );
            }
        }
    }

    let hints = if editing {
        "Type to edit | Enter: commit | Esc: cancel"
    } else {
        "Up/Down: navigate | Enter: select/cycle | Esc: back"
    };
    draw_hints(frame, area, hints);
}

/// Draws the import-confirmation screen.
///
/// Row layout (render list indices 0..=4):
///   0: "Import {N} policies?"              (informational, bold header, skip-nav)
///   1: "{conflicting_count} will overwrite" (informational, dark gray, skip-nav)
///   2: "{non_conflicting_count} will be created" (informational, dark gray, skip-nav)
///   3: [Confirm]   (Enter to proceed)      (actionable, green when selected)
///   4: [Cancel]    (Esc to abort)           (actionable, red when selected)
///
/// Additionally, shows the ImportState block below the list:
///   - InProgress: "Importing..." with a spinner line
///   - Success: "Imported {created} new, {updated} updated" in green
///   - Error: error message in red
fn draw_import_confirm(
    frame: &mut Frame,
    area: Rect,
    total: usize,
    conflicting_count: usize,
    non_conflicting_count: usize,
    selected: usize,
    state: &ImportState,
) {
    // Build the 5-row list (indices 0..=4).
    let items: Vec<ListItem> = vec![
        // Row 0: Header (informational, rendered in bold).
        ListItem::new(Line::from(vec![Span::styled(
            format!("Import {total} policies?"),
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::White),
        )])),
        // Row 1: Conflicting count (informational).
        ListItem::new(Line::from(vec![Span::styled(
            format!("  {conflicting_count} will overwrite existing entries"),
            Style::default().fg(Color::DarkGray),
        )])),
        // Row 2: Non-conflicting count (informational).
        ListItem::new(Line::from(vec![Span::styled(
            format!("  {non_conflicting_count} will be created as new"),
            Style::default().fg(Color::DarkGray),
        )])),
        // Row 3: [Confirm] button.
        {
            let is_selected = selected == 3;
            let style = if is_selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(vec![
                Span::styled("  [ Confirm ]  ", style),
                Span::raw("   (Enter to proceed)"),
            ]))
        },
        // Row 4: [Cancel] button.
        {
            let is_selected = selected == 4;
            let style = if is_selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(vec![
                Span::styled("  [ Cancel ]  ", style),
                Span::raw("   (Esc to abort)"),
            ]))
        },
    ];

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Import Policies ")
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    // Render list with cursor tracking the `selected` parameter (WR-02 fix).
    // Rows 0-2 are informational and skipped by nav; actionable rows are 3 and 4.
    let mut list_state = ListState::default();
    list_state.select(Some(selected));
    frame.render_stateful_widget(list, area, &mut list_state);

    // Render the ImportState block below the list.
    const STATE_HEIGHT: u16 = 4;
    if area.height > STATE_HEIGHT + 2 {
        let state_area = Rect {
            x: area.x + 2,
            y: area
                .y
                .saturating_add(area.height)
                .saturating_sub(STATE_HEIGHT + 1),
            width: area.width.saturating_sub(4),
            height: STATE_HEIGHT,
        };

        match state {
            ImportState::Pending => {
                // No state block when pending -- confirmation prompt is sufficient.
            }
            ImportState::InProgress => {
                let block = Block::default()
                    .title(" Working ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow));
                let text = Paragraph::new("Importing policies...")
                    .style(Style::default().fg(Color::Yellow));
                frame.render_widget(text.block(block), state_area);
            }
            ImportState::Success { created, updated } => {
                let block = Block::default()
                    .title(" Import Complete ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green));
                let line = Line::from(format!(
                    "Imported {} policies ({} new, {} updated).",
                    created + updated,
                    created,
                    updated
                ));
                frame.render_widget(
                    Paragraph::new(line)
                        .style(Style::default().fg(Color::Green))
                        .block(block),
                    state_area,
                );
            }
            ImportState::Error(msg) => {
                let block = Block::default()
                    .title(" Import Failed ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red));
                frame.render_widget(
                    Paragraph::new(msg.as_str())
                        .style(Style::default().fg(Color::Red))
                        .block(block),
                    state_area,
                );
            }
        }
    }

    // Hints bar: only shows action hints when state is Pending.
    let hints = match state {
        ImportState::Pending => "Up/Down: navigate | Enter: confirm | Esc: cancel",
        _ => "Enter/Esc: dismiss",
    };
    draw_hints(frame, area, hints);
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

/// Draws the Device Registry list screen.
///
/// Each device is shown as a compact one-liner:
/// `[TRUST_TIER] VID:{vid} PID:{pid} SER:{serial} "{description}"`
///
/// An empty list renders a single informational row.
fn draw_device_list(frame: &mut Frame, area: Rect, devices: &[serde_json::Value], selected: usize) {
    let items: Vec<ListItem> = if devices.is_empty() {
        vec![ListItem::new(Line::from(
            "No devices registered.".to_string(),
        ))]
    } else {
        devices
            .iter()
            .map(|d| {
                let trust_tier = d["trust_tier"].as_str().unwrap_or("blocked");
                let tier_tag = match trust_tier {
                    "read_only" => "[READ_ONLY]",
                    "full_access" => "[FULL_ACCESS]",
                    _ => "[BLOCKED]",
                };
                let vid = d["vid"].as_str().unwrap_or("-");
                let pid = d["pid"].as_str().unwrap_or("-");
                let serial = d["serial"].as_str().unwrap_or("");
                let description = d["description"].as_str().unwrap_or("");
                let line = format!("{tier_tag} VID:{vid} PID:{pid} SER:{serial} \"{description}\"");
                ListItem::new(Line::from(line))
            })
            .collect()
    };

    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(" Device Registry ({}) ", devices.len()))
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = ratatui::widgets::ListState::default();
    // Only select a row when the list is non-empty to avoid rendering
    // the highlight on the "No devices registered." informational row.
    if !devices.is_empty() {
        state.select(Some(selected));
    }
    frame.render_stateful_widget(list, area, &mut state);

    draw_hints(frame, area, "r: Register   d: Delete   Esc: Back");
}

/// Draws the USB scan and register screen as a 5-column ratatui `Table`.
///
/// Columns: VID | PID | Serial | Description | Registered
/// Already-registered devices show their current trust tier in the Registered
/// column; unregistered devices show `-` (per Phase 32 D-04).
/// Renders a hint footer: `r: Scan   Up/Down: Navigate   Enter: Register   Esc: Back`.
fn draw_usb_scan(
    frame: &mut Frame,
    area: Rect,
    devices: &[UsbScanEntry],
    selected: usize,
) {
    let header = Row::new(vec!["VID", "PID", "Serial", "Description", "Registered"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = devices
        .iter()
        .map(|e| {
            let tier = e.registered_tier.as_deref().unwrap_or("-");
            Row::new(vec![
                e.identity.vid.clone(),
                e.identity.pid.clone(),
                e.identity.serial.clone(),
                e.identity.description.clone(),
                tier.to_string(),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(8),  // VID
        Constraint::Percentage(8),  // PID
        Constraint::Percentage(20), // Serial
        Constraint::Percentage(44), // Description
        Constraint::Percentage(20), // Registered
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" USB Scan ({}) ", devices.len()))
                .borders(Borders::ALL),
        )
        .row_highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    // Only set selection when non-empty so an empty list does not show a
    // highlight cursor on a phantom row.
    let mut state = ratatui::widgets::TableState::default();
    if !devices.is_empty() {
        state.select(Some(selected));
    }
    frame.render_stateful_widget(table, area, &mut state);

    // AUTHORITATIVE HINT STRING — this exact literal, including the
    // "Up/Down: Navigate" group, is required by the plan's must_haves
    // truth list and the Task 3 acceptance criteria. Do NOT shorten or
    // re-order. Any draft hint string in 32-RESEARCH.md / 32-PATTERNS.md
    // that omits "Up/Down: Navigate" is non-authoritative.
    draw_hints(
        frame,
        area,
        "r: Scan   Up/Down: Navigate   Enter: Register   Esc: Back",
    );
}

/// Draws the Managed Origins list screen.
///
/// Each origin is shown as its URL-pattern string.
/// An empty list renders a single informational row.
fn draw_managed_origin_list(
    frame: &mut Frame,
    area: Rect,
    origins: &[serde_json::Value],
    selected: usize,
) {
    let items: Vec<ListItem> = if origins.is_empty() {
        vec![ListItem::new(Line::from(
            "No managed origins configured.".to_string(),
        ))]
    } else {
        origins
            .iter()
            .map(|o| {
                let origin = o["origin"].as_str().unwrap_or("-");
                ListItem::new(Line::from(origin.to_string()))
            })
            .collect()
    };

    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(" Managed Origins ({}) ", origins.len()))
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = ratatui::widgets::ListState::default();
    if !origins.is_empty() {
        state.select(Some(selected));
    }
    frame.render_stateful_widget(list, area, &mut state);

    draw_hints(frame, area, "a: Add   d: Delete   Esc: Back");
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

#[cfg(test)]
mod usb_scan_render_tests {
    use super::*;
    use crate::app::UsbScanEntry;
    use dlp_common::DeviceIdentity;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn sample_entry(
        vid: &str,
        pid: &str,
        serial: &str,
        desc: &str,
        tier: Option<&str>,
    ) -> UsbScanEntry {
        UsbScanEntry {
            identity: DeviceIdentity {
                vid: vid.into(),
                pid: pid.into(),
                serial: serial.into(),
                description: desc.into(),
            },
            registered_tier: tier.map(str::to_string),
        }
    }

    #[test]
    fn draw_usb_scan_renders_headers_and_row() {
        let backend = TestBackend::new(120, 20);
        let mut term = Terminal::new(backend).expect("test terminal");
        let entry = sample_entry("0951", "1666", "SN1234", "Kingston USB", Some("read_only"));
        term.draw(|frame| {
            let area = frame.area();
            draw_usb_scan(frame, area, &[entry.clone()], 0);
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let s: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(s.contains("VID"), "header VID missing: {s}");
        assert!(s.contains("PID"), "header PID missing");
        assert!(s.contains("Serial"), "header Serial missing");
        assert!(s.contains("Description"), "header Description missing");
        assert!(s.contains("Registered"), "header Registered missing");
        assert!(s.contains("0951"), "row vid missing");
        assert!(s.contains("1666"), "row pid missing");
        assert!(s.contains("SN1234"), "row serial missing");
        assert!(s.contains("read_only"), "row tier missing");
    }

    #[test]
    fn draw_usb_scan_handles_empty_list() {
        let backend = TestBackend::new(120, 20);
        let mut term = Terminal::new(backend).expect("test terminal");
        term.draw(|frame| {
            let area = frame.area();
            draw_usb_scan(frame, area, &[], 0);
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let s: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(s.contains("USB Scan (0)"), "empty title missing: {s}");
        assert!(s.contains("r: Scan"), "hints missing");
        // Authoritative hint string check — the Up/Down: Navigate group
        // MUST be present per this plan's must_haves.
        assert!(
            s.contains("Up/Down: Navigate"),
            "Up/Down hint missing — draft shorter form leaked: {s}"
        );
    }

    #[test]
    fn draw_screen_devices_menu_has_three_items() {
        let backend = TestBackend::new(80, 20);
        let mut term = Terminal::new(backend).expect("test terminal");
        term.draw(|frame| {
            let area = frame.area();
            draw_menu(
                frame,
                area,
                "Devices & Origins",
                &["Device Registry", "Managed Origins", "Scan & Register USB"],
                2,
            );
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let s: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(s.contains("Scan & Register USB"), "3rd item missing: {s}");
    }
}
