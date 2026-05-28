//! Renders the current [`Screen`] to the terminal frame.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, Wrap,
};
use ratatui::Frame;

use crate::app::{
    App, ApprovalFilter, BypassAlertSeverityFilter, ConditionAttribute, ImportState, LabelFilter,
    LabelFormMode, Screen, SimulateFormState, SimulateOutcome, StatusKind, UsbScanEntry,
    ACTION_OPTIONS, ATTRIBUTES, OBJECT_TYPE_OPTIONS, SIMULATE_ACCESS_CONTEXT_OPTIONS,
    SIMULATE_ACTION_OPTIONS, SIMULATE_CLASSIFICATION_OPTIONS, SIMULATE_DEVICE_TRUST_OPTIONS,
    SIMULATE_NETWORK_LOCATION_OPTIONS, TIER_OPTIONS,
};
use crate::screens::approvals::{
    APPROVAL_GRANT_HINTS, APPROVAL_LIST_EMPTY, APPROVAL_LIST_HINTS, EXPIRY_OPTIONS,
};
use crate::screens::cloud_config::{
    CLOUD_CONFIG_BACK_ROW, CLOUD_CONFIG_KEYS, CLOUD_CONFIG_LABELS, CLOUD_CONFIG_SAVE_ROW,
};
use crate::screens::dispatch::condition_display;
use crate::screens::dispatch::operators_for;
use crate::screens::print_config::{
    is_print_bool, is_print_numeric, is_print_picker, PRINT_CONFIG_KEYS, PRINT_CONFIG_LABELS,
};
use crate::screens::bypass_alerts::{
    BYPASS_ALERT_DETAIL_HINTS, BYPASS_ALERT_LIST_EMPTY, BYPASS_ALERT_LIST_HINTS,
};
use crate::screens::protected_paths::{PROTECTED_PATH_LIST_EMPTY, PROTECTED_PATH_LIST_HINTS};
use crate::screens::syslog_config::draw_syslog_config;
use crate::screens::usb_enforcement::{
    USB_ENFORCEMENT_BACK_ROW, USB_ENFORCEMENT_KEYS, USB_ENFORCEMENT_LABELS,
    USB_ENFORCEMENT_SAVE_ROW,
};
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
                    "Label Management",
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
                    "LDAP Config",
                    "USB Enforcement",
                    "Cloud Config",
                    "Print Config",
                    "Label Review Queue",
                    "Approval Management",
                    "Protected Paths",
                    "Bypass Alerts",
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
        Screen::LdapConfig {
            config,
            selected,
            editing,
            buffer,
        } => {
            draw_ldap_config(frame, area, config, *selected, *editing, buffer);
        }
        Screen::UsbEnforcementConfig {
            config,
            selected,
            editing,
            buffer,
        } => {
            draw_usb_enforcement_config(frame, area, config, *selected, *editing, buffer);
        }
        Screen::CloudConfig {
            config,
            selected,
            editing,
            buffer,
        } => {
            draw_cloud_config(frame, area, config, *selected, *editing, buffer);
        }
        Screen::PrintConfig {
            config,
            selected,
            editing,
            buffer,
        } => {
            draw_print_config(frame, area, config, *selected, *editing, buffer);
        }
        Screen::SyslogConfig {
            config,
            selected,
            editing,
            buffer,
        } => {
            draw_syslog_config(frame, area, config, *selected, *editing, buffer);
        }
        Screen::Allowlist { screen } => {
            crate::screens::allowlist::draw_allowlist_screen(frame, screen, area);
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
                &[
                    "Device Registry",
                    "Managed Origins",
                    "Scan & Register USB",
                    "Disk Registry",
                ],
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
        Screen::DiskRegistryList { disks, selected } => {
            draw_disk_registry_list(frame, area, disks, *selected);
        }
        Screen::LabelList {
            labels,
            selected,
            filter,
            page,
            page_size,
            total,
        } => {
            draw_label_list(
                frame, area, labels, *selected, *filter, *page, *page_size, *total,
            );
        }
        Screen::LabelReviewQueue {
            labels,
            selected,
            department_filter,
            departments,
            department_index,
            page,
            page_size,
            total,
        } => {
            draw_label_review_queue(
                frame,
                area,
                labels,
                *selected,
                department_filter.as_deref(),
                departments,
                *department_index,
                *page,
                *page_size,
                *total,
            );
        }
        Screen::LabelDetail { label } => {
            draw_label_detail(frame, area, label);
        }
        Screen::LabelForm {
            mode,
            step,
            path,
            object_type,
            tier,
            owner_sid,
            parent_label_id,
            ..
        } => {
            draw_label_form(
                frame,
                area,
                *mode,
                *step,
                path,
                *object_type,
                *tier,
                owner_sid,
                parent_label_id,
            );
        }
        // Approval workflow screens (Phase 61)
        Screen::ApprovalList {
            approvals,
            selected,
            filter,
            page,
            per_page,
            total,
            ..
        } => {
            draw_approval_list(
                frame, area, approvals, *selected, *filter, *page, *per_page, *total,
            );
        }
        Screen::ApprovalDetail { detail } => {
            draw_approval_detail(frame, area, detail);
        }
        Screen::ApprovalGrant {
            approval_id,
            requester_sid,
            object_path,
            action,
            destination,
            tier,
            expiry_hours,
            signature_hex,
            selected_field,
        } => {
            draw_approval_grant(
                frame,
                area,
                approval_id,
                requester_sid,
                object_path,
                action,
                destination.as_deref(),
                tier.as_deref(),
                *expiry_hours,
                signature_hex,
                *selected_field,
            );
        }
        Screen::ProtectedPathList {
            paths,
            selected,
            page,
            page_size,
            total,
        } => {
            draw_protected_path_list(frame, area, paths, *selected, *page, *page_size, *total);
        }
        Screen::BypassAlertList {
            alerts,
            selected,
            filter,
            hide_acknowledged,
            page,
            page_size,
            total,
            ..
        } => {
            draw_bypass_alert_list(
                frame, area, alerts, *selected, *filter, *hide_acknowledged, *page, *page_size,
                *total,
            );
        }
        Screen::BypassAlertDetail { alert } => {
            draw_bypass_alert_detail(frame, area, alert);
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
                ConditionAttribute::SourceOrigin | ConditionAttribute::DestinationOrigin => {
                    vec![] // text input, not a list picker
                }
            }
        }
        _ => vec![],
    }
}

/// Returns the picker highlight style based on whether the pending list has focus.
///
/// When `pending_focused` is `true`, the picker is not focused and uses plain White.
/// When `false`, the picker has focus and uses Cyan background with Black text.
fn picker_highlight_style(pending_focused: bool) -> Style {
    if pending_focused {
        Style::default().fg(Color::White)
    } else {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    }
}

/// Renders the pending conditions list into the given area.
///
/// Shows an empty-state placeholder when `pending` is empty, otherwise renders
/// a scrollable list of conditions with a delete hint.
fn render_pending_conditions(
    frame: &mut Frame,
    area: Rect,
    pending: &[dlp_common::abac::PolicyCondition],
    pending_focused: bool,
    pending_state: &ListState,
) {
    if pending.is_empty() {
        let empty = Paragraph::new(Line::from(
            "No conditions added. Use the picker below to add conditions.",
        ))
        .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(empty, area);
        return;
    }

    let highlight = if pending_focused {
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

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Pending Conditions ")
                .borders(Borders::ALL),
        )
        .highlight_style(highlight)
        .highlight_symbol("> ");

    let mut ps = pending_state.clone();
    frame.render_stateful_widget(list, area, &mut ps);
}

/// Renders the AppField sub-picker (Step 1.5) into the given area.
fn render_app_field_sub_picker(
    frame: &mut Frame,
    area: Rect,
    pending_focused: bool,
    picker_state: &ListState,
) {
    let sub_label = Line::styled(
        "Step 1.5: Select Application Field",
        Style::default().add_modifier(Modifier::BOLD),
    );
    frame.render_widget(Paragraph::new(sub_label), area);

    let sub_items: Vec<ListItem> = APP_FIELD_LABELS
        .iter()
        .map(|f| ListItem::new(f.to_string()))
        .collect();

    let sub_picker = List::new(sub_items)
        .highlight_style(picker_highlight_style(pending_focused))
        .highlight_symbol("> ");

    let mut pk = picker_state.clone();
    frame.render_stateful_widget(sub_picker, area, &mut pk);
}

/// Renders the Step 3 text input widget into the given area.
///
/// The title varies based on the selected attribute and field.
fn render_step3_text_input(
    frame: &mut Frame,
    area: Rect,
    selected_attribute: Option<&ConditionAttribute>,
    _selected_field: Option<dlp_common::abac::AppField>,
    buffer: &str,
) {
    let is_member_of = selected_attribute == Some(&ConditionAttribute::MemberOf);
    let is_origin = matches!(
        selected_attribute,
        Some(ConditionAttribute::SourceOrigin) | Some(ConditionAttribute::DestinationOrigin)
    );

    let title = if is_member_of {
        " AD Group SID (partial match) "
    } else if is_origin {
        " Origin URL "
    } else {
        " Application Value "
    };

    let input_display = format!("[{buffer}_]");
    let input_paragraph =
        Paragraph::new(input_display).block(Block::default().title(title).borders(Borders::ALL));
    frame.render_widget(input_paragraph, area);
}

/// Renders the regular step picker list into the given area.
fn render_step_picker_list(
    frame: &mut Frame,
    area: Rect,
    step: u8,
    selected_attribute: Option<&ConditionAttribute>,
    selected_field: Option<dlp_common::abac::AppField>,
    pending_focused: bool,
    picker_state: &ListState,
) {
    let items = picker_items(step, selected_attribute, selected_field);
    if items.is_empty() {
        return;
    }

    let picker_list = List::new(items)
        .highlight_style(picker_highlight_style(pending_focused))
        .highlight_symbol("> ");

    let mut pk = picker_state.clone();
    frame.render_stateful_widget(picker_list, area, &mut pk);
}

/// Returns the hint string for the conditions builder based on current state.
fn conditions_builder_hints(
    pending_focused: bool,
    in_app_field_sub_step: bool,
    is_text_input_step3: bool,
) -> &'static str {
    if pending_focused {
        "Up/Down Navigate  d: Delete  e: Edit  Tab: Switch to Picker  Esc: Close"
    } else if in_app_field_sub_step {
        "Enter: Select   Esc: Back to attribute"
    } else if is_text_input_step3 {
        "Type value  Enter: Add  Esc: Back  Tab: Switch to Pending"
    } else {
        "Up/Down Navigate  Enter: Select  Esc: Back/Close  Tab: Switch to Pending"
    }
}

/// Computes the step flags used to determine rendering mode.
///
/// Returns `(in_app_field_sub_step, is_text_input_step3)`.
fn step_flags(
    step: u8,
    selected_attribute: Option<&ConditionAttribute>,
    selected_field: Option<dlp_common::abac::AppField>,
) -> (bool, bool) {
    use dlp_common::abac::AppField;

    let in_app_field_sub_step = step == 1
        && matches!(
            selected_attribute,
            Some(ConditionAttribute::SourceApplication)
                | Some(ConditionAttribute::DestinationApplication)
        )
        && selected_field.is_none();

    let is_member_of_step3 = step == 3 && selected_attribute == Some(&ConditionAttribute::MemberOf);
    let is_app_text_step3 = step == 3
        && matches!(
            selected_attribute,
            Some(ConditionAttribute::SourceApplication)
                | Some(ConditionAttribute::DestinationApplication)
        )
        && matches!(
            selected_field,
            Some(AppField::Publisher)
                | Some(AppField::ImagePath)
                | Some(AppField::Aumid)
                | Some(AppField::PackageFamilyName)
        );
    let is_origin_text_step3 = step == 3
        && matches!(
            selected_attribute,
            Some(ConditionAttribute::SourceOrigin) | Some(ConditionAttribute::DestinationOrigin)
        );
    let is_text_input_step3 = is_member_of_step3 || is_app_text_step3 || is_origin_text_step3;

    (in_app_field_sub_step, is_text_input_step3)
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
    frame.render_widget(Clear, area);

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
    let inner = modal_block.inner(modal_area);
    frame.render_widget(modal_block, modal_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(6),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner);

    let header_area = chunks[0];
    let pending_area = chunks[1];
    let divider_area = chunks[2];
    let picker_area = chunks[3];

    frame.render_widget(Paragraph::new(build_breadcrumb(step)), header_area);

    let divider = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    frame.render_widget(divider, divider_area);

    render_pending_conditions(frame, pending_area, pending, pending_focused, pending_state);

    let picker_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(picker_area);

    let (in_app_field_sub_step, is_text_input_step3) =
        step_flags(step, selected_attribute, selected_field);

    if !in_app_field_sub_step {
        frame.render_widget(
            Paragraph::new(step_label(step, selected_attribute)),
            picker_chunks[0],
        );
    }

    if in_app_field_sub_step {
        render_app_field_sub_picker(frame, picker_chunks[1], pending_focused, picker_state);
    } else if is_text_input_step3 {
        render_step3_text_input(
            frame,
            picker_chunks[1],
            selected_attribute,
            selected_field,
            buffer,
        );
    } else {
        render_step_picker_list(
            frame,
            picker_chunks[1],
            step,
            selected_attribute,
            selected_field,
            pending_focused,
            picker_state,
        );
    }

    let hints =
        conditions_builder_hints(pending_focused, in_app_field_sub_step, is_text_input_step3);
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

/// Formats a single config field value for display.
///
/// Handles the editing buffer, boolean toggle display, secret masking,
/// numeric formatting, and plain text with empty-state fallback.
#[allow(clippy::too_many_arguments)]
fn format_config_field_value(
    config: &serde_json::Value,
    key: &str,
    index: usize,
    selected: usize,
    editing: bool,
    buffer: &str,
    is_bool_fn: fn(usize) -> bool,
    is_secret_fn: fn(usize) -> bool,
    is_numeric_fn: fn(usize) -> bool,
) -> String {
    if editing && index == selected {
        return format!("[{buffer}_]");
    }
    if is_bool_fn(index) {
        let b = config[key].as_bool().unwrap_or(false);
        return if b {
            "[x]".to_string()
        } else {
            "[ ]".to_string()
        };
    }
    if is_secret_fn(index) {
        let v = config[key].as_str().unwrap_or("");
        return if v.is_empty() {
            "(empty)".to_string()
        } else {
            "*****".to_string()
        };
    }
    if is_numeric_fn(index) {
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
            let value_display = format_config_field_value(
                config,
                KEYS[i],
                i,
                selected,
                editing,
                buffer,
                is_siem_bool,
                is_siem_secret,
                |_| false,
            );
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
            let value_display = format_config_field_value(
                config,
                KEYS[i],
                i,
                selected,
                editing,
                buffer,
                is_alert_bool,
                is_alert_secret,
                is_alert_numeric,
            );
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

/// Formats the policy name field line.
fn format_policy_name_field(
    label: &str,
    form: &crate::app::PolicyFormState,
    selected: usize,
    editing: bool,
    buffer: &str,
) -> Line<'static> {
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

/// Formats the policy description field line.
fn format_policy_description_field(
    label: &str,
    form: &crate::app::PolicyFormState,
    selected: usize,
    editing: bool,
    buffer: &str,
) -> Line<'static> {
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

/// Formats the policy priority field line.
fn format_policy_priority_field(
    label: &str,
    form: &crate::app::PolicyFormState,
    selected: usize,
    editing: bool,
    buffer: &str,
) -> Line<'static> {
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

/// Formats the policy action field line.
fn format_policy_action_field(label: &str, form: &crate::app::PolicyFormState) -> Line<'static> {
    let action_label = ACTION_OPTIONS[form.action];
    Line::from(format!("{label}:            {action_label}"))
}

/// Formats the policy enabled field line.
fn format_policy_enabled_field(label: &str, form: &crate::app::PolicyFormState) -> Line<'static> {
    let enabled_val = if form.enabled { "Yes" } else { "No" };
    Line::from(format!("{label}:              {enabled_val}"))
}

/// Formats the policy mode field line.
fn format_policy_mode_field(label: &str, form: &crate::app::PolicyFormState) -> Line<'static> {
    let mode_label = match form.mode {
        PolicyMode::ALL => "ALL",
        PolicyMode::ANY => "ANY",
        PolicyMode::NONE => "NONE",
    };
    Line::from(format!("{label}:              {mode_label}"))
}

/// Formats the policy conditions summary field line.
fn format_policy_conditions_field(
    label: &str,
    form: &crate::app::PolicyFormState,
) -> Line<'static> {
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

/// Renders the mode advisory hint when applicable.
fn render_mode_advisory(
    frame: &mut Frame,
    area: Rect,
    form: &crate::app::PolicyFormState,
    validation_error: Option<&str>,
) {
    if validation_error.is_some()
        || form.mode == PolicyMode::ALL
        || !form.conditions.is_empty()
        || area.height < 4
    {
        return;
    }
    let hint = match form.mode {
        PolicyMode::ANY => "Note: mode=ANY with no conditions will never match.",
        PolicyMode::NONE => "Note: mode=NONE with no conditions matches every request.",
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

/// Renders a validation error overlay at the bottom of the form area.
fn render_validation_error(frame: &mut Frame, area: Rect, validation_error: Option<&str>) {
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
    let mut items: Vec<ListItem> = Vec::with_capacity(POLICY_FIELD_LABELS.len());

    for (i, label) in POLICY_FIELD_LABELS.iter().enumerate() {
        let line = match i {
            0 => format_policy_name_field(label, form, selected, editing, buffer),
            1 => format_policy_description_field(label, form, selected, editing, buffer),
            2 => format_policy_priority_field(label, form, selected, editing, buffer),
            3 => format_policy_action_field(label, form),
            4 => format_policy_enabled_field(label, form),
            5 => format_policy_mode_field(label, form),
            6 => Line::from(format!("  {label}")),
            7 => format_policy_conditions_field(label, form),
            8 => Line::from(format!("  {label}")),
            _ => Line::from(""),
        };
        items.push(ListItem::new(line));
    }

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

    render_mode_advisory(frame, area, form, validation_error);
    render_validation_error(frame, area, validation_error);

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
    let mut items: Vec<ListItem> = Vec::with_capacity(POLICY_FIELD_LABELS.len());

    for (i, label) in POLICY_FIELD_LABELS.iter().enumerate() {
        let line = match i {
            0 => format_policy_name_field(label, form, selected, editing, buffer),
            1 => format_policy_description_field(label, form, selected, editing, buffer),
            2 => format_policy_priority_field(label, form, selected, editing, buffer),
            3 => format_policy_action_field(label, form),
            4 => format_policy_enabled_field(label, form),
            5 => format_policy_mode_field(label, form),
            6 => Line::from(format!("  {label}")),
            7 => format_policy_conditions_field(label, form),
            8 => Line::from("  [Save]"),
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

    render_mode_advisory(frame, area, form, validation_error);
    render_validation_error(frame, area, validation_error);

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

/// Draws the Device Registry list screen as a 6-column ratatui `Table`.
///
/// Columns: VID | PID | Serial | Owner | Tier | Description.
/// Machine-wide entries (null owner_sid) display "(all users)" in the Owner column.
/// Per-user entries display the owner_user if present, otherwise the SID truncated.
fn draw_device_list(frame: &mut Frame, area: Rect, devices: &[serde_json::Value], selected: usize) {
    if devices.is_empty() {
        let paragraph = Paragraph::new("No devices registered.")
            .block(
                Block::default()
                    .title(" Device Registry (0) ")
                    .borders(Borders::ALL),
            )
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(paragraph, area);
        draw_hints(frame, area, "r: Register   d: Delete   Esc: Back");
        return;
    }

    let header = Row::new(vec!["VID", "PID", "Serial", "Owner", "Tier", "Description"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = devices
        .iter()
        .map(|d| {
            let vid = d["vid"].as_str().unwrap_or("-");
            let pid = d["pid"].as_str().unwrap_or("-");
            let serial = d["serial"].as_str().unwrap_or("");
            let description = d["description"].as_str().unwrap_or("");
            let trust_tier = d["trust_tier"].as_str().unwrap_or("blocked");
            let tier_label = match trust_tier {
                "read_only" => "READ_ONLY",
                "full_access" => "FULL_ACCESS",
                _ => "BLOCKED",
            };

            // Owner column: per D-10, machine-wide entries show "(all users)".
            let owner_sid = d["owner_sid"].as_str();
            let owner_user = d["owner_user"].as_str();
            let owner = match (owner_sid, owner_user) {
                (None, None) => "(all users)".to_string(),
                (None, Some(user)) => format!("{user} (all users)"),
                (Some(_), Some(user)) => user.to_string(),
                (Some(sid), None) => {
                    // Truncate long SIDs to avoid breaking layout (T-38.4-11 mitigation).
                    if sid.len() > 20 {
                        format!("{}...", &sid[..17])
                    } else {
                        sid.to_string()
                    }
                }
            };

            Row::new(vec![
                vid.to_string(),
                pid.to_string(),
                serial.to_string(),
                owner,
                tier_label.to_string(),
                description.to_string(),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(8),  // VID
        Constraint::Percentage(8),  // PID
        Constraint::Percentage(18), // Serial
        Constraint::Percentage(18), // Owner
        Constraint::Percentage(12), // Tier
        Constraint::Percentage(36), // Description
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" Device Registry ({}) ", devices.len()))
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

    draw_hints(frame, area, "r: Register   d: Delete   Esc: Back");
}

/// Draws the USB scan and register screen as a 5-column ratatui `Table`.
///
/// Columns: VID | PID | Serial | Description | Registered
/// Already-registered devices show their current trust tier in the Registered
/// column; unregistered devices show `-` (per Phase 32 D-04).
/// Renders a hint footer: `r: Scan   Up/Down: Navigate   Enter: Register   Esc: Back`.
fn draw_usb_scan(frame: &mut Frame, area: Rect, devices: &[UsbScanEntry], selected: usize) {
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

/// Draws the disk-registry list screen as a 5-column ratatui `Table`.
///
/// Columns: Agent ID | Instance ID | Bus Type | Encrypted | Model.
fn draw_disk_registry_list(
    frame: &mut Frame,
    area: Rect,
    disks: &[serde_json::Value],
    selected: usize,
) {
    if disks.is_empty() {
        let paragraph = Paragraph::new("No disk registry entries.")
            .block(
                Block::default()
                    .title(" Disk Registry (0) ")
                    .borders(Borders::ALL),
            )
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(paragraph, area);
        draw_hints(frame, area, "a: Add   Esc: Back");
        return;
    }

    let header = Row::new(vec![
        "Agent ID",
        "Instance ID",
        "Bus Type",
        "Encrypted",
        "Model",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .bottom_margin(1);

    let rows: Vec<Row> = disks
        .iter()
        .map(|d| {
            Row::new(vec![
                d["agent_id"].as_str().unwrap_or("-").to_string(),
                d["instance_id"].as_str().unwrap_or("-").to_string(),
                d["bus_type"].as_str().unwrap_or("-").to_string(),
                d["encryption_status"].as_str().unwrap_or("-").to_string(),
                d["model"].as_str().unwrap_or("").to_string(),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(20), // Agent ID
        Constraint::Percentage(25), // Instance ID
        Constraint::Percentage(12), // Bus Type
        Constraint::Percentage(13), // Encrypted
        Constraint::Percentage(30), // Model
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" Disk Registry ({}) ", disks.len()))
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

/// Draws the USB enforcement config form.
///
/// Three picker fields (row 0-2) plus Save (row 3) and Back (row 4).
/// When `editing` is true, the selected picker cycles through its options
/// on Up/Down instead of moving between rows.
fn draw_usb_enforcement_config(
    frame: &mut Frame,
    area: Rect,
    config: &serde_json::Value,
    selected: usize,
    editing: bool,
    _buffer: &str,
) {
    let block = Block::default()
        .title("USB Enforcement Settings")
        .borders(Borders::ALL);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut items: Vec<ListItem> = Vec::new();

    for (i, key) in USB_ENFORCEMENT_KEYS.iter().enumerate() {
        let current_value = config.get(key).and_then(|v| v.as_str()).unwrap_or("");
        let label = USB_ENFORCEMENT_LABELS[i];
        let display = if editing && i == selected {
            format!("> {}: {} <", label, current_value)
        } else if i == selected {
            format!("> {}: {}", label, current_value)
        } else {
            format!("  {}: {}", label, current_value)
        };
        items.push(ListItem::new(display));
    }

    // Save row
    let save_text = if selected == USB_ENFORCEMENT_SAVE_ROW {
        "> [ Save ]"
    } else {
        "  [ Save ]"
    };
    items.push(ListItem::new(save_text));

    // Back row
    let back_text = if selected == USB_ENFORCEMENT_BACK_ROW {
        "> [ Back ]"
    } else {
        "  [ Back ]"
    };
    items.push(ListItem::new(back_text));

    let list = List::new(items).highlight_style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(list, inner);

    // Show hint when editing a picker field
    if editing && selected < USB_ENFORCEMENT_KEYS.len() {
        let hint = "Up/Down: cycle options | Enter: confirm | Esc: cancel".to_string();
        let hint_para = Paragraph::new(hint).style(Style::default().fg(Color::DarkGray));
        let hint_area = Rect {
            x: inner.x,
            y: inner.y + inner.height.saturating_sub(1),
            width: inner.width,
            height: 1,
        };
        frame.render_widget(hint_para, hint_area);
    }
}

/// Draws the Cloud Config form.
///
/// `cloud_hook_enabled` (row 0) is rendered as a bool toggle — `true` displays as "Enabled",
/// `false` displays as "Disabled". Row 1 = [Save], Row 2 = [Back].
fn draw_cloud_config(
    frame: &mut Frame,
    area: Rect,
    config: &serde_json::Value,
    selected: usize,
    _editing: bool,
    _buffer: &str,
) {
    let block = Block::default()
        .title(" Cloud Config ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut items: Vec<ListItem> = Vec::with_capacity(CLOUD_CONFIG_KEYS.len() + 2);

    for (i, key) in CLOUD_CONFIG_KEYS.iter().enumerate() {
        let label = CLOUD_CONFIG_LABELS[i];
        // cloud_hook_enabled is a bool — display as "Enabled"/"Disabled".
        let value_str =
            config[key]
                .as_bool()
                .map_or("Disabled", |b| if b { "Enabled" } else { "Disabled" });
        let line = if i == selected {
            format!("> {label}: {value_str}")
        } else {
            format!("  {label}: {value_str}")
        };
        items.push(ListItem::new(line));
    }

    let save_text = if selected == CLOUD_CONFIG_SAVE_ROW {
        "> [ Save ]"
    } else {
        "  [ Save ]"
    };
    items.push(ListItem::new(save_text));

    let back_text = if selected == CLOUD_CONFIG_BACK_ROW {
        "> [ Back ]"
    } else {
        "  [ Back ]"
    };
    items.push(ListItem::new(back_text));

    let list = List::new(items).highlight_style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(list, inner);

    draw_hints(
        frame,
        area,
        "Up/Down: navigate | Enter: toggle/action | Esc: back",
    );
}

/// Draws the Print Config form.
///
/// Row 0: print_enabled (bool toggle — "[x]" / "[ ]").
/// Row 1: print_xps_timeout_ms (numeric, edit buffer shown when editing).
/// Row 2: print_unclassifiable_action (picker — cycles on Up/Down in edit mode).
/// Row 3: print_max_pages (numeric).
/// Row 4: [Save], Row 5: [Back].
fn draw_print_config(
    frame: &mut Frame,
    area: Rect,
    config: &serde_json::Value,
    selected: usize,
    editing: bool,
    buffer: &str,
) {
    // Combine field labels with action rows for a single iteration pass.
    const ACTION_LABELS: [&str; 2] = ["[ Save ]", "[ Back ]"];
    let all_labels: Vec<&str> = PRINT_CONFIG_LABELS
        .iter()
        .copied()
        .chain(ACTION_LABELS.iter().copied())
        .collect();

    let mut items: Vec<ListItem> = Vec::with_capacity(all_labels.len());

    for (i, label) in all_labels.iter().enumerate() {
        let line = if i < PRINT_CONFIG_KEYS.len() {
            let value_display = if is_print_picker(i) && editing && i == selected {
                // Picker in edit mode: show buffer-like prompt with current value and hint arrows.
                format!(
                    "[{}]",
                    config
                        .get(PRINT_CONFIG_KEYS[i])
                        .and_then(|v| v.as_str())
                        .unwrap_or("Block")
                )
            } else if is_print_picker(i) {
                // Picker not editing: show the stored string value directly.
                config
                    .get(PRINT_CONFIG_KEYS[i])
                    .and_then(|v| v.as_str())
                    .unwrap_or("Block")
                    .to_string()
            } else {
                format_config_field_value(
                    config,
                    PRINT_CONFIG_KEYS[i],
                    i,
                    selected,
                    editing,
                    buffer,
                    is_print_bool,
                    |_| false,
                    is_print_numeric,
                )
            };
            format!("{label}: {value_display}")
        } else {
            (*label).to_string()
        };
        items.push(ListItem::new(Line::from(line)));
    }

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Print Config ")
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

    let hints = if editing && is_print_picker(selected) {
        "Up/Down: cycle options | Enter: confirm | Esc: cancel"
    } else if editing {
        "Type to edit | Enter: commit | Esc: cancel"
    } else {
        "Up/Down: navigate | Enter: edit/toggle | Esc: back"
    };
    draw_hints(frame, area, hints);
}

// ---------------------------------------------------------------------------
// Label management screens
// ---------------------------------------------------------------------------

pub use crate::screens::labels::{
    LABEL_LIST_EMPTY, LABEL_LIST_HINTS, LABEL_REVIEW_EMPTY, LABEL_REVIEW_HINTS,
};

/// Draws the Label Management list screen as a scrollable table.
///
/// Columns: Path (truncated), Type, Tier, State, Owner.
#[allow(clippy::too_many_arguments)]
fn draw_label_list(
    frame: &mut Frame,
    area: Rect,
    labels: &[serde_json::Value],
    selected: usize,
    filter: LabelFilter,
    page: usize,
    page_size: usize,
    total: usize,
) {
    if labels.is_empty() {
        let paragraph = Paragraph::new(LABEL_LIST_EMPTY)
            .block(
                Block::default()
                    .title(" Label Management (0) ")
                    .borders(Borders::ALL),
            )
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(paragraph, area);
        draw_hints(frame, area, LABEL_LIST_HINTS);
        return;
    }

    let filter_suffix = if filter != LabelFilter::All {
        format!(" [Filter: {}]", filter.label())
    } else {
        String::new()
    };

    let total_pages = if total == 0 {
        1
    } else {
        total.div_ceil(page_size)
    };
    let page_info = format!(
        "Page {} of {} | {} per page",
        page + 1,
        total_pages,
        page_size
    );

    let header = Row::new(vec!["Path", "Type", "Tier", "State", "Owner"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = labels
        .iter()
        .map(|l| {
            let path = l["path"].as_str().unwrap_or("-");
            let path_display = if path.len() > 40 {
                format!("{}...", &path[..37])
            } else {
                path.to_string()
            };
            let object_type = l["object_type"].as_str().unwrap_or("-");
            let tier = l["tier"].as_str().unwrap_or("-");
            let state = l["label_state"].as_str().unwrap_or("-");
            let owner = l["owner_sid"].as_str().unwrap_or("(none)");
            Row::new(vec![
                path_display,
                object_type.to_string(),
                tier.to_string(),
                state.to_string(),
                owner.to_string(),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(40), // Path
        Constraint::Percentage(10), // Type
        Constraint::Percentage(10), // Tier
        Constraint::Percentage(15), // State
        Constraint::Percentage(25), // Owner
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(
                    " Label Management ({}){filter_suffix} ",
                    labels.len()
                ))
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

    // Pagination info in the footer, right-aligned
    let hint_text = format!("{LABEL_LIST_HINTS}  |  {page_info}");
    draw_hints(frame, area, &hint_text);
}

/// Draws the Data Owner Review Queue screen.
///
/// Columns: Path, Tier, Owner SID, Confidence, Created.
#[allow(clippy::too_many_arguments)]
fn draw_label_review_queue(
    frame: &mut Frame,
    area: Rect,
    labels: &[serde_json::Value],
    selected: usize,
    department_filter: Option<&str>,
    _departments: &[String],
    _department_index: usize,
    page: usize,
    page_size: usize,
    total: usize,
) {
    // Build title with department filter indicator
    let title = if let Some(dept) = department_filter {
        format!(
            " Data Owner Review Queue ({}) [Dept: {}] ",
            labels.len(),
            dept
        )
    } else {
        format!(" Data Owner Review Queue ({}) ", labels.len())
    };

    let total_pages = if total == 0 {
        1
    } else {
        total.div_ceil(page_size)
    };
    let page_info = format!(
        "Page {} of {} | {} per page",
        page + 1,
        total_pages,
        page_size
    );

    if labels.is_empty() {
        let paragraph = Paragraph::new(LABEL_REVIEW_EMPTY)
            .block(Block::default().title(title).borders(Borders::ALL))
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(paragraph, area);
        let hint_text = format!("{LABEL_REVIEW_HINTS}  |  {page_info}");
        draw_hints(frame, area, &hint_text);
        return;
    }

    let header = Row::new(vec!["Path", "Tier", "Owner SID", "Confidence", "Created"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = labels
        .iter()
        .map(|l| {
            let path = l["path"].as_str().unwrap_or("-");
            let tier = l["tier"].as_str().unwrap_or("-");
            let owner = l["owner_sid"].as_str().unwrap_or("(none)");
            let confidence = l["scanner_confidence"]
                .as_f64()
                .map(|v| format!("{:.0}%", v * 100.0))
                .unwrap_or_else(|| "--".to_string());
            let created = l["created_at"].as_str().unwrap_or("-");
            Row::new(vec![
                path.to_string(),
                tier.to_string(),
                owner.to_string(),
                confidence,
                created.to_string(),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(35), // Path
        Constraint::Percentage(8),  // Tier
        Constraint::Percentage(22), // Owner SID
        Constraint::Percentage(10), // Confidence
        Constraint::Percentage(25), // Created
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().title(title).borders(Borders::ALL))
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

    let hint_text = format!("{LABEL_REVIEW_HINTS}  |  {page_info}");
    draw_hints(frame, area, &hint_text);
}

/// Draws the Label Detail read-only view.
fn draw_label_detail(frame: &mut Frame, area: Rect, label: &serde_json::Value) {
    let id = label["id"].as_str().unwrap_or("-");
    let path = label["path"].as_str().unwrap_or("-");
    let object_type = label["object_type"].as_str().unwrap_or("-");
    let tier = label["tier"].as_str().unwrap_or("-");
    let state = label["label_state"].as_str().unwrap_or("-");
    let owner = label["owner_sid"].as_str().unwrap_or("(none)");
    let parent = label["parent_label_id"].as_str().unwrap_or("(none)");
    let created = label["created_at"].as_str().unwrap_or("-");
    let updated = label["updated_at"].as_str().unwrap_or("-");

    let confidence = label["scanner_confidence"]
        .as_f64()
        .map(|v| format!("{:.0}%", v * 100.0))
        .unwrap_or_else(|| "--".to_string());
    let department = label["department"].as_str().unwrap_or("(none)");

    let body = format!(
        "ID:                {id}\n\
         Path:              {path}\n\
         Object Type:       {object_type}\n\
         Tier:              {tier}\n\
         State:             {state}\n\
         Owner SID:         {owner}\n\
         Parent Label ID:   {parent}\n\
         Scanner Confidence: {confidence}\n\
         Department:        {department}\n\
         Created At:        {created}\n\
         Updated At:        {updated}"
    );

    draw_result(frame, area, "Label Detail", &body);
}

/// Draws the multi-step Label Form (creation or edit).
///
/// Steps 1-5 show the current field with navigation hints.
/// Step 6 shows a summary with submit/cancel options.
#[allow(clippy::too_many_arguments)]
fn draw_label_form(
    frame: &mut Frame,
    area: Rect,
    mode: LabelFormMode,
    step: u8,
    path: &str,
    object_type: usize,
    tier: usize,
    owner_sid: &str,
    parent_label_id: &str,
) {
    let title = match mode {
        LabelFormMode::New => " Create Label ",
        LabelFormMode::Edit => " Edit Label ",
    };

    let mut items: Vec<ListItem> = Vec::with_capacity(8);

    // Step indicator line
    let step_line = format!("Step {step} of 6");
    items.push(ListItem::new(Line::styled(
        step_line,
        Style::default().add_modifier(Modifier::BOLD),
    )));
    items.push(ListItem::new(Line::raw("")));

    match step {
        1 => {
            items.push(ListItem::new(Line::from(format!("Path: [{path}_]"))));
            items.push(ListItem::new(Line::raw("")));
            items.push(ListItem::new(Line::styled(
                "Enter the file or folder path to label.",
                Style::default().fg(Color::DarkGray),
            )));
        }
        2 => {
            let ot = OBJECT_TYPE_OPTIONS.get(object_type).unwrap_or(&"file");
            items.push(ListItem::new(Line::from(format!("Object Type: {ot}"))));
            items.push(ListItem::new(Line::raw("")));
            items.push(ListItem::new(Line::styled(
                "Up/Down: cycle options | Enter: confirm",
                Style::default().fg(Color::DarkGray),
            )));
        }
        3 => {
            let t = TIER_OPTIONS.get(tier).unwrap_or(&"T1");
            items.push(ListItem::new(Line::from(format!("Tier: {t}"))));
            items.push(ListItem::new(Line::raw("")));
            items.push(ListItem::new(Line::styled(
                "Up/Down: cycle options | Enter: confirm",
                Style::default().fg(Color::DarkGray),
            )));
        }
        4 => {
            let display = if owner_sid.is_empty() {
                "(none)"
            } else {
                owner_sid
            };
            items.push(ListItem::new(Line::from(format!(
                "Owner SID: [{display}_]"
            ))));
            items.push(ListItem::new(Line::raw("")));
            items.push(ListItem::new(Line::styled(
                "Enter owner SID (optional). Press Enter to skip.",
                Style::default().fg(Color::DarkGray),
            )));
        }
        5 => {
            let display = if parent_label_id.is_empty() {
                "(none)"
            } else {
                parent_label_id
            };
            items.push(ListItem::new(Line::from(format!(
                "Parent Label ID: [{display}_]"
            ))));
            items.push(ListItem::new(Line::raw("")));
            items.push(ListItem::new(Line::styled(
                "Enter parent label ID (optional). Press Enter to skip.",
                Style::default().fg(Color::DarkGray),
            )));
        }
        6 => {
            let ot = OBJECT_TYPE_OPTIONS.get(object_type).unwrap_or(&"file");
            let t = TIER_OPTIONS.get(tier).unwrap_or(&"T1");
            let owner_disp = if owner_sid.is_empty() {
                "(none)"
            } else {
                owner_sid
            };
            let parent_disp = if parent_label_id.is_empty() {
                "(none)"
            } else {
                parent_label_id
            };
            items.push(ListItem::new(Line::styled(
                "Review and confirm:",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            items.push(ListItem::new(Line::raw("")));
            items.push(ListItem::new(Line::from(format!(
                "Path:            {path}"
            ))));
            items.push(ListItem::new(Line::from(format!("Object Type:     {ot}"))));
            items.push(ListItem::new(Line::from(format!("Tier:            {t}"))));
            items.push(ListItem::new(Line::from(format!(
                "Owner SID:       {owner_disp}"
            ))));
            items.push(ListItem::new(Line::from(format!(
                "Parent Label ID: {parent_disp}"
            ))));
            items.push(ListItem::new(Line::raw("")));
            items.push(ListItem::new(Line::styled(
                "[Enter] Submit  [Esc] Cancel",
                Style::default().fg(Color::DarkGray),
            )));
        }
        _ => {}
    }

    let list = List::new(items).block(Block::default().title(title).borders(Borders::ALL));

    frame.render_widget(list, area);

    let hints = match step {
        1 | 4 | 5 => "Type to enter | Enter: confirm | Esc: cancel",
        2 | 3 => "Up/Down: cycle | Enter: confirm | Esc: cancel",
        6 => "Enter: Submit | Esc: Cancel",
        _ => "",
    };
    draw_hints(frame, area, hints);
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

// ---------------------------------------------------------------------------
// LDAP Config (Phase 38.1)
// ---------------------------------------------------------------------------

/// Display labels for each row of the LDAP config form (in display order).
///
/// 5 editable fields + Save + Back = 7 total rows. The order MUST match
/// `LDAP_KEYS` in `dlp-admin-cli/src/screens/dispatch.rs` so each row's
/// label aligns with the JSON key it edits.
const LDAP_FIELD_LABELS: [&str; 7] = [
    "LDAP URL",
    "Base DN",
    "Require TLS",
    "Cache TTL (secs)",
    "VPN Subnets",
    "[ Save ]",
    "[ Back ]",
];

/// Returns `true` when a row index corresponds to the boolean `require_tls` field.
fn is_ldap_bool(index: usize) -> bool {
    matches!(index, 2)
}

/// Returns `true` when a row index corresponds to the numeric `cache_ttl_secs` field.
fn is_ldap_numeric(index: usize) -> bool {
    matches!(index, 3)
}

/// Draws the LDAP / Active Directory configuration form.
///
/// # Arguments
///
/// * `frame` - ratatui frame to render into
/// * `area` - screen area allocated to the form
/// * `config` - current config payload as a JSON object (loaded from the server)
/// * `selected` - index of the currently highlighted row (0..=6)
/// * `editing` - `true` when the highlighted text/numeric field is in edit mode
/// * `buffer` - edit buffer contents (only meaningful when `editing` is `true`)
fn draw_ldap_config(
    frame: &mut Frame,
    area: Rect,
    config: &serde_json::Value,
    selected: usize,
    editing: bool,
    buffer: &str,
) {
    // Map row index -> JSON key for editable fields. The 5 keys here match
    // the on-wire `LdapConfigPayload` field names from
    // `dlp-server/src/admin_api.rs` exactly.
    const KEYS: [&str; 5] = [
        "ldap_url",
        "base_dn",
        "require_tls",
        "cache_ttl_secs",
        "vpn_subnets",
    ];

    let mut items: Vec<ListItem> = Vec::with_capacity(LDAP_FIELD_LABELS.len());
    for (i, label) in LDAP_FIELD_LABELS.iter().enumerate() {
        let line = if i < KEYS.len() {
            let value_display = format_config_field_value(
                config,
                KEYS[i],
                i,
                selected,
                editing,
                buffer,
                is_ldap_bool,
                |_| false,
                is_ldap_numeric,
            );
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
                .title(" LDAP Config ")
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

#[cfg(test)]
mod ldap_render_tests {
    use super::*;

    #[test]
    fn ldap_field_labels_are_seven_in_order() {
        assert_eq!(LDAP_FIELD_LABELS.len(), 7);
        assert_eq!(LDAP_FIELD_LABELS[0], "LDAP URL");
        assert_eq!(LDAP_FIELD_LABELS[1], "Base DN");
        assert_eq!(LDAP_FIELD_LABELS[2], "Require TLS");
        assert_eq!(LDAP_FIELD_LABELS[3], "Cache TTL (secs)");
        assert_eq!(LDAP_FIELD_LABELS[4], "VPN Subnets");
        assert_eq!(LDAP_FIELD_LABELS[5], "[ Save ]");
        assert_eq!(LDAP_FIELD_LABELS[6], "[ Back ]");
    }

    #[test]
    fn is_ldap_bool_only_matches_row_2() {
        for i in 0..LDAP_FIELD_LABELS.len() {
            assert_eq!(is_ldap_bool(i), i == 2);
        }
    }

    #[test]
    fn is_ldap_numeric_only_matches_row_3() {
        for i in 0..LDAP_FIELD_LABELS.len() {
            assert_eq!(is_ldap_numeric(i), i == 3);
        }
    }
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
    fn draw_screen_devices_menu_has_four_items() {
        let backend = TestBackend::new(80, 20);
        let mut term = Terminal::new(backend).expect("test terminal");
        term.draw(|frame| {
            let area = frame.area();
            draw_menu(
                frame,
                area,
                "Devices & Origins",
                &[
                    "Device Registry",
                    "Managed Origins",
                    "Scan & Register USB",
                    "Disk Registry",
                ],
                3,
            );
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let s: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(s.contains("Scan & Register USB"), "3rd item missing: {s}");
        assert!(s.contains("Disk Registry"), "4th item missing: {s}");
    }
}

#[cfg(test)]
mod device_list_render_tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use serde_json::json;

    #[test]
    fn draw_device_list_empty_shows_message() {
        let backend = TestBackend::new(120, 20);
        let mut term = Terminal::new(backend).expect("test terminal");
        term.draw(|frame| {
            let area = frame.area();
            draw_device_list(frame, area, &[], 0);
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let s: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(
            s.contains("Device Registry (0)"),
            "empty title missing: {s}"
        );
        assert!(
            s.contains("No devices registered."),
            "empty message missing: {s}"
        );
        assert!(s.contains("r: Register"), "register hint missing: {s}");
        assert!(s.contains("Esc: Back"), "esc hint missing: {s}");
    }

    #[test]
    fn draw_device_list_with_owner_shows_username() {
        let backend = TestBackend::new(120, 20);
        let mut term = Terminal::new(backend).expect("test terminal");
        let devices = vec![json!({
            "id": "uuid-1",
            "vid": "0951",
            "pid": "1666",
            "serial": "SN1234",
            "description": "Kingston USB",
            "trust_tier": "read_only",
            "owner_sid": "S-1-5-21-1",
            "owner_user": "alice"
        })];
        term.draw(|frame| {
            let area = frame.area();
            draw_device_list(frame, area, &devices, 0);
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let s: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(
            s.contains("Device Registry (1)"),
            "title count missing: {s}"
        );
        assert!(s.contains("VID"), "header VID missing: {s}");
        assert!(s.contains("PID"), "header PID missing: {s}");
        assert!(s.contains("Serial"), "header Serial missing: {s}");
        assert!(s.contains("Owner"), "header Owner missing: {s}");
        assert!(s.contains("Tier"), "header Tier missing: {s}");
        assert!(s.contains("Description"), "header Description missing: {s}");
        assert!(s.contains("0951"), "row vid missing: {s}");
        assert!(s.contains("1666"), "row pid missing: {s}");
        assert!(s.contains("SN1234"), "row serial missing: {s}");
        assert!(s.contains("alice"), "row owner_user missing: {s}");
        assert!(s.contains("READ_ONLY"), "row tier missing: {s}");
    }

    #[test]
    fn draw_device_list_machine_wide_shows_all_users() {
        let backend = TestBackend::new(120, 20);
        let mut term = Terminal::new(backend).expect("test terminal");
        let devices = vec![json!({
            "id": "uuid-1",
            "vid": "0951",
            "pid": "1666",
            "serial": "SN1234",
            "description": "Kingston USB",
            "trust_tier": "full_access",
            "owner_sid": null,
            "owner_user": null
        })];
        term.draw(|frame| {
            let area = frame.area();
            draw_device_list(frame, area, &devices, 0);
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let s: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(
            s.contains("(all users)"),
            "machine-wide owner label missing: {s}"
        );
        assert!(s.contains("FULL_ACCESS"), "row tier missing: {s}");
    }

    #[test]
    fn draw_device_list_mixed_renders_correctly() {
        let backend = TestBackend::new(120, 20);
        let mut term = Terminal::new(backend).expect("test terminal");
        let devices = vec![
            json!({
                "id": "uuid-1",
                "vid": "0951",
                "pid": "1666",
                "serial": "SN1",
                "description": "Machine-wide device",
                "trust_tier": "blocked",
                "owner_sid": null,
                "owner_user": null
            }),
            json!({
                "id": "uuid-2",
                "vid": "05ac",
                "pid": "12a8",
                "serial": "SN2",
                "description": "Alice's device",
                "trust_tier": "read_only",
                "owner_sid": "S-1-5-21-1",
                "owner_user": "alice"
            }),
        ];
        term.draw(|frame| {
            let area = frame.area();
            draw_device_list(frame, area, &devices, 0);
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let s: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(
            s.contains("Device Registry (2)"),
            "title count missing: {s}"
        );
        assert!(s.contains("(all users)"), "machine-wide label missing: {s}");
        assert!(s.contains("alice"), "per-user owner missing: {s}");
        assert!(s.contains("BLOCKED"), "blocked tier missing: {s}");
        assert!(s.contains("READ_ONLY"), "read_only tier missing: {s}");
    }

    #[test]
    fn draw_device_list_sid_only_truncates_long_sid() {
        let backend = TestBackend::new(120, 20);
        let mut term = Terminal::new(backend).expect("test terminal");
        let long_sid = "S-1-5-21-1234567890-1234567890-1234567890-1234";
        let devices = vec![json!({
            "id": "uuid-1",
            "vid": "0951",
            "pid": "1666",
            "serial": "SN1",
            "description": "SID-only device",
            "trust_tier": "blocked",
            "owner_sid": long_sid,
            "owner_user": null
        })];
        term.draw(|frame| {
            let area = frame.area();
            draw_device_list(frame, area, &devices, 0);
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let s: String = buf.content().iter().map(|c| c.symbol()).collect();
        // Long SIDs are truncated (T-38.4-11 mitigation).
        // The full SID is not present; a truncated prefix is shown instead.
        assert!(
            !s.contains(long_sid),
            "full long SID should not appear in output: {s}"
        );
        assert!(
            s.contains("S-1-5-21-12345678"),
            "truncated SID prefix should appear: {s}"
        );
    }
}

// ---------------------------------------------------------------------------
// Approval workflow render functions (Phase 61)
// ---------------------------------------------------------------------------

/// Draws the ApprovalList screen.
///
/// Renders a scrollable table with columns: Requester, Object, Action, Status, Expires.
/// Shows pagination info, filter suffix in title, and status colors per UI-SPEC.
#[allow(clippy::too_many_arguments)]
fn draw_approval_list(
    frame: &mut Frame,
    area: Rect,
    approvals: &[serde_json::Value],
    selected: usize,
    filter: ApprovalFilter,
    page: u32,
    per_page: u32,
    total: i64,
) {
    if approvals.is_empty() {
        let filter_suffix = if filter != ApprovalFilter::All {
            format!(" [{}]", filter.as_str().unwrap_or(""))
        } else {
            String::new()
        };
        let paragraph = Paragraph::new(APPROVAL_LIST_EMPTY)
            .block(
                Block::default()
                    .title(format!(
                        " Approval Management (0){filter_suffix} — Page {page} "
                    ))
                    .borders(Borders::ALL),
            )
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(paragraph, area);
        draw_hints(frame, area, APPROVAL_LIST_HINTS);
        return;
    }

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
    let total_pages = total_pages.max(1);

    let filter_suffix = if filter != ApprovalFilter::All {
        format!(" [{}]", filter.as_str().unwrap_or(""))
    } else {
        String::new()
    };

    let header = Row::new(vec!["Requester", "Object", "Action", "Status", "Expires"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = approvals
        .iter()
        .map(|resp| {
            let approval = resp.get("approval").and_then(|a| a.as_object());
            let requester = approval
                .and_then(|a| a.get("requester_sid"))
                .and_then(|s| s.as_str())
                .unwrap_or("-");
            let object = approval
                .and_then(|a| a.get("data_object_id"))
                .and_then(|s| s.as_str())
                .unwrap_or("-");
            let action = approval
                .and_then(|a| a.get("allowed_action"))
                .and_then(|s| s.as_str())
                .unwrap_or("-");
            let status = approval
                .and_then(|a| a.get("status"))
                .and_then(|s| s.as_str())
                .unwrap_or("-");
            let expires = approval
                .and_then(|a| a.get("valid_until"))
                .and_then(|s| s.as_str())
                .unwrap_or("—");

            let status_style = match status {
                "pending" => Style::default().fg(Color::Yellow),
                "approved" => Style::default().fg(Color::Green),
                "rejected" => Style::default().fg(Color::Red),
                "revoked" => Style::default().fg(Color::DarkGray),
                "expired" => Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::CROSSED_OUT),
                _ => Style::default(),
            };

            let tier = resp.get("tier").and_then(|t| t.as_str());
            let t4_badge = if tier == Some("T4") { " [T4]" } else { "" };
            let status_text = format!("{status}{t4_badge}");

            let cells = vec![
                Cell::from(requester.to_string()),
                Cell::from(object.to_string()),
                Cell::from(action.to_string()),
                Cell::from(status_text).style(status_style),
                Cell::from(expires.to_string()),
            ];

            Row::new(cells)
        })
        .collect();

    let widths = [
        Constraint::Percentage(20), // Requester
        Constraint::Percentage(25), // Object
        Constraint::Percentage(15), // Action
        Constraint::Percentage(20), // Status
        Constraint::Percentage(20), // Expires
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(
                    " Approval Management ({total}){filter_suffix} — Page {page} of {total_pages} "
                ))
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

    draw_hints(frame, area, APPROVAL_LIST_HINTS);
}

/// Draws the ApprovalDetail read-only view.
///
/// Shows all approval fields plus T4 canonical message for board member copy-paste.
fn draw_approval_detail(frame: &mut Frame, area: Rect, detail: &serde_json::Value) {
    let approval = detail.get("approval").and_then(|a| a.as_object());

    let id = approval
        .and_then(|a| a.get("id"))
        .and_then(|s| s.as_str())
        .unwrap_or("-");
    let requester = approval
        .and_then(|a| a.get("requester_sid"))
        .and_then(|s| s.as_str())
        .unwrap_or("-");
    let approver = approval
        .and_then(|a| a.get("approver_sid"))
        .and_then(|s| s.as_str())
        .unwrap_or("—");
    let object = approval
        .and_then(|a| a.get("data_object_id"))
        .and_then(|s| s.as_str())
        .unwrap_or("-");
    let action = approval
        .and_then(|a| a.get("allowed_action"))
        .and_then(|s| s.as_str())
        .unwrap_or("-");
    let destination = approval
        .and_then(|a| a.get("destination_scope"))
        .and_then(|s| s.as_str())
        .unwrap_or("Any");
    let status = approval
        .and_then(|a| a.get("status"))
        .and_then(|s| s.as_str())
        .unwrap_or("-");
    let justification = approval
        .and_then(|a| a.get("justification"))
        .and_then(|s| s.as_str())
        .unwrap_or("-");
    let created = approval
        .and_then(|a| a.get("created_at"))
        .and_then(|s| s.as_str())
        .unwrap_or("-");
    let updated = approval
        .and_then(|a| a.get("updated_at"))
        .and_then(|s| s.as_str())
        .unwrap_or("-");

    let tier = detail.get("tier").and_then(|t| t.as_str()).unwrap_or("—");

    let mut body = format!(
        "ID:           {id}\n\
         Requester:    {requester}\n\
         Approver:     {approver}\n\
         Object:       {object}\n\
         Action:       {action}\n\
         Destination:  {destination}\n\
         Status:       {status}\n\
         Tier:         {tier}\n\
         Justification: {justification}\n\
         Created:      {created}\n\
         Updated:      {updated}"
    );

    // Display T4 canonical message for board member copy-paste
    if let Some(msg) = detail.get("t4_canonical_message").and_then(|m| m.as_str()) {
        body.push_str("\n\n");
        body.push_str("T4 CANONICAL MESSAGE (copy for signing):\n");
        body.push_str(msg);
    }

    draw_result(frame, area, "Approval Detail", &body);
}

/// Draws the ApprovalGrant form.
///
/// Shows read-only request info and editable expiry picker + T4 signature input.
#[allow(clippy::too_many_arguments)]
fn draw_approval_grant(
    frame: &mut Frame,
    area: Rect,
    _approval_id: &str,
    requester_sid: &str,
    object_path: &str,
    action: &str,
    destination: Option<&str>,
    tier: Option<&str>,
    expiry_hours: u32,
    signature_hex: &str,
    selected_field: usize,
) {
    let is_t4 = tier == Some("T4");

    let mut items: Vec<ListItem> = Vec::with_capacity(12);

    items.push(ListItem::new(Line::styled(
        "Grant Approval",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    items.push(ListItem::new(Line::raw("")));

    // Read-only request info
    items.push(ListItem::new(Line::from(format!(
        "Requester: {requester_sid}"
    ))));
    items.push(ListItem::new(Line::from(format!(
        "Object:    {object_path}"
    ))));
    items.push(ListItem::new(Line::from(format!("Action:    {action}"))));
    items.push(ListItem::new(Line::from(format!(
        "Destination: {}",
        destination.unwrap_or("—")
    ))));

    if is_t4 {
        items.push(ListItem::new(Line::raw("")));
        items.push(ListItem::new(Line::styled(
            "T4 REQUIREMENT: Board signature required",
            Style::default().fg(Color::Yellow),
        )));
    }

    items.push(ListItem::new(Line::raw("")));

    // Expiry picker
    let expiry_label = EXPIRY_OPTIONS
        .iter()
        .find(|(h, _)| *h == expiry_hours)
        .map(|(_, label)| *label)
        .unwrap_or("Custom");
    let expiry_selected = selected_field == 0;
    items.push(ListItem::new(Line::from(format!(
        "{} Expiry:     {}",
        if expiry_selected { ">" } else { " " },
        expiry_label
    ))));

    // T4 signature input (only for T4)
    if is_t4 {
        let sig_selected = selected_field == 1;
        let sig_display = if signature_hex.is_empty() {
            "[paste hex signature]"
        } else {
            signature_hex
        };
        items.push(ListItem::new(Line::from(format!(
            "{} Signature:  {}",
            if sig_selected { ">" } else { " " },
            sig_display
        ))));
    }

    items.push(ListItem::new(Line::raw("")));
    items.push(ListItem::new(Line::styled(
        "[Enter] Grant  [Esc] Cancel",
        Style::default().fg(Color::DarkGray),
    )));

    let list = List::new(items).block(
        Block::default()
            .title(" Grant Approval ")
            .borders(Borders::ALL),
    );

    frame.render_widget(list, area);

    draw_hints(frame, area, APPROVAL_GRANT_HINTS);
}

/// Draws the Protected Path List screen as a scrollable table.
///
/// Columns: Source (badge), Path, Tier, Label ID.
fn draw_protected_path_list(
    frame: &mut Frame,
    area: Rect,
    paths: &[serde_json::Value],
    selected: usize,
    page: usize,
    page_size: usize,
    total: usize,
) {
    if paths.is_empty() {
        let paragraph = Paragraph::new(PROTECTED_PATH_LIST_EMPTY)
            .block(
                Block::default()
                    .title(" Protected Paths (0) ")
                    .borders(Borders::ALL),
            )
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(paragraph, area);
        draw_hints(frame, area, PROTECTED_PATH_LIST_HINTS);
        return;
    }

    let total_pages = total.div_ceil(page_size).max(1);
    let page_info = format!(
        "Page {} of {} | {} per page",
        page + 1,
        total_pages,
        page_size
    );

    let header = Row::new(vec!["Source", "Path", "Tier", "Label ID"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = paths
        .iter()
        .map(|p| {
            let source = p["source"].as_str().unwrap_or("-");
            let source_badge = match source {
                "auto" => ("[A]", Style::default().fg(Color::DarkGray)),
                "manual" => ("[M]", Style::default().fg(Color::Cyan)),
                _ => ("[?]", Style::default()),
            };
            let path = p["path"].as_str().unwrap_or("-");
            let path_display = if path.len() > 40 {
                format!("{}...", &path[..37])
            } else {
                path.to_string()
            };
            let tier = p["tier"].as_str().unwrap_or("-");
            let tier_style = match tier {
                "T3" => Style::default().fg(Color::Yellow),
                "T4" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                _ => Style::default(),
            };
            let label_id = p["label_id"].as_str().unwrap_or("-");

            Row::new(vec![
                Cell::from(source_badge.0.to_string()).style(source_badge.1),
                Cell::from(path_display),
                Cell::from(tier.to_string()).style(tier_style),
                Cell::from(label_id.to_string()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(8),      // Source badge [A]/[M]
        Constraint::Percentage(45), // Path
        Constraint::Percentage(10), // Tier
        Constraint::Min(20),        // Label ID (remaining)
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" Protected Paths ({}) ", total))
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

    let hint_text = format!("{PROTECTED_PATH_LIST_HINTS}  |  {page_info}");
    draw_hints(frame, area, &hint_text);
}

#[cfg(test)]
mod protected_path_render_tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn draw_protected_path_list_empty_renders() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                draw_protected_path_list(frame, frame.area(), &[], 0, 0, 20, 0);
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let content: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert!(content.contains("No protected paths configured"));
    }

    #[test]
    fn draw_protected_path_list_renders_source_badge() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let paths = vec![serde_json::json!({
            "id": "1",
            "path": "C:\\Test",
            "source": "manual",
            "tier": "T3",
            "label_id": null
        })];
        terminal
            .draw(|frame| {
                draw_protected_path_list(frame, frame.area(), &paths, 0, 0, 20, 1);
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let content: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert!(content.contains("[M]"), "manual badge missing: {content}");
        assert!(content.contains("C:\\Test"), "path missing: {content}");
    }

    #[test]
    fn draw_protected_path_list_auto_badge_renders() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let paths = vec![serde_json::json!({
            "id": "2",
            "path": "C:\\AutoPath",
            "source": "auto",
            "tier": "T4",
            "label_id": "label-1"
        })];
        terminal
            .draw(|frame| {
                draw_protected_path_list(frame, frame.area(), &paths, 0, 0, 20, 1);
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let content: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert!(content.contains("[A]"), "auto badge missing: {content}");
        assert!(content.contains("label-1"), "label_id missing: {content}");
    }

    #[test]
    fn draw_protected_path_list_truncates_long_path() {
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let long_path = "C:\\\\".to_string() + &"A".repeat(50);
        let paths = vec![serde_json::json!({
            "id": "3",
            "path": long_path,
            "source": "manual",
            "tier": "T3",
            "label_id": null
        })];
        terminal
            .draw(|frame| {
                draw_protected_path_list(frame, frame.area(), &paths, 0, 0, 20, 1);
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let content: String = buf.content.iter().map(|c| c.symbol()).collect();
        // Should contain truncated path with ... suffix
        assert!(content.contains("..."), "truncation missing: {content}");
    }

    #[test]
    fn draw_protected_path_list_shows_page_info() {
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let paths = vec![serde_json::json!({
            "id": "1",
            "path": "C:\\Test",
            "source": "manual",
            "tier": "T3",
            "label_id": null
        })];
        terminal
            .draw(|frame| {
                draw_protected_path_list(frame, frame.area(), &paths, 0, 0, 20, 1);
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let content: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert!(
            content.contains("Page 1 of 1"),
            "page info missing: {content}"
        );
    }
}

/// Formats an ISO-8601 timestamp as a simple relative time string.
///
/// Uses coarse buckets: "<1m", "Xm", "Xh", "Xd" for recent times,
/// falls back to the raw timestamp for older entries.
fn format_relative_time(iso_timestamp: &str) -> String {
    use chrono::{DateTime, Utc};
    if let Ok(dt) = iso_timestamp.parse::<DateTime<Utc>>() {
        let now = Utc::now();
        let duration = now.signed_duration_since(dt);
        let mins = duration.num_minutes();
        let hours = duration.num_hours();
        let days = duration.num_days();
        if mins < 1 {
            "<1m".to_string()
        } else if mins < 60 {
            format!("{mins}m")
        } else if hours < 24 {
            format!("{hours}h")
        } else if days < 30 {
            format!("{days}d")
        } else {
            iso_timestamp.to_string()
        }
    } else {
        iso_timestamp.to_string()
    }
}

/// Renders the bypass alert list screen.
///
/// Columns: Severity (colored badge), Time (relative), Image Path (truncated),
/// File Path (truncated), Correlation Reason (human-friendly).
/// Acknowledged rows are dimmed with DarkGray foreground.
fn draw_bypass_alert_list(
    frame: &mut Frame,
    area: Rect,
    alerts: &[serde_json::Value],
    selected: usize,
    filter: BypassAlertSeverityFilter,
    hide_acknowledged: bool,
    page: usize,
    page_size: usize,
    total: usize,
) {
    if alerts.is_empty() {
        let filter_suffix = if filter != BypassAlertSeverityFilter::All {
            format!(" [Severity: {}]", filter.as_str().unwrap_or(""))
        } else {
            String::new()
        };
        let ack_suffix = if hide_acknowledged { " [Hide Ack'd]" } else { "" };
        let paragraph = Paragraph::new(BYPASS_ALERT_LIST_EMPTY)
            .block(
                Block::default()
                    .title(format!(
                        " Bypass Alerts (0){filter_suffix}{ack_suffix} "
                    ))
                    .borders(Borders::ALL),
            )
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(paragraph, area);
        draw_hints(frame, area, BYPASS_ALERT_LIST_HINTS);
        return;
    }

    let filter_suffix = if filter != BypassAlertSeverityFilter::All {
        format!(" [Severity: {}]", filter.as_str().unwrap_or(""))
    } else {
        String::new()
    };
    let ack_suffix = if hide_acknowledged { " [Hide Ack'd]" } else { "" };

    let total_pages = total.div_ceil(page_size).max(1);
    let page_info = format!("Page {} of {} ({} total)", page + 1, total_pages, total);

    let header = Row::new(vec!["Severity", "Time", "Image", "File", "Reason"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = alerts
        .iter()
        .map(|a| {
            let severity = a["severity"].as_str().unwrap_or("-");
            let acked = a["acknowledged"].as_bool().unwrap_or(false);
            let severity_style = match severity {
                "crit" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                "warn" => Style::default().fg(Color::Yellow),
                "info" => Style::default().fg(Color::Blue),
                _ => Style::default(),
            };

            // Simple relative time formatting
            let time = a["created_at"].as_str().unwrap_or("-");
            let time_display = format_relative_time(time);

            let image = a["image_path"].as_str().unwrap_or("-");
            let image_display = if image.len() > 25 {
                format!("{}...", &image[..22])
            } else {
                image.to_string()
            };

            let file = a["file_path"].as_str().unwrap_or("-");
            let file_display = if file.len() > 25 {
                format!("{}...", &file[..22])
            } else {
                file.to_string()
            };

            let reason = a["correlation_reason"].as_str().unwrap_or("-");
            let reason_display = match reason {
                "no_hook_journal" | "NoHookJournal" => "No Hook Journal",
                "op_mismatch" | "OpMismatch" => "Operation Mismatch",
                "hook_overwritten" | "HookOverwritten" => "Hook Overwritten",
                _ => reason,
            };

            let row_style = if acked {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(severity.to_string()).style(severity_style),
                Cell::from(time_display),
                Cell::from(image_display),
                Cell::from(file_display),
                Cell::from(reason_display.to_string()),
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Percentage(10),  // Severity
        Constraint::Percentage(12),  // Time
        Constraint::Percentage(28),  // Image Path
        Constraint::Percentage(28),  // File Path
        Constraint::Percentage(22),  // Reason
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(
                    " Bypass Alerts ({}){}{} ",
                    total, filter_suffix, ack_suffix
                ))
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

    let hint_text = format!("{BYPASS_ALERT_LIST_HINTS}  |  {page_info}");
    draw_hints(frame, area, &hint_text);
}

/// Renders the bypass alert detail popup.
///
/// Shows all fields from the alert JSON: id, severity, correlation_reason,
/// image_path, image_sha256, file_path, operation, timestamp, file_object,
/// pid, acknowledged, created_at.
fn draw_bypass_alert_detail(
    frame: &mut Frame,
    area: Rect,
    alert: &serde_json::Value,
) {
    let id = alert["id"].as_i64().unwrap_or(0);
    let severity = alert["severity"].as_str().unwrap_or("-");
    let reason = alert["correlation_reason"].as_str().unwrap_or("-");
    let reason_display = match reason {
        "no_hook_journal" | "NoHookJournal" => "No Hook Journal",
        "op_mismatch" | "OpMismatch" => "Operation Mismatch",
        "hook_overwritten" | "HookOverwritten" => "Hook Overwritten",
        _ => reason,
    };
    let image_path = alert["image_path"].as_str().unwrap_or("-");
    let image_sha256 = alert["image_sha256"].as_str().unwrap_or("-");
    let sha_display = if image_sha256.len() > 16 {
        format!("{}...", &image_sha256[..16])
    } else {
        image_sha256.to_string()
    };
    let file_path = alert["file_path"].as_str().unwrap_or("-");
    let operation = alert["operation"].as_str().unwrap_or("-");
    let timestamp = alert["timestamp"].as_str().unwrap_or("-");
    let file_object = alert["file_object"].as_str().unwrap_or("-");
    let pid = alert["pid"].as_i64().unwrap_or(0);
    let acknowledged = alert["acknowledged"].as_bool().unwrap_or(false);
    let created_at = alert["created_at"].as_str().unwrap_or("-");

    let severity_style = match severity {
        "crit" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        "warn" => Style::default().fg(Color::Yellow),
        "info" => Style::default().fg(Color::Blue),
        _ => Style::default(),
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("ID: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("{id}")),
        ]),
        Line::from(vec![
            Span::styled("Severity: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(severity.to_string(), severity_style),
        ]),
        Line::from(vec![
            Span::styled("Reason: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(reason_display.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Image Path: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(image_path.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Image SHA-256: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(sha_display),
        ]),
        Line::from(vec![
            Span::styled("File Path: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(file_path.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Operation: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(operation.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Timestamp: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(timestamp.to_string()),
        ]),
        Line::from(vec![
            Span::styled("File Object: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(file_object.to_string()),
        ]),
        Line::from(vec![
            Span::styled("PID: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("{pid}")),
        ]),
        Line::from(vec![
            Span::styled("Acknowledged: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("{acknowledged}")),
        ]),
        Line::from(vec![
            Span::styled("Created At: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(created_at.to_string()),
        ]),
    ];

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(format!(" Bypass Alert Detail (ID: {id}) "))
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
    draw_hints(frame, area, BYPASS_ALERT_DETAIL_HINTS);
}

#[cfg(test)]
mod bypass_alert_render_tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn draw_bypass_alert_list_empty_renders() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                draw_bypass_alert_list(
                    frame,
                    frame.area(),
                    &[],
                    0,
                    crate::app::BypassAlertSeverityFilter::All,
                    false,
                    0,
                    20,
                    0,
                );
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let content: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert!(content.contains("No bypass alerts found"));
    }

    #[test]
    fn draw_bypass_alert_list_renders_severity_badge() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let alerts = vec![serde_json::json!({
            "id": 1,
            "severity": "crit",
            "image_path": "C:\\\\Windows\\\\notepad.exe",
            "file_path": "C:\\\\Secret.doc",
            "correlation_reason": "NoHookJournal",
            "created_at": "2026-05-28T10:00:00Z",
            "acknowledged": false,
        })];
        terminal
            .draw(|frame| {
                draw_bypass_alert_list(
                    frame,
                    frame.area(),
                    &alerts,
                    0,
                    crate::app::BypassAlertSeverityFilter::All,
                    false,
                    0,
                    20,
                    1,
                );
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let content: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert!(content.contains("crit"), "severity badge missing: {content}");
        assert!(
            content.contains("No Hook Journal"),
            "reason display missing: {content}"
        );
    }

    #[test]
    fn draw_bypass_alert_list_acknowledged_row_dimmed() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let alerts = vec![serde_json::json!({
            "id": 1,
            "severity": "warn",
            "image_path": "C:\\\\Windows\\\\notepad.exe",
            "file_path": "C:\\\\Secret.doc",
            "correlation_reason": "OpMismatch",
            "created_at": "2026-05-28T10:00:00Z",
            "acknowledged": true,
        })];
        terminal
            .draw(|frame| {
                draw_bypass_alert_list(
                    frame,
                    frame.area(),
                    &alerts,
                    0,
                    crate::app::BypassAlertSeverityFilter::All,
                    false,
                    0,
                    20,
                    1,
                );
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let content: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert!(content.contains("warn"), "severity badge missing: {content}");
    }

    #[test]
    fn draw_bypass_alert_detail_renders_fields() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let alert = serde_json::json!({
            "id": 42,
            "severity": "crit",
            "correlation_reason": "HookOverwritten",
            "image_path": "C:\\\\Windows\\\\System32\\\\notepad.exe",
            "image_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "file_path": "C:\\\\Secret.doc",
            "operation": "WriteFile",
            "timestamp": "2026-05-28T10:00:00Z",
            "file_object": "0x00007FF6AABBCCDD",
            "pid": 1234,
            "acknowledged": false,
            "created_at": "2026-05-28T10:00:00Z",
        });
        terminal
            .draw(|frame| {
                draw_bypass_alert_detail(frame, frame.area(), &alert);
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let content: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert!(content.contains("ID: 42"), "id missing: {content}");
        assert!(content.contains("crit"), "severity missing: {content}");
        assert!(
            content.contains("Hook Overwritten"),
            "reason missing: {content}"
        );
        assert!(
            content.contains("abcdef1234567890"),
            "sha missing: {content}"
        );
        assert!(
            content.contains("0x00007FF6AABBCCDD"),
            "file_object missing: {content}"
        );
    }

    #[test]
    fn format_relative_time_recent() {
        use chrono::Utc;
        let now = Utc::now().to_rfc3339();
        let result = format_relative_time(&now);
        assert_eq!(result, "<1m", "recent timestamp should show <1m: got {result}");
    }

    #[test]
    fn format_relative_time_invalid() {
        let result = format_relative_time("not-a-timestamp");
        assert_eq!(result, "not-a-timestamp");
    }
}

#[cfg(test)]
mod disk_registry_render_tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use serde_json::json;

    #[test]
    fn draw_disk_registry_list_empty() {
        let backend = TestBackend::new(120, 20);
        let mut term = Terminal::new(backend).expect("test terminal");
        term.draw(|frame| {
            let area = frame.area();
            draw_disk_registry_list(frame, area, &[], 0);
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let s: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(s.contains("Disk Registry (0)"), "empty title missing: {s}");
        assert!(
            s.contains("No disk registry entries."),
            "empty message missing: {s}"
        );
        assert!(s.contains("a: Add"), "add hint missing: {s}");
        assert!(s.contains("Esc: Back"), "esc hint missing: {s}");
    }

    #[test]
    fn draw_disk_registry_list_nonempty() {
        let backend = TestBackend::new(120, 20);
        let mut term = Terminal::new(backend).expect("test terminal");
        let disks = vec![
            json!({
                "id": "uuid-1",
                "agent_id": "agent-001",
                "instance_id": "disk-xyz",
                "bus_type": "NVMe",
                "encryption_status": "encrypted",
                "model": "Samsung 980 Pro"
            }),
            json!({
                "id": "uuid-2",
                "agent_id": "agent-002",
                "instance_id": "disk-abc",
                "bus_type": "SATA",
                "encryption_status": "none",
                "model": "WD Blue"
            }),
        ];
        term.draw(|frame| {
            let area = frame.area();
            draw_disk_registry_list(frame, area, &disks, 0);
        })
        .expect("draw");
        let buf = term.backend().buffer().clone();
        let s: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(s.contains("Disk Registry (2)"), "title count missing: {s}");
        assert!(s.contains("Agent ID"), "header Agent ID missing: {s}");
        assert!(s.contains("Instance ID"), "header Instance ID missing: {s}");
        assert!(s.contains("Bus Type"), "header Bus Type missing: {s}");
        assert!(s.contains("Encrypted"), "header Encrypted missing: {s}");
        assert!(s.contains("Model"), "header Model missing: {s}");
        assert!(s.contains("agent-001"), "row agent_id missing: {s}");
        assert!(s.contains("disk-xyz"), "row instance_id missing: {s}");
        assert!(s.contains("NVMe"), "row bus_type missing: {s}");
        assert!(s.contains("encrypted"), "row encryption missing: {s}");
        assert!(s.contains("a: Add"), "add hint missing: {s}");
        assert!(s.contains("d: Delete"), "delete hint missing: {s}");
    }
}
