//! Renders the current [`Screen`] to the terminal frame.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table, Wrap,
};
use ratatui::Frame;

use crate::app::{App, Screen, StatusKind};

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
        // Plan 02 will replace this stub with the full draw_conditions_builder implementation.
        Screen::ConditionsBuilder { .. } => {
            let block = ratatui::widgets::Block::default()
                .title(" Conditions Builder ")
                .borders(ratatui::widgets::Borders::ALL);
            frame.render_widget(block, area);
        }
    }
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
