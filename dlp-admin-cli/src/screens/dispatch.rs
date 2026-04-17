//! Key-event dispatch for each [`Screen`] variant.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use crate::app::{
    App, CallerScreen, ConditionAttribute, ConfirmPurpose, InputPurpose, PasswordPurpose,
    PolicyFormState, Screen, StatusKind, ACTION_OPTIONS, ATTRIBUTES,
};
use crate::event::AppEvent;

/// Routes an event to the handler for the current screen.
pub fn handle_event(app: &mut App, event: AppEvent) {
    let key = match event {
        AppEvent::Key(k) if k.kind == KeyEventKind::Press => k,
        _ => return,
    };

    match &app.screen {
        Screen::MainMenu { .. } => handle_main_menu(app, key),
        Screen::PasswordMenu { .. } => handle_password_menu(app, key),
        Screen::PolicyMenu { .. } => handle_policy_menu(app, key),
        Screen::SystemMenu { .. } => handle_system_menu(app, key),
        Screen::PolicyList { .. } => handle_policy_list(app, key),
        Screen::AgentList { .. } => handle_agent_list(app, key),
        Screen::TextInput { .. } => handle_text_input(app, key),
        Screen::PasswordInput { .. } => handle_password_input(app, key),
        Screen::Confirm { .. } => handle_confirm(app, key),
        Screen::SiemConfig { .. } => handle_siem_config(app, key),
        Screen::AlertConfig { .. } => handle_alert_config(app, key),
        Screen::ConditionsBuilder { .. } => handle_conditions_builder(app, key),
        Screen::PolicyCreate { .. } => handle_policy_create(app, key),
        // Read-only views: Enter or Esc goes back.
        Screen::PolicyDetail { .. } | Screen::ServerStatus { .. } | Screen::ResultView { .. } => {
            handle_view(app, key)
        }
    }
}

// ---------------------------------------------------------------------------
// Menu helpers
// ---------------------------------------------------------------------------

/// Moves a selection index up/down within a menu of `count` items.
fn nav(selected: &mut usize, count: usize, key: KeyCode) {
    match key {
        KeyCode::Up => {
            *selected = selected.checked_sub(1).unwrap_or(count - 1);
        }
        KeyCode::Down => {
            *selected = (*selected + 1) % count;
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Main menu
// ---------------------------------------------------------------------------

fn handle_main_menu(app: &mut App, key: KeyEvent) {
    let selected = match &mut app.screen {
        Screen::MainMenu { selected } => selected,
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => nav(selected, 4, key.code),
        KeyCode::Enter => match *selected {
            0 => app.screen = Screen::PasswordMenu { selected: 0 },
            1 => app.screen = Screen::PolicyMenu { selected: 0 },
            2 => app.screen = Screen::SystemMenu { selected: 0 },
            3 => app.should_quit = true,
            _ => {}
        },
        KeyCode::Esc | KeyCode::Char('q') => app.should_quit = true,
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Password menu
// ---------------------------------------------------------------------------

fn handle_password_menu(app: &mut App, key: KeyEvent) {
    let selected = match &mut app.screen {
        Screen::PasswordMenu { selected } => selected,
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => nav(selected, 4, key.code),
        KeyCode::Enter => match *selected {
            0 => {
                app.screen = Screen::PasswordInput {
                    prompt: "Current admin password".to_string(),
                    input: String::new(),
                    purpose: PasswordPurpose::ChangeAdminPasswordCurrent,
                };
            }
            1 => {
                app.screen = Screen::PasswordInput {
                    prompt: "New agent password".to_string(),
                    input: String::new(),
                    purpose: PasswordPurpose::SetAgentPasswordNew,
                };
            }
            2 => {
                app.screen = Screen::PasswordInput {
                    prompt: "Enter agent password to verify".to_string(),
                    input: String::new(),
                    purpose: PasswordPurpose::VerifyAgentPassword,
                };
            }
            3 => app.screen = Screen::MainMenu { selected: 0 },
            _ => {}
        },
        KeyCode::Esc => app.screen = Screen::MainMenu { selected: 0 },
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Policy menu
// ---------------------------------------------------------------------------

fn handle_policy_menu(app: &mut App, key: KeyEvent) {
    let selected = match &mut app.screen {
        Screen::PolicyMenu { selected } => selected,
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => nav(selected, 6, key.code),
        KeyCode::Enter => match *selected {
            0 => action_list_policies(app),
            1 => {
                app.screen = Screen::TextInput {
                    prompt: "Policy ID".to_string(),
                    input: String::new(),
                    purpose: InputPurpose::GetPolicyById,
                };
            }
            2 => {
                app.screen = Screen::PolicyCreate {
                    form: PolicyFormState::default(),
                    selected: 0,
                    editing: false,
                    buffer: String::new(),
                    validation_error: None,
                };
            }
            3 => {
                app.screen = Screen::TextInput {
                    prompt: "Policy ID to update".to_string(),
                    input: String::new(),
                    purpose: InputPurpose::UpdatePolicyId,
                };
            }
            4 => {
                app.screen = Screen::TextInput {
                    prompt: "Policy ID to delete".to_string(),
                    input: String::new(),
                    purpose: InputPurpose::DeletePolicyId,
                };
            }
            5 => app.screen = Screen::MainMenu { selected: 1 },
            _ => {}
        },
        KeyCode::Esc => app.screen = Screen::MainMenu { selected: 1 },
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// System menu
// ---------------------------------------------------------------------------

fn handle_system_menu(app: &mut App, key: KeyEvent) {
    let selected = match &mut app.screen {
        Screen::SystemMenu { selected } => selected,
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => nav(selected, 5, key.code),
        KeyCode::Enter => match *selected {
            0 => action_server_status(app),
            1 => action_agent_list(app),
            2 => action_load_siem_config(app),
            3 => action_load_alert_config(app),
            4 => app.screen = Screen::MainMenu { selected: 2 },
            _ => {}
        },
        KeyCode::Esc => app.screen = Screen::MainMenu { selected: 2 },
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Text input
// ---------------------------------------------------------------------------

fn handle_text_input(app: &mut App, key: KeyEvent) {
    let (input, purpose) = match &mut app.screen {
        Screen::TextInput { input, purpose, .. } => (input, purpose.clone()),
        _ => return,
    };
    match key.code {
        KeyCode::Char(c) => input.push(c),
        KeyCode::Backspace => {
            input.pop();
        }
        KeyCode::Enter => {
            let value = input.clone();
            if value.is_empty() {
                app.set_status("Input cannot be empty", StatusKind::Error);
                return;
            }
            on_text_confirmed(app, &value, purpose);
        }
        KeyCode::Esc => {
            app.screen = Screen::PolicyMenu { selected: 0 };
        }
        _ => {}
    }
}

fn on_text_confirmed(app: &mut App, value: &str, purpose: InputPurpose) {
    match purpose {
        InputPurpose::GetPolicyById => action_get_policy(app, value),
        InputPurpose::CreatePolicyFromFile => action_create_policy(app, value),
        InputPurpose::UpdatePolicyId => {
            app.screen = Screen::TextInput {
                prompt: "JSON file path".to_string(),
                input: String::new(),
                purpose: InputPurpose::UpdatePolicyFile {
                    id: value.to_string(),
                },
            };
        }
        InputPurpose::UpdatePolicyFile { id } => {
            action_update_policy(app, &id, value);
        }
        InputPurpose::DeletePolicyId => {
            app.screen = Screen::Confirm {
                message: format!("Delete policy '{value}'?"),
                yes_selected: false,
                purpose: ConfirmPurpose::DeletePolicy {
                    id: value.to_string(),
                },
            };
        }
    }
}

// ---------------------------------------------------------------------------
// Password input
// ---------------------------------------------------------------------------

fn handle_password_input(app: &mut App, key: KeyEvent) {
    let (input, purpose) = match &mut app.screen {
        Screen::PasswordInput { input, purpose, .. } => (input, purpose.clone()),
        _ => return,
    };
    match key.code {
        KeyCode::Char(c) => input.push(c),
        KeyCode::Backspace => {
            input.pop();
        }
        KeyCode::Enter => {
            let value = input.clone();
            if value.is_empty() {
                app.set_status("Password cannot be empty", StatusKind::Error);
                return;
            }
            on_password_confirmed(app, &value, purpose);
        }
        KeyCode::Esc => {
            app.screen = Screen::PasswordMenu { selected: 0 };
        }
        _ => {}
    }
}

fn on_password_confirmed(app: &mut App, value: &str, purpose: PasswordPurpose) {
    match purpose {
        PasswordPurpose::ChangeAdminPasswordCurrent => {
            app.screen = Screen::PasswordInput {
                prompt: "New admin password".to_string(),
                input: String::new(),
                purpose: PasswordPurpose::ChangeAdminPasswordNew {
                    current: value.to_string(),
                },
            };
        }
        PasswordPurpose::ChangeAdminPasswordNew { current } => {
            app.screen = Screen::PasswordInput {
                prompt: "Confirm new admin password".to_string(),
                input: String::new(),
                purpose: PasswordPurpose::ChangeAdminPasswordConfirm {
                    current,
                    new_pw: value.to_string(),
                },
            };
        }
        PasswordPurpose::ChangeAdminPasswordConfirm { current, new_pw } => {
            if value != new_pw {
                app.set_status("Passwords do not match", StatusKind::Error);
                app.screen = Screen::PasswordMenu { selected: 0 };
                return;
            }
            action_change_admin_password(app, &current, &new_pw);
        }
        PasswordPurpose::SetAgentPasswordNew => {
            app.screen = Screen::PasswordInput {
                prompt: "Confirm agent password".to_string(),
                input: String::new(),
                purpose: PasswordPurpose::SetAgentPasswordConfirm {
                    first: value.to_string(),
                },
            };
        }
        PasswordPurpose::SetAgentPasswordConfirm { first } => {
            if value != first {
                app.set_status("Passwords do not match", StatusKind::Error);
                app.screen = Screen::PasswordMenu { selected: 1 };
                return;
            }
            action_set_agent_password(app, value);
        }
        PasswordPurpose::VerifyAgentPassword => {
            action_verify_agent_password(app, value);
        }
    }
}

// ---------------------------------------------------------------------------
// Confirm dialog
// ---------------------------------------------------------------------------

fn handle_confirm(app: &mut App, key: KeyEvent) {
    let (yes_selected, purpose) = match &mut app.screen {
        Screen::Confirm {
            yes_selected,
            purpose,
            ..
        } => (yes_selected, purpose.clone()),
        _ => return,
    };
    match key.code {
        KeyCode::Left | KeyCode::Right => *yes_selected = !*yes_selected,
        KeyCode::Enter => {
            if *yes_selected {
                match purpose {
                    ConfirmPurpose::DeletePolicy { id } => action_delete_policy(app, &id),
                }
            } else {
                app.screen = Screen::PolicyMenu { selected: 0 };
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::PolicyMenu { selected: 0 };
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Read-only views
// ---------------------------------------------------------------------------

fn handle_view(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter | KeyCode::Esc => {
            // Return to the appropriate parent screen.
            app.screen = match &app.screen {
                Screen::PolicyDetail { .. } => Screen::PolicyMenu { selected: 0 },
                Screen::ServerStatus { .. } => Screen::SystemMenu { selected: 0 },
                _ => Screen::MainMenu { selected: 0 },
            };
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// List views (PolicyList, AgentList)
// ---------------------------------------------------------------------------

fn handle_policy_list(app: &mut App, key: KeyEvent) {
    let (policies, selected) = match &mut app.screen {
        Screen::PolicyList { policies, selected } => (policies.clone(), selected),
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if !policies.is_empty() {
                nav(selected, policies.len(), key.code);
            }
        }
        KeyCode::Enter => {
            if let Some(policy) = policies.get(*selected) {
                app.screen = Screen::PolicyDetail {
                    policy: policy.clone(),
                };
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::PolicyMenu { selected: 0 };
        }
        _ => {}
    }
}

fn handle_agent_list(app: &mut App, key: KeyEvent) {
    let (agents, selected) = match &mut app.screen {
        Screen::AgentList { agents, selected } => (agents.clone(), selected),
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if !agents.is_empty() {
                nav(selected, agents.len(), key.code);
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::SystemMenu { selected: 0 };
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Server actions (blocking async calls)
// ---------------------------------------------------------------------------

fn action_list_policies(app: &mut App) {
    match app
        .rt
        .block_on(app.client.get::<Vec<serde_json::Value>>("policies"))
    {
        Ok(policies) => {
            app.set_status(
                format!("Loaded {} policies", policies.len()),
                StatusKind::Success,
            );
            app.screen = Screen::PolicyList {
                policies,
                selected: 0,
            };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

fn action_get_policy(app: &mut App, id: &str) {
    let path = format!("policies/{id}");
    match app.rt.block_on(app.client.get::<serde_json::Value>(&path)) {
        Ok(policy) => {
            app.screen = Screen::PolicyDetail { policy };
        }
        Err(e) => {
            app.set_status(format!("Failed: {e}"), StatusKind::Error);
            app.screen = Screen::PolicyMenu { selected: 1 };
        }
    }
}

fn action_create_policy(app: &mut App, file_path: &str) {
    let result = (|| -> anyhow::Result<()> {
        let data = std::fs::read_to_string(file_path)?;
        let payload: serde_json::Value = serde_json::from_str(&data)?;
        let _resp: serde_json::Value = app.rt.block_on(app.client.post("policies", &payload))?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            app.set_status("Policy created", StatusKind::Success);
            app.screen = Screen::PolicyMenu { selected: 2 };
        }
        Err(e) => {
            app.set_status(format!("Failed: {e}"), StatusKind::Error);
            app.screen = Screen::PolicyMenu { selected: 2 };
        }
    }
}

fn action_update_policy(app: &mut App, id: &str, file_path: &str) {
    let result = (|| -> anyhow::Result<()> {
        let data = std::fs::read_to_string(file_path)?;
        let payload: serde_json::Value = serde_json::from_str(&data)?;
        let path = format!("policies/{id}");
        let _resp: serde_json::Value = app.rt.block_on(app.client.put(&path, &payload))?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            app.set_status(format!("Policy '{id}' updated"), StatusKind::Success);
            app.screen = Screen::PolicyMenu { selected: 3 };
        }
        Err(e) => {
            app.set_status(format!("Failed: {e}"), StatusKind::Error);
            app.screen = Screen::PolicyMenu { selected: 3 };
        }
    }
}

fn action_delete_policy(app: &mut App, id: &str) {
    let path = format!("policies/{id}");
    match app.rt.block_on(app.client.delete(&path)) {
        Ok(()) => {
            app.set_status(format!("Policy '{id}' deleted"), StatusKind::Success);
            app.screen = Screen::PolicyMenu { selected: 4 };
        }
        Err(e) => {
            app.set_status(format!("Failed: {e}"), StatusKind::Error);
            app.screen = Screen::PolicyMenu { selected: 4 };
        }
    }
}

fn action_change_admin_password(app: &mut App, current: &str, new_pw: &str) {
    let payload = serde_json::json!({
        "current_password": current,
        "new_password": new_pw,
    });
    match app.rt.block_on(
        app.client
            .put::<serde_json::Value, _>("auth/password", &payload),
    ) {
        Ok(_) => {
            app.set_status("Admin password changed", StatusKind::Success);
        }
        Err(e) => {
            app.set_status(format!("Failed: {e}"), StatusKind::Error);
        }
    }
    app.screen = Screen::PasswordMenu { selected: 0 };
}

fn action_set_agent_password(app: &mut App, password: &str) {
    let result = (|| -> anyhow::Result<()> {
        let hash =
            bcrypt::hash(password, 12).map_err(|e| anyhow::anyhow!("bcrypt hash failed: {e}"))?;
        let payload = serde_json::json!({ "hash": hash });
        let _resp: serde_json::Value = app
            .rt
            .block_on(app.client.put("agent-credentials/auth-hash", &payload))?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            app.set_status("Agent password updated on server", StatusKind::Success);
            app.screen = Screen::PasswordMenu { selected: 0 };
        }
        Err(e) => {
            app.set_status(format!("Failed: {e}"), StatusKind::Error);
            app.screen = Screen::PasswordMenu { selected: 0 };
        }
    }
}

fn action_verify_agent_password(app: &mut App, password: &str) {
    #[derive(serde::Deserialize)]
    struct Resp {
        hash: String,
    }
    let result = app
        .rt
        .block_on(app.client.get::<Resp>("agent-credentials/auth-hash"));
    match result {
        Ok(resp) => {
            let ok = bcrypt::verify(password, &resp.hash).unwrap_or(false);
            if ok {
                app.set_status("Password is correct", StatusKind::Success);
            } else {
                app.set_status("Incorrect password", StatusKind::Error);
            }
            app.screen = Screen::PasswordMenu { selected: 1 };
        }
        Err(e) => {
            app.set_status(format!("Failed: {e}"), StatusKind::Error);
            app.screen = Screen::PasswordMenu { selected: 1 };
        }
    }
}

fn action_server_status(app: &mut App) {
    let health = match app.rt.block_on(app.client.check_health()) {
        Ok(()) => "OK".to_string(),
        Err(e) => format!("FAIL: {e}"),
    };
    // Ready endpoint may not be available in all server versions.
    let ready = match app
        .rt
        .block_on(app.client.get::<serde_json::Value>("ready"))
    {
        Ok(v) => v["status"].as_str().unwrap_or("unknown").to_string(),
        Err(e) => format!("FAIL: {e}"),
    };
    app.screen = Screen::ServerStatus { health, ready };
}

fn action_agent_list(app: &mut App) {
    match app
        .rt
        .block_on(app.client.get::<Vec<serde_json::Value>>("agents"))
    {
        Ok(agents) => {
            app.set_status(
                format!("Loaded {} agents", agents.len()),
                StatusKind::Success,
            );
            app.screen = Screen::AgentList {
                agents,
                selected: 0,
            };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

// ---------------------------------------------------------------------------
// SIEM config screen
// ---------------------------------------------------------------------------

/// JSON keys for the SIEM config form, indexed by row.
const SIEM_KEYS: [&str; 7] = [
    "splunk_url",
    "splunk_token",
    "splunk_enabled",
    "elk_url",
    "elk_index",
    "elk_api_key",
    "elk_enabled",
];

/// Row index of the Save button.
const SIEM_SAVE_ROW: usize = 7;
/// Row index of the Back button.
const SIEM_BACK_ROW: usize = 8;
/// Total number of rows in the SIEM config form.
const SIEM_ROW_COUNT: usize = 9;

/// Returns `true` if the row index is a bool (toggle) field.
fn siem_is_bool(index: usize) -> bool {
    matches!(index, 2 | 6)
}

/// Fetches the current SIEM config from the server and switches to the
/// `SiemConfig` screen.
fn action_load_siem_config(app: &mut App) {
    match app
        .rt
        .block_on(app.client.get::<serde_json::Value>("admin/siem-config"))
    {
        Ok(config) => {
            app.screen = Screen::SiemConfig {
                config,
                selected: 0,
                editing: false,
                buffer: String::new(),
            };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Persists the in-memory SIEM config to the server.
fn action_save_siem_config(app: &mut App) {
    // Clone the config out of the screen so we can release the borrow.
    let payload = match &app.screen {
        Screen::SiemConfig { config, .. } => config.clone(),
        _ => return,
    };
    match app.rt.block_on(
        app.client
            .put::<serde_json::Value, _>("admin/siem-config", &payload),
    ) {
        Ok(_) => {
            app.set_status("SIEM config saved", StatusKind::Success);
            app.screen = Screen::SystemMenu { selected: 2 };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Handles key events while the SIEM config form is active.
fn handle_siem_config(app: &mut App, key: KeyEvent) {
    // Split the match on `editing` to keep borrow lifetimes tight.
    let (selected, editing) = match &app.screen {
        Screen::SiemConfig {
            selected, editing, ..
        } => (*selected, *editing),
        _ => return,
    };

    if editing {
        handle_siem_config_editing(app, key, selected);
    } else {
        handle_siem_config_nav(app, key, selected);
    }
}

/// Handles key events while editing a text field in the SIEM config form.
fn handle_siem_config_editing(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Char(c) => {
            if let Screen::SiemConfig { buffer, .. } = &mut app.screen {
                buffer.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Screen::SiemConfig { buffer, .. } = &mut app.screen {
                buffer.pop();
            }
        }
        KeyCode::Enter => {
            if let Screen::SiemConfig {
                config,
                buffer,
                editing,
                ..
            } = &mut app.screen
            {
                let key_name = SIEM_KEYS[selected];
                config[key_name] = serde_json::Value::String(buffer.clone());
                buffer.clear();
                *editing = false;
            }
        }
        KeyCode::Esc => {
            if let Screen::SiemConfig {
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

/// Handles key events while navigating the SIEM config form.
fn handle_siem_config_nav(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::SiemConfig { selected: sel, .. } = &mut app.screen {
                nav(sel, SIEM_ROW_COUNT, key.code);
            }
        }
        KeyCode::Enter => {
            if selected == SIEM_SAVE_ROW {
                action_save_siem_config(app);
            } else if selected == SIEM_BACK_ROW {
                app.screen = Screen::SystemMenu { selected: 2 };
            } else if siem_is_bool(selected) {
                // Toggle the bool in place.
                if let Screen::SiemConfig { config, .. } = &mut app.screen {
                    let key_name = SIEM_KEYS[selected];
                    let cur = config[key_name].as_bool().unwrap_or(false);
                    config[key_name] = serde_json::Value::Bool(!cur);
                }
            } else {
                // Enter text-edit mode with the current value pre-filled.
                if let Screen::SiemConfig {
                    config,
                    editing,
                    buffer,
                    ..
                } = &mut app.screen
                {
                    let key_name = SIEM_KEYS[selected];
                    *buffer = config[key_name].as_str().unwrap_or("").to_string();
                    *editing = true;
                }
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::SystemMenu { selected: 2 };
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Alert Config screen
// ---------------------------------------------------------------------------

/// JSON keys for the Alert config form, indexed by row (10 editable fields).
///
/// Must match `AlertRouterConfigPayload` field names in
/// `dlp-server/src/admin_api.rs` exactly so the PUT round-trip deserializes.
const ALERT_KEYS: [&str; 10] = [
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

/// Row index of the Save button.
const ALERT_SAVE_ROW: usize = 10;
/// Row index of the Test Connection button.
const ALERT_TEST_ROW: usize = 11;
/// Row index of the Back button.
const ALERT_BACK_ROW: usize = 12;
/// Total number of rows in the Alert config form (10 editable + Save + Test + Back).
const ALERT_ROW_COUNT: usize = 13;

/// Row indices for the PolicyCreate form.
const POLICY_NAME_ROW: usize = 0;
const POLICY_DESC_ROW: usize = 1;
const POLICY_PRIORITY_ROW: usize = 2;
const POLICY_ACTION_ROW: usize = 3;
const POLICY_ADD_CONDITIONS_ROW: usize = 4;
const POLICY_CONDITIONS_DISPLAY_ROW: usize = 5;
const POLICY_SUBMIT_ROW: usize = 6;
/// Total rows in the form (0..=6).
const POLICY_ROW_COUNT: usize = 7;

/// Returns `true` if the row index is a bool (toggle) field.
fn alert_is_bool(index: usize) -> bool {
    matches!(index, 6 | 9) // smtp_enabled, webhook_enabled
}

/// Returns `true` if the row index is the numeric SMTP port field.
fn alert_is_numeric(index: usize) -> bool {
    matches!(index, 1) // smtp_port
}

/// Fetches the current alert router config from the server and switches
/// to the `AlertConfig` screen.
///
/// Uses the generic `client.get::<serde_json::Value>` path (matching the
/// Phase 3.1 SIEM Config pattern) rather than adding a typed client helper.
fn action_load_alert_config(app: &mut App) {
    match app
        .rt
        .block_on(app.client.get::<serde_json::Value>("admin/alert-config"))
    {
        Ok(config) => {
            app.screen = Screen::AlertConfig {
                config,
                selected: 0,
                editing: false,
                buffer: String::new(),
            };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Persists the in-memory alert router config to the server.
fn action_save_alert_config(app: &mut App) {
    // Clone the config out of the screen so we can release the borrow.
    let payload = match &app.screen {
        Screen::AlertConfig { config, .. } => config.clone(),
        _ => return,
    };
    match app.rt.block_on(
        app.client
            .put::<serde_json::Value, _>("admin/alert-config", &payload),
    ) {
        Ok(_) => {
            app.set_status("Alert config saved", StatusKind::Success);
            app.screen = Screen::SystemMenu { selected: 3 };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Sends a test alert using the current alert router configuration.
fn action_test_alert_config(app: &mut App) {
    match app.rt.block_on(
        app.client
            .post::<serde_json::Value, _>("admin/alert-config/test", &serde_json::json!({})),
    ) {
        Ok(_) => app.set_status("Test alert sent", StatusKind::Success),
        Err(e) => app.set_status(format!("Test failed: {e}"), StatusKind::Error),
    }
}

/// Handles key events while the Alert config form is active.
fn handle_alert_config(app: &mut App, key: KeyEvent) {
    let (selected, editing) = match &app.screen {
        Screen::AlertConfig {
            selected, editing, ..
        } => (*selected, *editing),
        _ => return,
    };

    if editing {
        handle_alert_config_editing(app, key, selected);
    } else {
        handle_alert_config_nav(app, key, selected);
    }
}

/// Handles key events while editing a text/numeric field in the Alert
/// config form.
///
/// The numeric branch (row 1, `smtp_port`) parses the buffer as `u16`. On
/// parse failure the function sets a status error and stays in edit mode
/// so the user can correct the value without losing their input.
fn handle_alert_config_editing(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Char(c) => {
            if let Screen::AlertConfig { buffer, .. } = &mut app.screen {
                buffer.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Screen::AlertConfig { buffer, .. } = &mut app.screen {
                buffer.pop();
            }
        }
        KeyCode::Enter => {
            // G2: commit the buffer. Numeric row 1 requires u16 parsing.
            if alert_is_numeric(selected) {
                // Parse smtp_port. On failure, set a status error and stay
                // in edit mode so the user can correct the value.
                let buffer_copy = match &app.screen {
                    Screen::AlertConfig { buffer, .. } => buffer.clone(),
                    _ => return,
                };
                match buffer_copy.trim().parse::<u16>() {
                    Ok(port) => {
                        if let Screen::AlertConfig {
                            config,
                            buffer,
                            editing,
                            ..
                        } = &mut app.screen
                        {
                            let key_name = ALERT_KEYS[selected];
                            // G9: store as JSON Number, not String, so the
                            // server's `smtp_port: u16` deserialization
                            // succeeds on PUT.
                            config[key_name] =
                                serde_json::Value::Number(serde_json::Number::from(port));
                            buffer.clear();
                            *editing = false;
                        }
                    }
                    Err(_) => {
                        app.set_status(
                            "SMTP port must be a number in 0..=65535",
                            StatusKind::Error,
                        );
                        // Stay in edit mode so the user can fix the buffer.
                    }
                }
            } else if let Screen::AlertConfig {
                config,
                buffer,
                editing,
                ..
            } = &mut app.screen
            {
                let key_name = ALERT_KEYS[selected];
                config[key_name] = serde_json::Value::String(buffer.clone());
                buffer.clear();
                *editing = false;
            }
        }
        KeyCode::Esc => {
            if let Screen::AlertConfig {
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

/// Handles key events while navigating the Alert config form.
fn handle_alert_config_nav(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::AlertConfig { selected: sel, .. } = &mut app.screen {
                nav(sel, ALERT_ROW_COUNT, key.code);
            }
        }
        KeyCode::Enter => {
            if selected == ALERT_SAVE_ROW {
                action_save_alert_config(app);
            } else if selected == ALERT_TEST_ROW {
                action_test_alert_config(app);
            } else if selected == ALERT_BACK_ROW {
                app.screen = Screen::SystemMenu { selected: 3 };
            } else if alert_is_bool(selected) {
                // Toggle the bool in place.
                if let Screen::AlertConfig { config, .. } = &mut app.screen {
                    let key_name = ALERT_KEYS[selected];
                    let cur = config[key_name].as_bool().unwrap_or(false);
                    config[key_name] = serde_json::Value::Bool(!cur);
                }
            } else if alert_is_numeric(selected) {
                // Enter edit mode pre-filled with the current port value.
                if let Screen::AlertConfig {
                    config,
                    editing,
                    buffer,
                    ..
                } = &mut app.screen
                {
                    let key_name = ALERT_KEYS[selected];
                    let n = config[key_name].as_i64().unwrap_or(587);
                    *buffer = n.to_string();
                    *editing = true;
                }
            } else {
                // Enter text-edit mode with the current string value pre-filled.
                if let Screen::AlertConfig {
                    config,
                    editing,
                    buffer,
                    ..
                } = &mut app.screen
                {
                    let key_name = ALERT_KEYS[selected];
                    *buffer = config[key_name].as_str().unwrap_or("").to_string();
                    *editing = true;
                }
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::SystemMenu { selected: 3 };
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Policy create form
// ---------------------------------------------------------------------------

/// Handles key events for the Policy Create form.
fn handle_policy_create(app: &mut App, key: KeyEvent) {
    // Phase 1: read-only borrow to extract guard fields.
    // This must be a separate block so the borrow ends before any &mut call.
    let (selected, editing) = match &app.screen {
        Screen::PolicyCreate {
            selected, editing, ..
        } => (*selected, *editing),
        _ => return,
    };

    if editing {
        handle_policy_create_editing(app, key, selected);
    } else {
        handle_policy_create_nav(app, key, selected);
    }
}

/// Handles key events while editing a text field in the Policy Create form.
///
/// Text field rows: 0 (Name), 1 (Description), 2 (Priority).
/// Enter commits the buffer to the form field; Esc cancels without discarding the form.
fn handle_policy_create_editing(app: &mut App, key: KeyEvent, _selected: usize) {
    match key.code {
        KeyCode::Char(c) => {
            if let Screen::PolicyCreate { buffer, .. } = &mut app.screen {
                buffer.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Screen::PolicyCreate { buffer, .. } = &mut app.screen {
                buffer.pop();
            }
        }
        KeyCode::Enter => {
            // Commit the buffer into the relevant form field.
            // Two-phase borrow: extract selected+buffer first, then mutate.
            let (selected, buf) = match &app.screen {
                Screen::PolicyCreate {
                    selected, buffer, ..
                } => (*selected, buffer.clone()),
                _ => return,
            };
            if let Screen::PolicyCreate {
                form,
                buffer,
                editing,
                ..
            } = &mut app.screen
            {
                match selected {
                    POLICY_NAME_ROW => form.name = buf.trim().to_string(),
                    POLICY_DESC_ROW => form.description = buf.trim().to_string(),
                    POLICY_PRIORITY_ROW => form.priority = buf.trim().to_string(),
                    _ => {}
                }
                buffer.clear();
                *editing = false;
            }
        }
        KeyCode::Esc => {
            // Cancel edit; restore field to pre-edit value (do NOT discard form).
            if let Screen::PolicyCreate {
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

/// Handles key events while navigating the Policy Create form.
fn handle_policy_create_nav(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::PolicyCreate { selected: sel, .. } = &mut app.screen {
                nav(sel, POLICY_ROW_COUNT, key.code);
            }
        }
        KeyCode::Enter => match selected {
            POLICY_SUBMIT_ROW => {
                // Two-phase borrow: clone form before calling action (Pitfall 5).
                let form = match &app.screen {
                    Screen::PolicyCreate { form, .. } => form.clone(),
                    _ => return,
                };
                action_submit_policy(app, form);
            }
            POLICY_ADD_CONDITIONS_ROW => {
                // Transition to ConditionsBuilder, carrying form_snapshot.
                let form = match &app.screen {
                    Screen::PolicyCreate { form, .. } => form.clone(),
                    _ => return,
                };
                let mut picker_state = ratatui::widgets::ListState::default();
                picker_state.select(Some(0));
                app.screen = Screen::ConditionsBuilder {
                    step: 1,
                    selected_attribute: None,
                    selected_operator: None,
                    // Pre-populate pending with any conditions already added.
                    pending: form.conditions.clone(),
                    buffer: String::new(),
                    pending_focused: false,
                    pending_state: ratatui::widgets::ListState::default(),
                    picker_state,
                    caller: CallerScreen::PolicyCreate,
                    // conditions field is empty in snapshot — live conditions travel via pending.
                    form_snapshot: PolicyFormState {
                        conditions: vec![],
                        ..form
                    },
                };
            }
            POLICY_ACTION_ROW => {
                // Cycle the action index (wraps at end of ACTION_OPTIONS).
                if let Screen::PolicyCreate { form, .. } = &mut app.screen {
                    form.action = (form.action + 1) % ACTION_OPTIONS.len();
                }
            }
            POLICY_CONDITIONS_DISPLAY_ROW => {
                // Read-only row; Enter does nothing.
            }
            _ => {
                // Text field rows: enter edit mode pre-filled with current value.
                if let Screen::PolicyCreate {
                    form,
                    editing,
                    buffer,
                    ..
                } = &mut app.screen
                {
                    let pre_fill = match selected {
                        POLICY_NAME_ROW => form.name.clone(),
                        POLICY_DESC_ROW => form.description.clone(),
                        POLICY_PRIORITY_ROW => form.priority.clone(),
                        _ => String::new(),
                    };
                    *buffer = pre_fill;
                    *editing = true;
                }
            }
        },
        KeyCode::Esc | KeyCode::Char('q') => {
            app.screen = Screen::PolicyMenu { selected: 0 };
        }
        _ => {}
    }
}

/// Validates the form, builds the POST payload, and sends it to the server.
///
/// On success: navigates to PolicyList.
/// On validation failure: sets `validation_error` inline and returns early.
/// On server error: sets `validation_error` to the error message inline.
fn action_submit_policy(app: &mut App, form: PolicyFormState) {
    // Inline validation before any network call.
    if form.name.trim().is_empty() {
        if let Screen::PolicyCreate {
            validation_error, ..
        } = &mut app.screen
        {
            *validation_error = Some("Name is required.".to_string());
        }
        return;
    }
    let priority = match form.priority.trim().parse::<u32>() {
        Ok(p) => p,
        Err(_) => {
            if let Screen::PolicyCreate {
                validation_error, ..
            } = &mut app.screen
            {
                *validation_error =
                    Some("Priority must be a valid integer (0 or greater).".to_string());
            }
            return;
        }
    };

    let action_str = ACTION_OPTIONS[form.action].to_string();
    // Serialize conditions; propagate any error inline rather than silently
    // replacing with an empty array, which could submit an allow-all policy.
    let conditions_json = match serde_json::to_value(&form.conditions) {
        Ok(v) => v,
        Err(e) => {
            if let Screen::PolicyCreate {
                validation_error, ..
            } = &mut app.screen
            {
                *validation_error = Some(format!("Failed to serialize conditions: {e}"));
            }
            return;
        }
    };

    let payload = serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "name": form.name.trim(),
        "description": if form.description.trim().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(form.description.trim().to_string())
        },
        "priority": priority,
        "conditions": conditions_json,
        "action": action_str,
        "enabled": true,
    });

    match app.rt.block_on(
        app.client
            .post::<serde_json::Value, _>("admin/policies", &payload),
    ) {
        Ok(_) => {
            // Navigate to policy list; action_list_policies sets the final
            // status message ("Loaded N policies") after the list fetch.
            // Setting a "Policy created" status here would be immediately
            // overwritten by action_list_policies, so we rely on that message.
            action_list_policies(app);
        }
        Err(e) => {
            // Display error inline; keep form on screen so user can correct.
            if let Screen::PolicyCreate {
                validation_error, ..
            } = &mut app.screen
            {
                *validation_error = Some(format!("{e}"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Conditions builder
// ---------------------------------------------------------------------------

/// Returns the operators available for the given attribute.
///
/// Tuple: `(operator_name, is_enforced)`. Currently all attributes have only
/// `"eq"` as an enforced operator; additional operators are reserved for v0.5.0.
fn operators_for(attr: ConditionAttribute) -> &'static [(&'static str, bool)] {
    match attr {
        ConditionAttribute::Classification => &[("eq", true)],
        ConditionAttribute::MemberOf => &[("eq", true)],
        ConditionAttribute::DeviceTrust => &[("eq", true)],
        ConditionAttribute::NetworkLocation => &[("eq", true)],
        ConditionAttribute::AccessContext => &[("eq", true)],
    }
}

/// Returns the number of value options for Step 3 per attribute.
///
/// Used to bound navigation and for `ListState` range checks.
/// `MemberOf` returns 0 because it uses free-text input, not a select list.
fn value_count_for(attr: ConditionAttribute) -> usize {
    match attr {
        ConditionAttribute::Classification => 4,  // T1, T2, T3, T4
        ConditionAttribute::MemberOf => 0,        // text input, not a list
        ConditionAttribute::DeviceTrust => 4,     // Managed, Unmanaged, Compliant, Unknown
        ConditionAttribute::NetworkLocation => 4, // Corporate, CorporateVpn, Guest, Unknown
        ConditionAttribute::AccessContext => 2,   // Local, Smb
    }
}

/// Constructs a `PolicyCondition` from the selected attribute, operator, picker index, and buffer.
///
/// Returns `None` if the picker index is out of range or the MemberOf buffer is empty.
///
/// # Field name note
///
/// `MemberOf` uses `group_sid: String`, NOT `value`. All other variants use `value`.
fn build_condition(
    attr: ConditionAttribute,
    op: &str,
    picker_selected: usize,
    buffer: &str,
) -> Option<dlp_common::abac::PolicyCondition> {
    use dlp_common::abac::{AccessContext, DeviceTrust, NetworkLocation, PolicyCondition};
    // Classification is at dlp_common root, NOT dlp_common::abac (see abac.rs line 222).
    use dlp_common::Classification;

    let op = op.to_string();
    Some(match attr {
        ConditionAttribute::Classification => {
            let value = match picker_selected {
                0 => Classification::T1,
                1 => Classification::T2,
                2 => Classification::T3,
                3 => Classification::T4,
                _ => return None,
            };
            PolicyCondition::Classification { op, value }
        }
        ConditionAttribute::MemberOf => {
            // CRITICAL: MemberOf uses group_sid, NOT value (abac.rs line 226).
            if buffer.trim().is_empty() {
                return None;
            }
            PolicyCondition::MemberOf {
                op,
                group_sid: buffer.trim().to_string(),
            }
        }
        ConditionAttribute::DeviceTrust => {
            let value = match picker_selected {
                0 => DeviceTrust::Managed,
                1 => DeviceTrust::Unmanaged,
                2 => DeviceTrust::Compliant,
                3 => DeviceTrust::Unknown,
                _ => return None,
            };
            PolicyCondition::DeviceTrust { op, value }
        }
        ConditionAttribute::NetworkLocation => {
            let value = match picker_selected {
                0 => NetworkLocation::Corporate,
                1 => NetworkLocation::CorporateVpn,
                2 => NetworkLocation::Guest,
                3 => NetworkLocation::Unknown,
                _ => return None,
            };
            PolicyCondition::NetworkLocation { op, value }
        }
        ConditionAttribute::AccessContext => {
            let value = match picker_selected {
                0 => AccessContext::Local,
                1 => AccessContext::Smb,
                _ => return None,
            };
            PolicyCondition::AccessContext { op, value }
        }
    })
}

/// Returns a human-readable display string for a `PolicyCondition`.
///
/// Used by the pending conditions list in the modal overlay.
/// `Classification` uses `Display` (label); others use `Debug` format.
// Called by Plan 02 render.rs draw_conditions_builder.
#[allow(dead_code)]
pub fn condition_display(cond: &dlp_common::abac::PolicyCondition) -> String {
    use dlp_common::abac::PolicyCondition;
    match cond {
        PolicyCondition::Classification { op, value } => format!("Classification {op} {value}"),
        PolicyCondition::MemberOf { op, group_sid } => format!("MemberOf {op} {group_sid}"),
        PolicyCondition::DeviceTrust { op, value } => format!("DeviceTrust {op} {value:?}"),
        PolicyCondition::NetworkLocation { op, value } => {
            format!("NetworkLocation {op} {value:?}")
        }
        PolicyCondition::AccessContext { op, value } => format!("AccessContext {op} {value:?}"),
    }
}

/// Handles key events for the conditions builder modal overlay.
///
/// Uses the two-phase read-then-mutate pattern: read scalar flags with a shared
/// borrow first, then mutate with `if let Screen::ConditionsBuilder { .. } = &mut app.screen`.
fn handle_conditions_builder(app: &mut App, key: KeyEvent) {
    // Phase 1: read scalar state with a shared borrow to avoid borrow conflicts.
    let (step, pending_focused, selected_attribute, selected_operator, pending_len) =
        match &app.screen {
            Screen::ConditionsBuilder {
                step,
                pending_focused,
                selected_attribute,
                selected_operator,
                pending,
                ..
            } => (
                *step,
                *pending_focused,
                *selected_attribute,
                selected_operator.clone(),
                pending.len(),
            ),
            _ => return,
        };

    // Tab toggles focus between the pending list and the picker — handled before routing.
    if key.code == KeyCode::Tab {
        if let Screen::ConditionsBuilder {
            pending_focused, ..
        } = &mut app.screen
        {
            *pending_focused = !*pending_focused;
        }
        return;
    }

    // Phase 2: route based on focus and step.
    if pending_focused {
        handle_conditions_pending(app, key, pending_len);
    } else {
        match step {
            1 => handle_conditions_step1(app, key),
            2 => handle_conditions_step2(app, key, selected_attribute),
            3 => {
                handle_conditions_step3(app, key, selected_attribute, selected_operator.as_deref())
            }
            _ => {}
        }
    }
}

/// Handles key events when the pending conditions list has focus.
fn handle_conditions_pending(app: &mut App, key: KeyEvent, pending_len: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if pending_len > 0 {
                if let Screen::ConditionsBuilder { pending_state, .. } = &mut app.screen {
                    let current = pending_state.selected().unwrap_or(0);
                    let new_idx = match key.code {
                        KeyCode::Up => {
                            if current == 0 {
                                pending_len - 1
                            } else {
                                current - 1
                            }
                        }
                        KeyCode::Down => (current + 1) % pending_len,
                        _ => current,
                    };
                    pending_state.select(Some(new_idx));
                }
            }
        }
        // 'd', 'D', or Delete removes the selected condition (per D-07).
        KeyCode::Char('d') | KeyCode::Char('D') | KeyCode::Delete => {
            if let Screen::ConditionsBuilder {
                pending,
                pending_state,
                ..
            } = &mut app.screen
            {
                if let Some(idx) = pending_state.selected() {
                    if idx < pending.len() {
                        pending.remove(idx);
                        // Adjust selection so it stays in range after removal.
                        if pending.is_empty() {
                            pending_state.select(None);
                        } else if idx >= pending.len() {
                            pending_state.select(Some(pending.len() - 1));
                        }
                    }
                }
            }
        }
        KeyCode::Esc => {
            // Per D-06: Esc from pending focus closes the modal.
            // Dispatch back to the caller screen, restoring form state.
            let (caller, pending, form_snapshot) = match &app.screen {
                Screen::ConditionsBuilder {
                    caller,
                    pending,
                    form_snapshot,
                    ..
                } => (*caller, pending.clone(), form_snapshot.clone()),
                _ => return,
            };
            match caller {
                CallerScreen::PolicyCreate => {
                    app.screen = Screen::PolicyCreate {
                        form: PolicyFormState {
                            conditions: pending,
                            ..form_snapshot
                        },
                        selected: POLICY_ADD_CONDITIONS_ROW,
                        editing: false,
                        buffer: String::new(),
                        validation_error: None,
                    };
                }
                CallerScreen::PolicyEdit => {
                    // Phase 15 handles this.
                    app.screen = Screen::PolicyMenu { selected: 0 };
                }
            }
        }
        _ => {}
    }
}

/// Handles key events at Step 1: attribute selection.
fn handle_conditions_step1(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::ConditionsBuilder { picker_state, .. } = &mut app.screen {
                let current = picker_state.selected().unwrap_or(0);
                let new_idx = match key.code {
                    KeyCode::Up => {
                        if current == 0 {
                            ATTRIBUTES.len() - 1
                        } else {
                            current - 1
                        }
                    }
                    KeyCode::Down => (current + 1) % ATTRIBUTES.len(),
                    _ => current,
                };
                picker_state.select(Some(new_idx));
            }
        }
        KeyCode::Enter => {
            // Advance to Step 2 with the selected attribute (per D-17).
            if let Screen::ConditionsBuilder {
                step,
                selected_attribute,
                picker_state,
                ..
            } = &mut app.screen
            {
                let idx = picker_state.selected().unwrap_or(0);
                // Bounds-checked: ATTRIBUTES.get returns None for out-of-range idx,
                // falling back to Classification so Step 2 always has a valid attribute.
                let attr = ATTRIBUTES
                    .get(idx)
                    .copied()
                    .unwrap_or(ConditionAttribute::Classification);
                *selected_attribute = Some(attr);
                *step = 2;
                // Reset picker to top for the new step's list (Pitfall 4).
                picker_state.select(Some(0));
            }
        }
        KeyCode::Esc => {
            // Per D-18: Esc at Step 1 closes the modal.
            // Dispatch back to the caller screen, restoring form state.
            let (caller, pending, form_snapshot) = match &app.screen {
                Screen::ConditionsBuilder {
                    caller,
                    pending,
                    form_snapshot,
                    ..
                } => (*caller, pending.clone(), form_snapshot.clone()),
                _ => return,
            };
            match caller {
                CallerScreen::PolicyCreate => {
                    app.screen = Screen::PolicyCreate {
                        form: PolicyFormState {
                            conditions: pending,
                            ..form_snapshot
                        },
                        selected: POLICY_ADD_CONDITIONS_ROW,
                        editing: false,
                        buffer: String::new(),
                        validation_error: None,
                    };
                }
                CallerScreen::PolicyEdit => {
                    // Phase 15 handles this.
                    app.screen = Screen::PolicyMenu { selected: 0 };
                }
            }
        }
        _ => {}
    }
}

/// Handles key events at Step 2: operator selection.
fn handle_conditions_step2(
    app: &mut App,
    key: KeyEvent,
    selected_attribute: Option<ConditionAttribute>,
) {
    let attr = match selected_attribute {
        Some(a) => a,
        None => return,
    };
    let ops = operators_for(attr);

    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::ConditionsBuilder { picker_state, .. } = &mut app.screen {
                let current = picker_state.selected().unwrap_or(0);
                if ops.is_empty() {
                    return;
                }
                let new_idx = match key.code {
                    KeyCode::Up => {
                        if current == 0 {
                            ops.len() - 1
                        } else {
                            current - 1
                        }
                    }
                    KeyCode::Down => (current + 1) % ops.len(),
                    _ => current,
                };
                picker_state.select(Some(new_idx));
            }
        }
        KeyCode::Enter => {
            // Advance to Step 3 with the selected operator (per D-17).
            if let Screen::ConditionsBuilder {
                step,
                selected_operator,
                picker_state,
                buffer,
                ..
            } = &mut app.screen
            {
                let idx = picker_state.selected().unwrap_or(0);
                *selected_operator = Some(ops[idx].0.to_string());
                *step = 3;
                // Clear any leftover MemberOf input from a previous iteration.
                buffer.clear();
                // Reset picker to top for Step 3 list (Pitfall 4).
                picker_state.select(Some(0));
            }
        }
        KeyCode::Esc => {
            // Per D-18: Esc at Step 2 goes back to Step 1.
            if let Screen::ConditionsBuilder {
                step,
                selected_attribute,
                selected_operator,
                picker_state,
                ..
            } = &mut app.screen
            {
                *step = 1;
                *selected_attribute = None;
                *selected_operator = None;
                picker_state.select(Some(0));
            }
        }
        _ => {}
    }
}

/// Handles key events at Step 3: value selection or text input.
///
/// Routes to the text-input path for `MemberOf` (free-text AD group SID)
/// or the list-select path for all other attributes.
fn handle_conditions_step3(
    app: &mut App,
    key: KeyEvent,
    selected_attribute: Option<ConditionAttribute>,
    selected_operator: Option<&str>,
) {
    let attr = match selected_attribute {
        Some(a) => a,
        None => return,
    };
    let op = match selected_operator {
        Some(o) => o,
        None => return,
    };

    if attr == ConditionAttribute::MemberOf {
        handle_conditions_step3_text(app, key, attr, op);
    } else {
        handle_conditions_step3_select(app, key, attr, op);
    }
}

/// Handles Step 3 for MemberOf: free-text input for the AD group SID.
fn handle_conditions_step3_text(app: &mut App, key: KeyEvent, attr: ConditionAttribute, op: &str) {
    match key.code {
        KeyCode::Char(c) => {
            if let Screen::ConditionsBuilder { buffer, .. } = &mut app.screen {
                buffer.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Screen::ConditionsBuilder { buffer, .. } = &mut app.screen {
                buffer.pop();
            }
        }
        KeyCode::Enter => {
            // Snapshot the buffer with a shared borrow before taking &mut.
            let buffer_snapshot = match &app.screen {
                Screen::ConditionsBuilder { buffer, .. } => buffer.clone(),
                _ => return,
            };
            match build_condition(attr, op, 0, &buffer_snapshot) {
                Some(cond) => {
                    if let Screen::ConditionsBuilder {
                        pending,
                        pending_state,
                        step,
                        selected_attribute,
                        selected_operator,
                        buffer,
                        picker_state,
                        ..
                    } = &mut app.screen
                    {
                        pending.push(cond);
                        // Select the newly added condition in the pending list.
                        pending_state.select(Some(pending.len() - 1));
                        // Reset to Step 1 for the next condition (per D-05, Pitfall 4).
                        *step = 1;
                        *selected_attribute = None;
                        *selected_operator = None;
                        buffer.clear();
                        picker_state.select(Some(0));
                    }
                }
                None => {
                    app.set_status("AD group SID cannot be empty", StatusKind::Error);
                }
            }
        }
        KeyCode::Esc => {
            // Per D-18: Esc at Step 3 goes back to Step 2.
            if let Screen::ConditionsBuilder {
                step,
                selected_operator,
                buffer,
                picker_state,
                ..
            } = &mut app.screen
            {
                *step = 2;
                *selected_operator = None;
                buffer.clear();
                picker_state.select(Some(0));
            }
        }
        _ => {}
    }
}

/// Handles Step 3 for select-based attributes (Classification, DeviceTrust, etc.).
fn handle_conditions_step3_select(
    app: &mut App,
    key: KeyEvent,
    attr: ConditionAttribute,
    op: &str,
) {
    let count = value_count_for(attr);

    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if count == 0 {
                return;
            }
            if let Screen::ConditionsBuilder { picker_state, .. } = &mut app.screen {
                let current = picker_state.selected().unwrap_or(0);
                let new_idx = match key.code {
                    KeyCode::Up => {
                        if current == 0 {
                            count - 1
                        } else {
                            current - 1
                        }
                    }
                    KeyCode::Down => (current + 1) % count,
                    _ => current,
                };
                picker_state.select(Some(new_idx));
            }
        }
        KeyCode::Enter => {
            let picker_idx = match &app.screen {
                Screen::ConditionsBuilder { picker_state, .. } => {
                    picker_state.selected().unwrap_or(0)
                }
                _ => return,
            };
            if let Some(cond) = build_condition(attr, op, picker_idx, "") {
                if let Screen::ConditionsBuilder {
                    pending,
                    pending_state,
                    step,
                    selected_attribute,
                    selected_operator,
                    picker_state,
                    ..
                } = &mut app.screen
                {
                    pending.push(cond);
                    pending_state.select(Some(pending.len() - 1));
                    // Reset to Step 1 for the next condition (per D-05, Pitfall 4).
                    *step = 1;
                    *selected_attribute = None;
                    *selected_operator = None;
                    picker_state.select(Some(0));
                }
            }
        }
        KeyCode::Esc => {
            // Per D-18: Esc at Step 3 goes back to Step 2.
            if let Screen::ConditionsBuilder {
                step,
                selected_operator,
                picker_state,
                ..
            } = &mut app.screen
            {
                *step = 2;
                *selected_operator = None;
                picker_state.select(Some(0));
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_menu_has_alert_config() {
        // Verify the Alert config constants are consistent with the 13-row form.
        assert_eq!(ALERT_KEYS.len(), 10, "10 editable fields");
        assert_eq!(ALERT_SAVE_ROW, 10);
        assert_eq!(ALERT_TEST_ROW, 11);
        assert_eq!(ALERT_BACK_ROW, 12);
        assert_eq!(ALERT_ROW_COUNT, 13);

        // Verify the bool rows map to the enabled columns.
        assert!(alert_is_bool(6)); // smtp_enabled
        assert!(alert_is_bool(9)); // webhook_enabled
        assert!(!alert_is_bool(0)); // smtp_host
        assert!(!alert_is_bool(1)); // smtp_port (numeric, not bool)

        // Verify the numeric row is smtp_port.
        assert!(alert_is_numeric(1));
        assert!(!alert_is_numeric(0));
        assert!(!alert_is_numeric(6));

        // Verify the KEYS order matches the documented form.
        assert_eq!(ALERT_KEYS[0], "smtp_host");
        assert_eq!(ALERT_KEYS[1], "smtp_port");
        assert_eq!(ALERT_KEYS[3], "smtp_password");
        assert_eq!(ALERT_KEYS[6], "smtp_enabled");
        assert_eq!(ALERT_KEYS[7], "webhook_url");
        assert_eq!(ALERT_KEYS[8], "webhook_secret");
        assert_eq!(ALERT_KEYS[9], "webhook_enabled");
    }

    #[test]
    fn build_condition_classification_t3() {
        let cond = build_condition(ConditionAttribute::Classification, "eq", 2, "");
        assert!(cond.is_some());
        let json = serde_json::to_string(&cond.unwrap()).expect("serialize");
        assert!(json.contains("\"attribute\":\"classification\""));
        assert!(json.contains("\"op\":\"eq\""));
        assert!(json.contains("\"value\":\"T3\""));
    }

    #[test]
    fn build_condition_member_of_group_sid() {
        let cond = build_condition(ConditionAttribute::MemberOf, "eq", 0, "S-1-5-21-123");
        assert!(cond.is_some());
        let json = serde_json::to_string(&cond.unwrap()).expect("serialize");
        assert!(json.contains("\"group_sid\":\"S-1-5-21-123\""));
        // Must NOT contain a bare "value" field.
        assert!(!json.contains("\"value\""));
    }

    #[test]
    fn build_condition_member_of_empty_buffer_returns_none() {
        let cond = build_condition(ConditionAttribute::MemberOf, "eq", 0, "  ");
        assert!(cond.is_none());
    }

    #[test]
    fn build_condition_device_trust_all_variants() {
        for (idx, expected) in [
            (0, "Managed"),
            (1, "Unmanaged"),
            (2, "Compliant"),
            (3, "Unknown"),
        ] {
            let cond = build_condition(ConditionAttribute::DeviceTrust, "eq", idx, "")
                .expect("should build");
            let json = serde_json::to_string(&cond).expect("serialize");
            assert!(
                json.contains(&format!("\"value\":\"{expected}\"")),
                "idx={idx}"
            );
        }
    }

    #[test]
    fn build_condition_network_location_all_variants() {
        for (idx, expected) in [
            (0, "Corporate"),
            (1, "CorporateVpn"),
            (2, "Guest"),
            (3, "Unknown"),
        ] {
            let cond = build_condition(ConditionAttribute::NetworkLocation, "eq", idx, "")
                .expect("should build");
            let json = serde_json::to_string(&cond).expect("serialize");
            assert!(
                json.contains(&format!("\"value\":\"{expected}\"")),
                "idx={idx}"
            );
        }
    }

    #[test]
    fn build_condition_access_context_all_variants() {
        for (idx, expected) in [(0, "local"), (1, "smb")] {
            let cond = build_condition(ConditionAttribute::AccessContext, "eq", idx, "")
                .expect("should build");
            let json = serde_json::to_string(&cond).expect("serialize");
            assert!(
                json.contains(&format!("\"value\":\"{expected}\"")),
                "idx={idx}"
            );
        }
    }

    #[test]
    fn build_condition_out_of_range_returns_none() {
        assert!(build_condition(ConditionAttribute::Classification, "eq", 5, "").is_none());
        assert!(build_condition(ConditionAttribute::AccessContext, "eq", 2, "").is_none());
    }

    #[test]
    fn operators_for_all_attributes_have_eq() {
        for attr in ATTRIBUTES {
            let ops = operators_for(attr);
            assert!(!ops.is_empty(), "operators_for({attr:?}) must not be empty");
            assert_eq!(ops[0].0, "eq", "first operator must be eq for {attr:?}");
            assert!(ops[0].1, "eq must be enforced for {attr:?}");
        }
    }

    #[test]
    fn condition_display_classification() {
        use dlp_common::abac::PolicyCondition;
        use dlp_common::Classification;
        let cond = PolicyCondition::Classification {
            op: "eq".to_string(),
            value: Classification::T3,
        };
        let display = condition_display(&cond);
        // Classification implements Display as "Confidential".
        assert_eq!(display, "Classification eq Confidential");
    }

    #[test]
    fn condition_display_member_of() {
        use dlp_common::abac::PolicyCondition;
        let cond = PolicyCondition::MemberOf {
            op: "eq".to_string(),
            group_sid: "S-1-5-21-123".to_string(),
        };
        let display = condition_display(&cond);
        assert_eq!(display, "MemberOf eq S-1-5-21-123");
    }

    #[test]
    fn value_count_for_all_attributes() {
        assert_eq!(value_count_for(ConditionAttribute::Classification), 4);
        assert_eq!(value_count_for(ConditionAttribute::MemberOf), 0);
        assert_eq!(value_count_for(ConditionAttribute::DeviceTrust), 4);
        assert_eq!(value_count_for(ConditionAttribute::NetworkLocation), 4);
        assert_eq!(value_count_for(ConditionAttribute::AccessContext), 2);
    }

    // ---------------------------------------------------------------------------
    // Helper: minimal App for unit tests (no server connection required).
    // ---------------------------------------------------------------------------

    fn make_test_app(screen: Screen) -> crate::app::App {
        let client = crate::client::EngineClient::for_test();
        // Single-threaded runtime is sufficient for tests that only hit the
        // validation path (which returns before any async call).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime build must succeed");
        let mut app = crate::app::App::new(client, rt);
        // Override the default MainMenu screen with the one needed by the test.
        app.screen = screen;
        app
    }

    // ---------------------------------------------------------------------------
    // Phase 14 tests: wire format, validation, CallerScreen dispatch.
    // ---------------------------------------------------------------------------

    /// Verifies that ACTION_OPTIONS contains the exact wire strings required by
    /// the server's `deserialize_policy_row` function (case-insensitive match).
    /// Catches the DenyWithLog vs DenyWithAlert naming pitfall (Pitfall 1).
    #[test]
    fn action_options_wire_format() {
        assert_eq!(ACTION_OPTIONS[0], "ALLOW");
        assert_eq!(ACTION_OPTIONS[1], "DENY");
        assert_eq!(ACTION_OPTIONS[2], "AllowWithLog");
        assert_eq!(ACTION_OPTIONS[3], "DenyWithAlert");
        assert_eq!(ACTION_OPTIONS.len(), 4);
    }

    /// Verifies that submitting a form with a whitespace-only name sets an
    /// inline validation error and does NOT navigate away from PolicyCreate.
    #[test]
    fn validate_policy_form_empty_name() {
        // Arrange: PolicyCreate screen with name = "  " (whitespace only).
        let form = PolicyFormState {
            name: "  ".to_string(),
            priority: "10".to_string(),
            ..Default::default()
        };
        let screen = Screen::PolicyCreate {
            form: form.clone(),
            selected: POLICY_SUBMIT_ROW,
            editing: false,
            buffer: String::new(),
            validation_error: None,
        };
        let mut app = make_test_app(screen);

        // Act: call action_submit_policy directly (validation runs before HTTP).
        action_submit_policy(&mut app, form);

        // Assert: screen is still PolicyCreate with the error set.
        match &app.screen {
            Screen::PolicyCreate {
                validation_error, ..
            } => {
                assert_eq!(
                    validation_error.as_deref(),
                    Some("Name is required."),
                    "expected inline validation error for empty name"
                );
            }
            other => panic!("expected Screen::PolicyCreate, got {other:?}"),
        }
    }

    /// Verifies that a non-numeric priority string sets an inline validation
    /// error and does NOT make a network call.
    #[test]
    fn validate_policy_priority_non_numeric() {
        // Arrange: valid name, non-numeric priority.
        let form = PolicyFormState {
            name: "Test".to_string(),
            priority: "abc".to_string(),
            ..Default::default()
        };
        let screen = Screen::PolicyCreate {
            form: form.clone(),
            selected: POLICY_SUBMIT_ROW,
            editing: false,
            buffer: String::new(),
            validation_error: None,
        };
        let mut app = make_test_app(screen);

        // Act.
        action_submit_policy(&mut app, form);

        // Assert.
        match &app.screen {
            Screen::PolicyCreate {
                validation_error, ..
            } => {
                assert_eq!(
                    validation_error.as_deref(),
                    Some("Priority must be a valid integer (0 or greater)."),
                    "expected inline validation error for non-numeric priority"
                );
            }
            other => panic!("expected Screen::PolicyCreate, got {other:?}"),
        }
    }

    /// Verifies that a negative priority string (e.g. "-5") fails u32 parsing
    /// and sets the same validation error message as non-numeric input.
    #[test]
    fn validate_policy_priority_negative() {
        // Arrange: valid name, negative priority.
        let form = PolicyFormState {
            name: "Test".to_string(),
            priority: "-5".to_string(),
            ..Default::default()
        };
        let screen = Screen::PolicyCreate {
            form: form.clone(),
            selected: POLICY_SUBMIT_ROW,
            editing: false,
            buffer: String::new(),
            validation_error: None,
        };
        let mut app = make_test_app(screen);

        // Act.
        action_submit_policy(&mut app, form);

        // Assert: "-5" fails u32 parse, same error message as non-numeric.
        match &app.screen {
            Screen::PolicyCreate {
                validation_error, ..
            } => {
                assert_eq!(
                    validation_error.as_deref(),
                    Some("Priority must be a valid integer (0 or greater)."),
                    "negative priority must fail u32 parse"
                );
            }
            other => panic!("expected Screen::PolicyCreate, got {other:?}"),
        }
    }

    /// Verifies that pressing Esc in ConditionsBuilder (Step 1) with
    /// CallerScreen::PolicyCreate restores the PolicyCreate screen, including
    /// the form_snapshot fields and the pending conditions.
    #[test]
    fn conditions_builder_esc_restores_form() {
        use dlp_common::abac::PolicyCondition;
        use dlp_common::Classification;

        // Arrange: ConditionsBuilder with a pending condition and a form_snapshot.
        let pending_condition = PolicyCondition::Classification {
            op: "eq".to_string(),
            value: Classification::T3,
        };
        let form_snapshot = PolicyFormState {
            name: "MyPolicy".to_string(),
            priority: "10".to_string(),
            conditions: vec![], // conditions travel via pending, not snapshot
            ..Default::default()
        };
        let mut picker_state = ratatui::widgets::ListState::default();
        picker_state.select(Some(0));
        let screen = Screen::ConditionsBuilder {
            step: 1,
            selected_attribute: None,
            selected_operator: None,
            pending: vec![pending_condition.clone()],
            buffer: String::new(),
            pending_focused: false,
            pending_state: ratatui::widgets::ListState::default(),
            picker_state,
            caller: CallerScreen::PolicyCreate,
            form_snapshot: form_snapshot.clone(),
        };
        let mut app = make_test_app(screen);

        // Act: simulate Esc at Step 1 by calling handle_conditions_step1 directly.
        let esc_key = KeyEvent::new(KeyCode::Esc, crossterm::event::KeyModifiers::NONE);
        handle_conditions_step1(&mut app, esc_key);

        // Assert: screen is PolicyCreate with form_snapshot fields and pending conditions.
        match &app.screen {
            Screen::PolicyCreate { form, selected, .. } => {
                assert_eq!(
                    form.name, "MyPolicy",
                    "name must be restored from form_snapshot"
                );
                assert_eq!(
                    form.priority, "10",
                    "priority must be restored from form_snapshot"
                );
                assert_eq!(
                    form.conditions.len(),
                    1,
                    "pending condition must be written back"
                );
                assert_eq!(
                    *selected, POLICY_ADD_CONDITIONS_ROW,
                    "cursor must land on Add Conditions row"
                );
            }
            other => panic!("expected Screen::PolicyCreate, got {other:?}"),
        }
    }
}
