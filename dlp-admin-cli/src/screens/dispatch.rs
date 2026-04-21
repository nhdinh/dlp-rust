//! Key-event dispatch for each [`Screen`] variant.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use crate::app::{
    App, CallerScreen, ConditionAttribute, ConfirmPurpose, ImportCaller, ImportState, InputPurpose,
    PasswordPurpose, PolicyFormState, Screen, SimulateCaller, SimulateFormState, SimulateOutcome,
    StatusKind, ACTION_OPTIONS, ATTRIBUTES,
};
use crate::event::AppEvent;
use dlp_common::abac::PolicyMode;

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
        Screen::PolicyEdit { .. } => handle_policy_edit(app, key),
        Screen::PolicySimulate { .. } => handle_policy_simulate(app, key),
        Screen::ImportConfirm { .. } => handle_import_confirm(app, key),
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
        KeyCode::Up | KeyCode::Down => nav(selected, 5, key.code),
        KeyCode::Enter => match *selected {
            0 => app.screen = Screen::PasswordMenu { selected: 0 },
            1 => app.screen = Screen::PolicyMenu { selected: 0 },
            2 => app.screen = Screen::SystemMenu { selected: 0 },
            3 => action_open_simulate(app, SimulateCaller::MainMenu),
            4 => app.should_quit = true,
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
        KeyCode::Up | KeyCode::Down => nav(selected, 9, key.code),
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
            5 => action_open_simulate(app, SimulateCaller::PolicyMenu),
            6 => action_import_policies(app),
            7 => action_export_policies(app),
            8 => app.screen = Screen::MainMenu { selected: 1 },
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
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            *yes_selected = true;
            let ConfirmPurpose::DeletePolicy { id } = &purpose;
            action_delete_policy(app, id);
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            // Cancel: stay on PolicyList (D-17).
            action_list_policies(app);
        }
        KeyCode::Enter => {
            if *yes_selected {
                match purpose {
                    ConfirmPurpose::DeletePolicy { id } => action_delete_policy(app, &id),
                }
            } else {
                action_list_policies(app);
            }
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
        KeyCode::Char('e') => {
            if let Some(policy) = policies.get(*selected) {
                let id = policy["id"].as_str().unwrap_or_default().to_string();
                let name = policy["name"].as_str().unwrap_or("<unnamed>").to_string();
                action_load_policy_for_edit(app, &id, &name);
            }
        }
        KeyCode::Char('d') => {
            if let Some(policy) = policies.get(*selected) {
                let id = policy["id"].as_str().unwrap_or_default().to_string();
                let name = policy["name"].as_str().unwrap_or("<unnamed>").to_string();
                app.screen = Screen::Confirm {
                    message: format!("Delete policy '{name}'? [y/n]"),
                    yes_selected: false,
                    purpose: ConfirmPurpose::DeletePolicy { id },
                };
            }
        }
        KeyCode::Char('n') => {
            app.screen = Screen::PolicyCreate {
                form: PolicyFormState::default(),
                selected: 0,
                editing: false,
                buffer: String::new(),
                validation_error: None,
            };
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
            // Client-side sort: primary key = priority ascending (malformed = u32::MAX sinks to bottom);
            // secondary key = name case-insensitive ascending for stable tiebreak.
            let mut sorted = policies;
            sorted.sort_by(|a, b| {
                let pa = a["priority"]
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .unwrap_or(u32::MAX);
                let pb = b["priority"]
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .unwrap_or(u32::MAX);
                pa.cmp(&pb).then_with(|| {
                    let na = a["name"].as_str().unwrap_or("").to_lowercase();
                    let nb = b["name"].as_str().unwrap_or("").to_lowercase();
                    na.cmp(&nb)
                })
            });
            app.screen = Screen::PolicyList {
                policies: sorted,
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
            // Reload the policy list (D-16).
            action_list_policies(app);
        }
        Err(e) => {
            app.set_status(format!("Failed: {e}"), StatusKind::Error);
            // Stay on PolicyList (D-17) — do NOT navigate to PolicyMenu.
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

/// Row indices for the PolicyCreate/PolicyEdit form (Phase 19: 9 rows).
const POLICY_NAME_ROW: usize = 0;
const POLICY_DESC_ROW: usize = 1;
const POLICY_PRIORITY_ROW: usize = 2;
const POLICY_ACTION_ROW: usize = 3;
/// Row index of the Enabled toggle.
const POLICY_ENABLED_ROW: usize = 4;
/// Row index of the Mode cycler (ALL / ANY / NONE), cycles on Enter or Space.
const POLICY_MODE_ROW: usize = 5;
/// Row index of the [Add Conditions] action row.
const POLICY_ADD_CONDITIONS_ROW: usize = 6;
/// Row index of the Conditions summary display row.
const POLICY_CONDITIONS_DISPLAY_ROW: usize = 7;
/// Row index of the [Save] / [Submit] action row.
const POLICY_SAVE_ROW: usize = 8;
/// Total rows in the PolicyCreate/PolicyEdit form (0..=8).
const POLICY_ROW_COUNT: usize = 9;

/// Cycles a `PolicyMode` to the next variant: ALL -> ANY -> NONE -> ALL.
///
/// Matches the `Action` enum cycler pattern (see `POLICY_ACTION_ROW` arm). `PolicyMode`
/// is `Copy`, so the argument is taken by value and a new value is returned.
///
/// # Arguments
///
/// * `mode` - current mode
///
/// # Returns
///
/// The next mode in the cycle.
fn cycle_mode(mode: dlp_common::abac::PolicyMode) -> dlp_common::abac::PolicyMode {
    use dlp_common::abac::PolicyMode;
    match mode {
        PolicyMode::ALL => PolicyMode::ANY,
        PolicyMode::ANY => PolicyMode::NONE,
        PolicyMode::NONE => PolicyMode::ALL,
    }
}

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
            POLICY_SAVE_ROW => {
                // Two-phase borrow: clone form before calling action (Pitfall 5).
                let form = match &app.screen {
                    Screen::PolicyCreate { form, .. } => form.clone(),
                    _ => return,
                };
                action_submit_policy(app, form);
            }
            POLICY_ENABLED_ROW => {
                // Toggle the enabled bool (no edit mode, no buffer).
                if let Screen::PolicyCreate { form, .. } = &mut app.screen {
                    form.enabled = !form.enabled;
                }
            }
            POLICY_MODE_ROW => {
                // Cycle the boolean mode (ALL -> ANY -> NONE -> ALL).
                if let Screen::PolicyCreate { form, .. } = &mut app.screen {
                    form.mode = cycle_mode(form.mode);
                }
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
                    edit_index: None,
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
                // Guard against out-of-bounds `selected` values — only rows 0..=2
                // are editable text fields. Any other index is a no-op.
                if selected > POLICY_PRIORITY_ROW {
                    return;
                }
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
                        // Unreachable given the `selected > POLICY_PRIORITY_ROW`
                        // guard above, but Rust requires an exhaustive match.
                        _ => return,
                    };
                    *buffer = pre_fill;
                    *editing = true;
                }
            }
        },
        KeyCode::Char(' ') if selected == POLICY_MODE_ROW => {
            // Same cycle-on-activate UX as Enter for the Mode row.
            if let Screen::PolicyCreate { form, .. } = &mut app.screen {
                form.mode = cycle_mode(form.mode);
            }
        }
        KeyCode::Esc | KeyCode::Char('q') => {
            app.screen = Screen::PolicyMenu { selected: 0 };
        }
        _ => {}
    }
}

/// Maps a `PolicyMode` to its wire-format string. The server accepts the
/// verbatim variant names `"ALL"` / `"ANY"` / `"NONE"` per Phase 18 D-02.
///
/// Mirrors the `mode_str` helper in `dlp-server/src/policy_store.rs` §29 —
/// duplicated here because that helper is `pub(crate)` to its server crate.
fn policy_mode_to_wire(mode: PolicyMode) -> &'static str {
    match mode {
        PolicyMode::ALL => "ALL",
        PolicyMode::ANY => "ANY",
        PolicyMode::NONE => "NONE",
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
        "enabled": form.enabled,
        "mode": policy_mode_to_wire(form.mode),
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
// Policy edit form
// ---------------------------------------------------------------------------

/// Loads an existing policy via GET /admin/policies/{id} and opens the edit form.
fn action_load_policy_for_edit(app: &mut App, id: &str, _name: &str) {
    let path = format!("policies/{id}");
    match app.rt.block_on(app.client.get::<serde_json::Value>(&path)) {
        Ok(policy) => {
            // Map `action` JSON to an ACTION_OPTIONS index (case-insensitive).
            let action_str = policy["action"].as_str().unwrap_or("ALLOW");
            let action_idx = ACTION_OPTIONS
                .iter()
                .position(|opt| opt.eq_ignore_ascii_case(action_str))
                .unwrap_or(0);
            if action_idx == 0 && !ACTION_OPTIONS[0].eq_ignore_ascii_case(action_str) {
                app.set_status(
                    format!("Warning: unknown action '{action_str}', defaulted to ALLOW"),
                    StatusKind::Error,
                );
            }

            // Deserialize conditions from the JSON policy.
            let conditions: Vec<dlp_common::abac::PolicyCondition> = policy["conditions"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| serde_json::from_value(v.clone()).ok())
                        .collect()
                })
                .unwrap_or_default();

            let form = PolicyFormState {
                name: policy["name"].as_str().unwrap_or("").to_string(),
                description: policy["description"].as_str().unwrap_or("").to_string(),
                priority: policy["priority"]
                    .as_i64()
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                action: action_idx,
                enabled: policy["enabled"].as_bool().unwrap_or(true),
                conditions,
                mode: match policy["mode"].as_str() {
                    Some("ALL") => PolicyMode::ALL,
                    Some("ANY") => PolicyMode::ANY,
                    Some("NONE") => PolicyMode::NONE,
                    _ => PolicyMode::ALL,
                },
                id: id.to_string(),
            };

            app.screen = Screen::PolicyEdit {
                id: id.to_string(),
                form,
                selected: 0,
                editing: false,
                buffer: String::new(),
                validation_error: None,
            };
        }
        Err(e) => {
            app.set_status(format!("Failed to load policy: {e}"), StatusKind::Error);
            // Stay on PolicyList rather than navigating away.
        }
    }
}

/// Handles key events for the Policy Edit form.
fn handle_policy_edit(app: &mut App, key: KeyEvent) {
    let (selected, editing) = match &app.screen {
        Screen::PolicyEdit {
            selected, editing, ..
        } => (*selected, *editing),
        _ => return,
    };

    if editing {
        handle_policy_edit_editing(app, key, selected);
    } else {
        handle_policy_edit_nav(app, key, selected);
    }
}

/// Handles key events while editing a text field in the Policy Edit form.
fn handle_policy_edit_editing(app: &mut App, key: KeyEvent, _selected: usize) {
    match key.code {
        KeyCode::Char(c) => {
            if let Screen::PolicyEdit { buffer, .. } = &mut app.screen {
                buffer.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Screen::PolicyEdit { buffer, .. } = &mut app.screen {
                buffer.pop();
            }
        }
        KeyCode::Enter => {
            let (selected, buf) = match &app.screen {
                Screen::PolicyEdit {
                    selected, buffer, ..
                } => (*selected, buffer.clone()),
                _ => return,
            };
            if let Screen::PolicyEdit {
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
            if let Screen::PolicyEdit {
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

/// Handles key events while navigating the Policy Edit form.
fn handle_policy_edit_nav(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::PolicyEdit { selected: sel, .. } = &mut app.screen {
                nav(sel, POLICY_ROW_COUNT, key.code);
            }
        }
        KeyCode::Enter => match selected {
            POLICY_SAVE_ROW => {
                let form = match &app.screen {
                    Screen::PolicyEdit { form, .. } => form.clone(),
                    _ => return,
                };
                action_submit_policy_update(app, &form.id.clone(), form);
            }
            POLICY_ENABLED_ROW => {
                if let Screen::PolicyEdit { form, .. } = &mut app.screen {
                    form.enabled = !form.enabled;
                }
            }
            POLICY_MODE_ROW => {
                if let Screen::PolicyEdit { form, .. } = &mut app.screen {
                    form.mode = cycle_mode(form.mode);
                }
            }
            POLICY_ACTION_ROW => {
                if let Screen::PolicyEdit { form, .. } = &mut app.screen {
                    form.action = (form.action + 1) % ACTION_OPTIONS.len();
                }
            }
            POLICY_ADD_CONDITIONS_ROW => {
                let form = match &app.screen {
                    Screen::PolicyEdit { form, .. } => form.clone(),
                    _ => return,
                };
                let mut picker_state = ratatui::widgets::ListState::default();
                picker_state.select(Some(0));
                app.screen = Screen::ConditionsBuilder {
                    step: 1,
                    selected_attribute: None,
                    selected_operator: None,
                    pending: form.conditions.clone(),
                    buffer: String::new(),
                    pending_focused: false,
                    pending_state: ratatui::widgets::ListState::default(),
                    picker_state,
                    caller: CallerScreen::PolicyEdit,
                    form_snapshot: PolicyFormState {
                        conditions: vec![],
                        ..form
                    },
                    edit_index: None,
                };
            }
            POLICY_CONDITIONS_DISPLAY_ROW => {
                // Read-only row; Enter does nothing.
            }
            _ => {
                if selected > POLICY_PRIORITY_ROW {
                    return;
                }
                if let Screen::PolicyEdit {
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
                        _ => return,
                    };
                    *buffer = pre_fill;
                    *editing = true;
                }
            }
        },
        KeyCode::Char(' ') if selected == POLICY_MODE_ROW => {
            if let Screen::PolicyEdit { form, .. } = &mut app.screen {
                form.mode = cycle_mode(form.mode);
            }
        }
        KeyCode::Esc | KeyCode::Char('q') => {
            action_list_policies(app);
        }
        _ => {}
    }
}

/// Validates the form, builds the PUT payload, and sends it to the server.
///
/// On success: navigates to PolicyList with a success status.
/// On validation failure: sets `validation_error` inline and stays on PolicyEdit.
/// On server error: sets `validation_error` inline and stays on PolicyEdit.
fn action_submit_policy_update(app: &mut App, id: &str, form: PolicyFormState) {
    // Inline validation before any network call.
    if form.name.trim().is_empty() {
        if let Screen::PolicyEdit {
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
            if let Screen::PolicyEdit {
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
    let conditions_json = match serde_json::to_value(&form.conditions) {
        Ok(v) => v,
        Err(e) => {
            if let Screen::PolicyEdit {
                validation_error, ..
            } = &mut app.screen
            {
                *validation_error = Some(format!("Failed to serialize conditions: {e}"));
            }
            return;
        }
    };

    let payload = serde_json::json!({
        "id": id,
        "name": form.name.trim(),
        "description": if form.description.trim().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(form.description.trim().to_string())
        },
        "priority": priority,
        "conditions": conditions_json,
        "action": action_str,
        "enabled": form.enabled,
        "mode": policy_mode_to_wire(form.mode),
    });

    match app.rt.block_on(
        app.client
            .put::<serde_json::Value, _>(&format!("admin/policies/{id}"), &payload),
    ) {
        Ok(_) => {
            app.set_status(
                format!("Policy '{}' updated", form.name.trim()),
                StatusKind::Success,
            );
            action_list_policies(app);
        }
        Err(e) => {
            if let Screen::PolicyEdit {
                validation_error, ..
            } = &mut app.screen
            {
                *validation_error = Some(format!("{e}"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Policy Simulate screen
// ---------------------------------------------------------------------------

/// Opens the Policy Simulate screen with a fresh `SimulateFormState::default()`
/// and the appropriate caller enum value.
fn action_open_simulate(app: &mut App, caller: SimulateCaller) {
    app.screen = Screen::PolicySimulate {
        form: SimulateFormState::default(),
        selected: 0,
        editing: false,
        buffer: String::new(),
        result: SimulateOutcome::None,
        caller,
    };
}

/// Builds an EvaluateRequest from the current form state, POSTs to /evaluate,
/// and stores the outcome in the screen's result field.
///
/// On success: result = SimulateOutcome::Success(response).
/// On reqwest network error: result = SimulateOutcome::Error("Network error: ...").
/// On server 4xx/5xx: result = SimulateOutcome::Error("Server error: ...").
fn action_submit_simulate(app: &mut App) {
    // Clone form out of the screen to avoid borrow conflicts.
    let form = match &app.screen {
        Screen::PolicySimulate { form, .. } => form.clone(),
        _ => return,
    };

    // Parse groups from comma-separated raw input.
    let groups: Vec<String> = form
        .groups_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Map select indices to typed ABAC enums.
    use dlp_common::abac::{
        AccessContext, Action, DeviceTrust, Environment, EvaluateRequest, NetworkLocation,
        Resource, Subject,
    };
    use dlp_common::Classification;

    let device_trust_vals: [DeviceTrust; 4] = [
        DeviceTrust::Managed,
        DeviceTrust::Unmanaged,
        DeviceTrust::Compliant,
        DeviceTrust::Unknown,
    ];
    let network_location_vals: [NetworkLocation; 4] = [
        NetworkLocation::Corporate,
        NetworkLocation::CorporateVpn,
        NetworkLocation::Guest,
        NetworkLocation::Unknown,
    ];
    let classification_vals: [Classification; 4] = [
        Classification::T1,
        Classification::T2,
        Classification::T3,
        Classification::T4,
    ];
    let action_vals: [Action; 6] = [
        Action::READ,
        Action::WRITE,
        Action::COPY,
        Action::DELETE,
        Action::MOVE,
        Action::PASTE,
    ];
    let access_context_vals: [AccessContext; 2] = [AccessContext::Local, AccessContext::Smb];

    let req = EvaluateRequest {
        subject: Subject {
            user_sid: form.user_sid,
            user_name: form.user_name,
            groups,
            device_trust: device_trust_vals
                .get(form.device_trust)
                .cloned()
                .unwrap_or(DeviceTrust::Unmanaged),
            network_location: network_location_vals
                .get(form.network_location)
                .cloned()
                .unwrap_or(NetworkLocation::Unknown),
        },
        resource: Resource {
            path: form.path,
            classification: classification_vals
                .get(form.classification)
                .copied()
                .unwrap_or(Classification::T1),
        },
        environment: Environment {
            timestamp: chrono::Utc::now(),
            session_id: 0,
            access_context: access_context_vals
                .get(form.access_context)
                .copied()
                .unwrap_or(AccessContext::Local),
        },
        action: *action_vals.get(form.action).unwrap_or(&Action::READ),
        agent: None,
    };

    let result = app.rt.block_on(
        app.client
            .post::<dlp_common::abac::EvaluateResponse, _>("evaluate", &req),
    );

    // Store outcome in screen (result field is &mut, needs to happen after block_on).
    if let Screen::PolicySimulate {
        result: out_result, ..
    } = &mut app.screen
    {
        match result {
            Ok(resp) => {
                *out_result = SimulateOutcome::Success(resp);
            }
            Err(e) => {
                // Distinguish reqwest transport errors from HTTP 4xx/5xx.
                let prefix = if e.downcast_ref::<reqwest::Error>().is_some() {
                    "Network error: "
                } else {
                    "Server error: "
                };
                *out_result = SimulateOutcome::Error(format!("{prefix}{e}"));
            }
        }
    }
}

/// Routes key events for the Policy Simulate screen.
fn handle_policy_simulate(app: &mut App, key: KeyEvent) {
    // Extract guard fields in a separate borrow to avoid conflicts.
    let (selected, editing) = match &app.screen {
        Screen::PolicySimulate {
            selected, editing, ..
        } => (*selected, *editing),
        _ => return,
    };
    if editing {
        handle_simulate_editing(app, key, selected);
    } else {
        handle_simulate_nav(app, key, selected);
    }
}

/// Handles key events while editing a text field in the Policy Simulate form.
///
/// Text rows: 0 = user_sid, 1 = user_name, 2 = groups_raw, 5 = path.
fn handle_simulate_editing(app: &mut App, key: KeyEvent, _selected: usize) {
    match key.code {
        KeyCode::Char(c) => {
            if let Screen::PolicySimulate { buffer, .. } = &mut app.screen {
                buffer.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Screen::PolicySimulate { buffer, .. } = &mut app.screen {
                buffer.pop();
            }
        }
        KeyCode::Enter => {
            // Commit buffer to the appropriate field, then exit edit mode.
            let (selected, buf) = match &app.screen {
                Screen::PolicySimulate {
                    selected, buffer, ..
                } => (*selected, buffer.clone()),
                _ => return,
            };
            if let Screen::PolicySimulate {
                form,
                buffer,
                editing,
                ..
            } = &mut app.screen
            {
                match selected {
                    0 => form.user_sid = buf.trim().to_string(),
                    1 => form.user_name = buf.trim().to_string(),
                    2 => form.groups_raw = buf.clone(), // Preserve exact formatting.
                    5 => form.path = buf.trim().to_string(),
                    _ => {}
                }
                buffer.clear();
                *editing = false;
            }
        }
        KeyCode::Esc => {
            // Cancel edit; restore field to pre-edit value by simply exiting edit mode.
            // The buffer retains in-progress text so it is recoverable if Enter is pressed
            // again before re-entering edit mode (pre-fill from form field overwrites it).
            if let Screen::PolicySimulate { editing, .. } = &mut app.screen {
                *editing = false;
            }
        }
        _ => {}
    }
}

/// Handles key events while navigating the Policy Simulate form (not editing).
fn handle_simulate_nav(app: &mut App, key: KeyEvent, selected: usize) {
    use crate::app::SIMULATE_ROW_COUNT;
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::PolicySimulate { selected: sel, .. } = &mut app.screen {
                nav(sel, SIMULATE_ROW_COUNT, key.code);
            }
        }
        KeyCode::Enter => match selected {
            // Text field rows: 0 (user_sid), 1 (user_name), 5 (path) — enter edit mode.
            0 | 1 | 5 => {
                if let Screen::PolicySimulate {
                    form,
                    editing,
                    buffer,
                    ..
                } = &mut app.screen
                {
                    let pre_fill = match selected {
                        0 => form.user_sid.clone(),
                        1 => form.user_name.clone(),
                        5 => form.path.clone(),
                        _ => return,
                    };
                    *buffer = pre_fill;
                    *editing = true;
                }
            }
            // Groups row (2): free-text comma-separated SID input.
            2 => {
                if let Screen::PolicySimulate {
                    form,
                    editing,
                    buffer,
                    ..
                } = &mut app.screen
                {
                    *buffer = form.groups_raw.clone();
                    *editing = true;
                }
            }
            // Select rows: Enter cycles to next option.
            3 => {
                if let Screen::PolicySimulate { form, .. } = &mut app.screen {
                    form.device_trust =
                        (form.device_trust + 1) % crate::app::SIMULATE_DEVICE_TRUST_OPTIONS.len();
                }
            }
            4 => {
                if let Screen::PolicySimulate { form, .. } = &mut app.screen {
                    form.network_location = (form.network_location + 1)
                        % crate::app::SIMULATE_NETWORK_LOCATION_OPTIONS.len();
                }
            }
            6 => {
                if let Screen::PolicySimulate { form, .. } = &mut app.screen {
                    form.classification = (form.classification + 1)
                        % crate::app::SIMULATE_CLASSIFICATION_OPTIONS.len();
                }
            }
            7 => {
                if let Screen::PolicySimulate { form, .. } = &mut app.screen {
                    form.action = (form.action + 1) % crate::app::SIMULATE_ACTION_OPTIONS.len();
                }
            }
            8 => {
                if let Screen::PolicySimulate { form, .. } = &mut app.screen {
                    form.access_context = (form.access_context + 1)
                        % crate::app::SIMULATE_ACCESS_CONTEXT_OPTIONS.len();
                }
            }
            // [Simulate] submit row (index 9).
            9 => {
                action_submit_simulate(app);
            }
            _ => {}
        },
        KeyCode::Esc | KeyCode::Char('q') => {
            // Return to the caller screen, keeping the Simulate Policy row selected.
            let caller = match &app.screen {
                Screen::PolicySimulate { caller, .. } => *caller,
                _ => return,
            };
            match caller {
                SimulateCaller::MainMenu => {
                    app.screen = Screen::MainMenu { selected: 3 };
                }
                SimulateCaller::PolicyMenu => {
                    app.screen = Screen::PolicyMenu { selected: 5 };
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Conditions builder
// ---------------------------------------------------------------------------

/// Returns the operator list (wire string + enforcement flag) valid for the given attribute.
///
/// Per D-08: DeviceTrust, NetworkLocation, AccessContext get `neq` added.
/// Per D-10: each attribute's list is fixed; the Step 2 picker auto-sizes to the count.
/// Display labels are: "equals" (eq), "not equals" (neq), "greater than" (gt),
/// "less than" (lt), "contains" (contains).
pub(crate) fn operators_for(attr: ConditionAttribute) -> &'static [(&'static str, bool)] {
    match attr {
        ConditionAttribute::Classification => {
            &[("eq", true), ("neq", true), ("gt", true), ("lt", true)]
        }
        ConditionAttribute::MemberOf => &[("eq", true), ("neq", true), ("contains", true)],
        ConditionAttribute::DeviceTrust => &[("eq", true), ("neq", true)],
        ConditionAttribute::NetworkLocation => &[("eq", true), ("neq", true)],
        ConditionAttribute::AccessContext => &[("eq", true), ("neq", true)],
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

/// Decomposes a [`PolicyCondition`] into the `(attribute, op, picker_idx, buffer)`
/// tuple needed to pre-fill the 3-step picker for in-place editing.
///
/// This is the inverse of [`build_condition`]: given a condition, it returns
/// the four values that, when passed back to `build_condition`, reproduce the
/// same condition.
///
/// # Arguments
///
/// * `cond` — The condition to decompose.
///
/// # Returns
///
/// `(ConditionAttribute, op_wire_string, picker_idx, buffer)` where:
/// - `picker_idx` is the 0-based index into the Step 3 value list for
///   select attributes; `0` for `MemberOf` (text path, index unused).
/// - `buffer` is the `group_sid` string for `MemberOf`; `String::new()`
///   for all other attributes.
fn condition_to_prefill(
    cond: &dlp_common::abac::PolicyCondition,
) -> (ConditionAttribute, String, usize, String) {
    use dlp_common::abac::{AccessContext, DeviceTrust, NetworkLocation, PolicyCondition};
    // Classification is at dlp_common root, NOT dlp_common::abac (see abac.rs line 222).
    use dlp_common::Classification;
    match cond {
        PolicyCondition::Classification { op, value } => {
            let idx = match value {
                Classification::T1 => 0,
                Classification::T2 => 1,
                Classification::T3 => 2,
                Classification::T4 => 3,
            };
            (
                ConditionAttribute::Classification,
                op.clone(),
                idx,
                String::new(),
            )
        }
        PolicyCondition::MemberOf { op, group_sid } => {
            // picker_idx is unused for MemberOf (text input); return 0.
            (
                ConditionAttribute::MemberOf,
                op.clone(),
                0,
                group_sid.clone(),
            )
        }
        PolicyCondition::DeviceTrust { op, value } => {
            let idx = match value {
                DeviceTrust::Managed => 0,
                DeviceTrust::Unmanaged => 1,
                DeviceTrust::Compliant => 2,
                DeviceTrust::Unknown => 3,
            };
            (
                ConditionAttribute::DeviceTrust,
                op.clone(),
                idx,
                String::new(),
            )
        }
        PolicyCondition::NetworkLocation { op, value } => {
            let idx = match value {
                NetworkLocation::Corporate => 0,
                NetworkLocation::CorporateVpn => 1,
                NetworkLocation::Guest => 2,
                NetworkLocation::Unknown => 3,
            };
            (
                ConditionAttribute::NetworkLocation,
                op.clone(),
                idx,
                String::new(),
            )
        }
        PolicyCondition::AccessContext { op, value } => {
            let idx = match value {
                AccessContext::Local => 0,
                AccessContext::Smb => 1,
            };
            (
                ConditionAttribute::AccessContext,
                op.clone(),
                idx,
                String::new(),
            )
        }
    }
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
        // 'e' or 'E' opens the selected condition in the 3-step picker pre-filled for editing.
        KeyCode::Char('e') | KeyCode::Char('E') => {
            // Phase 1: clone the condition and capture its index under a shared borrow.
            // This must complete before taking &mut app.screen (Rust borrow rules).
            let edit_target = match &app.screen {
                Screen::ConditionsBuilder {
                    pending,
                    pending_state,
                    ..
                } => pending_state
                    .selected()
                    .and_then(|i| pending.get(i).cloned().map(|c| (i, c))),
                _ => return,
            };
            let Some((edit_i, cond)) = edit_target else {
                return;
            };

            let (attr, op_str, picker_idx, buf) = condition_to_prefill(&cond);

            // Find the attribute's position in ATTRIBUTES for Step 1 picker pre-fill.
            let attr_idx = ATTRIBUTES.iter().position(|a| *a == attr).unwrap_or(0);

            // picker_idx is used for Step 3 pre-fill via build_condition roundtrip;
            // not needed here but consumed to avoid unused-variable warnings.
            let _ = picker_idx;

            // Phase 2: mutate screen state under a mutable borrow.
            // The shared borrow from Phase 1 is fully dropped at this point.
            if let Screen::ConditionsBuilder {
                step,
                selected_attribute,
                selected_operator,
                buffer,
                edit_index,
                pending_focused,
                picker_state,
                ..
            } = &mut app.screen
            {
                *step = 1;
                *selected_attribute = Some(attr);
                // Pre-set the operator so the SC-1 guard in handle_conditions_step1 can
                // evaluate it when the user advances through Step 1. The guard will clear
                // this if they change the attribute to an incompatible one.
                *selected_operator = Some(op_str);
                *buffer = buf;
                *edit_index = Some(edit_i);
                *pending_focused = false;
                // Pre-select the attribute row so Step 1 opens on the correct item.
                picker_state.select(Some(attr_idx));
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
                    let id = form_snapshot.id.clone();
                    app.screen = Screen::PolicyEdit {
                        form: PolicyFormState {
                            conditions: pending,
                            ..form_snapshot
                        },
                        id,
                        selected: POLICY_ADD_CONDITIONS_ROW,
                        editing: false,
                        buffer: String::new(),
                        validation_error: None,
                    };
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
                selected_operator,
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
                // SC-1: clear a stale operator when it is not valid for the new attribute.
                // In normal navigation the operator is already None here (Esc from Step 2
                // always clears it), but this guard is an explicit safety net per ROADMAP SC-1.
                if let Some(prev_op) = selected_operator.as_deref() {
                    if !operators_for(attr).iter().any(|(op, _)| *op == prev_op) {
                        *selected_operator = None;
                    }
                }
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
                    let id = form_snapshot.id.clone();
                    app.screen = Screen::PolicyEdit {
                        form: PolicyFormState {
                            conditions: pending,
                            ..form_snapshot
                        },
                        id,
                        selected: POLICY_ADD_CONDITIONS_ROW,
                        editing: false,
                        buffer: String::new(),
                        validation_error: None,
                    };
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
                // Use `.get(idx)` rather than direct indexing: picker state
                // could be desynchronized from `ops` (e.g. stale state after
                // navigating away and back). A panic here would crash the
                // TUI, so out-of-range selection silently aborts the advance.
                let op_name = match ops.get(idx) {
                    Some((name, _)) => name.to_string(),
                    None => return,
                };
                *selected_operator = Some(op_name);
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
                        edit_index,
                        ..
                    } = &mut app.screen
                    {
                        // Replace at original index (edit mode) or append (new condition mode).
                        match *edit_index {
                            Some(i) if i < pending.len() => {
                                // SC-2: replace in-place, preserving list length and position.
                                pending[i] = cond;
                                pending_state.select(Some(i));
                                *edit_index = None;
                            }
                            _ => {
                                pending.push(cond);
                                pending_state.select(Some(pending.len() - 1));
                            }
                        }
                        // Reset picker state for the next operation (regardless of mode).
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
                    edit_index,
                    ..
                } = &mut app.screen
                {
                    // Replace at original index (edit mode) or append (new condition mode).
                    match *edit_index {
                        Some(i) if i < pending.len() => {
                            // SC-2: replace in-place, preserving list length and position.
                            pending[i] = cond;
                            pending_state.select(Some(i));
                            *edit_index = None;
                        }
                        _ => {
                            pending.push(cond);
                            pending_state.select(Some(pending.len() - 1));
                        }
                    }
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

    // ---------------------------------------------------------------------------
    // Phase 20 operator regression tests.
    // ---------------------------------------------------------------------------

    #[cfg(test)]
    mod operator_tests {
        use super::*;

        #[test]
        fn test_operators_for_classification() {
            let ops = operators_for(ConditionAttribute::Classification);
            assert_eq!(ops.len(), 4);
            let wire: Vec<_> = ops.iter().map(|(w, _)| *w).collect();
            assert!(wire.contains(&"eq"));
            assert!(wire.contains(&"neq"));
            assert!(wire.contains(&"gt"));
            assert!(wire.contains(&"lt"));
        }

        #[test]
        fn test_operators_for_memberof() {
            let ops = operators_for(ConditionAttribute::MemberOf);
            assert_eq!(ops.len(), 3);
            let wire: Vec<_> = ops.iter().map(|(w, _)| *w).collect();
            assert!(wire.contains(&"eq"));
            assert!(wire.contains(&"neq"));
            assert!(wire.contains(&"contains"));
        }

        #[test]
        fn test_operators_for_device_trust() {
            let ops = operators_for(ConditionAttribute::DeviceTrust);
            assert_eq!(ops.len(), 2);
            let wire: Vec<_> = ops.iter().map(|(w, _)| *w).collect();
            assert!(wire.contains(&"eq"));
            assert!(wire.contains(&"neq"));
        }

        #[test]
        fn test_operators_for_network_location() {
            let ops = operators_for(ConditionAttribute::NetworkLocation);
            assert_eq!(ops.len(), 2);
        }

        #[test]
        fn test_operators_for_access_context() {
            let ops = operators_for(ConditionAttribute::AccessContext);
            assert_eq!(ops.len(), 2);
        }

        #[test]
        fn test_condition_display_with_gt_lt() {
            // Regression guard: condition_display renders {op} {value} verbatim,
            // so "gt" and "lt" operators must appear unchanged in the display string.
            use dlp_common::abac::PolicyCondition;
            use dlp_common::Classification;

            let cond_gt = PolicyCondition::Classification {
                op: "gt".to_string(),
                value: Classification::T3,
            };
            let display_gt = condition_display(&cond_gt);
            assert!(
                display_gt.contains("gt"),
                "expected 'gt' in display: {display_gt}"
            );
            assert!(
                display_gt.contains("Confidential"),
                "expected 'Confidential' in display: {display_gt}"
            );

            let cond_lt = PolicyCondition::Classification {
                op: "lt".to_string(),
                value: Classification::T2,
            };
            let display_lt = condition_display(&cond_lt);
            assert!(
                display_lt.contains("lt"),
                "expected 'lt' in display: {display_lt}"
            );
            assert!(
                display_lt.contains("Internal"),
                "expected 'Internal' in display: {display_lt}"
            );
        }
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
            selected: POLICY_SAVE_ROW,
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
            selected: POLICY_SAVE_ROW,
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
            selected: POLICY_SAVE_ROW,
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
            edit_index: None,
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

    #[test]
    fn condition_to_prefill_roundtrip() {
        use dlp_common::abac::{AccessContext, DeviceTrust, NetworkLocation, PolicyCondition};
        use dlp_common::Classification;

        // For each variant, prefill then rebuild and assert equality.
        let cases: &[PolicyCondition] = &[
            PolicyCondition::Classification {
                op: "gt".to_string(),
                value: Classification::T3,
            },
            PolicyCondition::MemberOf {
                op: "contains".to_string(),
                group_sid: "S-1-5-21-999".to_string(),
            },
            PolicyCondition::DeviceTrust {
                op: "neq".to_string(),
                value: DeviceTrust::Unmanaged,
            },
            PolicyCondition::NetworkLocation {
                op: "eq".to_string(),
                value: NetworkLocation::CorporateVpn,
            },
            PolicyCondition::AccessContext {
                op: "neq".to_string(),
                value: AccessContext::Smb,
            },
        ];
        for original in cases {
            let (attr, op_str, picker_idx, buf) = condition_to_prefill(original);
            let rebuilt = build_condition(attr, &op_str, picker_idx, &buf)
                .expect("roundtrip must produce a valid condition");
            assert_eq!(
                &rebuilt, original,
                "condition_to_prefill roundtrip failed for {original:?}"
            );
        }
    }

    #[test]
    fn edit_opens_picker_prefilled() {
        use dlp_common::abac::PolicyCondition;
        use dlp_common::Classification;

        let pending_condition = PolicyCondition::Classification {
            op: "eq".to_string(),
            value: Classification::T3,
        };
        let form_snapshot = PolicyFormState {
            ..Default::default()
        };
        let mut picker_state = ratatui::widgets::ListState::default();
        picker_state.select(Some(0));
        let mut pending_state = ratatui::widgets::ListState::default();
        pending_state.select(Some(0)); // row 0 selected in pending list

        let screen = Screen::ConditionsBuilder {
            step: 1,
            selected_attribute: None,
            selected_operator: None,
            pending: vec![pending_condition.clone()],
            buffer: String::new(),
            pending_focused: true, // focus is on pending list (e is only handled here)
            pending_state,
            picker_state,
            caller: CallerScreen::PolicyCreate,
            form_snapshot,
            edit_index: None,
        };
        let mut app = make_test_app(screen);

        // Act: press 'e'
        let key = KeyEvent::new(KeyCode::Char('e'), crossterm::event::KeyModifiers::NONE);
        handle_conditions_pending(&mut app, key, 1);

        // Assert: picker transitions to edit mode pre-filled.
        match &app.screen {
            Screen::ConditionsBuilder {
                step,
                selected_attribute,
                selected_operator,
                edit_index,
                pending_focused,
                picker_state,
                ..
            } => {
                assert_eq!(*step, 1, "step must reset to 1 (attribute picker)");
                assert_eq!(
                    *selected_attribute,
                    Some(ConditionAttribute::Classification),
                    "attribute must be pre-filled"
                );
                assert_eq!(
                    selected_operator.as_deref(),
                    Some("eq"),
                    "operator must be pre-filled"
                );
                assert_eq!(
                    *edit_index,
                    Some(0),
                    "edit_index must point to the source row"
                );
                assert!(!pending_focused, "focus must switch to picker");
                // Classification is ATTRIBUTES[0] => picker_state should select index 0.
                assert_eq!(
                    picker_state.selected(),
                    Some(0),
                    "picker must pre-select the attribute row"
                );
            }
            other => panic!("expected ConditionsBuilder, got {other:?}"),
        }
    }

    #[test]
    fn edit_replace_preserves_index() {
        use dlp_common::abac::PolicyCondition;
        use dlp_common::Classification;

        let original = PolicyCondition::Classification {
            op: "eq".to_string(),
            value: Classification::T3,
        };
        // Set up already in edit mode (edit_index = Some(0)).
        let mut picker_state = ratatui::widgets::ListState::default();
        picker_state.select(Some(3)); // T4 = index 3 for step3_select commit

        let screen = Screen::ConditionsBuilder {
            step: 3,
            selected_attribute: Some(ConditionAttribute::Classification),
            selected_operator: Some("eq".to_string()),
            pending: vec![original.clone()],
            buffer: String::new(),
            pending_focused: false,
            pending_state: ratatui::widgets::ListState::default(),
            picker_state,
            caller: CallerScreen::PolicyCreate,
            form_snapshot: PolicyFormState {
                ..Default::default()
            },
            edit_index: Some(0), // edit mode
        };
        let mut app = make_test_app(screen);

        // Act: Enter at Step 3 (select path) commits the new T4 value.
        let key = KeyEvent::new(KeyCode::Enter, crossterm::event::KeyModifiers::NONE);
        handle_conditions_step3_select(&mut app, key, ConditionAttribute::Classification, "eq");

        // Assert: replace happened at index 0; list length unchanged.
        match &app.screen {
            Screen::ConditionsBuilder {
                pending,
                edit_index,
                ..
            } => {
                assert_eq!(
                    pending.len(),
                    1,
                    "list length must be unchanged after replace"
                );
                let expected = PolicyCondition::Classification {
                    op: "eq".to_string(),
                    value: Classification::T4,
                };
                assert_eq!(
                    pending[0], expected,
                    "condition at index 0 must be replaced"
                );
                assert_eq!(*edit_index, None, "edit_index must be cleared after commit");
            }
            other => panic!("expected ConditionsBuilder, got {other:?}"),
        }
    }

    #[test]
    fn edit_cancel_preserves_condition() {
        use dlp_common::abac::PolicyCondition;
        use dlp_common::Classification;

        let original = PolicyCondition::Classification {
            op: "eq".to_string(),
            value: Classification::T3,
        };
        // Set up in edit mode at step 3.
        let mut picker_state = ratatui::widgets::ListState::default();
        picker_state.select(Some(0));

        let screen = Screen::ConditionsBuilder {
            step: 3,
            selected_attribute: Some(ConditionAttribute::Classification),
            selected_operator: Some("eq".to_string()),
            pending: vec![original.clone()],
            buffer: String::new(),
            pending_focused: false,
            pending_state: ratatui::widgets::ListState::default(),
            picker_state,
            caller: CallerScreen::PolicyCreate,
            form_snapshot: PolicyFormState {
                ..Default::default()
            },
            edit_index: Some(0),
        };
        let mut app = make_test_app(screen);

        // Act: Esc at Step 3 goes back to Step 2 without modifying pending.
        let esc_key = KeyEvent::new(KeyCode::Esc, crossterm::event::KeyModifiers::NONE);
        handle_conditions_step3_select(&mut app, esc_key, ConditionAttribute::Classification, "eq");

        // Assert: pending is untouched; step retreated to 2.
        match &app.screen {
            Screen::ConditionsBuilder {
                pending,
                step,
                edit_index,
                ..
            } => {
                assert_eq!(pending.len(), 1, "pending list must be unchanged");
                assert_eq!(pending[0], original, "original condition must be preserved");
                assert_eq!(*step, 2, "step must retreat to 2 on Esc");
                // edit_index is NOT cleared by Esc — it persists until commit or modal close.
                assert_eq!(*edit_index, Some(0), "edit_index survives Esc");
            }
            other => panic!("expected ConditionsBuilder, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Import / Export actions
// ---------------------------------------------------------------------------

/// Opens a native save dialog and writes the full policy set as JSON.
///
/// D-03 / D-04 / D-05 from Phase 17 context.
/// Uses `GET /policies` -> `serde_json::to_string_pretty` -> `rfd::FileDialog::save_file`.
fn action_export_policies(app: &mut App) {
    let policies_result = app
        .rt
        .block_on(app.client.get::<Vec<serde_json::Value>>("policies"));

    let policies = match policies_result {
        Ok(p) => p,
        Err(e) => {
            app.set_status(format!("Failed to fetch policies: {e}"), StatusKind::Error);
            return;
        }
    };

    let json = match serde_json::to_string_pretty(&policies) {
        Ok(j) => j,
        Err(e) => {
            app.set_status(
                format!("Failed to serialize policies: {e}"),
                StatusKind::Error,
            );
            return;
        }
    };

    // Build default filename: policies-export-{YYYY-MM-DD}.json
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let default_name = format!("policies-export-{today}.json");

    let save_path = rfd::FileDialog::new()
        .set_title("Export Policies")
        .add_filter("JSON Files", &["json"])
        .set_file_name(&default_name)
        .save_file();

    let file_path = match save_path {
        Some(p) => p,
        None => {
            // User cancelled -- no error, just return to PolicyMenu.
            return;
        }
    };

    // Write in a blocking task to avoid blocking the async runtime.
    let write_result = std::fs::write(&file_path, json);

    match write_result {
        Ok(()) => {
            app.set_status(
                format!(
                    "Exported {} policies to {}",
                    policies.len(),
                    file_path.display()
                ),
                StatusKind::Success,
            );
        }
        Err(e) => {
            app.set_status(format!("Failed to write file: {e}"), StatusKind::Error);
        }
    }
}

/// Opens a file-open dialog, parses the selected JSON, and transitions to
/// `Screen::ImportConfirm` for conflict review.
///
/// D-07 / D-08 / D-09 / D-13 from Phase 17 context.
fn action_import_policies(app: &mut App) {
    let file_path = rfd::FileDialog::new()
        .set_title("Import Policies")
        .add_filter("JSON Files", &["json"])
        .pick_file();

    let file_path = match file_path {
        Some(p) => p,
        None => {
            // User cancelled -- no error, just return to PolicyMenu.
            return;
        }
    };

    // Read and parse JSON in a blocking task.
    let read_result = std::fs::read_to_string(&file_path);
    let json_str = match read_result {
        Ok(s) => s,
        Err(e) => {
            app.set_status(
                format!("Failed to read file {}: {e}", file_path.display()),
                StatusKind::Error,
            );
            return;
        }
    };

    let imported: Vec<crate::app::PolicyResponse> = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => {
            app.set_status(format!("Failed to parse JSON file: {e}"), StatusKind::Error);
            return;
        }
    };

    // Fetch existing IDs for conflict detection (authenticated endpoint).
    let existing_result = app
        .rt
        .block_on(app.client.get::<Vec<serde_json::Value>>("policies"));

    let (existing_ids, conflicting_count, non_conflicting_count) = match existing_result {
        Ok(existing) => {
            let ids: Vec<String> = existing
                .iter()
                .filter_map(|p| p["id"].as_str().map(String::from))
                .collect();
            let conflict = imported.iter().filter(|p| ids.contains(&p.id)).count();
            let non_conflict = imported.len() - conflict;
            (ids, conflict, non_conflict)
        }
        Err(e) => {
            app.set_status(
                format!("Could not fetch current policies: {e}"),
                StatusKind::Error,
            );
            return;
        }
    };

    app.screen = Screen::ImportConfirm {
        policies: imported,
        existing_ids,
        conflicting_count,
        non_conflicting_count,
        selected: 3, // Start on [Confirm] row
        state: ImportState::Pending,
        caller: ImportCaller::PolicyMenu,
    };
}

// ---------------------------------------------------------------------------
// ImportConfirm screen handler
// ---------------------------------------------------------------------------

/// Handles key events for the `Screen::ImportConfirm` variant.
///
/// Navigation: Up/Down cycles only between rows 3 ([Confirm]) and 4 ([Cancel]).
/// Enter on row 3 -> execute import (POST new policies, PUT conflicting policies).
/// Enter on row 4 / Esc -> return to PolicyMenu.
///
/// Import execution (per Phase 17 D-09, D-11, D-17, D-18, D-19):
/// - POST non-conflicting policies (IDs not on server).
/// - PUT conflicting policies (IDs already on server).
/// - Abort on first failure with per-policy error message.
/// - Transitions to ImportState::Success { created, updated } on success,
///   ImportState::Error(msg) on failure.
fn handle_import_confirm(app: &mut App, key: KeyEvent) {
    use crate::app::{PolicyPayload, PolicyResponse};

    let caller = match &app.screen {
        Screen::ImportConfirm { caller, .. } => *caller,
        _ => return,
    };

    // Outside Pending, only Enter/Esc dismiss the screen.
    if !matches!(
        app.screen,
        Screen::ImportConfirm {
            state: ImportState::Pending,
            ..
        }
    ) {
        if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
            let return_to = match caller {
                ImportCaller::PolicyMenu => Screen::PolicyMenu { selected: 0 },
            };
            app.screen = return_to;
        }
        return;
    }

    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::ImportConfirm { selected, .. } = &mut app.screen {
                *selected = if *selected == 3 { 4 } else { 3 };
            }
        }
        KeyCode::Esc => {
            let return_to = match caller {
                ImportCaller::PolicyMenu => Screen::PolicyMenu { selected: 0 },
            };
            app.screen = return_to;
        }
        KeyCode::Enter => {
            // Determine which button is active.
            let selected = match &app.screen {
                Screen::ImportConfirm { selected, .. } => *selected,
                _ => return,
            };

            if selected != 3 {
                // [Cancel] pressed.
                let return_to = match caller {
                    ImportCaller::PolicyMenu => Screen::PolicyMenu { selected: 0 },
                };
                app.screen = return_to;
                return;
            }

            // [Confirm] pressed — extract execution state.
            let (policies, existing_ids): (Vec<PolicyResponse>, Vec<String>) = match &app.screen {
                Screen::ImportConfirm {
                    policies,
                    existing_ids,
                    ..
                } => (policies.clone(), existing_ids.clone()),
                _ => return,
            };

            // Transition to InProgress immediately so UI reflects working state.
            if let Screen::ImportConfirm { state, .. } = &mut app.screen {
                *state = ImportState::InProgress;
            }

            // Partition into POST (new) and PUT (existing) using O(1) HashSet lookup.
            let existing_set: std::collections::HashSet<String> =
                existing_ids.into_iter().collect();
            let (to_create, to_update): (Vec<PolicyResponse>, Vec<PolicyResponse>) = policies
                .into_iter()
                .partition(|p| !existing_set.contains(&p.id));

            let mut created = 0usize;
            let mut updated = 0usize;

            // POST non-conflicting policies.
            for policy in to_create {
                let name = policy.name.clone();
                let payload: PolicyPayload = policy.into();
                let result = app.rt.block_on(
                    app.client
                        .post::<serde_json::Value, _>("admin/policies", &payload),
                );
                match result {
                    Ok(_) => created += 1,
                    Err(e) => {
                        if let Screen::ImportConfirm { state, .. } = &mut app.screen {
                            *state = ImportState::Error(format!("Failed on policy '{name}': {e}"));
                        }
                        return;
                    }
                }
            }

            // PUT conflicting policies.
            for policy in to_update {
                let name = policy.name.clone();
                let id = policy.id.clone();
                let payload: PolicyPayload = policy.into();
                let path = format!("admin/policies/{id}");
                let result = app
                    .rt
                    .block_on(app.client.put::<serde_json::Value, _>(&path, &payload));
                match result {
                    Ok(_) => updated += 1,
                    Err(e) => {
                        if let Screen::ImportConfirm { state, .. } = &mut app.screen {
                            *state = ImportState::Error(format!("Failed on policy '{name}': {e}"));
                        }
                        return;
                    }
                }
            }

            // All succeeded — invalidate cache and show summary.
            if let Screen::ImportConfirm { state, .. } = &mut app.screen {
                *state = ImportState::Success { created, updated };
            }
        }
        _ => {}
    }
}
