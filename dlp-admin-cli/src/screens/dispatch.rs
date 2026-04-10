//! Key-event dispatch for each [`Screen`] variant.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use crate::app::{
    App, ConfirmPurpose, InputPurpose, PasswordPurpose, Screen, StatusKind,
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
        // Read-only views: Enter or Esc goes back.
        Screen::PolicyDetail { .. }
        | Screen::ServerStatus { .. }
        | Screen::ResultView { .. } => handle_view(app, key),
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
                app.screen = Screen::TextInput {
                    prompt: "JSON file path".to_string(),
                    input: String::new(),
                    purpose: InputPurpose::CreatePolicyFromFile,
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
        KeyCode::Up | KeyCode::Down => nav(selected, 4, key.code),
        KeyCode::Enter => match *selected {
            0 => action_server_status(app),
            1 => action_agent_list(app),
            2 => action_load_siem_config(app),
            3 => app.screen = Screen::MainMenu { selected: 2 },
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
        KeyCode::Backspace => { input.pop(); }
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
        KeyCode::Backspace => { input.pop(); }
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
    match app.rt.block_on(app.client.get::<Vec<serde_json::Value>>("policies")) {
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
        let _resp: serde_json::Value =
            app.rt.block_on(app.client.post("policies", &payload))?;
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
        let _resp: serde_json::Value =
            app.rt.block_on(app.client.put(&path, &payload))?;
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
    match app.rt.block_on(app.client.put::<serde_json::Value, _>("auth/password", &payload)) {
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
        let hash = bcrypt::hash(password, 12)
            .map_err(|e| anyhow::anyhow!("bcrypt hash failed: {e}"))?;
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
    match app
        .rt
        .block_on(app.client.put::<serde_json::Value, _>(
            "admin/siem-config",
            &payload,
        )) {
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
            if let Screen::SiemConfig {
                selected: sel, ..
            } = &mut app.screen
            {
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
                    *buffer = config[key_name]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
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
