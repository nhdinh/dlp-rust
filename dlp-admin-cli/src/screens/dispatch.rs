//! Key-event dispatch for each [`Screen`] variant.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use crate::app::{
    App, CallerScreen, ConditionAttribute, ConfirmPurpose, ImportCaller, ImportState, InputPurpose,
    PasswordPurpose, PolicyFormState, Screen, SimulateCaller, SimulateFormState, SimulateOutcome,
    StatusKind, TierPickerCaller, UsbScanEntry, ACTION_OPTIONS, ATTRIBUTES, LDAP_BACK_ROW,
    LDAP_ROW_COUNT, LDAP_SAVE_ROW,
};
use crate::event::AppEvent;
use crate::screens::cloud_config::{
    CLOUD_CONFIG_BACK_ROW, CLOUD_CONFIG_KEYS, CLOUD_CONFIG_ROW_COUNT, CLOUD_CONFIG_SAVE_ROW,
};
use crate::screens::print_config::{
    is_print_bool, is_print_numeric, is_print_picker, PRINT_CONFIG_BACK_ROW, PRINT_CONFIG_KEYS,
    PRINT_CONFIG_ROW_COUNT, PRINT_CONFIG_SAVE_ROW, PRINT_UNCLASSIFIABLE_OPTIONS,
};
use crate::screens::usb_enforcement::{
    USB_ENFORCEMENT_BACK_ROW, USB_ENFORCEMENT_KEYS, USB_ENFORCEMENT_OPTIONS,
    USB_ENFORCEMENT_ROW_COUNT, USB_ENFORCEMENT_SAVE_ROW,
};
use dlp_common::abac::PolicyMode;

/// Routes an event to the handler for the current screen.
pub fn handle_event(app: &mut App, event: AppEvent) {
    let key = match event {
        AppEvent::Key(k) => {
            // In headless test mode (TestBackend) KeyEventKind is not set to
            // Press, so accept all kinds.  In production (CrosstermBackend)
            // only Press events are meaningful.
            if cfg!(test) || k.kind == KeyEventKind::Press {
                k
            } else {
                return;
            }
        }
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
        Screen::LdapConfig { .. } => handle_ldap_config(app, key),
        Screen::UsbEnforcementConfig { .. } => handle_usb_enforcement_config(app, key),
        Screen::CloudConfig { .. } => handle_cloud_config(app, key),
        Screen::PrintConfig { .. } => handle_print_config(app, key),
        Screen::ConditionsBuilder { .. } => handle_conditions_builder(app, key),
        Screen::PolicyCreate { .. } => handle_policy_create(app, key),
        Screen::PolicyEdit { .. } => handle_policy_edit(app, key),
        Screen::PolicySimulate { .. } => handle_policy_simulate(app, key),
        Screen::ImportConfirm { .. } => handle_import_confirm(app, key),
        Screen::DevicesMenu { .. } => handle_devices_menu(app, key),
        Screen::DeviceList { .. } => handle_device_list(app, key),
        Screen::DeviceTierPicker { .. } => handle_device_tier_picker(app, key),
        Screen::ManagedOriginList { .. } => handle_managed_origin_list(app, key),
        Screen::DiskRegistryList { .. } => handle_disk_registry_list(app, key),
        Screen::UsbScan { .. } => handle_usb_scan(app, key),
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
        // Updated from 5 to 6 items: added "Devices & Origins" at index 3.
        KeyCode::Up | KeyCode::Down => nav(selected, 6, key.code),
        KeyCode::Enter => match *selected {
            0 => app.screen = Screen::PasswordMenu { selected: 0 },
            1 => app.screen = Screen::PolicyMenu { selected: 0 },
            2 => app.screen = Screen::SystemMenu { selected: 0 },
            3 => app.screen = Screen::DevicesMenu { selected: 0 },
            4 => action_open_simulate(app, SimulateCaller::MainMenu),
            5 => app.should_quit = true,
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
        // Phase 43.05: expanded from 6 to 7 items — added "USB Enforcement" at index 5.
        // Phase 38.2: expanded from 7 to 9 items — added "Cloud Config" at index 6, "Print Config" at index 7.
        KeyCode::Up | KeyCode::Down => nav(selected, 9, key.code),
        KeyCode::Enter => match *selected {
            0 => action_server_status(app),
            1 => action_agent_list(app),
            2 => action_load_siem_config(app),
            3 => action_load_alert_config(app),
            4 => action_load_ldap_config(app),
            5 => action_load_usb_enforcement_config(app),
            6 => action_load_cloud_config(app),
            7 => action_load_print_config(app),
            8 => app.screen = Screen::MainMenu { selected: 2 },
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
            // Serial number and description are optional fields in the device register chain;
            // they are allowed to be empty. All other text inputs require a non-empty value.
            let allow_empty = matches!(
                purpose,
                InputPurpose::RegisterDeviceSerial { .. }
                    | InputPurpose::RegisterDeviceDescription { .. }
                    | InputPurpose::RegisterDeviceOwnerSid { .. }
                    | InputPurpose::RegisterDeviceOwnerUser { .. }
            );
            if value.is_empty() && !allow_empty {
                app.set_status("Input cannot be empty", StatusKind::Error);
                return;
            }
            on_text_confirmed(app, &value, purpose);
        }
        KeyCode::Esc => {
            // Return to the contextually appropriate parent screen.
            app.screen = match &purpose {
                InputPurpose::RegisterDeviceVid
                | InputPurpose::RegisterDevicePid { .. }
                | InputPurpose::RegisterDeviceSerial { .. }
                | InputPurpose::RegisterDeviceDescription { .. }
                | InputPurpose::RegisterDeviceOwnerSid { .. }
                | InputPurpose::RegisterDeviceOwnerUser { .. } => {
                    Screen::DevicesMenu { selected: 0 }
                }
                InputPurpose::AddManagedOrigin => Screen::DevicesMenu { selected: 1 },
                InputPurpose::AddDiskRegistryAgentId
                | InputPurpose::AddDiskRegistryInstanceId { .. }
                | InputPurpose::AddDiskRegistryBusType { .. }
                | InputPurpose::AddDiskRegistryEncryption { .. }
                | InputPurpose::AddDiskRegistryModel { .. } => Screen::DevicesMenu { selected: 3 },
                _ => Screen::PolicyMenu { selected: 0 },
            };
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
        // Device register sequential chain: each step carries accumulated fields forward.
        InputPurpose::RegisterDeviceVid => {
            app.screen = Screen::TextInput {
                prompt: "PID (hex, e.g. 1666):".to_string(),
                input: String::new(),
                purpose: InputPurpose::RegisterDevicePid {
                    vid: value.to_string(),
                },
            };
        }
        InputPurpose::RegisterDevicePid { vid } => {
            app.screen = Screen::TextInput {
                prompt: "Serial number (or press Enter to skip):".to_string(),
                input: String::new(),
                purpose: InputPurpose::RegisterDeviceSerial {
                    vid,
                    pid: value.to_string(),
                },
            };
        }
        InputPurpose::RegisterDeviceSerial { vid, pid } => {
            app.screen = Screen::TextInput {
                prompt: "Description (optional):".to_string(),
                input: String::new(),
                purpose: InputPurpose::RegisterDeviceDescription {
                    vid,
                    pid,
                    serial: value.to_string(),
                },
            };
        }
        InputPurpose::RegisterDeviceDescription { vid, pid, serial } => {
            app.screen = Screen::TextInput {
                prompt: "Owner SID (optional, press Enter to skip):".to_string(),
                input: String::new(),
                purpose: InputPurpose::RegisterDeviceOwnerSid {
                    vid,
                    pid,
                    serial,
                    description: value.to_string(),
                },
            };
        }
        InputPurpose::RegisterDeviceOwnerSid {
            vid,
            pid,
            serial,
            description,
        } => {
            app.screen = Screen::TextInput {
                prompt: "Owner User (optional, press Enter to skip):".to_string(),
                input: String::new(),
                purpose: InputPurpose::RegisterDeviceOwnerUser {
                    vid,
                    pid,
                    serial,
                    description,
                    owner_sid: value.to_string(),
                },
            };
        }
        InputPurpose::RegisterDeviceOwnerUser {
            vid,
            pid,
            serial,
            description,
            owner_sid,
        } => {
            let owner_sid_opt = if owner_sid.is_empty() {
                None
            } else {
                Some(owner_sid)
            };
            let owner_user_opt = if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            };
            app.screen = Screen::DeviceTierPicker {
                vid,
                pid,
                serial,
                description,
                owner_sid: owner_sid_opt,
                owner_user: owner_user_opt,
                selected: 0,
                caller: TierPickerCaller::DeviceList,
            };
        }
        InputPurpose::AddManagedOrigin => {
            let body = serde_json::json!({ "origin": value });
            match app.rt.block_on(
                app.client
                    .post::<serde_json::Value, _>("admin/managed-origins", &body),
            ) {
                Ok(_) => {
                    app.set_status("Managed origin added.", StatusKind::Success);
                    action_load_managed_origin_list(app);
                }
                Err(e) => {
                    app.set_status(format!("Error adding origin: {e}"), StatusKind::Error);
                    app.screen = Screen::DevicesMenu { selected: 1 };
                }
            }
        }
        // -- Disk registry 5-field add flow: each step chains to the next prompt --
        InputPurpose::AddDiskRegistryAgentId => {
            app.screen = Screen::TextInput {
                prompt: "Instance ID:".to_string(),
                input: String::new(),
                purpose: InputPurpose::AddDiskRegistryInstanceId {
                    agent_id: value.to_string(),
                },
            };
        }
        InputPurpose::AddDiskRegistryInstanceId { agent_id } => {
            app.screen = Screen::TextInput {
                prompt: "Bus type (usb/sata/nvme/scsi/unknown):".to_string(),
                input: String::new(),
                purpose: InputPurpose::AddDiskRegistryBusType {
                    agent_id: agent_id.clone(),
                    instance_id: value.to_string(),
                },
            };
        }
        InputPurpose::AddDiskRegistryBusType {
            agent_id,
            instance_id,
        } => {
            app.screen = Screen::TextInput {
                prompt: "Encryption status (encrypted/suspended/unencrypted/unknown):".to_string(),
                input: String::new(),
                purpose: InputPurpose::AddDiskRegistryEncryption {
                    agent_id: agent_id.clone(),
                    instance_id: instance_id.clone(),
                    bus_type: value.to_string(),
                },
            };
        }
        InputPurpose::AddDiskRegistryEncryption {
            agent_id,
            instance_id,
            bus_type,
        } => {
            app.screen = Screen::TextInput {
                prompt: "Model (or leave empty):".to_string(),
                input: String::new(),
                purpose: InputPurpose::AddDiskRegistryModel {
                    agent_id: agent_id.clone(),
                    instance_id: instance_id.clone(),
                    bus_type: bus_type.clone(),
                    encryption_status: value.to_string(),
                },
            };
        }
        InputPurpose::AddDiskRegistryModel {
            agent_id,
            instance_id,
            bus_type,
            encryption_status,
        } => {
            let body = serde_json::json!({
                "agent_id": agent_id,
                "instance_id": instance_id,
                "bus_type": bus_type,
                "encryption_status": encryption_status,
                "model": value,
            });
            match app.rt.block_on(
                app.client
                    .post::<serde_json::Value, _>("admin/disk-registry", &body),
            ) {
                Ok(_) => {
                    app.set_status("Disk registry entry added.", StatusKind::Success);
                    action_load_disk_registry_list(app);
                }
                Err(e) => {
                    app.set_status(format!("Error adding disk entry: {e}"), StatusKind::Error);
                    app.screen = Screen::DevicesMenu { selected: 3 };
                }
            }
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
            on_confirm_yes(app, &purpose);
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            on_confirm_cancel(app, &purpose);
        }
        KeyCode::Enter => {
            if *yes_selected {
                on_confirm_yes(app, &purpose);
            } else {
                on_confirm_cancel(app, &purpose);
            }
        }
        _ => {}
    }
}

/// Executes the confirmed action for the given purpose.
fn on_confirm_yes(app: &mut App, purpose: &ConfirmPurpose) {
    match purpose {
        ConfirmPurpose::DeletePolicy { id } => action_delete_policy(app, id),
        ConfirmPurpose::DeleteDevice { id } => action_delete_device(app, id),
        ConfirmPurpose::DeleteManagedOrigin { id } => action_delete_managed_origin(app, id),
        ConfirmPurpose::DeleteDiskRegistry { id } => action_delete_disk_registry(app, id),
    }
}

/// Navigates back to the appropriate parent screen on cancel/no.
fn on_confirm_cancel(app: &mut App, purpose: &ConfirmPurpose) {
    match purpose {
        // Policy delete cancel: stay on PolicyList (D-17).
        ConfirmPurpose::DeletePolicy { .. } => action_list_policies(app),
        // Device/origin delete cancel: return to the respective list.
        ConfirmPurpose::DeleteDevice { .. } => action_load_device_list(app),
        ConfirmPurpose::DeleteManagedOrigin { .. } => action_load_managed_origin_list(app),
        ConfirmPurpose::DeleteDiskRegistry { .. } => action_load_disk_registry_list(app),
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

/// Commits a numeric buffer value to the Alert config field at `selected`.
fn alert_commit_numeric(app: &mut App, selected: usize) {
    let buffer_copy = match &app.screen {
        Screen::AlertConfig { buffer, .. } => buffer.clone(),
        _ => return,
    };
    let port = match buffer_copy.trim().parse::<u16>() {
        Ok(p) => p,
        Err(_) => {
            app.set_status("SMTP port must be a number in 0..=65535", StatusKind::Error);
            return;
        }
    };
    if let Screen::AlertConfig {
        config,
        buffer,
        editing,
        ..
    } = &mut app.screen
    {
        let key_name = ALERT_KEYS[selected];
        config[key_name] = serde_json::Value::Number(serde_json::Number::from(port));
        buffer.clear();
        *editing = false;
    }
}

/// Commits a string buffer value to the Alert config field at `selected`.
fn alert_commit_string(app: &mut App, selected: usize) {
    if let Screen::AlertConfig {
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

/// Cancels editing mode for the Alert config form.
fn alert_cancel_edit(app: &mut App) {
    if let Screen::AlertConfig {
        buffer, editing, ..
    } = &mut app.screen
    {
        buffer.clear();
        *editing = false;
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
            if alert_is_numeric(selected) {
                alert_commit_numeric(app, selected);
            } else {
                alert_commit_string(app, selected);
            }
        }
        KeyCode::Esc => alert_cancel_edit(app),
        _ => {}
    }
}

/// Toggles a boolean field in the Alert config at `selected`.
fn alert_toggle_bool(app: &mut App, selected: usize) {
    if let Screen::AlertConfig { config, .. } = &mut app.screen {
        let key_name = ALERT_KEYS[selected];
        let cur = config[key_name].as_bool().unwrap_or(false);
        config[key_name] = serde_json::Value::Bool(!cur);
    }
}

/// Enters numeric edit mode for the Alert config field at `selected`.
fn alert_enter_numeric_edit(app: &mut App, selected: usize) {
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
}

/// Enters string edit mode for the Alert config field at `selected`.
fn alert_enter_string_edit(app: &mut App, selected: usize) {
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

/// Handles Enter key in Alert config navigation.
fn alert_nav_enter(app: &mut App, selected: usize) {
    if selected == ALERT_SAVE_ROW {
        action_save_alert_config(app);
        return;
    }
    if selected == ALERT_TEST_ROW {
        action_test_alert_config(app);
        return;
    }
    if selected == ALERT_BACK_ROW {
        app.screen = Screen::SystemMenu { selected: 3 };
        return;
    }
    if alert_is_bool(selected) {
        alert_toggle_bool(app, selected);
        return;
    }
    if alert_is_numeric(selected) {
        alert_enter_numeric_edit(app, selected);
        return;
    }
    alert_enter_string_edit(app, selected);
}

/// Handles key events while navigating the Alert config form.
fn handle_alert_config_nav(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::AlertConfig { selected: sel, .. } = &mut app.screen {
                nav(sel, ALERT_ROW_COUNT, key.code);
            }
        }
        KeyCode::Enter => alert_nav_enter(app, selected),
        KeyCode::Esc => {
            app.screen = Screen::SystemMenu { selected: 3 };
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// LDAP Config screen (Phase 38.1)
// ---------------------------------------------------------------------------

/// JSON keys for the LDAP config form, indexed by row (5 editable fields).
///
/// Must match `LdapConfigPayload` field names in `dlp-server/src/admin_api.rs`
/// exactly so the PUT round-trip deserializes.
const LDAP_KEYS: [&str; 5] = [
    "ldap_url",
    "base_dn",
    "require_tls",
    "cache_ttl_secs",
    "vpn_subnets",
];

/// Returns `true` if the row index is the boolean `require_tls` toggle.
fn ldap_is_bool(index: usize) -> bool {
    matches!(index, 2)
}

/// Returns `true` if the row index is the numeric `cache_ttl_secs` field.
fn ldap_is_numeric(index: usize) -> bool {
    matches!(index, 3)
}

/// Fetches the current LDAP config from the server and switches to the
/// `LdapConfig` screen.
///
/// Mirrors the Phase 3.1 SIEM / Phase 28 Alert pattern: uses the generic
/// `client.get::<serde_json::Value>` helper rather than a typed wrapper.
fn action_load_ldap_config(app: &mut App) {
    match app
        .rt
        .block_on(app.client.get::<serde_json::Value>("admin/ldap-config"))
    {
        Ok(config) => {
            app.screen = Screen::LdapConfig {
                config,
                selected: 0,
                editing: false,
                buffer: String::new(),
            };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Persists the in-memory LDAP config to the server.
///
/// On success, returns the user to the SystemMenu with the LDAP Config row
/// (index 4) highlighted.
fn action_save_ldap_config(app: &mut App) {
    let payload = match &app.screen {
        Screen::LdapConfig { config, .. } => config.clone(),
        _ => return,
    };
    match app.rt.block_on(
        app.client
            .put::<serde_json::Value, _>("admin/ldap-config", &payload),
    ) {
        Ok(_) => {
            app.set_status("LDAP config saved", StatusKind::Success);
            app.screen = Screen::SystemMenu { selected: 4 };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Handles key events while the LDAP config form is active.
fn handle_ldap_config(app: &mut App, key: KeyEvent) {
    let (selected, editing) = match &app.screen {
        Screen::LdapConfig {
            selected, editing, ..
        } => (*selected, *editing),
        _ => return,
    };

    if editing {
        handle_ldap_config_editing(app, key, selected);
    } else {
        handle_ldap_config_nav(app, key, selected);
    }
}

/// Handles key events while editing a text/numeric field in the LDAP config form.
///
/// The numeric branch (row 3, `cache_ttl_secs`) parses the buffer as `u64` and
/// rejects any value outside the inclusive range [60, 3600]. On parse failure
/// or out-of-range, the function sets a status error and stays in edit mode so
/// the user can correct the value without losing input.
fn handle_ldap_config_editing(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Char(c) => {
            if let Screen::LdapConfig { buffer, .. } = &mut app.screen {
                buffer.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Screen::LdapConfig { buffer, .. } = &mut app.screen {
                buffer.pop();
            }
        }
        KeyCode::Enter => {
            if ldap_is_numeric(selected) {
                ldap_commit_numeric(app, selected);
            } else {
                ldap_commit_string(app, selected);
            }
        }
        KeyCode::Esc => ldap_cancel_edit(app),
        _ => {}
    }
}

/// Commits a numeric buffer value to the LDAP config field at `selected`.
fn ldap_commit_numeric(app: &mut App, selected: usize) {
    let buffer_copy = match &app.screen {
        Screen::LdapConfig { buffer, .. } => buffer.clone(),
        _ => return,
    };
    let ttl = match buffer_copy.trim().parse::<u64>() {
        Ok(v) if (60..=3600).contains(&v) => v,
        _ => {
            app.set_status(
                "Cache TTL must be between 60 and 3600 seconds",
                StatusKind::Error,
            );
            return;
        }
    };
    if let Screen::LdapConfig {
        config,
        buffer,
        editing,
        ..
    } = &mut app.screen
    {
        let key_name = LDAP_KEYS[selected];
        config[key_name] = serde_json::Value::Number(serde_json::Number::from(ttl));
        buffer.clear();
        *editing = false;
    }
}

/// Commits a string buffer value to the LDAP config field at `selected`.
fn ldap_commit_string(app: &mut App, selected: usize) {
    if let Screen::LdapConfig {
        config,
        buffer,
        editing,
        ..
    } = &mut app.screen
    {
        let key_name = LDAP_KEYS[selected];
        config[key_name] = serde_json::Value::String(buffer.clone());
        buffer.clear();
        *editing = false;
    }
}

/// Cancels editing mode for the LDAP config form.
fn ldap_cancel_edit(app: &mut App) {
    if let Screen::LdapConfig {
        buffer, editing, ..
    } = &mut app.screen
    {
        buffer.clear();
        *editing = false;
    }
}

/// Toggles a boolean field in the LDAP config at `selected`.
fn ldap_toggle_bool(app: &mut App, selected: usize) {
    if let Screen::LdapConfig { config, .. } = &mut app.screen {
        let key_name = LDAP_KEYS[selected];
        let cur = config[key_name].as_bool().unwrap_or(false);
        config[key_name] = serde_json::Value::Bool(!cur);
    }
}

/// Enters numeric edit mode for the LDAP config field at `selected`.
fn ldap_enter_numeric_edit(app: &mut App, selected: usize) {
    if let Screen::LdapConfig {
        config,
        editing,
        buffer,
        ..
    } = &mut app.screen
    {
        let key_name = LDAP_KEYS[selected];
        let n = config[key_name].as_u64().unwrap_or(300);
        *buffer = n.to_string();
        *editing = true;
    }
}

/// Enters string edit mode for the LDAP config field at `selected`.
fn ldap_enter_string_edit(app: &mut App, selected: usize) {
    if let Screen::LdapConfig {
        config,
        editing,
        buffer,
        ..
    } = &mut app.screen
    {
        let key_name = LDAP_KEYS[selected];
        *buffer = config[key_name].as_str().unwrap_or("").to_string();
        *editing = true;
    }
}

/// Handles Enter key in LDAP config navigation.
fn ldap_nav_enter(app: &mut App, selected: usize) {
    if selected == LDAP_SAVE_ROW {
        action_save_ldap_config(app);
        return;
    }
    if selected == LDAP_BACK_ROW {
        app.screen = Screen::SystemMenu { selected: 4 };
        return;
    }
    if ldap_is_bool(selected) {
        ldap_toggle_bool(app, selected);
        return;
    }
    if ldap_is_numeric(selected) {
        ldap_enter_numeric_edit(app, selected);
        return;
    }
    ldap_enter_string_edit(app, selected);
}

/// Handles key events while navigating the LDAP config form.
fn handle_ldap_config_nav(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::LdapConfig { selected: sel, .. } = &mut app.screen {
                nav(sel, LDAP_ROW_COUNT, key.code);
            }
        }
        KeyCode::Enter => ldap_nav_enter(app, selected),
        KeyCode::Esc => {
            app.screen = Screen::SystemMenu { selected: 4 };
        }
        _ => {}
    }
}

#[cfg(test)]
mod ldap_config_tests {
    use super::*;

    #[test]
    fn ldap_keys_match_payload_field_order() {
        assert_eq!(LDAP_KEYS.len(), 5);
        assert_eq!(LDAP_KEYS[0], "ldap_url");
        assert_eq!(LDAP_KEYS[1], "base_dn");
        assert_eq!(LDAP_KEYS[2], "require_tls");
        assert_eq!(LDAP_KEYS[3], "cache_ttl_secs");
        assert_eq!(LDAP_KEYS[4], "vpn_subnets");
    }

    #[test]
    fn ldap_row_constants_are_consistent() {
        assert_eq!(LDAP_ROW_COUNT, 7);
        assert_eq!(LDAP_SAVE_ROW, 5);
        assert_eq!(LDAP_BACK_ROW, 6);
        assert!(LDAP_SAVE_ROW < LDAP_ROW_COUNT);
        assert!(LDAP_BACK_ROW < LDAP_ROW_COUNT);
    }

    #[test]
    fn ldap_is_bool_only_matches_require_tls_row() {
        for i in 0..LDAP_ROW_COUNT {
            assert_eq!(ldap_is_bool(i), i == 2);
        }
    }

    #[test]
    fn ldap_is_numeric_only_matches_cache_ttl_row() {
        for i in 0..LDAP_ROW_COUNT {
            assert_eq!(ldap_is_numeric(i), i == 3);
        }
    }
}

// ---------------------------------------------------------------------------
// USB enforcement config screen
// ---------------------------------------------------------------------------

/// Fetches the current agent config from the server and switches to the
/// `UsbEnforcementConfig` screen.
fn action_load_usb_enforcement_config(app: &mut App) {
    match app
        .rt
        .block_on(app.client.get::<serde_json::Value>("admin/agent-config"))
    {
        Ok(config) => {
            app.screen = Screen::UsbEnforcementConfig {
                config,
                selected: 0,
                editing: false,
                buffer: String::new(),
            };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Persists the in-memory USB enforcement config to the server.
///
/// Sends the FULL agent config payload (not just USB fields) because
/// the server PUT /admin/agent-config expects the complete payload.
/// NOTE: This is the existing pattern for all config screens. A TOCTOU
/// risk exists: if another admin changes a different field between load
/// and save, this screen will overwrite it with the stale value. This is
/// a pre-existing design limitation, not introduced by this plan.
fn action_save_usb_enforcement_config(app: &mut App) {
    let payload = match &app.screen {
        Screen::UsbEnforcementConfig { config, .. } => config.clone(),
        _ => return,
    };
    match app.rt.block_on(
        app.client
            .put::<serde_json::Value, _>("admin/agent-config", &payload),
    ) {
        Ok(_) => {
            app.set_status("USB enforcement config saved", StatusKind::Success);
            app.screen = Screen::SystemMenu { selected: 5 };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Handles key events while the USB enforcement config form is active.
fn handle_usb_enforcement_config(app: &mut App, key: KeyEvent) {
    let (selected, editing) = match &app.screen {
        Screen::UsbEnforcementConfig {
            selected, editing, ..
        } => (*selected, *editing),
        _ => return,
    };

    if editing {
        handle_usb_enforcement_editing(app, key, selected);
    } else {
        handle_usb_enforcement_nav(app, key, selected);
    }
}

/// Handles key events while editing a picker field in the USB enforcement config form.
fn handle_usb_enforcement_editing(app: &mut App, key: KeyEvent, selected: usize) {
    if selected >= USB_ENFORCEMENT_KEYS.len() {
        return; // Save/Back rows don't enter edit mode
    }

    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::UsbEnforcementConfig { config, .. } = &mut app.screen {
                let key_name = USB_ENFORCEMENT_KEYS[selected];
                let current = config.get(key_name).and_then(|v| v.as_str()).unwrap_or("");
                let options = USB_ENFORCEMENT_OPTIONS[selected];
                let current_idx = options.iter().position(|&o| o == current).unwrap_or(0);
                let new_idx = match key.code {
                    KeyCode::Up => current_idx.checked_sub(1).unwrap_or(options.len() - 1),
                    _ => (current_idx + 1) % options.len(),
                };
                config[key_name] = serde_json::Value::String(options[new_idx].to_string());
            }
        }
        KeyCode::Enter => {
            if let Screen::UsbEnforcementConfig { editing, .. } = &mut app.screen {
                *editing = false;
            }
        }
        KeyCode::Esc => {
            if let Screen::UsbEnforcementConfig { editing, .. } = &mut app.screen {
                *editing = false;
            }
        }
        _ => {}
    }
}

/// Handles key events while navigating the USB enforcement config form.
fn handle_usb_enforcement_nav(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::UsbEnforcementConfig { selected: s, .. } = &mut app.screen {
                nav(s, USB_ENFORCEMENT_ROW_COUNT, key.code);
            }
        }
        KeyCode::Enter => match selected {
            0..=2 => {
                // Enter edit mode for picker fields
                if let Screen::UsbEnforcementConfig { editing, .. } = &mut app.screen {
                    *editing = true;
                }
            }
            USB_ENFORCEMENT_SAVE_ROW => action_save_usb_enforcement_config(app),
            USB_ENFORCEMENT_BACK_ROW => {
                app.screen = Screen::SystemMenu { selected: 5 };
            }
            _ => {}
        },
        KeyCode::Esc => {
            app.screen = Screen::SystemMenu { selected: 5 };
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Cloud config screen
// ---------------------------------------------------------------------------

/// Fetches the current agent config from the server and switches to the `CloudConfig` screen.
fn action_load_cloud_config(app: &mut App) {
    match app
        .rt
        .block_on(app.client.get::<serde_json::Value>("admin/agent-config"))
    {
        Ok(config) => {
            app.screen = Screen::CloudConfig {
                config,
                selected: 0,
                editing: false,
                buffer: String::new(),
            };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Persists the in-memory cloud config to the server (full payload round-trip).
fn action_save_cloud_config(app: &mut App) {
    let payload = match &app.screen {
        Screen::CloudConfig { config, .. } => config.clone(),
        _ => return,
    };
    match app.rt.block_on(
        app.client
            .put::<serde_json::Value, _>("admin/agent-config", &payload),
    ) {
        Ok(_) => {
            app.set_status("Cloud config saved", StatusKind::Success);
            app.screen = Screen::SystemMenu { selected: 6 };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Handles key events while the cloud config form is active.
///
/// `cloud_hook_enabled` (row 0) is a bool that toggles on Enter — no edit mode required.
fn handle_cloud_config(app: &mut App, key: KeyEvent) {
    let selected = match &app.screen {
        Screen::CloudConfig { selected, .. } => *selected,
        _ => return,
    };

    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::CloudConfig { selected: sel, .. } = &mut app.screen {
                nav(sel, CLOUD_CONFIG_ROW_COUNT, key.code);
            }
        }
        KeyCode::Enter => match selected {
            0 => {
                // Toggle the boolean field in-place.
                if let Screen::CloudConfig { config, .. } = &mut app.screen {
                    let key_name = CLOUD_CONFIG_KEYS[0];
                    let cur = config[key_name].as_bool().unwrap_or(false);
                    config[key_name] = serde_json::Value::Bool(!cur);
                }
            }
            CLOUD_CONFIG_SAVE_ROW => action_save_cloud_config(app),
            CLOUD_CONFIG_BACK_ROW => {
                app.screen = Screen::SystemMenu { selected: 6 };
            }
            _ => {}
        },
        KeyCode::Esc => {
            app.screen = Screen::SystemMenu { selected: 6 };
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Print config screen
// ---------------------------------------------------------------------------

/// Fetches the current agent config from the server and switches to the `PrintConfig` screen.
fn action_load_print_config(app: &mut App) {
    match app
        .rt
        .block_on(app.client.get::<serde_json::Value>("admin/agent-config"))
    {
        Ok(config) => {
            app.screen = Screen::PrintConfig {
                config,
                selected: 0,
                editing: false,
                buffer: String::new(),
            };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Persists the in-memory print config to the server (full payload round-trip).
fn action_save_print_config(app: &mut App) {
    let payload = match &app.screen {
        Screen::PrintConfig { config, .. } => config.clone(),
        _ => return,
    };
    match app.rt.block_on(
        app.client
            .put::<serde_json::Value, _>("admin/agent-config", &payload),
    ) {
        Ok(_) => {
            app.set_status("Print config saved", StatusKind::Success);
            app.screen = Screen::SystemMenu { selected: 7 };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

/// Handles key events while the print config form is in edit mode.
fn handle_print_config_editing(app: &mut App, key: KeyEvent, selected: usize) {
    if is_print_numeric(selected) {
        match key.code {
            KeyCode::Char(c) => {
                if let Screen::PrintConfig { buffer, .. } = &mut app.screen {
                    buffer.push(c);
                }
            }
            KeyCode::Backspace => {
                if let Screen::PrintConfig { buffer, .. } = &mut app.screen {
                    buffer.pop();
                }
            }
            KeyCode::Enter => print_commit_numeric(app, selected),
            KeyCode::Esc => {
                if let Screen::PrintConfig {
                    buffer, editing, ..
                } = &mut app.screen
                {
                    buffer.clear();
                    *editing = false;
                }
            }
            _ => {}
        }
    } else if is_print_picker(selected) {
        match key.code {
            KeyCode::Up | KeyCode::Down => {
                if let Screen::PrintConfig { config, .. } = &mut app.screen {
                    let key_name = PRINT_CONFIG_KEYS[selected];
                    let current = config.get(key_name).and_then(|v| v.as_str()).unwrap_or("");
                    let options = PRINT_UNCLASSIFIABLE_OPTIONS;
                    let current_idx = options.iter().position(|&o| o == current).unwrap_or(0);
                    let new_idx = match key.code {
                        KeyCode::Up => current_idx.checked_sub(1).unwrap_or(options.len() - 1),
                        _ => (current_idx + 1) % options.len(),
                    };
                    config[key_name] = serde_json::Value::String(options[new_idx].to_string());
                }
            }
            KeyCode::Enter | KeyCode::Esc => {
                if let Screen::PrintConfig { editing, .. } = &mut app.screen {
                    *editing = false;
                }
            }
            _ => {}
        }
    }
}

/// Commits a numeric buffer to the print config field at `selected`.
fn print_commit_numeric(app: &mut App, selected: usize) {
    let buffer_copy = match &app.screen {
        Screen::PrintConfig { buffer, .. } => buffer.clone(),
        _ => return,
    };
    let value: u64 = match buffer_copy.trim().parse() {
        Ok(v) => v,
        Err(_) => {
            app.set_status("Value must be a positive integer", StatusKind::Error);
            return;
        }
    };
    if let Screen::PrintConfig {
        config,
        buffer,
        editing,
        ..
    } = &mut app.screen
    {
        let key_name = PRINT_CONFIG_KEYS[selected];
        config[key_name] = serde_json::Value::Number(serde_json::Number::from(value));
        buffer.clear();
        *editing = false;
    }
}

/// Handles key events while navigating the print config form.
fn handle_print_config_nav(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::PrintConfig { selected: sel, .. } = &mut app.screen {
                nav(sel, PRINT_CONFIG_ROW_COUNT, key.code);
            }
        }
        KeyCode::Enter => {
            if selected == PRINT_CONFIG_SAVE_ROW {
                action_save_print_config(app);
                return;
            }
            if selected == PRINT_CONFIG_BACK_ROW {
                app.screen = Screen::SystemMenu { selected: 7 };
                return;
            }
            if is_print_bool(selected) {
                // Toggle the boolean in-place.
                if let Screen::PrintConfig { config, .. } = &mut app.screen {
                    let key_name = PRINT_CONFIG_KEYS[selected];
                    let cur = config[key_name].as_bool().unwrap_or(false);
                    config[key_name] = serde_json::Value::Bool(!cur);
                }
                return;
            }
            if is_print_numeric(selected) {
                // Enter numeric edit mode, seeding the buffer with the current value.
                if let Screen::PrintConfig {
                    config,
                    editing,
                    buffer,
                    ..
                } = &mut app.screen
                {
                    let key_name = PRINT_CONFIG_KEYS[selected];
                    let n = config[key_name].as_u64().unwrap_or(0);
                    *buffer = n.to_string();
                    *editing = true;
                }
                return;
            }
            if is_print_picker(selected) {
                // Enter picker edit mode.
                if let Screen::PrintConfig { editing, .. } = &mut app.screen {
                    *editing = true;
                }
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::SystemMenu { selected: 7 };
        }
        _ => {}
    }
}

/// Handles key events while the print config form is active.
fn handle_print_config(app: &mut App, key: KeyEvent) {
    let (selected, editing) = match &app.screen {
        Screen::PrintConfig {
            selected, editing, ..
        } => (*selected, *editing),
        _ => return,
    };

    if editing {
        handle_print_config_editing(app, key, selected);
    } else {
        handle_print_config_nav(app, key, selected);
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

/// Transitions to ConditionsBuilder from PolicyCreate.
fn policy_create_open_conditions(app: &mut App) {
    let form = match &app.screen {
        Screen::PolicyCreate { form, .. } => form.clone(),
        _ => return,
    };
    let mut picker_state = ratatui::widgets::ListState::default();
    picker_state.select(Some(0));
    app.screen = Screen::ConditionsBuilder {
        step: 1,
        selected_attribute: None,
        selected_field: None,
        selected_operator: None,
        pending: form.conditions.clone(),
        buffer: String::new(),
        pending_focused: false,
        pending_state: ratatui::widgets::ListState::default(),
        picker_state,
        caller: CallerScreen::PolicyCreate,
        form_snapshot: PolicyFormState {
            conditions: vec![],
            ..form
        },
        edit_index: None,
        edit_picker_prefill: None,
    };
}

/// Handles Enter key in PolicyCreate navigation.
fn policy_create_nav_enter(app: &mut App, selected: usize) {
    match selected {
        POLICY_SAVE_ROW => {
            let form = match &app.screen {
                Screen::PolicyCreate { form, .. } => form.clone(),
                _ => return,
            };
            action_submit_policy(app, form);
        }
        POLICY_ENABLED_ROW => {
            if let Screen::PolicyCreate { form, .. } = &mut app.screen {
                form.enabled = !form.enabled;
            }
        }
        POLICY_MODE_ROW => {
            if let Screen::PolicyCreate { form, .. } = &mut app.screen {
                form.mode = cycle_mode(form.mode);
            }
        }
        POLICY_ADD_CONDITIONS_ROW => policy_create_open_conditions(app),
        POLICY_ACTION_ROW => {
            if let Screen::PolicyCreate { form, .. } = &mut app.screen {
                form.action = (form.action + 1) % ACTION_OPTIONS.len();
            }
        }
        POLICY_CONDITIONS_DISPLAY_ROW => {}
        _ => policy_create_enter_edit(app, selected),
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
        KeyCode::Enter => policy_create_nav_enter(app, selected),
        KeyCode::Char(' ') if selected == POLICY_MODE_ROW => {
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

/// Enters edit mode for a text field in PolicyCreate.
fn policy_create_enter_edit(app: &mut App, selected: usize) {
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
            _ => return,
        };
        *buffer = pre_fill;
        *editing = true;
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

/// Transitions to ConditionsBuilder from PolicyEdit.
fn policy_edit_open_conditions(app: &mut App) {
    let form = match &app.screen {
        Screen::PolicyEdit { form, .. } => form.clone(),
        _ => return,
    };
    let mut picker_state = ratatui::widgets::ListState::default();
    picker_state.select(Some(0));
    app.screen = Screen::ConditionsBuilder {
        step: 1,
        selected_attribute: None,
        selected_field: None,
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
        edit_picker_prefill: None,
    };
}

/// Enters edit mode for a text field in PolicyEdit.
fn policy_edit_enter_edit(app: &mut App, selected: usize) {
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

/// Handles Enter key in PolicyEdit navigation.
fn policy_edit_nav_enter(app: &mut App, selected: usize) {
    match selected {
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
        POLICY_ADD_CONDITIONS_ROW => policy_edit_open_conditions(app),
        POLICY_CONDITIONS_DISPLAY_ROW => {}
        _ => policy_edit_enter_edit(app, selected),
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
        KeyCode::Enter => policy_edit_nav_enter(app, selected),
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
        ..Default::default()
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
            // Cancel edit: clear the in-progress buffer and exit edit mode.
            // Clearing ensures stale input is never silently re-used if the user
            // re-enters edit mode on a different field before committing (WR-04 fix).
            if let Screen::PolicySimulate {
                editing, buffer, ..
            } = &mut app.screen
            {
                buffer.clear();
                *editing = false;
            }
        }
        _ => {}
    }
}

/// Cycles a simulate form select field by index.
fn simulate_cycle_field(app: &mut App, selected: usize) {
    if let Screen::PolicySimulate { form, .. } = &mut app.screen {
        match selected {
            3 => {
                form.device_trust =
                    (form.device_trust + 1) % crate::app::SIMULATE_DEVICE_TRUST_OPTIONS.len();
            }
            4 => {
                form.network_location = (form.network_location + 1)
                    % crate::app::SIMULATE_NETWORK_LOCATION_OPTIONS.len();
            }
            6 => {
                form.classification =
                    (form.classification + 1) % crate::app::SIMULATE_CLASSIFICATION_OPTIONS.len();
            }
            7 => {
                form.action = (form.action + 1) % crate::app::SIMULATE_ACTION_OPTIONS.len();
            }
            8 => {
                form.access_context =
                    (form.access_context + 1) % crate::app::SIMULATE_ACCESS_CONTEXT_OPTIONS.len();
            }
            _ => {}
        }
    }
}

/// Enters edit mode for a simulate form text field.
fn simulate_enter_text_edit(app: &mut App, selected: usize) {
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

/// Returns to the caller screen from PolicySimulate.
fn simulate_return_to_caller(app: &mut App) {
    let caller = match &app.screen {
        Screen::PolicySimulate { caller, .. } => *caller,
        _ => return,
    };
    match caller {
        SimulateCaller::MainMenu => app.screen = Screen::MainMenu { selected: 3 },
        SimulateCaller::PolicyMenu => app.screen = Screen::PolicyMenu { selected: 5 },
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
            0 | 1 | 5 => simulate_enter_text_edit(app, selected),
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
            3 | 4 | 6 | 7 | 8 => simulate_cycle_field(app, selected),
            9 => action_submit_simulate(app),
            _ => {}
        },
        KeyCode::Esc | KeyCode::Char('q') => simulate_return_to_caller(app),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Conditions builder
// ---------------------------------------------------------------------------

/// Returns the operator list (wire string + enforcement flag) valid for the given attribute.
///
/// For `SourceApplication` and `DestinationApplication`, the operator set depends on the
/// selected `AppField`: Publisher/ImagePath support `contains`; TrustTier does not.
/// Pass `None` for `field` on initial sub-step entry (before field selection) to get the
/// conservative eq/ne set.
///
/// Per D-08: DeviceTrust, NetworkLocation, AccessContext get `neq` added.
/// Per D-10: each attribute's list is fixed; the Step 2 picker auto-sizes to the count.
/// Display labels are: "equals" (eq), "not equals" (neq), "greater than" (gt),
/// "less than" (lt), "contains" (contains).
///
/// # Arguments
///
/// * `attr` - The condition attribute being built.
/// * `field` - For app-identity attributes: which AppField was selected in the sub-step.
///   For other attributes this parameter is ignored (pass `None`).
pub(crate) fn operators_for(
    attr: ConditionAttribute,
    field: Option<dlp_common::abac::AppField>,
) -> &'static [(&'static str, bool)] {
    use dlp_common::abac::AppField;
    match attr {
        ConditionAttribute::Classification => {
            &[("eq", true), ("neq", true), ("gt", true), ("lt", true)]
        }
        ConditionAttribute::MemberOf => &[("eq", true), ("neq", true), ("contains", true)],
        ConditionAttribute::DeviceTrust => &[("eq", true), ("neq", true)],
        ConditionAttribute::NetworkLocation => &[("eq", true), ("neq", true)],
        ConditionAttribute::AccessContext => &[("eq", true), ("neq", true)],
        ConditionAttribute::SourceApplication | ConditionAttribute::DestinationApplication => {
            match field {
                Some(AppField::Publisher)
                | Some(AppField::ImagePath)
                | Some(AppField::Aumid)
                | Some(AppField::PackageFamilyName) => {
                    // String fields support equality, inequality, and substring matching.
                    &[("eq", true), ("ne", true), ("contains", true)]
                }
                // TrustTier is an enum value — contains doesn't apply.
                // None means sub-step not yet resolved; conservative set is safe.
                Some(AppField::TrustTier) | None => &[("eq", true), ("ne", true)],
            }
        }
        ConditionAttribute::SourceOrigin | ConditionAttribute::DestinationOrigin => {
            // Origin URL conditions support equality, inequality, and substring matching.
            &[("eq", true), ("ne", true), ("contains", true)]
        }
    }
}

/// Returns the number of value options for Step 3 per attribute.
///
/// Used to bound navigation and for `ListState` range checks.
/// `MemberOf` returns 0 because it uses free-text input, not a select list.
/// For app-identity attributes, `TrustTier` returns 3 (picker); Publisher/ImagePath
/// return 0 (free-text input). Pass `None` when field is not yet resolved — returns 0.
///
/// # Arguments
///
/// * `attr` - The condition attribute being built.
/// * `field` - For app-identity attributes: which AppField was selected in the sub-step.
///   Ignored for other attributes.
fn value_count_for(attr: ConditionAttribute, field: Option<dlp_common::abac::AppField>) -> usize {
    use dlp_common::abac::AppField;
    match attr {
        ConditionAttribute::Classification => 4,  // T1, T2, T3, T4
        ConditionAttribute::MemberOf => 0,        // text input, not a list
        ConditionAttribute::DeviceTrust => 4,     // Managed, Unmanaged, Compliant, Unknown
        ConditionAttribute::NetworkLocation => 4, // Corporate, CorporateVpn, Guest, Unknown
        ConditionAttribute::AccessContext => 2,   // Local, Smb
        ConditionAttribute::SourceApplication | ConditionAttribute::DestinationApplication => {
            match field {
                Some(AppField::TrustTier) => 3, // trusted / untrusted / unknown picker
                _ => 0,                         // Publisher / ImagePath: free-text input
            }
        }
        ConditionAttribute::SourceOrigin | ConditionAttribute::DestinationOrigin => 0, // text input
    }
}

/// Constructs a `PolicyCondition` from the selected attribute, operator, picker index, and buffer.
///
/// Returns `None` if the picker index is out of range, the MemberOf buffer is empty,
/// or an app-identity attribute is provided without a resolved `field` (T-28-02-01 mitigated
/// by the `field?` early-return, which prevents a malformed condition from being constructed).
///
/// # Field name note
///
/// `MemberOf` uses `group_sid: String`, NOT `value`. All other variants use `value`.
///
/// # Arguments
///
/// * `attr` - Condition attribute to build.
/// * `op` - Operator wire string (e.g. `"eq"`, `"ne"`, `"contains"`).
/// * `picker_selected` - 0-based index into the Step 3 value picker list.
/// * `buffer` - Free-text input for MemberOf and app-identity Publisher/ImagePath fields.
/// * `field` - For `SourceApplication`/`DestinationApplication`: the AppField selected in the
///   sub-step. `None` causes an early return of `None` (fail-closed, per T-28-02-01).
///
/// Builds a Classification condition from picker index.
fn build_classification_condition(
    op: String,
    picker_selected: usize,
) -> Option<dlp_common::abac::PolicyCondition> {
    use dlp_common::Classification;
    let value = match picker_selected {
        0 => Classification::T1,
        1 => Classification::T2,
        2 => Classification::T3,
        3 => Classification::T4,
        _ => return None,
    };
    Some(dlp_common::abac::PolicyCondition::Classification { op, value })
}

/// Builds a DeviceTrust condition from picker index.
fn build_device_trust_condition(
    op: String,
    picker_selected: usize,
) -> Option<dlp_common::abac::PolicyCondition> {
    use dlp_common::abac::DeviceTrust;
    let value = match picker_selected {
        0 => DeviceTrust::Managed,
        1 => DeviceTrust::Unmanaged,
        2 => DeviceTrust::Compliant,
        3 => DeviceTrust::Unknown,
        _ => return None,
    };
    Some(dlp_common::abac::PolicyCondition::DeviceTrust { op, value })
}

/// Builds a NetworkLocation condition from picker index.
fn build_network_location_condition(
    op: String,
    picker_selected: usize,
) -> Option<dlp_common::abac::PolicyCondition> {
    use dlp_common::abac::NetworkLocation;
    let value = match picker_selected {
        0 => NetworkLocation::Corporate,
        1 => NetworkLocation::CorporateVpn,
        2 => NetworkLocation::Guest,
        3 => NetworkLocation::Unknown,
        _ => return None,
    };
    Some(dlp_common::abac::PolicyCondition::NetworkLocation { op, value })
}

/// Builds an AccessContext condition from picker index.
fn build_access_context_condition(
    op: String,
    picker_selected: usize,
) -> Option<dlp_common::abac::PolicyCondition> {
    use dlp_common::abac::AccessContext;
    let value = match picker_selected {
        0 => AccessContext::Local,
        1 => AccessContext::Smb,
        _ => return None,
    };
    Some(dlp_common::abac::PolicyCondition::AccessContext { op, value })
}

/// Builds an app-identity condition value from field and picker/buffer.
fn build_app_value(
    field: dlp_common::abac::AppField,
    picker_selected: usize,
    buffer: &str,
) -> Option<String> {
    use dlp_common::abac::AppField;
    match field {
        AppField::TrustTier => Some(match picker_selected {
            0 => "trusted".to_string(),
            1 => "untrusted".to_string(),
            _ => "unknown".to_string(),
        }),
        AppField::Publisher
        | AppField::ImagePath
        | AppField::Aumid
        | AppField::PackageFamilyName => {
            let v = buffer.trim().to_string();
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }
    }
}

/// Builds a SourceApplication or DestinationApplication condition.
fn build_app_condition(
    attr: ConditionAttribute,
    op: String,
    picker_selected: usize,
    buffer: &str,
    field: Option<dlp_common::abac::AppField>,
) -> Option<dlp_common::abac::PolicyCondition> {
    let f = field?;
    let value = build_app_value(f, picker_selected, buffer)?;
    match attr {
        ConditionAttribute::SourceApplication => {
            Some(dlp_common::abac::PolicyCondition::SourceApplication {
                field: f,
                op,
                value,
            })
        }
        ConditionAttribute::DestinationApplication => {
            Some(dlp_common::abac::PolicyCondition::DestinationApplication {
                field: f,
                op,
                value,
            })
        }
        _ => None,
    }
}

/// Builds an origin condition from buffer text.
fn build_origin_condition(
    attr: ConditionAttribute,
    op: String,
    buffer: &str,
) -> Option<dlp_common::abac::PolicyCondition> {
    let v = buffer.trim().to_string();
    if v.is_empty() {
        return None;
    }
    match attr {
        ConditionAttribute::SourceOrigin => {
            Some(dlp_common::abac::PolicyCondition::SourceOrigin { op, value: v })
        }
        ConditionAttribute::DestinationOrigin => {
            Some(dlp_common::abac::PolicyCondition::DestinationOrigin { op, value: v })
        }
        _ => None,
    }
}

/// Constructs a `PolicyCondition` from the selected attribute, operator, picker index, and buffer.
///
/// Returns `None` if the picker index is out of range, the MemberOf buffer is empty,
/// or an app-identity attribute is provided without a resolved `field` (T-28-02-01 mitigated
/// by the `field?` early-return, which prevents a malformed condition from being constructed).
///
/// # Field name note
///
/// `MemberOf` uses `group_sid: String`, NOT `value`. All other variants use `value`.
///
/// # Arguments
///
/// * `attr` - Condition attribute to build.
/// * `op` - Operator wire string (e.g. `"eq"`, `"ne"`, `"contains"`).
/// * `picker_selected` - 0-based index into the Step 3 value picker list.
/// * `buffer` - Free-text input for MemberOf and app-identity Publisher/ImagePath fields.
/// * `field` - For `SourceApplication`/`DestinationApplication`: the AppField selected in the
///   sub-step. `None` causes an early return of `None` (fail-closed, per T-28-02-01).
fn build_condition(
    attr: ConditionAttribute,
    op: &str,
    picker_selected: usize,
    buffer: &str,
    field: Option<dlp_common::abac::AppField>,
) -> Option<dlp_common::abac::PolicyCondition> {
    let op = op.to_string();
    match attr {
        ConditionAttribute::Classification => build_classification_condition(op, picker_selected),
        ConditionAttribute::MemberOf => {
            if buffer.trim().is_empty() {
                return None;
            }
            Some(dlp_common::abac::PolicyCondition::MemberOf {
                op,
                group_sid: buffer.trim().to_string(),
            })
        }
        ConditionAttribute::DeviceTrust => build_device_trust_condition(op, picker_selected),
        ConditionAttribute::NetworkLocation => {
            build_network_location_condition(op, picker_selected)
        }
        ConditionAttribute::AccessContext => build_access_context_condition(op, picker_selected),
        ConditionAttribute::SourceApplication | ConditionAttribute::DestinationApplication => {
            build_app_condition(attr, op, picker_selected, buffer, field)
        }
        ConditionAttribute::SourceOrigin | ConditionAttribute::DestinationOrigin => {
            build_origin_condition(attr, op, buffer)
        }
    }
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
///
/// Maps a Classification value to its picker index.
fn classification_to_idx(value: &dlp_common::Classification) -> usize {
    match value {
        dlp_common::Classification::T1 => 0,
        dlp_common::Classification::T2 => 1,
        dlp_common::Classification::T3 => 2,
        dlp_common::Classification::T4 => 3,
    }
}

/// Maps a DeviceTrust value to its picker index.
fn device_trust_to_idx(value: &dlp_common::abac::DeviceTrust) -> usize {
    match value {
        dlp_common::abac::DeviceTrust::Managed => 0,
        dlp_common::abac::DeviceTrust::Unmanaged => 1,
        dlp_common::abac::DeviceTrust::Compliant => 2,
        dlp_common::abac::DeviceTrust::Unknown => 3,
    }
}

/// Maps a NetworkLocation value to its picker index.
fn network_location_to_idx(value: &dlp_common::abac::NetworkLocation) -> usize {
    match value {
        dlp_common::abac::NetworkLocation::Corporate => 0,
        dlp_common::abac::NetworkLocation::CorporateVpn => 1,
        dlp_common::abac::NetworkLocation::Guest => 2,
        dlp_common::abac::NetworkLocation::Unknown => 3,
    }
}

/// Maps an AccessContext value to its picker index.
fn access_context_to_idx(value: &dlp_common::abac::AccessContext) -> usize {
    match value {
        dlp_common::abac::AccessContext::Local => 0,
        dlp_common::abac::AccessContext::Smb => 1,
    }
}

/// Maps a TrustTier string to its picker index.
fn trust_tier_to_idx(value: &str) -> usize {
    match value {
        "trusted" => 0,
        "untrusted" => 1,
        _ => 2,
    }
}

/// Maps an AppField to its (picker_idx, buffer) prefill values.
fn app_field_to_prefill(field: &dlp_common::abac::AppField, value: &str) -> (usize, String) {
    use dlp_common::abac::AppField;
    match field {
        AppField::Publisher
        | AppField::ImagePath
        | AppField::Aumid
        | AppField::PackageFamilyName => (0usize, value.to_string()),
        AppField::TrustTier => (trust_tier_to_idx(value), String::new()),
    }
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
    use dlp_common::abac::PolicyCondition;
    match cond {
        PolicyCondition::Classification { op, value } => (
            ConditionAttribute::Classification,
            op.clone(),
            classification_to_idx(value),
            String::new(),
        ),
        PolicyCondition::MemberOf { op, group_sid } => (
            ConditionAttribute::MemberOf,
            op.clone(),
            0,
            group_sid.clone(),
        ),
        PolicyCondition::DeviceTrust { op, value } => (
            ConditionAttribute::DeviceTrust,
            op.clone(),
            device_trust_to_idx(value),
            String::new(),
        ),
        PolicyCondition::NetworkLocation { op, value } => (
            ConditionAttribute::NetworkLocation,
            op.clone(),
            network_location_to_idx(value),
            String::new(),
        ),
        PolicyCondition::AccessContext { op, value } => (
            ConditionAttribute::AccessContext,
            op.clone(),
            access_context_to_idx(value),
            String::new(),
        ),
        PolicyCondition::SourceApplication { field, op, value } => {
            let (picker_idx, buffer) = app_field_to_prefill(field, value);
            (
                ConditionAttribute::SourceApplication,
                op.clone(),
                picker_idx,
                buffer,
            )
        }
        PolicyCondition::DestinationApplication { field, op, value } => {
            let (picker_idx, buffer) = app_field_to_prefill(field, value);
            (
                ConditionAttribute::DestinationApplication,
                op.clone(),
                picker_idx,
                buffer,
            )
        }
        PolicyCondition::SourceOrigin { op, value } => (
            ConditionAttribute::SourceOrigin,
            op.clone(),
            0,
            value.clone(),
        ),
        PolicyCondition::DestinationOrigin { op, value } => (
            ConditionAttribute::DestinationOrigin,
            op.clone(),
            0,
            value.clone(),
        ),
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
        PolicyCondition::SourceApplication { field, op, value } => {
            format!("SourceApplication {field:?} {op} {value}")
        }
        PolicyCondition::DestinationApplication { field, op, value } => {
            format!("DestinationApplication {field:?} {op} {value}")
        }
        PolicyCondition::SourceOrigin { op, value } => {
            format!("SourceOrigin {op} {value}")
        }
        PolicyCondition::DestinationOrigin { op, value } => {
            format!("DestinationOrigin {op} {value}")
        }
    }
}

/// Handles key events for the conditions builder modal overlay.
///
/// Uses the two-phase read-then-mutate pattern: read scalar flags with a shared
/// borrow first, then mutate with `if let Screen::ConditionsBuilder { .. } = &mut app.screen`.
fn handle_conditions_builder(app: &mut App, key: KeyEvent) {
    // Phase 1: read scalar state with a shared borrow to avoid borrow conflicts.
    let (step, pending_focused, selected_attribute, selected_field, selected_operator, pending_len) =
        match &app.screen {
            Screen::ConditionsBuilder {
                step,
                pending_focused,
                selected_attribute,
                selected_field,
                selected_operator,
                pending,
                ..
            } => (
                *step,
                *pending_focused,
                *selected_attribute,
                *selected_field,
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
            2 => handle_conditions_step2(app, key, selected_attribute, selected_field),
            3 => handle_conditions_step3(
                app,
                key,
                selected_attribute,
                selected_field,
                selected_operator.as_deref(),
            ),
            _ => {}
        }
    }
}

/// Navigates the pending conditions list up or down.
fn pending_nav(app: &mut App, pending_len: usize, key: KeyCode) {
    if pending_len == 0 {
        return;
    }
    if let Screen::ConditionsBuilder { pending_state, .. } = &mut app.screen {
        let current = pending_state.selected().unwrap_or(0);
        let new_idx = match key {
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

/// Deletes the selected condition from the pending list.
fn pending_delete(app: &mut App) {
    if let Screen::ConditionsBuilder {
        pending,
        pending_state,
        ..
    } = &mut app.screen
    {
        let Some(idx) = pending_state.selected() else {
            return;
        };
        if idx >= pending.len() {
            return;
        }
        pending.remove(idx);
        if pending.is_empty() {
            pending_state.select(None);
        } else if idx >= pending.len() {
            pending_state.select(Some(pending.len() - 1));
        }
    }
}

/// Extracts the AppField from an app-identity condition for prefill.
fn app_field_from_condition(
    cond: &dlp_common::abac::PolicyCondition,
) -> Option<dlp_common::abac::AppField> {
    match cond {
        dlp_common::abac::PolicyCondition::SourceApplication { field, .. }
        | dlp_common::abac::PolicyCondition::DestinationApplication { field, .. } => Some(*field),
        _ => None,
    }
}

/// Opens the selected condition for editing in the 3-step picker.
fn pending_edit(app: &mut App) {
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
    let prefill_field = app_field_from_condition(&cond);
    let attr_idx = ATTRIBUTES.iter().position(|a| *a == attr).unwrap_or(0);

    if let Screen::ConditionsBuilder {
        step,
        selected_attribute,
        selected_field,
        selected_operator,
        buffer,
        edit_index,
        edit_picker_prefill,
        pending_focused,
        picker_state,
        ..
    } = &mut app.screen
    {
        *step = 1;
        *selected_attribute = Some(attr);
        *selected_field = prefill_field;
        *selected_operator = Some(op_str);
        *buffer = buf;
        *edit_index = Some(edit_i);
        *edit_picker_prefill = Some(picker_idx);
        *pending_focused = false;
        picker_state.select(Some(attr_idx.min(ATTRIBUTES.len().saturating_sub(1))));
    }
}

/// Closes the conditions builder modal and returns to the caller screen.
fn pending_close_modal(app: &mut App) {
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

/// Handles key events when the pending conditions list has focus.
fn handle_conditions_pending(app: &mut App, key: KeyEvent, pending_len: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Down => pending_nav(app, pending_len, key.code),
        KeyCode::Char('d') | KeyCode::Char('D') | KeyCode::Delete => pending_delete(app),
        KeyCode::Char('e') | KeyCode::Char('E') => pending_edit(app),
        KeyCode::Esc => pending_close_modal(app),
        _ => {}
    }
}

/// Handles key events at Step 1: attribute selection, and the AppField sub-step.
///
/// The sub-step is active when `step == 1`, `selected_attribute` is `Some(SourceApplication)`
/// or `Some(DestinationApplication)`, and `selected_field` is `None`.
/// The attribute picker is active when `selected_attribute` is `None`.
fn handle_conditions_step1(app: &mut App, key: KeyEvent) {
    // Phase 1: read the sub-step guard flags under a shared borrow.
    let (selected_attribute, selected_field) = match &app.screen {
        Screen::ConditionsBuilder {
            selected_attribute,
            selected_field,
            ..
        } => (*selected_attribute, *selected_field),
        _ => return,
    };

    // Determine whether we are in the AppField sub-step.
    // Sub-step is active when an app-identity attribute is selected but no field is chosen yet.
    let in_sub_step = matches!(
        selected_attribute,
        Some(ConditionAttribute::SourceApplication)
            | Some(ConditionAttribute::DestinationApplication)
    ) && selected_field.is_none();

    if in_sub_step {
        handle_conditions_app_field_sub_step(app, key);
    } else {
        handle_conditions_attribute_picker(app, key);
    }
}

/// The AppField labels shown in picker order:
/// Publisher (0), ImagePath (1), TrustTier (2), AUMID (3), PackageFamilyName (4).
const APP_FIELD_LABELS: [&str; 5] = [
    "publisher",
    "image_path",
    "trust_tier",
    "aumid",
    "package_family_name",
];

/// Maps a picker index to the corresponding [`dlp_common::abac::AppField`].
fn app_field_from_idx(idx: usize) -> dlp_common::abac::AppField {
    use dlp_common::abac::AppField;
    match idx {
        0 => AppField::Publisher,
        1 => AppField::ImagePath,
        2 => AppField::TrustTier,
        3 => AppField::Aumid,
        _ => AppField::PackageFamilyName,
    }
}

/// Handles key events in the AppField sub-picker (Step 1.5).
///
/// Active when `step == 1`, an app-identity attribute is selected, and `selected_field` is `None`.
/// Up/Down navigates the three field options; Enter confirms the field and advances to Step 2;
/// Esc returns to the attribute picker by clearing `selected_attribute`.
fn handle_conditions_app_field_sub_step(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::ConditionsBuilder { picker_state, .. } = &mut app.screen {
                let current = picker_state.selected().unwrap_or(0);
                let new_idx = match key.code {
                    KeyCode::Up => {
                        if current == 0 {
                            APP_FIELD_LABELS.len() - 1
                        } else {
                            current - 1
                        }
                    }
                    KeyCode::Down => (current + 1) % APP_FIELD_LABELS.len(),
                    _ => current,
                };
                picker_state.select(Some(new_idx));
            }
        }
        KeyCode::Enter => {
            // Confirm the AppField selection and advance to Step 2.
            if let Screen::ConditionsBuilder {
                step,
                selected_field,
                selected_operator,
                picker_state,
                ..
            } = &mut app.screen
            {
                let idx = picker_state.selected().unwrap_or(0);
                *selected_field = Some(app_field_from_idx(idx));
                // Clear any stale operator from a previous condition-builder iteration.
                *selected_operator = None;
                *step = 2;
                picker_state.select(Some(0));
            }
        }
        KeyCode::Esc => {
            // Return to the attribute picker: clear the selected attribute so the user
            // can choose a different one.
            if let Screen::ConditionsBuilder {
                selected_attribute,
                picker_state,
                ..
            } = &mut app.screen
            {
                *selected_attribute = None;
                picker_state.select(Some(0));
            }
        }
        _ => {}
    }
}

/// Clears the selected operator if it is not valid for the given attribute and field.
fn clear_stale_operator(
    selected_operator: &mut Option<String>,
    attr: ConditionAttribute,
    field: Option<dlp_common::abac::AppField>,
) {
    if let Some(prev_op) = selected_operator.as_deref() {
        if !operators_for(attr, field)
            .iter()
            .any(|(op, _)| *op == prev_op)
        {
            *selected_operator = None;
        }
    }
}

/// Navigates the attribute picker up or down.
fn attribute_picker_nav(app: &mut App, key: KeyCode) {
    if let Screen::ConditionsBuilder { picker_state, .. } = &mut app.screen {
        let current = picker_state.selected().unwrap_or(0);
        let new_idx = match key {
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

/// Advances from Step 1 attribute picker based on selected attribute type.
fn attribute_picker_advance(app: &mut App) {
    if let Screen::ConditionsBuilder {
        step,
        selected_attribute,
        selected_field,
        selected_operator,
        picker_state,
        ..
    } = &mut app.screen
    {
        let idx = picker_state.selected().unwrap_or(0);
        let attr = ATTRIBUTES
            .get(idx)
            .copied()
            .unwrap_or(ConditionAttribute::Classification);
        *selected_attribute = Some(attr);

        let is_app_identity = matches!(
            attr,
            ConditionAttribute::SourceApplication | ConditionAttribute::DestinationApplication
        );

        if is_app_identity && selected_field.is_some() {
            clear_stale_operator(selected_operator, attr, *selected_field);
            *step = 2;
            picker_state.select(Some(0));
        } else if is_app_identity {
            *selected_operator = None;
            picker_state.select(Some(0));
        } else {
            clear_stale_operator(selected_operator, attr, None);
            *step = 2;
            picker_state.select(Some(0));
        }
    }
}

/// Handles key events at the attribute picker (Step 1, before attribute is selected).
fn handle_conditions_attribute_picker(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Down => attribute_picker_nav(app, key.code),
        KeyCode::Enter => attribute_picker_advance(app),
        KeyCode::Esc => pending_close_modal(app),
        _ => {}
    }
}

/// Handles key events at Step 2: operator selection.
fn handle_conditions_step2(
    app: &mut App,
    key: KeyEvent,
    selected_attribute: Option<ConditionAttribute>,
    selected_field: Option<dlp_common::abac::AppField>,
) {
    let attr = match selected_attribute {
        Some(a) => a,
        None => return,
    };
    // Pass selected_field so app-identity attributes show the field-constrained operator set.
    let ops = operators_for(attr, selected_field);

    match key.code {
        KeyCode::Up | KeyCode::Down => step2_nav(app, ops, key.code),
        KeyCode::Enter => step2_advance(app),
        KeyCode::Esc => step2_go_back(app),
        _ => {}
    }
}

/// Navigates the Step 2 operator picker.
fn step2_nav(app: &mut App, ops: &[(&str, bool)], key: KeyCode) {
    if ops.is_empty() {
        return;
    }
    if let Screen::ConditionsBuilder { picker_state, .. } = &mut app.screen {
        let current = picker_state.selected().unwrap_or(0);
        let new_idx = match key {
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

/// Gets the operator name at the given index for the currently selected attribute.
fn selected_attribute_and_ops(app: &App, idx: usize) -> Option<String> {
    let (attr, field) = match &app.screen {
        Screen::ConditionsBuilder {
            selected_attribute,
            selected_field,
            ..
        } => (*selected_attribute, *selected_field),
        _ => return None,
    };
    let attr = attr?;
    let ops = operators_for(attr, field);
    ops.get(idx).map(|(name, _)| name.to_string())
}

/// Advances from Step 2 to Step 3 with the selected operator.
fn step2_advance(app: &mut App) {
    let idx = match &app.screen {
        Screen::ConditionsBuilder { picker_state, .. } => picker_state.selected().unwrap_or(0),
        _ => return,
    };
    let op_name = match selected_attribute_and_ops(app, idx) {
        Some(name) => name,
        None => return,
    };
    if let Screen::ConditionsBuilder {
        step,
        selected_operator,
        picker_state,
        buffer,
        edit_picker_prefill,
        ..
    } = &mut app.screen
    {
        *selected_operator = Some(op_name);
        *step = 3;
        buffer.clear();
        let prefill = edit_picker_prefill.take().unwrap_or(0);
        picker_state.select(Some(prefill));
    }
}

/// Goes back from Step 2 to Step 1.
fn step2_go_back(app: &mut App) {
    if let Screen::ConditionsBuilder {
        step,
        selected_attribute,
        selected_field,
        selected_operator,
        picker_state,
        ..
    } = &mut app.screen
    {
        *step = 1;
        let is_app_identity = matches!(
            *selected_attribute,
            Some(ConditionAttribute::SourceApplication)
                | Some(ConditionAttribute::DestinationApplication)
        );
        if is_app_identity {
            *selected_field = None;
        } else {
            *selected_attribute = None;
        }
        *selected_operator = None;
        picker_state.select(Some(0));
    }
}

/// Handles key events at Step 3: value selection or text input.
///
/// Routes to the text-input path for `MemberOf` and for app-identity
/// Publisher/ImagePath fields, or the list-select path for all other attributes.
///
/// # Arguments
///
/// * `selected_field` - For app-identity attributes, the AppField chosen in the sub-step.
///   `None` for all other attributes.
fn handle_conditions_step3(
    app: &mut App,
    key: KeyEvent,
    selected_attribute: Option<ConditionAttribute>,
    selected_field: Option<dlp_common::abac::AppField>,
    selected_operator: Option<&str>,
) {
    use dlp_common::abac::AppField;
    let attr = match selected_attribute {
        Some(a) => a,
        None => return,
    };
    let op = match selected_operator {
        Some(o) => o,
        None => return,
    };

    // Use text input for:
    // - MemberOf (AD group SID)
    // - app-identity Publisher, ImagePath, Aumid, or PackageFamilyName (free-text string)
    // - SourceOrigin / DestinationOrigin (origin URL free-text input)
    let use_text_input = attr == ConditionAttribute::MemberOf
        || matches!(
            (attr, selected_field),
            (
                ConditionAttribute::SourceApplication | ConditionAttribute::DestinationApplication,
                Some(AppField::Publisher)
                    | Some(AppField::ImagePath)
                    | Some(AppField::Aumid)
                    | Some(AppField::PackageFamilyName)
            )
        )
        || attr == ConditionAttribute::SourceOrigin
        || attr == ConditionAttribute::DestinationOrigin;

    if use_text_input {
        handle_conditions_step3_text(app, key, attr, op, selected_field);
    } else {
        handle_conditions_step3_select(app, key, attr, op, selected_field);
    }
}

/// Commits a condition from Step 3 and resets the builder state.
fn step3_commit_condition(app: &mut App, cond: dlp_common::abac::PolicyCondition) {
    if let Screen::ConditionsBuilder {
        pending,
        pending_state,
        step,
        selected_attribute,
        selected_field,
        selected_operator,
        buffer,
        picker_state,
        edit_index,
        ..
    } = &mut app.screen
    {
        match *edit_index {
            Some(i) if i < pending.len() => {
                pending[i] = cond;
                pending_state.select(Some(i));
                *edit_index = None;
            }
            _ => {
                pending.push(cond);
                pending_state.select(Some(pending.len() - 1));
            }
        }
        *step = 1;
        *selected_attribute = None;
        *selected_field = None;
        *selected_operator = None;
        buffer.clear();
        picker_state.select(Some(0));
    }
}

/// Goes back from Step 3 to Step 2.
fn step3_go_back(app: &mut App) {
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

/// Navigates the Step 3 value picker.
fn step3_select_nav(app: &mut App, count: usize, key: KeyCode) {
    if count == 0 {
        return;
    }
    if let Screen::ConditionsBuilder { picker_state, .. } = &mut app.screen {
        let current = picker_state.selected().unwrap_or(0);
        let new_idx = match key {
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

/// Handles Step 3 for text-input attributes: MemberOf (AD group SID) and app-identity
/// Publisher/ImagePath fields.
fn handle_conditions_step3_text(
    app: &mut App,
    key: KeyEvent,
    attr: ConditionAttribute,
    op: &str,
    field: Option<dlp_common::abac::AppField>,
) {
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
            let buffer_snapshot = match &app.screen {
                Screen::ConditionsBuilder { buffer, .. } => buffer.clone(),
                _ => return,
            };
            match build_condition(attr, op, 0, &buffer_snapshot, field) {
                Some(cond) => step3_commit_condition(app, cond),
                None => app.set_status("Value cannot be empty", StatusKind::Error),
            }
        }
        KeyCode::Esc => step3_go_back(app),
        _ => {}
    }
}

/// Handles Step 3 for select-based attributes (Classification, DeviceTrust, TrustTier, etc.).
///
/// # Arguments
///
/// * `field` - For app-identity attributes with a `TrustTier` field, the picker shows
///   `trusted/untrusted/unknown`; for other attributes `field` is `None` and ignored.
fn handle_conditions_step3_select(
    app: &mut App,
    key: KeyEvent,
    attr: ConditionAttribute,
    op: &str,
    field: Option<dlp_common::abac::AppField>,
) {
    let count = value_count_for(attr, field);

    match key.code {
        KeyCode::Up | KeyCode::Down => step3_select_nav(app, count, key.code),
        KeyCode::Enter => {
            let picker_idx = match &app.screen {
                Screen::ConditionsBuilder { picker_state, .. } => {
                    picker_state.selected().unwrap_or(0)
                }
                _ => return,
            };
            if let Some(cond) = build_condition(attr, op, picker_idx, "", field) {
                step3_commit_condition(app, cond);
            }
        }
        KeyCode::Esc => step3_go_back(app),
        _ => {}
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
///
/// Returns the caller screen for ImportConfirm.
fn import_confirm_return_screen(caller: ImportCaller) -> Screen {
    match caller {
        ImportCaller::PolicyMenu => Screen::PolicyMenu { selected: 0 },
    }
}

/// Posts a single policy to the server during import.
fn import_post_policy(
    app: &mut App,
    policy: crate::app::PolicyResponse,
) -> Result<(), (String, String)> {
    let name = policy.name.clone();
    let payload: crate::app::PolicyPayload = policy.into();
    match app.rt.block_on(
        app.client
            .post::<serde_json::Value, _>("admin/policies", &payload),
    ) {
        Ok(_) => Ok(()),
        Err(e) => Err((name, e.to_string())),
    }
}

/// Puts a single policy to the server during import.
fn import_put_policy(
    app: &mut App,
    policy: crate::app::PolicyResponse,
) -> Result<(), (String, String)> {
    let name = policy.name.clone();
    let id = policy.id.clone();
    let payload: crate::app::PolicyPayload = policy.into();
    let path = format!("admin/policies/{id}");
    match app
        .rt
        .block_on(app.client.put::<serde_json::Value, _>(&path, &payload))
    {
        Ok(_) => Ok(()),
        Err(e) => Err((name, e.to_string())),
    }
}

/// Executes the import: POST new policies, PUT conflicting ones.
fn import_execute_policies(app: &mut App) {
    use crate::app::PolicyResponse;

    let (policies, existing_ids): (Vec<PolicyResponse>, Vec<String>) = match &app.screen {
        Screen::ImportConfirm {
            policies,
            existing_ids,
            ..
        } => (policies.clone(), existing_ids.clone()),
        _ => return,
    };

    if let Screen::ImportConfirm { state, .. } = &mut app.screen {
        *state = ImportState::InProgress;
    }

    let existing_set: std::collections::HashSet<String> = existing_ids.into_iter().collect();
    let (to_create, to_update): (Vec<PolicyResponse>, Vec<PolicyResponse>) = policies
        .into_iter()
        .partition(|p| !existing_set.contains(&p.id));

    let mut created = 0usize;
    let mut updated = 0usize;

    for policy in to_create {
        match import_post_policy(app, policy) {
            Ok(()) => created += 1,
            Err((name, e)) => {
                if let Screen::ImportConfirm { state, .. } = &mut app.screen {
                    *state = ImportState::Error(format!("Failed on policy '{name}': {e}"));
                }
                return;
            }
        }
    }

    for policy in to_update {
        match import_put_policy(app, policy) {
            Ok(()) => updated += 1,
            Err((name, e)) => {
                if let Screen::ImportConfirm { state, .. } = &mut app.screen {
                    *state = ImportState::Error(format!("Failed on policy '{name}': {e}"));
                }
                return;
            }
        }
    }

    if let Screen::ImportConfirm { state, .. } = &mut app.screen {
        *state = ImportState::Success { created, updated };
    }
}

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
            app.screen = import_confirm_return_screen(caller);
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
            app.screen = import_confirm_return_screen(caller);
        }
        KeyCode::Enter => {
            let selected = match &app.screen {
                Screen::ImportConfirm { selected, .. } => *selected,
                _ => return,
            };

            if selected != 3 {
                app.screen = import_confirm_return_screen(caller);
                return;
            }

            import_execute_policies(app);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Devices & Origins screens
// ---------------------------------------------------------------------------

/// Handles key events for the Devices & Origins submenu.
fn handle_devices_menu(app: &mut App, key: KeyEvent) {
    let selected = match &mut app.screen {
        Screen::DevicesMenu { selected } => selected,
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => nav(selected, 4, key.code),
        KeyCode::Esc => app.screen = Screen::MainMenu { selected: 3 },
        KeyCode::Enter => {
            let idx = *selected;
            match idx {
                0 => action_load_device_list(app),
                1 => action_load_managed_origin_list(app),
                2 => action_open_usb_scan(app),
                3 => action_load_disk_registry_list(app),
                _ => {}
            }
        }
        _ => {}
    }
}

/// Loads the device registry list from the server and navigates to DeviceList.
fn action_load_device_list(app: &mut App) {
    match app.rt.block_on(
        app.client
            .get::<Vec<serde_json::Value>>("admin/device-registry/full"),
    ) {
        Ok(devices) => {
            app.screen = Screen::DeviceList {
                devices,
                selected: 0,
            };
        }
        Err(e) => {
            app.set_status(format!("Error loading devices: {e}"), StatusKind::Error);
        }
    }
}

/// Loads the managed origins list from the server and navigates to ManagedOriginList.
fn action_load_managed_origin_list(app: &mut App) {
    match app.rt.block_on(
        app.client
            .get::<Vec<serde_json::Value>>("admin/managed-origins"),
    ) {
        Ok(origins) => {
            app.screen = Screen::ManagedOriginList {
                origins,
                selected: 0,
            };
        }
        Err(e) => {
            app.set_status(format!("Error loading origins: {e}"), StatusKind::Error);
        }
    }
}

/// Navigates to the USB scan and register screen in its initial empty state.
///
/// The actual concurrent scan is triggered by `r` inside `handle_usb_scan`,
/// which calls [`action_usb_scan`]. This helper exists so DevicesMenu only
/// needs to know the entry point — no async work happens here.
fn action_open_usb_scan(app: &mut App) {
    app.screen = Screen::UsbScan {
        devices: Vec::new(),
        selected: 0,
    };
    app.set_status(
        "Press r to scan for connected USB mass storage devices.",
        StatusKind::Info,
    );
}

/// Builds a `(vid, pid, serial) -> trust_tier` lookup from a JSON array
/// returned by `GET /admin/device-registry/full`.
///
/// Only includes machine-wide entries (where `owner_sid` is null/None).
/// Per-user entries are intentionally excluded because the USB scan screen
/// runs on the admin machine, not the target user's session, so machine-wide
/// entries are the most relevant for cross-referencing locally-connected devices.
///
/// Missing or non-string fields default to empty / `"blocked"` respectively
/// (matches the existing DeviceList parsing convention).
pub(crate) fn build_registry_map(
    registry: &[serde_json::Value],
) -> std::collections::HashMap<(String, String, String), String> {
    let mut map = std::collections::HashMap::new();
    for row in registry {
        // Skip per-user entries: only machine-wide entries matter for the
        // admin-machine USB scan cross-reference.
        if row["owner_sid"].as_str().is_some() {
            continue;
        }
        let vid = row["vid"].as_str().unwrap_or("").to_string();
        let pid = row["pid"].as_str().unwrap_or("").to_string();
        let serial = row["serial"].as_str().unwrap_or("").to_string();
        let tier = row["trust_tier"].as_str().unwrap_or("blocked").to_string();
        map.insert((vid, pid, serial), tier);
    }
    map
}

/// Merges enumerated USB devices with a registry lookup map into the
/// per-row UsbScanEntry vector consumed by `Screen::UsbScan`.
///
/// USB enumeration drives row identity (only locally-present devices show);
/// registry entries supply `registered_tier` when (vid, pid, serial) matches.
pub(crate) fn merge_registry_with_usb(
    registry_map: &std::collections::HashMap<(String, String, String), String>,
    usb_devices: Vec<dlp_common::DeviceIdentity>,
) -> Vec<UsbScanEntry> {
    usb_devices
        .into_iter()
        .map(|identity| {
            let key = (
                identity.vid.clone(),
                identity.pid.clone(),
                identity.serial.clone(),
            );
            let registered_tier = registry_map.get(&key).cloned();
            UsbScanEntry {
                identity,
                registered_tier,
            }
        })
        .collect()
}

/// Formats the status-bar message for a completed USB scan per D-06.
///
/// `total == 0` -> the rescan hint;
/// `total > 0`  -> `"N USB devices found (M already registered)"`.
pub(crate) fn format_usb_scan_status(total: usize, registered: usize) -> String {
    if total == 0 {
        "No USB mass storage devices found. Plug in a device and press r to rescan.".to_string()
    } else {
        format!("{total} USB devices found ({registered} already registered)")
    }
}

/// Runs USB enumeration and registry fetch concurrently, then populates
/// `Screen::UsbScan` with the merged result (per D-11).
///
/// Architecture:
/// - `client.clone()` -> owned by the async block. `EngineClient` is
///   internally `Arc`-backed; clone is O(1).
/// - `tokio::join!` runs both futures concurrently on the existing tokio runtime.
/// - The Win32 SetupDi call is wrapped in `tokio::task::spawn_blocking` so it does
///   not stall the async executor (per Pitfall 2 in 32-RESEARCH.md).
/// - Outer `app.rt.block_on` blocks the synchronous TUI event loop for the
///   duration (~100ms) — acceptable per D-02.
/// - `JoinError` from `spawn_blocking` is treated as an empty result (a panic
///   inside the SetupDi closure should not crash the TUI).
/// - HTTP error: caller sees an `Error` status and an empty-registry merge
///   (USB devices still display, just without registration tier annotations).
fn action_usb_scan(app: &mut App) {
    let client = app.client.clone();
    let (registry_result, usb_join) = app.rt.block_on(async move {
        tokio::join!(
            client.get::<Vec<serde_json::Value>>("admin/device-registry/full"),
            tokio::task::spawn_blocking(dlp_common::usb::enumerate_connected_usb_devices),
        )
    });

    let usb_devices = usb_join.unwrap_or_default();
    let (registry_devices, fetch_error_message): (Vec<serde_json::Value>, Option<String>) =
        match registry_result {
            Ok(rows) => (rows, None),
            Err(e) => (
                Vec::new(),
                Some(format!("Error fetching device registry: {e}")),
            ),
        };

    let registry_map = build_registry_map(&registry_devices);
    let entries = merge_registry_with_usb(&registry_map, usb_devices);

    let registered_count = entries
        .iter()
        .filter(|e| e.registered_tier.is_some())
        .count();
    let total = entries.len();

    // Set status: error wins over the count line so the user sees the failure.
    if let Some(err) = fetch_error_message {
        app.set_status(err, StatusKind::Error);
    } else {
        app.set_status(
            format_usb_scan_status(total, registered_count),
            StatusKind::Info,
        );
    }

    app.screen = Screen::UsbScan {
        devices: entries,
        selected: 0,
    };
}

/// Handles key events for the USB scan and register screen (Phase 32).
///
/// Keybindings:
/// - `r`         — trigger concurrent USB enumeration + registry fetch (D-02)
/// - Up/Down     — navigate the rows (no-op on empty list)
/// - Enter       — open `Screen::DeviceTierPicker` with caller = UsbScan
/// - Esc         — return to DevicesMenu with selected = 2
fn handle_usb_scan(app: &mut App, key: KeyEvent) {
    let devices_len = match &app.screen {
        Screen::UsbScan { devices, .. } => devices.len(),
        _ => return,
    };
    match key.code {
        KeyCode::Char('r') => action_usb_scan(app),
        KeyCode::Up | KeyCode::Down => {
            if devices_len == 0 {
                return;
            }
            if let Screen::UsbScan { selected, .. } = &mut app.screen {
                nav(selected, devices_len, key.code);
            }
        }
        KeyCode::Enter => {
            if devices_len == 0 {
                return;
            }
            let (vid, pid, serial, description) = match &app.screen {
                Screen::UsbScan { devices, selected } => {
                    let entry = &devices[*selected];
                    (
                        entry.identity.vid.clone(),
                        entry.identity.pid.clone(),
                        entry.identity.serial.clone(),
                        entry.identity.description.clone(),
                    )
                }
                _ => return,
            };
            app.screen = Screen::DeviceTierPicker {
                vid,
                pid,
                serial,
                description,
                owner_sid: None,
                owner_user: None,
                selected: 0,
                caller: TierPickerCaller::UsbScan,
            };
        }
        KeyCode::Esc => {
            app.screen = Screen::DevicesMenu { selected: 2 };
        }
        _ => {}
    }
}

/// Handles key events for the Device Registry list screen.
fn handle_device_list(app: &mut App, key: KeyEvent) {
    let devices_len = match &app.screen {
        Screen::DeviceList { devices, .. } => devices.len(),
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if devices_len == 0 {
                return;
            }
            if let Screen::DeviceList { selected, .. } = &mut app.screen {
                nav(selected, devices_len, key.code);
            }
        }
        // `r` starts the device register sequential input chain.
        KeyCode::Char('r') => {
            app.screen = Screen::TextInput {
                prompt: "VID (hex, e.g. 0951):".to_string(),
                input: String::new(),
                purpose: InputPurpose::RegisterDeviceVid,
            };
        }
        // `d` opens delete confirmation for the selected device.
        KeyCode::Char('d') => {
            if devices_len == 0 {
                return;
            }
            let id = match &app.screen {
                Screen::DeviceList { devices, selected } => {
                    devices[*selected]["id"].as_str().unwrap_or("").to_string()
                }
                _ => return,
            };
            if id.is_empty() {
                return;
            }
            app.screen = Screen::Confirm {
                message: format!("Delete device {id}?"),
                yes_selected: true,
                purpose: ConfirmPurpose::DeleteDevice { id },
            };
        }
        KeyCode::Esc => app.screen = Screen::DevicesMenu { selected: 0 },
        _ => {}
    }
}

/// Deletes a device registry entry by UUID and reloads the device list.
fn action_delete_device(app: &mut App, id: &str) {
    let path = format!("admin/device-registry/{id}");
    match app.rt.block_on(app.client.delete(&path)) {
        Ok(()) => {
            app.set_status("Device deleted.", StatusKind::Success);
            action_load_device_list(app);
        }
        Err(e) => {
            app.set_status(format!("Error deleting device: {e}"), StatusKind::Error);
            app.screen = Screen::DevicesMenu { selected: 0 };
        }
    }
}

/// Handles key events for the DeviceTierPicker screen (final step of device register flow).
fn handle_device_tier_picker(app: &mut App, key: KeyEvent) {
    // Extract all fields before mutable borrow for the nav branch.
    let (vid, pid, serial, description, owner_sid, owner_user, sel, caller) = match &app.screen {
        Screen::DeviceTierPicker {
            vid,
            pid,
            serial,
            description,
            owner_sid,
            owner_user,
            selected,
            caller,
        } => (
            vid.clone(),
            pid.clone(),
            serial.clone(),
            description.clone(),
            owner_sid.clone(),
            owner_user.clone(),
            *selected,
            *caller,
        ),
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::DeviceTierPicker { selected, .. } = &mut app.screen {
                nav(selected, 3, key.code);
            }
        }
        KeyCode::Esc => app.screen = Screen::DevicesMenu { selected: 0 },
        KeyCode::Enter => {
            let trust_tier = match sel {
                0 => "blocked",
                1 => "read_only",
                _ => "full_access",
            };
            let owner_sid_opt = owner_sid.as_deref();
            let owner_user_opt = owner_user.as_deref();
            let body = serde_json::json!({
                "vid": vid,
                "pid": pid,
                "serial": serial,
                "description": description,
                "owner_sid": owner_sid_opt,
                "owner_user": owner_user_opt,
                "trust_tier": trust_tier,
            });
            match app.rt.block_on(
                app.client
                    .post::<serde_json::Value, _>("admin/device-registry", &body),
            ) {
                Ok(_) => match caller {
                    TierPickerCaller::DeviceList => {
                        app.set_status("Device registered successfully.", StatusKind::Success);
                        action_load_device_list(app);
                    }
                    TierPickerCaller::UsbScan => {
                        action_usb_scan(app);
                        app.set_status("Device registered successfully.", StatusKind::Success);
                    }
                },
                Err(e) => {
                    app.set_status(format!("Error registering device: {e}"), StatusKind::Error);
                    app.screen = Screen::DevicesMenu { selected: 0 };
                }
            }
        }
        _ => {}
    }
}

/// Handles key events for the Managed Origins list screen.
fn handle_managed_origin_list(app: &mut App, key: KeyEvent) {
    let origins_len = match &app.screen {
        Screen::ManagedOriginList { origins, .. } => origins.len(),
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if origins_len == 0 {
                return;
            }
            if let Screen::ManagedOriginList { selected, .. } = &mut app.screen {
                nav(selected, origins_len, key.code);
            }
        }
        // `a` starts the add-origin text input.
        KeyCode::Char('a') => {
            app.screen = Screen::TextInput {
                prompt: "Origin URL pattern (e.g. https://company.sharepoint.com/*):".to_string(),
                input: String::new(),
                purpose: InputPurpose::AddManagedOrigin,
            };
        }
        // `d` opens delete confirmation for the selected origin.
        KeyCode::Char('d') => {
            if origins_len == 0 {
                return;
            }
            // Extract both the UUID (for the DELETE request) and the origin URL
            // (for the human-readable confirm message).
            let (id, origin_str) = match &app.screen {
                Screen::ManagedOriginList { origins, selected } => {
                    let id = origins[*selected]["id"].as_str().unwrap_or("").to_string();
                    let origin = origins[*selected]["origin"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    (id, origin)
                }
                _ => return,
            };
            if id.is_empty() {
                return;
            }
            app.screen = Screen::Confirm {
                message: format!("Remove origin '{origin_str}'?"),
                yes_selected: true,
                purpose: ConfirmPurpose::DeleteManagedOrigin { id },
            };
        }
        KeyCode::Esc => app.screen = Screen::DevicesMenu { selected: 1 },
        _ => {}
    }
}

/// Deletes a managed origin entry by UUID and reloads the origins list.
fn action_delete_managed_origin(app: &mut App, id: &str) {
    let path = format!("admin/managed-origins/{id}");
    match app.rt.block_on(app.client.delete(&path)) {
        Ok(()) => {
            app.set_status("Managed origin deleted.", StatusKind::Success);
            action_load_managed_origin_list(app);
        }
        Err(e) => {
            app.set_status(format!("Error deleting origin: {e}"), StatusKind::Error);
            app.screen = Screen::DevicesMenu { selected: 1 };
        }
    }
}

// ---------------------------------------------------------------------------
// Disk Registry screen
// ---------------------------------------------------------------------------

/// Loads the disk registry list from the server and navigates to DiskRegistryList.
fn action_load_disk_registry_list(app: &mut App) {
    match app.rt.block_on(
        app.client
            .get::<Vec<serde_json::Value>>("admin/disk-registry"),
    ) {
        Ok(disks) => {
            app.screen = Screen::DiskRegistryList { disks, selected: 0 };
        }
        Err(e) => {
            app.set_status(
                format!("Error loading disk registry: {e}"),
                StatusKind::Error,
            );
        }
    }
}

/// Handles key events for the disk registry list screen.
fn handle_disk_registry_list(app: &mut App, key: KeyEvent) {
    let disks_len = match &app.screen {
        Screen::DiskRegistryList { disks, .. } => disks.len(),
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if disks_len == 0 {
                return;
            }
            if let Screen::DiskRegistryList { selected, .. } = &mut app.screen {
                nav(selected, disks_len, key.code);
            }
        }
        // `a` starts the 5-field add flow.
        KeyCode::Char('a') => {
            app.screen = Screen::TextInput {
                prompt: "Agent ID:".to_string(),
                input: String::new(),
                purpose: InputPurpose::AddDiskRegistryAgentId,
            };
        }
        // `d` opens delete confirmation for the selected entry.
        KeyCode::Char('d') => {
            if disks_len == 0 {
                return;
            }
            let id = match &app.screen {
                Screen::DiskRegistryList { disks, selected } => {
                    disks[*selected]["id"].as_str().unwrap_or("").to_string()
                }
                _ => return,
            };
            if id.is_empty() {
                return;
            }
            app.screen = Screen::Confirm {
                message: format!("Delete disk registry entry {id}?"),
                yes_selected: true,
                purpose: ConfirmPurpose::DeleteDiskRegistry { id },
            };
        }
        KeyCode::Esc => app.screen = Screen::DevicesMenu { selected: 3 },
        _ => {}
    }
}

/// Deletes a disk registry entry by UUID and reloads the list.
fn action_delete_disk_registry(app: &mut App, id: &str) {
    let path = format!("admin/disk-registry/{id}");
    match app.rt.block_on(app.client.delete(&path)) {
        Ok(()) => {
            app.set_status("Disk registry entry deleted.", StatusKind::Success);
            action_load_disk_registry_list(app);
        }
        Err(e) => {
            app.set_status(format!("Error deleting disk entry: {e}"), StatusKind::Error);
            app.screen = Screen::DevicesMenu { selected: 3 };
        }
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
        let cond = build_condition(ConditionAttribute::Classification, "eq", 2, "", None);
        assert!(cond.is_some());
        let json = serde_json::to_string(&cond.unwrap()).expect("serialize");
        assert!(json.contains("\"attribute\":\"classification\""));
        assert!(json.contains("\"op\":\"eq\""));
        assert!(json.contains("\"value\":\"T3\""));
    }

    #[test]
    fn build_condition_member_of_group_sid() {
        let cond = build_condition(ConditionAttribute::MemberOf, "eq", 0, "S-1-5-21-123", None);
        assert!(cond.is_some());
        let json = serde_json::to_string(&cond.unwrap()).expect("serialize");
        assert!(json.contains("\"group_sid\":\"S-1-5-21-123\""));
        // Must NOT contain a bare "value" field.
        assert!(!json.contains("\"value\""));
    }

    #[test]
    fn build_condition_member_of_empty_buffer_returns_none() {
        let cond = build_condition(ConditionAttribute::MemberOf, "eq", 0, "  ", None);
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
            let cond = build_condition(ConditionAttribute::DeviceTrust, "eq", idx, "", None)
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
            let cond = build_condition(ConditionAttribute::NetworkLocation, "eq", idx, "", None)
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
            let cond = build_condition(ConditionAttribute::AccessContext, "eq", idx, "", None)
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
        assert!(build_condition(ConditionAttribute::Classification, "eq", 5, "", None).is_none());
        assert!(build_condition(ConditionAttribute::AccessContext, "eq", 2, "", None).is_none());
    }

    #[test]
    fn operators_for_all_attributes_have_eq() {
        for attr in ATTRIBUTES {
            let ops = operators_for(attr, None);
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
            let ops = operators_for(ConditionAttribute::Classification, None);
            assert_eq!(ops.len(), 4);
            let wire: Vec<_> = ops.iter().map(|(w, _)| *w).collect();
            assert!(wire.contains(&"eq"));
            assert!(wire.contains(&"neq"));
            assert!(wire.contains(&"gt"));
            assert!(wire.contains(&"lt"));
        }

        #[test]
        fn test_operators_for_memberof() {
            let ops = operators_for(ConditionAttribute::MemberOf, None);
            assert_eq!(ops.len(), 3);
            let wire: Vec<_> = ops.iter().map(|(w, _)| *w).collect();
            assert!(wire.contains(&"eq"));
            assert!(wire.contains(&"neq"));
            assert!(wire.contains(&"contains"));
        }

        #[test]
        fn test_operators_for_device_trust() {
            let ops = operators_for(ConditionAttribute::DeviceTrust, None);
            assert_eq!(ops.len(), 2);
            let wire: Vec<_> = ops.iter().map(|(w, _)| *w).collect();
            assert!(wire.contains(&"eq"));
            assert!(wire.contains(&"neq"));
        }

        #[test]
        fn test_operators_for_network_location() {
            let ops = operators_for(ConditionAttribute::NetworkLocation, None);
            assert_eq!(ops.len(), 2);
        }

        #[test]
        fn test_operators_for_access_context() {
            let ops = operators_for(ConditionAttribute::AccessContext, None);
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
        assert_eq!(value_count_for(ConditionAttribute::Classification, None), 4);
        assert_eq!(value_count_for(ConditionAttribute::MemberOf, None), 0);
        assert_eq!(value_count_for(ConditionAttribute::DeviceTrust, None), 4);
        assert_eq!(
            value_count_for(ConditionAttribute::NetworkLocation, None),
            4
        );
        assert_eq!(value_count_for(ConditionAttribute::AccessContext, None), 2);
    }

    // ---------------------------------------------------------------------------
    // Phase 41-04: Origin condition tests.
    // ---------------------------------------------------------------------------

    #[test]
    fn build_condition_source_origin_eq() {
        let cond = build_condition(
            ConditionAttribute::SourceOrigin,
            "eq",
            0,
            "https://company.sharepoint.com",
            None,
        );
        assert!(cond.is_some());
        let json = serde_json::to_string(&cond.unwrap()).expect("serialize");
        assert!(json.contains("\"attribute\":\"source_origin\""));
        assert!(json.contains("\"op\":\"eq\""));
        assert!(json.contains("\"value\":\"https://company.sharepoint.com\""));
    }

    #[test]
    fn build_condition_destination_origin_contains() {
        let cond = build_condition(
            ConditionAttribute::DestinationOrigin,
            "contains",
            0,
            "sharepoint.com",
            None,
        );
        assert!(cond.is_some());
        let json = serde_json::to_string(&cond.unwrap()).expect("serialize");
        assert!(json.contains("\"attribute\":\"destination_origin\""));
        assert!(json.contains("\"op\":\"contains\""));
        assert!(json.contains("\"value\":\"sharepoint.com\""));
    }

    #[test]
    fn build_condition_source_origin_empty_buffer_returns_none() {
        let cond = build_condition(ConditionAttribute::SourceOrigin, "eq", 0, "  ", None);
        assert!(cond.is_none());
    }

    #[test]
    fn condition_display_source_origin() {
        use dlp_common::abac::PolicyCondition;
        let cond = PolicyCondition::SourceOrigin {
            op: "eq".to_string(),
            value: "https://company.sharepoint.com".to_string(),
        };
        let display = condition_display(&cond);
        assert_eq!(display, "SourceOrigin eq https://company.sharepoint.com");
    }

    #[test]
    fn condition_display_destination_origin() {
        use dlp_common::abac::PolicyCondition;
        let cond = PolicyCondition::DestinationOrigin {
            op: "contains".to_string(),
            value: "sharepoint.com".to_string(),
        };
        let display = condition_display(&cond);
        assert_eq!(display, "DestinationOrigin contains sharepoint.com");
    }

    #[test]
    fn condition_to_prefill_source_origin_round_trip() {
        use dlp_common::abac::PolicyCondition;
        let original = PolicyCondition::SourceOrigin {
            op: "eq".to_string(),
            value: "https://company.sharepoint.com".to_string(),
        };
        let (attr, op_str, picker_idx, buf) = condition_to_prefill(&original);
        assert_eq!(attr, ConditionAttribute::SourceOrigin);
        assert_eq!(op_str, "eq");
        assert_eq!(picker_idx, 0);
        assert_eq!(buf, "https://company.sharepoint.com");

        let rebuilt = build_condition(attr, &op_str, picker_idx, &buf, None)
            .expect("roundtrip must produce a valid condition");
        assert_eq!(&rebuilt, &original);
    }

    #[test]
    fn operators_for_source_origin_has_eq_ne_contains() {
        let ops = operators_for(ConditionAttribute::SourceOrigin, None);
        assert_eq!(ops.len(), 3);
        let wire: Vec<_> = ops.iter().map(|(w, _)| *w).collect();
        assert!(wire.contains(&"eq"));
        assert!(wire.contains(&"ne"));
        assert!(wire.contains(&"contains"));
    }

    #[test]
    fn operators_for_destination_origin_has_eq_ne_contains() {
        let ops = operators_for(ConditionAttribute::DestinationOrigin, None);
        assert_eq!(ops.len(), 3);
        let wire: Vec<_> = ops.iter().map(|(w, _)| *w).collect();
        assert!(wire.contains(&"eq"));
        assert!(wire.contains(&"ne"));
        assert!(wire.contains(&"contains"));
    }

    #[test]
    fn value_count_for_source_origin_is_zero() {
        assert_eq!(value_count_for(ConditionAttribute::SourceOrigin, None), 0);
    }

    #[test]
    fn value_count_for_destination_origin_is_zero() {
        assert_eq!(
            value_count_for(ConditionAttribute::DestinationOrigin, None),
            0
        );
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
            selected_field: None,
            selected_operator: None,
            pending: vec![pending_condition.clone()],
            buffer: String::new(),
            pending_focused: false,
            pending_state: ratatui::widgets::ListState::default(),
            picker_state,
            caller: CallerScreen::PolicyCreate,
            form_snapshot: form_snapshot.clone(),
            edit_index: None,
            edit_picker_prefill: None,
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
            let rebuilt = build_condition(attr, &op_str, picker_idx, &buf, None)
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
            selected_field: None,
            selected_operator: None,
            pending: vec![pending_condition.clone()],
            buffer: String::new(),
            pending_focused: true, // focus is on pending list (e is only handled here)
            pending_state,
            picker_state,
            caller: CallerScreen::PolicyCreate,
            form_snapshot,
            edit_index: None,
            edit_picker_prefill: None,
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
            selected_field: None,
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
            edit_picker_prefill: None,
        };
        let mut app = make_test_app(screen);

        // Act: Enter at Step 3 (select path) commits the new T4 value.
        let key = KeyEvent::new(KeyCode::Enter, crossterm::event::KeyModifiers::NONE);
        handle_conditions_step3_select(
            &mut app,
            key,
            ConditionAttribute::Classification,
            "eq",
            None,
        );

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
            selected_field: None,
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
            edit_picker_prefill: None,
        };
        let mut app = make_test_app(screen);

        // Act: Esc at Step 3 goes back to Step 2 without modifying pending.
        let esc_key = KeyEvent::new(KeyCode::Esc, crossterm::event::KeyModifiers::NONE);
        handle_conditions_step3_select(
            &mut app,
            esc_key,
            ConditionAttribute::Classification,
            "eq",
            None,
        );

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

    // ---------------------------------------------------------------------------
    // Phase 32 tests: USB scan dispatch.
    // ---------------------------------------------------------------------------

    fn key_event(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
    }

    #[test]
    fn opening_usb_scan_from_devices_menu_idx_2() {
        let mut app = make_test_app(Screen::DevicesMenu { selected: 2 });
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Enter)));
        match &app.screen {
            Screen::UsbScan { devices, selected } => {
                assert!(devices.is_empty());
                assert_eq!(*selected, 0);
            }
            other => panic!("expected Screen::UsbScan, got {other:?}"),
        }
        assert!(matches!(app.status, Some((_, StatusKind::Info))));
    }

    #[test]
    fn devices_menu_nav_wraps_with_four_items() {
        let mut app = make_test_app(Screen::DevicesMenu { selected: 0 });
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Up)));
        match &app.screen {
            Screen::DevicesMenu { selected } => assert_eq!(*selected, 3),
            _ => panic!("screen mismatch"),
        }
    }

    #[test]
    fn usb_scan_esc_returns_to_devices_menu_idx_2() {
        let mut app = make_test_app(Screen::UsbScan {
            devices: vec![],
            selected: 0,
        });
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Esc)));
        match &app.screen {
            Screen::DevicesMenu { selected } => assert_eq!(*selected, 2),
            _ => panic!("expected DevicesMenu"),
        }
    }

    #[test]
    fn usb_scan_enter_on_empty_list_is_noop() {
        let mut app = make_test_app(Screen::UsbScan {
            devices: vec![],
            selected: 0,
        });
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Enter)));
        assert!(matches!(app.screen, Screen::UsbScan { .. }));
    }

    #[test]
    fn usb_scan_up_on_empty_list_is_noop() {
        let mut app = make_test_app(Screen::UsbScan {
            devices: vec![],
            selected: 0,
        });
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Up)));
        assert!(matches!(app.screen, Screen::UsbScan { .. }));
    }

    #[test]
    fn devices_menu_idx_3_opens_disk_registry() {
        let mut app = make_test_app(Screen::DevicesMenu { selected: 3 });
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Enter)));
        // action_load_disk_registry_list issues an HTTP GET; with the test client
        // pointing at a closed port, it returns an error status confirming the route.
        assert!(
            matches!(app.status, Some((_, StatusKind::Error)))
                || matches!(app.screen, Screen::DiskRegistryList { .. }),
            "expected DiskRegistryList or error status from network call, got {:?}",
            app.screen,
        );
    }

    #[test]
    fn disk_registry_esc_returns_to_devices_menu() {
        let mut app = make_test_app(Screen::DiskRegistryList {
            disks: vec![],
            selected: 0,
        });
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Esc)));
        match &app.screen {
            Screen::DevicesMenu { selected } => assert_eq!(*selected, 3),
            other => panic!("expected DevicesMenu {{ selected: 3 }}, got {other:?}"),
        }
    }

    #[test]
    fn disk_registry_nav_up_down() {
        use serde_json::json;
        let disks = vec![
            json!({"id": "1", "agent_id": "a1", "instance_id": "i1", "bus_type": "SATA", "encryption_status": "encrypted", "model": "Model A"}),
            json!({"id": "2", "agent_id": "a2", "instance_id": "i2", "bus_type": "NVMe", "encryption_status": "none", "model": "Model B"}),
            json!({"id": "3", "agent_id": "a3", "instance_id": "i3", "bus_type": "USB", "encryption_status": "encrypted", "model": "Model C"}),
        ];
        let mut app = make_test_app(Screen::DiskRegistryList { disks, selected: 0 });

        // Down from 0 -> 1
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Down)));
        match &app.screen {
            Screen::DiskRegistryList { selected, .. } => assert_eq!(*selected, 1),
            other => panic!("expected DiskRegistryList, got {other:?}"),
        }

        // Down from 1 -> 2
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Down)));
        match &app.screen {
            Screen::DiskRegistryList { selected, .. } => assert_eq!(*selected, 2),
            other => panic!("expected DiskRegistryList, got {other:?}"),
        }

        // Down from 2 wraps to 0
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Down)));
        match &app.screen {
            Screen::DiskRegistryList { selected, .. } => assert_eq!(*selected, 0),
            other => panic!("expected DiskRegistryList, got {other:?}"),
        }

        // Up from 0 wraps to 2
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Up)));
        match &app.screen {
            Screen::DiskRegistryList { selected, .. } => assert_eq!(*selected, 2),
            other => panic!("expected DiskRegistryList, got {other:?}"),
        }
    }

    #[test]
    fn disk_registry_nav_on_empty_is_noop() {
        let mut app = make_test_app(Screen::DiskRegistryList {
            disks: vec![],
            selected: 0,
        });
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Down)));
        match &app.screen {
            Screen::DiskRegistryList { selected, .. } => assert_eq!(*selected, 0),
            other => panic!("expected DiskRegistryList, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------------------
    // Register flow with owner fields (Phase 38.4 Plan 03).
    // ---------------------------------------------------------------------------

    #[test]
    fn register_flow_description_to_owner_sid() {
        let mut app = make_test_app(Screen::TextInput {
            prompt: "Description".to_string(),
            input: "My USB".to_string(),
            purpose: InputPurpose::RegisterDeviceDescription {
                vid: "0951".into(),
                pid: "1666".into(),
                serial: "ABC".into(),
            },
        });
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Enter)));
        match &app.screen {
            Screen::TextInput {
                prompt, purpose, ..
            } => {
                assert!(
                    prompt.contains("Owner SID"),
                    "expected Owner SID prompt, got: {prompt}"
                );
                assert!(
                    matches!(purpose, InputPurpose::RegisterDeviceOwnerSid { .. }),
                    "expected RegisterDeviceOwnerSid"
                );
            }
            other => panic!("expected TextInput for Owner SID, got {other:?}"),
        }
    }

    #[test]
    fn register_flow_owner_sid_to_owner_user() {
        let mut app = make_test_app(Screen::TextInput {
            prompt: "Owner SID".to_string(),
            input: "S-1-5-21-1".to_string(),
            purpose: InputPurpose::RegisterDeviceOwnerSid {
                vid: "0951".into(),
                pid: "1666".into(),
                serial: "ABC".into(),
                description: "My USB".into(),
            },
        });
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Enter)));
        match &app.screen {
            Screen::TextInput {
                prompt, purpose, ..
            } => {
                assert!(
                    prompt.contains("Owner User"),
                    "expected Owner User prompt, got: {prompt}"
                );
                assert!(
                    matches!(purpose, InputPurpose::RegisterDeviceOwnerUser { .. }),
                    "expected RegisterDeviceOwnerUser"
                );
            }
            other => panic!("expected TextInput for Owner User, got {other:?}"),
        }
    }

    #[test]
    fn register_flow_owner_user_to_tier_picker_with_owner() {
        let mut app = make_test_app(Screen::TextInput {
            prompt: "Owner User".to_string(),
            input: "alice".to_string(),
            purpose: InputPurpose::RegisterDeviceOwnerUser {
                vid: "0951".into(),
                pid: "1666".into(),
                serial: "ABC".into(),
                description: "My USB".into(),
                owner_sid: "S-1-5-21-1".into(),
            },
        });
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Enter)));
        match &app.screen {
            Screen::DeviceTierPicker {
                vid,
                pid,
                serial,
                description,
                owner_sid,
                owner_user,
                selected,
                caller,
            } => {
                assert_eq!(vid, "0951");
                assert_eq!(pid, "1666");
                assert_eq!(serial, "ABC");
                assert_eq!(description, "My USB");
                assert_eq!(owner_sid.as_deref(), Some("S-1-5-21-1"));
                assert_eq!(owner_user.as_deref(), Some("alice"));
                assert_eq!(*selected, 0);
                assert_eq!(*caller, TierPickerCaller::DeviceList);
            }
            other => panic!("expected DeviceTierPicker, got {other:?}"),
        }
    }

    #[test]
    fn register_flow_skipped_owner_fields_are_none() {
        // Empty owner_sid -> None, empty owner_user -> None.
        let mut app = make_test_app(Screen::TextInput {
            prompt: "Owner User".to_string(),
            input: "".to_string(),
            purpose: InputPurpose::RegisterDeviceOwnerUser {
                vid: "0951".into(),
                pid: "1666".into(),
                serial: "ABC".into(),
                description: "My USB".into(),
                owner_sid: "".into(),
            },
        });
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Enter)));
        match &app.screen {
            Screen::DeviceTierPicker {
                owner_sid,
                owner_user,
                ..
            } => {
                assert!(owner_sid.is_none(), "empty owner_sid should be None");
                assert!(owner_user.is_none(), "empty owner_user should be None");
            }
            other => panic!("expected DeviceTierPicker, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod usb_scan_merge_tests {
    use super::*;
    use dlp_common::DeviceIdentity;
    use serde_json::json;

    fn id(vid: &str, pid: &str, serial: &str, desc: &str) -> DeviceIdentity {
        DeviceIdentity {
            vid: vid.into(),
            pid: pid.into(),
            serial: serial.into(),
            description: desc.into(),
        }
    }

    #[test]
    fn build_registry_map_extracts_tier_from_row() {
        let rows = vec![
            json!({"vid":"0951","pid":"1666","serial":"ABC","trust_tier":"read_only"}),
            json!({"vid":"05ac","pid":"12a8","serial":"X","trust_tier":"blocked"}),
        ];
        let map = build_registry_map(&rows);
        assert_eq!(
            map.get(&("0951".into(), "1666".into(), "ABC".into())),
            Some(&"read_only".to_string())
        );
        assert_eq!(
            map.get(&("05ac".into(), "12a8".into(), "X".into())),
            Some(&"blocked".to_string())
        );
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn build_registry_map_skips_per_user_entries() {
        // Machine-wide entry (no owner_sid) should be included.
        // Per-user entry (has owner_sid) should be excluded.
        let rows = vec![
            json!({"vid":"0951","pid":"1666","serial":"ABC","trust_tier":"read_only"}),
            json!({"vid":"05ac","pid":"12a8","serial":"X","trust_tier":"blocked","owner_sid":"S-1-5-21-1","owner_user":"alice"}),
        ];
        let map = build_registry_map(&rows);
        assert_eq!(
            map.get(&("0951".into(), "1666".into(), "ABC".into())),
            Some(&"read_only".to_string()),
            "machine-wide entry should be in map"
        );
        assert_eq!(
            map.get(&("05ac".into(), "12a8".into(), "X".into())),
            None,
            "per-user entry should be excluded from map"
        );
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn build_registry_map_defaults_missing_tier_to_blocked() {
        let rows = vec![json!({"vid":"0951","pid":"1666","serial":"ABC"})];
        let map = build_registry_map(&rows);
        assert_eq!(
            map.get(&("0951".into(), "1666".into(), "ABC".into())),
            Some(&"blocked".to_string())
        );
    }

    #[test]
    fn merge_marks_matching_devices_with_tier() {
        let rows = vec![json!({"vid":"0951","pid":"1666","serial":"ABC","trust_tier":"read_only"})];
        let map = build_registry_map(&rows);
        let usb = vec![id("0951", "1666", "ABC", "Kingston")];
        let out = merge_registry_with_usb(&map, usb);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].registered_tier.as_deref(), Some("read_only"));
        assert_eq!(out[0].identity.description, "Kingston");
    }

    #[test]
    fn merge_marks_unregistered_devices_with_none() {
        let map = std::collections::HashMap::new();
        let usb = vec![id("0951", "1666", "ABC", "Kingston")];
        let out = merge_registry_with_usb(&map, usb);
        assert_eq!(out.len(), 1);
        assert!(out[0].registered_tier.is_none());
    }

    #[test]
    fn merge_drives_rows_from_usb_not_registry() {
        let rows = vec![json!({"vid":"AAAA","pid":"AAAA","serial":"A","trust_tier":"read_only"})];
        let map = build_registry_map(&rows);
        let usb = vec![id("BBBB", "BBBB", "B", "other")];
        let out = merge_registry_with_usb(&map, usb);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].identity.vid, "BBBB");
        assert!(out[0].registered_tier.is_none());
    }

    #[test]
    fn format_usb_scan_status_zero_returns_rescan_hint() {
        let s = format_usb_scan_status(0, 0);
        assert_eq!(
            s,
            "No USB mass storage devices found. Plug in a device and press r to rescan."
        );
    }

    #[test]
    fn format_usb_scan_status_nonzero_uses_count_template() {
        let s = format_usb_scan_status(2, 1);
        assert_eq!(s, "2 USB devices found (1 already registered)");
    }
}

#[cfg(test)]
mod usb_scan_routing_tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn enter() -> crossterm::event::KeyEvent {
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Enter,
            crossterm::event::KeyModifiers::NONE,
        )
    }

    async fn make_app_with_mocks_ok() -> (App, MockServer) {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/admin/device-registry"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-id",
                "vid": "0951",
                "pid": "1666",
                "serial": "ABC",
                "description": "Kingston",
                "trust_tier": "read_only"
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/admin/device-registry/full"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<serde_json::Value>::new()))
            .mount(&server)
            .await;

        let client = crate::client::EngineClient::for_test_with_url(server.uri());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let mut app = crate::app::App::new(client, rt);
        app.screen = Screen::MainMenu { selected: 0 };
        (app, server)
    }

    async fn make_app_with_mocks_err() -> (App, MockServer) {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/admin/device-registry"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/admin/device-registry/full"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<serde_json::Value>::new()))
            .mount(&server)
            .await;

        let client = crate::client::EngineClient::for_test_with_url(server.uri());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let mut app = crate::app::App::new(client, rt);
        app.screen = Screen::MainMenu { selected: 0 };
        (app, server)
    }

    #[test]
    fn tier_picker_caller_devicelist_routes_to_devicelist_on_success() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (mut app, _server) = rt.block_on(make_app_with_mocks_ok());
        app.screen = Screen::DeviceTierPicker {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "ABC".into(),
            description: "Kingston".into(),
            owner_sid: None,
            owner_user: None,
            selected: 1,
            caller: TierPickerCaller::DeviceList,
        };
        handle_event(&mut app, AppEvent::Key(enter()));
        assert!(matches!(app.screen, Screen::DeviceList { .. }));
        assert!(matches!(app.status, Some((_, StatusKind::Success))));
    }

    #[test]
    fn tier_picker_caller_usbscan_routes_to_usbscan_on_success() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (mut app, _server) = rt.block_on(make_app_with_mocks_ok());
        app.screen = Screen::DeviceTierPicker {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "ABC".into(),
            description: "Kingston".into(),
            owner_sid: None,
            owner_user: None,
            selected: 1,
            caller: TierPickerCaller::UsbScan,
        };
        handle_event(&mut app, AppEvent::Key(enter()));
        assert!(matches!(app.screen, Screen::UsbScan { .. }));
        let (msg, kind) = app.status.as_ref().expect("status set");
        assert!(msg.contains("registered successfully"), "status was: {msg}");
        assert_eq!(*kind, StatusKind::Success);
    }

    #[test]
    fn tier_picker_caller_devicelist_routes_to_devices_menu_on_err() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (mut app, _server) = rt.block_on(make_app_with_mocks_err());
        app.screen = Screen::DeviceTierPicker {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "ABC".into(),
            description: "Kingston".into(),
            owner_sid: None,
            owner_user: None,
            selected: 1,
            caller: TierPickerCaller::DeviceList,
        };
        handle_event(&mut app, AppEvent::Key(enter()));
        match &app.screen {
            Screen::DevicesMenu { selected } => assert_eq!(*selected, 0),
            other => panic!("expected DevicesMenu on err, got {other:?}"),
        }
    }

    #[test]
    fn tier_picker_caller_usbscan_routes_to_devices_menu_on_err() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (mut app, _server) = rt.block_on(make_app_with_mocks_err());
        app.screen = Screen::DeviceTierPicker {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "ABC".into(),
            description: "Kingston".into(),
            owner_sid: None,
            owner_user: None,
            selected: 1,
            caller: TierPickerCaller::UsbScan,
        };
        handle_event(&mut app, AppEvent::Key(enter()));
        match &app.screen {
            Screen::DevicesMenu { selected } => assert_eq!(*selected, 0),
            other => panic!("expected DevicesMenu on err, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod usb_enforcement_tests {
    use super::*;

    fn key_event(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
    }

    fn make_test_app(screen: Screen) -> crate::app::App {
        let client = crate::client::EngineClient::for_test();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime build must succeed");
        let mut app = crate::app::App::new(client, rt);
        app.screen = screen;
        app
    }

    #[test]
    fn usb_enforcement_screen_navigates_all_rows() {
        let config = serde_json::json!({
            "usb_blocked_failure_mode": "Warning only",
            "usb_startup_resolution_mode": "VID/PID/serial fallback",
            "usb_none_serial_policy": "Always Blocked",
        });
        let screen = Screen::UsbEnforcementConfig {
            config,
            selected: 0,
            editing: false,
            buffer: String::new(),
        };
        let mut app = make_test_app(screen);

        // Navigate Down through all 5 rows (0..=4).
        for expected in [1, 2, 3, 4, 0] {
            handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Down)));
            match &app.screen {
                Screen::UsbEnforcementConfig { selected, .. } => {
                    assert_eq!(*selected, expected);
                }
                other => panic!("expected UsbEnforcementConfig, got {other:?}"),
            }
        }
    }

    #[test]
    fn usb_enforcement_editing_cycles_picker_options() {
        let config = serde_json::json!({
            "usb_blocked_failure_mode": "Warning only",
            "usb_startup_resolution_mode": "VID/PID/serial fallback",
            "usb_none_serial_policy": "Always Blocked",
        });
        let screen = Screen::UsbEnforcementConfig {
            config,
            selected: 0,
            editing: true,
            buffer: String::new(),
        };
        let mut app = make_test_app(screen);

        // Row 0 has 3 options; cycle Up from "Warning only" -> "Hard error".
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Up)));
        match &app.screen {
            Screen::UsbEnforcementConfig { config, .. } => {
                let val = config["usb_blocked_failure_mode"].as_str().unwrap_or("");
                assert_eq!(val, "Hard error");
            }
            other => panic!("expected UsbEnforcementConfig, got {other:?}"),
        }

        // Cycle Down from "Hard error" -> "Warning only" -> "Retry then error".
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Down)));
        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Down)));
        match &app.screen {
            Screen::UsbEnforcementConfig { config, .. } => {
                let val = config["usb_blocked_failure_mode"].as_str().unwrap_or("");
                assert_eq!(val, "Retry then error");
            }
            other => panic!("expected UsbEnforcementConfig, got {other:?}"),
        }
    }

    #[test]
    fn usb_enforcement_enter_exits_edit_mode() {
        let config = serde_json::json!({
            "usb_blocked_failure_mode": "Warning only",
            "usb_startup_resolution_mode": "VID/PID/serial fallback",
            "usb_none_serial_policy": "Always Blocked",
        });
        let screen = Screen::UsbEnforcementConfig {
            config,
            selected: 0,
            editing: true,
            buffer: String::new(),
        };
        let mut app = make_test_app(screen);

        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Enter)));
        match &app.screen {
            Screen::UsbEnforcementConfig { editing, .. } => {
                assert!(!editing);
            }
            other => panic!("expected UsbEnforcementConfig, got {other:?}"),
        }
    }

    #[test]
    fn usb_enforcement_esc_returns_to_system_menu() {
        let config = serde_json::json!({
            "usb_blocked_failure_mode": "Warning only",
            "usb_startup_resolution_mode": "VID/PID/serial fallback",
            "usb_none_serial_policy": "Always Blocked",
        });
        let screen = Screen::UsbEnforcementConfig {
            config,
            selected: 2,
            editing: false,
            buffer: String::new(),
        };
        let mut app = make_test_app(screen);

        handle_event(&mut app, AppEvent::Key(key_event(KeyCode::Esc)));
        match &app.screen {
            Screen::SystemMenu { selected } => {
                assert_eq!(*selected, 5);
            }
            other => panic!("expected SystemMenu, got {other:?}"),
        }
    }
}
