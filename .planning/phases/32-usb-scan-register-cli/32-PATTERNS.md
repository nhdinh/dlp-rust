# Phase 32: USB Scan & Register CLI - Pattern Map

**Mapped:** 2026-04-29
**Files analyzed:** 8
**Analogs found:** 8 / 8

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `dlp-common/src/usb.rs` | utility (shared lib) | request-response (Win32 blocking) | `dlp-agent/src/detection/usb.rs` | exact (extract from) |
| `dlp-common/src/lib.rs` | config (module registry) | — | `dlp-common/src/lib.rs` (self) | exact |
| `dlp-common/Cargo.toml` | config (deps) | — | `dlp-common/Cargo.toml` (self) | exact |
| `dlp-agent/src/detection/usb.rs` | service (Win32 event-driven) | event-driven | self (remove extracted fns) | exact |
| `dlp-admin-cli/src/app.rs` | model (state machine) | — | `dlp-admin-cli/src/app.rs` (self) | exact (extend enum) |
| `dlp-admin-cli/src/screens/dispatch.rs` | controller | request-response | `dispatch.rs` `handle_device_list` / `handle_device_tier_picker` | exact |
| `dlp-admin-cli/src/screens/render.rs` | component (TUI) | request-response | `render.rs` `draw_agent_list` (Table) + `DevicesMenu` arm | exact |
| `dlp-admin-cli/src/client.rs` | service (HTTP) | request-response | self (no change needed — `get` already generic) | exact |

---

## Pattern Assignments

---

### `dlp-common/src/usb.rs` (utility, Win32 blocking)

**Analog:** `dlp-agent/src/detection/usb.rs` — extract and promote private functions

**Imports pattern** (agent usb.rs lines 31-66, adapt for dlp-common):
```rust
// dlp-common has no windows UI imports needed; only SetupDi + Foundation
use crate::endpoint::DeviceIdentity;

#[cfg(windows)]
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiGetDeviceRegistryPropertyW, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT,
    SETUP_DI_REGISTRY_PROPERTY, SP_DEVINFO_DATA,
};

/// Registry property ID for device friendly name.
/// Falls back to `SPDRP_DEVICEDESC` when not set. Value = 12 (0xC).
#[cfg(windows)]
const SPDRP_FRIENDLYNAME: u32 = 0x0000_000C;

/// Registry property ID for device description (fallback). Value = 0.
#[cfg(windows)]
const SPDRP_DEVICEDESC: u32 = 0x0000_0000;
```

**Public API / cfg-guard pattern** (RESEARCH.md Pattern 3):
```rust
/// Enumerates currently-connected USB mass storage devices.
///
/// Returns a `Vec<DeviceIdentity>` with VID, PID, serial, and description
/// populated from SetupDi. Empty on non-Windows or if no USB mass storage
/// devices are present.
///
/// # Platform
///
/// Windows only. On non-Windows platforms, always returns `vec![]`.
pub fn enumerate_connected_usb_devices() -> Vec<DeviceIdentity> {
    #[cfg(windows)]
    { enumerate_connected_usb_devices_windows() }
    #[cfg(not(windows))]
    { vec![] }
}
```

**`parse_usb_device_path` — move verbatim from agent** (agent usb.rs lines 1063-1089):
```rust
// Pure string parsing — no Win32 calls, no cfg guard needed.
// Make `pub fn` (was private in agent) so agent can re-import from dlp-common.
pub fn parse_usb_device_path(dbcc_name: &str) -> DeviceIdentity {
    let mut identity = DeviceIdentity::default();
    let parts: Vec<&str> = dbcc_name.split('#').collect();

    if let Some(vid_pid_segment) = parts.get(1) {
        for token in vid_pid_segment.split('&') {
            let lower = token.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("vid_") {
                identity.vid = rest.to_string();
            } else if let Some(rest) = lower.strip_prefix("pid_") {
                identity.pid = rest.to_string();
            }
        }
    }

    let raw_serial = parts.get(2).copied().unwrap_or("");
    identity.serial = if raw_serial.is_empty() || raw_serial.starts_with('&') {
        "(none)".to_string()
    } else {
        raw_serial.to_string()
    };

    identity
}
```

**`setupdi_description_for_device` — move verbatim from agent** (agent usb.rs lines 724-797):
```rust
// Keep cfg(windows) guard. Change from `fn` to `pub(crate) fn`
// (only called internally by enumerate_connected_usb_devices_windows).
#[cfg(windows)]
pub(crate) fn setupdi_description_for_device(device_path: &str) -> String {
    // ... (body moved verbatim — see agent usb.rs lines 725-797)
    // Uses GUID_DEVINTERFACE_USB_DEVICE, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT
    // VID/PID match heuristic, 1024-iteration safety valve, DestroyDeviceInfoList cleanup
}
```

**`read_string_property` helper — move verbatim from agent** (agent usb.rs lines 810-846):
```rust
// Keep cfg(windows) guard. Keep private (fn, not pub).
#[cfg(windows)]
fn read_string_property(
    hdev: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    devinfo: &SP_DEVINFO_DATA,
    property: u32,
) -> Option<String> {
    // 1024-byte UTF-16 LE buffer; chunks_exact(2) decode; take_while null terminator
    // (body moved verbatim — see agent usb.rs lines 810-846)
}
```

**`enumerate_connected_usb_devices_windows` — new Windows-only impl function**:
```rust
// Private impl called only by the public enumerate_connected_usb_devices().
// Enumerates GUID_DEVINTERFACE_USB_DEVICE (same as agent arrival handler —
// proven working; avoids GUID_DEVINTERFACE_DISK format mismatch risk per
// RESEARCH.md Pitfall 1 / Open Question 1).
// Filters: only entries where parse_usb_device_path yields non-empty vid AND pid.
#[cfg(windows)]
fn enumerate_connected_usb_devices_windows() -> Vec<DeviceIdentity> {
    // SetupDiGetClassDevsW(GUID_DEVINTERFACE_USB_DEVICE, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT)
    // Loop: SetupDiEnumDeviceInfo -> SetupDiGetDeviceInstanceIdW -> parse_usb_device_path
    // Filter: identity.vid.is_empty() || identity.pid.is_empty() -> skip (hub/HID)
    // Populate description: setupdi_description_for_device(instance_id)
    // Safety valve: index > 1024 break (mirrors agent pattern, line 784)
    // Cleanup: SetupDiDestroyDeviceInfoList
    vec![] // stub; implementation fills from SetupDi loop
}
```

**Tests — move from agent and add new** (agent usb.rs lines 1103-1134):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Move all parse_usb_device_path tests verbatim from agent:
    // test_parse_happy_path, test_parse_no_serial_empty_segment,
    // test_parse_no_serial_ampersand_synthesized, etc.

    #[test]
    fn test_enumerate_returns_vec_on_non_windows() {
        // On non-Windows CI, enumerate_connected_usb_devices() must return vec![]
        // (the cfg(not(windows)) stub).
        // On Windows this is a no-op compile-only test; full enumeration is manual.
        #[cfg(not(windows))]
        assert!(enumerate_connected_usb_devices().is_empty());
    }
}
```

---

### `dlp-common/src/lib.rs` (module registry, extend)

**Analog:** `dlp-common/src/lib.rs` lines 1-19 (self)

**Current state** (lib.rs lines 7-19):
```rust
pub mod abac;
pub mod ad_client;
pub mod audit;
pub mod classification;
pub mod classifier;
pub mod endpoint;

pub use abac::*;
pub use ad_client::{get_device_trust, get_network_location, AdClient, AdClientError, LdapConfig};
pub use audit::*;
pub use classification::*;
pub use classifier::classify_text;
pub use endpoint::{AppIdentity, AppTrustTier, DeviceIdentity, SignatureState, UsbTrustTier};
```

**Addition pattern — append after the last `pub mod`**:
```rust
pub mod usb;
pub use usb::{enumerate_connected_usb_devices, parse_usb_device_path};
```

---

### `dlp-common/Cargo.toml` (dependency config, extend windows features)

**Analog:** `dlp-common/Cargo.toml` lines 21-29 (self — existing windows block)

**Current block** (Cargo.toml lines 21-29):
```toml
[target.'cfg(windows)'.dependencies]
windows = { version = "0.61", features = [
    "Win32_NetworkManagement_NetManagement",
    "Win32_NetworkManagement_Ndis",
    "Win32_NetworkManagement_IpHelper",
    "Win32_Networking_ActiveDirectory",
    "Win32_Networking_WinSock",
    "Win32_Foundation",
] }
```

**Required additions** (append to the features list — RESEARCH.md lines 96-97):
```toml
    # NEW for usb.rs enumeration (SetupDiGetClassDevsW, SetupDiEnumDeviceInfo, etc.):
    "Win32_Devices_DeviceAndDriverInstallation",
```

**Note:** `Win32_Storage_FileSystem` is NOT required if using `GUID_DEVINTERFACE_USB_DEVICE`
(no `GetDriveTypeW` call needed). `Win32_Foundation` already present (provides `HWND` etc.).
Do not add `Win32_UI_WindowsAndMessaging` — those stay in dlp-agent only.

---

### `dlp-agent/src/detection/usb.rs` (service, refactor — remove extracted fns)

**Analog:** self (lines 725-846 and 1063-1089 are the sections to remove)

**Removal pattern:**
- Delete `fn parse_usb_device_path` (lines 1063-1089) — body moves to dlp-common
- Delete `fn setupdi_description_for_device` (lines 724-797) — body moves to dlp-common
- Delete `fn read_string_property` (lines 810-846) — body moves to dlp-common
- Delete `SPDRP_FRIENDLYNAME` and `SPDRP_DEVICEDESC` constants (lines 61-66) — move to dlp-common

**Replacement import pattern** (add to agent usb.rs import block, lines 36):
```rust
// After existing: use dlp_common::{Classification, DeviceIdentity, UsbTrustTier};
// Add the moved helpers:
use dlp_common::usb::{parse_usb_device_path, setupdi_description_for_device};
// Note: setupdi_description_for_device is pub(crate) in dlp-common — if needed from
// agent, promote to pub in dlp-common usb.rs OR keep a wrapper.
// Simplest: make it pub fn in dlp-common (the agent is an external crate).
```

**Call-site pattern** (existing callers in agent usb.rs — no signature changes needed):
```rust
// Existing call at on_usb_device_arrival (line ~580 area):
//   let identity = parse_usb_device_path(path);
// These call sites remain identical — only the fn definition moves.
```

**Test removal:** Move `test_parse_happy_path` and all `parse_usb_device_path` tests from
agent `#[cfg(test)] mod tests` to `dlp-common/src/usb.rs` tests.

---

### `dlp-admin-cli/src/app.rs` (model/state machine, extend Screen enum)

**Analog:** `dlp-admin-cli/src/app.rs` — existing `CallerScreen` enum (lines 152-158),
existing `Screen::DeviceTierPicker` variant (lines 570-577), existing `Screen::DeviceList`
variant (lines 557-565).

**`TierPickerCaller` enum — new, follows `CallerScreen` pattern** (app.rs lines 152-158):
```rust
/// Identifies which screen opened `DeviceTierPicker`, used to route back after
/// successful registration.
///
/// Mirrors the `CallerScreen` pattern used by `ConditionsBuilder` for return routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierPickerCaller {
    /// Opened from the manual register flow in `DeviceList`.
    DeviceList,
    /// Opened from the USB scan and register screen.
    UsbScan,
}
```

**`UsbScanEntry` struct — new, follows `PolicyFormState` / `SimulateFormState` pattern**:
```rust
/// A single entry in the USB scan list: local device cross-referenced with the
/// server registry.
///
/// Constructed by `action_usb_scan` from the merged SetupDi + GET registry results.
#[derive(Debug, Clone)]
pub struct UsbScanEntry {
    /// VID, PID, serial, description from SetupDi enumeration.
    pub identity: dlp_common::DeviceIdentity,
    /// `None` = not in server registry; `Some("read_only")` = registered with that tier.
    pub registered_tier: Option<String>,
}
```

**`Screen::UsbScan` variant — insert after `Screen::DeviceTierPicker`**:
```rust
/// USB scan and register screen.
///
/// Opens empty; `r` triggers concurrent USB enumeration + registry fetch.
/// `Enter` on a row opens `DeviceTierPicker`.
/// Keybindings: r=scan, Up/Down=navigate, Enter=open tier picker, Esc=back.
Screen::UsbScan {
    /// Merged local USB devices with registry cross-reference.
    devices: Vec<UsbScanEntry>,
    /// Currently highlighted row index.
    selected: usize,
},
```

**`Screen::DeviceTierPicker` — add `caller` field** (existing variant lines 570-577):
```rust
// Before (lines 570-577):
DeviceTierPicker {
    vid: String,
    pid: String,
    serial: String,
    description: String,
    selected: usize,
},

// After:
DeviceTierPicker {
    vid: String,
    pid: String,
    serial: String,
    description: String,
    /// Selected tier index: 0 = blocked, 1 = read_only, 2 = full_access.
    selected: usize,
    /// Which screen opened the picker (for post-registration routing).
    caller: TierPickerCaller,
},
```

**`DevicesMenu` comment update** (line 554):
```rust
// Change:
//   "Devices & Origins" submenu with 2 items: Device Registry, Managed Origins.
// To:
//   "Devices & Origins" submenu with 3 items: Device Registry, Managed Origins,
//   Scan & Register USB.
```

---

### `dlp-admin-cli/src/screens/dispatch.rs` (controller, extend)

**Analog:** `dispatch.rs` — `handle_devices_menu` (lines 3560-3579),
`action_load_device_list` (lines 3581-3597), `handle_device_list` (lines 3617-3663),
`handle_device_tier_picker` (lines 3680-3735).

**`handle_devices_menu` patch — change `nav` count from 2 to 3, add index 2**:
```rust
// Line 3567: nav(selected, 2, key.code)  ->  nav(selected, 3, key.code)
// Line 3572-3574: add case 2:
2 => action_open_usb_scan(app),
```

**`action_open_usb_scan` — new, opens screen empty (no scan yet)**:
```rust
/// Navigates to the USB scan screen in its initial (empty) state.
///
/// The actual scan is triggered by `r` inside `handle_usb_scan`.
fn action_open_usb_scan(app: &mut App) {
    app.screen = Screen::UsbScan {
        devices: vec![],
        selected: 0,
    };
    app.set_status(
        "Press r to scan for connected USB mass storage devices.",
        StatusKind::Info,
    );
}
```

**`action_usb_scan` — new, concurrent scan (follows `action_load_device_list` pattern)**:
```rust
/// Runs USB enumeration and registry fetch concurrently, then populates
/// `Screen::UsbScan`.
///
/// Uses `tokio::join!` inside `block_on` — both futures run on the single
/// tokio reactor. `spawn_blocking` bridges the blocking Win32 SetupDi call.
/// The event loop blocks for the duration (~100ms) — acceptable per D-02.
fn action_usb_scan(app: &mut App) {
    // Clone the client so the async block can take ownership (reqwest::Client
    // is internally Arc-backed; clone is O(1)).
    let client = app.client.clone();
    let (registry_result, usb_join) = app.rt.block_on(async move {
        tokio::join!(
            client.get::<Vec<serde_json::Value>>("admin/device-registry/full"),
            // spawn_blocking required: enumerate_connected_usb_devices makes blocking
            // Win32 calls that must not run on the async executor thread.
            tokio::task::spawn_blocking(dlp_common::usb::enumerate_connected_usb_devices)
        )
    });

    // JoinError -> treat as empty (spawn_blocking panic is non-fatal here)
    let usb_devices = usb_join.unwrap_or_default();
    let registry_devices = registry_result.unwrap_or_default();

    // Build lookup: (vid, pid, serial) -> trust_tier string
    let mut registry_map: std::collections::HashMap<(String, String, String), String> =
        std::collections::HashMap::new();
    for d in &registry_devices {
        let vid = d["vid"].as_str().unwrap_or("").to_string();
        let pid = d["pid"].as_str().unwrap_or("").to_string();
        let serial = d["serial"].as_str().unwrap_or("").to_string();
        let tier = d["trust_tier"].as_str().unwrap_or("blocked").to_string();
        registry_map.insert((vid, pid, serial), tier);
    }

    let entries: Vec<UsbScanEntry> = usb_devices
        .into_iter()
        .map(|identity| {
            let key = (identity.vid.clone(), identity.pid.clone(), identity.serial.clone());
            let registered_tier = registry_map.get(&key).cloned();
            UsbScanEntry { identity, registered_tier }
        })
        .collect();

    let registered_count = entries.iter().filter(|e| e.registered_tier.is_some()).count();
    let total = entries.len();
    let status_msg = if total == 0 {
        "No USB mass storage devices found. Plug in a device and press r to rescan."
            .to_string()
    } else {
        format!("{total} USB devices found ({registered_count} already registered)")
    };

    app.set_status(status_msg, StatusKind::Info);
    // Preserve selected index at 0 (fresh scan always resets position).
    app.screen = Screen::UsbScan { devices: entries, selected: 0 };
}
```

**`handle_usb_scan` — new, follows `handle_device_list` pattern exactly**:
```rust
/// Handles key events for the USB scan and register screen.
fn handle_usb_scan(app: &mut App, key: KeyEvent) {
    let devices_len = match &app.screen {
        Screen::UsbScan { devices, .. } => devices.len(),
        _ => return,
    };
    match key.code {
        // r: trigger concurrent USB scan + registry fetch (D-02)
        KeyCode::Char('r') => action_usb_scan(app),

        KeyCode::Up | KeyCode::Down => {
            if devices_len == 0 {
                return; // Guard against empty list (RESEARCH.md Pitfall 4)
            }
            if let Screen::UsbScan { selected, .. } = &mut app.screen {
                nav(selected, devices_len, key.code);
            }
        }

        KeyCode::Enter => {
            if devices_len == 0 {
                return; // Guard: prevent index-out-of-bounds on empty vec
            }
            let (vid, pid, serial, description) = match &app.screen {
                Screen::UsbScan { devices, selected } => {
                    let e = &devices[*selected];
                    (
                        e.identity.vid.clone(),
                        e.identity.pid.clone(),
                        e.identity.serial.clone(),
                        e.identity.description.clone(),
                    )
                }
                _ => return,
            };
            // Transition to DeviceTierPicker with caller = UsbScan (D-05)
            app.screen = Screen::DeviceTierPicker {
                vid,
                pid,
                serial,
                description,
                selected: 0,
                caller: TierPickerCaller::UsbScan,
            };
        }

        KeyCode::Esc => app.screen = Screen::DevicesMenu { selected: 2 },
        _ => {}
    }
}
```

**`handle_device_tier_picker` — add `caller` field extraction and routing**
(existing lines 3680-3735, extend the `Ok(_)` branch):
```rust
// Existing: extract (vid, pid, serial, description, sel) from Screen::DeviceTierPicker
// ADD: also extract `caller`
let (vid, pid, serial, description, sel, caller) = match &app.screen {
    Screen::DeviceTierPicker { vid, pid, serial, description, selected, caller } => (
        vid.clone(), pid.clone(), serial.clone(), description.clone(), *selected, *caller,
    ),
    _ => return,
};

// ... (nav branch unchanged) ...

// In the KeyCode::Enter -> Ok(_) branch, REPLACE:
//   action_load_device_list(app);
// WITH:
match caller {
    TierPickerCaller::DeviceList => {
        app.set_status("Device registered successfully.", StatusKind::Success);
        action_load_device_list(app);
    }
    TierPickerCaller::UsbScan => {
        // Re-run the full scan so the newly-registered tier shows immediately (D-03).
        action_usb_scan(app);
        // action_usb_scan sets its own status; override with success message.
        app.set_status("Device registered successfully.", StatusKind::Success);
    }
}

// Esc branch: return to DevicesMenu regardless of caller (existing behavior OK).
// Error branch: return to DevicesMenu regardless of caller (existing behavior OK).
```

**`InputPurpose::RegisterDeviceDescription` handler — add `caller` field**:
```rust
// Wherever Screen::DeviceTierPicker is constructed from the manual register flow,
// add `caller: TierPickerCaller::DeviceList`.
// Search for: Screen::DeviceTierPicker { vid, pid, serial, description, selected: 0 }
// in the InputPurpose::RegisterDeviceDescription branch and add the caller field.
```

**dispatch function routing — add UsbScan arm** to the top-level `handle_key` / `dispatch`
function (follows the pattern of all other `Screen::*` arms):
```rust
Screen::UsbScan { .. } => handle_usb_scan(app, key),
```

---

### `dlp-admin-cli/src/screens/render.rs` (component/TUI, extend)

**Analog:** `render.rs` — `draw_agent_list` Table pattern (lines 1863-1916),
`DevicesMenu` render arm (lines 236-244), `DeviceTierPicker` render arm (lines 249-258),
`draw_hints` (lines 2040-2054).

**`DevicesMenu` arm patch — add 3rd item** (render.rs line 241):
```rust
// Change:
&["Device Registry", "Managed Origins"],
// To:
&["Device Registry", "Managed Origins", "Scan & Register USB"],
```

**`Screen::UsbScan` arm — add to `draw_screen` match** (after the `DeviceTierPicker` arm):
```rust
Screen::UsbScan { devices, selected } => {
    draw_usb_scan(frame, area, devices, *selected);
}
```

**`draw_usb_scan` — new function, copy `draw_agent_list` Table pattern** (lines 1863-1916):
```rust
/// Draws the USB scan and register screen as a 5-column table.
///
/// Columns: VID | PID | Serial | Description | Registered
/// Already-registered devices show their current tier in the Registered column;
/// unregistered devices show `-` (D-04).
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
        Constraint::Percentage(8),   // VID
        Constraint::Percentage(8),   // PID
        Constraint::Percentage(20),  // Serial
        Constraint::Percentage(44),  // Description
        Constraint::Percentage(20),  // Registered
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

    // Only select a row when the list is non-empty to avoid TableState with
    // Some(idx) on an empty table (ratatui silently clamps, but explicit guard
    // is clearer).
    let mut state = ratatui::widgets::TableState::default();
    if !devices.is_empty() {
        state.select(Some(selected));
    }
    frame.render_stateful_widget(table, area, &mut state);

    draw_hints(frame, area, "r: Scan   Up/Down: Navigate   Enter: Register   Esc: Back");
}
```

**`draw_status_bar` — no change needed** (already handles `StatusKind::Info/Success/Error`,
lines 2056-2066).

---

### `dlp-admin-cli/src/client.rs` (HTTP client, no modification needed)

**Analog:** self — `get<T>` (lines 210-228), `post<T, B>` (lines 231+).

The existing `EngineClient::get::<Vec<serde_json::Value>>("admin/device-registry/full")` and
`EngineClient::post::<serde_json::Value, _>("admin/device-registry", &body)` already cover
all required endpoints. No new methods needed.

**Confirmed patterns for use in dispatch.rs:**
```rust
// GET — already used by action_load_device_list (dispatch.rs line 3585):
app.client.get::<Vec<serde_json::Value>>("admin/device-registry/full")

// POST — already used by handle_device_tier_picker (dispatch.rs line 3721):
app.client.post::<serde_json::Value, _>("admin/device-registry", &body)

// Clone for async move block (EngineClient derives Clone, client.rs line 14):
let client = app.client.clone();
```

---

## Shared Patterns

### `block_on` + single async call
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` lines 3583-3596 (`action_load_device_list`)
**Apply to:** `action_usb_scan` (the GET half)
```rust
// Single async call:
match app.rt.block_on(app.client.get::<Vec<serde_json::Value>>("admin/device-registry/full")) {
    Ok(devices) => { /* update screen */ }
    Err(e) => { app.set_status(format!("Error ...: {e}"), StatusKind::Error); }
}
```

### `block_on` + `tokio::join!` + `spawn_blocking`
**Source:** RESEARCH.md Pitfall 2 (verified against dispatch.rs patterns)
**Apply to:** `action_usb_scan` (concurrent GET + Win32 scan)
```rust
// Clone client first (avoids 'static borrow issue with spawn_blocking):
let client = app.client.clone();
let (registry_result, usb_join) = app.rt.block_on(async move {
    tokio::join!(
        client.get::<Vec<serde_json::Value>>("admin/device-registry/full"),
        tokio::task::spawn_blocking(dlp_common::usb::enumerate_connected_usb_devices)
    )
});
// usb_join: Result<Vec<DeviceIdentity>, tokio::task::JoinError>
let usb_devices = usb_join.unwrap_or_default();
```

### Status bar API
**Source:** `dlp-admin-cli/src/app.rs` lines 650-652 (`App::set_status`)
**Apply to:** All action functions in dispatch.rs for UsbScan
```rust
app.set_status("message", StatusKind::Info);    // neutral feedback
app.set_status("message", StatusKind::Success); // after successful POST
app.set_status("message", StatusKind::Error);   // after any failure
```

### `nav` helper
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` lines 61-72
**Apply to:** `handle_usb_scan` Up/Down handling
```rust
// nav wraps at both ends: Up at 0 wraps to count-1; Down at count-1 wraps to 0.
fn nav(selected: &mut usize, count: usize, key: KeyCode) {
    match key {
        KeyCode::Up => { *selected = selected.checked_sub(1).unwrap_or(count - 1); }
        KeyCode::Down => { *selected = (*selected + 1) % count; }
        _ => {}
    }
}
```

### Empty-list guard before index access
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` lines 3624-3627, 3641-3644
**Apply to:** `handle_usb_scan` Up/Down and Enter handlers
```rust
if devices_len == 0 {
    return;
}
```

### `draw_menu` for simple list screens
**Source:** `dlp-admin-cli/src/screens/render.rs` lines 236-244 (DevicesMenu arm)
**Apply to:** `DevicesMenu` arm patch (3-item list)
```rust
draw_menu(frame, area, "Devices & Origins",
    &["Device Registry", "Managed Origins", "Scan & Register USB"], *selected);
draw_hints(frame, area, "Enter: Open   Esc: Main Menu");
```

### `CallerScreen` enum pattern (for `TierPickerCaller`)
**Source:** `dlp-admin-cli/src/app.rs` lines 152-158
**Apply to:** `TierPickerCaller` enum declaration
```rust
// Exact structural pattern:
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerScreen {
    PolicyCreate,
    PolicyEdit,
}
// TierPickerCaller mirrors this with DeviceList + UsbScan variants.
```

### SetupDi enumeration loop + safety valve
**Source:** `dlp-agent/src/detection/usb.rs` lines 748-787
**Apply to:** `enumerate_connected_usb_devices_windows` inner loop
```rust
// Pattern: index: u32 = 0; loop { SetupDiEnumDeviceInfo -> Err -> break;
//          ... process ...; index += 1; if index > 1024 { break; } }
// Cleanup: let _ = unsafe { SetupDiDestroyDeviceInfoList(hdev) };
```

---

## No Analog Found

All 8 files have clear analogs. No files require falling back to RESEARCH.md external
patterns only.

---

## Metadata

**Analog search scope:** `dlp-admin-cli/src/`, `dlp-common/src/`, `dlp-agent/src/detection/`
**Files scanned:** 8 source files read directly
**Pattern extraction date:** 2026-04-29
