# Phase 32: USB Scan & Register CLI — Research

**Researched:** 2026-04-29
**Domain:** Rust / ratatui TUI + Windows SetupDi USB enumeration + dlp-common refactor
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** "Scan & Register USB" is the 3rd entry in DevicesMenu (after "Device Registry" and "Managed Origins").
- **D-02:** Screen opens empty; `r` key triggers USB scan.
- **D-03:** After successful registration return to UsbScan, show success status bar message.
- **D-04:** Scan list columns: VID | PID | Serial | Description | Registered (tier string or `-`).
- **D-05:** Enter on any row (registered or not) opens DeviceTierPicker for update/initial register.
- **D-06:** Status bar: "N USB devices found (M already registered)". Empty: "No USB mass storage devices found. Plug in a device and press r to rescan."
- **D-07:** New `dlp-common/src/usb.rs` with `pub fn enumerate_connected_usb_devices() -> Vec<DeviceIdentity>`.
- **D-08:** Function is `#[cfg(windows)]` only; non-Windows stub returns `vec![]`. Windows crate features for SetupDi under `[target.'cfg(windows)'.dependencies]` in `dlp-common/Cargo.toml`.
- **D-09:** Extract `parse_usb_device_path` and `setupdi_description_for_device` from `dlp-agent/src/detection/usb.rs` into the new module. Agent delegates to shared helpers.
- **D-10:** Enumerate USB mass storage only via `GUID_DEVINTERFACE_DISK` filtered to removable media.
- **D-11:** On `r` keypress: `tokio::join!` two concurrent operations: `GET /admin/device-registry` + `enumerate_connected_usb_devices()`. Merge into `HashMap<(vid, pid, serial), Option<String>>`.
- **D-12:** Description auto-populated from SetupDi; no editing step.
- **D-13:** Single-select only.

### Claude's Discretion

None listed — all major decisions are locked.

### Deferred Ideas (OUT OF SCOPE)

- Multi-select batch registration
- Editable description before registration
- Persistent scan history (point-in-time scan only)
</user_constraints>

---

## Summary

This phase has two distinct parts: (1) a library refactor — moving ~160 lines of working SetupDi code from `dlp-agent` into a new `dlp-common/src/usb.rs` shared module, and (2) a new TUI screen — `Screen::UsbScan` in `dlp-admin-cli` that uses the shared code plus the existing server API to show and register physically-connected USB devices.

The codebase is well-understood. All the raw materials exist: the SetupDi enumeration logic is in `dlp-agent/src/detection/usb.rs` (functions `parse_usb_device_path` and `setupdi_description_for_device`), the shared types `DeviceIdentity` and `UsbTrustTier` are in `dlp-common/src/endpoint.rs`, the server API shape (`DeviceRegistryRequest` / `DeviceRegistryResponse`) is in `dlp-server/src/admin_api.rs`, and the TUI patterns for multi-column tables, menu navigation, and `DeviceTierPicker` are established in `dlp-admin-cli`.

The key engineering challenges are: (a) the refactored `enumerate_connected_usb_devices` must switch from `GUID_DEVINTERFACE_USB_DEVICE` (used by agent's event-driven arrival handler) to `GUID_DEVINTERFACE_DISK` filtered to removable media (per D-10), which is a different SetupDi enumeration strategy; (b) `tokio::join!` inside `app.rt.block_on(...)` is the correct concurrency bridge since the TUI event loop is synchronous; (c) `DeviceTierPicker` needs a new `caller: TierPickerCaller` field to route back to `UsbScan` instead of always returning to `DeviceList`.

**Primary recommendation:** Implement in three waves: Wave 0 (test stubs), Wave 1 (dlp-common/src/usb.rs + agent refactor), Wave 2 (TUI state + dispatch + render).

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| USB hardware enumeration | dlp-common (shared lib) | — | Must be usable by both dlp-agent and dlp-admin-cli without duplication |
| Scan trigger + data merge | dlp-admin-cli dispatch | dlp-common | TUI owns the orchestration; dlp-common provides the enumeration fn |
| Registry cross-reference | dlp-admin-cli dispatch | dlp-server API | GET /admin/device-registry/full returns full rows with trust_tier |
| UsbScan screen state | dlp-admin-cli app.rs | — | Screen enum variant; follows established pattern |
| Device registration | dlp-server API | dlp-admin-cli | POST /admin/device-registry (upsert); same path used by existing TierPicker |
| Return routing (TierPicker) | dlp-admin-cli dispatch | — | TierPickerCaller enum controls post-registration navigation |

---

## Standard Stack

### Core (already in workspace — no new top-level deps needed)

| Library | Version | Purpose | Notes |
|---------|---------|---------|-------|
| `windows` crate | 0.61.3 (in Cargo.lock) | SetupDi Win32 API bindings | Already in `dlp-common` `[target.'cfg(windows)'.dependencies]`; need to ADD features |
| `ratatui` | 0.29 | TUI rendering | Already in `dlp-admin-cli` |
| `crossterm` | 0.28 | Terminal backend | Already in `dlp-admin-cli` |
| `tokio` | 1 (workspace) | Async runtime + `join!` | Already in `dlp-admin-cli` |
| `dlp-common` | workspace | Shared types (`DeviceIdentity`, `UsbTrustTier`) | Already in `dlp-admin-cli` |

[VERIFIED: Cargo.toml files + Cargo.lock]

### New windows crate features required in dlp-common/Cargo.toml

The existing `dlp-common` `[target.'cfg(windows)'.dependencies]` block already declares `windows = { version = "0.61", features = [...] }` but does NOT include the SetupDi features. Add:

```toml
[target.'cfg(windows)'.dependencies]
windows = { version = "0.61", features = [
    # existing features...
    "Win32_NetworkManagement_NetManagement",
    "Win32_NetworkManagement_Ndis",
    "Win32_NetworkManagement_IpHelper",
    "Win32_Networking_ActiveDirectory",
    "Win32_Networking_WinSock",
    "Win32_Foundation",
    # NEW for usb.rs enumeration:
    "Win32_Devices_DeviceAndDriverInstallation",
    "Win32_Storage_FileSystem",
] }
```

`Win32_Devices_DeviceAndDriverInstallation` provides `SetupDiGetClassDevsW`, `SetupDiEnumDeviceInfo`, `SetupDiGetDeviceRegistryPropertyW`, `SetupDiDestroyDeviceInfoList`, `SP_DEVINFO_DATA`, `DIGCF_PRESENT`, `DIGCF_DEVICEINTERFACE`, `SETUP_DI_REGISTRY_PROPERTY`.

`Win32_Storage_FileSystem` provides `GetDriveTypeW` (needed if the enumeration fn also wants to confirm removable status — see D-10 note below).

[VERIFIED: dlp-common/Cargo.toml, dlp-agent/Cargo.toml, dlp-agent/src/detection/usb.rs imports]

---

## Architecture Patterns

### System Architecture Diagram

```
[Admin presses 'r' on UsbScan screen]
         |
         v
[dispatch: app.rt.block_on(async {
    tokio::join!(
        client.get("admin/device-registry"),       --> [dlp-server GET /admin/device-registry/full]
        tokio::task::spawn_blocking(||
            dlp_common::usb::enumerate_connected_usb_devices()  --> [Win32 SetupDi]
        )
    )
})]
         |
    [merge results]
    HashMap<(vid,pid,serial), Option<trust_tier>>
         |
         v
    [Screen::UsbScan { devices: Vec<UsbScanEntry>, selected }]
         |
    [render: draw_usb_scan -- ratatui Table widget]
         |
    [Enter on row]
         |
         v
    [Screen::DeviceTierPicker { ..., caller: TierPickerCaller::UsbScan }]
         |
    [Enter confirms tier]
         |
         v
    [POST /admin/device-registry]  --> [dlp-server upsert]
         |
    [on success: app.set_status + restore Screen::UsbScan]
```

### Recommended Project Structure

```
dlp-common/src/
├── usb.rs           # NEW: pub fn enumerate_connected_usb_devices()
│                    #      + pub(crate) parse_usb_device_path (moved from agent)
│                    #      + pub(crate) setupdi_description_for_device (moved from agent)
├── lib.rs           # ADD: pub mod usb; pub use usb::enumerate_connected_usb_devices;
└── endpoint.rs      # unchanged (DeviceIdentity, UsbTrustTier already here)

dlp-agent/src/detection/
└── usb.rs           # MODIFY: remove parse_usb_device_path + setupdi_description_for_device
                     #          call dlp_common::usb::enumerate_connected_usb_devices() instead
                     #          (or keep parse_usb_device_path in agent for path-parsing from
                     #           arrival events — see critical note below)

dlp-admin-cli/src/
├── app.rs           # ADD: Screen::UsbScan, TierPickerCaller enum, UsbScanEntry struct
└── screens/
    ├── dispatch.rs  # ADD: handle_usb_scan, action_usb_scan,
    │                #      update handle_devices_menu (nav 3, idx 2 -> UsbScan),
    │                #      update handle_device_tier_picker (caller routing)
    └── render.rs    # ADD: draw_usb_scan (Table widget, 5 columns)
                     #      update draw_screen match arm for Screen::DevicesMenu (3 items)
                     #      update draw_screen match arm for Screen::DeviceTierPicker (no change to render)
                     #      update draw_screen match arm for Screen::UsbScan
```

---

## Critical Implementation Notes

### D-10: GUID_DEVINTERFACE_DISK vs GUID_DEVINTERFACE_USB_DEVICE

The agent's existing `setupdi_description_for_device` enumerates using `GUID_DEVINTERFACE_USB_DEVICE`. Decision D-10 requires the new `enumerate_connected_usb_devices` to use `GUID_DEVINTERFACE_DISK` filtered to removable media — the same class the agent tracks for enforcement.

**GUID_DEVINTERFACE_DISK:**
`{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}` — storage class; covers all disk devices including USB mass storage drives. Filter by checking `GetDriveTypeW` returns `DRIVE_REMOVABLE` (= 2) for the associated drive letter, OR use `SetupDiGetDeviceRegistryPropertyW` with `SPDRP_REMOVAL_POLICY` (= 0x001F) to detect removable media without needing a drive letter.

**Simpler approach (matches existing agent pattern):** Enumerate `GUID_DEVINTERFACE_USB_DEVICE` (which the agent already does successfully for identity capture), then for each device attempt to get VID/PID/serial by parsing the device instance ID. This avoids needing to cross-reference disk letters. The agent's `setupdi_description_for_device` already does exactly this and works.

**Recommendation:** Re-use `GUID_DEVINTERFACE_USB_DEVICE` enumeration (proven working code) and filter to only devices that have a VID and non-empty PID (i.e., real storage devices, not hubs). This is lower-risk than switching to `GUID_DEVINTERFACE_DISK` which requires additional property reads. The planner should decide which GUID to use — document both options and flag for confirmation.

[ASSUMED — the D-10 requirement to use GUID_DEVINTERFACE_DISK may need implementation verification against actual SetupDi behavior on Windows]

### D-09: What to keep in dlp-agent vs what to move

**`parse_usb_device_path`**: This function parses `dbcc_name` strings (e.g., `\\?\USB#VID_0951&PID_1666#SN#GUID`). It is called both in `on_usb_device_arrival` and `on_usb_device_removal` from the WM_DEVICECHANGE callback. It must remain callable from the agent. Two options:

Option A: Move to `dlp-common/src/usb.rs` as a `pub fn` — agent imports from dlp-common.
Option B: Move to `dlp-common/src/usb.rs` as `pub(crate)` and provide a wrapper.

**Recommendation: Option A** — make it `pub fn parse_usb_device_path(dbcc_name: &str) -> DeviceIdentity` in dlp-common. It has no Windows API calls (pure string parsing), so no `#[cfg(windows)]` guard needed. The agent can call `dlp_common::usb::parse_usb_device_path(path)` directly.

**`setupdi_description_for_device`**: Has Win32 calls, needs `#[cfg(windows)]`. Move to `dlp-common/src/usb.rs` under `#[cfg(windows)]`. The agent calls `dlp_common::usb::setupdi_description_for_device(path)`.

**`enumerate_connected_usb_devices`**: New function that calls both of the above internally. Returns `Vec<DeviceIdentity>` with descriptions populated.

[VERIFIED: dlp-agent/src/detection/usb.rs — both functions are private (no `pub`), no external callers outside this module]

### D-11: tokio::join! concurrency pattern

The TUI event loop is synchronous. All async calls go through `app.rt.block_on(...)`. The `tokio::join!` macro runs two futures concurrently within a single `block_on` call:

```rust
// In handle_usb_scan's action_usb_scan function:
let (registry_result, usb_result) = app.rt.block_on(async {
    tokio::join!(
        app.client.get::<Vec<serde_json::Value>>("admin/device-registry/full"),
        tokio::task::spawn_blocking(|| {
            #[cfg(windows)]
            { dlp_common::usb::enumerate_connected_usb_devices() }
            #[cfg(not(windows))]
            { vec![] }
        })
    )
});
```

Note: `spawn_blocking` is needed because `enumerate_connected_usb_devices` makes blocking Win32 calls. It returns `Result<Vec<DeviceIdentity>, JoinError>` from `spawn_blocking`, so the result needs `.unwrap_or_default()` or explicit error handling.

[VERIFIED: dispatch.rs — existing pattern is `app.rt.block_on(app.client.get::<T>(path))` for single calls; tokio::join! is not yet used but tokio = { version = "1", features = ["full"] } in workspace deps provides it]

### TierPickerCaller enum and routing

The existing `handle_device_tier_picker` function (dispatch.rs line 3680):
- On Esc: goes to `Screen::DevicesMenu { selected: 0 }`
- On Enter+success: calls `action_load_device_list(app)` (navigates to DeviceList)
- On Enter+error: goes to `Screen::DevicesMenu { selected: 0 }`

After adding `caller: TierPickerCaller`, the success path becomes:

```rust
match caller {
    TierPickerCaller::DeviceList => action_load_device_list(app),
    TierPickerCaller::UsbScan => {
        // restore UsbScan with same devices list, set success status
        app.set_status("Device registered successfully.", StatusKind::Success);
        // rebuild UsbScan screen -- re-scan or restore from saved state
    }
}
```

**Design question:** On return to UsbScan after registration, should the screen re-run the full scan (fresh data) or restore the previous devices list? D-03 says "return to the scan list" with a success message. Re-running the scan gives fresh registered state (the just-registered device now shows its tier). This is the better UX.

**Recommendation:** On success from TierPicker, call a new `action_usb_scan(app)` function that re-runs the concurrent scan. The `selected` index should be preserved or reset to 0.

To preserve the previous scan results without re-scanning (simpler), the `Screen::UsbScan` variant can be directly restored — but the tier column would be stale. Re-scanning is cleaner.

[ASSUMED — exact behavior on UsbScan restoration (re-scan vs restore) needs final decision]

---

## Pattern 1: Multi-Column ratatui Table (established codebase pattern)

The `draw_usb_scan` function should use the same `Table::new` pattern as `draw_agent_list` and `draw_policy_list`.

```rust
// Source: dlp-admin-cli/src/screens/render.rs (draw_agent_list, line 1863)
fn draw_usb_scan(
    frame: &mut Frame,
    area: Rect,
    devices: &[UsbScanEntry],
    selected: usize,
) {
    let header = Row::new(vec!["VID", "PID", "Serial", "Description", "Registered"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = if devices.is_empty() {
        // empty state handled by showing hint in status bar per D-06;
        // render an empty table body
        vec![]
    } else {
        devices.iter().map(|e| {
            let tier = e.registered_tier.as_deref().unwrap_or("-");
            Row::new(vec![
                e.identity.vid.clone(),
                e.identity.pid.clone(),
                e.identity.serial.clone(),
                e.identity.description.clone(),
                tier.to_string(),
            ])
        }).collect()
    };

    let widths = [
        Constraint::Percentage(8),   // VID
        Constraint::Percentage(8),   // PID
        Constraint::Percentage(20),  // Serial
        Constraint::Percentage(44),  // Description
        Constraint::Percentage(20),  // Registered
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default()
            .title(format!(" USB Scan ({}) ", devices.len()))
            .borders(Borders::ALL))
        .row_highlight_style(
            Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
        )
        .highlight_symbol("> ");

    let mut state = ratatui::widgets::TableState::default();
    if !devices.is_empty() {
        state.select(Some(selected));
    }
    frame.render_stateful_widget(table, area, &mut state);

    draw_hints(frame, area, "r: Scan   Enter: Register   Esc: Back");
}
```

[VERIFIED: render.rs lines 1863-1916 (draw_agent_list), 1400-1462 (draw_policy_list)]

### Pattern 2: DevicesMenu dispatch — adding a 3rd item

Current `handle_devices_menu` uses `nav(selected, 2, key.code)` (2 items). Change to `nav(selected, 3, key.code)` and add `2 => action_open_usb_scan(app)` to the Enter match.

Current render uses `&["Device Registry", "Managed Origins"]`. Change to `&["Device Registry", "Managed Origins", "Scan & Register USB"]`.

[VERIFIED: dispatch.rs lines 3560-3579, render.rs lines 236-244]

### Pattern 3: enumerate_connected_usb_devices function signature

```rust
// dlp-common/src/usb.rs
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

/// Parses a USB device interface path into a `DeviceIdentity`.
///
/// Pure string parsing — no Win32 calls, no cfg guard needed.
/// Input: `\\?\USB#VID_0951&PID_1666#SERIAL#{GUID}`
/// Returns `DeviceIdentity` with empty `description` (filled separately).
pub fn parse_usb_device_path(dbcc_name: &str) -> DeviceIdentity {
    // ... (moved from dlp-agent verbatim)
}

#[cfg(windows)]
fn setupdi_description_for_device(device_path: &str) -> String {
    // ... (moved from dlp-agent verbatim)
}
```

[VERIFIED: dlp-agent/src/detection/usb.rs lines 1063-1088 (parse_usb_device_path), 725-797 (setupdi_description_for_device)]

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Concurrent async + blocking USB scan | Manual thread spawn + channel | `tokio::join!` + `spawn_blocking` | Integrates with existing `block_on` pattern; handles panics via JoinError |
| USB device description lookup | Custom registry queries | Existing `setupdi_description_for_device` (move, don't rewrite) | ~70 lines of tested Win32 code already handles edge cases |
| USB path parsing | New parser | Existing `parse_usb_device_path` (move, don't rewrite) | Has 8 unit tests covering edge cases including synthesized serials |
| Multi-column TUI table | Custom widget | `ratatui::widgets::Table` + `TableState` | Already used in `draw_agent_list` and `draw_policy_list` |
| Device registration HTTP | Custom | `app.client.post::<DeviceRegistryResponse, _>("admin/device-registry", &body)` | Existing pattern, existing server endpoint |

---

## Common Pitfalls

### Pitfall 1: windows crate version mismatch between dlp-common and dlp-agent

**What goes wrong:** `dlp-common` declares `windows = "0.61"` while `dlp-agent` declares `windows = "0.58"`. Cargo resolves these as separate crates. If `usb.rs` uses Windows types from 0.61 (e.g., `HDEVINFO`), the agent cannot pass those types to dlp-common functions from its 0.58 imports — they are different types at the type level.

**Why it happens:** The functions being moved use `HDEVINFO`, `SP_DEVINFO_DATA` as parameters in internal helper functions (`read_string_property`). If those helpers remain as internal `fn` (not exported), this is not an issue — callers never see the Win32 types.

**How to avoid:** Keep all Win32 types internal to `dlp-common/src/usb.rs`. The only public API surface is `enumerate_connected_usb_devices() -> Vec<DeviceIdentity>` and `parse_usb_device_path(&str) -> DeviceIdentity`. Both use only `DeviceIdentity` from dlp-common's own types.

[VERIFIED: dlp-common/Cargo.toml uses windows 0.61; dlp-agent/Cargo.toml uses windows 0.58]

### Pitfall 2: spawn_blocking closure cannot capture &EngineClient

**What goes wrong:** `tokio::task::spawn_blocking` requires `'static` — it cannot capture borrows of `app.client`. The USB enumeration function has no network call, but if you try to inline the GET call inside the join!, you cannot borrow `app.client` in a `move` closure with `'static` bound.

**How to avoid:** Use `tokio::join!` with two independent futures. The registry GET is a standard `async` future (`app.client.get(...)`) — it does NOT go in `spawn_blocking`. Only the blocking `enumerate_connected_usb_devices()` call goes in `spawn_blocking`. The join! macro runs them concurrently on the current tokio runtime:

```rust
let client_ref = &app.client;
let (reg, usb) = app.rt.block_on(async {
    tokio::join!(
        client_ref.get::<Vec<serde_json::Value>>("admin/device-registry/full"),
        tokio::task::spawn_blocking(enumerate_connected_usb_devices)
    )
});
```

[VERIFIED: dispatch.rs patterns — all existing block_on calls use `&app.client` borrow]

### Pitfall 3: TierPickerCaller breaks existing DeviceList flow

**What goes wrong:** Adding `caller: TierPickerCaller` to `Screen::DeviceTierPicker` is a breaking change to the enum variant. Every pattern match on `Screen::DeviceTierPicker` in the codebase must be updated.

**How to avoid:** Search for all `Screen::DeviceTierPicker` references before changing the struct. There are 4 locations to update:
1. `app.rs` — variant definition
2. `dispatch.rs` — `handle_device_tier_picker` (reads caller field)
3. `dispatch.rs` — `InputPurpose::RegisterDeviceDescription` handler (constructs with `caller: TierPickerCaller::DeviceList`)
4. `render.rs` — `draw_screen` match arm (already uses `..` ignore for most fields, so no change needed there)

[VERIFIED: grep of DeviceTierPicker in dispatch.rs lines 3680-3735, render.rs line 249]

### Pitfall 4: Empty UsbScan list + Enter key panic

**What goes wrong:** If `devices` is empty and user presses Enter, `devices[selected]` panics (index out of bounds on an empty Vec).

**How to avoid:** In `handle_usb_scan`, guard Enter with `if devices.is_empty() { return; }` — same pattern used in `handle_device_list` (dispatch.rs line 3641-3645).

[VERIFIED: dispatch.rs line 3641 — handle_device_list guards `d` key with `devices_len == 0` check]

### Pitfall 5: Registered tier display — endpoint mismatch

**What goes wrong:** The unauthenticated `GET /admin/device-registry` (no `/full`) intentionally omits `trust_tier` (server comment: "unauthenticated callers must not enumerate which devices have elevated access"). If the scan uses this endpoint, the `Registered` column always shows `-`.

**How to avoid:** Use `GET /admin/device-registry/full` (authenticated, returns `DeviceRegistryResponse` with `trust_tier`) — the same endpoint used by `action_load_device_list`. The D-11 spec says "GET /admin/device-registry" but the implementation must use the `/full` variant to get tier information for column D-04.

[VERIFIED: dlp-server/src/admin_api.rs lines 1559-1605; dispatch.rs line 3585 — DeviceList already calls `/full`]

---

## Code Examples

### UsbScanEntry struct (goes in app.rs or a new types module)

```rust
// Source: 32-CONTEXT.md specifics section
/// A single entry in the USB scan list: local device identity cross-referenced
/// with the server registry.
#[derive(Debug, Clone)]
pub struct UsbScanEntry {
    /// VID, PID, serial, description from SetupDi enumeration.
    pub identity: DeviceIdentity,
    /// `None` = not in server registry; `Some("read_only")` = registered with that tier.
    pub registered_tier: Option<String>,
}
```

### TierPickerCaller enum (goes in app.rs)

```rust
// Source: 32-CONTEXT.md specifics section
/// Identifies which screen opened `DeviceTierPicker`, used to route back after
/// successful registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierPickerCaller {
    /// Opened from the manual register flow in DeviceList.
    DeviceList,
    /// Opened from the USB scan screen.
    UsbScan,
}
```

### Screen::UsbScan variant addition

```rust
// Goes in Screen enum in app.rs, after DeviceTierPicker variant
/// USB scan and register screen.
///
/// Opens empty; `r` triggers concurrent USB enumeration + registry fetch.
/// Enter on a row opens `DeviceTierPicker`.
Screen::UsbScan {
    /// Merged local USB devices with registry cross-reference.
    devices: Vec<UsbScanEntry>,
    /// Currently highlighted row index.
    selected: usize,
},
```

### DeviceTierPicker variant with caller field

```rust
// Updated variant in app.rs Screen enum
Screen::DeviceTierPicker {
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

### action_usb_scan function skeleton

```rust
// In dispatch.rs
fn action_usb_scan(app: &mut App) {
    // Run concurrently: GET registry (async) + USB enumerate (blocking).
    // Both run inside a single block_on so the event loop is blocked for
    // the duration — acceptable since USB enumeration is fast (~100ms).
    let client = app.client.clone();
    let (registry_result, usb_result) = app.rt.block_on(async move {
        tokio::join!(
            client.get::<Vec<serde_json::Value>>("admin/device-registry/full"),
            tokio::task::spawn_blocking(dlp_common::usb::enumerate_connected_usb_devices)
        )
    });

    let registry_devices = registry_result.unwrap_or_default();
    let usb_devices = usb_result.unwrap_or_default(); // JoinError -> empty

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

    let entries: Vec<UsbScanEntry> = usb_devices.into_iter().map(|identity| {
        let key = (identity.vid.clone(), identity.pid.clone(), identity.serial.clone());
        let registered_tier = registry_map.get(&key).cloned();
        UsbScanEntry { identity, registered_tier }
    }).collect();

    let registered_count = entries.iter().filter(|e| e.registered_tier.is_some()).count();
    let total = entries.len();

    let status_msg = if total == 0 {
        "No USB mass storage devices found. Plug in a device and press r to rescan.".to_string()
    } else {
        format!("{total} USB devices found ({registered_count} already registered)")
    };
    app.set_status(status_msg, StatusKind::Info);
    app.screen = Screen::UsbScan { devices: entries, selected: 0 };
}
```

### dlp-common/src/lib.rs addition

```rust
// Add to lib.rs:
pub mod usb;
pub use usb::enumerate_connected_usb_devices;
pub use usb::parse_usb_device_path;
```

---

## State of the Art

| Old Approach | Current Approach | Impact |
|--------------|------------------|--------|
| Agent-private USB enumeration | Shared `dlp-common::usb` module | Admin CLI can scan without duplicating Win32 code |
| Manual 4-step VID/PID/serial/desc input for registration | Scan + auto-populate from SetupDi | Eliminates manual entry for physically-connected devices |
| DeviceTierPicker always returns to DeviceList | TierPickerCaller routing | Single TierPicker serves both DeviceList and UsbScan flows |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Using `GUID_DEVINTERFACE_USB_DEVICE` (existing agent approach) for enumeration is acceptable for D-10 rather than switching to `GUID_DEVINTERFACE_DISK` | Critical Notes, D-10 | If D-10 strictly requires GUID_DEVINTERFACE_DISK, the enumeration strategy needs a different SetupDi call that walks disk devices and checks removable property |
| A2 | On successful registration from UsbScan, re-running the full scan (concurrent GET + SetupDi) is the right behavior for "return to scan list" per D-03 | Architecture, TierPickerCaller | If returning the cached pre-scan list is preferred (faster, no API call), the Screen::UsbScan variant needs to store previous state before transitioning |

---

## Open Questions

1. **GUID for D-10 enumeration**
   - What we know: Agent uses `GUID_DEVINTERFACE_USB_DEVICE` for identity capture on arrival events. D-10 says "use `GUID_DEVINTERFACE_DISK` filtered to removable media."
   - What's unclear: Whether `GUID_DEVINTERFACE_DISK` enumeration via `SetupDiGetClassDevsW` returns usable VID/PID device instance IDs that `parse_usb_device_path` can parse. Disk interface paths have a different format than USB device paths.
   - Recommendation: Use `GUID_DEVINTERFACE_USB_DEVICE` in the new enumeration function (it works in the agent today) with a filter to skip non-storage devices. Flag this for planner decision.

2. **EngineClient::clone() availability**
   - What we know: `EngineClient` derives `Clone` (seen in client.rs line 14: `#[derive(Clone)]`).
   - What's unclear: Whether cloning into the `async move` block is idiomatic or if passing a `&'async` ref is cleaner.
   - Recommendation: Clone is correct here — the async block needs owned data; `reqwest::Client` is internally Arc-backed so clone is cheap.

---

## Environment Availability

Step 2.6: SKIPPED — this phase is code/config changes within the existing workspace. No new external tools, services, or runtimes required beyond what is already present.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` via `cargo test` |
| Config file | none (workspace default) |
| Quick run command | `cargo test -p dlp-common usb` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| D-07/D-09 | `parse_usb_device_path` returns correct DeviceIdentity | unit | `cargo test -p dlp-common usb::tests` | Wave 0 — move existing tests from agent |
| D-07/D-09 | `enumerate_connected_usb_devices` returns Vec (Windows stub OK in CI) | unit | `cargo test -p dlp-common usb::tests::test_enumerate` | Wave 0 |
| D-11 | merge logic: registered devices show tier, unregistered show None | unit | `cargo test -p dlp-admin-cli` (app logic tests) | Wave 0 |
| D-04 | UsbScanEntry registered_tier None shows "-" in render | unit | `cargo test -p dlp-admin-cli screens` | Wave 0 |
| D-01 | DevicesMenu has 3 items | unit | `cargo test -p dlp-admin-cli` | Wave 0 |
| D-05/D-12 | Enter opens TierPicker with pre-populated fields | manual | — | manual-only (Win32 required) |

### Wave 0 Gaps

- [ ] `dlp-common/src/usb.rs` — new file; move `test_parse_happy_path` and all parse tests from agent
- [ ] `dlp-admin-cli/src/app.rs` — tests for `TierPickerCaller`, `UsbScanEntry` default construction
- [ ] Merge logic unit test: given a list of `DeviceIdentity` and `Vec<serde_json::Value>` registry rows, verify correct `UsbScanEntry.registered_tier` population

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | JWT bearer on `GET /admin/device-registry/full` and `POST /admin/device-registry` — already enforced by server |
| V3 Session Management | no | Session managed by existing EngineClient JWT |
| V4 Access Control | yes | Only authenticated admin can scan/register — enforced by server auth middleware |
| V5 Input Validation | yes | VID/PID/serial/description passed to existing `upsert_device_registry_handler` which validates `trust_tier` allowlist; no new validation surface added |
| V6 Cryptography | no | No new crypto operations |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Rogue USB device enumerated and displayed | Information Disclosure | Display-only; registration requires explicit admin Enter+confirm — no auto-registration |
| Oversized SetupDi description injected via malicious USB device | Tampering | `setupdi_description_for_device` uses fixed 1024-byte buffer; truncates silently. Description is only rendered in TUI — no SQL injection surface (description sent to server via existing `upsert_device_registry_handler` which does not validate length beyond DB constraints) |
| VID/PID spoofing by USB device | Spoofing | Out of scope for this phase — same threat exists in current agent flow |

---

## Sources

### Primary (HIGH confidence)
- `dlp-agent/src/detection/usb.rs` — full source of `parse_usb_device_path` (lines 1063-1089), `setupdi_description_for_device` (lines 725-797), `read_string_property` (lines 810-846); verified Win32 feature imports
- `dlp-common/src/endpoint.rs` — `DeviceIdentity`, `UsbTrustTier` struct/enum definitions
- `dlp-common/src/lib.rs` — current module exports; confirmed `pub mod usb` not yet present
- `dlp-common/Cargo.toml` — confirmed windows 0.61 with existing features; confirmed SetupDi features not yet present
- `dlp-admin-cli/src/app.rs` — `Screen` enum, `App` struct, `set_status`, `rt: tokio::runtime::Runtime`
- `dlp-admin-cli/src/screens/dispatch.rs` — `handle_devices_menu` (lines 3560-3579), `handle_device_tier_picker` (lines 3680-3735), `action_load_device_list` (lines 3581-3597), `nav` helper (lines 62-72)
- `dlp-admin-cli/src/screens/render.rs` — `draw_agent_list` Table pattern (lines 1863-1916), `draw_device_list` List pattern (lines 1924-1972), `DevicesMenu` render (lines 236-244), `DeviceTierPicker` render (lines 249-258), `draw_hints` (lines 2041-2054)
- `dlp-server/src/admin_api.rs` — `DeviceRegistryRequest`, `DeviceRegistryResponse`, `PublicDeviceEntry` shapes; route map confirming `/full` variant for authenticated full-detail listing
- `dlp-agent/Cargo.toml` — confirmed windows 0.58 with `Win32_Devices_DeviceAndDriverInstallation`
- `dlp-admin-cli/Cargo.toml` — confirmed no SetupDi deps (correct — USB enumeration lives in dlp-common)
- `Cargo.lock` — confirmed three windows versions: 0.24.0, 0.58.0, 0.61.3 in workspace

### Secondary (MEDIUM confidence)
- `Cargo.toml` (workspace) — confirmed `tokio = { version = "1", features = ["full"] }` provides `tokio::join!` and `spawn_blocking`

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries already in workspace; only feature additions needed
- Architecture: HIGH — all patterns verified from existing codebase; no speculative design
- Pitfalls: HIGH — all pitfalls verified against actual code line numbers
- D-10 GUID strategy: MEDIUM — A2 assumption; both approaches are viable but D-10 spec may require clarification

**Research date:** 2026-04-29
**Valid until:** 2026-05-30 (stable Rust workspace; no fast-moving dependencies)
