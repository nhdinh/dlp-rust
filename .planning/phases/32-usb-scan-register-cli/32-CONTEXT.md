# Phase 32: USB Scan & Register CLI — Context

**Gathered:** 2026-04-29
**Status:** Ready for planning

<domain>
## Phase Boundary

Add a "Scan & Register USB" feature to `dlp-admin-cli`: when an admin opens the new screen, they can trigger a scan of all USB mass storage devices currently plugged into the local machine (via SetupDi), see each device's VID/PID/serial/description, cross-reference against the server's device registry, and select one to register with a trust tier — replacing the need to manually type VID/PID/serial/description for devices that are physically present.

**In scope:**
- New `dlp-common/src/usb.rs` module with `pub fn enumerate_connected_usb_devices() -> Vec<DeviceIdentity>` (Windows-only, cfg-guarded)
- Move agent's private `parse_usb_device_path` and `setupdi_description_for_device` logic into the shared function
- New `Screen::UsbScan` state in `dlp-admin-cli`
- New "Scan & Register USB" entry as the 3rd item in `DevicesMenu`
- `GET /admin/device-registry` + local USB enumeration run concurrently on scan
- Already-registered devices shown with tier annotation (`[read_only]`, `[blocked]`, etc.)
- Enter on a device → existing `DeviceTierPicker` screen → on success, return to scan list
- Description auto-populated from SetupDi (no editing step)
- Single-select, natural loop (select → register → back to list → repeat)

**Out of scope:**
- Editing device description before registration (use Device Registry screen instead)
- Multi-select batch registration
- USB enumeration on non-Windows platforms (cfg-guarded, returns empty vec)
- Replacing the existing manual `r`-key register flow in `DeviceList`

</domain>

<decisions>
## Implementation Decisions

### UX — Navigation
- **D-01:** Add "Scan & Register USB" as the 3rd entry in `DevicesMenu` (after "Device Registry" and "Managed Origins").
- **D-02:** Screen opens empty. The `r` key triggers the USB scan. This lets the admin plug in a USB mid-session and rescan without leaving the screen.
- **D-03:** After successful registration, return to the scan list (not `DeviceList`). Show a success status bar message. Admin can immediately select the next device.

### UX — Scan Screen Layout
- **D-04:** The scan list shows columns: VID | PID | Serial | Description | Registered. Already-registered devices show their current tier (e.g., `[read_only]`) in the Registered column; unregistered devices show `-`.
- **D-05:** Enter on any row (registered or not) advances to the existing `DeviceTierPicker` screen. Re-registering an already-registered device updates its tier via `POST /admin/device-registry` (server upserts on VID+PID+serial).
- **D-06:** Status bar shows scan results: "N USB devices found (M already registered)". On empty: "No USB mass storage devices found. Plug in a device and press r to rescan."

### Code Location — USB Enumeration
- **D-07:** Create `dlp-common/src/usb.rs` with `pub fn enumerate_connected_usb_devices() -> Vec<DeviceIdentity>`. This is the single canonical USB scanner shared across crates.
- **D-08:** The function is `#[cfg(windows)]` only. On non-Windows it returns `vec![]` via a stub. Add `windows` crate features for SetupDi (`Win32_Devices_DeviceAndDriverInstallation`) under `[target.'cfg(windows)'.dependencies]` in `dlp-common/Cargo.toml`.
- **D-09:** Refactor `parse_usb_device_path` and `setupdi_description_for_device` out of `dlp-agent/src/detection/usb.rs` into this new module. The agent then delegates to `dlp_common::usb::enumerate_connected_usb_devices()` or the shared helpers rather than duplicating them.
- **D-10:** Enumerate USB mass storage only — use `GUID_DEVINTERFACE_USB_DEVICE` (the existing proven GUID used by the agent). Research confirmed `GUID_DEVINTERFACE_DISK` paths have a different format incompatible with `parse_usb_device_path`; filter to devices with non-empty VID+PID to exclude hubs and HID devices. This GUID is used in `dlp-agent` today and is tested.

### Data Fetching
- **D-11:** On `r` keypress, run two operations concurrently (via `tokio::join!`): `GET /admin/device-registry` (fetch registered devices) and `enumerate_connected_usb_devices()` (local scan). Merge: build a `HashMap<(vid, pid, serial), Option<String>>` where the value is the trust_tier if registered. Display once both complete.

### Registration Flow
- **D-12:** Description field uses the SetupDi-captured value (friendly name, fallback to device description) as-is. No intermediate editing step. Admin must use the Device Registry screen to change the description after registration.
- **D-13:** Single-select: one device per registration cycle. No Space/multi-select batch mode. The "return to scan list" behavior after each registration already makes registering multiple devices fast.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Existing USB Code (to be refactored)
- `dlp-agent/src/detection/usb.rs` — private `parse_usb_device_path` (parses VID/PID/serial from `\\?\USB#VID_XXXX&PID_YYYY#SERIAL#{...}` paths) and `setupdi_description_for_device` (SetupDi SPDRP_FRIENDLYNAME lookup) must be extracted to `dlp-common/src/usb.rs`
- `dlp-common/src/endpoint.rs` — `DeviceIdentity` struct (vid, pid, serial, description fields); `UsbTrustTier` enum — these are the shared types the new enumeration fn returns

### Admin CLI — Existing Screens
- `dlp-admin-cli/src/app.rs` — `Screen` enum (add `UsbScan` variant), `InputPurpose` enum, `DevicesMenu`, `DeviceList`, `DeviceTierPicker` — new screen integrates as a peer of `DeviceList`
- `dlp-admin-cli/src/screens/dispatch.rs` — event handler; new `Screen::UsbScan` branch required
- `dlp-admin-cli/src/screens/render.rs` — rendering; new `draw_usb_scan` function required
- `dlp-admin-cli/src/client.rs` — `EngineClient` for `GET /admin/device-registry`

### Server API
- `dlp-server/src/admin_api.rs` — `POST /admin/device-registry` request/response shape (`DeviceRegistryRequest`: vid, pid, serial, description, trust_tier); `GET /admin/device-registry` returns `Vec<PublicDeviceEntry>` with trust_tier

### Prior Phase Context
- `.planning/phases/24-device-registry-db-admin-api/24-CONTEXT.md` — server-side device registry decisions
- `.planning/phases/28-admin-tui-screens/28-CONTEXT.md` — DevicesMenu and DeviceList screen design decisions

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `Screen::DeviceTierPicker { vid, pid, serial, description, selected }` — already exists; this phase routes into it from `UsbScan` instead of from `DeviceList`'s manual register flow. The tier picker handles `POST /admin/device-registry` on confirm.
- `dlp-agent/src/detection/usb.rs::parse_usb_device_path` and `setupdi_description_for_device` — ~120 lines of working SetupDi code; extract rather than rewrite
- `App::set_status(msg, StatusKind)` — existing status bar API; use for scan result summary and success/error feedback
- `EngineClient` in `dlp-admin-cli/src/client.rs` — existing typed HTTP client; `GET /admin/device-registry` is already called from `DeviceList`'s load logic

### Established Patterns
- TUI screens store all mutable state in the `Screen` enum variant fields (see `Screen::DeviceList { devices, selected }`); `Screen::UsbScan` follows the same pattern
- Async HTTP calls use `app.rt.block_on(...)` inside event handlers (synchronous ratatui event loop bridges into tokio)
- Status bar uses `app.set_status(msg, StatusKind::Success/Error)` after any server operation
- `DevicesMenu { selected }` uses a fixed `items` list for rendering; adding a 3rd item requires updating the render and dispatch for that screen

### Integration Points
- `DevicesMenu` dispatch: Enter on index 2 → `Screen::UsbScan { devices: vec![], scanning: false }`
- `UsbScan` dispatch: `r` keypress → call `enumerate_connected_usb_devices()` + `GET /admin/device-registry` concurrently → update `Screen::UsbScan { devices, ... }`
- `UsbScan` dispatch: Enter on selected row → transition to `Screen::DeviceTierPicker { vid, pid, serial, description, selected: 0 }`
- `DeviceTierPicker` on success: currently returns to `DeviceList`; needs to return to `UsbScan` when caller is the scan screen (add a `caller: TierPickerCaller` field — enum variant `DeviceList` vs `UsbScan`)

</code_context>

<specifics>
## Specific Requirements

### UsbScan Screen State
```rust
Screen::UsbScan {
    /// Merged list: local USB devices cross-referenced with server registry.
    devices: Vec<UsbScanEntry>,
    /// Currently highlighted row index.
    selected: usize,
}

struct UsbScanEntry {
    identity: DeviceIdentity,         // VID, PID, serial, description
    registered_tier: Option<String>,  // None = not in registry; Some("read_only") = registered
}
```

### Keybindings for UsbScan
- `r` — trigger scan (enumerate + fetch registry)
- `Up`/`Down` — navigate list
- `Enter` — open `DeviceTierPicker` for selected device
- `Esc` — back to `DevicesMenu`

### DeviceTierPicker caller routing
Add `caller: TierPickerCaller` to `Screen::DeviceTierPicker` where:
```rust
enum TierPickerCaller {
    DeviceList,
    UsbScan,
}
```
On success, route back to the appropriate screen.

</specifics>

<deferred>
## Deferred Ideas

- **Multi-select batch registration** — Admin suggested skipping this; single-select loop is sufficient. Future phase if volume of USB registrations warrants it.
- **Editable description** — If SetupDi produces generic names (e.g., "USB Mass Storage Device"), admins may want to override. Deferred: use Device Registry screen for post-registration edits.
- **Persistent scan history** — Showing previously-seen (but currently unplugged) devices. Out of scope: scan is point-in-time, not a history.

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 32-usb-scan-register-cli*
*Context gathered: 2026-04-29*
