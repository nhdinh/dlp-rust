---
phase: 28-admin-tui-screens
plan: "03"
subsystem: dlp-admin-cli
tags: [tui, device-registry, managed-origins, ratatui, dispatch, render]
dependency_graph:
  requires: [28-01, 28-02]
  provides: [DevicesMenu-TUI, DeviceList-TUI, DeviceTierPicker-TUI, ManagedOriginList-TUI]
  affects:
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs
tech_stack:
  added: []
  patterns:
    - Sequential InputPurpose chain for multi-step device register flow
    - Two-phase borrow pattern for extracting scalars before mutable state updates
    - Contextual Esc routing in handle_text_input based on InputPurpose variant
    - on_confirm_yes/on_confirm_cancel helper split for exhaustive ConfirmPurpose dispatch
key_files:
  created: []
  modified:
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs
decisions:
  - "ManagedOriginList Screen variant added alongside DevicesMenu/DeviceList/DeviceTierPicker — Plan 04 wires full managed-origins TUI from this screen"
  - "handle_confirm refactored into on_confirm_yes/on_confirm_cancel helpers to support exhaustive match across 3 ConfirmPurpose variants"
  - "handle_text_input Esc routes to DevicesMenu for device register and managed-origin flows instead of PolicyMenu"
  - "Serial and description fields in register chain allow empty input (optional USB fields)"
  - "#[allow(clippy::enum_variant_names)] on ConfirmPurpose — all variants are Delete* by design"
metrics:
  duration_seconds: 480
  completed_date: "2026-04-23"
  tasks_completed: 2
  files_changed: 3
---

# Phase 28 Plan 03: Device Registry TUI Screens Summary

**One-liner:** Three new Screen variants (DevicesMenu, DeviceList, DeviceTierPicker) plus ManagedOriginList stub wired into dlp-admin-cli with sequential register flow, delete confirmation, full dispatch and render coverage.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| T-28-03-01 | Add Device Registry screen types to app.rs | 35791f1 | dlp-admin-cli/src/app.rs |
| T-28-03-02 | Device Registry dispatch handlers + render arms | 7c90c10 | dlp-admin-cli/src/screens/dispatch.rs, dlp-admin-cli/src/screens/render.rs |

## What Was Built

### Task 1 — app.rs type additions

**InputPurpose variants added:**
- `RegisterDeviceVid` — Step 1 of device register chain
- `RegisterDevicePid { vid }` — Step 2, carries VID
- `RegisterDeviceSerial { vid, pid }` — Step 3, carries VID+PID
- `RegisterDeviceDescription { vid, pid, serial }` — Step 4, carries VID+PID+serial
- `AddManagedOrigin` — single-step add for managed origins

**ConfirmPurpose variants added:**
- `DeleteDevice { id }` — confirm device registry deletion
- `DeleteManagedOrigin { id }` — confirm managed origin deletion

**Screen variants added:**
- `DevicesMenu { selected }` — "Devices & Origins" submenu
- `DeviceList { devices, selected }` — scrollable registered-device list
- `DeviceTierPicker { vid, pid, serial, description, selected }` — final step of register flow
- `ManagedOriginList { origins, selected }` — managed origins list (stub for Plan 04)

### Task 2 — dispatch.rs and render.rs

**dispatch.rs changes:**
- `handle_event` match: added arms for all four new Screen variants
- `handle_main_menu`: updated `nav(selected, 6, ...)`, shifted items so index 3 = DevicesMenu, 4 = simulate, 5 = quit
- `handle_confirm`: refactored into `on_confirm_yes` / `on_confirm_cancel` helpers — exhaustive match across all three `ConfirmPurpose` variants; `y` key now routes correctly
- `handle_text_input`: added `allow_empty` check for `RegisterDeviceSerial` and `RegisterDeviceDescription`; Esc routes to `DevicesMenu` for device register and managed-origin purposes
- `on_text_confirmed`: full device register chain (VID -> PID -> serial -> description -> DeviceTierPicker) plus `AddManagedOrigin` POST handler
- `handle_devices_menu`: Up/Down/Enter/Esc; index 0 loads device list, index 1 loads managed origins
- `action_load_device_list`: `GET admin/device-registry`, transitions to `Screen::DeviceList`
- `action_load_managed_origin_list`: `GET admin/managed-origins`, transitions to `Screen::ManagedOriginList`
- `handle_device_list`: Up/Down nav, `r` starts register chain, `d` opens `Screen::Confirm` with `DeleteDevice`, Esc back to DevicesMenu
- `action_delete_device`: `DELETE admin/device-registry/{id}`, reloads list on success
- `handle_device_tier_picker`: Up/Down cycles tiers (blocked/read_only/full_access), Enter POSTs to `admin/device-registry`, reloads list; Esc back to DevicesMenu
- `handle_managed_origin_list`: Up/Down nav, `a` starts AddManagedOrigin input, `d` opens delete confirm, Esc back to DevicesMenu
- `action_delete_managed_origin`: `DELETE admin/managed-origins/{id}`, reloads list on success

**render.rs changes:**
- `draw_screen` MainMenu arm: updated to 6 items (added "Devices & Origins" at index 3)
- `draw_screen` new arms: `DevicesMenu` (reuses `draw_menu`), `DeviceList`, `DeviceTierPicker` (reuses `draw_menu`), `ManagedOriginList`
- `draw_device_list`: compact one-liner format `[TIER_TAG] VID:{vid} PID:{pid} SER:{serial} "{description}"` with empty-state message; hints `r: Register   d: Delete   Esc: Back`
- `draw_managed_origin_list`: shows origin URL strings; hints `a: Add   d: Delete   Esc: Back`

## Deviations from Plan

### Auto-added: ManagedOriginList Screen variant and handlers

**Rule 2 — Missing critical functionality**
- **Found during:** Task 1 design review
- **Issue:** Plan 04 needs a `ManagedOriginList` screen to navigate to from DevicesMenu index 1. Without the Screen variant and basic handler in this plan, DevicesMenu item 1 would have no dispatch target, making the menu partially broken.
- **Fix:** Added `Screen::ManagedOriginList`, `handle_managed_origin_list`, `action_load_managed_origin_list`, `action_delete_managed_origin`, `draw_managed_origin_list`, and `InputPurpose::AddManagedOrigin` + `ConfirmPurpose::DeleteManagedOrigin`. Plan 04 will override `action_load_managed_origin_list` stub with nothing — it already calls the live API.
- **Files modified:** app.rs, dispatch.rs, render.rs
- **Commits:** 35791f1, 7c90c10

### Auto-fixed: handle_confirm hardcoded irrefutable pattern

**Rule 1 — Bug**
- **Found during:** Task 2 (adding new ConfirmPurpose variants)
- **Issue:** `handle_confirm` `KeyCode::Char('y')` arm had `let ConfirmPurpose::DeletePolicy { id } = &purpose;` — an irrefutable pattern that would panic at runtime (and fail to compile) for `DeleteDevice` and `DeleteManagedOrigin`.
- **Fix:** Refactored into `on_confirm_yes` / `on_confirm_cancel` helpers with exhaustive `match purpose`.
- **Files modified:** dlp-admin-cli/src/screens/dispatch.rs
- **Commit:** 7c90c10

### Auto-fixed: handle_text_input Esc destination for device flows

**Rule 1 — Bug**
- **Found during:** Task 2
- **Issue:** `handle_text_input` Esc always navigated to `Screen::PolicyMenu`, which is wrong context for device register and managed-origin text inputs.
- **Fix:** Added `match &purpose` in the Esc arm to route device register purposes to `DevicesMenu { selected: 0 }` and `AddManagedOrigin` to `DevicesMenu { selected: 1 }`.
- **Files modified:** dlp-admin-cli/src/screens/dispatch.rs
- **Commit:** 7c90c10

### Auto-fixed: empty input rejection for optional device fields

**Rule 1 — Bug**
- **Found during:** Task 2
- **Issue:** `handle_text_input` rejected all empty input, but serial number and description in the device register chain are optional.
- **Fix:** Added `allow_empty` flag for `RegisterDeviceSerial` and `RegisterDeviceDescription` purposes.
- **Files modified:** dlp-admin-cli/src/screens/dispatch.rs
- **Commit:** 7c90c10

## Known Stubs

- `ManagedOriginList` is fully wired (live API calls to `GET/POST/DELETE admin/managed-origins`) — not a stub. Plan 04 adds the full TUI navigation entry point but the screen itself is complete here.

## Threat Flags

None — all new routes follow the established trust boundary pattern:
- `GET admin/device-registry` and `GET admin/managed-origins` are called through `app.client` which carries the JWT from the login session.
- `DELETE` routes pass the UUID from the API response, not from user text input, preventing ID injection.

## Self-Check: PASSED

- Commit 35791f1: FOUND (`feat(28-03): add Device Registry and Managed Origins screen types to app.rs`)
- Commit 7c90c10: FOUND (`feat(28-03): add Device Registry dispatch handlers and render arms`)
- `dlp-admin-cli/src/app.rs` contains `RegisterDeviceVid`: VERIFIED
- `dlp-admin-cli/src/app.rs` contains `DevicesMenu`: VERIFIED
- `dlp-admin-cli/src/screens/dispatch.rs` contains `handle_devices_menu`: VERIFIED
- `dlp-admin-cli/src/screens/dispatch.rs` contains `handle_device_list`: VERIFIED
- `dlp-admin-cli/src/screens/render.rs` contains `DevicesMenu`: VERIFIED
- `dlp-admin-cli/src/screens/render.rs` contains `FULL_ACCESS`: VERIFIED
- `cargo build -p dlp-admin-cli`: 0 errors, 0 warnings
- `cargo clippy -p dlp-admin-cli -- -D warnings`: PASSED
- `cargo fmt -p dlp-admin-cli --check`: PASSED
- `cargo test -p dlp-admin-cli`: 42/42 PASSED
