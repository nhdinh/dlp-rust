# Phase 43 Plan 05: USB Enforcement Config TUI Screen Summary

**Plan:** 43-05
**Phase:** 43
**Subsystem:** dlp-admin-cli (TUI screen rendering and event dispatch)
**Completed:** 2026-05-08
**Duration:** ~22 minutes

---

## Objective

Add a "USB Enforcement Settings" config screen to the dlp-admin-cli TUI. This screen allows the admin to configure `usb_blocked_failure_mode`, `usb_startup_resolution_mode`, and `usb_none_serial_policy` via the existing config form pattern. Exclude unimplemented options to prevent admin confusion.

---

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create shared constants module and Screen variant | (see below) | `dlp-admin-cli/src/screens/usb_enforcement.rs`, `dlp-admin-cli/src/screens/mod.rs`, `dlp-admin-cli/src/app.rs` |
| 2 | Add render function and update SystemMenu | (see below) | `dlp-admin-cli/src/screens/render.rs` |
| 3 | Add dispatch handlers and system menu integration | (see below) | `dlp-admin-cli/src/screens/dispatch.rs` |

---

## Key Changes

### dlp-admin-cli/src/screens/usb_enforcement.rs (NEW)

- Shared constants module for DRY across render.rs and dispatch.rs:
  - `USB_ENFORCEMENT_KEYS`: `["usb_blocked_failure_mode", "usb_startup_resolution_mode", "usb_none_serial_policy"]`
  - `USB_ENFORCEMENT_OPTIONS`: `&[&[&str]]` with variable-length rows (no empty-string padding)
    - Row 0: `["Hard error", "Warning only", "Retry then error"]`
    - Row 1: `["VID/PID/serial fallback"]` ("Volume GUID resolution" excluded)
    - Row 2: `["Always Blocked", "Allow unregistered"]` ("Port-based disambiguation" excluded)
  - `USB_ENFORCEMENT_LABELS`: `["Failure Mode", "Startup Resolution", "(none) Serial Policy"]`
  - `USB_ENFORCEMENT_SAVE_ROW` (3), `USB_ENFORCEMENT_BACK_ROW` (4), `USB_ENFORCEMENT_ROW_COUNT` (5)
- Unit tests verifying keys count, options length alignment, excluded unimplemented options, row constant consistency, and label alignment

### dlp-admin-cli/src/app.rs

- Added `UsbEnforcementConfig` variant to the `Screen` enum (after `LdapConfig`, before `ConditionsBuilder`)
- Variant fields: `config: serde_json::Value`, `selected: usize`, `editing: bool`, `buffer: String`

### dlp-admin-cli/src/screens/render.rs

- Added render arm for `Screen::UsbEnforcementConfig` in `draw_screen`
- Added `draw_usb_enforcement_config` function:
  - Renders 3 picker field rows with labels and current values
  - Renders Save (row 3) and Back (row 4) action rows
  - Shows editing highlight (`> ... <`) when `editing` is true
  - Shows hint bar when editing: "Up/Down: cycle options | Enter: confirm | Esc: cancel"
- Updated `SystemMenu` render to 7 items with "USB Enforcement" at index 5, "Back" at index 6

### dlp-admin-cli/src/screens/dispatch.rs

- Added event dispatch arm for `Screen::UsbEnforcementConfig` in `handle_event`
- Added `action_load_usb_enforcement_config`: GET `/admin/agent-config`, transitions to `UsbEnforcementConfig` screen
- Added `action_save_usb_enforcement_config`: PUT `/admin/agent-config` with full payload, returns to `SystemMenu { selected: 5 }`
- Added `handle_usb_enforcement_config`: routes to editing or nav based on `editing` flag
- Added `handle_usb_enforcement_editing`: cycles picker values with Up/Down, exits edit mode on Enter/Esc
- Added `handle_usb_enforcement_nav`: row navigation with Up/Down, enters edit mode on Enter for picker fields, saves on Save row, returns to SystemMenu on Back row or Esc
- Updated `handle_system_menu`: expanded from 6 to 7 items, USB Enforcement at index 5 triggers `action_load_usb_enforcement_config`
- Added 4 unit tests in `usb_enforcement_tests` module:
  - `usb_enforcement_screen_navigates_all_rows`: verifies Down navigation wraps through all 5 rows
  - `usb_enforcement_editing_cycles_picker_options`: verifies Up/Down cycles picker values
  - `usb_enforcement_enter_exits_edit_mode`: verifies Enter commits edit
  - `usb_enforcement_esc_returns_to_system_menu`: verifies Esc returns to SystemMenu with selected=5

---

## Verification Results

- `cargo test -p dlp-admin-cli --lib`: 106 passed (1 suite)
- `cargo check -p dlp-admin-cli`: Clean (no warnings)
- `cargo fmt --check` for modified files: Clean

---

## Deviations from Plan

None. Plan executed exactly as written.

---

## Auth Gates

None.

---

## Known Stubs

None. All data sources are wired to the server API.

---

## Threat Flags

None beyond what is documented in the plan's threat model. The picker-only input (no free-text) mitigates T-43-12 (Tampering/invalid config values). The full-config overwrite on save is a pre-existing pattern limitation documented in the code comments (T-43-13).

---

## Self-Check: PASSED

- [x] `dlp-admin-cli/src/screens/usb_enforcement.rs` exports all shared constants
- [x] `dlp-admin-cli/src/screens/mod.rs` includes `mod usb_enforcement`
- [x] `dlp-admin-cli/src/app.rs` has `UsbEnforcementConfig` Screen variant
- [x] `dlp-admin-cli/src/screens/render.rs` has `draw_usb_enforcement_config` and SystemMenu updated
- [x] `dlp-admin-cli/src/screens/dispatch.rs` has load/save handlers, editing/nav handlers, system menu integration
- [x] `USB_ENFORCEMENT_OPTIONS` uses `&[&[&str]]` (no empty-string padding)
- [x] Unimplemented options excluded from picker (no "Volume GUID resolution", no "Port-based disambiguation")
- [x] All tests pass (106 passed)
- [x] No compiler warnings
- [x] Format clean for modified files
