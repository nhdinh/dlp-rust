---
id: T03
parent: S05
milestone: M017
key_files:
  - dlp-admin-cli/src/screens/cloud_config.rs
  - dlp-admin-cli/src/screens/print_config.rs
  - dlp-admin-cli/src/screens/mod.rs
  - dlp-admin-cli/src/app.rs
  - dlp-admin-cli/src/screens/dispatch.rs
  - dlp-admin-cli/src/screens/render.rs
key_decisions:
  - draw_cloud_config renders cloud_hook_enabled as Enabled/Disabled text (not [x]/[ ] checkbox) — more semantically clear for an on/off network hook toggle than a checkbox widget
  - draw_print_config uses inline picker display logic instead of format_config_field_value for row 2 — format_config_field_value treats unknown rows as string fields but picker cycling happens in dispatch so the stored value IS the string; the inline path avoids the picker/bool/string ambiguity cleanly
  - Back from CloudConfig returns to SystemMenu { selected: 6 } and from PrintConfig to { selected: 7 } to preserve cursor position on return, consistent with all other config screens
duration: 
verification_result: passed
completed_at: 2026-05-09T02:05:54.004Z
blocker_discovered: false
---

# T03: Added CloudConfig and PrintConfig admin CLI screens with constants modules, Screen variants, dispatch handlers, and render functions wired into SystemMenu at indices 6 and 7

**Added CloudConfig and PrintConfig admin CLI screens with constants modules, Screen variants, dispatch handlers, and render functions wired into SystemMenu at indices 6 and 7**

## What Happened

Created two new constants modules following the `usb_enforcement.rs` pattern:

- `cloud_config.rs`: single field `cloud_hook_enabled` (bool), with CLOUD_CONFIG_KEYS, CLOUD_CONFIG_LABELS, CLOUD_CONFIG_SAVE_ROW (1), CLOUD_CONFIG_BACK_ROW (2), CLOUD_CONFIG_ROW_COUNT (3), and unit tests.
- `print_config.rs`: four fields (print_enabled bool, print_xps_timeout_ms numeric, print_unclassifiable_action picker, print_max_pages numeric), with PRINT_CONFIG_KEYS, PRINT_CONFIG_LABELS, PRINT_UNCLASSIFIABLE_OPTIONS ("Block"/"Allow"), row constants (SAVE=4, BACK=5, COUNT=6), plus `is_print_bool`, `is_print_numeric`, `is_print_picker` predicates, and full unit test coverage.

Registered both modules in `screens/mod.rs`.

Added `Screen::CloudConfig` and `Screen::PrintConfig` variants to `app.rs` after `UsbEnforcementConfig`, with identical field shapes (config, selected, editing, buffer).

Updated `dispatch.rs`:
- Added imports for cloud_config and print_config constants/predicates.
- Added match arms `Screen::CloudConfig { .. } => handle_cloud_config(app, key)` and `Screen::PrintConfig { .. } => handle_print_config(app, key)`.
- Updated `handle_system_menu` nav count from 7→9, added indices 6→`action_load_cloud_config`, 7→`action_load_print_config`, shifted Back from index 6 to index 8.
- Added `action_load_cloud_config`, `action_save_cloud_config`, `handle_cloud_config` following the USB pattern; cloud_hook_enabled toggles in-place on Enter (no picker cycling needed for a single bool).
- Added `action_load_print_config`, `action_save_print_config`, plus the full LDAP-pattern handler suite: `handle_print_config`, `handle_print_config_editing` (handles numeric char/backspace/enter/esc and picker up/down/enter/esc), `print_commit_numeric`, `handle_print_config_nav` (dispatches to toggle-bool / enter-numeric-edit / enter-picker-edit / save / back).

Updated `render.rs`:
- Added imports for cloud_config and print_config symbols.
- Extended SystemMenu items from 7 to 9: inserted "Cloud Config" and "Print Config" before "Back".
- Added match arms `Screen::CloudConfig { .. } => draw_cloud_config(...)` and `Screen::PrintConfig { .. } => draw_print_config(...)` after the UsbEnforcementConfig arm.
- `draw_cloud_config`: renders the single bool field as "Enabled"/"Disabled" text (not the `[x]/[ ]` format — more readable for a cloud hook toggle), uses simple pointer-style selection, shows a hint bar.
- `draw_print_config`: uses `format_config_field_value` for bool/numeric, custom inline logic for the picker row (shows raw string when not editing, `[Block]`-style brackets when editing), uses `ListState`-based highlight matching the LDAP pattern.

All changes compile with zero clippy warnings under `-D warnings`. 116 tests pass including 3 new cloud_config tests and 7 new print_config tests.

## Verification

Ran `cargo clippy -p dlp-admin-cli -- -D warnings` — exits 0 with no warnings. Ran `cargo test -p dlp-admin-cli` — 116 tests pass, 0 failures. New module tests confirmed: cloud_config (3 tests: keys length, labels match, row constants), print_config (7 tests: keys length, labels match, row constants, is_print_bool, is_print_numeric, is_print_picker, picker options).

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo clippy -p dlp-admin-cli -- -D warnings` | 0 | pass | 1870ms |
| 2 | `cargo test -p dlp-admin-cli` | 0 | pass | 1520ms |

## Deviations

CLOUD_CONFIG_OPTIONS constant from the plan (an &[&[&str]] picker table) was omitted — cloud_hook_enabled is handled as a bool toggle (toggle on Enter, no picker cycling), making a picker options table redundant and potentially misleading. The bool toggle pattern is cleaner for a single true/false field.

## Known Issues

none

## Files Created/Modified

- `dlp-admin-cli/src/screens/cloud_config.rs`
- `dlp-admin-cli/src/screens/print_config.rs`
- `dlp-admin-cli/src/screens/mod.rs`
- `dlp-admin-cli/src/app.rs`
- `dlp-admin-cli/src/screens/dispatch.rs`
- `dlp-admin-cli/src/screens/render.rs`
