---
estimated_steps: 66
estimated_files: 6
skills_used: []
---

# T03: Add CloudConfig and PrintConfig admin CLI screens wired into SystemMenu

The admin CLI's `SystemMenu` tops out at index 5 ('USB Enforcement') with a back item at index 6. This task adds two new screens — `CloudConfig` (one boolean toggle: `cloud_hook_enabled`) and `PrintConfig` (five fields: `print_enabled` bool, `print_xps_timeout_ms` numeric, `print_unclassifiable_action` picker, `print_max_pages` numeric, `cloud_hook_enabled` is NOT on print config) — wired into the menu at indices 6 and 7 respectively, with Back shifting to index 8. The implementation follows established patterns: `cloud_config.rs` constants module follows `usb_enforcement.rs`; `print_config.rs` follows the same shape. Rendering follows `draw_usb_enforcement_config` for cloud (picker-only) and `draw_ldap_config` for print (bool + numeric + picker mix). Dispatch follows `handle_usb_enforcement_config` / `handle_ldap_config` as appropriate.

Why this task exists: completing the admin operator surface for M017 — without these screens, operators cannot enable/disable cloud and print interception from the TUI.

## Steps

1. **Create `dlp-admin-cli/src/screens/cloud_config.rs`** following `usb_enforcement.rs` shape:
   - `CLOUD_CONFIG_KEYS: [&str; 1] = ["cloud_hook_enabled"]`
   - `CLOUD_CONFIG_OPTIONS: &[&[&str]] = &[&["Enabled", "Disabled"]]` — cloud hook is a bool rendered as picker (same pattern as USB fields, but maps true/false to "Enabled"/"Disabled")
   - `CLOUD_CONFIG_LABELS: [&str; 1] = ["Cloud Hook"]`
   - `CLOUD_CONFIG_SAVE_ROW: usize = 1`
   - `CLOUD_CONFIG_BACK_ROW: usize = 2`
   - `CLOUD_CONFIG_ROW_COUNT: usize = 3`
   - Unit tests: constants length assertions, save/back index sanity checks.

2. **Create `dlp-admin-cli/src/screens/print_config.rs`** following the same shape:
   - `PRINT_CONFIG_KEYS: [&str; 4] = ["print_enabled", "print_xps_timeout_ms", "print_unclassifiable_action", "print_max_pages"]`
   - `PRINT_CONFIG_LABELS: [&str; 4] = ["Print Enabled", "XPS Timeout (ms)", "Unclassifiable Action", "Max Pages"]`
   - `PRINT_CONFIG_SAVE_ROW: usize = 4`, `PRINT_CONFIG_BACK_ROW: usize = 5`, `PRINT_CONFIG_ROW_COUNT: usize = 6`
   - `fn is_print_bool(index: usize) -> bool { index == 0 }` — `print_enabled` is a bool toggle
   - `fn is_print_numeric(index: usize) -> bool { matches!(index, 1 | 3) }` — `print_xps_timeout_ms` (row 1) and `print_max_pages` (row 3) are numeric
   - `fn is_print_picker(index: usize) -> bool { index == 2 }` — `print_unclassifiable_action` is a two-option picker ("Block", "Allow")
   - `PRINT_UNCLASSIFIABLE_OPTIONS: &[&str] = &["Block", "Allow"]`
   - Unit tests: constants length assertions, bool/numeric/picker predicate coverage.

3. **Register modules in `dlp-admin-cli/src/screens/mod.rs`:** Add `pub mod cloud_config;` and `pub mod print_config;` after `mod usb_enforcement;`.

4. **Add `CloudConfig` and `PrintConfig` variants to `Screen` enum in `dlp-admin-cli/src/app.rs`:** After the `UsbEnforcementConfig` variant (~line 542), add:
   ```rust
   /// Cloud sync hook configuration form.
   /// Row 0: cloud_hook_enabled (bool toggle). Row 1 = [Save]. Row 2 = [Back].
   CloudConfig {
       config: serde_json::Value,
       selected: usize,
       editing: bool,
       buffer: String,
   },
   /// Print spooler interception configuration form.
   /// Row 0: print_enabled (bool). Row 1: print_xps_timeout_ms (numeric).
   /// Row 2: print_unclassifiable_action (picker). Row 3: print_max_pages (numeric).
   /// Row 4 = [Save]. Row 5 = [Back].
   PrintConfig {
       config: serde_json::Value,
       selected: usize,
       editing: bool,
       buffer: String,
   },
   ```

5. **Extend `dispatch.rs` screen match arms** (the `match &app.screen` in `handle_event`): add `Screen::CloudConfig { .. } => handle_cloud_config(app, key),` and `Screen::PrintConfig { .. } => handle_print_config(app, key),` following the `UsbEnforcementConfig` line.

6. **Update `handle_system_menu`** in `dispatch.rs`:
   - Change `nav(selected, 7, key.code)` to `nav(selected, 9, key.code)`
   - Add index 6 → `action_load_cloud_config(app)`
   - Add index 7 → `action_load_print_config(app)`
   - Change index 6 (Back) to index 8

7. **Add `action_load_cloud_config`, `action_save_cloud_config`, `handle_cloud_config`** in `dispatch.rs` following the exact `action_load_usb_enforcement_config` / `action_save_usb_enforcement_config` / `handle_usb_enforcement_config` pattern. `handle_cloud_config` only needs nav and a bool toggle (no picker cycling — bools toggle in-place on Enter). Back returns to `Screen::SystemMenu { selected: 6 }`. Save returns to `Screen::SystemMenu { selected: 6 }`.

8. **Add `action_load_print_config`, `action_save_print_config`, `handle_print_config`** in `dispatch.rs` following the LDAP config pattern for mixed bool/numeric/picker. Boolean row (row 0) toggles on Enter. Numeric rows (rows 1 and 3) enter edit mode on Enter, commit on Enter, cancel on Esc. Picker row (row 2) cycles on Up/Down while `editing` is true, Enter confirms, Esc cancels. Use the existing `ldap_toggle_bool` + `ldap_enter_numeric_edit` logic shapes as templates. Back returns to `Screen::SystemMenu { selected: 7 }`. Save returns to `Screen::SystemMenu { selected: 7 }`.

9. **Update `render.rs` SystemMenu** (~line 88): add `"Cloud Config"` and `"Print Config"` to the menu items slice before `"Back"`. The items array now has 9 entries: `["Server Status", "Agent List", "SIEM Config", "Alert Config", "LDAP Config", "USB Enforcement", "Cloud Config", "Print Config", "Back"]`.

10. **Add `draw_cloud_config` in `render.rs`** following `draw_usb_enforcement_config` with bool-as-display: display `true` as `"Enabled"`, `false` as `"Disabled"`. Add a match arm `Screen::CloudConfig { config, selected, editing, buffer } => draw_cloud_config(frame, area, config, *selected, *editing, buffer)`.

11. **Add `draw_print_config` in `render.rs`** following `draw_ldap_config`. Use `is_print_bool`, `is_print_numeric`, `is_print_picker` predicates. For the picker row, use `format_config_field_value` with a picker display helper (or inline the value lookup from the JSON blob). Add a match arm `Screen::PrintConfig { config, selected, editing, buffer } => draw_print_config(frame, area, config, *selected, *editing, buffer)`.

12. **Import new constants** in `dispatch.rs` and `render.rs`: `use crate::screens::cloud_config::{...}; use crate::screens::print_config::{...};`.

13. Run `cargo clippy -p dlp-admin-cli -- -D warnings` and `cargo test -p dlp-admin-cli`. Fix any warnings before marking done.

## Must-Haves

- [ ] `dlp-admin-cli/src/screens/cloud_config.rs` exists with constants + unit tests
- [ ] `dlp-admin-cli/src/screens/print_config.rs` exists with constants + predicates + unit tests
- [ ] `Screen::CloudConfig` and `Screen::PrintConfig` variants in `app.rs`
- [ ] SystemMenu shows "Cloud Config" at index 6, "Print Config" at index 7, "Back" at index 8
- [ ] `nav(selected, 9, key.code)` in `handle_system_menu`
- [ ] `action_load_cloud_config`, `action_save_cloud_config`, `handle_cloud_config` wired
- [ ] `action_load_print_config`, `action_save_print_config`, `handle_print_config` wired
- [ ] `draw_cloud_config` and `draw_print_config` render functions exist and are dispatched
- [ ] `cargo clippy -p dlp-admin-cli -- -D warnings` exits 0
- [ ] `cargo test -p dlp-admin-cli` exits 0 with new screen constant tests included

## Inputs

- `dlp-admin-cli/src/screens/dispatch.rs`
- `dlp-admin-cli/src/screens/render.rs`
- `dlp-admin-cli/src/screens/usb_enforcement.rs`
- `dlp-admin-cli/src/screens/mod.rs`
- `dlp-admin-cli/src/app.rs`
- `dlp-server/src/admin_api.rs`

## Expected Output

- `dlp-admin-cli/src/screens/cloud_config.rs`
- `dlp-admin-cli/src/screens/print_config.rs`
- `dlp-admin-cli/src/screens/mod.rs`
- `dlp-admin-cli/src/app.rs`
- `dlp-admin-cli/src/screens/dispatch.rs`
- `dlp-admin-cli/src/screens/render.rs`

## Verification

cargo clippy -p dlp-admin-cli -- -D warnings && cargo test -p dlp-admin-cli
