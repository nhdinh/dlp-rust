# Plan 55-06 Summary: Admin TUI Enforcement Mode Integration

**Phase:** 55-monitor-only-audit-only-per-policy-enforcement-mode
**Plan:** 06 (Admin TUI Integration)
**Status:** Complete
**Date:** 2026-05-29

---

## Objective

Add the Enforcement Mode dropdown to the admin TUI Conditions Builder, wire it through create/edit flows, and show global override status so operators can set and view enforcement mode without raw API calls.

---

## Tasks Completed

### Task 1: Extend PolicyFormState and app.rs with enforcement_mode field

**Files:** `dlp-admin-cli/src/app.rs`, `dlp-admin-cli/src/client.rs`, `dlp-admin-cli/src/main.rs`

- Added `pub enforcement_mode: usize` to `PolicyFormState`, defaulting to 1 (Block) via manual `Default` impl
- Added `pub const ENFORCEMENT_MODE_OPTIONS: [&str; 3] = ["Audit", "Block", "AuditAndBlock"]`
- Extended `PolicyResponse` and `PolicyPayload` with `#[serde(default)] pub enforcement_mode: EnforcementMode`
- Updated `From<PolicyResponse> for PolicyPayload` to include `enforcement_mode`
- Added `pub global_enforcement_mode: Option<String>` to `App` struct
- Added `get_global_enforcement_mode()` client method calling `GET /admin/config/global-enforcement-mode`
- TUI startup (`run_tui`) fetches global mode before first render via `app.rt.block_on`
- 3 unit tests: default form state, options length, serde round-trip

### Task 2: Wire enforcement_mode into dispatch.rs create/edit handlers

**Files:** `dlp-admin-cli/src/screens/dispatch.rs`

- Added `POLICY_ENFORCEMENT_MODE_ROW = 4`, shifted all subsequent rows up by 1
- `POLICY_ROW_COUNT` updated from 9 to 10
- Added `cycle_enforcement_mode(idx) -> usize` cycling 0->1->2->0
- Updated `policy_create_nav_enter` and `policy_edit_nav_enter` to handle `POLICY_ENFORCEMENT_MODE_ROW`
- Updated space-bar toggles in `handle_policy_create_nav` and `handle_policy_edit_nav`
- Updated `action_submit_policy` and `action_submit_policy_update` to include `"enforcement_mode"` in JSON payload
- Updated `action_load_policy_for_edit` to parse `enforcement_mode` from policy response ("Audit"->0, "Block"->1, "AuditAndBlock"->2)
- 2 unit tests: cycle function, payload inclusion

### Task 3: Render enforcement mode dropdown and global override banner

**Files:** `dlp-admin-cli/src/screens/render.rs`

- Updated `POLICY_FIELD_LABELS` to 10 elements with "Enforcement Mode" at index 4
- Updated `draw_policy_create` and `draw_policy_edit` match arms for new row layout
- Added `format_enforcement_mode_field()` helper displaying the mode label
- Added `render_global_override_banner()` helper with yellow bold styling
- Updated `draw_policy_list` to show "Mode" column and append " (global)" suffix when override active
- Passed `global_enforcement_mode` through all draw function signatures
- Banner renders on create/edit/list screens when global mode is not "PerPolicy"
- Banner hidden when `global_mode` is `None` or `"PerPolicy"`
- 5 unit tests: format helper (3 modes), mode column presence, banner render when active, banner hidden when PerPolicy, banner hidden when None

---

## Verification Results

| Check | Command | Result |
|-------|---------|--------|
| dlp-admin-cli full test suite | `cargo test -p dlp-admin-cli` | 198 passed |
| dlp-admin-cli clippy | `cargo clippy -p dlp-admin-cli -- -D warnings` | Clean |

---

## Key Design Decisions

1. **Manual Default impl for PolicyFormState:** The derived `Default` would set `enforcement_mode: 0` (Audit), but the safe default is `1` (Block). A manual `Default` impl ensures new policies default to Block.

2. **Global mode fetched synchronously on startup:** `run_tui` blocks on `get_global_enforcement_mode()` before entering the event loop. On failure, it logs a warning and continues with `None` (banner hidden). This is safe because the server still enforces the mode; the banner is purely a UX safety feature.

3. **Banner as yellow text, not a popup:** The global override banner is rendered as inline styled text at the top of each policy screen. This avoids modal fatigue while remaining visually prominent.

4. **Mode column with "(global)" suffix:** The policy list shows the per-policy mode and appends " (global)" when a global override is active, making the effective mode immediately visible.

---

## Artifacts Produced

- `dlp-admin-cli/src/app.rs` — `PolicyFormState.enforcement_mode`, `ENFORCEMENT_MODE_OPTIONS`, `App.global_enforcement_mode`
- `dlp-admin-cli/src/client.rs` — `get_global_enforcement_mode()` method
- `dlp-admin-cli/src/main.rs` — TUI startup global mode fetch
- `dlp-admin-cli/src/screens/dispatch.rs` — Row constants, cycle function, nav handlers, payload submission
- `dlp-admin-cli/src/screens/render.rs` — Dropdown rendering, global override banner, policy list mode column

---

## Threat Model Disposition

| Threat ID | Status | Notes |
|-----------|--------|-------|
| T-55-16 | Mitigated | Global override banner is visible in TUI; audit log records all mode changes |
| T-55-17 | Mitigated | Admin TUI requires JWT auth; same access control as all admin screens |
