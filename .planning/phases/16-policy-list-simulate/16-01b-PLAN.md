---
phase: 16-policy-list-simulate
plan: "01b"
type: execute
wave: 1
depends_on: []
requirements:
  - POLICY-06
files_modified:
  - dlp-admin-cli/src/app.rs
  - dlp-admin-cli/src/screens/dispatch.rs
  - dlp-admin-cli/src/screens/render.rs
autonomous: true
must_haves:
  truths:
    - "Simulate types (SimulateFormState, SimulateOutcome, SimulateCaller) exist in app.rs"
    - "Screen::PolicySimulate variant exists with all 6 fields"
    - "PolicySimulate wired into handle_event dispatch and draw_screen render"
    - "Simulate Policy entry exists in both MainMenu and PolicyMenu"
    - "Simulate Policy entry has correct nav counts and Esc return routing"
    - "Full simulate dispatch and render functions exist and are complete"
  artifacts:
    - path: "dlp-admin-cli/src/app.rs"
      provides: "SimulateCaller, SimulateOutcome, SimulateFormState, Screen::PolicySimulate"
    - path: "dlp-admin-cli/src/screens/dispatch.rs"
      provides: "action_open_simulate, action_submit_simulate, handle_policy_simulate, handle_simulate_editing, handle_simulate_nav, simulate_cycle_field, simulate_enter_text_edit, simulate_return_to_caller"
    - path: "dlp-admin-cli/src/screens/render.rs"
      provides: "draw_policy_simulate, build_simulate_items, EDITABLE_TO_RENDER"
  key_links:
    - from: "dlp-admin-cli/src/screens/dispatch.rs"
      to: "dlp-admin-cli/src/app.rs"
      via: "imports SimulateCaller, SimulateFormState, SimulateOutcome"
    - from: "dlp-admin-cli/src/screens/render.rs"
      to: "dlp-admin-cli/src/app.rs"
      via: "imports SimulateOutcome for draw_policy_simulate"
    - from: "dlp-admin-cli/src/screens/render.rs"
      to: "dlp-admin-cli/src/screens/render.rs"
      via: "render_global_override_banner called from draw_policy_list"
---

# Phase 16 — Wave 1b: Verify Simulate Foundation Implementation

## Objective

Confirm that the Simulate screen foundation already present in `master` is complete and correct. The shipped code includes all Simulate types, the Screen variant, dispatch wiring, render functions, menu entries, and full form handling. This plan documents the current state and verifies correctness.

**Purpose:** Ensure the existing Simulate implementation is the source of truth for future enhancement work.
**Output:** Verified state of Simulate foundation artifacts.

## Context

@dlp-admin-cli/src/app.rs
@dlp-admin-cli/src/screens/dispatch.rs
@dlp-admin-cli/src/screens/render.rs

## Tasks

<task type="auto">
  <name>Task 1: Verify Simulate types and screen wiring exist in app.rs</name>
  <files>dlp-admin-cli/src/app.rs</files>
  <read_first>
    dlp-admin-cli/src/app.rs (lines 370-432, Simulate types and constants)
    dlp-admin-cli/src/app.rs (lines 970-1000, Screen::PolicySimulate variant)
  </read_first>
  <action>
    Verify the existing `app.rs` contains:
    - `SimulateCaller` enum with `MainMenu` and `PolicyMenu` variants (line ~374)
    - `SimulateOutcome` enum with `None`, `Success(EvaluateResponse)`, `Error(String)` variants (line ~382)
    - `SimulateFormState` struct with all 9 fields: `groups_raw`, `user_sid`, `user_name`, `device_trust`, `network_location`, `path`, `classification`, `action`, `access_context` (line ~397)
    - All 5 `SIMULATE_*_OPTIONS` arrays with correct values (lines ~419-425)
    - `SIMULATE_ROW_COUNT: usize = 10` and `SIMULATE_SUBMIT_ROW: usize = 9` (lines ~428-431)
    - `Screen::PolicySimulate` variant with fields `form`, `selected`, `editing`, `buffer`, `result`, `caller` (line ~981)
    Verify `dispatch.rs` contains `Screen::PolicySimulate { .. } => handle_policy_simulate(app, key)` in `handle_event`.
    Verify `render.rs` contains the `draw_policy_simulate` call in `draw_screen`.
    If any are missing, report the deviation. Do NOT modify files.
  </action>
  <verify>
    <automated>
      grep -n "pub enum SimulateCaller" dlp-admin-cli/src/app.rs
      grep -n "pub enum SimulateOutcome" dlp-admin-cli/src/app.rs
      grep -n "pub struct SimulateFormState" dlp-admin-cli/src/app.rs
      grep -n "SIMULATE_DEVICE_TRUST_OPTIONS" dlp-admin-cli/src/app.rs
      grep -n "SIMULATE_ROW_COUNT" dlp-admin-cli/src/app.rs
      grep -n "SIMULATE_SUBMIT_ROW" dlp-admin-cli/src/app.rs
      grep -n "PolicySimulate {" dlp-admin-cli/src/app.rs
      grep -n "Screen::PolicySimulate { .. } => handle_policy_simulate" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "draw_policy_simulate" dlp-admin-cli/src/screens/render.rs
    </automated>
  </verify>
  <acceptance_criteria>
    - `grep -n "pub enum SimulateCaller" dlp-admin-cli/src/app.rs` returns the enum definition
    - `grep -n "pub enum SimulateOutcome" dlp-admin-cli/src/app.rs` returns the enum definition
    - `grep -n "pub struct SimulateFormState" dlp-admin-cli/src/app.rs` returns the struct definition
    - `grep -n "SIMULATE_DEVICE_TRUST_OPTIONS" dlp-admin-cli/src/app.rs` returns the constant array
    - `grep -n "SIMULATE_ROW_COUNT" dlp-admin-cli/src/app.rs` returns `= 10`
    - `grep -n "SIMULATE_SUBMIT_ROW" dlp-admin-cli/src/app.rs` returns `= 9`
    - `grep -n "PolicySimulate {" dlp-admin-cli/src/app.rs` returns the Screen variant
    - `grep -n "Screen::PolicySimulate { .. } => handle_policy_simulate" dlp-admin-cli/src/screens/dispatch.rs` returns the dispatch arm
    - `grep -n "draw_policy_simulate" dlp-admin-cli/src/screens/render.rs` returns the render call
  </acceptance_criteria>
  <done>All Simulate types, constants, Screen variant, dispatch wiring, and render wiring are confirmed present in the shipped code.</done>
</task>

<task type="auto">
  <name>Task 2: Verify Simulate Policy menu entries and navigation counts</name>
  <files>dlp-admin-cli/src/screens/render.rs, dlp-admin-cli/src/screens/dispatch.rs</files>
  <read_first>
    dlp-admin-cli/src/screens/render.rs (lines 28-80, MainMenu and PolicyMenu draw functions)
    dlp-admin-cli/src/screens/dispatch.rs (lines 61-78, handle_main_menu; lines 125-169, handle_policy_menu)
  </read_first>
  <action>
    Verify the existing menu arrays and handlers contain:
    - `draw_main_menu` array includes "Simulate Policy" as the 4th element (index 3, before "Exit")
    - `handle_main_menu` has `nav(selected, 5, key.code)` (count = 5)
    - `handle_main_menu` Enter branch has `3 => action_open_simulate(app, SimulateCaller::MainMenu)`
    - `draw_policy_menu` array includes "Simulate Policy" as the 6th element (index 5, before "Back")
    - `handle_policy_menu` has `nav(selected, 7, key.code)` (count = 7)
    - `handle_policy_menu` Enter branch has `5 => action_open_simulate(app, SimulateCaller::PolicyMenu)`
    - Esc return from Simulate goes to `MainMenu { selected: 3 }` or `PolicyMenu { selected: 5 }`
    If any are missing, report the deviation. Do NOT modify files.
  </action>
  <verify>
    <automated>
      grep -n '"Simulate Policy"' dlp-admin-cli/src/screens/render.rs
      grep -n "nav(selected, 5" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "nav(selected, 7" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "SimulateCaller::MainMenu" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "SimulateCaller::PolicyMenu" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "selected: 3" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "selected: 5" dlp-admin-cli/src/screens/dispatch.rs
    </automated>
  </verify>
  <acceptance_criteria>
    - `grep -n '"Simulate Policy"' dlp-admin-cli/src/screens/render.rs` returns 2 occurrences (MainMenu and PolicyMenu)
    - `grep -n "nav(selected, 5" dlp-admin-cli/src/screens/dispatch.rs` returns the MainMenu nav count
    - `grep -n "nav(selected, 7" dlp-admin-cli/src/screens/dispatch.rs` returns the PolicyMenu nav count
    - `grep -n "SimulateCaller::MainMenu" dlp-admin-cli/src/screens/dispatch.rs` returns the MainMenu entry point
    - `grep -n "SimulateCaller::PolicyMenu" dlp-admin-cli/src/screens/dispatch.rs` returns the PolicyMenu entry point
    - `grep -n "selected: 3" dlp-admin-cli/src/screens/dispatch.rs` returns the MainMenu return target
    - `grep -n "selected: 5" dlp-admin-cli/src/screens/dispatch.rs` returns the PolicyMenu return target
  </acceptance_criteria>
  <done>Both menu entry points, correct nav counts, and Esc return routing are confirmed present.</done>
</task>

<task type="auto">
  <name>Task 3: Verify full simulate dispatch and render functions exist</name>
  <files>dlp-admin-cli/src/screens/dispatch.rs, dlp-admin-cli/src/screens/render.rs</files>
  <read_first>
    dlp-admin-cli/src/screens/dispatch.rs (lines 2809-3107, simulate functions)
    dlp-admin-cli/src/screens/render.rs (lines 1825-2059, draw_policy_simulate and helpers)
  </read_first>
  <action>
    Verify the existing simulate functions are complete and functional:
    - `action_open_simulate` creates `Screen::PolicySimulate` with `SimulateFormState::default()` and correct `caller`
    - `action_submit_simulate` builds `EvaluateRequest`, POSTs to `/evaluate`, stores `SimulateOutcome::Success` or `Error`
    - `handle_policy_simulate` routes to `handle_simulate_editing` or `handle_simulate_nav`
    - `handle_simulate_editing` handles Char, Backspace, Enter (commit), Esc (cancel)
    - `handle_simulate_nav` handles Up/Down, Enter (text edit / select cycle / submit), Esc/Q (return to caller)
    - `simulate_cycle_field` cycles select indices for device_trust, network_location, classification, action, access_context
    - `simulate_enter_text_edit` pre-fills buffer for text fields
    - `simulate_return_to_caller` routes Esc to correct menu
    - `draw_policy_simulate` renders the 14-item form with section headers, inline result block, and hints
    - `build_simulate_items` creates the 14 ListItems with correct section headers interleaved
    - `EDITABLE_TO_RENDER` lookup table maps 10 editable indices to 14 render positions
    If any function is missing or incomplete, report the deviation. Do NOT modify files.
  </action>
  <verify>
    <automated>
      grep -n "fn action_open_simulate" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "fn action_submit_simulate" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "fn handle_policy_simulate" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "fn handle_simulate_editing" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "fn handle_simulate_nav" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "fn simulate_cycle_field" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "fn simulate_enter_text_edit" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "fn simulate_return_to_caller" dlp-admin-cli/src/screens/dispatch.rs
      grep -n "fn draw_policy_simulate" dlp-admin-cli/src/screens/render.rs
      grep -n "fn build_simulate_items" dlp-admin-cli/src/screens/render.rs
      grep -n "const EDITABLE_TO_RENDER" dlp-admin-cli/src/screens/render.rs
    </automated>
  </verify>
  <acceptance_criteria>
    - `grep -n "fn action_open_simulate" dlp-admin-cli/src/screens/dispatch.rs` returns the function
    - `grep -n "fn action_submit_simulate" dlp-admin-cli/src/screens/dispatch.rs` returns the function
    - `grep -n "fn handle_policy_simulate" dlp-admin-cli/src/screens/dispatch.rs` returns the function
    - `grep -n "fn handle_simulate_editing" dlp-admin-cli/src/screens/dispatch.rs` returns the function
    - `grep -n "fn handle_simulate_nav" dlp-admin-cli/src/screens/dispatch.rs` returns the function
    - `grep -n "fn simulate_cycle_field" dlp-admin-cli/src/screens/dispatch.rs` returns the function
    - `grep -n "fn simulate_enter_text_edit" dlp-admin-cli/src/screens/dispatch.rs` returns the function
    - `grep -n "fn simulate_return_to_caller" dlp-admin-cli/src/screens/dispatch.rs` returns the function
    - `grep -n "fn draw_policy_simulate" dlp-admin-cli/src/screens/render.rs` returns the function
    - `grep -n "fn build_simulate_items" dlp-admin-cli/src/screens/render.rs` returns the function
    - `grep -n "const EDITABLE_TO_RENDER" dlp-admin-cli/src/screens/render.rs` returns the lookup table
  </acceptance_criteria>
  <done>All simulate dispatch handlers, render functions, and lookup tables are confirmed present and complete.</done>
</task>

## Verification

After all tasks complete, run the build to confirm no regressions:

```bash
cargo build -p dlp-admin-cli 2>&1 | grep -i "error" | grep -v "warning:" | head -20
```

Expected: no compile errors.

Then run the test suite:

```bash
cargo test -p dlp-admin-cli 2>&1 | tail -5
```

Expected: all tests pass.

## Success Criteria

- All Simulate types, Screen variant, dispatch wiring, and render functions confirmed
- Both menu entry points and Esc return routing confirmed
- Full simulate dispatch and render functions confirmed present and complete
- Build passes with no errors
- All tests pass

## Output

Create `.planning/phases/16-policy-list-simulate/16-01b-SUMMARY.md` when done.
