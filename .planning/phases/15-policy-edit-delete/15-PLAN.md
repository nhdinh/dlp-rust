---
gsd_state_version: 1.0
wave: 1 of 2
depends_on: []
phase: 15
slug: policy-edit-delete
status: draft
created: "2026-04-17"
requirements:
  - POLICY-03  # Edit form: name, description, priority, action, enabled, conditions, PUT /admin/policies/{id}, conditions pre-pop
  - POLICY-04   # Delete: d key, confirm dialog [y/n], DELETE /admin/policies/{id}, PolicyList reload
autonomous: false
---

# Phase 15 Plan: Policy Edit + Delete

## Overview

Two capabilities added to the admin TUI:

1. **Edit (POLICY-03):** Press `e` on a PolicyList row → GET /admin/policies/{id} → `Screen::PolicyEdit` (8-row form) → PUT on `[Save]` → PolicyList reload.
2. **Delete (POLICY-04):** Press `d` on a PolicyList row → `Screen::Confirm` with `"Delete policy '{name}'? [y/n]"` → DELETE on `y` → PolicyList reload.

**Phase 14 Update (D-09 scope):** Both `Screen::PolicyCreate` and `Screen::PolicyEdit` adopt an 8-row layout with the new Enabled toggle row (was hardcoded `enabled: true` in POST body). `action_submit_policy` body gains `"enabled": form.enabled`.

## File Map

| File | Changes |
|------|---------|
| `dlp-admin-cli/src/app.rs` | Add `Screen::PolicyEdit`, activate `CallerScreen::PolicyEdit` |
| `dlp-admin-cli/src/screens/dispatch.rs` | Extend `handle_policy_list` (`e`/`d`), extend `handle_confirm` (`y`/`n`), update Phase 14 row constants + handlers to 8 rows, add `action_load_policy_for_edit` / `handle_policy_edit*` / `action_submit_policy_update`, update `action_delete_policy` post-success, update `action_submit_policy` POST body |
| `dlp-admin-cli/src/screens/render.rs` | Add `draw_policy_edit`, extend `draw_policy_create` to 8 rows, update `draw_confirm` hints |

## Wave 1 (Edit — POLICY-03) — Modify in this order

### Wave 1, Task 1 — Phase 14 Update: 7→8 rows in dispatch.rs constants and handlers

**Read first:**
- `dlp-admin-cli/src/screens/dispatch.rs` §813–§822 (Phase 14 constants)
- `dlp-admin-cli/src/screens/dispatch.rs` §1040–§1166 (`handle_policy_create` + `handle_policy_create_nav`)
- `dlp-admin-cli/src/screens/dispatch.rs` §1062–§1116 (`handle_policy_create_editing`)
- `dlp-admin-cli/src/screens/dispatch.rs` §1206–§1287 (`action_submit_policy`)
- `dlp-admin-cli/src/app.rs` §119–§139 (`PolicyFormState`)

**Action:**
1. In `dispatch.rs`, after the existing Phase 14 constants, add:
   ```rust
   /// Row index of the Enabled toggle (Phase 15: row 4 in both Create and Edit).
   const POLICY_ENABLED_ROW: usize = 4;
   /// Row index of the [Add Conditions] action row.
   const POLICY_ADD_CONDITIONS_ROW: usize = 5;
   /// Row index of the Conditions summary display row.
   const POLICY_CONDITIONS_DISPLAY_ROW: usize = 6;
   /// Row index of the [Save] / [Submit] action row.
   const POLICY_SAVE_ROW: usize = 7;
   /// Total rows in the PolicyCreate/PolicyEdit form (0..=7).
   const POLICY_ROW_COUNT: usize = 8;
   ```
2. **Delete** the old Phase 14 constants (`POLICY_NAME_ROW=0`, `POLICY_DESC_ROW=1`, `POLICY_PRIORITY_ROW=2`, `POLICY_ACTION_ROW=3`, `POLICY_ADD_CONDITIONS_ROW=4`, `POLICY_CONDITIONS_DISPLAY_ROW=5`, `POLICY_SUBMIT_ROW=6`, `POLICY_ROW_COUNT=7`).
3. In `handle_policy_create_nav`:
   - `nav(sel, 7, ...)` → `nav(sel, POLICY_ROW_COUNT, ...)` (1 occurrence)
   - `POLICY_SUBMIT_ROW` → `POLICY_SAVE_ROW` (1 occurrence, submit row match arm)
   - Add new match arm for `POLICY_ENABLED_ROW`: `form.enabled = !form.enabled` (same pattern as `POLICY_ACTION_ROW` cycling)
   - Change `POLICY_ADD_CONDITIONS_ROW` → `5` in the navigation match; change `POLICY_CONDITIONS_DISPLAY_ROW` → `6`
   - In the text-field guard: `if selected > POLICY_PRIORITY_ROW` → `if selected > 2` (keep text field rows as 0/1/2)
4. In `handle_policy_create_editing`: add `POLICY_ENABLED_ROW` branch in the `POLICY_NAME_ROW`/`POLICY_DESC_ROW`/`POLICY_PRIORITY_ROW` commit match — since Enabled has no edit mode, add `POLICY_ENABLED_ROW` to a no-op `_` arm or an explicit no-op.
5. In `action_submit_policy`:
   - Change `POLICY_SUBMIT_ROW` reference in the test helpers at the bottom of the file → `POLICY_SAVE_ROW`
   - In the `let payload = serde_json::json!({` block, change `"enabled": true,` → `"enabled": form.enabled,`
6. In `app.rs`: remove `#[allow(dead_code)]` from `PolicyFormState.enabled` (D-09: Phase 15 consumes this field, removing the dead_code lint).

**Acceptance criteria:**
- `grep -n "POLICY_ENABLED_ROW\|POLICY_SAVE_ROW\|POLICY_ROW_COUNT" dispatch.rs` returns 8+ lines including `const POLICY_ROW_COUNT: usize = 8;`
- `grep -n "enabled.*form.enabled\|form.enabled" dispatch.rs` in `action_submit_policy` returns `"enabled": form.enabled,`
- `grep -n "allow(dead_code)" app.rs | grep -i enabled` returns no results
- All existing Phase 14 unit tests still pass (run `cargo test` in dlp-admin-cli; tests use `POLICY_SUBMIT_ROW` → updated to `POLICY_SAVE_ROW`)

---

### Wave 1, Task 2 — Phase 14 Update: extend `draw_policy_create` to 8 rows in render.rs

**Read first:**
- `dlp-admin-cli/src/screens/render.rs` §536–§543 (`POLICY_FIELD_LABELS[7]`)
- `dlp-admin-cli/src/screens/render.rs` §731–§877 (`draw_policy_create`)
- `.planning/phases/14-policy-create/14-UI-SPEC.md` (authoritative label widths and spacing)

**Action:**
1. In `render.rs`, replace `const POLICY_FIELD_LABELS: [&str; 7]` with:
   ```rust
   /// Display labels for each row in the PolicyCreate/PolicyEdit form (8 rows, indices 0-7).
   const POLICY_FIELD_LABELS: [&str; 8] = [
       "Name",
       "Description",
       "Priority",
       "Action",
       "Enabled",
       "[Add Conditions]",
       "Conditions",
       "[Save]",   // Edit: [Save]; Create: [Submit] (passed as parameter)
   ];
   ```
2. Extend the `draw_policy_create` render match to cover indices 0–7 (currently 0–6):
   - **Index 0–3:** unchanged (Name, Description, Priority, Action)
   - **Index 4 (NEW — Enabled):** `let enabled_val = if form.enabled { "Yes" } else { "No" }; Line::from(format!("{label}:              {enabled_val}"))` — no edit mode, no buffer; White when unselected, highlighted when selected (same as Action row)
   - **Index 5:** `[Add Conditions]` action row (was index 4)
   - **Index 6:** Conditions summary (was index 5; unchanged logic)
   - **Index 7:** `[Save]` action row (was index 6; label from `POLICY_FIELD_LABELS[7]`)
3. In `draw_policy_create`'s list block title, change `" Create Policy "` to `" Create Policy "`. (No change to title — only the Enabled row and row count change for Create.)

**Acceptance criteria:**
- `grep -n "POLICY_FIELD_LABELS" render.rs` shows `[&str; 8]`
- `grep -n "Enabled\|enabled_val\|Yes.*No" render.rs` shows Enabled row handling at index 4
- `grep -n "POLICY_FIELD_LABELS\[7\]" render.rs` shows `"[Save]"` as the last label

---

### Wave 1, Task 3 — Add `Screen::PolicyEdit` variant to app.rs

**Read first:**
- `dlp-admin-cli/src/app.rs` §150–§286 (`Screen` enum; read PolicyCreate variant as template)
- `dlp-admin-cli/src/app.rs` §106–§117 (`CallerScreen` enum)

**Action:**
1. In `app.rs`, activate `CallerScreen::PolicyEdit` by removing `#[allow(dead_code)]` from the `PolicyEdit` variant.
2. In the `Screen` enum, after `PolicyCreate { ... }`, add:
   ```rust
   /// Policy edit multi-field form.
   ///
   /// Row layout (selected index -> field):
   ///   0: Name         (text, required)
   ///   1: Description  (text, optional)
   ///   2: Priority     (text, parsed as u32 at submit)
   ///   3: Action       (select index into ACTION_OPTIONS)
   ///   4: Enabled      (bool toggle — Enter toggles, no edit mode)
   ///   5: [Add Conditions]
   ///   6: Conditions display (read-only summary)
   ///   7: [Save]
   PolicyEdit {
       /// Server-side policy ID; used for PUT URL path only — NOT rendered on form.
       id: String,
       /// All form field values and conditions, pre-populated from GET response.
       form: PolicyFormState,
       /// Index of the currently highlighted row (0..=7).
       selected: usize,
       /// Whether the selected text field is in edit mode.
       editing: bool,
       /// Text buffer for the active text field (Name, Description, Priority).
       buffer: String,
       /// Inline validation error displayed below the [Save] row.
       /// Cleared on Esc or successful submission.
       validation_error: Option<String>,
   },
   ```

**Acceptance criteria:**
- `grep -n "PolicyEdit" app.rs` shows the new `Screen::PolicyEdit` variant with all 6 fields
- `grep -n "CallerScreen::PolicyEdit" app.rs` shows the activated enum variant
- `grep -n "PolicyEdit" app.rs | grep -i "allow"` returns no lines (dead_code removed)

---

### Wave 1, Task 4 — Add `draw_policy_edit` to render.rs

**Read first:**
- `dlp-admin-cli/src/screens/render.rs` §731–§877 (`draw_policy_create` — clone-and-adapt source)
- `dlp-admin-cli/src/screens/render.rs` §25–§160 (`draw_screen` — match arm to add)
- `.planning/phases/15-policy-edit-delete/15-UI-SPEC.md` §40–§79 (form layout contract)

**Action:**
1. In `render.rs`, add `draw_policy_edit` as a copy of `draw_policy_create` with three deltas:
   - **Block title:** `" Edit Policy: {name} "` where `{name}` = `form.name`. Accept `policy_name: &str` as an additional parameter.
   - **Row 7 label:** Use `[Save]` hardcoded (not `POLICY_FIELD_LABELS[7]`), consistent with UI-SPEC D-03.
   - **Row 4 (Enabled):** identical to the new index-4 row in `draw_policy_create`.
2. In `draw_screen` match arm for `Screen::PolicyCreate { form, selected, editing, buffer, validation_error }`, add a new match arm BEFORE or AFTER for:
   ```rust
   Screen::PolicyEdit { id: _, form, selected, editing, buffer, validation_error } => {
       draw_policy_edit(
           frame,
           area,
           &form.name,  // policy_name for title
           form,
           *selected,
           *editing,
           buffer,
           validation_error.as_deref(),
       );
   }
   ```
   (Note: `id` is consumed but not used in rendering.)

**Acceptance criteria:**
- `grep -n "fn draw_policy_edit\|draw_policy_edit" render.rs` shows the new function
- `grep -n "Edit Policy:" render.rs` shows `" Edit Policy: {name} "` in `draw_policy_edit`
- `grep -n "PolicyEdit" render.rs` shows the new `draw_screen` match arm

---

### Wave 1, Task 5 — Add `handle_policy_edit*` handlers and `action_load_policy_for_edit` to dispatch.rs

**Read first:**
- `dlp-admin-cli/src/screens/dispatch.rs` §1040–§1166 (`handle_policy_create` + `handle_policy_create_nav` as template)
- `dlp-admin-cli/src/screens/dispatch.rs` §1062–§1116 (`handle_policy_create_editing` as template)
- `dlp-admin-cli/src/screens/dispatch.rs` §1206–§1287 (`action_submit_policy` as template for `action_submit_policy_update`)
- `dlp-admin-cli/src/screens/dispatch.rs` §386–§409 (`handle_policy_list` — where `e` key calls this)
- `dlp-admin-cli/src/screens/dispatch.rs` §11–§37 (`handle_event` dispatch — add match arm)

**Action:**
1. In `dispatch.rs`, add the `handle_event` match arm for `Screen::PolicyEdit` → `handle_policy_edit`.
2. Add `action_load_policy_for_edit(app, &id, &name)` function:
   - Calls `app.rt.block_on(app.client.get::<serde_json::Value>(&format!("policies/{id}")))`
   - On success: deserializes conditions from JSON into `Vec<PolicyCondition>`, maps `action` JSON to `ACTION_OPTIONS` index (case-insensitive match; fallback index 0 with `"Warning: unknown action '{v}', defaulted to ALLOW"` validation error), constructs `PolicyFormState`, transitions to `Screen::PolicyEdit { id, form, selected: 0, editing: false, buffer: String::new(), validation_error: None }`.
   - On failure: `app.set_status(format!("Failed to load policy: {e}"), StatusKind::Error)`, stays on `PolicyList`.
3. Add `handle_policy_edit(app, key)` — mirrors `handle_policy_create` exactly but matches `Screen::PolicyEdit { ... }`:
   - Delegates to `handle_policy_edit_editing` or `handle_policy_edit_nav` based on `editing` flag.
4. Add `handle_policy_edit_editing(app, key, selected)` — mirrors `handle_policy_create_editing` but matches `Screen::PolicyEdit { form, buffer, editing, .. }` and commits to `form.name`, `form.description`, `form.priority` on Enter. No-op for `POLICY_ENABLED_ROW`.
5. Add `handle_policy_edit_nav(app, key, selected)` — mirrors `handle_policy_create_nav`:
   - Up/Down → navigate (uses `POLICY_ROW_COUNT = 8`)
   - `POLICY_SAVE_ROW` (index 7) → calls `action_submit_policy_update(app, id, form.clone())`
   - `POLICY_ENABLED_ROW` (index 4) → `form.enabled = !form.enabled`
   - `POLICY_ACTION_ROW` (index 3) → cycles `form.action`
   - `POLICY_ADD_CONDITIONS_ROW` (index 5) → opens `Screen::ConditionsBuilder` with `caller: CallerScreen::PolicyEdit`, `pending: form.conditions.clone()`, `form_snapshot: PolicyFormState { conditions: vec![], ..form.clone() }`
   - `POLICY_CONDITIONS_DISPLAY_ROW` (index 6) → no-op
   - Text rows (0, 1, 2) → enter edit mode, pre-fill buffer
   - `Esc | Char('q')` → `action_list_policies(app)` (no confirmation, D-21)
6. Add `action_submit_policy_update(app, id, form)`:
   - Inline validation identical to `action_submit_policy` (empty name, bad priority, serialize conditions).
   - Builds payload with `"id": id` (NOT a new UUID — preserves existing policy ID), `"name"`, `"description"`, `"priority"`, `"conditions"`, `"action"`, `"enabled": form.enabled`.
   - Calls `app.rt.block_on(app.client.put(&format!("admin/policies/{id}"), &payload))`.
   - On success: `action_list_policies(app)`, `app.set_status(format!("Policy '{name}' updated"), StatusKind::Success)`.
   - On error: sets `validation_error` inline, stays on `PolicyEdit`.
7. Update the Phase 13 `handle_conditions_pending` / `handle_conditions_step1` Esc handlers: replace the `CallerScreen::PolicyEdit` placeholder (`app.screen = Screen::PolicyMenu { selected: 0 };`) with:
   ```rust
   CallerScreen::PolicyEdit => {
       app.screen = Screen::PolicyEdit {
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
   ```
   The `id` field is NOT restored in `form_snapshot` (it's only on the `PolicyEdit` Screen variant). Since `form_snapshot` is constructed from `PolicyFormState` (which has no `id`), and we already hold `id` in the `PolicyEdit` screen at the time of the ConditionsBuilder open, the `id` is preserved through the modal round-trip by the Screen variant structure itself.

**Acceptance criteria:**
- `grep -n "fn handle_policy_edit\|fn action_load_policy_for_edit\|fn action_submit_policy_update" dispatch.rs` shows all 5 new functions
- `grep -n "Screen::PolicyEdit" dispatch.rs` shows the `handle_event` match arm and the ConditionsBuilder Esc handlers
- `grep -n "action_list_policies" dispatch.rs | grep -i "policy.*updated\|PolicyEdit\|Esc"` shows Esc returns to PolicyList (not PolicyMenu)
- `cargo build --manifest-path dlp-admin-cli/Cargo.toml` compiles with zero errors

---

## Wave 2 (Delete — POLICY-04) — Can run in parallel with Wave 1 edits

### Wave 2, Task 1 — Extend `handle_policy_list` with `e` and `d` key bindings

**Read first:**
- `dlp-admin-cli/src/screens/dispatch.rs` §386–§409 (`handle_policy_list`)
- `dlp-admin-cli/src/screens/dispatch.rs` §504–§516 (`action_delete_policy`)
- `.planning/phases/15-policy-edit-delete/15-CONTEXT.md` D-25, D-24

**Action:**
1. In `handle_policy_list`, extend the `_ => {}` catch-all with two new `KeyCode::Char` branches:
   ```rust
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
   ```
   Note: `policies` is already cloned from `app.screen` at the top of `handle_policy_list`, so the `id` and `name` extraction is safe.

**Acceptance criteria:**
- `grep -n "Char('e')\|Char('d')" dispatch.rs` shows both key branches in `handle_policy_list`
- `grep -n "Delete policy" dispatch.rs` shows `format!("Delete policy '{name}'? [y/n]")`
- `grep -n "ConfirmPurpose::DeletePolicy" dispatch.rs` shows the transition

---

### Wave 2, Task 2 — Extend `handle_confirm` with `y`/`n`/`Y`/`N` key bindings and fix return path

**Read first:**
- `dlp-admin-cli/src/screens/dispatch.rs` §337–§362 (`handle_confirm`)
- `dlp-admin-cli/src/screens/dispatch.rs` §504–§516 (`action_delete_policy`)

**Action:**
1. In `handle_confirm`:
   - Add `KeyCode::Char('y') | KeyCode::Char('Y')` branch: `*yes_selected = true;` then fire the purpose action (same as `KeyCode::Enter` when `*yes_selected`).
   - Add `KeyCode::Char('n') | KeyCode::Char('N')` branch: same as `KeyCode::Esc` (cancel).
   - For the `ConfirmPurpose::DeletePolicy` path in `KeyCode::Enter`: the call to `action_delete_policy(app, &id)` is unchanged.
2. Update `action_delete_policy`:
   - On success: change `app.screen = Screen::PolicyMenu { selected: 4 };` → `action_list_policies(app)`; change `app.set_status(...)` → `"Policy '{id}' deleted"` (D-16).
   - On failure: change `app.screen = Screen::PolicyMenu { selected: 4 };` → stay on `PolicyList` by NOT changing screen (D-17); keep `app.set_status(format!("Failed: {e}"), StatusKind::Error)`.
   - Also update the `KeyCode::Enter` cancel path in `handle_confirm` from `Screen::PolicyMenu { selected: 0 }` → `action_list_policies(app)` (D-17: delete failure stays on PolicyList, not PolicyMenu).

**Acceptance criteria:**
- `grep -n "Char('y')\|Char('n')\|Char('Y')\|Char('N')" dispatch.rs` in `handle_confirm` shows all 4 branches
- `grep -n "action_delete_policy" dispatch.rs` shows `action_list_policies(app)` on success, NOT PolicyMenu
- `grep -n "Failed.*delete\|Failed.*policy\|Failed: " dispatch.rs | grep -i "delete\|policy"` shows failure stays on PolicyList

---

### Wave 2, Task 3 — Update `draw_confirm` hints bar

**Read first:**
- `dlp-admin-cli/src/screens/render.rs` §931–§969 (`draw_confirm`)

**Action:**
In `draw_confirm`, change the hints bar string from:
```rust
"Left/Right: select | Enter: confirm | Esc: cancel"
```
to:
```rust
"Left/Right/y: confirm | n/Esc: cancel"
```
This reflects that `y`/`n` keys now also work alongside Left/Right/Enter.

**Acceptance criteria:**
- `grep -n "Left/Right/y" render.rs` shows the updated hints string in `draw_confirm`

---

### Wave 2, Task 4 — Update PolicyList hints bar in `draw_policy_list`

**Read first:**
- `dlp-admin-cli/src/screens/render.rs` §971–§1010 (`draw_policy_list`)

**Action:**
In `draw_policy_list`, change the `draw_hints` call at the bottom from:
```rust
"Up/Down: navigate | Esc: back"
```
to:
```rust
"n: new | e: edit | d: delete | Enter: view | Esc: back"
```

**Acceptance criteria:**
- `grep -n "n: new.*e: edit.*d: delete" render.rs` shows the updated hints in `draw_policy_list`

---

## Verification

After all tasks complete, run:

```bash
cargo build --manifest-path dlp-admin-cli/Cargo.toml
cargo test --manifest-path dlp-admin-cli/Cargo.toml
cargo clippy --manifest-path dlp-admin-cli/Cargo.toml -- -D warnings
cargo fmt --check --manifest-path dlp-admin-cli/Cargo.toml
```

**Must-have checks (grep):**
- `POLICY_ROW_COUNT` is `8` (not `7`) in dispatch.rs
- `POLICY_FIELD_LABELS` is `[&str; 8]` in render.rs
- `Screen::PolicyEdit` variant exists with 6 fields in app.rs
- `draw_policy_edit` function exists in render.rs with `" Edit Policy: "` title
- `action_load_policy_for_edit` function exists in dispatch.rs
- `action_submit_policy_update` function exists in dispatch.rs
- `handle_confirm` has `Char('y')` and `Char('n')` branches in dispatch.rs
- `handle_policy_list` has `Char('e')` and `Char('d')` branches in dispatch.rs
- `action_submit_policy` POST body has `"enabled": form.enabled` in dispatch.rs
- `action_delete_policy` calls `action_list_policies(app)` on success in dispatch.rs
- `PolicyFormState.enabled` has no `#[allow(dead_code)]` in app.rs
- `CallerScreen::PolicyEdit` is activated (no `#[allow(dead_code)]`) in app.rs
- Phase 13 ConditionsBuilder Esc handlers return `Screen::PolicyEdit` (not PolicyMenu) in dispatch.rs

## must_haves (goal-backward)

| # | Criterion |
|---|-----------|
| 1 | Pressing `e` on a PolicyList row loads the policy and opens the edit form |
| 2 | Edit form pre-populates Name, Description, Priority, Action, Enabled from GET response |
| 3 | Edit form pre-populates conditions from GET response (visible in Conditions summary) |
| 4 | Enter on `[Add Conditions]` from Edit opens ConditionsBuilder with existing conditions |
| 5 | Enabled row toggles Yes/No on Enter (no text buffer) |
| 6 | `[Save]` submits PUT /admin/policies/{id} with all form fields including `enabled` |
| 7 | PUT success reloads PolicyList with updated row |
| 8 | Esc on Edit form returns to PolicyList without confirmation |
| 9 | Pressing `d` on a PolicyList row shows confirm dialog with `y/n` inline hint |
| 10 | `y`/`Y` on confirm fires DELETE and reloads PolicyList |
| 11 | `n`/`N`/Esc on confirm cancels and returns to PolicyList |
| 12 | DELETE failure shows error in status bar and stays on PolicyList |
| 13 | Phase 14 Create form also has 8 rows with Enabled toggle |
| 14 | All existing Phase 14 unit tests pass with updated row constants |
