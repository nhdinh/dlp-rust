---
phase: 15
status: issues_found
files_reviewed: 3
critical: 0
warning: 2
info: 1
total: 3
created: "2026-04-17"
---

## Phase 15 Review: Policy Edit + Delete (POLICY-03, POLICY-04)

Reviewed at **standard depth**. All three files compile and pass the existing test suite. No data-loss, security, or crash bugs were found. Two actionable quality issues were identified.

---

## Finding 1 — WARNING: Misleading hint in `draw_policy_list`

**File:** `dlp-admin-cli/src/screens/render.rs:1191`
**Severity:** WARNING
**Category:** Correctness / UX

### Description

The hints bar rendered by `draw_policy_list` advertises `n: new` as a keybinding:

```rust
draw_hints(
    frame,
    area,
    "n: new | e: edit | d: delete | Enter: view | Esc: back",
);
```

However, `handle_policy_list` in `dispatch.rs` has no handler for `KeyCode::Char('n')`. Pressing `n` is silently ignored. The only way to create a new policy from the policy list is to Esc back to the PolicyMenu and select "Create Policy".

### Recommendation

Either:
- Add `KeyCode::Char('n')` support in `handle_policy_list` that transitions to `Screen::PolicyCreate`; or
- Remove `n: new` from the hints string.

The former is preferred — `n` from the policy list is a natural, discoverable shortcut that mirrors the `e` and `d` shortcuts already present.

### Fix (if implemented)

```rust
// dispatch.rs, handle_policy_list match arms
KeyCode::Char('n') => {
    app.screen = Screen::PolicyCreate {
        form: PolicyFormState::default(),
        selected: 0,
        editing: false,
        buffer: String::new(),
        validation_error: None,
    };
}
```

---

## Finding 2 — WARNING: Misleading hint in `draw_policy_edit`

**File:** `dlp-admin-cli/src/screens/render.rs:1043`
**Severity:** WARNING
**Category:** Correctness / UX

### Description

The hints bar rendered by `draw_policy_edit` reads:

```rust
"Up/Down: navigate | Enter: edit/toggle/open | Esc: back"
```

This overstates what Enter does from navigation mode. Pressing Enter on text fields (rows 0, 1, 2) does NOT edit — it commits whatever value is already in the buffer (the cursor was already in edit mode when typing). Enter on the Enabled row (4) and Action row (3) toggles values. Enter on the [Save] row (7) submits. Enter on [Add Conditions] (5) transitions to the ConditionsBuilder. None of these are "edit" in the traditional sense, and "open" is not applicable.

A more accurate hint for navigation mode:

```
"Up/Down: navigate | Enter: select/toggle/submit | Esc: back"
```

### Recommendation

Replace the hint string at render.rs line 1043:

```rust
// From:
"Up/Down: navigate | Enter: edit/toggle/open | Esc: back"
// To:
"Up/Down: navigate | Enter: select/toggle/submit | Esc: back"
```

---

## Finding 3 — INFO: `PolicyFormState.id` is structurally redundant with `Screen::PolicyEdit.id`

**File:** `dlp-admin-cli/src/app.rs:139`
**Severity:** INFO
**Category:** Code quality / Design

### Description

`PolicyFormState` carries an `id: String` field (line 139) that is populated when loading a policy for edit and preserved through the ConditionsBuilder round-trip. However, `Screen::PolicyEdit` also carries its own top-level `id: String` field (line 302). Both fields are always set to the same value:

```
action_load_policy_for_edit (line 1366): form.id = id.to_string()
action_load_policy_for_edit (line 1370): Screen::PolicyEdit { id: id.to_string(), ... }

handle_conditions_pending Esc (line 1853):  id = form_snapshot.id.clone()
handle_conditions_step1 Esc  (line 1940):  id = form_snapshot.id.clone()
```

The `form.id` field is never read independently — only `Screen::PolicyEdit.id` is used for the PUT URL (line 1592). The `form.id` exists solely to survive the ConditionsBuilder round-trip inside `form_snapshot`, but the round-trip already preserves `id` at the `Screen::PolicyEdit` level.

### Recommendation

This is **not a blocking issue**. The current design is correct and works correctly. However, if future refactoring is desired:

- Remove `PolicyFormState.id` entirely.
- On ConditionsBuilder Esc, reconstruct `Screen::PolicyEdit` using `Screen::PolicyEdit { form, id: caller_screen_id.clone(), ... }` where `caller_screen_id` is read from the live screen's top-level `id` field before replacing the screen.
- This eliminates one source of potential divergence.

No action required before Phase 16.

---

## Verification Checklist

### dispatch.rs

| Check | Result |
|---|---|
| `POLICY_ENABLED_ROW = 4` | ✓ Line 845 |
| `POLICY_SAVE_ROW = 7` | ✓ Line 851 |
| `POLICY_ROW_COUNT = 8` | ✓ Line 853 |
| `action_submit_policy` POST body includes `"enabled": form.enabled` | ✓ Line 1298 |
| `action_delete_policy` success: calls `action_list_policies(app)` | ✓ Line 535 |
| `action_delete_policy` failure: stays on PolicyList (no screen change) | ✓ Line 538 — no screen assignment |
| `handle_confirm` Enter/cancel path: `action_list_policies(app)` | ✓ Lines 364–365 |
| `handle_confirm` Char('y')/Char('Y')/`Char('n')/Char('N')` branches | ✓ Lines 349–357 |
| `handle_policy_list` Char('e') and Char('d') branches | ✓ Lines 414–430 |
| `handle_policy_edit_nav` Esc: `action_list_policies(app)` | ✓ Line 1526 |
| `handle_policy_edit_nav` Enter on Save: uses `form.id.clone()` | ✓ Line 1465 |
| `action_load_policy_for_edit`: GET `policies/{id}`, transitions to `Screen::PolicyEdit` | ✓ Lines 1330–1382 |
| `action_submit_policy_update`: PUT `/admin/policies/{id}`, payload includes `id` | ✓ Lines 1576–1592 |
| `handle_policy_edit_nav` rows 0–7 handled, Esc → PolicyList | ✓ Lines 1451–1529 |

### app.rs

| Check | Result |
|---|---|
| `Screen::PolicyEdit` has 6 fields (id, form, selected, editing, buffer, validation_error) | ✓ Lines 299–314 |
| `PolicyFormState.enabled` field present, no `#[allow(dead_code)]` | ✓ Line 134; no deny attribute |
| `CallerScreen::PolicyEdit` is live (no `#[allow(dead_code)]`) | ✓ Line 115; no deny attribute |
| `PolicyFormState.id: String` present | ✓ Line 139 |

### render.rs

| Check | Result |
|---|---|
| `POLICY_FIELD_LABELS`: `[&str; 8]` with "Enabled" at index 4 | ✓ Lines 556–565 |
| `draw_policy_create` index 4: Yes/No toggle, no edit mode | ✓ Lines 820–824 |
| `draw_policy_edit` function exists | ✓ Lines 920–1046 |
| `draw_policy_edit` block title: `" Edit Policy: {name} "` | ✓ Line 1012 |
| `draw_screen`: `Screen::PolicyEdit` match arm calls `draw_policy_edit` | ✓ Lines 168–186 |
| `draw_confirm` hints: `"Left/Right/y: confirm \| n/Esc: cancel"` | ✓ Line 1133 |
| `draw_policy_list` hints: `"n: new \| e: edit \| d: delete \| Enter: view \| Esc: back"` | ✓ Line 1190 (see warning) |

---

## Summary

The Phase 15 implementation is correct end-to-end. All three files implement the specification faithfully:

- Policy edit form (8 rows, enabled toggle, conditions builder integration, PUT submission)
- Policy delete flow (confirm dialog, y/n keys, list reload on success, stay-on-list on failure)
- ConditionsBuilder Esc round-trip preserves all form state including the `id` field

**2 warnings** about misleading hint strings should be addressed before release (Finding 1 is more impactful than Finding 2). **1 info-level** design note about `PolicyFormState.id` redundancy is logged for future consideration.
