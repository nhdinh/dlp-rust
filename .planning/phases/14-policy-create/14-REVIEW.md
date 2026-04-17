---
phase: 14-policy-create
reviewed: 2026-04-17T00:00:00Z
depth: standard
files_reviewed: 5
files_reviewed_list:
  - dlp-admin-cli/Cargo.toml
  - dlp-admin-cli/src/app.rs
  - dlp-admin-cli/src/screens/dispatch.rs
  - dlp-admin-cli/src/screens/render.rs
  - dlp-admin-cli/src/client.rs
findings:
  critical: 0
  warning: 5
  info: 4
  total: 9
status: issues_found
---

# Phase 14: Code Review Report

**Reviewed:** 2026-04-17T00:00:00Z
**Depth:** standard
**Files Reviewed:** 5
**Status:** issues_found

## Summary

Phase 14 introduces the Policy Create multi-field form with a conditions builder
modal. The implementation is structurally sound: the two-phase borrow pattern is
applied consistently, the UUID-on-client-side approach is correct, form
validation fires before any network call, and the CallerScreen Esc restoration
logic is symmetric across Step 1 and the pending-focused path.

The five warnings below are all correctness risks; none require server changes.
The four info items are quality/style observations.

---

## Warnings

### WR-01: Debug/temporary keyboard shortcut left in production dispatch path

**File:** `dlp-admin-cli/src/screens/dispatch.rs:167-184`
**Issue:** The `KeyCode::Char('c')` branch in `handle_policy_menu` opens
`ConditionsBuilder` directly, bypassing `PolicyCreate`. The branch is guarded
only by a `// TODO(phase-14): remove temporary test entry point` comment.
Because this code is compiled unconditionally into the release binary, any user
on the Policy Management menu can press `c` to enter the modal with a blank
`form_snapshot`. Pressing Esc at Step 1 will reconstruct `PolicyCreate` from
that blank snapshot, silently discarding any in-progress form state that was
navigated here via the normal path.
**Fix:** Remove the branch entirely before shipping. If a development shortcut
is needed, gate it with `#[cfg(debug_assertions)]`:
```rust
#[cfg(debug_assertions)]
KeyCode::Char('c') => { /* test entry */ }
```

---

### WR-02: `action_submit_policy` overwrites `validation_error` on server error even after successful navigation

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1262-1280`
**Issue:** On a successful POST, `action_submit_policy` calls
`action_list_policies(app)`, which replaces `app.screen` with
`Screen::PolicyList`. If (in a future code path) the server call succeeds but
`action_list_policies` fails (e.g. a subsequent list fetch returns an error),
the `Err(e)` branch at line 1272 tries to pattern-match `app.screen` as
`Screen::PolicyCreate` to write `validation_error`. However, the screen has
already been replaced by this point (or by `action_list_policies`'s own error
path), so the `if let` silently does nothing — the error is lost.

More immediately: `app.set_status("Policy created", StatusKind::Success)` is
called at line 1267 and then `action_list_policies` immediately calls
`app.set_status(...)` again at line 456-460, overwriting the success message
with the list-loaded count. This is benign but confusing — the "Policy created"
status is always shadowed.

**Fix:** Remove the intermediate `set_status` call before `action_list_policies`
and rely on the list-load message, or set the status after the entire sequence:
```rust
Ok(_) => {
    action_list_policies(app);
    // status is already set by action_list_policies
}
```

---

### WR-03: `serde_json::to_value(&form.conditions).unwrap_or(...)` silently swallows serialization failures

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1245-1246`
**Issue:** `PolicyCondition` serialization should not fail for valid enum
variants, but `unwrap_or` silently replaces the conditions with an empty array
if it does. This means a policy could be created with zero conditions even when
the user added some — a DLP correctness bug (an allow-all policy could be
submitted accidentally).
**Fix:** Propagate the serialization error inline rather than silently
discarding the conditions:
```rust
let conditions_json = match serde_json::to_value(&form.conditions) {
    Ok(v) => v,
    Err(e) => {
        if let Screen::PolicyCreate { validation_error, .. } = &mut app.screen {
            *validation_error = Some(format!("Failed to serialize conditions: {e}"));
        }
        return;
    }
};
```

---

### WR-04: `handle_policy_create_nav` — the catch-all `_` arm enters edit mode for non-editable rows

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1187-1205`
**Issue:** The final `_` arm in the `match selected` block inside
`handle_policy_create_nav` runs for **any** row index that is not explicitly
matched. The explicitly matched rows are `POLICY_SUBMIT_ROW` (6),
`POLICY_ADD_CONDITIONS_ROW` (4), `POLICY_ACTION_ROW` (3), and
`POLICY_CONDITIONS_DISPLAY_ROW` (5). That leaves rows 0, 1, 2 (text fields)
correctly handled, but also **any out-of-bounds `selected` value** (e.g. 7+),
which would attempt to match the `pre_fill` sub-arm and write
`String::new()` into `buffer` then set `editing = true`. While `selected` is
bounded by `nav(sel, POLICY_ROW_COUNT, ...)` today, any future change to
`POLICY_ROW_COUNT` without updating the match could expose this.

More concretely, `POLICY_CONDITIONS_DISPLAY_ROW` (5) is explicitly matched as
a no-op, but rows 0–2 fall through to the catch-all with a `match selected`
sub-arm that has its own `_ => String::new()` fallthrough. This inner `_` arm
means pressing Enter on row 5 (already no-op matched) is fine, but any other
unaccounted row silently enters edit mode with an empty buffer.

**Fix:** Replace the inner `_ => String::new()` fallthrough with an explicit
`return` or a debug assertion:
```rust
_ => {
    // Not a text-field row; guard against out-of-bounds selected.
    if selected > POLICY_PRIORITY_ROW {
        return;
    }
    // ... pre_fill logic for rows 0-2 only
}
```

---

### WR-05: `handle_conditions_step2` — operator index used without bounds check

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1654`
**Issue:** At line 1654, `ops[idx].0` is indexed directly without a bounds
check. `idx` comes from `picker_state.selected().unwrap_or(0)`. Today all
attributes return exactly one operator (`eq`), so `idx` will always be 0 and
in range. However, if `operators_for` is extended to return multiple operators
in a future phase and the picker state is somehow desynchronized (e.g. via a
stale `selected` after navigating away and back), this will panic at runtime.
**Fix:** Use `.get(idx)` with a fallback:
```rust
let op_name = match ops.get(idx) {
    Some((name, _)) => name.to_string(),
    None => return, // picker state out of range; ignore
};
*selected_operator = Some(op_name);
```

---

## Info

### IN-01: `CallerScreen::PolicyEdit` Esc handler is a placeholder stub producing wrong navigation

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1523-1526` and `1601-1603`
**Issue:** Both Esc-at-step-1 and Esc-from-pending-focused return
`Screen::PolicyMenu { selected: 0 }` for `CallerScreen::PolicyEdit`. This is
documented as "Phase 15 handles this," but the `#[allow(dead_code)]` on the
`PolicyEdit` variant in `app.rs` confirms it is never constructed today. This
is acceptable for Phase 14, but the stubs should be clearly unreachable or
replaced with `unreachable!()` to prevent accidental activation if Phase 15
starts constructing `CallerScreen::PolicyEdit` without updating both dispatch
branches.

**Fix:** (Phase 15 concern — note for review at that phase.) Consider using
`unreachable!("Phase 15 not yet implemented")` or a compile-time gate.

---

### IN-02: `draw_policy_create` uses hardcoded column-alignment padding strings

**File:** `dlp-admin-cli/src/screens/render.rs:759-793`
**Issue:** Each label row uses a manually counted padding string
(`"              "`, `"       "`, `"          "`, `"            "`) to
right-align the colon. These are fragile — a label change silently misaligns
all rows. This is a maintenance hazard as Phase 15 adds more rows.
**Fix:** Compute padding from a constant column width:
```rust
const LABEL_COL_WIDTH: usize = 15;
let pad = " ".repeat(LABEL_COL_WIDTH.saturating_sub(label.len()));
format!("{label}:{pad}{value}")
```

---

### IN-03: TODO comment left in dispatch (test entry point)

**File:** `dlp-admin-cli/src/screens/dispatch.rs:167`
**Issue:** `// TODO(phase-14): remove temporary test entry point` — this
comment is self-documenting that the `Char('c')` branch (covered in WR-01)
must be removed. If the branch is removed, the comment is automatically gone.
Retaining a `TODO` tied to the current phase in committed code violates the
project coding standard (§ 9.14: never commit commented-out code or debug
statements; the `TODO` is the debug artifact here).
**Fix:** Remove with the branch (see WR-01).

---

### IN-04: `client.rs` — `tls_verify` variable name is inverted relative to its meaning

**File:** `dlp-admin-cli/src/client.rs:50-51`
**Issue:** The variable is named `tls_verify` but its value is `true` when the
env var equals `"false"`, meaning the variable holds `disable_tls_verify`, not
`tls_verify`. The condition `if tls_verify` then calls
`danger_accept_invalid_certs(true)`, which is correct behaviour but the name
inverts the semantic. This predates Phase 14 but is in the reviewed file.
**Fix:** Rename for clarity:
```rust
let disable_tls_verify = std::env::var("DLP_ENGINE_TLS_VERIFY")
    .map(|v| v == "false")
    .unwrap_or(false);
// ...
if disable_tls_verify {
    tracing::warn!("TLS verification disabled (DLP_ENGINE_TLS_VERIFY=false)");
    builder = builder.danger_accept_invalid_certs(true);
}
```

---

_Reviewed: 2026-04-17T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
