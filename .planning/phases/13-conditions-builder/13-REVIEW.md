---
phase: 13-conditions-builder
reviewed: 2026-04-16T00:00:00Z
depth: standard
files_reviewed: 3
files_reviewed_list:
  - dlp-admin-cli/src/app.rs
  - dlp-admin-cli/src/screens/dispatch.rs
  - dlp-admin-cli/src/screens/render.rs
findings:
  critical: 0
  warning: 4
  info: 4
  total: 8
status: issues_found
---

# Phase 13: Code Review Report

**Reviewed:** 2026-04-16
**Depth:** standard
**Files Reviewed:** 3
**Status:** issues_found

## Summary

The conditions-builder state machine is structurally sound. The borrow-checker
patterns are correct throughout: all three dispatch sub-handlers use the
two-phase read-then-mutate idiom, and the render path clones `ListState`
before calling `render_stateful_widget` (Pitfall 3 avoided correctly).
`build_condition` correctly uses `group_sid` for `MemberOf` and the unit
tests provide solid coverage of `build_condition`, `operators_for`, and
`condition_display`.

Four warnings identify logic bugs or missing coverage that could cause
incorrect runtime behavior; four info items flag quality issues.

---

## Warnings

### WR-01: Panic on Up-arrow in Step 2 / Step 3 picker when operator list is empty

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1329`
**Issue:** `handle_conditions_step2` computes `ops.len() - 1` without a
zero-check. `operators_for` currently always returns at least one entry, but
the function signature returns `&'static [(&'static str, bool)]`, and a
future variant with an empty slice would cause an integer underflow (panic in
debug, wrap to `usize::MAX` in release). The same pattern appears in
`handle_conditions_step3_select` at line 1489 where `count - 1` is computed
from `value_count_for`, which explicitly returns `0` for `MemberOf`. If
`MemberOf` were ever routed to `handle_conditions_step3_select` (today it is
guarded, but the guard is in the caller), the subtraction would underflow.

**Fix:** Guard both subtraction sites:
```rust
// handle_conditions_step2, Up arrow branch (line ~1329)
KeyCode::Up => {
    if ops.is_empty() { return; }
    if current == 0 { ops.len() - 1 } else { current - 1 }
}

// handle_conditions_step3_select, Up arrow branch (line ~1489)
KeyCode::Up => {
    if count == 0 { return; }
    if current == 0 { count - 1 } else { current - 1 }
}
```

---

### WR-02: Step 1 picker index can exceed `ATTRIBUTES` bounds after a resize

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1296`
**Issue:** `handle_conditions_step1` on Enter uses
`picker_state.selected().unwrap_or(0)` as a direct index into `ATTRIBUTES`
without a bounds check:
```rust
let idx = picker_state.selected().unwrap_or(0);
*selected_attribute = Some(ATTRIBUTES[idx]);   // panics if idx >= 5
```
`picker_state` is set by the Up/Down handler which wraps modulo
`ATTRIBUTES.len()`, so in normal operation `idx` stays in range. However,
`ListState::select` accepts any `usize`; if an external caller (e.g., a
future phase) sets a stale index, this will panic.

**Fix:**
```rust
let attr = ATTRIBUTES.get(idx).copied().unwrap_or(ConditionAttribute::Classification);
*selected_attribute = Some(attr);
```

---

### WR-03: `handle_conditions_step1` Up-arrow wraps to `ATTRIBUTES.len() - 1` without checking `picker_state.selected()` is valid

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1273-1284`
**Issue:** The Step 1 Up-arrow navigation computes `ATTRIBUTES.len() - 1`
(which is 4) unconditionally. This is fine today because `ATTRIBUTES` is a
static array of 5 elements. However, the same literal pattern is not used
for Steps 2 and 3 (they use `ops.len()` and `count`). For consistency and
future-safety, the Step 1 Up-arrow should also be based on `ATTRIBUTES.len()`
rather than a compile-time constant — and it already is (uses `ATTRIBUTES.len() - 1`).
The actual bug is that this is the one spot where `current` could be stale
(e.g., set to `Some(5)` externally) and `current == 0` never triggers,
so `current - 1` subtraction on `usize` would underflow if `current` is `0`
and `picker_state.selected()` returns `None` (unwrap_or(0) guards that case,
so this is safe). This is a false positive on closer inspection — see WR-01
and WR-02 for the real issues. Marking as warning only because the `unwrap_or`
correctly handles the `None` branch.

**Fix:** No code change required; the pattern is safe given `unwrap_or(0)`.
Retract to Info — see IN-03.

---

### WR-04: `handle_conditions_step2` Esc resets `selected_attribute` to `None` but should preserve it

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1362-1375`
**Issue:** Pressing Esc at Step 2 sets `*selected_attribute = None` before
returning to Step 1. When the user returns to Step 1 and presses Enter again,
`picker_state.selected()` still holds the previously chosen row index, so the
attribute is re-selected correctly. The reset of `selected_attribute` to `None`
in the Esc path is therefore redundant rather than harmful — but it is
potentially inconsistent: if any render or dispatch code checks
`selected_attribute` while `step == 1` and expects `None` (none currently
does), this assumption would be violated if the attribute were preserved. The
concern is the breadcrumb render at line 196 in render.rs: `step_label` uses
`selected_attribute` for display in Steps 2 and 3 only, so clearing it on
Esc at Step 2 is correct behavior for the current render.

No bug here; downgraded to Info — see IN-04.

---

## Revised Warning Count After Analysis

WR-03 and WR-04 were retracted during analysis. Final warning list:

### WR-01: Potential underflow panic — `ops.len() - 1` and `count - 1` unguarded

*(See full description above.)*

### WR-02: Unchecked array index — `ATTRIBUTES[idx]` in Step 1 Enter handler

*(See full description above.)*

### WR-03: `handle_policies` list clone unnecessarily clones the entire `Vec<serde_json::Value>`

**File:** `dlp-admin-cli/src/screens/dispatch.rs:401`
**Issue:** `handle_policy_list` and `handle_agent_list` both clone the entire
policies/agents `Vec` at the top of the function purely to satisfy the borrow
checker:
```rust
let (policies, selected) = match &mut app.screen {
    Screen::PolicyList { policies, selected } => (policies.clone(), selected),
    //                                            ^^^^^^^^^^^^^^^^ clones all JSON
    _ => return,
};
```
The clone is needed because `selected` is borrowed mutably while `policies`
is borrowed immutably — but the `policies` data is only ever read (via
`policies.len()` and `policies.get(*selected)`). The standard two-phase
pattern (read length first, then mutate) eliminates the clone.

**Fix:**
```rust
fn handle_policy_list(app: &mut App, key: KeyEvent) {
    let (len, enter_idx) = match &app.screen {
        Screen::PolicyList { policies, selected } => (policies.len(), *selected),
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if len > 0 {
                if let Screen::PolicyList { selected, .. } = &mut app.screen {
                    nav(selected, len, key.code);
                }
            }
        }
        KeyCode::Enter => {
            let policy = match &app.screen {
                Screen::PolicyList { policies, .. } => policies.get(enter_idx).cloned(),
                _ => return,
            };
            if let Some(p) = policy {
                app.screen = Screen::PolicyDetail { policy: p };
            }
        }
        KeyCode::Esc => app.screen = Screen::PolicyMenu { selected: 0 },
        _ => {}
    }
}
```
Apply the same fix to `handle_agent_list`. This is a correctness-adjacent
warning because the current approach produces a shallow clone of every
`serde_json::Value` on every key press in the list view.

### WR-04: `draw_conditions_builder` divider string allocates on every frame

**File:** `dlp-admin-cli/src/screens/render.rs:343`
**Issue:** `"-".repeat(inner.width as usize)` allocates a new `String` on
every render tick (typically 60 fps). This is the hot path and causes
repeated heap allocation. It is not a correctness bug but is a rendering
quality issue that can cause visible flicker on slow terminals because
repeated `String` allocations pressure the allocator.

**Fix:** Use a static dash and rely on ratatui's `Wrap` or a `Block` title,
or cap the divider at a reasonable constant width:
```rust
// Replace the dynamic repeat with a fixed-length separator.
const DIVIDER: &str = "────────────────────────────────────────────────────────────────";
let divider_line = &DIVIDER[..DIVIDER.len().min(inner.width as usize)];
let divider = Paragraph::new(Line::styled(divider_line, Style::default().fg(Color::DarkGray)));
```
Or use a `Block::default().borders(Borders::BOTTOM)` on the pending list
instead, which ratatui renders without allocation.

---

## Info

### IN-01: `TODO(phase-14)` temporary entry point — review note

**File:** `dlp-admin-cli/src/screens/dispatch.rs:164-179`
**Issue:** The `KeyCode::Char('c')` branch in `handle_policy_menu` is a
dev-only shortcut to open the ConditionsBuilder without a policy create form.
It is correctly marked `// TODO(phase-14): remove temporary test entry point`
and poses no security risk because the entire binary is admin-only and
requires a JWT. The `#[allow(dead_code)]` on `ConditionsBuilder` in app.rs
(line 229) is consistent with this phase boundary.

**Fix:** No action required. Remove the `Char('c')` arm and the
`#[allow(dead_code)]` annotation on `ConditionsBuilder` as part of Phase 14.

---

### IN-02: `condition_display` uses `{value:?}` (Debug) for `DeviceTrust`, `NetworkLocation`, `AccessContext`

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1155-1160`
**Issue:** The pending conditions list shows e.g. `DeviceTrust eq Managed`
for `DeviceTrust` (because `Debug` for unit-like enum variants prints the
variant name). This is readable but is fragile: if the `Debug` impl of those
enums is ever changed (e.g., via a derive macro attribute), the display string
silently changes. `Classification` correctly uses `Display`; the others should
too if those enums implement `Display`.

**Fix:** If `DeviceTrust`, `NetworkLocation`, and `AccessContext` implement
`Display` (or can have it derived via `strum`), use `{value}` instead of
`{value:?}` in `condition_display`. Otherwise, document the `Debug`
dependency explicitly in the function doc comment so it is not accidentally
broken.

---

### IN-03: Missing test for `build_condition` with picker index `0` for `MemberOf` (non-empty buffer path)

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1592-1605`
**Issue:** `build_condition_member_of_group_sid` tests that `group_sid` is
correctly used instead of `value`. However, there is no test for the combined
case where a non-ASCII SID is provided (e.g., a SID with hyphens and numeric
segments), nor a test that verifies the `trim()` behavior for leading/trailing
whitespace that is not all-spaces (e.g., `"  S-1-5-21-1234  "`).

**Fix:** Add:
```rust
#[test]
fn build_condition_member_of_trims_whitespace() {
    let cond = build_condition(ConditionAttribute::MemberOf, "eq", 0, "  S-1-5-21-999  ");
    assert!(cond.is_some());
    let json = serde_json::to_string(&cond.unwrap()).expect("serialize");
    assert!(json.contains("\"group_sid\":\"S-1-5-21-999\""));
}
```

---

### IN-04: `operators_for` and `value_count_for` are private but not tested as a pair

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1064-1072`
**Issue:** `value_count_for` is tested in isolation (line 1697), and
`operators_for` is tested in isolation (line 1663). There is no test
verifying that `value_count_for(MemberOf) == 0` correlates with the
`is_member_of_step3` branch in `handle_conditions_step3` (i.e., that routing
MemberOf to `handle_conditions_step3_text` rather than
`handle_conditions_step3_select` is consistent with `value_count_for`
returning 0). A future developer adding a new attribute could set
`value_count_for` to a non-zero value while forgetting to update the branch
guard in `handle_conditions_step3`.

**Fix:** Add a consistency test:
```rust
#[test]
fn member_of_value_count_is_zero_consistent_with_text_input_routing() {
    // MemberOf must have value_count == 0 because it uses text input, not a list.
    // If this fails, also update the branch guard in handle_conditions_step3.
    assert_eq!(value_count_for(ConditionAttribute::MemberOf), 0);
    // All other attributes must have value_count > 0 (they use list selection).
    for attr in ATTRIBUTES {
        if attr != ConditionAttribute::MemberOf {
            assert!(
                value_count_for(attr) > 0,
                "Non-MemberOf attribute {:?} must have value_count > 0",
                attr
            );
        }
    }
}
```

---

_Reviewed: 2026-04-16_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
