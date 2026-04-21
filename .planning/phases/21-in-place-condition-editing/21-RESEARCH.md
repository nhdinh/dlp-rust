# Phase 21: In-Place Condition Editing - Research

**Researched:** 2026-04-21
**Domain:** ratatui TUI state machine — ConditionsBuilder modal extension
**Confidence:** HIGH

---

## Summary

Phase 21 is a TUI-only change that adds edit mode to the existing conditions builder
modal. No server, wire format, or ABAC evaluator changes are needed. All work is
confined to `dlp-admin-cli/src/screens/dispatch.rs` and `dlp-admin-cli/src/app.rs`
(adding one field to the `ConditionsBuilder` variant), with a minor render adjustment
for the modal title in `render.rs`.

The conditions builder already has a clean state machine: `step: u8` (1/2/3),
`selected_attribute: Option<ConditionAttribute>`, `selected_operator: Option<String>`,
`pending: Vec<PolicyCondition>`, `buffer: String`, `pending_focused: bool`, and two
`ListState` fields. Phase 20 delivered `operators_for()` and the SC-1 operator reset
guard. The only gap for edit mode is (a) knowing which pending list index is being
edited, (b) pre-filling the picker state at modal entry, and (c) replacing at that
index instead of `push()`-ing on commit.

The minimal design: add `edit_index: Option<usize>` to `Screen::ConditionsBuilder`.
When `None`, behaviour is new-condition (push). When `Some(i)`, behaviour is edit
(replace at index `i`). Both paths converge at the commit point in
`handle_conditions_step3_text` and `handle_conditions_step3_select`.

**Primary recommendation:** Add `edit_index: Option<usize>` to `Screen::ConditionsBuilder`.
Introduce a `condition_to_prefill()` helper that converts a `PolicyCondition` to
`(ConditionAttribute, String, usize, String)` (attribute, op wire string, picker_idx,
buffer). Wire `'e'` in `handle_conditions_pending` to extract the selected condition,
call `condition_to_prefill()`, then set the picker and buffer to pre-filled state and
set `edit_index = Some(idx)`. Modify the two step-3 commit blocks to call
`pending[i] = cond` when `edit_index` is `Some(i)` rather than `push`.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Edit-mode state tracking | TUI (ConditionsBuilder screen state) | — | edit_index lives inside Screen::ConditionsBuilder, same tier as all other picker state |
| Pre-fill on 'e' keypress | TUI dispatch layer (handle_conditions_pending) | — | Existing key handler; this is where 'd' lives today |
| Picker pre-population | TUI dispatch (picker_state + buffer mutation) | — | picker_state and buffer are ConditionsBuilder fields manipulated in dispatch.rs |
| Replace-at-index commit | TUI dispatch (step3 commit blocks) | — | Both handle_conditions_step3_text and handle_conditions_step3_select call pending.push() today; replace with index-aware write |
| Visual indicator (modal title) | TUI render layer (render.rs) | — | draw_conditions_builder title string; pass edit_index through to render |
| Cancel (Esc) correctness | TUI dispatch (existing Esc paths) | — | Esc at any step already reverts to pending list without push; no change needed when edit_index is set — the original pending entry is untouched |

---

## Standard Stack

### Core (already in Cargo.toml)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| ratatui | existing | TUI widget framework | [VERIFIED: in Cargo.toml] |
| crossterm | existing | Terminal key event backend | [VERIFIED: in Cargo.toml] |

No new dependencies required for this phase. [VERIFIED: codebase grep]

---

## Architecture Patterns

### Current ConditionsBuilder State Machine

```
Screen::ConditionsBuilder {
    step: u8,                              // 1=attribute, 2=operator, 3=value
    selected_attribute: Option<ConditionAttribute>,
    selected_operator: Option<String>,
    pending: Vec<PolicyCondition>,         // the list being built
    buffer: String,                        // MemberOf text input only
    pending_focused: bool,                 // Tab toggles focus
    pending_state: ListState,             // pending list selection
    picker_state: ListState,              // step picker selection
    caller: CallerScreen,                  // PolicyCreate | PolicyEdit
    form_snapshot: PolicyFormState,        // parent form state for Esc-return
}
```

[VERIFIED: dlp-admin-cli/src/app.rs lines 390-411]

### Proposed Edit-Mode Addition

Add a single field to `Screen::ConditionsBuilder`:

```rust
/// Index of the condition being edited, or None for a new condition.
///
/// Set to Some(i) when the user presses 'e' on pending row i.
/// Cleared to None after commit (replace) or cancel (step back).
/// When Some(i), the step-3 commit path calls pending[i] = cond
/// instead of pending.push(cond).
edit_index: Option<usize>,
```

All existing match arms that destructure `ConditionsBuilder { .. }` use `..` to ignore
unknown fields, so adding one field is non-breaking. [VERIFIED: dispatch.rs pattern audit]

### Pre-Fill Helper (new function in dispatch.rs)

A reverse of `build_condition`: given a `PolicyCondition`, return the four pieces
needed to populate the picker:

```rust
/// Decomposes a `PolicyCondition` into the (attribute, op, picker_idx, buffer)
/// tuple needed to pre-fill the 3-step picker for in-place editing.
///
/// `picker_idx` is the 0-based index into the Step 3 value list for select
/// attributes; 0 for MemberOf (text path, index unused).
/// `buffer` is the MemberOf group_sid string; empty for select attributes.
fn condition_to_prefill(
    cond: &PolicyCondition,
) -> (ConditionAttribute, String, usize, String) {
    use dlp_common::abac::{AccessContext, DeviceTrust, NetworkLocation};
    use dlp_common::Classification;
    match cond {
        PolicyCondition::Classification { op, value } => {
            let idx = match value {
                Classification::T1 => 0,
                Classification::T2 => 1,
                Classification::T3 => 2,
                Classification::T4 => 3,
            };
            (ConditionAttribute::Classification, op.clone(), idx, String::new())
        }
        PolicyCondition::MemberOf { op, group_sid } => {
            (ConditionAttribute::MemberOf, op.clone(), 0, group_sid.clone())
        }
        PolicyCondition::DeviceTrust { op, value } => {
            let idx = match value {
                DeviceTrust::Managed   => 0,
                DeviceTrust::Unmanaged => 1,
                DeviceTrust::Compliant => 2,
                DeviceTrust::Unknown   => 3,
            };
            (ConditionAttribute::DeviceTrust, op.clone(), idx, String::new())
        }
        PolicyCondition::NetworkLocation { op, value } => {
            let idx = match value {
                NetworkLocation::Corporate    => 0,
                NetworkLocation::CorporateVpn => 1,
                NetworkLocation::Guest        => 2,
                NetworkLocation::Unknown      => 3,
            };
            (ConditionAttribute::NetworkLocation, op.clone(), idx, String::new())
        }
        PolicyCondition::AccessContext { op, value } => {
            let idx = match value {
                AccessContext::Local => 0,
                AccessContext::Smb   => 1,
            };
            (ConditionAttribute::AccessContext, op.clone(), idx, String::new())
        }
    }
}
```

[VERIFIED: picker index order from build_condition lines 2068-2114 and ATTRIBUTES const lines 82-88]

The picker_idx maps directly to `picker_state.select(Some(picker_idx))` for the Step 3
pre-fill. For Step 2, the operator wire string is used to find its position in
`operators_for(attr)` and `picker_state.select(Some(op_idx))` is called. For Step 1, the
attribute index is found by scanning ATTRIBUTES.

### Entry-Point: 'e' key in handle_conditions_pending

Wire `KeyCode::Char('e') | KeyCode::Char('E')` in `handle_conditions_pending`, adjacent
to the existing 'd' / Delete arm. The handler:

1. Reads `pending_state.selected()` — returns if None or out of bounds.
2. Clones `pending[i]` to avoid borrow conflict.
3. Calls `condition_to_prefill(&cond)` to get `(attr, op_str, picker_idx, buffer)`.
4. Finds `attr_idx` by `ATTRIBUTES.iter().position(|a| *a == attr).unwrap_or(0)`.
5. Finds `op_idx` by `operators_for(attr).iter().position(|(w, _)| *w == op_str).unwrap_or(0)`.
6. Mutates `ConditionsBuilder` fields: `step = 1`, `selected_attribute = Some(attr)`,
   `selected_operator = Some(op_str)`, `buffer = buffer`, `edit_index = Some(i)`,
   `picker_state.select(Some(attr_idx))`, `pending_focused = false`.

**Why step = 1?** The user sees the full 3-step flow pre-filled so they can change any
level, including attribute. Phase 20's SC-1 guard auto-resets the operator if they
change the attribute in Step 1. This naturally handles SC-5 (success criterion 5).

Alternatively, the modal could jump directly to Step 3 if attribute+operator are kept,
but starting at Step 1 is simpler, tests better, and matches natural "re-enter" UX.
The planner should decide; both are viable. [ASSUMED]

### Commit Path: replace vs push

In both `handle_conditions_step3_text` and `handle_conditions_step3_select`, the Enter
arm today calls `pending.push(cond)`. For edit mode, replace instead:

```rust
// Replace or append depending on edit mode.
match edit_index {
    Some(i) if *i < pending.len() => {
        // In-place replace: preserve list length and position (SC-2).
        pending[*i] = cond;
        pending_state.select(Some(*i));
        *edit_index = None;
    }
    _ => {
        // New condition: append to list.
        pending.push(cond);
        pending_state.select(Some(pending.len() - 1));
    }
}
// Common: reset picker to Step 1 for the next operation.
*step = 1;
*selected_attribute = None;
*selected_operator = None;
buffer.clear();
picker_state.select(Some(0));
```

### Cancel (Esc) Correctness

Esc at any step goes back toward Step 1 and eventually closes the modal. The original
`pending[i]` entry is never touched during the 3-step navigation — only the commit path
(Enter at Step 3) writes to `pending`. So Esc-at-Step-3 → Step 2 → Step 1 → modal
close leaves `pending` exactly as it was before 'e' was pressed. SC-3 is satisfied
without any extra state. `edit_index` only needs to be cleared on commit; on Esc-modal-
close it is silently discarded with the rest of the screen state.

One subtle case: the user is in edit mode (edit_index = Some(i)), navigates to Step 1,
and presses Esc to close the modal. The modal closes and returns to the parent form with
`pending` unchanged — which is correct. No edge case here.

### Render: modal title indicator

Pass `edit_index: Option<usize>` through `draw_conditions_builder`'s signature and
update the modal title to `" Edit Condition "` when `edit_index.is_some()`, or keep
`" Conditions Builder "` for new-condition mode. This is the only render change needed.

The render call site (`render.rs` lines 143-165) destructures `ConditionsBuilder` — add
`edit_index` to the destructure pattern and pass it as an argument.

### Existing Open Transitions in ConditionsBuilder

The modal is opened from two places (both transition from the parent form's
`POLICY_ADD_CONDITIONS_ROW` Enter handler):
- `PolicyCreate` at dispatch.rs line 1244
- `PolicyEdit` at dispatch.rs line 1579

Both construct `Screen::ConditionsBuilder { ... }`. When `edit_index` is added to the
variant, both call sites must include `edit_index: None` (normal open = new condition
mode). [VERIFIED: app.rs lines 390-411, dispatch.rs lines 1244-1260 and 1579-1593]

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Enum-to-index reverse mapping | A HashMap or serde round-trip | Direct match block in condition_to_prefill | The enum variants are small and stable; a match is O(1), exhaustive, and compile-checked |
| TUI modal state | A separate Modal enum layer | extend edit_index directly into existing ConditionsBuilder | Adding one field is zero overhead vs wrapping in a new enum layer |

---

## Common Pitfalls

### Pitfall 1: Forgetting edit_index in ConditionsBuilder open call sites

**What goes wrong:** `Screen::ConditionsBuilder { ..., }` struct literal requires all
fields once `edit_index` is added. Missing it at the two open-call sites causes a
compile error.

**How to avoid:** grep for `Screen::ConditionsBuilder {` after adding the field; fix
both open sites to include `edit_index: None`.

**Warning signs:** `error[E0063]: missing field 'edit_index' in initializer` at compile.

### Pitfall 2: Forgetting edit_index in render.rs destructure

**What goes wrong:** The `Screen::ConditionsBuilder { step, ..., .. }` destructure in
`render.rs` uses `..` to ignore extra fields — so adding `edit_index` does NOT break
the destructure. However, the planner must also pass `edit_index` through as a new
argument to `draw_conditions_builder` if the title indicator is wanted.

**How to avoid:** Grep for `draw_conditions_builder(` to find the call site and add the
argument.

### Pitfall 3: edit_index not cleared on Esc-close

**What goes wrong:** If the user opens edit mode, presses Esc to close the modal, and
re-enters the builder (Add Conditions row), `edit_index` might carry over if the builder
is reconstructed from the form_snapshot.

**Why it doesn't happen here:** The modal is reconstructed from scratch every time the
parent form opens it (lines 1244-1260 and 1579-1593); `edit_index: None` is set at
construction. The form_snapshot holds `PolicyFormState`, which does not carry
`edit_index`. So stale state is impossible.

### Pitfall 4: operator pre-fill index mismatch after Phase 20

**What goes wrong:** `operators_for()` returns a slice in a specific order. To pre-fill
Step 2's `picker_state`, the code must find the op wire string's *position* in that
slice. Using a hardcoded index (e.g., always 0) would silently select the wrong operator.

**How to avoid:** Use `operators_for(attr).iter().position(|(w, _)| *w == op_str)` to
find the correct index.

### Pitfall 5: Borrow conflict when reading pending[i] and then mutating screen

**What goes wrong:** Reading `&app.screen` for `pending[i]` and then doing `if let
Screen::ConditionsBuilder { ..., edit_index, ... } = &mut app.screen` on the same line
violates Rust's borrow rules.

**How to avoid:** Clone `pending[i]` first (shared borrow), drop the shared borrow,
then take the mutable borrow. Follow the two-phase read-then-mutate pattern already
established in `handle_conditions_builder` (line 2143). [VERIFIED: dispatch.rs line 2143]

---

## Code Examples

### Two-phase borrow pattern (existing, extend this)

[VERIFIED: dispatch.rs lines 2141-2185]

```rust
fn handle_conditions_builder(app: &mut App, key: KeyEvent) {
    // Phase 1: shared borrow to snapshot scalars.
    let (step, pending_focused, ...) = match &app.screen {
        Screen::ConditionsBuilder { step, pending_focused, .. } => (*step, *pending_focused, ...),
        _ => return,
    };
    // Phase 2: mutable borrow after shared is dropped.
    if let Screen::ConditionsBuilder { pending_focused, .. } = &mut app.screen {
        *pending_focused = !*pending_focused;
    }
}
```

### 'd' key handler to model 'e' after (existing)

[VERIFIED: dispatch.rs lines 2211-2229]

```rust
KeyCode::Char('d') | KeyCode::Char('D') | KeyCode::Delete => {
    if let Screen::ConditionsBuilder { pending, pending_state, .. } = &mut app.screen {
        if let Some(idx) = pending_state.selected() {
            if idx < pending.len() {
                pending.remove(idx);
                // adjust selection...
            }
        }
    }
}
```

The 'e' handler needs to: clone `pending[idx]`, then call `condition_to_prefill`, then
take the mutable borrow to set all picker fields.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` via `cargo test` |
| Config file | none (workspace Cargo.toml) |
| Quick run command | `cargo test -p dlp-admin-cli` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| POLICY-10 (SC-1) | 'e' opens picker pre-filled with attribute/op/value | unit | `cargo test -p dlp-admin-cli -- condition_edit` | No - Wave 0 |
| POLICY-10 (SC-2) | Save replaces at original index; count and order unchanged | unit | `cargo test -p dlp-admin-cli -- edit_replace_preserves_index` | No - Wave 0 |
| POLICY-10 (SC-3) | Esc returns pending list unchanged | unit | `cargo test -p dlp-admin-cli -- edit_cancel_preserves_condition` | No - Wave 0 |
| POLICY-10 (SC-4) | Delete binding still works (regression) | unit | `cargo test -p dlp-admin-cli -- pending_delete` | Yes (existing) |
| POLICY-10 (SC-5) | Attribute change resets operator (SC-1 guard) | unit | `cargo test -p dlp-admin-cli -- operator_reset_on_attr_change` | Yes (existing, Phase 20) |

TUI state machine tests are unit-testable without a real terminal: construct
`App { screen: Screen::ConditionsBuilder { ... } }`, call `handle_conditions_builder()`
with a synthetic `KeyEvent`, and assert on `app.screen`. This is exactly the pattern
used in the existing test at dispatch.rs lines 3012-3057. [VERIFIED: dispatch.rs line 3016]

### Wave 0 Gaps

- [ ] `dlp-admin-cli/src/screens/dispatch.rs` — `#[cfg(test)]` block needs new test:
  `edit_opens_picker_prefilled` (verify 'e' sets step=1, selected_attribute, selected_operator,
  picker_state position, and edit_index=Some(i))
- [ ] `edit_replace_preserves_index` (verify commit replaces at i, len unchanged)
- [ ] `edit_cancel_preserves_condition` (verify Esc-from-step3 leaves pending[i] untouched)
- [ ] `condition_to_prefill_roundtrip` (verify all 5 variants: prefill -> build_condition yields same condition)

---

## Security Domain

This phase makes no server-side, authentication, or data-transit changes. It is
TUI-state-only. No ASVS categories apply. [VERIFIED: phase description]

---

## Files to Modify

Exactly three files:

| File | Change |
|------|--------|
| `dlp-admin-cli/src/app.rs` | Add `edit_index: Option<usize>` field to `Screen::ConditionsBuilder` variant |
| `dlp-admin-cli/src/screens/dispatch.rs` | (1) Add `condition_to_prefill()` helper; (2) Wire 'e' in `handle_conditions_pending`; (3) Modify step-3 commit in both `handle_conditions_step3_text` and `handle_conditions_step3_select`; (4) Add unit tests |
| `dlp-admin-cli/src/screens/render.rs` | Pass `edit_index` through `draw_conditions_builder` signature; update modal title when edit_index is Some |

[VERIFIED: file locations from Phase 20 canonical_refs and direct codebase inspection]

---

## Open Questions

1. **Step navigation in edit mode: start at Step 1 or jump to Step 3?**
   - What we know: starting at Step 1 is simpler and handles SC-5 (attribute change) naturally
     because SC-1 guard already resets the operator.
   - What's unclear: some users might prefer jumping straight to Step 3 if they only want
     to change the value.
   - Recommendation: start at Step 1 (pre-filled). If the planner or user prefers Step 3
     jump, it is an additive change — initialize `step = 3` and skip straight there. [ASSUMED]

2. **Footer key hint for 'e'**
   - What we know: `draw_conditions_builder` renders a footer with key hints. The 'd' delete
     hint is already shown.
   - What's unclear: exact footer string format and where it is rendered in render.rs.
   - Recommendation: add `e: edit` adjacent to `d: delete` in the footer hint. The planner
     should read render.rs footer section before specifying the exact copy.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Starting edit at Step 1 (pre-filled) is the correct UX rather than jumping to Step 3 | Architecture Patterns, Open Questions | Low — either approach satisfies SC-1 through SC-5; it is a UX preference, not a correctness issue |
| A2 | The render title change to "Edit Condition" is the only visual indicator needed | Architecture Patterns | Low — the planner may want an additional indicator; purely additive |

---

## Sources

### Primary (HIGH confidence)

All findings verified directly from the codebase in this session:

- `dlp-admin-cli/src/app.rs` lines 60-411 — `ConditionAttribute`, `ATTRIBUTES`, `PolicyFormState`, `Screen::ConditionsBuilder` variant with all current fields
- `dlp-admin-cli/src/screens/dispatch.rs` lines 2055-2620 — `build_condition`, `condition_display`, `handle_conditions_builder`, `handle_conditions_pending` (delete handler), all step handlers
- `dlp-admin-cli/src/screens/dispatch.rs` lines 2020-2046 — `operators_for`, `value_count_for`
- `dlp-admin-cli/src/screens/dispatch.rs` lines 1244-1260, 1579-1593 — both ConditionsBuilder open call sites
- `dlp-admin-cli/src/screens/render.rs` lines 143-165, 387-433 — render destructure and `draw_conditions_builder` signature
- `dlp-common/src/abac.rs` lines 213-247 — `PolicyCondition` enum with all five variants and field names
- `.planning/phases/20-operator-expansion/20-CONTEXT.md` — `operators_for` decisions, SC-1 guard, D-08/D-10
- `.planning/phases/20-operator-expansion/20-02-tui-operator-picker-PLAN.md` — `operators_for` signature, `pick_operators` in render.rs

---

## Metadata

**Confidence breakdown:**
- Files to modify: HIGH — directly verified in source
- State machine design (edit_index field): HIGH — pattern matches existing `..` destructure convention
- Pre-fill helper design: HIGH — verified against build_condition mapping and ATTRIBUTES const
- Step-start UX decision (Step 1 vs Step 3): ASSUMED — valid either way; flagged for planner

**Research date:** 2026-04-21
**Valid until:** stable — this is internal TUI code; no external dependencies
