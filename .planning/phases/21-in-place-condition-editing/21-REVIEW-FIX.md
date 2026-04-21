---
phase: 21-in-place-condition-editing
fixed_at: 2026-04-21T07:50:00Z
review_path: .planning/phases/21-in-place-condition-editing/21-REVIEW.md
iteration: 1
findings_in_scope: 4
fixed: 4
skipped: 0
status: all_fixed
---

# Phase 21: Code Review Fix Report

**Fixed at:** 2026-04-21T07:50:00Z
**Source review:** .planning/phases/21-in-place-condition-editing/21-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 4
- Fixed: 4
- Skipped: 0

## Fixed Issues

### WR-01: `picker_idx` from `condition_to_prefill` is discarded — Step 3 pre-fill silently broken

**Files modified:** `dlp-admin-cli/src/app.rs`, `dlp-admin-cli/src/screens/dispatch.rs`
**Commit:** ca203ee
**Applied fix:**
Added `edit_picker_prefill: Option<usize>` field to `Screen::ConditionsBuilder` in `app.rs`
with a full doc comment. In the `'e'` handler (`dispatch.rs`), replaced `let _ = picker_idx`
with `*edit_picker_prefill = Some(picker_idx)`. In `handle_conditions_step2`'s Enter arm,
replaced the hardcoded `picker_state.select(Some(0))` with
`picker_state.select(Some(edit_picker_prefill.take().unwrap_or(0)))` so the Step 3 value
list opens on the original item during edits and falls back to 0 for new conditions.
All five `Screen::ConditionsBuilder` construction sites (two in production code, three in
tests) were updated with `edit_picker_prefill: None`.

Note: WR-03's defensive clamp (`attr_idx.min(ATTRIBUTES.len().saturating_sub(1))`) was
applied in the same commit since it is in the same 'e'-handler block.

### WR-02: `draw_import_confirm` ignores the `selected` parameter — cursor always fixed at row 3

**Files modified:** `dlp-admin-cli/src/screens/render.rs`
**Commit:** 60db19f
**Applied fix:**
Replaced `list_state.select(Some(3))` with `list_state.select(Some(selected))` at line 1661
so the `>` highlight symbol tracks the active row (Confirm=3 or Cancel=4) as the user
navigates.

### WR-03: `attr_idx` could exceed Step 2 operator count if used without bounds-checking

**Files modified:** `dlp-admin-cli/src/screens/dispatch.rs`
**Commit:** ca203ee (included with WR-01 — same 'e'-handler block)
**Applied fix:**
Added `.min(ATTRIBUTES.len().saturating_sub(1))` clamp to the `picker_state.select` call
in the 'e' handler. This is a defensive guard; the primary protection (Step 1 Enter resets
`picker_state` to `Some(0)` before Step 2) was already correct, so this makes the invariant
explicit.

### WR-04: `handle_simulate_editing` Esc branch does not clear the buffer

**Files modified:** `dlp-admin-cli/src/screens/dispatch.rs`
**Commit:** ca203ee (included with WR-01 — same file, committed together)
**Applied fix:**
Added `buffer.clear()` before `*editing = false` in the `KeyCode::Esc` arm of
`handle_simulate_editing`. Destructured `buffer` from the pattern match. Updated the
comment to reflect the new intent (clear on cancel rather than retain for recovery).

---

_Fixed: 2026-04-21T07:50:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
