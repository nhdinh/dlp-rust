---
phase: 21-in-place-condition-editing
reviewed: 2026-04-21T00:00:00Z
depth: standard
files_reviewed: 4
files_reviewed_list:
  - dlp-common/src/abac.rs
  - dlp-admin-cli/src/app.rs
  - dlp-admin-cli/src/screens/dispatch.rs
  - dlp-admin-cli/src/screens/render.rs
findings:
  critical: 0
  warning: 4
  info: 5
  total: 9
status: issues_found
---

# Phase 21: Code Review Report

**Reviewed:** 2026-04-21
**Depth:** standard
**Files Reviewed:** 4
**Status:** issues_found

## Summary

The four files implement the Phase 21 in-place condition editing feature on top of the existing
conditions builder modal. The overall design is sound: a new `edit_index: Option<usize>` field
on `Screen::ConditionsBuilder` tracks whether the builder is in edit-vs-new mode, and
`condition_to_prefill` provides the inverse of `build_condition` so the three-step picker
pre-populates correctly.

Two logic bugs were found that can silently produce wrong behavior at runtime: the `picker_idx`
value returned by `condition_to_prefill` is intentionally discarded in the `'e'` handler
(preventing Step 3 from opening on the correct list item), and the `draw_import_confirm`
function always hard-codes its list cursor to row 3 regardless of the `selected` state variable.
Two additional warnings cover an out-of-bounds panic risk and a subtle borrow-clone allocation
pattern. Five info-level items address naming consistency, dead-code annotations, and minor
code-duplication opportunities.

---

## Warnings

### WR-01: `picker_idx` from `condition_to_prefill` is discarded — Step 3 pre-fill silently broken

**File:** `dlp-admin-cli/src/screens/dispatch.rs:2349`

**Issue:** `condition_to_prefill` returns a 4-tuple `(attr, op_str, picker_idx, buf)`.
The `picker_idx` is explicitly silenced with `let _ = picker_idx;` at line 2349 and is
never written into `picker_state`. When the user presses `'e'` to edit an existing
condition, the builder opens at Step 1 as intended, but when they navigate forward to
Step 3, the picker will always start at index 0 instead of the original value's index.
The comment says "picker_idx is used for Step 3 pre-fill via build_condition roundtrip;
not needed here but consumed to avoid unused-variable warnings" — but the pre-fill never
actually happens, because `picker_state` is reset to `Some(attr_idx)` (the Step 1 index)
rather than a Step 3 index. This means editing a T4 classification condition, for example,
will open Step 3 with T1 highlighted rather than T4.

**Fix:** Store `picker_idx` as a dedicated field in `Screen::ConditionsBuilder` (e.g.,
`edit_picker_prefill: Option<usize>`), then apply it in `handle_conditions_step2`'s Enter
handler when advancing to Step 3 and `edit_index` is `Some(_)`:

```rust
// In Screen::ConditionsBuilder, add:
edit_picker_prefill: Option<usize>,

// In the 'e' handler (dispatch.rs ~line 2374), replace:
let _ = picker_idx;
// with:
*edit_picker_prefill = Some(picker_idx);

// In handle_conditions_step2 Enter handler, after setting step = 3:
if let Some(prefill) = *edit_picker_prefill {
    picker_state.select(Some(prefill));
    *edit_picker_prefill = None;
} else {
    picker_state.select(Some(0));
}
```

---

### WR-02: `draw_import_confirm` ignores the `selected` parameter — navigation cursor always fixed at row 3

**File:** `dlp-admin-cli/src/screens/render.rs:1661`

**Issue:** `draw_import_confirm` accepts a `selected: usize` parameter that is intended
to indicate which of the actionable rows (3 = Confirm, 4 = Cancel) is highlighted.
However, the list is rendered with a hard-coded `list_state.select(Some(3))` at line 1661
regardless of the `selected` argument. The `selected` variable is checked for styling on
rows 3 and 4 (lines 1612, 1628) but the list highlight cursor itself is pinned to row 3.
This means pressing Down to move to Cancel will update the style on the Cancel item but
the `>` highlight symbol will never follow — the cursor stays on Confirm.

**Fix:** Replace the hard-coded value with the `selected` parameter:

```rust
// Line 1661: change
list_state.select(Some(3));
// to
list_state.select(Some(selected));
```

---

### WR-03: `handle_conditions_step1` Enter handler re-uses the same `picker_state` for Step 2 without bounds-checking against the new attribute's operator count

**File:** `dlp-admin-cli/src/screens/dispatch.rs:2469-2470`

**Issue:** After selecting an attribute at Step 1 and advancing to Step 2, `picker_state`
is reset to `Some(0)`. That is correct for a fresh navigation. However, in the edit
path the `picker_state` starts with `Some(attr_idx)` (the attribute's position in the
ATTRIBUTES array, set at line 2374). If `attr_idx` (e.g. 4 for AccessContext) is larger
than the operator count for the new attribute (2 for AccessContext: "eq" and "neq"),
then `handle_conditions_step2`'s `ops.get(idx)` call at line 2566 would return `None`
and silently abort the Enter action, leaving the user stuck at Step 2 with no feedback.
This is not a crash, but it is confusing UX that could appear as a hang.

**Fix:** The reset at line 2470 already resets `picker_state` to `Some(0)` after
advancing to Step 2, so `attr_idx` is consumed in Step 1 and not carried into Step 2.
Verify this is always the case — the concern applies if `attr_idx` is ever set after the
step is advanced. The current code does reset on Enter; the risk is only if the `'e'`
path sets `picker_state` to `attr_idx` and then the user presses Enter at Step 1 to confirm
before Up/Down navigation (the initial selection is at `attr_idx`). Since `attr_idx` can
be up to 4 (for AccessContext) and Step 2 has at most 4 operators, a simple max bound
check makes this explicit and safe:

```rust
// Line 2374 in the 'e' handler, clamp to ATTRIBUTES.len() - 1:
picker_state.select(Some(attr_idx.min(ATTRIBUTES.len().saturating_sub(1))));
```

---

### WR-04: `handle_simulate_editing` Esc branch does not clear the buffer — stale input is silently preserved

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1905-1912`

**Issue:** When the user presses Esc while editing a simulate form field, the handler
sets `*editing = false` but does NOT clear `buffer`. The comment at line 1906 acknowledges
this by saying "The buffer retains in-progress text so it is recoverable if Enter is
pressed again." However, re-entering edit mode calls `action_open_simulate`'s path which
pre-fills `*buffer = pre_fill` from the form field — so the stale buffer is only cleared
if the user re-activates the same field. If the user cancels editing field A, navigates to
field B, and opens field B for editing, field B correctly pre-fills from the form. But if
the user then abandons edit on field B without committing, the buffer from field A is still
in memory (partially: the field B enter-edit path overwrote it). The comment in the code
describes this correctly. The actual risk is when `selected` changes without the buffer
being updated — e.g., Esc from field 0, navigate Down, then accidentally press Enter on
a select row (row 3-8), which calls `form.device_trust = (form.device_trust + 1) % ...`
with no issue, but if `editing` is left true through some edge, the stale buffer would
render as the active field. Current code sets `editing = false` on Esc, so the worst case
is a confusing UI state, not data corruption.

The defensive fix aligns with the existing policy/SIEM/alert pattern — clear buffer on
Esc:

```rust
KeyCode::Esc => {
    if let Screen::PolicySimulate { editing, buffer, .. } = &mut app.screen {
        buffer.clear(); // add this
        *editing = false;
    }
}
```

---

## Info

### IN-01: `condition_display` has `#[allow(dead_code)]` but is `pub` and actively used

**File:** `dlp-admin-cli/src/screens/dispatch.rs:2216-2217`

**Issue:** `condition_display` is declared `pub fn` and called from `render.rs` (lines 479
and 916). The `#[allow(dead_code)]` annotation is therefore incorrect — the function is
not dead code. The attribute was likely added during scaffolding and not removed. The
comment on the same line ("Called by Plan 02 render.rs draw_conditions_builder.") confirms
it is intentionally public. The annotation suppresses a lint that will never fire, making
intent harder to infer.

**Fix:** Remove the `#[allow(dead_code)]` attribute at line 2216.

---

### IN-02: `ConditionAttribute::label` has `#[allow(dead_code)]` but is called in `render.rs`

**File:** `dlp-admin-cli/src/app.rs:94`

**Issue:** Same pattern as IN-01. `ConditionAttribute::label` carries `#[allow(dead_code)]`
with a comment "Used by Plan 02 render.rs draw_conditions_builder." and is called at
`render.rs:303` and `render.rs:313`. The attribute is not dead and the annotation should
be removed.

**Fix:** Remove the `#[allow(dead_code)]` at line 94 of `app.rs`.

---

### IN-03: `draw_policy_create` and `draw_policy_edit` share identical rendering logic — duplication opportunity

**File:** `dlp-admin-cli/src/screens/render.rs:825-999` and `1017-1177`

**Issue:** The two functions (`draw_policy_create` and `draw_policy_edit`) are structurally
identical in their per-row rendering logic (rows 0-7) and differ only in the block title,
the final action row label ("[Submit]" vs "[Save]"), and the `policy_name` argument. The
doc comment on `draw_policy_edit` (line 1001) explicitly notes "Identical to
`draw_policy_create` except for the block title and the final action row label." This
duplication means that a future row change (e.g., adding row 9) must be applied in two
places.

**Fix:** Extract a shared `draw_policy_form` function parameterized on `title`, `submit_label`,
and the same arguments as the current pair. Both callers delegate to it.

---

### IN-04: `action_load_policy_for_edit` uses raw JSON key access for `priority` with `as_i64` — silently accepts negative values into a `u32` form field

**File:** `dlp-admin-cli/src/screens/dispatch.rs:1444-1447`

**Issue:** The priority is read with `policy["priority"].as_i64().map(|n| n.to_string())`.
If the server returns a negative priority (malformed data), this would store e.g. `"-1"`
in `form.priority`. The form's submit path parses priority as `u32`, so a negative value
would be caught at submit time with an error message. This is not a data-corruption risk,
but the UX is slightly inconsistent: the form displays a value it will refuse to submit.

**Fix:** Clamp or validate at load time:

```rust
priority: policy["priority"]
    .as_u64()
    .map(|n| n.to_string())
    .unwrap_or_default(),
```

---

### IN-05: `POLICY_FIELD_LABELS` has 9 entries but forms in Phase 19 have 9 rows (0-8) — the off-by-one comment is misleading

**File:** `dlp-admin-cli/src/screens/render.rs:618-628`

**Issue:** `POLICY_FIELD_LABELS` has 9 entries (indices 0-8). The doc comment for
`draw_policy_edit` at line 1027 says "Build 9 ListItems — one per row (Phase 19: 9 rows)"
which is correct. However, `draw_policy_create` at line 835 says "Build 8 ListItems" in
its comment, which is incorrect post-Phase-19 (Mode row was added). This comment mismatch
could mislead future maintainers.

**Fix:** Update the comment at line 835 of `render.rs`:

```rust
// Build 9 ListItems — one per row (rows 0..=8).
```

---

_Reviewed: 2026-04-21_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
