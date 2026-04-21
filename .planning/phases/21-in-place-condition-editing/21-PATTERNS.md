# Phase 21: In-Place Condition Editing - Pattern Map

**Mapped:** 2026-04-21
**Files analyzed:** 3
**Analogs found:** 3 / 3

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-admin-cli/src/app.rs` | model (enum variant) | — | `app.rs` `Screen::ConditionsBuilder` (self, existing fields) | exact — extend same variant |
| `dlp-admin-cli/src/screens/dispatch.rs` | state-machine / handler | event-driven | `dispatch.rs` `handle_conditions_pending` ('d' arm) + step3 commit blocks | exact |
| `dlp-admin-cli/src/screens/render.rs` | component | request-response | `render.rs` `draw_conditions_builder` (self, title + hints) | exact |

---

## Pattern Assignments

### `dlp-admin-cli/src/app.rs` — add `edit_index` field to `Screen::ConditionsBuilder`

**Analog:** `app.rs` lines 390–411 — the existing `ConditionsBuilder` variant

**Existing variant structure** (lines 390–411):
```rust
ConditionsBuilder {
    step: u8,
    selected_attribute: Option<ConditionAttribute>,
    selected_operator: Option<String>,
    pending: Vec<dlp_common::abac::PolicyCondition>,
    buffer: String,
    pending_focused: bool,
    pending_state: ratatui::widgets::ListState,
    picker_state: ratatui::widgets::ListState,
    caller: CallerScreen,
    form_snapshot: PolicyFormState,
},
```

**Field to insert** (after `form_snapshot`, before the closing brace):
```rust
    /// Index of the condition being edited, or None for a new condition.
    ///
    /// Set to Some(i) when the user presses 'e' on pending row i.
    /// Cleared to None after commit (replace) or cancel (step back).
    /// When Some(i), the step-3 commit path calls `pending[i] = cond`
    /// instead of `pending.push(cond)`.
    edit_index: Option<usize>,
```

**Doc-comment style pattern** — match the surrounding doc style (triple-slash, `///`).
All existing fields use `///` doc comments with a single sentence followed by a
blank-line elaboration where needed. Copy that style exactly.

**Why adding one field is non-breaking:** All match arms in dispatch.rs and render.rs
that destructure `ConditionsBuilder { ... }` use `..` to ignore unknown fields, so no
existing arm requires updating. The only two places that *construct* the variant must
be updated:

- `dispatch.rs` line 1244 (`PolicyCreate` open path) — add `edit_index: None`
- `dispatch.rs` line 1579 (`PolicyEdit` open path) — add `edit_index: None`

**Construction pattern** (lines 1244–1260, canonical, copy for both open sites):
```rust
let mut picker_state = ratatui::widgets::ListState::default();
picker_state.select(Some(0));
app.screen = Screen::ConditionsBuilder {
    step: 1,
    selected_attribute: None,
    selected_operator: None,
    pending: form.conditions.clone(),
    buffer: String::new(),
    pending_focused: false,
    pending_state: ratatui::widgets::ListState::default(),
    picker_state,
    caller: CallerScreen::PolicyCreate,   // or CallerScreen::PolicyEdit at line 1588
    form_snapshot: PolicyFormState {
        conditions: vec![],
        ..form
    },
    edit_index: None,    // <-- add this line to both open sites
};
```

---

### `dlp-admin-cli/src/screens/dispatch.rs` — four change areas

#### Area 1: new `condition_to_prefill()` helper

**Analog:** `build_condition()` (lines 2055–2116) — `condition_to_prefill` is its
exact inverse. Copy the match structure and import block verbatim, reversing the
direction (enum variant fields → picker indices).

**Import block to copy** (lines 2061–2063):
```rust
use dlp_common::abac::{AccessContext, DeviceTrust, NetworkLocation, PolicyCondition};
// Classification is at dlp_common root, NOT dlp_common::abac (see abac.rs line 222).
use dlp_common::Classification;
```

**build_condition core pattern** (lines 2066–2116) — the index order defined here is
the canonical source of truth for `condition_to_prefill`'s reverse mapping:
```rust
ConditionAttribute::Classification => {
    let value = match picker_selected {
        0 => Classification::T1,
        1 => Classification::T2,
        2 => Classification::T3,
        3 => Classification::T4,
        _ => return None,
    };
    PolicyCondition::Classification { op, value }
}
ConditionAttribute::MemberOf => {
    // CRITICAL: MemberOf uses group_sid, NOT value (abac.rs line 226).
    if buffer.trim().is_empty() { return None; }
    PolicyCondition::MemberOf { op, group_sid: buffer.trim().to_string() }
}
ConditionAttribute::DeviceTrust => {
    let value = match picker_selected {
        0 => DeviceTrust::Managed,
        1 => DeviceTrust::Unmanaged,
        2 => DeviceTrust::Compliant,
        3 => DeviceTrust::Unknown,
        _ => return None,
    };
    PolicyCondition::DeviceTrust { op, value }
}
ConditionAttribute::NetworkLocation => {
    let value = match picker_selected {
        0 => NetworkLocation::Corporate,
        1 => NetworkLocation::CorporateVpn,
        2 => NetworkLocation::Guest,
        3 => NetworkLocation::Unknown,
        _ => return None,
    };
    PolicyCondition::NetworkLocation { op, value }
}
ConditionAttribute::AccessContext => {
    let value = match picker_selected {
        0 => AccessContext::Local,
        1 => AccessContext::Smb,
        _ => return None,
    };
    PolicyCondition::AccessContext { op, value }
}
```

**New function signature** (place adjacent to `build_condition`, same module scope):
```rust
/// Decomposes a `PolicyCondition` into the `(attribute, op, picker_idx, buffer)`
/// tuple needed to pre-fill the 3-step picker for in-place editing.
///
/// # Arguments
///
/// * `cond` - The condition to decompose.
///
/// # Returns
///
/// `(ConditionAttribute, op_wire_string, picker_idx, buffer)`
/// - `picker_idx` is the 0-based index into the Step 3 value list for select
///   attributes; 0 for MemberOf (text path, index unused).
/// - `buffer` is the MemberOf `group_sid` string; `String::new()` for select
///   attributes.
fn condition_to_prefill(
    cond: &dlp_common::abac::PolicyCondition,
) -> (ConditionAttribute, String, usize, String) {
```

---

#### Area 2: 'e' key handler in `handle_conditions_pending`

**Analog:** the existing 'd' / Delete arm (lines 2211–2230) — the 'e' arm is
structurally identical, differing only in what it does to the screen state after
reading the index.

**'d' arm to copy structure from** (lines 2211–2230):
```rust
KeyCode::Char('d') | KeyCode::Char('D') | KeyCode::Delete => {
    if let Screen::ConditionsBuilder {
        pending,
        pending_state,
        ..
    } = &mut app.screen
    {
        if let Some(idx) = pending_state.selected() {
            if idx < pending.len() {
                pending.remove(idx);
                // Adjust selection so it stays in range after removal.
                if pending.is_empty() {
                    pending_state.select(None);
                } else if idx >= pending.len() {
                    pending_state.select(Some(pending.len() - 1));
                }
            }
        }
    }
}
```

**Two-phase borrow pattern for 'e'** (established at lines 2141–2185) — required
because reading `pending[idx]` (shared borrow on `app.screen`) and then mutating
`app.screen` fields cannot happen in the same borrow scope:
```rust
// Phase 1: shared borrow to snapshot the condition.
let (step, pending_focused, selected_attribute, selected_operator, pending_len) =
    match &app.screen {
        Screen::ConditionsBuilder {
            step,
            pending_focused,
            selected_attribute,
            selected_operator,
            pending,
            ..
        } => (
            *step,
            *pending_focused,
            *selected_attribute,
            selected_operator.clone(),
            pending.len(),
        ),
        _ => return,
    };
// Phase 2: mutable borrow after shared is dropped.
if let Screen::ConditionsBuilder { pending_focused, .. } = &mut app.screen {
    *pending_focused = !*pending_focused;
}
```

**Concrete 'e' handler structure** — wire immediately after the 'd' arm in
`handle_conditions_pending`:
```rust
KeyCode::Char('e') | KeyCode::Char('E') => {
    // Phase 1: clone the condition under shared borrow before any mutation.
    let cond_to_edit = match &app.screen {
        Screen::ConditionsBuilder { pending, pending_state, .. } => {
            pending_state.selected().and_then(|i| pending.get(i).cloned())
        }
        _ => return,
    };
    let Some((edit_i, cond)) = cond_to_edit.and_then(|c| {
        // re-read idx from shared borrow for edit_index value
        if let Screen::ConditionsBuilder { pending_state, .. } = &app.screen {
            pending_state.selected().map(|i| (i, c))
        } else {
            None
        }
    }) else { return };

    let (attr, op_str, picker_idx, buf) = condition_to_prefill(&cond);

    // Find attr_idx in ATTRIBUTES (Step 1 pre-fill).
    let attr_idx = ATTRIBUTES.iter().position(|a| *a == attr).unwrap_or(0);

    // Find op_idx in operators_for(attr) (Step 2 pre-fill) — use position(),
    // NOT a hardcoded index, because operators_for() order is the source of truth.
    let op_idx = operators_for(attr)
        .iter()
        .position(|(w, _)| *w == op_str)
        .unwrap_or(0);

    // Phase 2: mutate screen state under mutable borrow.
    if let Screen::ConditionsBuilder {
        step,
        selected_attribute,
        selected_operator,
        buffer,
        edit_index,
        pending_focused,
        picker_state,
        ..
    } = &mut app.screen
    {
        *step = 1;
        *selected_attribute = Some(attr);
        *selected_operator = Some(op_str);
        *buffer = buf;
        *edit_index = Some(edit_i);
        *pending_focused = false;
        // Pre-select the attribute row so Step 1 opens on the right item.
        picker_state.select(Some(attr_idx));
        // Store op_idx as a hint for Step 2; see note below.
        let _ = op_idx; // used when navigating to Step 2
    }
}
```

**Note on op_idx:** The Step 2 `handle_conditions_step2` Enter handler transitions
to Step 3 and calls `picker_state.select(Some(0))` for the value picker. For the
pre-fill to work correctly at Step 2, `picker_state` must be set to `op_idx` when
entering Step 2. The `handle_conditions_step1` Enter arm (which advances to Step 2)
is the right place to call `picker_state.select(Some(op_idx))` when `edit_index.is_some()`.
Alternatively, set `picker_state.select(Some(op_idx))` immediately in the 'e' handler
if `step` starts at 1 — the Step 1 Enter arm will overwrite it when the user advances.
Read `handle_conditions_step1`'s Enter arm before deciding; the planner should inspect
lines ~2295–2340 in dispatch.rs.

---

#### Area 3: step-3 commit — replace vs push

**Analog:** two existing `pending.push(cond)` call sites:
- `handle_conditions_step3_text` Enter arm (lines 2498–2524)
- `handle_conditions_step3_select` Enter arm (lines 2576–2602)

**Existing push pattern** (lines 2508–2518, text variant — select is structurally
identical):
```rust
if let Screen::ConditionsBuilder {
    pending,
    pending_state,
    step,
    selected_attribute,
    selected_operator,
    buffer,
    picker_state,
    ..
} = &mut app.screen
{
    pending.push(cond);
    // Select the newly added condition in the pending list.
    pending_state.select(Some(pending.len() - 1));
    // Reset to Step 1 for the next condition (per D-05, Pitfall 4).
    *step = 1;
    *selected_attribute = None;
    *selected_operator = None;
    buffer.clear();
    picker_state.select(Some(0));
}
```

**Replacement pattern** — add `edit_index` to the destructure and replace the
`pending.push(cond)` + `pending_state.select(...)` block with an index-aware write.
Apply identically to both step3_text and step3_select:
```rust
if let Screen::ConditionsBuilder {
    pending,
    pending_state,
    step,
    selected_attribute,
    selected_operator,
    buffer,     // present in step3_text only; omit in step3_select destructure
    picker_state,
    edit_index, // <-- add to destructure
    ..
} = &mut app.screen
{
    // Replace or append depending on edit mode (SC-2: preserve index).
    match *edit_index {
        Some(i) if i < pending.len() => {
            pending[i] = cond;
            pending_state.select(Some(i));
            *edit_index = None;
        }
        _ => {
            pending.push(cond);
            pending_state.select(Some(pending.len() - 1));
        }
    }
    // Common reset: back to Step 1 for the next operation.
    *step = 1;
    *selected_attribute = None;
    *selected_operator = None;
    // buffer.clear() only in step3_text block; step3_select has no buffer.
    picker_state.select(Some(0));
}
```

---

#### Area 4: unit tests

**Analog:** existing `#[cfg(test)]` block (lines 2622–3075), specifically:
- `conditions_builder_esc_restores_form` (lines 3016–3074) — the canonical
  ConditionsBuilder test; copy its `make_test_app(screen)` setup pattern.
- `build_condition_classification_t3` (lines 2657–2664) — simple unit test with
  `assert!(cond.is_some())` + JSON content assertion.

**Test setup pattern** (lines 3031–3049):
```rust
let mut picker_state = ratatui::widgets::ListState::default();
picker_state.select(Some(0));
let screen = Screen::ConditionsBuilder {
    step: 1,
    selected_attribute: None,
    selected_operator: None,
    pending: vec![pending_condition.clone()],
    buffer: String::new(),
    pending_focused: false,
    pending_state: ratatui::widgets::ListState::default(),
    picker_state,
    caller: CallerScreen::PolicyCreate,
    form_snapshot: form_snapshot.clone(),
    edit_index: None,    // <-- include in all new test setups
};
let mut app = make_test_app(screen);
```

**Key event construction pattern** (line 3048):
```rust
let key = KeyEvent::new(KeyCode::Char('e'), crossterm::event::KeyModifiers::NONE);
```

**Tests to write** (per RESEARCH.md Wave 0 gap list):

1. `edit_opens_picker_prefilled` — construct a `ConditionsBuilder` with
   `pending_focused = true`, `pending_state` selecting index 0, and a known
   `pending[0]`. Call `handle_conditions_pending(&mut app, 'e' key, 1)`. Assert:
   `step == 1`, `selected_attribute == Some(expected_attr)`,
   `selected_operator == Some(expected_op)`, `edit_index == Some(0)`,
   `pending_focused == false`.

2. `edit_replace_preserves_index` — after 'e' pre-fills, simulate advancing through
   steps to commit (or call `handle_conditions_step3_select` directly with a modified
   `picker_state`). Assert: `pending.len()` unchanged, `pending[0]` is the new condition,
   `edit_index == None`.

3. `edit_cancel_preserves_condition` — after 'e' sets `edit_index = Some(0)`, call
   the Esc handler at Step 3. Assert: `pending[0]` is unchanged, step retreats to 2.

4. `condition_to_prefill_roundtrip` — for each of the 5 `PolicyCondition` variants,
   call `condition_to_prefill(&cond)` then `build_condition(attr, &op, picker_idx, &buf)`,
   and assert the resulting condition equals the original. Uses the same
   `use dlp_common::abac::*` imports as `build_condition_classification_t3`.

---

### `dlp-admin-cli/src/screens/render.rs` — two change areas

#### Area 1: destructure `edit_index` and pass to `draw_conditions_builder`

**Analog:** the existing `Screen::ConditionsBuilder { ... }` arm (lines 143–166):
```rust
Screen::ConditionsBuilder {
    step,
    selected_attribute,
    selected_operator,
    pending,
    buffer,
    pending_focused,
    pending_state,
    picker_state,
    ..       // <-- currently ignores edit_index; change this
} => {
    draw_conditions_builder(
        frame,
        area,
        *step,
        selected_attribute.as_ref(),
        selected_operator.as_deref(),
        pending,
        buffer,
        *pending_focused,
        pending_state,
        picker_state,
    );
}
```

**Pattern:** name `edit_index` explicitly in the destructure (remove from `..`), then
pass it as the final argument to `draw_conditions_builder`. All other parameters remain
in place — this is purely additive.

#### Area 2: `draw_conditions_builder` signature + title + hints

**Analog:** the existing function signature (lines 387–399) and modal title (line 416)
and hints bar (lines 542–549).

**Current signature** (lines 387–399):
```rust
#[allow(clippy::too_many_arguments)]
fn draw_conditions_builder(
    frame: &mut Frame,
    area: Rect,
    step: u8,
    selected_attribute: Option<&ConditionAttribute>,
    _selected_operator: Option<&str>,
    pending: &[dlp_common::abac::PolicyCondition],
    buffer: &str,
    pending_focused: bool,
    pending_state: &ListState,
    picker_state: &ListState,
)
```

**New parameter to append** (after `picker_state`):
```rust
    edit_index: Option<usize>,
```

**Current title** (line 416):
```rust
let modal_block = Block::default()
    .title(" Conditions Builder ")
    .borders(Borders::ALL);
```

**Pattern for conditional title:**
```rust
let title = if edit_index.is_some() {
    " Edit Condition "
} else {
    " Conditions Builder "
};
let modal_block = Block::default()
    .title(title)
    .borders(Borders::ALL);
```

**Current hints bar** (lines 542–549):
```rust
let hints = if pending_focused {
    "Up/Down Navigate  d: Delete  Tab: Switch to Picker  Esc: Close"
} else if is_member_of_step3 {
    "Type SID  Enter: Add  Esc: Back  Tab: Switch to Pending"
} else {
    "Up/Down Navigate  Enter: Select  Esc: Back/Close  Tab: Switch to Pending"
};
draw_hints(frame, modal_area, hints);
```

**Pattern for updated pending-focused hint** — add `e: edit` adjacent to `d: delete`:
```rust
"Up/Down Navigate  d: Delete  e: Edit  Tab: Switch to Picker  Esc: Close"
```

The picker hints (`is_member_of_step3` branch and default branch) may optionally read
`"Enter: Add"` → `"Enter: Save"` when `edit_index.is_some()`. The planner should decide
based on space; the title change alone satisfies the visual indicator requirement.

---

## Shared Patterns

### Two-phase read-then-mutate borrow pattern
**Source:** `dispatch.rs` lines 2141–2185 (`handle_conditions_builder`)
**Apply to:** the 'e' key handler in `handle_conditions_pending`

```rust
// Phase 1: shared borrow to snapshot scalars / clone data.
let snapshot = match &app.screen {
    Screen::ConditionsBuilder { field, .. } => field.clone(),
    _ => return,
};
// Phase 2: mutable borrow after shared is dropped.
if let Screen::ConditionsBuilder { field, .. } = &mut app.screen {
    *field = new_value;
}
```

### Exhaustive match on `ConditionAttribute`
**Source:** `dispatch.rs` `build_condition` (lines 2066–2116) and `operators_for` (lines 2022–2032)
**Apply to:** `condition_to_prefill` — every new match block must cover all five
variants without a catch-all `_` arm, per CLAUDE.md §9.10 ("exhaustive matching").

### `#[allow(clippy::too_many_arguments)]`
**Source:** `render.rs` line 386
**Apply to:** `draw_conditions_builder` after adding the `edit_index` parameter
(already present; confirm the attribute remains when the signature changes).

---

## No Analog Found

All three files have close analogs within themselves; no file lacks a codebase pattern.

---

## Metadata

**Analog search scope:** `dlp-admin-cli/src/app.rs`, `dlp-admin-cli/src/screens/dispatch.rs`, `dlp-admin-cli/src/screens/render.rs`
**Pattern extraction date:** 2026-04-21
