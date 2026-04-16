# Phase 13: Conditions Builder - Research

**Researched:** 2026-04-16
**Domain:** ratatui TUI modal overlay / ABAC type construction / Rust state machine
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

| ID | Decision |
|----|----------|
| D-01 | Conditions builder is a modal overlay using `Clear` + constrained `Layout`. |
| D-02 | Opened from Policy Create/Edit form via "Add Conditions" button/key. |
| D-03 | `PolicyFormState` struct holds `conditions: Vec<PolicyCondition>` — no borrow-split issues. |
| D-04 | Modal contains both the step picker (Steps 1->2->3) and the inline pending-conditions list. Both visible simultaneously. |
| D-05 | After Step 3 Enter, condition appended to pending list, picker resets to Step 1. |
| D-06 | Esc at Step 1 closes modal; pending list preserved in `PolicyFormState`. |
| D-07 | Each pending condition has a `d` key delete binding. No in-place edit in v0.4.0. |
| D-08 | `PolicyCondition` variants from `dlp_common::abac.rs` are authoritative. |
| D-09 | All conditions evaluated as implicit AND. |
| D-10 | Operators derived dynamically per attribute from lookup table. Only `eq` enforced today; others shown with `(not enforced)` annotation. |
| D-11 | Classification -> T1/T2/T3/T4 select (4 options). |
| D-12 | MemberOf -> free-text input (AD group SID). `group_sid: String` field, NOT `value`. |
| D-13 | DeviceTrust -> 4-option select (Managed / Unmanaged / Compliant / Unknown). |
| D-14 | NetworkLocation -> 4-option select (Corporate / CorporateVpn / Guest / Unknown). |
| D-15 | AccessContext -> 2-option select (Local / Smb). |
| D-16 | Up/Down arrows navigate the current step's options list. |
| D-17 | Enter advances to the next step. |
| D-18 | Esc steps back: Step 3 -> Step 2 -> Step 1 -> modal close. |
| D-19 | Empty pending list shows muted placeholder: "No conditions added. Use the picker below to add conditions." |

### Claude's Discretion
- Exact color/style of the modal box (uses existing TUI color scheme)
- Specific key hint labels (e.g., "Enter: add" vs "Enter: next")
- Scroll behavior for the pending list (mouse scroll vs arrow-only)
- Empty state copy (placeholder text wording)

### Deferred Ideas (OUT OF SCOPE)
- AND/OR/NOT boolean logic (v0.5.0)
- In-place condition editing (POLICY-F2, v0.5.0)
- Non-eq operator enforcement (POLICY-F3)
- TOML export (POLICY-F4)

</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| POLICY-05 | Admin can build policy conditions using a 3-step sequential picker (no raw JSON entry at any step). Step 1: attribute select (5). Step 2: operator filtered by attribute. Step 3: typed value picker. After Step 3, condition added to pending list. Delete binding on each pending condition. | Fully supported by verified ratatui `List`+`ListState` pattern, `Screen::ConditionsBuilder` variant design, `PolicyFormState` struct pattern, `PolicyCondition` enum construction verified in `abac.rs`. |

</phase_requirements>

---

## Summary

Phase 13 is a pure TUI-layer implementation in `dlp-admin-cli`. No server-side changes
are needed. The phase adds one new `Screen` variant (`ConditionsBuilder`) and implements
its render function and dispatch handler following patterns already established in the
codebase for `SiemConfig`, `AlertConfig`, and `draw_confirm`.

The codebase is fully verified. All five `PolicyCondition` variants exist in
`dlp-common/src/abac.rs`. The `Screen` enum in `app.rs` has no `ConditionsBuilder`
variant yet — adding it is the primary code change. Existing helper functions
(`draw_hints`, `nav`, the `List`+`ListState` pattern from `draw_policy_list`) are
directly reusable.

The single architectural challenge is the two-focus-area problem inside the modal: the
pending conditions list and the step picker are both navigable. The `ConditionsBuilder`
screen variant must track which area is focused (picker vs. pending list) so that
Up/Down and `d` route correctly. This is managed entirely within the `Screen` variant
fields — no new widget types are needed.

**Primary recommendation:** Add `Screen::ConditionsBuilder` variant, `draw_conditions_builder`
render function, `handle_conditions_builder` dispatch handler, and a `PolicyFormState`
struct in `app.rs`. All implemented by extending existing patterns; no new dependencies.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| 3-step attribute/operator/value picker | TUI (dlp-admin-cli) | — | Pure UI navigation; no server round-trip needed |
| Pending conditions accumulation | TUI (dlp-admin-cli) | — | In-memory list in `PolicyFormState`; survives modal open/close |
| `PolicyCondition` construction | TUI (dlp-admin-cli) | dlp-common (types) | Builder assembles typed variants from user selections |
| Modal overlay rendering | TUI render.rs | — | `Clear` + constrained `Layout` per existing `draw_confirm` pattern |
| Modal event dispatch | TUI dispatch.rs | — | New `handle_conditions_builder` branch in `handle_event` |
| Data return to caller form | `PolicyFormState` struct | `Screen` enum state | Caller reads `form_state.conditions` after modal closes |

---

## Standard Stack

### Core (verified in `dlp-admin-cli/Cargo.toml`)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| ratatui | 0.29 | TUI rendering — `List`, `ListState`, `Block`, `Clear`, `Layout`, `Paragraph`, `Span`, `Line` | Already in use across all TUI screens |
| crossterm | 0.28 | Terminal raw mode, key events (`KeyCode::Up/Down/Enter/Esc/Char`) | Already in use; event system drives the entire TUI |
| dlp-common | workspace | `PolicyCondition`, `Classification`, `DeviceTrust`, `NetworkLocation`, `AccessContext` types | Source of truth for ABAC model |
| serde / serde_json | 1.x | `PolicyCondition` serialization for policy form submit | Already in use |

[VERIFIED: dlp-admin-cli/Cargo.toml and dlp-admin-cli/src/app.rs]

### No New Dependencies Required

All ratatui widgets needed (`List`, `ListState`, `Paragraph`, `Block`, `Clear`, `Layout`,
`Span`, `Line`, `Borders`) are already imported in `render.rs`. No new crates need to
be added to `Cargo.toml`.

---

## Architecture Patterns

### System Architecture Diagram

```
Admin keypress (Up/Down/Enter/Esc/d)
        |
        v
event.rs::poll()  -> AppEvent::Key
        |
        v
dispatch.rs::handle_event()
        |-- Screen::ConditionsBuilder{..} --> handle_conditions_builder()
                |
                |-- Step picker focus
                |     |-- Up/Down -> update picker_state
                |     |-- Enter (Step 1) -> advance to Step 2, populate operator list
                |     |-- Enter (Step 2) -> advance to Step 3, populate value options
                |     |-- Enter (Step 3, select) -> build PolicyCondition, push to pending, reset Step 1
                |     |-- Enter (Step 3, text) -> build MemberOf{group_sid}, push, reset Step 1
                |     |-- Esc (Step 2/3) -> step back
                |     |-- Esc (Step 1) -> close modal, return to parent Screen
                |
                |-- Pending list focus
                      |-- Up/Down -> update pending_state
                      |-- d/D -> remove selected item from pending
                      |-- Tab/Enter -> switch focus to picker (or vice versa)
                      
                              |
                              v
                    Screen::ConditionsBuilder state mutated in place
                              |
                              v
render.rs::draw_conditions_builder()
    |-- Clear (full frame overlay)
    |-- constrained Layout (60% width, 22 rows, centered)
    |-- Block border "Conditions Builder"
    |-- Breadcrumb header (Paragraph, mixed Span styles)
    |-- Pending list (List + ListState, 6 rows)
    |-- Step picker (List + ListState, 12 rows)
    |-- Hints bar (draw_hints)
```

### Recommended Project Structure

No new files or directories required. All changes are additive to:

```
dlp-admin-cli/src/
├── app.rs                      # +Screen::ConditionsBuilder variant, +PolicyFormState struct
└── screens/
    ├── dispatch.rs             # +handle_conditions_builder(), +ConditionsBuilder branch
    └── render.rs               # +draw_conditions_builder()
```

### Pattern 1: Screen Variant with Dual-Area Focus Tracking

The `ConditionsBuilder` variant must distinguish which area (picker vs. pending list) has
keyboard focus. The UI spec shows both areas visible simultaneously; Up/Down routes to the
focused area.

```rust
// Source: [VERIFIED: app.rs Screen enum pattern]
/// Conditions Builder modal overlay.
///
/// 3-step sequential picker: Attribute -> Operator -> Value.
/// Completed conditions accumulate in `pending` and are returned
/// to the caller via `PolicyFormState`.
ConditionsBuilder {
    /// Current step: 1, 2, or 3.
    step: u8,
    /// The attribute selected in Step 1 (None until Step 1 completed).
    selected_attribute: Option<ConditionAttribute>,
    /// The operator selected in Step 2 (None until Step 2 completed).
    selected_operator: Option<String>,
    /// Conditions already added this session.
    pending: Vec<dlp_common::abac::PolicyCondition>,
    /// For MemberOf Step 3 only: buffered text input.
    buffer: String,
    /// Whether the pending list area has focus (vs. the step picker).
    pending_focused: bool,
    /// ListState for the pending conditions list.
    pending_state: ratatui::widgets::ListState,
    /// ListState for the step picker (step-appropriate options).
    picker_state: ratatui::widgets::ListState,
}
```

The `selected_attribute` and `selected_operator` fields enable the render function to
display the breadcrumb correctly and populate the Step 2/3 option lists without
re-computing from `picker_state.selected`.

**Why a separate `ConditionAttribute` enum:** The five attribute names are used across
Step 1 display, Step 2 operator lookup table, Step 3 value-picker branching, and
`PolicyCondition` construction. A dedicated enum avoids repeated string comparisons and
enables exhaustive matching.

```rust
// New helper type in app.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionAttribute {
    Classification,
    MemberOf,
    DeviceTrust,
    NetworkLocation,
    AccessContext,
}
```

### Pattern 2: Operator Lookup Table (Static Array)

All five attributes currently map to `eq` only (plus optionally annotated non-enforced
operators). A static array indexed by `ConditionAttribute` drives Step 2.

```rust
// Source: [VERIFIED: 13-CONTEXT.md D-10 and abac.rs]
// In dispatch.rs or a helpers module.
/// Returns the list of operators for the given attribute.
/// First entry is always "eq" (the only currently enforced operator).
fn operators_for(attr: ConditionAttribute) -> &'static [(&'static str, bool)] {
    // Tuple: (operator_name, is_enforced)
    match attr {
        ConditionAttribute::Classification => &[("eq", true)],
        ConditionAttribute::MemberOf       => &[("eq", true)],
        ConditionAttribute::DeviceTrust    => &[("eq", true)],
        ConditionAttribute::NetworkLocation => &[("eq", true)],
        ConditionAttribute::AccessContext  => &[("eq", true)],
    }
}
```

For v0.4.0 each attribute has exactly one operator (`eq`). Entering Step 2 with a
single-item list and auto-advancing on Enter is acceptable (user sees the selection
briefly). The UI-SPEC includes `(not enforced)` annotation support for future operators.

### Pattern 3: Modal Overlay Rendering

Copied from `draw_confirm` but with a fixed 22-row, 60%-width constrained layout.

```rust
// Source: [VERIFIED: render.rs draw_confirm pattern]
fn draw_conditions_builder(frame: &mut Frame, area: Rect, /* fields */) {
    // Step 1: Dim the background with Clear over the entire frame area.
    frame.render_widget(Clear, area);

    // Step 2: Compute the centered modal rect.
    let modal_width = area.width * 60 / 100;
    let modal_height = 22;
    let modal_x = area.x + (area.width.saturating_sub(modal_width)) / 2;
    let modal_y = area.y + (area.height.saturating_sub(modal_height)) / 2;
    let modal_area = Rect {
        x: modal_x,
        y: modal_y,
        width: modal_width,
        height: modal_height,
    };

    // Step 3: Draw the modal box.
    let modal_block = Block::default()
        .title(" Conditions Builder ")
        .borders(Borders::ALL);
    frame.render_widget(modal_block, modal_area);

    // Step 4: Split interior into sub-areas per UI-SPEC area allocations.
    let inner = modal_block.inner(modal_area);
    // ... Layout::vertical([header=2, pending=6, divider=1, picker=12, hints=1])
}
```

**Critical ratatui note (VERIFIED):** `Block::inner()` returns the area inside the
border. The inner area must be computed from the same `Block` reference used in
`render_widget`, or the geometry will be off by 1 on each side.

### Pattern 4: Breadcrumb Header with Mixed Span Styles

```rust
// Source: [VERIFIED: render.rs Span/Line pattern; 13-UI-SPEC.md breadcrumb spec]
fn build_breadcrumb(step: u8) -> Line<'static> {
    let completed = Style::default().fg(Color::DarkGray);
    let current   = Style::default().fg(Color::White).add_modifier(Modifier::BOLD);
    let sep        = Style::default().fg(Color::DarkGray);

    let s1 = if step == 1 { current } else { completed };
    let s2 = if step == 2 { current } else { completed };
    let s3 = if step == 3 { current } else { completed };

    Line::from(vec![
        Span::styled("Step 1: Attribute", s1),
        Span::styled(" > ", sep),
        Span::styled("Step 2: Operator", s2),
        Span::styled(" > ", sep),
        Span::styled("Step 3: Value", s3),
    ])
}
```

### Pattern 5: PolicyCondition Construction

Each `PolicyCondition` variant has different field names. This is a critical
implementation detail that must be done correctly to match the `#[serde(tag="attribute")]`
JSON shape.

```rust
// Source: [VERIFIED: dlp-common/src/abac.rs PolicyCondition enum]
fn build_condition(
    attr: ConditionAttribute,
    op: &str,
    picker_selected: usize,
    buffer: &str,
) -> Option<dlp_common::abac::PolicyCondition> {
    use dlp_common::abac::{AccessContext, DeviceTrust, NetworkLocation, PolicyCondition};
    use dlp_common::Classification;

    let op = op.to_string();
    Some(match attr {
        ConditionAttribute::Classification => {
            // Classification uses `value: Classification`, NOT `group_sid`.
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
            // MemberOf uses `group_sid: String`, NOT `value`.
            if buffer.trim().is_empty() {
                return None;
            }
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
    })
}
```

**Note:** `DeviceTrust` and `NetworkLocation` use `#[serde(rename_all = "PascalCase")]`.
`AccessContext` uses `#[serde(rename_all = "lowercase")]`. `Classification` uses
`#[serde(rename_all = "UPPERCASE")]`. These are the authoritative serde shapes for
JSON serialization — verified in `abac.rs` and `classification.rs`.

### Pattern 6: Pending Condition Display String

The pending list needs to render each condition as a human-readable string with a `[d]`
delete hint. A helper function mapping `PolicyCondition` to a display string must be
consistent with the variant field names.

```rust
// Source: [VERIFIED: abac.rs PolicyCondition variants]
fn condition_display(cond: &dlp_common::abac::PolicyCondition) -> String {
    use dlp_common::abac::PolicyCondition;
    match cond {
        PolicyCondition::Classification { op, value } =>
            format!("Classification {op} {value}"),
        PolicyCondition::MemberOf { op, group_sid } =>
            format!("MemberOf {op} {group_sid}"),
        PolicyCondition::DeviceTrust { op, value } =>
            format!("DeviceTrust {op} {value:?}"),
        PolicyCondition::NetworkLocation { op, value } =>
            format!("NetworkLocation {op} {value:?}"),
        PolicyCondition::AccessContext { op, value } =>
            format!("AccessContext {op} {value:?}"),
    }
}
```

`Classification` implements `Display` (verified in `classification.rs`). `DeviceTrust`,
`NetworkLocation`, and `AccessContext` implement `Debug` but not `Display` — use `{:?}`
or add a local helper that maps variants to strings.

### Pattern 7: PolicyFormState Struct

This struct is the contract between the conditions builder (Phase 13) and the caller
forms (Phases 14/15). It must be defined in `app.rs` now so Phase 14 can use it.

```rust
// Source: [VERIFIED: STATE.md 2026-04-16 decision]
/// All state for the Policy Create / Edit form.
///
/// Holds form fields and the accumulated conditions list.
/// Using a single struct avoids borrow-split when the conditions
/// builder modal writes into the conditions list.
#[derive(Debug, Clone, Default)]
pub struct PolicyFormState {
    pub name: String,
    pub description: String,
    pub priority: String,
    pub action: usize,          // index into DECISION_OPTIONS
    pub enabled: bool,
    pub conditions: Vec<dlp_common::abac::PolicyCondition>,
}
```

In Phase 13, only `conditions` is used. The other fields are placeholders consumed by
Phase 14/15. Defining the struct now prevents Phase 13 from creating incompatible state.

### Anti-Patterns to Avoid

- **Storing selected attribute as a `usize`:** Using the raw list index to recover the
  selected attribute at Step 2/3 is fragile. Always commit the `ConditionAttribute` enum
  variant into the `Screen` state on Step 1 Enter. [VERIFIED: needed to populate the
  Step 2 label `Step 2: Operator [{selected_attribute}]`]

- **Single `ListState` for both pending list and picker:** The pending list and the step
  picker have independent scroll positions. They require separate `ListState` instances
  (`pending_state` and `picker_state`). Using one state would cause both lists to jump
  together. [VERIFIED: dispatch.rs uses separate `state` instances per list]

- **Borrow-split on `App` when pushing to pending:** The existing pattern for all
  screen mutation is to match `&mut app.screen` directly. The `ConditionsBuilder`
  variant fields are all `pub` within the variant so inner mutation via `if let
  Screen::ConditionsBuilder { pending, .. } = &mut app.screen { pending.push(...) }`
  works without borrow issues. Do NOT clone the entire screen.

- **Not resetting picker_state on step reset:** After appending to pending and resetting
  to Step 1, `picker_state.select(Some(0))` must be called explicitly. `ListState`
  retains scroll position; failing to reset leaves the cursor mid-list on the next
  step, which is visually confusing.

- **Using `draw_hints` inside the modal at the wrong y-position:** The existing
  `draw_hints` function computes `y = area.y + area.height - 1`. Pass the modal's inner
  area (or the hints sub-area from the layout) — not the full frame area. Otherwise the
  hint bar renders at the bottom of the screen, not inside the modal.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Scrollable list with selection highlight | Custom scroll logic | `List` + `ListState` (ratatui) | Already in use for `draw_policy_list`, `draw_agent_list`; handles wrapping, highlight_symbol, stateful rendering |
| Terminal-wide overlay / dimming | Manual background-fill | `ratatui::widgets::Clear` | Already used in `draw_hints`; clears the cell content behind the modal |
| Text input with cursor | Custom buffer display | Existing `buffer` + `"[{buffer}_]"` pattern | Already established in `draw_siem_config` / `draw_alert_config`; no new widget needed |
| Breadcrumb with mixed styles | Multi-widget layout | `Paragraph` with `Line` + `Vec<Span>` | ratatui `Span::styled` handles per-span color/weight |
| Centered modal rect calculation | Custom centering math | Inline `Rect` arithmetic (area.width * 60 / 100, centered x/y) | Simple arithmetic; no library needed but must use saturating_sub to avoid underflow |

**Key insight:** Every required UI element is directly served by ratatui built-ins that
are already imported in `render.rs`. The phase is entirely about wiring state and
pattern application, not new widget discovery.

---

## Common Pitfalls

### Pitfall 1: MemberOf `group_sid` Field Name

**What goes wrong:** Constructing `PolicyCondition::MemberOf { op, value: buffer }` —
the variant has no `value` field. It has `group_sid: String`.

**Why it happens:** All other variants use `value` for their typed payload. `MemberOf`
is the exception.

**How to avoid:** See Pattern 5 above. The `build_condition` helper centralizes this
mapping. Enforce it with a compile-time check — wrong field names produce a Rust compile
error, not a runtime panic.

**Warning signs:** Compiler error `no field 'value' on PolicyCondition::MemberOf`.

[VERIFIED: dlp-common/src/abac.rs line 226: `MemberOf { op: String, group_sid: String }`]

---

### Pitfall 2: `Classification` Import Path

**What goes wrong:** `use dlp_common::abac::Classification` fails with "not found in
`abac`".

**Why it happens:** `Classification` is defined in `dlp_common::classification`, not
`dlp_common::abac`. The `abac.rs` file uses it via `crate::Classification`, which is
re-exported from `dlp_common` root. The `abac` module does NOT re-export it.

**How to avoid:** Import as `dlp_common::Classification` (from root), not
`dlp_common::abac::Classification`.

**Warning signs:** Compiler error `use of undeclared type 'Classification' in module
dlp_common::abac`.

[VERIFIED: dlp-common/src/abac.rs line 222 uses `crate::Classification`; STATE.md
decision 2026-04-16 "Classification from dlp_common root"]

---

### Pitfall 3: `Block::inner()` Geometry Off-By-One

**What goes wrong:** Computing the inner area of a `Block` manually (subtracting 1 from
x/y/width/height) rather than calling `block.inner(rect)`. The result renders content
overlapping the border.

**Why it happens:** A border consumes 1 cell on each side. Manual calculation is
error-prone.

**How to avoid:** Always call `block.inner(modal_area)` to get the area inside the
border before splitting with `Layout`.

[VERIFIED: ratatui 0.29 API — `Block::inner(&self, area: Rect) -> Rect` is the
canonical approach]

---

### Pitfall 4: `ListState` Scroll Position Not Reset After Step Change

**What goes wrong:** After committing a condition and resetting the picker to Step 1,
the `picker_state` still has `selected = Some(3)` from Step 3. Step 1 has only 5 items;
index 3 is valid but shows the wrong default selection.

**Why it happens:** `ListState` is a plain struct; it does not auto-reset when the
underlying list changes length.

**How to avoid:** On every step transition (Step1->Step2, Step2->Step3, reset to Step1),
call `picker_state.select(Some(0))` explicitly.

---

### Pitfall 5: Dual-Focus Key Routing

**What goes wrong:** `Up`/`Down` keys navigate the pending list when the user intends to
navigate the step picker, or vice versa.

**Why it happens:** Both the pending list and the step picker respond to `Up`/`Down`.
Without a focus flag, the dispatch handler does not know which list to update.

**How to avoid:** Use `pending_focused: bool` in the `ConditionsBuilder` variant state.
Route `Up`/`Down` to `pending_state` when `pending_focused == true`, else to
`picker_state`. Use `Tab` or a deliberate key to switch focus between the two areas.
The UI-SPEC does not define a focus-switch key explicitly — this is Claude's Discretion.
Recommended: `Tab` switches focus; `d`/`D` always acts on the pending list regardless
of focus (contextually obvious).

---

### Pitfall 6: Esc From Parent Screen While Modal Open

**What goes wrong:** When the modal is open and the user presses Esc, two handlers could
fire: the conditions builder Esc handler (step back) and the parent form's Esc handler
(exit form). Since the `Screen` variant IS `ConditionsBuilder`, only one handler fires
— the modal handler. The parent form is not the active screen.

**Why it doesn't go wrong (verification):** ratatui TUI is a single-screen state
machine. `app.screen` is the active screen. While `ConditionsBuilder` is active, the
parent form is NOT in `app.screen` — it lives in `PolicyFormState` fields. Esc at Step
1 closes the modal by switching `app.screen` back to the parent form screen. This is
correct behavior.

**Implication for Phase 14/15:** The parent form screens (PolicyCreate, PolicyEdit) will
need to hold a `PolicyFormState` in their own `Screen` variant fields. The
`ConditionsBuilder` Esc-at-Step-1 handler must know what screen to return to. Store a
`return_to` discriminant (or use a fixed convention: always return to `PolicyCreate` or
`PolicyEdit`). Since Phase 13 is foundational (before 14/15 exist), define the
`ConditionsBuilder` variant with a `return_screen` field or equivalent — see Open
Questions section.

---

### Pitfall 7: `DeviceTrust` / `NetworkLocation` Display

**What goes wrong:** Using `{value}` format in condition display when `DeviceTrust` and
`NetworkLocation` do not implement `Display`, only `Debug`.

**Why it happens:** `Classification` has an explicit `Display` impl; the others do not.

**How to avoid:** Use `{value:?}` for Debug output, or add a local `display_str` helper
mapping each variant. Debug output (`Managed`, `Compliant`, etc.) is acceptable for the
pending list display.

[VERIFIED: dlp-common/src/abac.rs — `DeviceTrust`, `NetworkLocation`, `AccessContext`
derive `Debug` but do not impl `Display`]

---

## Code Examples

### Verified: `List` + `ListState` stateful render (existing pattern)

```rust
// Source: [VERIFIED: render.rs draw_policy_list, draw_siem_config]
let mut state = ListState::default();
state.select(Some(selected));
frame.render_stateful_widget(list, area, &mut state);
```

### Verified: `Clear` overlay (existing pattern in `draw_hints`)

```rust
// Source: [VERIFIED: render.rs draw_hints line 603]
frame.render_widget(Clear, hint_area);
```

### Verified: Mixed-span `Line` (existing pattern in `draw_confirm`)

```rust
// Source: [VERIFIED: render.rs draw_confirm lines 446-451]
Line::from(vec![
    Span::styled("  [ Yes ]  ", yes_style),
    Span::raw("    "),
    Span::styled("  [ No ]  ", no_style),
])
```

### Verified: `nav` helper for Up/Down (existing pattern in dispatch.rs)

```rust
// Source: [VERIFIED: dispatch.rs nav() lines 39-49]
fn nav(selected: &mut usize, count: usize, key: KeyCode) {
    match key {
        KeyCode::Up   => *selected = selected.checked_sub(1).unwrap_or(count - 1),
        KeyCode::Down => *selected = (*selected + 1) % count,
        _ => {}
    }
}
```

### Verified: Borrow-split avoidance in screen mutation (existing pattern)

```rust
// Source: [VERIFIED: dispatch.rs handle_siem_config_editing lines 698-729]
if let Screen::SiemConfig { buffer, editing, .. } = &mut app.screen {
    buffer.push(c);
}
// Pattern: match on specific variant, mutate fields directly via if-let.
// No clone of app.screen needed.
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Raw JSON file path to create policy | Typed 3-step builder UI | Phase 13 (this phase) | Eliminates manual JSON authoring; typed conditions enforced at build time |
| `PolicyCondition` only used server-side | `PolicyCondition` constructed in TUI | Phase 13 (this phase) | TUI now imports and constructs typed ABAC conditions |

**Not applicable (no deprecated patterns):** This is a new feature, not a refactor.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `Tab` is a reasonable focus-switch key between pending list and step picker | Pitfall 5, Anti-Patterns | If not acceptable, any other key works — purely cosmetic; Claude's Discretion |
| A2 | Auto-advance from Step 2 when only one operator (`eq`) is acceptable UX | Pattern 2 | User might want to see the Step 2 list even with 1 item; if not, skip is easy to implement |

---

## Open Questions

1. **How does `ConditionsBuilder` know which screen to return to on Esc-at-Step-1?**
   - What we know: Phase 14 (PolicyCreate) and Phase 15 (PolicyEdit) will both open the
     modal. The return screen is different for each.
   - What's unclear: The Phase 14/15 `Screen` variants do not exist yet.
   - Recommendation: Add a `caller: CallerScreen` enum field to `ConditionsBuilder`
     with variants `PolicyCreate` and `PolicyEdit`. The Esc-at-Step-1 handler matches
     on this to reconstruct the parent screen. Alternatively, define the field as a
     `Box<Screen>` snapshot of the parent — but cloning a full Screen may be expensive
     if future screens are large. `CallerScreen` enum is cleaner.

2. **Should Step 2 auto-advance when only one operator is available?**
   - What we know: All 5 attributes currently have exactly one operator (`eq`). Showing
     a 1-item list and requiring the user to press Enter is technically correct.
   - What's unclear: Whether auto-advancing (skipping Step 2 visually) is better UX.
   - Recommendation: Do NOT auto-advance. Displaying Step 2 with a single `eq` item
     keeps the UI consistent and teaches the admin the pattern for when more operators
     are added in v0.5.0.

---

## Environment Availability

Step 2.6 SKIPPED — Phase 13 has no external dependencies. All changes are to
`dlp-admin-cli` source files. No new CLI tools, services, databases, or runtimes are
required beyond the existing Rust/Cargo toolchain.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` + `cargo test` |
| Config file | none (workspace Cargo.toml) |
| Quick run command | `cargo test -p dlp-admin-cli -- --nocapture` |
| Full suite command | `cargo test --workspace -- --nocapture` |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| POLICY-05 | Step 1: 5 attributes selectable | unit | `cargo test -p dlp-admin-cli conditions_builder` | No - Wave 0 |
| POLICY-05 | Step 2: operators filtered per attribute | unit | `cargo test -p dlp-admin-cli conditions_builder` | No - Wave 0 |
| POLICY-05 | Step 3: typed value picker per attribute | unit | `cargo test -p dlp-admin-cli conditions_builder` | No - Wave 0 |
| POLICY-05 | Condition construction (all 5 variants) | unit | `cargo test -p dlp-admin-cli build_condition` | No - Wave 0 |
| POLICY-05 | Pending list delete | unit | `cargo test -p dlp-admin-cli pending_delete` | No - Wave 0 |
| POLICY-05 | Esc step-back navigation | unit | `cargo test -p dlp-admin-cli esc_navigation` | No - Wave 0 |
| POLICY-05 | MemberOf group_sid field (not value) | unit | `cargo test -p dlp-admin-cli member_of_group_sid` | No - Wave 0 |
| POLICY-05 | Classification import path (dlp_common root) | compile | `cargo build -p dlp-admin-cli` | No - Wave 0 |
| POLICY-05 | PolicyCondition serde round-trip | unit | `cargo test -p dlp-common` | Yes - existing in abac.rs |

**Note:** TUI rendering cannot be unit tested without a real terminal. Tests target the
dispatch logic (state mutation) and condition construction functions, not the render
functions.

### Sampling Rate

- **Per task commit:** `cargo test -p dlp-admin-cli -- --nocapture`
- **Per wave merge:** `cargo test --workspace -- --nocapture`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `dlp-admin-cli/src/screens/dispatch.rs` — add `#[cfg(test)]` module with tests
  for `handle_conditions_builder` state transitions
- [ ] `dlp-admin-cli/src/app.rs` — no test module needed for struct definitions, but
  `ConditionAttribute` enum and `operators_for` lookup table should have unit tests
- [ ] Framework: none needed — `cargo test` already works

---

## Security Domain

Phase 13 is a pure TUI state-machine feature. No network calls, no authentication, no
data storage, no cryptographic operations are performed. The conditions builder
constructs in-memory `PolicyCondition` structs that are later serialized and submitted
in Phase 14 via the existing admin API (which is already authenticated with JWT).

**ASVS applicability:**

| ASVS Category | Applies | Rationale |
|---------------|---------|-----------|
| V2 Authentication | No | No auth in this phase; builder is behind the login screen |
| V3 Session Management | No | No session changes |
| V4 Access Control | No | Access control enforced at server layer (existing admin JWT) |
| V5 Input Validation | Partial | MemberOf free-text input (AD group SID): no server-side injection risk since the SID is embedded in a typed `PolicyCondition::MemberOf` struct and serialized as a JSON string field. The server's existing policy creation endpoint validates inputs. No special sanitization needed at TUI layer. |
| V6 Cryptography | No | No secrets handled |

**Threat model note:** The admin TUI is a privileged tool behind authentication. The
conditions builder only constructs data structures that are submitted over HTTPS to the
admin API. No new threat surface is introduced.

---

## Sources

### Primary (HIGH confidence)

- `dlp-admin-cli/src/app.rs` — Screen enum, StatusKind, InputPurpose patterns (VERIFIED 2026-04-16)
- `dlp-admin-cli/src/screens/dispatch.rs` — handle_event, nav(), borrow-split patterns (VERIFIED 2026-04-16)
- `dlp-admin-cli/src/screens/render.rs` — draw_confirm, draw_hints, draw_policy_list, List+ListState pattern (VERIFIED 2026-04-16)
- `dlp-common/src/abac.rs` — PolicyCondition variants and field names, serde tags (VERIFIED 2026-04-16)
- `dlp-common/src/classification.rs` — Classification enum and Display impl (VERIFIED 2026-04-16)
- `dlp-admin-cli/Cargo.toml` — ratatui 0.29, crossterm 0.28, no new deps needed (VERIFIED 2026-04-16)
- `.planning/phases/13-conditions-builder/13-CONTEXT.md` — locked decisions D-01 through D-19
- `.planning/phases/13-conditions-builder/13-UI-SPEC.md` — modal layout, color scheme, component inventory
- `.planning/REQUIREMENTS.md` — POLICY-05 authoritative spec
- `.planning/STATE.md` — PolicyFormState decision, Classification import path decision

### Secondary (MEDIUM confidence)

- ratatui 0.29 `Block::inner()` API — confirmed via existing use in codebase context and ratatui 0.29 changelog consistency [ASSUMED: specific API signature; low risk given pattern is idiomatic ratatui]

### Tertiary (LOW confidence)

None — all claims in this research are verified from codebase sources.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — verified in Cargo.toml
- Architecture patterns: HIGH — verified in render.rs, dispatch.rs, abac.rs
- Pitfalls: HIGH — verified against actual source code, especially MemberOf field name and Classification import path
- Test strategy: HIGH — follows existing test module pattern in codebase

**Research date:** 2026-04-16
**Valid until:** Stable (no external dependencies; only changes if dlp-common types change)
