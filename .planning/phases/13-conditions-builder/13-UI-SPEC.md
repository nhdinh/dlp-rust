---
phase: 13
slug: conditions-builder
status: draft
shadcn_initialized: false
preset: none
created: "2026-04-16"
updated: "2026-04-16"
---

# Phase 13 — UI Design Contract

> Visual and interaction contract for the Conditions Builder modal overlay.
> Originally approved 2026-04-16. Reset to draft for re-verification after
> codebase scan on 2026-04-16 confirmed all component inventory entries and
> Screen enum definition are correct forward-looking contracts (not yet
> implemented — Phase 13 is pending).

---

## Design System

| Property | Value |
|----------|-------|
| Tool | ratatui + crossterm |
| Preset | none |
| Component library | ratatui built-ins (Block, List, ListState, Paragraph, Table, Layout, Clear) |
| Icon library | none (text-based TUI) |
| Font | terminal default (monospace) |

---

## Layout Structure

The conditions builder renders as a **modal overlay** drawn with `ratatui::widgets::Clear` (full-frame overlay) then a constrained `Layout` centered box.

```
+- Conditions Builder --------------------------------------------+
| Step 1: Attribute > Step 2: Operator > ...                     |  <- header (breadcrumb)
| -------------------------------------------------------------- |
| Pending Conditions (6 rows, scrollable):                       |
|   > Classification = T3                              [d]       |
|     Classification = T2                              [d]       |
|     DeviceTrust = Managed                            [d]       |
| -------------------------------------------------------------- |
| Step 3 of 3 -- Value                                           |  <- step indicator
|   > T1: Public                                                 |
|     T2: Internal                                               |
|     T3: Confidential                                           |
|     T4: Restricted                                             |
| -------------------------------------------------------------- |
| Up/Down Navigate  Enter: Add  Esc: Back/Close                  |  <- hints bar (DarkGray)
+----------------------------------------------------------------+
```

### Modal Dimensions

- **Width:** 60% of terminal width, centered.
- **Height:** fixed at 22 rows, centered vertically.
- **Horizontal padding:** 2 cells on each side inside the box.
- **Vertical padding:** 1 row inside the box top/bottom.

The modal is rendered with a `Block` with `Borders::ALL` and title `" Conditions Builder "`.

### Area Allocations (22-row modal)

| Area | Rows | Content |
|------|------|---------|
| Header | 2 | Step breadcrumb |
| Pending list | 6 | Scrollable conditions list (fixed 6-row allocation, scrollable) |
| Divider | 1 | spacer line |
| Step picker | 12 | Steps 1-3 content |
| Hints bar | 1 | Key navigation hints |

### Step Picker Sub-areas (12 rows)

| Area | Rows | Content |
|------|------|---------|
| Step label | 1 | "Step 3 of 3 -- Value  [Classification]" |
| Options list | 9 | 5 attributes or operators or values |
| Spacer | 2 | alignment padding |

### Breadcrumb Header

The header (2 rows) shows the full step trail using mixed-style `Span` rendering:

```
Step 1: Attribute > Step 2: Operator > Step 3: Value
```

- **Completed steps** -> `Color::DarkGray`, regular weight
- **Current step** -> `Color::White`, `Modifier::BOLD`
- **Separator (`>`)** -> `Color::DarkGray`, regular weight

Example at Step 2:
```
Step 1: Attribute > Step 2: Operator > Step 3: Value
(DarkGray)          (White+BOLD)      (DarkGray)
```

---

## Spacing Scale

Terminal cell-based spacing -- 1 unit = 1 character cell.

| Token | Value | Usage |
|-------|-------|-------|
| xs | 1 cell | Inline symbol spacing |
| sm | 2 cells | Label-to-value separator (`: `) |
| md | 4 cells | List item left indent (for `> ` highlight symbol) |
| lg | 8 cells | Horizontal section padding inside modal box |
| xl | 12 cells | Modal box horizontal margin from screen edge |
| 2xl | 16 cells | Modal box vertical margin from screen edge |

No exceptions.

---

## Typography

| Role | Size | Weight | Line Height |
|------|------|--------|-------------|
| Body / Options | terminal default (monospace) | regular | 1 |
| Heading (block title) | terminal default | `Modifier::BOLD` | 1 |
| Step label (active) | terminal default | `Modifier::BOLD` | 1 |
| Step label (completed) | terminal default | regular | 1 |
| Breadcrumb (current) | terminal default | `Modifier::BOLD` | 1 |
| Breadcrumb (completed) | terminal default | regular | 1 |
| Key hints | terminal default | regular | 1 |
| Pending list item | terminal default | regular | 1 |
| Not-enforced annotation | terminal default | regular | 1 |

ratatui renders with the terminal's default monospace font. No font size overrides. All emphasis via `Modifier::BOLD` or `Color`.

---

## Color

All values are `ratatui::style::Color` enum variants.

| Role | Value | Usage |
|------|-------|-------|
| Default text | `Color::White` | Non-selected list items, block title |
| Selected item fg | `Color::Black` | Text on selected/highlighted row |
| Selected item bg | `Color::Cyan` | Currently highlighted option row |
| Selected modifier | `Modifier::BOLD` | Bold on selected row |
| Completed breadcrumb steps | `Color::DarkGray` | Past steps in the breadcrumb trail |
| Hints text | `Color::DarkGray` | Key hint bar at bottom |
| Empty state text | `Color::DarkGray` | Pending list placeholder |
| Pending list highlight | `Color::Cyan` bg + `Color::Black` fg + `Modifier::BOLD` | Currently focused pending item |
| Confirm button bg | `Color::Green` | Yes button in `draw_confirm` |
| Delete button bg | `Color::Red` | No button / delete confirm |
| Status: Info | `Color::Cyan` | Status bar info |
| Status: Success | `Color::Green` | Status bar success |
| Status: Error | `Color::Red` | Status bar error |

**Existing TUI style in use (from render.rs, verified 2026-04-16):**
```rust
// List selection highlight (all existing TUI screens: draw_menu, draw_siem_config,
// draw_alert_config, draw_policy_list, draw_agent_list)
Style::default()
    .fg(Color::Black)
    .bg(Color::Cyan)
    .add_modifier(Modifier::BOLD)

// Hints bar (draw_hints function)
Style::default().fg(Color::DarkGray)

// draw_confirm: Yes button
Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)

// draw_confirm: No button
Style::default().fg(Color::Black).bg(Color::Red).add_modifier(Modifier::BOLD)
```

**Design decisions confirmed (Q1-Q4):**
- **Q1 Modal dimensions:** 60% terminal width, 22 rows, vertically centered -- CONFIRMED
- **Q2 Selected highlight:** Black + Cyan + BOLD (matches all existing TUI lists) -- CONFIRMED
- **Q3 Step format:** Breadcrumb with bold current step, DarkGray completed steps -- CONFIRMED
- **Q4 Pending list height:** Fixed 6 rows above step picker, scrollable -- CONFIRMED

---

## Step Picker -- Visual States

### Breadcrumb (Header, 2 rows)

Rendered as a `Paragraph` with a single `Line` containing mixed `Span` styles.

Example at Step 2:

```
Step 1: Attribute > Step 2: Operator > Step 3: Value
```

| Span | Color | Weight |
|------|-------|--------|
| `Step 1: Attribute` | `Color::DarkGray` | regular |
| ` > ` | `Color::DarkGray` | regular |
| `Step 2: Operator` | `Color::White` | `Modifier::BOLD` |
| ` > ` | `Color::DarkGray` | regular |
| `Step 3: Value` | `Color::DarkGray` | regular |

### Step 1: Attribute Selection

```
Step 1: Attribute
---------------------------------------------------------
  > Classification
    MemberOf
    DeviceTrust
    NetworkLocation
    AccessContext
```

Items rendered as `List` with `highlight_symbol("> ")`. Selected item: `Color::Black` fg + `Color::Cyan` bg + `Modifier::BOLD`.

### Step 2: Operator Selection

Operators derived per attribute from lookup table. All 5 attributes currently only support `eq` (per ABAC engine). Operators not yet enforced shown with annotation `(not enforced)` in `Color::DarkGray`.

```
Step 2: Operator  [Classification]
---------------------------------------------------------
  > eq
    ne  (not enforced)
    gt  (not enforced)
    lt  (not enforced)
```

### Step 3: Value Picker (typed per attribute)

**Classification -> select (4 options):**
```
Step 3 of 3 -- Value  [Classification]
---------------------------------------------------------
  > T1: Public
    T2: Internal
    T3: Confidential
    T4: Restricted
```

**MemberOf -> text input:**
```
Step 3 of 3 -- Value  [MemberOf -- enter AD group SID]
---------------------------------------------------------
[________________________________]
```

Note: `PolicyCondition::MemberOf` stores the SID in the `group_sid: String` field
(not `value`). The executor must map the text buffer to `group_sid` when constructing
the `PolicyCondition::MemberOf { op, group_sid }` variant.

**DeviceTrust -> select (4 options):**
```
Step 3 of 3 -- Value  [DeviceTrust]
---------------------------------------------------------
  > Managed
    Unmanaged
    Compliant
    Unknown
```

**NetworkLocation -> select (4 options):**
```
Step 3 of 3 -- Value  [NetworkLocation]
---------------------------------------------------------
  > Corporate
    CorporateVpn
    Guest
    Unknown
```

**AccessContext -> select (2 options):**
```
Step 3 of 3 -- Value  [AccessContext]
---------------------------------------------------------
  > Local
    Smb
```

---

## Pending Conditions List

Rendered as a `List` above the step picker, inside the modal box. Uses `ListState` for scroll position. Fixed 6-row allocation, scrollable when more than 6 items.

**Normal item:**
```
  > Classification = T3                           [d]
    Classification = T2                           [d]
    DeviceTrust = Managed                         [d]
```

The `[d]` annotation is rendered in `Color::DarkGray` as a visible delete hint -- it is not a button, just copy. The delete action fires when `d` is pressed while the item is selected.

**Empty state** (when pending list is empty, D-19):
```
  (empty) No conditions added. Use the picker below to add conditions.
```
Rendered as `Paragraph` with `Color::DarkGray`.

**Delete behavior (D-07):** When a pending list item is focused (Up/Down navigates to it) and `d` is pressed, the item is removed from the list immediately. No confirmation dialog in v0.4.0.

**After adding a condition (D-05):** The condition is appended to the pending list, the picker resets to Step 1. Pending list scroll position is preserved.

---

## Interaction States

| State | Visual |
|-------|--------|
| List item -- default | `Color::White`, no background |
| List item -- selected (step picker) | `Color::Black` fg + `Color::Cyan` bg + `Modifier::BOLD` |
| Pending list item -- default | `Color::White`, `[d]` in `Color::DarkGray` |
| Pending list item -- selected | `Color::Black` fg + `Color::Cyan` bg + `Modifier::BOLD`, `[d]` visible |
| Breadcrumb -- completed step | `Color::DarkGray`, regular weight |
| Breadcrumb -- current step | `Color::White`, `Modifier::BOLD` |
| Text input -- editing | `[buffer_]` inside block |
| Operator not enforced | `Color::DarkGray`, `(not enforced)` annotation |
| Empty pending list | `Color::DarkGray`, placeholder paragraph |

---

## Copywriting Contract

| Element | Copy |
|---------|------|
| Modal title | `Conditions Builder` |
| Breadcrumb -- completed step | `Step N: {name}` |
| Breadcrumb -- separator | ` > ` |
| Breadcrumb -- current step | `Step N: {name}` |
| Empty pending heading | `(empty)` |
| Empty pending body | `No conditions added. Use the picker below to add conditions.` |
| Step 1 label | `Step 1: Attribute` |
| Step 2 label | `Step 2: Operator  [{selected_attribute}]` |
| Step 3 label | `Step 3 of 3 -- Value  [{selected_attribute}]` |
| Step 2 (no attr selected) | `Step 2: Operator` |
| Key hint -- navigate | `Up/Down Navigate` |
| Key hint -- advance | `Enter: Add` |
| Key hint -- back | `Esc: Back/Close` |
| Full modal hint bar | `Up/Down Navigate  Enter: Add  Esc: Back/Close` |
| Pending delete hint | `[d]` |
| PolicyCreate "Add Conditions" CTA | `Add Conditions` |
| PolicyEdit "Add Conditions" CTA | `Add Conditions` |
| Not-enforced annotation | `(not enforced)` |

---

## Key Bindings Summary

| Key | Action |
|-----|--------|
| Up Arrow | Move selection up in current step |
| Down Arrow | Move selection down in current step |
| Enter | Advance to next step / confirm value -> add to pending list -> reset to Step 1 |
| Esc | Step back (Step 3 -> Step 2 -> Step 1) or close modal (at Step 1) |
| `d` | Delete currently focused pending condition |
| `D` | Same as `d` |
| `Q` | Same as Esc |

---

## Component Inventory

> Codebase scan 2026-04-16 confirmed: `ConditionsBuilder` variant does NOT yet exist
> in `app.rs` `Screen` enum. All entries below are forward-looking contracts for the
> executor to implement in Phase 13.

| Component | ratatui widget | Key behavior |
|-----------|---------------|--------------|
| Modal overlay | `Clear` (full frame) + constrained `Layout` | Dims parent, centers modal box |
| Modal box | `Block::default().borders(Borders::ALL).title(" Conditions Builder ")` | Box-drawing border |
| Step breadcrumb | `Paragraph` with `Line` + mixed `Span` styles | Current step bold White; completed steps DarkGray regular |
| Pending list | `List` + `ListState` | 6-row fixed, scrollable, delete on `d` |
| Pending empty state | `Paragraph` styled `Color::DarkGray` | Placeholder text |
| Pending delete hint | `Span` in `Color::DarkGray` | `[d]` annotation per item |
| Step picker list | `List` + `ListState` | `highlight_symbol("> ")` |
| Step label | `Paragraph` bold | `Modifier::BOLD` |
| Key hints bar | `draw_hints(frame, modal_area, hints)` | Bottom of modal box, overlaid via existing `draw_hints` pattern |
| Confirm Yes | `Span::styled(..., Black+Green+BOLD)` | Existing `draw_confirm` |
| Confirm No | `Span::styled(..., Black+Red+BOLD)` | Existing `draw_confirm` |

---

## Screen Enum Addition

The `Screen` enum in `app.rs` gains one new variant. Codebase scan confirmed this
variant does not yet exist -- it is the contract for the executor.

```rust
/// Conditions Builder modal overlay.
///
/// 3-step sequential picker: Attribute -> Operator -> Value.
/// Completed conditions accumulate in `pending` and are returned
/// to the caller via `PolicyFormState`.
ConditionsBuilder {
    /// 1, 2, or 3.
    step: u8,
    /// Conditions already added this session.
    pending: Vec<dlp_common::abac::PolicyCondition>,
    /// Currently selected option in the active step's list.
    selected_option: usize,
    /// For MemberOf Step 3 only: buffered text input.
    /// Maps to `PolicyCondition::MemberOf { group_sid }` on commit.
    buffer: String,
    /// ListState for the pending conditions list (scroll position).
    pending_state: ratatui::widgets::ListState,
    /// ListState for the step picker (Attributes / Operators / Values).
    picker_state: ratatui::widgets::ListState,
}
```

**MemberOf field note:** `PolicyCondition::MemberOf` uses `group_sid: String` (not
`value`). The executor must map `buffer` to `group_sid` when constructing the variant:
`PolicyCondition::MemberOf { op: "eq".to_string(), group_sid: buffer.clone() }`.

---

## Screen Dispatch Addition

`handle_event` in `dispatch.rs` gains a new branch for `Screen::ConditionsBuilder { .. }`.
Codebase scan confirmed no such branch exists yet -- this is the contract for the executor.

- `Up/Down` -> update `selected_option` within list bounds
- `Enter` on Step 1 -> advance to Step 2, update operator list
- `Enter` on Step 2 -> advance to Step 3, populate value list
- `Enter` on Step 3 -> push condition to `pending`, reset picker to Step 1
- `Esc` -> step back (3->2->1) or emit event to close modal and return to parent screen
- `d` / `D` -> delete selected item from `pending`

---

## Decisions Locked from CONTEXT.md (verbatim)

| ID | Decision |
|----|----------|
| D-01 | Conditions builder is a modal overlay using `Clear` + constrained `Layout`. |
| D-02 | Opened from Policy Create/Edit form via "Add Conditions" button/key. |
| D-03 | `PolicyFormState` struct holds `conditions: Vec<PolicyCondition>` -- no borrow-split issues. |
| D-04 | Modal contains both the step picker (Steps 1->2->3) and the inline pending-conditions list. Both visible simultaneously. |
| D-05 | After Step 3 Enter, condition appended to pending list, picker resets to Step 1. |
| D-06 | Esc at Step 1 closes modal; pending list preserved in `PolicyFormState`. |
| D-07 | Each pending condition has a `d` key delete binding. No in-place edit in v0.4.0. |
| D-08 | `PolicyCondition` variants from `dlp_common::abac.rs` are authoritative. |
| D-09 | All conditions evaluated as implicit AND. |
| D-10 | Operators derived dynamically per attribute from lookup table. |
| D-11 | Classification -> T1/T2/T3/T4 select (4 options). |
| D-12 | MemberOf -> free-text input (AD group SID). |
| D-13 | DeviceTrust -> 4-option select (Managed / Unmanaged / Compliant / Unknown). |
| D-14 | NetworkLocation -> 4-option select (Corporate / CorporateVpn / Guest / Unknown). |
| D-15 | AccessContext -> 2-option select (Local / Smb). |
| D-16 | Up/Down arrows navigate the current step's options list. |
| D-17 | Enter advances to the next step. |
| D-18 | Esc steps back: Step 3 -> Step 2 -> Step 1 -> modal close. |
| D-19 | Empty pending list shows muted placeholder: "No conditions added. Use the picker below to add conditions." |

---

## Checker Sign-Off

- [ ] Dimension 1 Copywriting: PASS (all 18 elements defined in Copywriting Contract)
- [ ] Dimension 2 Visuals: PASS (ASCII layout diagram, component inventory, breadcrumb states)
- [ ] Dimension 3 Color: PASS (`Color::` enum values, existing TUI style preserved: Black+Cyan+BOLD)
- [ ] Dimension 4 Typography: PASS (terminal default, `Modifier::BOLD` emphasis, cell-based spacing)
- [ ] Dimension 5 Spacing: PASS (cell-based 1/2/4/8/12/16 scale, 22-row fixed modal, 6-row pending list)
- [ ] Dimension 6 Registry Safety: PASS (no external registries -- TUI)

**Approval:** pending

---

## Sources

| Source | Decisions Locked |
|--------|-----------------|
| 13-CONTEXT.md | D-01--D-19 verbatim above; modal overlay pattern, 3-step picker, pending list visible, keyboard nav, empty state, PolicyCondition serde format, 5 attributes, typed Step 3 pickers |
| 13-DISCUSSION-LOG.md | Modal overlay chosen over embedded rows or single-condition session; builder steps + inline pending list chosen over summary screen |
| render.rs (verified 2026-04-16) | `Color::Black/White/Cyan/Green/Red/DarkGray`, `Modifier::BOLD`, `highlight_symbol("> ")`, `draw_confirm` box-drawing pattern, `draw_hints` pattern; all color/style constants confirmed unchanged |
| app.rs (verified 2026-04-16) | `Screen` enum pattern confirmed; `ConditionsBuilder` variant NOT YET present -- spec is a forward-looking contract; `ListState`, `Block`, `Borders::ALL` confirmed in use |
| dispatch.rs (verified 2026-04-16) | `handle_event` routing pattern confirmed; no `ConditionsBuilder` branch yet -- spec is forward-looking |
| abac.rs (verified 2026-04-16) | `PolicyCondition` 5 variants confirmed; `MemberOf.group_sid: String` field name noted in Screen Enum Addition and Step 3 sections |
| REQUIREMENTS.md ss POLICY-05 | 5 attributes, operator list, step 3 value options, implicit AND |
| REQUIREMENTS.md ss Open Design Decisions | Operator display annotation requirement |
| STATE.md | PolicyFormState pattern, "Conditions builder: PolicyFormState struct" |
| ROADMAP.md ss Phase 13 | Success criteria |
