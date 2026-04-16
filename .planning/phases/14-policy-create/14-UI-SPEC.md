---
phase: 14
slug: policy-create
status: draft
shadcn_initialized: false
preset: none
created: "2026-04-16"
updated: "2026-04-16"
---

# Phase 14 — UI Design Contract

> Visual and interaction contract for the Policy Create multi-field form screen.
> Phase 14 builds on top of the Phase 13 ConditionsBuilder modal; all color,
> spacing, typography, and key-binding conventions are inherited and extended.

---

## Design System

| Property | Value |
|----------|-------|
| Tool | ratatui + crossterm |
| Preset | none |
| Component library | ratatui built-ins (Block, List, ListState, Paragraph, Layout, Borders, Clear) |
| Icon library | none (text-based TUI) |
| Font | terminal default (monospace) |

> Source: Phase 13 UI-SPEC (approved 2026-04-16); confirmed by direct scan of
> `dlp-admin-cli/src/screens/render.rs` and `app.rs`.

---

## Layout Structure

Phase 14 renders as a **full-screen form** (not a modal). It follows the same
`List`-based field-row pattern used by `draw_siem_config` and `draw_alert_config`.

```
+- Create Policy -----------------------------------------------+
| > Name:              [______________________________]          |
|   Description:       (empty)                                   |
|   Priority:          (empty)                                   |
|   Action:            ALLOW                                     |
|   [Add Conditions]                                             |
|   Conditions (0):    No conditions added.                      |
|   [Submit]                                                     |
|                                                                |
|   Validation error text (Color::Red, shown below Submit)      |
| Up/Down: navigate | Enter: edit/toggle/open | Esc: back        |
+----------------------------------------------------------------+
```

### Area Allocations

The form occupies the full terminal area minus the global status bar row at the
bottom (same `Layout::vertical([Min(0), Length(1)])` split used by all screens).

| Area | Rows | Content |
|------|------|---------|
| Form list | remaining | All field rows + action rows |
| Status bar | 1 | Global `draw_status_bar` (success / error / info) |
| Hints bar | 1 | Overlaid inside form list via `draw_hints` (y = area.bottom - 1) |

### Field Row Layout

Each row in the `List` is a single `ListItem` formatted as:

```
{Label}:              {Value display}
```

Label is left-aligned, padded with spaces to a fixed column of 22 characters.
Value display follows immediately after the colon + space.

**Row index mapping (selected: usize):**

| Row | Index | Label | Type |
|-----|-------|-------|------|
| Name | 0 | `Name` | Text input (required) |
| Description | 1 | `Description` | Text input (optional) |
| Priority | 2 | `Priority` | Numeric text input (required, u32) |
| Action | 3 | `Action` | Select (cycles through 4 fixed options on Enter) |
| [Add Conditions] | 4 | — | Action row (opens ConditionsBuilder modal) |
| Conditions display | 5 | `Conditions ({n})` | Read-only summary row |
| [Submit] | 6 | — | Action row (triggers validation + POST) |

Total rows: 7 (indices 0–6).

### Conditions Summary Row (Row 5)

Row 5 is a read-only display row that reflects the current count of conditions
attached to the form. It is not selectable for editing, but it is navigable
(cursor can rest on it). It displays:

```
Conditions (0):    No conditions added.
```

When conditions exist:

```
Conditions (2):    Classification = T3, DeviceTrust = Managed
```

- Conditions are rendered as a comma-separated summary on a single line.
- If the summary exceeds terminal width, it is truncated with `...` at the right edge.
- The summary is rendered in `Color::DarkGray` when the row is not selected.
- The condition count in parentheses updates immediately after returning from
  the ConditionsBuilder.

### Validation Error Display

When `validation_error: Option<String>` is `Some(text)`, an additional
`Paragraph` is rendered directly below the Submit row in `Color::Red`.
It is not a `ListItem` — it is rendered as an overlay paragraph so the
list row count stays stable at 7.

---

## Spacing Scale

Inherited unchanged from Phase 13 UI-SPEC. ratatui TUI uses character-cell grid
units; pixel-based 4px scale does not apply.

| Token | Value | Usage |
|-------|-------|-------|
| xs | 1 cell | Inline symbol spacing |
| sm | 2 cells | `highlight_symbol("> ")` indent |
| md | 4 cells | Effective left margin inside block border |
| lg | 8 cells | Horizontal padding inside block title bar |
| xl | 12 cells | Not used in full-screen forms |
| 2xl | 16 cells | Not used in full-screen forms |

**Label column width:** 22 characters (fixed). Derived from longest label
`Conditions (N):` (15 chars) + padding to 22 for value alignment.

---

## Typography

Inherited unchanged from Phase 13 UI-SPEC. All emphasis via `Modifier::BOLD` or
`Color`; no font size overrides in ratatui.

| Role | Size | Weight | Line Height |
|------|------|--------|-------------|
| Body / field values | terminal default (monospace) | regular | 1 |
| Block title | terminal default | `Modifier::BOLD` (via `Block::title`) | 1 |
| Selected row | terminal default | `Modifier::BOLD` (via highlight_style) | 1 |
| Action row labels | terminal default | regular | 1 |
| Validation error | terminal default | regular | 1 |
| Key hints | terminal default | regular | 1 |
| Edit mode buffer | terminal default | regular (cursor indicated by `_`) | 1 |

---

## Color

All values are `ratatui::style::Color` enum variants. Palette inherited from
Phase 13 UI-SPEC and confirmed present in `render.rs` (verified 2026-04-16).

**TUI color hierarchy (60/30/10 intent):**
Dominant: `Color::White` (default text, majority of cells); Secondary:
`Color::DarkGray` (empty values, hints, conditions summary when unfocused);
Accent: `Color::Cyan` (selection highlight — reserved for the active list row
only); Semantic: `Color::Green` (success status), `Color::Red` (validation
errors and error status).

| Role | Value | Usage |
|------|-------|-------|
| Default text | `Color::White` | Non-selected field labels and values |
| Selected row fg | `Color::Black` | Text on the highlighted row |
| Selected row bg | `Color::Cyan` | Currently highlighted row |
| Selected modifier | `Modifier::BOLD` | Bold on selected row |
| Empty value text | `Color::DarkGray` | `(empty)` placeholder for unfilled fields |
| Conditions summary (unfocused) | `Color::DarkGray` | Conditions row value when not selected |
| Hints text | `Color::DarkGray` | Key hint bar at bottom |
| Validation error text | `Color::Red` | Inline error paragraph below Submit row |
| Status bar: Success | `Color::Green` | `"Policy created"` success message |
| Status bar: Error | `Color::Red` | Network / server error messages |
| Status bar: Info | `Color::Cyan` | Informational status messages |

**Accent reserved for:** active list row selection only (`bg(Color::Cyan)` +
`fg(Color::Black)` + `Modifier::BOLD`). Not used for borders, labels, or action
rows in their default state.

**Exact highlight style (must match all existing TUI screens):**
```rust
Style::default()
    .fg(Color::Black)
    .bg(Color::Cyan)
    .add_modifier(Modifier::BOLD)
```

---

## Field Visual States

### Text Input Fields (Name, Description, Priority)

| State | Visual |
|-------|--------|
| Default, not selected | `{label}: (empty)` in `Color::White` / `Color::DarkGray` |
| Selected, not editing | `{label}: (empty)` highlighted with `Black+Cyan+BOLD` |
| Selected, editing | `{label}: [{buffer}_]` highlighted with `Black+Cyan+BOLD` |
| Has value, not selected | `{label}: {value}` in `Color::White` |

The `[{buffer}_]` pattern (square brackets + trailing underscore) is the cursor
indicator. This is the existing convention from `draw_siem_config` and
`draw_alert_config` (confirmed in `render.rs`).

### Action Select Field (Row 3)

| State | Visual |
|-------|--------|
| Not selected | `Action:               ALLOW` (current selection label) |
| Selected | Same row highlighted with `Black+Cyan+BOLD` |
| Enter key | Cycles to next option in `ACTION_OPTIONS` array |

The four options cycle in order: `ALLOW` → `DENY` → `AllowWithLog` →
`DenyWithAlert` → `ALLOW`. The Enter key advances the index; no separate
dropdown or sub-menu opens.

**Action options display labels and wire strings:**

| Display Label | Wire String (POST body) | Index |
|---------------|------------------------|-------|
| `ALLOW` | `"ALLOW"` | 0 |
| `DENY` | `"DENY"` | 1 |
| `AllowWithLog` | `"AllowWithLog"` | 2 |
| `DenyWithAlert` | `"DenyWithAlert"` | 3 |

> Source: `dlp-common/src/abac.rs` Decision enum and `policy_store.rs`
> `deserialize_policy_row` case-insensitive mapping. "DenyWithLog" in the
> roadmap is a naming error — the actual enum variant is `DenyWithAlert`.

### [Add Conditions] Row (Row 4)

| State | Visual |
|-------|--------|
| Not selected | `  [Add Conditions]` |
| Selected | `> [Add Conditions]` highlighted with `Black+Cyan+BOLD` |
| Enter key | Transitions to `Screen::ConditionsBuilder`, carrying `form_snapshot` |

The row label `[Add Conditions]` uses square brackets to visually distinguish
action rows from field rows. This convention follows how `[Submit]` and `[Save]`
are rendered in other forms (convention inferred from AlertConfig label pattern).

### [Submit] Row (Row 6)

| State | Visual |
|-------|--------|
| Not selected | `  [Submit]` |
| Selected | `> [Submit]` highlighted with `Black+Cyan+BOLD` |
| Enter key | Runs validation; on pass, fires POST /admin/policies |

### Validation Error Paragraph

Rendered as a `Paragraph` overlaid below the list area (not a list item):

```
  Name is required.
```

or:

```
  Priority must be a valid integer (0 or greater).
```

or (on server error):

```
  Server error: POST .../admin/policies returned 400: id and name are required
```

Styled: `Style::default().fg(Color::Red)`. Visible only when
`validation_error` is `Some`. Cleared on any successful navigation away from
the form.

---

## Interaction States

| State | Visual |
|-------|--------|
| Field row — default | `Color::White` label + value, no background |
| Field row — selected, not editing | `Color::Black` fg + `Color::Cyan` bg + `Modifier::BOLD` |
| Field row — selected, editing | `Color::Black` fg + `Color::Cyan` bg + `Modifier::BOLD`, value shows `[{buffer}_]` |
| Action row — default | `Color::White`, no background |
| Action row — selected | `Color::Black` fg + `Color::Cyan` bg + `Modifier::BOLD` |
| Conditions row — 0 conditions | `Conditions (0):    No conditions added.` in `Color::DarkGray` |
| Conditions row — N conditions | `Conditions (N):    {summary}` — count in `Color::White`, summary in `Color::DarkGray` |
| Validation error — visible | `Color::Red` paragraph below Submit row |
| Validation error — hidden | No paragraph rendered (not an empty row) |

---

## Copywriting Contract

| Element | Copy |
|---------|------|
| Block title | ` Create Policy ` |
| Name label | `Name` |
| Description label | `Description` |
| Priority label | `Priority` |
| Action label | `Action` |
| Add Conditions CTA | `[Add Conditions]` |
| Submit CTA | `[Submit]` |
| Empty field value | `(empty)` |
| Conditions row — no conditions | `No conditions added.` |
| Conditions row — N conditions | `{n} condition(s): {summary}` where summary is `Attribute = Value` pairs joined by `, ` |
| Validation error — empty name | `Name is required.` |
| Validation error — bad priority | `Priority must be a valid integer (0 or greater).` |
| Validation error — server 4xx | `Server error: {error message from EngineClient}` |
| Validation error — network fail | `Network error: {error message from EngineClient}` |
| Hints bar — navigating | `Up/Down: navigate | Enter: edit/toggle/open | Esc: back` |
| Hints bar — editing text | `Type to edit | Enter: commit | Esc: cancel` |
| Status bar — success | `Policy created` |

> Note: No destructive actions exist in Phase 14. Submit is a create-only POST
> with no confirmation dialog. Esc cancels and returns to PolicyMenu without
> confirmation (form data is discarded silently).

---

## Key Bindings Summary

| Key | Context | Action |
|-----|---------|--------|
| Up Arrow | Navigating | Move cursor to row above |
| Down Arrow | Navigating | Move cursor to row below |
| Enter | Text field selected, not editing | Enter edit mode; pre-fill buffer from current value |
| Enter | Text field selected, editing | Commit buffer to form field; exit edit mode |
| Enter | Action (select) row selected | Cycle action index by 1 (wraps at end of list) |
| Enter | [Add Conditions] row selected | Transition to `Screen::ConditionsBuilder` carrying `form_snapshot` |
| Enter | [Submit] row selected | Run validation; fire POST if valid |
| Esc | Navigating | Return to `Screen::PolicyMenu` (form discarded) |
| Esc | Editing text field | Cancel edit; restore field to pre-edit value |
| `Q` | Navigating | Same as Esc |

---

## Screen Transitions

```
Screen::PolicyMenu
    |
    Enter on "Create Policy"
    |
    v
Screen::PolicyCreate
    |
    +-- Enter on [Add Conditions] --> Screen::ConditionsBuilder { caller: CallerScreen::PolicyCreate, form_snapshot }
    |                                     |
    |                                     Esc (Step 1 or pending list)
    |                                     --> Screen::PolicyCreate { form with updated conditions }
    |
    +-- Enter on [Submit] (valid) --> POST /admin/policies --> Screen::PolicyList (via action_list_policies)
    |
    +-- Esc / Q --> Screen::PolicyMenu
```

**ConditionsBuilder round-trip (critical):** When transitioning to
`Screen::ConditionsBuilder`, the full `PolicyFormState` (name, description,
priority, action, conditions) must be stored in `form_snapshot` inside the
`ConditionsBuilder` variant. On Esc, BOTH Esc code paths in `dispatch.rs`
(Step 1 Esc and pending-focus Esc) must reconstruct `Screen::PolicyCreate`
using `form_snapshot` with conditions replaced by the current `pending` list.

---

## Component Inventory

| Component | ratatui widget | Key behavior |
|-----------|---------------|--------------|
| Form list | `List` + `ListState` | 7 rows, cursor navigation, `highlight_symbol("> ")` |
| List highlight style | `Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)` | All rows (matches existing TUI screens) |
| Block border | `Block::default().borders(Borders::ALL).title(" Create Policy ")` | Full-screen border |
| Text input (editing) | `ListItem` with `[{buffer}_]` format | Name, Description, Priority |
| Action select | `ListItem` showing `ACTION_OPTIONS[form.action]` | Cycles on Enter |
| Add Conditions row | `ListItem` with `[Add Conditions]` text | Opens ConditionsBuilder modal |
| Conditions summary | `ListItem` with count + summary | Read-only; updates after modal returns |
| Submit row | `ListItem` with `[Submit]` text | Triggers validation and POST |
| Validation error | `Paragraph` below list | `Color::Red`; only rendered when `Some` |
| Key hints bar | `draw_hints(frame, area, hints)` | Existing function; hints string changes by mode |
| Status bar | `draw_status_bar(app, frame, status_area)` | Existing global function |

---

## Screen Enum Addition

```rust
/// Policy creation multi-field form.
///
/// Row layout (selected index -> field):
///   0: Name         (text, required)
///   1: Description  (text, optional)
///   2: Priority     (text, parsed as u32 at submit)
///   3: Action       (select index into ACTION_OPTIONS)
///   4: [Add Conditions]
///   5: Conditions display (read-only summary)
///   6: [Submit]
Screen::PolicyCreate {
    /// All form field values and accumulated conditions.
    form: PolicyFormState,
    /// Index of the currently highlighted row (0..=6).
    selected: usize,
    /// Whether the selected text field is in edit mode.
    editing: bool,
    /// Text buffer for the active text field (Name, Description, Priority).
    buffer: String,
    /// Inline validation error displayed below the Submit row.
    /// Cleared on Esc or successful submission.
    validation_error: Option<String>,
},
```

---

## Registry Safety

| Registry | Blocks Used | Safety Gate |
|----------|-------------|-------------|
| N/A — TUI project | none | not applicable |

This is a ratatui TUI application. No web component registries (shadcn or
third-party) are involved. Registry safety gate is not applicable.

---

## Decisions Locked from Upstream Artifacts

| ID | Decision | Source |
|----|----------|--------|
| D-01 | Full-screen form (not modal); same layout as draw_siem_config/draw_alert_config | RESEARCH.md Pattern 1 |
| D-02 | `List` widget with `ListState` for field navigation | render.rs (verified 2026-04-16) |
| D-03 | `highlight_symbol("> ")` for selected row | render.rs (verified 2026-04-16) |
| D-04 | `Color::Black + Color::Cyan + Modifier::BOLD` selection style (matches all existing screens) | Phase 13 UI-SPEC + render.rs |
| D-05 | Action field stored as `usize` index; rendered as display label; converted to wire string at submit | RESEARCH.md Pattern 3 |
| D-06 | Wire strings: ALLOW, DENY, AllowWithLog, DenyWithAlert (not DenyWithLog — roadmap naming error) | RESEARCH.md Pitfall 1 + abac.rs |
| D-07 | Inline validation error as `Option<String>` on the screen variant; rendered as `Color::Red` paragraph | RESEARCH.md Pattern 1 + Pattern 4 |
| D-08 | `draw_hints` for key hint bar (existing function, overlaid at bottom-1 row) | render.rs (verified 2026-04-16) |
| D-09 | `draw_status_bar` for global status (existing global function) | render.rs (verified 2026-04-16) |
| D-10 | `form_snapshot: PolicyFormState` inside `ConditionsBuilder` variant to survive modal round-trip | RESEARCH.md Pattern 2 + Pitfall 2 |
| D-11 | BOTH Esc code paths in dispatch.rs (Step 1 + pending) must restore `Screen::PolicyCreate` | RESEARCH.md Pitfall 3 |
| D-12 | UUID generated at submit time via `uuid::Uuid::new_v4().to_string()` | RESEARCH.md Standard Stack + Pitfall 4 |
| D-13 | Priority parsed as `u32` (not i32) — negative values rejected with inline error | RESEARCH.md Pitfall 6 |
| D-14 | Post-submit navigation: `Screen::PolicyList` via `action_list_policies` | RESEARCH.md Pattern 4 + Open Questions |
| D-15 | Post-submit status bar message: `"Policy created"` with `StatusKind::Success` | RESEARCH.md code example |
| D-16 | Esc from form discards without confirmation (create form, not destructive) | REQUIREMENTS.md POLICY-02 |
| D-17 | Conditions summary row is read-only (not selectable for editing); navigable only | RESEARCH.md Architecture Diagram |
| D-18 | Empty state for no conditions: `"No conditions added."` in `Color::DarkGray` | Phase 13 UI-SPEC copywriting + REQUIREMENTS.md |
| D-19 | `[Edit mode buffer]` pattern: `[{buffer}_]` with trailing underscore as cursor | render.rs (verified 2026-04-16) |

---

## Checker Sign-Off

- [ ] Dimension 1 Copywriting: PASS (all 15 copy elements defined; no destructive actions in scope)
- [ ] Dimension 2 Visuals: PASS (ASCII layout diagram, 7-row field map, all visual states documented)
- [ ] Dimension 3 Color: PASS (`Color::` enum values, 60/30/10 hierarchy declared, accent reserved for selection highlight only)
- [ ] Dimension 4 Typography: PASS (terminal default, `Modifier::BOLD` emphasis, cell-based spacing, edit mode cursor convention)
- [ ] Dimension 5 Spacing: PASS (cell-based scale inherited from Phase 13; 22-char label column width declared)
- [ ] Dimension 6 Registry Safety: PASS (no external registries — TUI)

**Approval:** pending

---

## Sources

| Source | Decisions Used |
|--------|---------------|
| Phase 13 UI-SPEC (approved 2026-04-16) | Design system, color palette, spacing scale, typography, `draw_hints` convention, `draw_confirm` convention |
| 14-RESEARCH.md (2026-04-16) | Screen variant structure, form field row map, action options, CallerScreen round-trip pattern, submit flow, pitfalls 1-6 |
| REQUIREMENTS.md POLICY-02 | Form fields, validation requirements, POST endpoint, cache invalidation responsibility |
| ROADMAP.md Phase 14 success criteria | Form fields list, inline validation, conditions integration, network error display |
| render.rs (verified 2026-04-16) | `draw_siem_config`, `draw_alert_config` patterns; `draw_hints`, `draw_status_bar`; `Color::*`, `Modifier::BOLD`, `highlight_symbol("> ")`; `[{buffer}_]` cursor convention |
| app.rs (verified 2026-04-16) | `PolicyFormState` struct, `ACTION_OPTIONS`, `CallerScreen`, `Screen` enum, `StatusKind` |
| abac.rs (verified 2026-04-16) | `Decision` enum variants confirming `DenyWithAlert` (not `DenyWithLog`) |
| STATE.md | `PolicyFormState` pattern decision, `TUI screens: ratatui + crossterm` pattern |
