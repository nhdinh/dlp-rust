---
phase: 15
slug: policy-edit-delete
status: draft
shadcn_initialized: false
preset: none
created: "2026-04-17"
---

# Phase 15 — UI Design Contract

> Visual and interaction contract for the Policy Edit form and PolicyList key
> extensions. Inherits all design system, layout, color, and typography from
> Phase 14 UI-SPEC. This document covers only Phase 15 deltas:
> `Screen::PolicyEdit` (8-row form), the Enabled toggle row, `handle_confirm`
> y/n keys, and the PolicyList hints bar extension.
>
> **Inherited from Phase 14 UI-SPEC:** design system (ratatui + crossterm,
> color palette, spacing scale, typography, highlight style, cursor convention,
> validation error pattern, `draw_hints`, `draw_status_bar`).

---

## Design System

Inherited from [Phase 14 UI-SPEC — Design System] verbatim.

| Property | Value |
|----------|-------|
| Tool | ratatui + crossterm |
| Preset | none |
| Component library | ratatui built-ins (Block, List, ListState, Paragraph, Layout, Borders, Clear) |
| Icon library | none (text-based TUI) |
| Font | terminal default (monospace) |

---

## Layout Structure

### PolicyEdit Form (Screen::PolicyEdit)

Full-screen form identical to `Screen::PolicyCreate` in structure and
presentation, with three deltas: title string, row-7 label, and row-4 content.

```
+- Edit Policy: Confidential File Policy ------------------------+
| > Name:              [Confidential File Policy_________________]  |
|   Description:       Restricts T3/T4 files                    |
|   Priority:          50                                        |
|   Action:            DENY                                      |
|   Enabled:           Yes                                       |
|   [Add Conditions]                                             |
|   Conditions (2):    Classification = T3, MemberOf = S-1-5-...  |
|   [Save]                                                        |
|                                                                |
|   Validation error text (Color::Red, shown below Save)        |
| Up/Down: navigate | Enter: edit/toggle/open | Esc: back        |
+----------------------------------------------------------------+
```

**Delta from Phase 14 (7 rows → 8 rows):**

| Row | Index | Label | Type | Delta from Phase 14 |
|-----|-------|-------|------|---------------------|
| Name | 0 | `Name` | Text input (required) | unchanged |
| Description | 1 | `Description` | Text input (optional) | unchanged |
| Priority | 2 | `Priority` | Numeric text input (u32) | unchanged |
| Action | 3 | `Action` | Select (cycles 4 options) | unchanged |
| **Enabled** | **4** | **`Enabled`** | **Bool toggle** | **NEW row** |
| [Add Conditions] | 5 | — | Action row | index +1 |
| Conditions display | 6 | `Conditions ({n})` | Read-only summary | index +1 |
| [Save] | 7 | — | Action row | **label changed** `[Submit]` → `[Save]` |

Total rows: **8** (indices 0–7).

**Block title:** `" Edit Policy: {name} "` where `{name}` is the policy's current
name loaded from `GET /admin/policies/{id}` at screen open time. No ID in title.

**Label column width:** 22 characters (identical to Phase 14).

---

## Enabled Toggle Row (Rows 3 and 4 — Select-style, No Buffer)

> Phase 14 Create form is also updated to include this row (Phase 15 D-09 scope).
> Both forms share the identical render/dispatch pattern.

### Row 4: Action Select (Row Index 3 — Unchanged)

```
Action:               DENY
```

- Cycles through `ACTION_OPTIONS` on Enter: `ALLOW` → `DENY` → `AllowWithLog` →
  `DenyWithAlert` → `ALLOW`.
- Rendered in `Color::White` when not selected.
- Highlighted with `Black+Cyan+BOLD` when selected.

### Row 5: Enabled Toggle (Row Index 4 — NEW)

```
Enabled:              Yes
```
or:
```
Enabled:              No
```

**Visual states:**

| State | Visual |
|-------|--------|
| Selected, enabled=true | `Enabled:              Yes` highlighted `Black+Cyan+BOLD` |
| Selected, enabled=false | `Enabled:              No` highlighted `Black+Cyan+BOLD` |
| Not selected, enabled=true | `Enabled:              Yes` in `Color::White` |
| Not selected, enabled=false | `Enabled:              No` in `Color::White` |

**Enter behavior:** `form.enabled = !form.enabled` — toggle boolean, no edit mode,
no buffer. Same pattern as Action select row.

**Esc behavior:** Not applicable — no edit mode, no text to cancel.

**`PolicyFormState::default()`:** `enabled: true` (existing, carried from Phase 14
D-08). New policies default to enabled unless admin explicitly toggles off.

---

## Key Binding Deltas

### handle_policy_edit (NEW — parallel to handle_policy_create)

| Key | Context | Action |
|-----|---------|--------|
| Up Arrow | Navigating | Move cursor to row above |
| Down Arrow | Navigating | Move cursor to row below |
| Enter | Text field selected, not editing | Enter edit mode; pre-fill buffer from current value |
| Enter | Text field selected, editing | Commit buffer; exit edit mode |
| Enter | Action row selected (row 3) | Cycle action index +1 (wraps) |
| Enter | Enabled row selected (row 4) | Toggle `form.enabled` |
| Enter | [Add Conditions] row selected | Transition to `Screen::ConditionsBuilder` with `form.conditions.clone()` as pending |
| Enter | [Save] row selected | Validate; fire PUT /admin/policies/{id} |
| Esc | Navigating | Return to `Screen::PolicyList` via `action_list_policies(app)` (no confirmation) |
| Esc | Editing text field | Cancel edit; restore pre-edit value |
| `Q` | Navigating | Same as Esc |

### handle_confirm extension (Char('y') / Char('n'))

> `draw_confirm` is REUSED AS-IS — no visual changes to the confirm dialog.

**Extended key branches added to existing `handle_confirm`:**

| Key | Context | Action |
|-----|---------|--------|
| `y` | ConfirmPurpose::DeletePolicy | Set `yes_selected = true`; fire purpose action; clear screen |
| `n` | ConfirmPurpose::DeletePolicy | Same as Esc (cancel, return to PolicyList) |
| `Y` | ConfirmPurpose::DeletePolicy | Same as `y` |
| `N` | ConfirmPurpose::DeletePolicy | Same as `n` |

**Existing key bindings unchanged:** `Left`/`Right`/`Enter` → yes_selected toggle/fire;
`Esc` → cancel.

### handle_policy_list extension (Char('e') / Char('d'))

**Extended key branches added to existing `handle_policy_list`:**

| Key | Context | Action |
|-----|---------|--------|
| `e` | PolicyList row selected | `action_load_policy_for_edit(app, &id, &name)` → GET /admin/policies/{id} → Screen::PolicyEdit |
| `d` | PolicyList row selected | Transition to `Screen::Confirm { message: "Delete policy '{name}'? [y/n]", yes_selected: false, purpose: ConfirmPurpose::DeletePolicy { id } }` |

**Unchanged:** Up/Down (navigation), Enter (→ PolicyDetail read-only view), Esc (back).

---

## Confirm Delete Dialog

> `draw_confirm` renders this dialog. Visual contract is inherited from Phase 14
> UI-SPEC. No visual changes to the dialog itself — key binding extension only.

**Delete confirm prompt:**
```
Delete policy 'Confidential File Policy'? [y/n]
```

- `{name}` frozen from `PolicyList` row JSON at time `d` is pressed.
- Inline `[y/n]` hint in prompt text per ROADMAP Phase 15 verbatim.

**Confirm dialog (from draw_confirm):**

```
+- Confirm ------------------------------------------------------------+
|                                                                        |
|   Delete policy 'Confidential File Policy'? [y/n]                      |
|                                                                        |
|   [ Yes ]    [ No ]                                                    |
|                                                                        |
+------------------------------------------------------------------------+
```

- `Yes` button: `Color::Black` fg, `Color::Green` bg, `Modifier::BOLD`
- `No` button: `Color::Black` fg, `Color::Red` bg, `Modifier::BOLD`
- When `yes_selected = true`, a `>` highlight appears next to the active button
  (existing `draw_confirm` behavior).

---

## Hints Bar Extensions

### PolicyList hints (handle_policy_list)

**Old (Phase 14):** `n: new | Enter: view | Esc: back`

**Phase 15:** `n: new | e: edit | d: delete | Enter: view | Esc: back`

### PolicyEdit hints (handle_policy_edit)

**When navigating (editing = false):**
`Up/Down: navigate | Enter: edit/toggle/open | Esc: back`

**When editing text:**
`Type to edit | Enter: commit | Esc: cancel`

---

## Copywriting Contract

Deltas and extensions from Phase 14. Unchanged elements inherit Phase 14 verbatim.

| Element | Copy | Phase 15 Delta |
|---------|------|----------------|
| Block title | ` Edit Policy: {name} ` | **NEW** (Phase 14: ` Create Policy `) |
| Name label | `Name` | inherited |
| Description label | `Description` | inherited |
| Priority label | `Priority` | inherited |
| Action label | `Action` | inherited |
| Enabled label | `Enabled` | **NEW** |
| Enabled value (true) | `Yes` | **NEW** |
| Enabled value (false) | `No` | **NEW** |
| Add Conditions CTA | `[Add Conditions]` | inherited |
| Submit CTA | `[Save]` | **Changed** (Phase 14: `[Submit]`) |
| Empty field value | `(empty)` | inherited |
| Conditions row — no conditions | `No conditions added.` | inherited |
| Validation error — empty name | `Name is required.` | inherited |
| Validation error — bad priority | `Priority must be a valid integer (0 or greater).` | inherited |
| Validation error — server error | `Server error: {message}` | inherited |
| Validation error — network fail | `Network error: {message}` | inherited |
| **NEW** — Policy load failure | `Failed to load policy: {e}` | **NEW** — status bar, `StatusKind::Error` |
| Delete confirm prompt | `Delete policy '{name}'? [y/n]` | **NEW** |
| PolicyList hints | `n: new \| e: edit \| d: delete \| Enter: view \| Esc: back` | **Extended** |
| PolicyEdit hints (navigate) | `Up/Down: navigate \| Enter: edit/toggle/open \| Esc: back` | **NEW** |
| Status bar — success (edit) | `Policy '{name}' updated` | **NEW** |
| Status bar — success (delete) | `Policy '{name}' deleted` | **NEW** |
| Status bar — error | `Failed: {e}` | **NEW** (override legacy PolicyMenu redirect) |

---

## Screen Enum Addition

```rust
/// Policy edit multi-field form.
///
/// Loads an existing policy via GET /admin/policies/{id} on entry.
/// Row layout (selected index -> field):
///   0: Name         (text, required)
///   1: Description  (text, optional)
///   2: Priority     (text, parsed as u32 at submit)
///   3: Action       (select index into ACTION_OPTIONS)
///   4: Enabled      (bool toggle — Enter toggles, no edit mode)
///   5: [Add Conditions]
///   6: Conditions display (read-only summary)
///   7: [Save]
Screen::PolicyEdit {
    /// Server-side policy ID used only for PUT URL path; not rendered on form.
    id: String,
    /// All form field values and conditions, pre-populated from GET response.
    form: PolicyFormState,
    /// Index of the currently highlighted row (0..=7).
    selected: usize,
    /// Whether the selected text field is in edit mode.
    editing: bool,
    /// Text buffer for the active text field (Name, Description, Priority).
    buffer: String,
    /// Inline validation error displayed below the [Save] row.
    /// Cleared on Esc or successful submission.
    validation_error: Option<String>,
},
```

`CallerScreen` enum gains:
```rust
PolicyEdit  // round-trip destination for ConditionsBuilder modal
```

---

## Decisions Locked from Upstream Artifacts

| ID | Decision | Source |
|----|----------|--------|
| D-01 | New `Screen::PolicyEdit` variant (no shared helper with PolicyCreate) | 15-CONTEXT.md D-01 |
| D-02 | Title: `" Edit Policy: {name} "` — name from loaded policy | 15-CONTEXT.md D-02 |
| D-03 | Submit row label: `[Save]` | 15-CONTEXT.md D-03 |
| D-04 | Policy ID in Screen variant field only; not rendered | 15-CONTEXT.md D-04 |
| D-05 | Both Create and Edit forms adopt 8-row layout | 15-CONTEXT.md D-05 |
| D-06 | Enabled row: `Enabled:              Yes/No`, White when unselected, Black+Cyan+BOLD when selected | 15-CONTEXT.md D-06 |
| D-07 | Enter on Enabled row: `form.enabled = !form.enabled`, no buffer | 15-CONTEXT.md D-07 |
| D-08 | `PolicyFormState::default().enabled = true` | 15-CONTEXT.md D-08 |
| D-09 | Phase 14 Create form updated to 8 rows alongside Phase 15 | 15-CONTEXT.md D-09 |
| D-14 | `handle_confirm` extended with `Char('y')` / `Char('n')` / `Char('Y')` / `Char('N')` | 15-CONTEXT.md D-14 |
| D-15 | Delete confirm prompt: `"Delete policy '{name}'? [y/n]"` | 15-CONTEXT.md D-15 |
| D-16 | Delete success: `action_list_policies(app)`, status `"Policy '{name}' deleted"` | 15-CONTEXT.md D-16 |
| D-17 | Delete failure: status `"Failed: {e}"`, stays on PolicyList | 15-CONTEXT.md D-17 |
| D-18 | Edit success: `action_list_policies(app)`, status `"Policy '{name}' updated"` | 15-CONTEXT.md D-18 |
| D-19 | Edit validation error renders as red Paragraph below `[Save]` | 15-CONTEXT.md D-19 |
| D-21 | Esc from PolicyEdit: `action_list_policies(app)`, no confirmation | 15-CONTEXT.md D-21 |
| D-24 | `d` key wired only in `handle_policy_list` | 15-CONTEXT.md D-24 |
| D-25 | `e` → `action_load_policy_for_edit`; `d` → Confirm dialog | 15-CONTEXT.md D-25 |
| D-27 | PolicyList hints: `n: new \| e: edit \| d: delete \| Enter: view \| Esc: back` | 15-CONTEXT.md D-27 |

---

## Inherited Elements (Phase 14 UI-SPEC — Not Re-Documented Here)

The following are inherited verbatim from Phase 14 UI-SPEC and are binding:

- **Design system:** ratatui + crossterm, color palette, spacing scale, typography
- **Highlight style:** `Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)`
- **Cursor convention:** `[{buffer}_]` for text field edit mode
- **Validation error paragraph:** `Color::Red` `Paragraph` below `[Save]`/`[Submit]`
- **`draw_hints` / `draw_status_bar`:** existing global functions; called with updated hints strings
- **`draw_confirm`:** reused as-is (key binding change only, no visual change)
- **Text input field states:** Default / Selected not editing / Selected editing / Has value
- **Conditions summary row:** read-only display, count + comma-joined summary, `Color::DarkGray` when not selected
- **Action field select:** cycles `ACTION_OPTIONS` on Enter; display labels match wire strings
- **`PolicyFormState`:** holds `name`, `description`, `priority`, `action`, `enabled`, `conditions`
- **ConditionsBuilder modal:** `CallerScreen::PolicyEdit` added for round-trip; otherwise unchanged

---

## Checker Sign-Off

- [ ] Dimension 1 Copywriting: PASS (14 copy elements defined — new CTAs, delete prompt, extended hints, status messages)
- [ ] Dimension 2 Visuals: PASS (8-row form ASCII layout, Enabled row states, 4-state table, confirm dialog, hints bar)
- [ ] Dimension 3 Color: PASS (`Color::White/DarkGray/Cyan/Red/Green` — inherited from Phase 14)
- [ ] Dimension 4 Typography: PASS (terminal default, `Modifier::BOLD` — inherited from Phase 14)
- [ ] Dimension 5 Spacing: PASS (cell-based 22-char label column, inherited from Phase 14)
- [ ] Dimension 6 Registry Safety: PASS (no external registries — TUI)

**Approval:** pending

---

## Sources

| Source | Decisions Locked |
|--------|-----------------|
| 15-CONTEXT.md | D-01–D-27 (all Phase 15 decisions) |
| Phase 14 UI-SPEC (approved 2026-04-16) | Design system, color palette, spacing scale, highlight style, cursor convention, validation error pattern, `draw_hints`, `[Submit]` CTA, form field map |
| Phase 13 UI-SPEC (approved 2026-04-16) | ConditionsBuilder modal overlay visual contract, pending list, step picker |
| ROADMAP.md Phase 15 success criteria | `e`/`d` key hints, `[y/n]` in confirm prompt, reload on success |
| REQUIREMENTS.md POLICY-03 | Edit form fields, PUT endpoint, cache invalidation scope |
| REQUIREMENTS.md POLICY-04 | Delete confirm prompt, `d` key, DELETE endpoint |