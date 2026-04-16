# Phase 14: Policy Create - Pattern Map

**Mapped:** 2026-04-16
**Files analyzed:** 4 (3 modified source files + 1 Cargo.toml)
**Analogs found:** 4 / 4

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `dlp-admin-cli/src/app.rs` | model/state | request-response | `dlp-admin-cli/src/app.rs` (AlertConfig variant) | exact |
| `dlp-admin-cli/src/screens/dispatch.rs` | controller | request-response | `dlp-admin-cli/src/screens/dispatch.rs` (handle_alert_config) | exact |
| `dlp-admin-cli/src/screens/render.rs` | component | request-response | `dlp-admin-cli/src/screens/render.rs` (draw_alert_config) | exact |
| `dlp-admin-cli/Cargo.toml` | config | — | `dlp-admin-cli/Cargo.toml` (existing deps block) | exact |

---

## Pattern Assignments

### `dlp-admin-cli/src/app.rs` — Screen variant addition + ConditionsBuilder extension

**Analogs:**
- `Screen::AlertConfig` variant (lines 213–222) — multi-field form with `selected`, `editing`, `buffer`
- `Screen::ConditionsBuilder` variant (lines 229–249) — existing modal that needs `form_snapshot` added

**Screen enum: Screen::PolicyCreate variant to add after ConditionsBuilder (after line 249):**

Existing `AlertConfig` shape to copy from (lines 213–222):
```rust
AlertConfig {
    /// Currently loaded config as a JSON object.
    config: serde_json::Value,
    /// Index of the selected row (0..=11).
    selected: usize,
    /// Whether the selected text field is in edit mode.
    editing: bool,
    /// Buffered input while editing.
    buffer: String,
},
```

New `PolicyCreate` variant follows the same shape, replacing `config: serde_json::Value`
with `form: PolicyFormState` and adding `validation_error: Option<String>`:
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
PolicyCreate {
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

**ConditionsBuilder variant: add `form_snapshot` field (line 248, before closing brace):**

Current variant ends at line 249. Add `form_snapshot` before the closing brace:
```rust
/// Snapshot of the caller's form state, restored when the modal closes.
form_snapshot: PolicyFormState,
```

The full extended variant shape becomes:
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
    /// Snapshot of the caller's form state, restored when the modal closes.
    form_snapshot: PolicyFormState,
},
```

**ACTION_OPTIONS constant to add near PolicyFormState (after line 134):**

```rust
/// Fixed action options for the policy create / edit form.
///
/// Indices match `PolicyFormState.action`. The wire strings are sent verbatim
/// in the POST body; the server's `deserialize_policy_row` accepts them
/// case-insensitively.
pub const ACTION_OPTIONS: [&str; 4] = ["ALLOW", "DENY", "AllowWithLog", "DenyWithAlert"];
```

Note: `PolicyFormState.action` field (line 129) has doc comment saying
`"ALLOW/DENY/AllowWithLog/DenyWithLog"` — update it to `DenyWithAlert`.

---

### `dlp-admin-cli/src/screens/dispatch.rs` — handle_policy_create + CallerScreen fix

**Analog:** `handle_alert_config` / `handle_alert_config_nav` / `handle_alert_config_editing`
(lines 889–1040) — exact role and data flow match.

**Imports pattern** (lines 3–8, copy existing, add `CallerScreen` and `PolicyFormState`):
```rust
use crate::app::{
    App, CallerScreen, ConditionAttribute, ConfirmPurpose, InputPurpose,
    PasswordPurpose, PolicyFormState, Screen, StatusKind, ACTION_OPTIONS, ATTRIBUTES,
};
```

**Row index constants (add near ALERT constants, lines 800–824):**
```rust
/// Row indices for the PolicyCreate form.
const POLICY_NAME_ROW: usize = 0;
const POLICY_DESC_ROW: usize = 1;
const POLICY_PRIORITY_ROW: usize = 2;
const POLICY_ACTION_ROW: usize = 3;
const POLICY_ADD_CONDITIONS_ROW: usize = 4;
const POLICY_CONDITIONS_DISPLAY_ROW: usize = 5;
const POLICY_SUBMIT_ROW: usize = 6;
/// Total rows in the form (0..=6).
const POLICY_ROW_COUNT: usize = 7;
```

**handle_event routing: add arm before the read-only views match arm (lines 31–35):**
```rust
Screen::PolicyCreate { .. } => handle_policy_create(app, key),
```

**Top-level dispatcher (copy handle_alert_config lines 889–901 pattern):**
```rust
/// Handles key events for the Policy Create form.
fn handle_policy_create(app: &mut App, key: KeyEvent) {
    // Phase 1: read-only borrow to extract guard fields.
    // This must be a separate block so the borrow ends before any &mut call.
    let (selected, editing) = match &app.screen {
        Screen::PolicyCreate { selected, editing, .. } => (*selected, *editing),
        _ => return,
    };

    if editing {
        handle_policy_create_editing(app, key, selected);
    } else {
        handle_policy_create_nav(app, key, selected);
    }
}
```

**Editing handler (copy handle_alert_config_editing lines 910–981, adapt for PolicyCreate):**

Text field rows: 0 (Name), 1 (Description), 2 (Priority). Only Enter on row 2 needs
special handling (trim + no-op commit; actual u32 parse happens at submit time).
```rust
fn handle_policy_create_editing(app: &mut App, key: KeyEvent, _selected: usize) {
    match key.code {
        KeyCode::Char(c) => {
            if let Screen::PolicyCreate { buffer, .. } = &mut app.screen {
                buffer.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Screen::PolicyCreate { buffer, .. } = &mut app.screen {
                buffer.pop();
            }
        }
        KeyCode::Enter => {
            // Commit the buffer into the relevant form field.
            // Two-phase: extract selected+buffer first, then mutate.
            let (selected, buf) = match &app.screen {
                Screen::PolicyCreate { selected, buffer, .. } => (*selected, buffer.clone()),
                _ => return,
            };
            if let Screen::PolicyCreate { form, buffer, editing, .. } = &mut app.screen {
                match selected {
                    POLICY_NAME_ROW     => form.name = buf.trim().to_string(),
                    POLICY_DESC_ROW     => form.description = buf.trim().to_string(),
                    POLICY_PRIORITY_ROW => form.priority = buf.trim().to_string(),
                    _ => {}
                }
                buffer.clear();
                *editing = false;
            }
        }
        KeyCode::Esc => {
            // Cancel edit; restore field to pre-edit value (do NOT discard form).
            if let Screen::PolicyCreate { buffer, editing, .. } = &mut app.screen {
                buffer.clear();
                *editing = false;
            }
        }
        _ => {}
    }
}
```

**Nav handler (copy handle_alert_config_nav lines 984–1040, adapt for PolicyCreate):**
```rust
fn handle_policy_create_nav(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::PolicyCreate { selected: sel, .. } = &mut app.screen {
                nav(sel, POLICY_ROW_COUNT, key.code);
            }
        }
        KeyCode::Enter => match selected {
            POLICY_SUBMIT_ROW => {
                // Two-phase borrow: clone form before calling action (Pitfall 5).
                let form = match &app.screen {
                    Screen::PolicyCreate { form, .. } => form.clone(),
                    _ => return,
                };
                action_submit_policy(app, form);
            }
            POLICY_ADD_CONDITIONS_ROW => {
                // Transition to ConditionsBuilder, carrying form_snapshot.
                let (form, sel) = match &app.screen {
                    Screen::PolicyCreate { form, selected, .. } => (form.clone(), *selected),
                    _ => return,
                };
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
                    caller: CallerScreen::PolicyCreate,
                    form_snapshot: PolicyFormState {
                        conditions: vec![],  // conditions live in pending
                        ..form
                    },
                };
                let _ = sel; // cursor position not needed in ConditionsBuilder
            }
            POLICY_ACTION_ROW => {
                // Cycle the action index (wraps at end of ACTION_OPTIONS).
                if let Screen::PolicyCreate { form, .. } = &mut app.screen {
                    form.action = (form.action + 1) % ACTION_OPTIONS.len();
                }
            }
            POLICY_CONDITIONS_DISPLAY_ROW => {
                // Read-only row; Enter does nothing (per D-17).
            }
            _ => {
                // Text field rows: enter edit mode pre-filled with current value.
                if let Screen::PolicyCreate { form, editing, buffer, .. } = &mut app.screen {
                    let pre_fill = match selected {
                        POLICY_NAME_ROW     => form.name.clone(),
                        POLICY_DESC_ROW     => form.description.clone(),
                        POLICY_PRIORITY_ROW => form.priority.clone(),
                        _ => String::new(),
                    };
                    *buffer = pre_fill;
                    *editing = true;
                }
            }
        },
        KeyCode::Esc | KeyCode::Char('q') => {
            app.screen = Screen::PolicyMenu { selected: 0 };
        }
        _ => {}
    }
}
```

**action_submit_policy (copy action_save_alert_config lines 859–875 structure,
extend with validation + UUID + POST):**
```rust
fn action_submit_policy(app: &mut App, form: PolicyFormState) {
    // Inline validation before any network call.
    if form.name.trim().is_empty() {
        if let Screen::PolicyCreate { validation_error, .. } = &mut app.screen {
            *validation_error = Some("Name is required.".to_string());
        }
        return;
    }
    let priority = match form.priority.trim().parse::<u32>() {
        Ok(p) => p,
        Err(_) => {
            if let Screen::PolicyCreate { validation_error, .. } = &mut app.screen {
                *validation_error =
                    Some("Priority must be a valid integer (0 or greater).".to_string());
            }
            return;
        }
    };

    let action_str = ACTION_OPTIONS[form.action].to_string();
    let conditions_json =
        serde_json::to_value(&form.conditions).unwrap_or(serde_json::Value::Array(vec![]));

    let payload = serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "name": form.name.trim(),
        "description": if form.description.trim().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(form.description.trim().to_string())
        },
        "priority": priority,
        "conditions": conditions_json,
        "action": action_str,
        "enabled": true,
    });

    match app
        .rt
        .block_on(app.client.post::<serde_json::Value, _>("admin/policies", &payload))
    {
        Ok(_) => {
            app.set_status("Policy created", StatusKind::Success);
            // Navigate to policy list (action_list_policies navigates + sets status).
            action_list_policies(app);
        }
        Err(e) => {
            // Display error inline; keep form on screen so user can correct.
            if let Screen::PolicyCreate { validation_error, .. } = &mut app.screen {
                *validation_error = Some(format!("{e}"));
            }
        }
    }
}
```

**CallerScreen return fix in handle_conditions_pending (line 1257) and
handle_conditions_step1 (line 1308) — replace BOTH placeholder arms:**

Both current placeholder arms (lines 1260 and 1311):
```rust
// BEFORE (placeholder):
app.screen = Screen::PolicyMenu { selected: 0 };
```

Replace both with the same CallerScreen dispatch helper — extract from the
`ConditionsBuilder` variant, then match on `caller`:
```rust
// AFTER (Phase 14 fix — identical logic in BOTH Esc arms):
let (caller, pending, form_snapshot) = match &app.screen {
    Screen::ConditionsBuilder { caller, pending, form_snapshot, .. } => {
        (*caller, pending.clone(), form_snapshot.clone())
    }
    _ => return,
};
match caller {
    CallerScreen::PolicyCreate => {
        app.screen = Screen::PolicyCreate {
            form: PolicyFormState {
                conditions: pending,
                ..form_snapshot
            },
            selected: POLICY_ADD_CONDITIONS_ROW,
            editing: false,
            buffer: String::new(),
            validation_error: None,
        };
    }
    CallerScreen::PolicyEdit => {
        // Phase 15 handles this.
        app.screen = Screen::PolicyMenu { selected: 0 };
    }
}
```

**Test module additions (after line 1716, inside existing `#[cfg(test)] mod tests`):**

Copy the arrange-act-assert pattern from existing tests (lines 1563–1715).
Add five new tests:
```rust
#[test]
fn validate_policy_form_empty_name() { /* name.trim().is_empty() -> Some(error) */ }

#[test]
fn validate_policy_priority_non_numeric() { /* priority "abc" -> Some(error) */ }

#[test]
fn action_options_wire_format() {
    assert_eq!(ACTION_OPTIONS[0], "ALLOW");
    assert_eq!(ACTION_OPTIONS[1], "DENY");
    assert_eq!(ACTION_OPTIONS[2], "AllowWithLog");
    assert_eq!(ACTION_OPTIONS[3], "DenyWithAlert");
    assert_eq!(ACTION_OPTIONS.len(), 4);
}

#[test]
fn conditions_builder_esc_restores_form() { /* CallerScreen dispatch reconstructs PolicyCreate */ }

#[test]
fn submit_builds_payload() { /* serde_json::json! shape has id, name, priority, action, enabled */ }
```

---

### `dlp-admin-cli/src/screens/render.rs` — draw_policy_create

**Analog:** `draw_alert_config` (lines 603–692) — exact role and data flow match.
Secondary analog: `draw_siem_config` (lines 511–591) for the simpler case.

**Imports pattern** (lines 3–11, copy existing):
```rust
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::app::{App, ConditionAttribute, Screen, StatusKind, ACTION_OPTIONS, ATTRIBUTES};
use crate::screens::dispatch::condition_display;
```

**draw_screen match arm to add (copy SiemConfig arm lines 111–117, adapt for PolicyCreate):**

Add after the `ConditionsBuilder` arm (after line 150):
```rust
Screen::PolicyCreate {
    form,
    selected,
    editing,
    buffer,
    validation_error,
} => {
    draw_policy_create(frame, area, form, *selected, *editing, buffer, validation_error.as_deref());
}
```

**Row label constants (add near SIEM_FIELD_LABELS at line 452):**
```rust
/// Display labels for each row in the PolicyCreate form (7 rows, indices 0–6).
const POLICY_FIELD_LABELS: [&str; 7] = [
    "Name",
    "Description",
    "Priority",
    "Action",
    "[Add Conditions]",
    "Conditions",   // suffixed dynamically with count in render fn
    "[Submit]",
];
```

**draw_policy_create function (copy draw_alert_config lines 603–692 pattern):**

The key differences from draw_alert_config:
1. Data source is `PolicyFormState` fields (not `serde_json::Value` by key)
2. Row 3 (Action) is a select-index display, not a text field
3. Row 4 ([Add Conditions]) and row 6 ([Submit]) are action-only rows (no value)
4. Row 5 (Conditions display) is read-only with count + summary
5. Validation error is rendered as an overlay `Paragraph` below the list

```rust
/// Draws the Policy Create multi-field form.
///
/// # Arguments
///
/// * `frame` - ratatui frame
/// * `area` - screen area allocated to the form
/// * `form` - current form state (fields + conditions)
/// * `selected` - index of the highlighted row (0..=6)
/// * `editing` - true when a text field is in edit mode
/// * `buffer` - text input buffer (only meaningful when `editing` is true)
/// * `validation_error` - inline error shown below Submit row, or None
fn draw_policy_create(
    frame: &mut Frame,
    area: Rect,
    form: &crate::app::PolicyFormState,
    selected: usize,
    editing: bool,
    buffer: &str,
    validation_error: Option<&str>,
) {
    // Build 7 ListItems — one per row.
    let mut items: Vec<ListItem> = Vec::with_capacity(POLICY_FIELD_LABELS.len());

    for (i, label) in POLICY_FIELD_LABELS.iter().enumerate() {
        let line = match i {
            0 => {
                // Name (text, required)
                let val = if editing && selected == 0 {
                    format!("{label}:              [{buffer}_]")
                } else if form.name.is_empty() {
                    format!("{label}:              (empty)")
                } else {
                    format!("{label}:              {}", form.name)
                };
                Line::from(val)
            }
            1 => {
                // Description (text, optional)
                let val = if editing && selected == 1 {
                    format!("{label}:       [{buffer}_]")
                } else if form.description.is_empty() {
                    format!("{label}:       (empty)")
                } else {
                    format!("{label}:       {}", form.description)
                };
                Line::from(val)
            }
            2 => {
                // Priority (numeric text)
                let val = if editing && selected == 2 {
                    format!("{label}:          [{buffer}_]")
                } else if form.priority.is_empty() {
                    format!("{label}:          (empty)")
                } else {
                    format!("{label}:          {}", form.priority)
                };
                Line::from(val)
            }
            3 => {
                // Action (select index)
                let action_label = ACTION_OPTIONS[form.action];
                Line::from(format!("{label}:            {action_label}"))
            }
            4 => {
                // [Add Conditions] action row
                Line::from(format!("  {label}"))
            }
            5 => {
                // Conditions summary (read-only)
                let n = form.conditions.len();
                if n == 0 {
                    // DarkGray empty state (per D-18)
                    Line::from(vec![
                        Span::raw(format!("{label} ({n}):    ")),
                        Span::styled("No conditions added.", Style::default().fg(Color::DarkGray)),
                    ])
                } else {
                    // Comma-separated summary of conditions
                    let summary = form
                        .conditions
                        .iter()
                        .map(|c| condition_display(c))
                        .collect::<Vec<_>>()
                        .join(", ");
                    Line::from(vec![
                        Span::raw(format!("{n} condition(s):    ")),
                        Span::styled(summary, Style::default().fg(Color::DarkGray)),
                    ])
                }
            }
            6 => {
                // [Submit] action row
                Line::from(format!("  {label}"))
            }
            _ => Line::from(""),
        };
        items.push(ListItem::new(line));
    }

    // Render list with same highlight style used by all existing TUI screens.
    let list = List::new(items)
        .block(
            Block::default()
                .title(" Create Policy ")
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = ListState::default();
    state.select(Some(selected));
    frame.render_stateful_widget(list, area, &mut state);

    // Validation error overlay below the Submit row (not a list item).
    if let Some(err) = validation_error {
        // Position: bottom-2 row (above hints bar at bottom-1).
        if area.height >= 4 {
            let err_area = Rect {
                x: area.x + 2,
                y: area.y + area.height - 2,
                width: area.width.saturating_sub(4),
                height: 1,
            };
            let err_para = Paragraph::new(err)
                .style(Style::default().fg(Color::Red));
            frame.render_widget(err_para, err_area);
        }
    }

    // Key hints bar (copy draw_siem_config lines 585–590 pattern).
    let hints = if editing {
        "Type to edit | Enter: commit | Esc: cancel"
    } else {
        "Up/Down: navigate | Enter: edit/toggle/open | Esc: back"
    };
    draw_hints(frame, area, hints);
}
```

---

### `dlp-admin-cli/Cargo.toml` — uuid dependency addition

**Analog:** Existing dependency block (lines 9–28). Pattern: `name = { version = "X", features = [...] }`

**Add after the `dlp-common` line (after line 28):**
```toml
# UUID v4 generation for caller-supplied policy IDs (POST /admin/policies requires non-empty id).
uuid = { version = "1", features = ["v4"] }
```

**Verification that `uuid` is not already present:**
Current `Cargo.toml` has no `uuid` entry (confirmed by reading lines 1–36).

---

## Shared Patterns

### Two-Phase Borrow Pattern (borrow-then-mutate)
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` lines 861–874 (`action_save_alert_config`)
**Apply to:** `action_submit_policy`, all CallerScreen Esc handlers
```rust
// Phase 1: extract needed values with a shared (&) borrow.
let payload = match &app.screen {
    Screen::AlertConfig { config, .. } => config.clone(),
    _ => return,
};
// Phase 2: borrow has ended; now safe to call &mut methods.
match app.rt.block_on(...) { ... }
```

### Navigation helper
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` lines 43–53
**Apply to:** `handle_policy_create_nav`
```rust
fn nav(selected: &mut usize, count: usize, key: KeyCode) {
    match key {
        KeyCode::Up => { *selected = selected.checked_sub(1).unwrap_or(count - 1); }
        KeyCode::Down => { *selected = (*selected + 1) % count; }
        _ => {}
    }
}
```

### Selection highlight style (all screens must match exactly)
**Source:** `dlp-admin-cli/src/screens/render.rs` lines 707–712 and 673–679
**Apply to:** `draw_policy_create` list widget
```rust
Style::default()
    .fg(Color::Black)
    .bg(Color::Cyan)
    .add_modifier(Modifier::BOLD)
```

### draw_hints call convention
**Source:** `dlp-admin-cli/src/screens/render.rs` lines 915–928
**Apply to:** `draw_policy_create`
```rust
// draw_hints renders a DarkGray line at area.y + area.height - 1.
// Passed area must be the full screen area, not a sub-rect.
draw_hints(frame, area, hints);
```

### Status-bar success/error pattern
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` lines 868–875 (`action_save_alert_config`)
**Apply to:** `action_submit_policy`
```rust
Ok(_) => {
    app.set_status("Alert config saved", StatusKind::Success);
    app.screen = Screen::SystemMenu { selected: 3 };
}
Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
```

### Test module location and pattern
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` lines 1559–1716
**Apply to:** New tests for Phase 14 (add to same `#[cfg(test)] mod tests` block)
```rust
#[cfg(test)]
mod tests {
    use super::*;  // wildcard import OK in test modules per CLAUDE.md

    #[test]
    fn descriptive_test_name() {
        // Arrange
        // Act
        // Assert
    }
}
```

---

## No Analog Found

All files have direct analogs. No files require falling back to RESEARCH.md patterns.

---

## Critical Notes for Planner

1. **`app.rs` borrow note:** `Screen::ConditionsBuilder` adding `form_snapshot: PolicyFormState`
   changes the variant's field count. All existing construction sites of `ConditionsBuilder`
   (line 168 in dispatch.rs — the temporary `'c'` key test entry point) must be updated
   to supply `form_snapshot: PolicyFormState::default()`.

2. **Two Esc code paths in dispatch.rs** must BOTH be updated:
   - `handle_conditions_pending` Esc arm at line 1257
   - `handle_conditions_step1` Esc arm at line 1308
   Both currently contain the exact placeholder comment "Phase 14/15 will use CallerScreen."

3. **Temporary test entry point** at dispatch.rs line 165 (`KeyCode::Char('c')`) needs
   `form_snapshot: PolicyFormState::default()` added once `ConditionsBuilder` is extended.
   The TODO comment on line 164 can be removed or converted to the real `PolicyCreate` entry.

4. **`condition_display` function** is already `pub` in dispatch.rs (imported by render.rs
   line 12). The import `use crate::screens::dispatch::condition_display;` is already present
   in render.rs and is reused in `draw_policy_create`.

5. **`PolicyFormState` doc comment** in app.rs line 128 says `"ALLOW/DENY/AllowWithLog/DenyWithLog"`.
   This must be corrected to `"DenyWithAlert"` (not DenyWithLog) when adding `ACTION_OPTIONS`.

---

## Metadata

**Analog search scope:** `dlp-admin-cli/src/` (app.rs, screens/dispatch.rs, screens/render.rs, Cargo.toml)
**Files scanned:** 4 source files read in full
**Pattern extraction date:** 2026-04-16
