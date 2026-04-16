# Phase 13: Conditions Builder - Pattern Map

**Mapped:** 2026-04-16
**Files analyzed:** 3 (app.rs, dispatch.rs, render.rs — all modified, no new files)
**Analogs found:** 3 / 3

---

## File Classification

| Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---------------|------|-----------|----------------|---------------|
| `dlp-admin-cli/src/app.rs` | model / state | event-driven | `app.rs` — `SiemConfig` / `AlertConfig` variants | exact |
| `dlp-admin-cli/src/screens/dispatch.rs` | controller | event-driven | `handle_siem_config` + `handle_alert_config` in dispatch.rs | exact |
| `dlp-admin-cli/src/screens/render.rs` | component | event-driven | `draw_siem_config` + `draw_confirm` in render.rs | exact |

---

## Pattern Assignments

### `dlp-admin-cli/src/app.rs` — Screen enum extension + PolicyFormState struct + ConditionAttribute enum

**Analog:** Existing `Screen::SiemConfig` / `Screen::AlertConfig` variants (lines 109–140)

**Imports pattern — no change needed.** `app.rs` has no imports today (only `use crate::client::EngineClient`). New types require adding `dlp_common::abac::PolicyCondition` in the variant. Import it inline inside the variant definition via the full path `dlp_common::abac::PolicyCondition` to keep `app.rs` free of top-level use statements for workspace crates, matching the current style.

**Existing Screen variant pattern** (`app.rs` lines 109–140):
```rust
SiemConfig {
    /// Currently loaded config as a JSON object.
    config: serde_json::Value,
    /// Index of the selected row (0..=8).
    selected: usize,
    /// Whether the selected text field is in edit mode.
    editing: bool,
    /// Buffered input while editing.
    buffer: String,
},
AlertConfig {
    config: serde_json::Value,
    selected: usize,
    editing: bool,
    buffer: String,
},
```

**New Screen variant to add** (after `AlertConfig`):
```rust
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
},
```

**Key deviation from SiemConfig analog:** Two `ListState` fields instead of one `selected: usize` — because the modal has two independently scrollable areas. The `ratatui::widgets::ListState` path must be fully qualified since `render.rs` imports `ListState` but `app.rs` does not.

**New helper enum to add** (above `Screen` enum):
```rust
/// The five ABAC condition attributes available in the conditions builder.
///
/// Used across Step 1 display, Step 2 operator lookup, Step 3 value-picker
/// branching, and `PolicyCondition` construction. A dedicated enum avoids
/// repeated string comparisons and enables exhaustive matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionAttribute {
    Classification,
    MemberOf,
    DeviceTrust,
    NetworkLocation,
    AccessContext,
}
```

**New PolicyFormState struct to add** (in `app.rs`):
```rust
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
    /// Index into the Decision enum options list.
    pub action: usize,
    pub enabled: bool,
    pub conditions: Vec<dlp_common::abac::PolicyCondition>,
}
```

**StatusKind pattern** for error reporting (`app.rs` line 172–175):
```rust
pub fn set_status(&mut self, msg: impl Into<String>, kind: StatusKind) {
    self.status = Some((msg.into(), kind));
}
// Usage in dispatch.rs:
app.set_status("...", StatusKind::Error);
```

---

### `dlp-admin-cli/src/screens/dispatch.rs` — handle_conditions_builder + branch in handle_event

**Analog:** `handle_siem_config` / `handle_alert_config` (lines 678–1020) and the `nav` helper (lines 39–49)

**handle_event routing pattern** (`dispatch.rs` lines 9–32):
```rust
pub fn handle_event(app: &mut App, event: AppEvent) {
    let key = match event {
        AppEvent::Key(k) if k.kind == KeyEventKind::Press => k,
        _ => return,
    };

    match &app.screen {
        Screen::MainMenu { .. } => handle_main_menu(app, key),
        // ... existing branches ...
        Screen::AlertConfig { .. } => handle_alert_config(app, key),
        // ADD:
        Screen::ConditionsBuilder { .. } => handle_conditions_builder(app, key),
        // ...
    }
}
```

**nav helper** (`dispatch.rs` lines 39–49) — copy verbatim, do not rewrite:
```rust
fn nav(selected: &mut usize, count: usize, key: KeyCode) {
    match key {
        KeyCode::Up => {
            *selected = selected.checked_sub(1).unwrap_or(count - 1);
        }
        KeyCode::Down => {
            *selected = (*selected + 1) % count;
        }
        _ => {}
    }
}
```

**Borrow-split avoidance pattern** (`dispatch.rs` lines 695–730 — the SiemConfig editing handler):
```rust
fn handle_siem_config_editing(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Char(c) => {
            if let Screen::SiemConfig { buffer, .. } = &mut app.screen {
                buffer.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Screen::SiemConfig { buffer, .. } = &mut app.screen {
                buffer.pop();
            }
        }
        KeyCode::Enter => {
            if let Screen::SiemConfig { config, buffer, editing, .. } = &mut app.screen {
                // ... commit buffer ...
                *editing = false;
            }
        }
        KeyCode::Esc => {
            if let Screen::SiemConfig { buffer, editing, .. } = &mut app.screen {
                buffer.clear();
                *editing = false;
            }
        }
        _ => {}
    }
}
```
Apply the same pattern for `handle_conditions_builder`: read `step` and `pending_focused` first with a shared borrow, then use `if let Screen::ConditionsBuilder { ... } = &mut app.screen { }` blocks to mutate individual fields.

**Two-phase read-then-mutate pattern** (`dispatch.rs` lines 679–692 — SiemConfig outer handler):
```rust
fn handle_siem_config(app: &mut App, key: KeyEvent) {
    // Phase 1: read scalar flags with a shared borrow.
    let (selected, editing) = match &app.screen {
        Screen::SiemConfig { selected, editing, .. } => (*selected, *editing),
        _ => return,
    };
    // Phase 2: route to sub-handler that holds mutable borrow.
    if editing {
        handle_siem_config_editing(app, key, selected);
    } else {
        handle_siem_config_nav(app, key, selected);
    }
}
```
For `handle_conditions_builder`, read `step` and `pending_focused` in Phase 1, then route to `handle_conditions_builder_picker` or `handle_conditions_builder_pending` in Phase 2.

**Operator lookup table pattern** (static array, no analog in codebase — implement as):
```rust
/// Returns the operators available for the given attribute.
///
/// Tuple: `(operator_name, is_enforced)`. Currently all attributes have only
/// `"eq"` as an enforced operator; additional operators are reserved for v0.5.0.
fn operators_for(attr: ConditionAttribute) -> &'static [(&'static str, bool)] {
    match attr {
        ConditionAttribute::Classification  => &[("eq", true)],
        ConditionAttribute::MemberOf        => &[("eq", true)],
        ConditionAttribute::DeviceTrust     => &[("eq", true)],
        ConditionAttribute::NetworkLocation => &[("eq", true)],
        ConditionAttribute::AccessContext   => &[("eq", true)],
    }
}
```

**PolicyCondition construction pattern** (verified against `abac.rs` lines 216–247):
```rust
fn build_condition(
    attr: ConditionAttribute,
    op: &str,
    picker_selected: usize,
    buffer: &str,
) -> Option<dlp_common::abac::PolicyCondition> {
    use dlp_common::abac::{AccessContext, DeviceTrust, NetworkLocation, PolicyCondition};
    // NOTE: Classification is at dlp_common root, NOT dlp_common::abac::Classification.
    use dlp_common::Classification;

    let op = op.to_string();
    Some(match attr {
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
            // CRITICAL: MemberOf uses group_sid: String, NOT value.
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

**Condition display string pattern** (verified against `abac.rs` + `classification.rs`):
```rust
fn condition_display(cond: &dlp_common::abac::PolicyCondition) -> String {
    use dlp_common::abac::PolicyCondition;
    match cond {
        // Classification implements Display (classification.rs line 50).
        PolicyCondition::Classification { op, value } =>
            format!("Classification {op} {value}"),
        // MemberOf uses group_sid, not value (abac.rs line 226).
        PolicyCondition::MemberOf { op, group_sid } =>
            format!("MemberOf {op} {group_sid}"),
        // DeviceTrust/NetworkLocation/AccessContext implement Debug only.
        PolicyCondition::DeviceTrust { op, value } =>
            format!("DeviceTrust {op} {value:?}"),
        PolicyCondition::NetworkLocation { op, value } =>
            format!("NetworkLocation {op} {value:?}"),
        PolicyCondition::AccessContext { op, value } =>
            format!("AccessContext {op} {value:?}"),
    }
}
```

**Test module pattern** (`dispatch.rs` lines 1022–1055):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_menu_has_alert_config() {
        assert_eq!(ALERT_KEYS.len(), 10, "10 editable fields");
        // ... constant verification tests ...
    }
}
```
Add a `#[cfg(test)]` module at the bottom of dispatch.rs testing `build_condition`, `operators_for`, step-back navigation, and pending list delete. Test dispatch logic (state mutation), not render functions (no terminal needed for tests).

---

### `dlp-admin-cli/src/screens/render.rs` — draw_conditions_builder + draw_screen branch

**Analog 1:** `draw_confirm` (lines 425–462) — modal overlay geometry, mixed Span styles, hints bar

**Analog 2:** `draw_siem_config` / `draw_alert_config` (lines 189–370) — List + ListState stateful rendering, buffer cursor display pattern, hints routing

**Analog 3:** `draw_hints` (lines 593–606) — `Clear` widget, DarkGray paragraph overlay

**draw_screen branch pattern** (`render.rs` lines 26–127) — add after `AlertConfig` arm:
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

**Import block** (`render.rs` lines 1–11) — no changes needed; all required widgets already imported:
```rust
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table, Wrap,
};
use ratatui::Frame;
use crate::app::{App, Screen, StatusKind};
```
Add `ConditionAttribute` to the `use crate::app` import.

**Modal overlay geometry pattern** (derived from `draw_hints` lines 597–605 + `draw_confirm` lines 453–455):
```rust
fn draw_conditions_builder(frame: &mut Frame, area: Rect, /* fields */) {
    // Full-frame Clear to overlay parent content (matches draw_hints pattern).
    frame.render_widget(Clear, area);

    // Center a 60%-width, 22-row modal box.
    let modal_width = area.width * 60 / 100;
    let modal_height = 22_u16;
    let modal_x = area.x + (area.width.saturating_sub(modal_width)) / 2;
    let modal_y = area.y + (area.height.saturating_sub(modal_height)) / 2;
    let modal_area = Rect {
        x: modal_x,
        y: modal_y,
        width: modal_width,
        height: modal_height,
    };

    let modal_block = Block::default()
        .title(" Conditions Builder ")
        .borders(Borders::ALL);
    frame.render_widget(modal_block.clone(), modal_area);

    // CRITICAL: use block.inner() to get area inside the border (not manual -1).
    let inner = modal_block.inner(modal_area);

    // Split inner area per UI-SPEC: header=2, pending=6, divider=1, picker=12, hints=1.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),   // header / breadcrumb
            Constraint::Length(6),   // pending list
            Constraint::Length(1),   // divider
            Constraint::Min(0),      // step picker (fills remaining)
        ])
        .split(inner);

    // Draw hints inside the modal (not the full frame area).
    draw_hints(frame, modal_area, "Up/Down Navigate  Enter: Add  Esc: Back/Close");
}
```

**Breadcrumb header pattern** (derived from `draw_confirm` lines 443–451 mixed-Span `Line`):
```rust
fn build_breadcrumb(step: u8, selected_attribute: Option<&ConditionAttribute>) -> Line<'static> {
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

**List + ListState stateful render pattern** (`render.rs` lines 245–261 from `draw_siem_config`):
```rust
let list = List::new(items)
    .block(Block::default().title(" ... ").borders(Borders::ALL))
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
```
For the conditions builder, the `ListState` is passed in as `&mut pending_state` / `&mut picker_state` — do NOT create a new `ListState::default()` for these; use the ones stored in the `Screen` variant so scroll position is preserved across renders.

**Buffer cursor display pattern** (`render.rs` line 212 from `draw_siem_config`):
```rust
// When editing a text field, show buffer with trailing cursor marker.
let display = format!("[{buffer}_]");
```
Used for MemberOf Step 3 value input.

**Empty state Paragraph pattern** (new — no analog in codebase; consistent with DarkGray style):
```rust
let empty = Paragraph::new(
    Line::from("No conditions added. Use the picker below to add conditions.")
        .style(Style::default().fg(Color::DarkGray))
);
frame.render_widget(empty, pending_area);
```

**draw_hints inside modal — pass modal_area, not frame area** (`render.rs` lines 593–606):
```rust
fn draw_hints(frame: &mut Frame, area: Rect, hints: &str) {
    if area.height < 3 {
        return;
    }
    let hint_area = Rect {
        x: area.x + 1,
        y: area.y + area.height - 1,   // bottom row of whichever area is passed
        width: area.width.saturating_sub(2),
        height: 1,
    };
    frame.render_widget(Clear, hint_area);
    let line = Paragraph::new(Line::from(hints).style(Style::default().fg(Color::DarkGray)));
    frame.render_widget(line, hint_area);
}
```
Pass `modal_area` (the full modal `Rect` including border) to `draw_hints` so the hint bar renders at `modal_area.y + modal_area.height - 1` (bottom of modal), not at the bottom of the terminal.

---

## Shared Patterns

### Selection Highlight Style
**Source:** `dlp-admin-cli/src/screens/render.rs` lines 251–255 (used in `draw_siem_config`, `draw_alert_config`, `draw_menu`, `draw_policy_list`, `draw_agent_list`)
**Apply to:** Step picker list, pending conditions list
```rust
Style::default()
    .fg(Color::Black)
    .bg(Color::Cyan)
    .add_modifier(Modifier::BOLD)
```

### Hint Bar
**Source:** `dlp-admin-cli/src/screens/render.rs` lines 593–606 (`draw_hints`)
**Apply to:** `draw_conditions_builder` — pass `modal_area` as the area argument
```rust
draw_hints(frame, modal_area, "Up/Down Navigate  Enter: Add  Esc: Back/Close");
```

### Error Reporting
**Source:** `dlp-admin-cli/src/app.rs` lines 172–175 (`set_status`)
**Apply to:** `handle_conditions_builder` — empty MemberOf buffer, invalid state
```rust
app.set_status("AD group SID cannot be empty", StatusKind::Error);
```

### Esc to Return Parent Screen
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` lines 109, 159, 183 (all menu Esc handlers)
**Apply to:** `handle_conditions_builder` Esc at Step 1
```rust
// Pattern: on Esc, set app.screen to the logical parent screen.
KeyCode::Esc => {
    app.screen = Screen::PolicyMenu { selected: 0 }; // placeholder until Phase 14/15
}
```
When Phase 14/15 exist, the `ConditionsBuilder` variant will need a `caller` discriminant field to know which parent to return to. Define it now as `Screen::PolicyMenu { selected: 0 }` as a temporary stand-in.

### ListState Scroll Reset After Step Transition
**Source:** No codebase analog — new pattern required
**Apply to:** `handle_conditions_builder` on every step transition (1→2, 2→3, and reset to 1 after condition add)
```rust
// After any step change, reset picker_state to top of new list.
if let Screen::ConditionsBuilder { picker_state, .. } = &mut app.screen {
    picker_state.select(Some(0));
}
```

---

## No Analog Found

No files fall into this category. All three modified files have strong existing analogs in the codebase. The only truly novel sub-patterns (operator lookup table, `build_condition`, `condition_display`, dual `ListState`) have been documented above with their implementation contracts.

---

## Critical Implementation Notes (Verified Against Source)

| Issue | Verified Source | Rule |
|-------|----------------|------|
| `MemberOf` field is `group_sid`, not `value` | `abac.rs` line 226 | Use `PolicyCondition::MemberOf { op, group_sid }` only |
| `Classification` import path is `dlp_common::Classification`, not `dlp_common::abac::Classification` | `abac.rs` line 222 uses `crate::Classification`; root re-export confirmed | Import from crate root |
| `DeviceTrust` / `NetworkLocation` have `#[serde(rename_all = "PascalCase")]` | `abac.rs` lines 86–87, 100–101 | Variant names serialize as `"Managed"`, `"CorporateVpn"`, etc. |
| `AccessContext` has `#[serde(rename_all = "lowercase")]` | `abac.rs` line 39 | Serializes as `"local"` / `"smb"` |
| `Classification` has `#[serde(rename_all = "UPPERCASE")]` | `classification.rs` line 17 | Serializes as `"T1"` / `"T3"` etc. |
| `DeviceTrust` / `NetworkLocation` / `AccessContext` implement `Debug` but NOT `Display` | `abac.rs` — no `impl Display` | Use `{value:?}` in condition display strings |
| `Classification` implements `Display` via `.label()` | `classification.rs` lines 50–53 | Use `{value}` (expands to "Public", "Confidential", etc.) |
| `Block::inner()` must be called on the block variable to get interior area | ratatui 0.29 API; pattern consistent with render.rs | Never manually subtract 1 from border coords |
| Two separate `ListState` fields required | dispatch.rs uses separate `state` per list (e.g., `PolicyList`, `AgentList`) | `pending_state` and `picker_state` are independent |

---

## Metadata

**Analog search scope:** `dlp-admin-cli/src/app.rs`, `dlp-admin-cli/src/screens/dispatch.rs`, `dlp-admin-cli/src/screens/render.rs`, `dlp-common/src/abac.rs`, `dlp-common/src/classification.rs`
**Files scanned:** 5
**Pattern extraction date:** 2026-04-16
