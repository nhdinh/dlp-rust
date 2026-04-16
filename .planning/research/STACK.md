# Technology Stack — v0.4.0 Policy Authoring TUI

**Project:** dlp-rust / dlp-admin-cli
**Milestone:** v0.4.0 Policy Authoring
**Researched:** 2026-04-16
**Scope:** Stack additions for TUI policy create/edit, condition builder, simulate, and import/export

---

## Verdict

Two additions to `dlp-admin-cli/Cargo.toml` cover everything needed. No ratatui upgrade required. No new framework needed — the existing screen state-machine pattern handles all new screens.

---

## Additions Required

### 1. `tui-textarea = "0.7"` — Multi-field text input

**Why needed:** POLICY-02, POLICY-03, POLICY-06 all require multi-field forms with real text editing (cursor movement, backspace, paste). The existing `TextInput` screen stores raw `String` + appends characters via `KeyCode::Char(c)` — it has no cursor positioning, no emacs shortcuts, and no copy-paste. For the EvaluateRequest simulate form (6+ fields) and the policy create/edit form (name, description, priority, etc.) this becomes unusable.

**Why tui-textarea 0.7 specifically (not ratatui-textarea 0.9):**

| Crate | Ratatui req | Crossterm req | Project match |
|-------|-------------|---------------|---------------|
| `tui-textarea` 0.7 (rhysd) | `^0.29.0` | `^0.28` | **EXACT MATCH** |
| `ratatui-textarea` 0.9 (ratatui org) | `ratatui-core ^0.1` (= 0.30+) | `^0.29` | Requires upgrade |
| `tui-input` 0.15 | `0.30.0` | N/A | Requires upgrade |

Using `ratatui-textarea` or `tui-input` would force a ratatui 0.29 → 0.30 upgrade. Ratatui 0.30 renamed `Alignment` to `HorizontalAlignment`, changed `Flex` enum variants, changed `Style::reset()`, and bumped MSRV to 1.86.0. That is a non-trivial migration with no v0.4.0 value — it introduces risk for unrelated changes. Use `tui-textarea` 0.7.

**How it integrates:** `TextArea::new(vec![initial_value])` creates a single-line input. In the event loop, pass `crossterm::event::KeyEvent` directly via `textarea.input(key_event.into())`. Suppress `Enter` and `Ctrl+M` to keep single-line behavior. Retrieve text with `textarea.lines()[0].clone()`. The existing `crossterm` 0.28 backend is already the default feature for this crate.

**Usage for masked password fields:** `tui-textarea` does not natively support masked input. The existing `PasswordInput` screen already uses a custom approach (stores chars, renders asterisks) — keep that pattern for password fields.

```toml
# dlp-admin-cli/Cargo.toml
tui-textarea = { version = "0.7", features = ["crossterm"] }
```

**Confidence:** HIGH — verified via rhysd/tui-textarea Cargo.toml showing exact `ratatui = "0.29.0"` and `crossterm = "0.28"` dep specs.

---

### 2. `toml = "0.8"` — Policy file import/export

**Why needed:** POLICY-07 (export) and POLICY-08 (import) require serializing/deserializing the full policy set to a file. `serde_json` is already in the project and could handle this, but TOML is strongly preferred for policy files that admins read and edit by hand.

**TOML vs JSON for policy files:**

| Criterion | TOML | JSON |
|-----------|------|------|
| Human readability | High — key = value, comments allowed | Low — brackets, no comments |
| Admin editability | Yes — admins can add comments, edit values clearly | Error-prone — missing commas, quoting issues |
| Serde support | `toml::to_string_pretty()` / `toml::from_str()` | Already in project |
| Rust ecosystem | Standard config format (Cargo.toml, agent-config.toml) | Standard API wire format |
| Conflict with existing | None — agent already uses `toml = "0.8"` | Would reuse serde_json |

**Decision:** Use TOML for export/import. It matches the existing agent-config.toml format (admins already have mental model), supports comments for policy documentation, and is readable without tooling. JSON export is a secondary option accessed via `serde_json::to_string_pretty()` — no additional dependency needed for that path.

**Version note:** The `toml` crate has released 1.0.x (latest: `1.0.6+spec-1.1.0` as of 2026). However, `dlp-agent` already pins `toml = "0.8"`. To avoid a workspace dependency split, use `"0.8"` in `dlp-admin-cli` as well, and move it to `[workspace.dependencies]` so both crates share the same resolution.

```toml
# workspace Cargo.toml — add to [workspace.dependencies]
toml = "0.8"

# dlp-admin-cli/Cargo.toml
toml.workspace = true
```

**Confidence:** HIGH — toml 0.8 ships `toml::to_string_pretty`, `toml::from_str`, full serde integration. Already validated in dlp-agent.

---

## No-Addition Decisions

### Popup/dialog overlay — use built-in ratatui pattern

`tui-popup` (now inside `tui-widgets`) requires ratatui 0.30. The official ratatui popup example shows the built-in pattern: render `Clear` widget over a centered `Rect`, then render the popup content. This is two lines of code:

```rust
let popup_area = frame.area().inner(Margin { horizontal: 10, vertical: 5 });
frame.render_widget(Clear, popup_area);
// then render Block + content inside popup_area
```

The existing `SiemConfig` and `AlertConfig` screens already handle multi-field editing without popup crates. Apply the same pattern to `PolicyCreate`, `PolicyEdit`, and `Simulate` screens.

**Decision:** No external popup crate. Use `Clear` + centered layout. Add a `centered_rect(percent_x, percent_y, r: Rect) -> Rect` helper in `screens/render.rs` (10 lines; standard ratatui recipe).

### Multi-select / dropdown — use ratatui built-in `List`

The condition builder (POLICY-05) needs a pick-list for attribute (`Classification`, `MemberOf`, `DeviceTrust`, `NetworkLocation`, `AccessContext`) and operator (`Equals`, `NotEquals`, `Contains`, etc.). Ratatui's built-in `List` widget with `ListState` is sufficient — it already drives `PolicyList` and `AgentList` screens. No external widget crate needed.

The condition builder UX maps cleanly to the existing screen state-machine:

```
ConditionBuilder {
    step: BuilderStep,          // Attribute | Operator | Value
    attribute_list: ListState,
    operator_list: ListState,
    value_input: TextArea,      // tui-textarea for value entry
    conditions: Vec<PolicyCondition>,
}
```

**Decision:** No `ratatui-interact`, no `rat-widget`, no `ratatui-form`. The existing `List` + new `TextArea` covers all required widgets.

### Form framework — custom screens, not a form library

Libraries like `ratatui-form` or `ratatui-interact` impose opinionated navigation models that conflict with the existing `Screen` enum state-machine. The project already handles `SiemConfig` (7-field form) and `AlertConfig` (10-field form) without any form library. Apply the same `selected: usize` row-cursor + `editing: bool` pattern.

**Decision:** No form library. Policy create/edit screens follow the `SiemConfig`/`AlertConfig` pattern exactly.

---

## Complete Dependency Delta for dlp-admin-cli

```toml
# Additions only — existing dependencies unchanged
tui-textarea = { version = "0.7", features = ["crossterm"] }
toml.workspace = true          # toml = "0.8" moved to workspace

# Also add to [workspace.dependencies] in root Cargo.toml:
# toml = "0.8"
```

---

## Integration Points with Existing Setup

| New capability | Integrates with | How |
|---------------|-----------------|-----|
| `TextArea` widgets | `crossterm::event::KeyEvent` | Cast via `.into()` from existing event loop in `event.rs` |
| `TextArea` widgets | `screens/render.rs` | Call `frame.render_widget(textarea.widget(), area)` — same as any other `Widget` |
| `TextArea` widgets | `screens/dispatch.rs` | Add `Screen::PolicyCreate { textarea_name, textarea_desc, ... }` variants with `TextArea` fields |
| `toml::to_string_pretty` | `client.rs` | After fetching policy list via GET /admin/policies, serialize to `PolicyExportFile` struct |
| `toml::from_str` | `client.rs` | Deserialize import file, then POST each policy to /admin/policies |
| `centered_rect` helper | `screens/render.rs` | New private fn, used by condition builder and simulate overlay |

---

## Ratatui Upgrade Assessment

**Recommendation: Do NOT upgrade to ratatui 0.30 for v0.4.0.**

The tui-textarea 0.7 crate provides everything needed without upgrading. Ratatui 0.30 introduces `Alignment` → `HorizontalAlignment` rename, `Flex` enum variant changes, backend API changes, and MSRV bump to 1.86.0. These changes touch render.rs, dispatch.rs, and potentially all screen rendering code. The risk/reward ratio is negative for this milestone. Defer to a dedicated v0.5.0 "dependency maintenance" phase if 0.30 features (modular crates, new backends) are later needed.

**Confidence:** HIGH — confirmed via rhysd Cargo.toml and ratatui 0.30 breaking changes page.

---

## Sources

- [tui-textarea rhysd/Cargo.toml — ratatui 0.29 + crossterm 0.28 deps confirmed](https://github.com/rhysd/tui-textarea/blob/main/Cargo.toml)
- [tui-textarea 0.7.0 docs — single-line usage pattern](https://docs.rs/tui-textarea/0.7.0/tui_textarea/)
- [ratatui-textarea ratatui/Cargo.toml — ratatui-core 0.1 (= 0.30+) confirmed](https://github.com/ratatui/ratatui-textarea/blob/main/Cargo.toml)
- [tui-input Cargo.toml — ratatui 0.30.0 required](https://github.com/sayanarijit/tui-input/blob/main/Cargo.toml)
- [ratatui v0.30.0 highlights and breaking changes](https://ratatui.rs/highlights/v030/)
- [ratatui popup built-in pattern](https://ratatui.rs/examples/apps/popup/)
- [ratatui JSON editor tutorial — multi-field popup editing pattern](https://ratatui.rs/tutorials/json-editor/ui-editing/)
- [tui-widgets Cargo.toml — ratatui 0.30 required](https://github.com/ratatui/tui-widgets/blob/main/Cargo.toml)
- [toml crate 1.0.6+spec-1.1.0 — latest stable](https://docs.rs/toml/latest/toml/)
