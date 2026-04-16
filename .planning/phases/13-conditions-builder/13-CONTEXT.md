# Phase 13: Conditions Builder - Context

**Gathered:** 2026-04-16
**Status:** Ready for planning

<domain>
## Phase Boundary

Provide a 3-step sequential picker in the admin TUI for building typed `PolicyCondition` lists — Attribute → Operator → Value — with no raw JSON entry. The picker is opened from the Policy Create form (Phase 14) and Policy Edit form (Phase 15) via an "Add Conditions" button. Completed conditions are accumulated in a pending list and returned to the caller form as a `Vec<PolicyCondition>` via the `PolicyFormState` struct (no borrow-split issues).

</domain>

<decisions>
## Implementation Decisions

### Entry Point
- **D-01:** The conditions builder is a **modal overlay** — a centered box drawn on top of the parent form using ratatui's `Clear` + constrained `Layout`. The parent form remains visible but dimmed behind the modal.
- **D-02:** The modal is opened from the Policy Create/Edit form via an "Add Conditions" button/key accessible from the conditions section of the form.
- **D-03:** `PolicyFormState` struct (already decided in STATE.md 2026-04-16) holds all form fields and the conditions list, eliminating borrow-split when the modal returns `Vec<PolicyCondition>` to the caller.

### Modal UX
- **D-04:** The modal contains **both** the step picker (Steps 1→2→3) and the inline pending-conditions list. Both are visible simultaneously while the modal is open.
- **D-05:** After completing Step 3 (Enter on a value), the condition is appended to the pending list and the picker resets to Step 1 for the next condition. The pending list scrolls independently.
- **D-06:** **Esc at Step 1** (or a "Close" button when no step is active) dismisses the modal. The pending conditions list is preserved in `PolicyFormState` — reopening the builder from the same form session shows all previously added conditions.
- **D-07:** Each condition in the pending list has a **delete binding** (`d` key) to remove it. No in-place edit in v0.4.0 (delete-and-recreate pattern per POLICY-F2 deferred).

### Conditions Data Model
- **D-08:** `PolicyCondition` variants from `dlp-common::abac.rs` are the authoritative types. Conditions are accumulated as `Vec<dlp_common::abac::PolicyCondition>` in `PolicyFormState`.
- **D-09:** All conditions are evaluated as implicit AND (documented in REQUIREMENTS.md § POLICY-05). NOT/OR boolean logic deferred to v0.5.0.

### Operators
- **D-10:** Operators are derived dynamically per attribute type from a lookup table. Only `eq` is enforced by the ABAC engine today — other operators may be shown with a "not yet enforced" annotation (per REQUIREMENTS.md § Open Design Decisions).
  - Classification → `eq`
  - MemberOf → `eq`
  - DeviceTrust → `eq`
  - NetworkLocation → `eq`
  - AccessContext → `eq`

### Step 3 Value Picker (typed per attribute)
- **D-11:** Classification → T1/T2/T3/T4 select (4 options)
- **D-12:** MemberOf → free-text input (AD group SID)
- **D-13:** DeviceTrust → 4-option select (Managed / Unmanaged / Compliant / Unknown)
- **D-14:** NetworkLocation → 4-option select (Corporate / CorporateVpn / Guest / Unknown)
- **D-15:** AccessContext → 2-option select (Local / Smb)

### Step Navigation
- **D-16:** Up/Down arrows navigate the current step's options list.
- **D-17:** Enter advances to the next step.
- **D-18:** Esc steps back: from Step 3 → Step 2 → Step 1 → modal close.

### Empty State
- **D-19:** When the pending list is empty (no conditions yet), the pending list area shows a muted placeholder: "No conditions added. Use the picker below to add conditions." This makes the pending list area non-abandoned and signals the modal's purpose clearly.

### Keyboard Summary (within modal)
- Up/Down: navigate current step options
- Enter: advance step / confirm value / add to pending list
- Esc: step back (Step 3→2→1) or close modal (at Step 1)
- d/Delete: delete selected condition from pending list
- Esc from the parent form while modal is open closes the modal (not the form)

### Key Constraints
- No raw JSON entry at any step
- No in-place condition editing (delete-and-recreate in v0.4.0)
- No AND/OR/NOT grouping (deferred to v0.5.0)
- All serde via `#[serde(tag = "attribute")]`: PolicyCondition serializes to e.g. `{"attribute":"classification","op":"eq","value":"T3"}`

### Claude's Discretion
- Exact color/style of the modal box (uses existing TUI color scheme)
- Specific key hint labels (e.g., "Enter: add" vs "Enter: next")
- Scroll behavior for the pending list (mouse scroll vs arrow-only)
- Empty state copy (placeholder text wording)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Core Types
- `dlp-common/src/abac.rs` — PolicyCondition enum (5 variants with serde tags), Policy struct, Decision enum, Classification enum (T1-T4), DeviceTrust, NetworkLocation, AccessContext
- `dlp-admin-cli/src/app.rs` — Screen enum (existing variants), PolicyFormState struct pattern, InputPurpose enum
- `dlp-admin-cli/src/screens/dispatch.rs` — handle_event routing, key handling patterns, action_* function conventions
- `dlp-admin-cli/src/screens/render.rs` — draw_siem_config / draw_alert_config (row-nav form patterns), draw_confirm (modal pattern), draw_policy_list (stateful table pattern)

### Requirements
- `dlp-common/src/abac.rs` § PolicyCondition serde — `#[serde(tag = "attribute", rename_all = "snake_case")]` is authoritative for JSON shape
- `.planning/REQUIREMENTS.md` § POLICY-05 — authoritative spec for step behavior
- `.planning/REQUIREMENTS.md` § Open Design Decisions — operator display annotation requirement
- `.planning/STATE.md` — PolicyFormState struct decision (2026-04-16)
- `.planning/ROADMAP.md` § Phase 13 — goal and success criteria

### Prior Context
- `.planning/STATE.md` § Decisions — "Conditions builder: PolicyFormState struct" (2026-04-16)
- `.planning/STATE.md` § Patterns — "TUI screens: ratatui + crossterm; generic get::<serde_json::Value> HTTP client pattern"
- `.planning/STATE.md` § Patterns — "Policy forms: PolicyFormState struct holds all form fields + conditions list to avoid borrow-split at submit time"

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `draw_confirm` in render.rs — modal overlay pattern (centered box with `Clear` + constrained layout). Can be extended or replicated for the conditions builder modal.
- `draw_siem_config` / `draw_alert_config` — row-navigation form pattern with Step 1-2 text entry and per-row typed handlers. The conditions builder step picker follows the same Up/Down/Enter/Esc navigation pattern.
- `draw_policy_list` — stateful scrollable list. The pending conditions list in the modal uses the same `ListState` scrolling pattern.
- `PolicyCondition` serde tags — `#[serde(tag = "attribute")]` means JSON output is `{"attribute":"classification","op":"eq","value":"T3"}` — no variant name wrapper.

### Established Patterns
- Form navigation: `selected` usize + Up/Down nav + Enter activates. State mutates only on Enter commit.
- Edit mode: buffer String + editing bool. Not needed for the step picker (no free text at Steps 1 and 2).
- Error states: `app.set_status("...", StatusKind::Error)` — shown in the status bar, not inline.
- Modal dismissal: Esc closes the modal and returns to the parent screen variant (no mutation of parent state needed).
- HTTP client: `client.get::<Vec<serde_json::Value>>("...")` — uses untyped serde_json::Value throughout for config forms.

### Integration Points
- `Screen` enum (`app.rs`) — new `ConditionsBuilder { step, pending, selected_option, buffer }` variant needed
- `handle_event` in dispatch.rs — new branch for the conditions builder screen
- `draw_screen` in render.rs — new branch for conditions builder modal (uses `Clear` overlay + constrained layout)
- `PolicyFormState` in app.rs — holds `conditions: Vec<PolicyCondition>` accumulated from modal
- The conditions builder is opened from Policy Create (Phase 14) and Policy Edit (Phase 15) forms

</code_context>

<specifics>
## Specific Ideas

- The conditions builder modal should use `ratatui::widgets::Clear` to dim the parent form behind it — matching the `draw_confirm` modal pattern.
- The pending conditions list uses `ListState` (same as `draw_policy_list`) so the admin can delete conditions with `d` even when the list is focused.
- Step 3 for Classification uses a select (Up/Down/Enter) — no text input needed.
- Step 3 for MemberOf uses a text input (free-form AD group SID entry) — same `draw_input` pattern.
- After completing Step 3, the picker resets to Step 1 automatically (Enter on last value commits the condition).
- No JSON is shown to the admin at any point — the builder is purely typed selection.

</specifics>

<deferred>
## Deferred Ideas

### Reviewed Todos (not folded)
None — no relevant todos matched Phase 13 scope.

</deferred>

---

*Phase: 13-conditions-builder*
*Context gathered: 2026-04-16*
