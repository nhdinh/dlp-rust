# Phase 15: Policy Edit + Delete - Context

**Gathered:** 2026-04-17
**Status:** Ready for planning

<domain>
## Phase Boundary

Deliver two admin-TUI capabilities on top of the Phase 13 ConditionsBuilder
and Phase 14 PolicyCreate form:

1. **Edit**: Pressing `e` on a selected row in `Screen::PolicyList` triggers
   `GET /admin/policies/{id}`, populates a new `Screen::PolicyEdit` form with
   name / description / priority / action / enabled / conditions, and submits
   via `PUT /admin/policies/{id}` on `[Save]`. Conditions are edited via the
   existing ConditionsBuilder modal using the delete-and-recreate pattern
   (conditions pre-populate `pending` on modal open).
2. **Delete**: Pressing `d` on a selected row in `Screen::PolicyList` opens
   the existing `Screen::Confirm` dialog with
   `ConfirmPurpose::DeletePolicy { id }`; on confirmation, fires
   `DELETE /admin/policies/{id}` and reloads PolicyList.

Both paths require an active session (JWT present on `EngineClient`).
Server-side cache invalidation on PUT/DELETE is already handled by the admin
API (no client-side cache changes required).

</domain>

<decisions>
## Implementation Decisions

### Edit Screen Structure
- **D-01:** New `Screen::PolicyEdit { id: String, form: PolicyFormState, selected: usize, editing: bool, buffer: String, validation_error: Option<String> }` variant, parallel to `Screen::PolicyCreate`. No shared helper layer — copy-and-adapt Phase 14's render and dispatch functions. Keeps dispatch match arms readable; avoids `Option<id>` branches on every create code path.
- **D-02:** Edit form block title: `" Edit Policy: {name} "` where `{name}` is the policy's current name at load time. ID is not shown in the title or on the form body.
- **D-03:** Submit action row label: `[Save]` (matches SIEM/Alert config forms, distinguishes visually from Create's `[Submit]`).
- **D-04:** Policy ID is kept only in the `Screen::PolicyEdit { id, ... }` variant field and used for the PUT URL path. Not rendered anywhere on the form, the title, or the hints bar.

### Enabled Toggle Row (Both Forms)
- **D-05:** Both `Screen::PolicyCreate` and `Screen::PolicyEdit` forms adopt an **8-row layout** (was 7 rows in Phase 14):
  - 0: Name (text, required)
  - 1: Description (text, optional)
  - 2: Priority (text, parsed as u32 on submit)
  - 3: Action (select, cycles ACTION_OPTIONS)
  - 4: **Enabled** (bool toggle) ← new row
  - 5: [Add Conditions]
  - 6: Conditions display (read-only summary)
  - 7: [Save] (Edit) / [Submit] (Create)
- **D-06:** Enabled row rendering: `Enabled:              Yes` or `Enabled:              No`. Value in `Color::White` when not selected; `Black+Cyan+BOLD` when selected (same highlight as other rows).
- **D-07:** Enabled row keybinding: **Enter toggles** `form.enabled = !form.enabled`. No text edit mode for this row. Same pattern as the Action row (select-style, no buffer).
- **D-08:** `PolicyFormState::default()` continues to set `enabled: true` so new policies remain enabled by default. Create form POST body still sends `"enabled": true` unless admin explicitly toggles it off before `[Submit]`.
- **D-09:** **Scope note — this touches Phase 14:** The decision to add the Enabled row to the Create form is a deliberate parity change inside Phase 15. Phase 14 code (dispatch.rs row-map, render.rs draw_policy_create, action_submit_policy body) will be updated alongside the new Edit code, not in a separate phase. Phase 14's current unit tests for row indices and submit payload must be updated to assert the new 8-row layout and the `enabled` field in the POST payload.

### Conditions Pre-Population (Edit Mode)
- **D-10:** On `e` key from PolicyList, after `GET /admin/policies/{id}` succeeds, deserialize the JSON `conditions` array into `Vec<dlp_common::abac::PolicyCondition>` using the existing `#[serde(tag = "attribute", rename_all = "snake_case")]` tags. Populate `form.conditions` on the new `Screen::PolicyEdit`.
- **D-11:** When admin presses Enter on `[Add Conditions]` from Edit, the ConditionsBuilder modal opens with `pending: form.conditions.clone()` so existing conditions are visible and deletable. `caller: CallerScreen::PolicyEdit` added to `CallerScreen` enum for the return round-trip.
- **D-12:** Conditions are edited by delete-and-recreate only (Phase 13 D-07 carry-forward). No in-place edit. `d` in the modal pending list removes a condition; the full three-step picker adds a new one. On modal close, `form.conditions` is replaced wholesale by `pending`.

### Action Field Loading
- **D-13:** The loaded policy's `action` JSON value (e.g. `"ALLOW"`, `"deny"`, `"AllowWithLog"`) is mapped to `ACTION_OPTIONS` index via case-insensitive match. Unknown or missing values fall back to index 0 (`ALLOW`) and the validation_error paragraph shows `"Warning: unknown action '{value}', defaulted to ALLOW"`. This matches server-side `deserialize_policy_row`'s case-insensitive tolerance.

### Delete Confirm UX
- **D-14:** The existing `handle_confirm` dispatch is extended to accept **both** key sets: `y` / `n` (new, per ROADMAP Phase 15 #4) **and** `Left` / `Right` / `Enter` (existing). `Esc` continues to cancel. `y` is equivalent to setting `yes_selected = true` then firing the purpose action; `n` is equivalent to Esc.
- **D-15:** Delete confirm prompt text: exactly `"Delete policy '{name}'? [y/n]"` where `{name}` is taken from the `PolicyList` row's JSON `name` field. Inline `[y/n]` hint matches ROADMAP wording verbatim.
- **D-16:** After successful DELETE: reload PolicyList by calling `action_list_policies(app)` so admin sees the row disappear. Status bar: `"Policy '{name}' deleted"` with `StatusKind::Success`.
- **D-17:** After failed DELETE: status bar shows `"Failed: {e}"` with `StatusKind::Error`. Screen remains on `Screen::PolicyList` with the original row still present; admin can retry. (Overrides the current legacy behavior which returns to `PolicyMenu { selected: 4 }` — this legacy path is a stale vestige of the file-based flow.)

### Edit Submit & Error Handling
- **D-18:** On successful `PUT /admin/policies/{id}`: reload PolicyList by calling `action_list_policies(app)`. Status bar: `"Policy '{name}' updated"` with `StatusKind::Success`. Admin sees the updated row (priority, action, enabled) immediately.
- **D-19:** Validation errors and server errors render inline as a red `Paragraph` below the `[Save]` row, identical to Phase 14's `validation_error: Option<String>` pattern. Form stays mounted; fields retain their edits so admin can fix and retry.
- **D-20:** Copywriting extended from Phase 14's contract:
  - Empty name: `"Name is required."` (same)
  - Bad priority: `"Priority must be a valid integer (0 or greater)."` (same)
  - Server 4xx/5xx: `"Server error: {error from EngineClient}"` (same)
  - Network failure: `"Network error: {error from EngineClient}"` (same)
  - **New** — Policy load failure (when `e` is pressed): status bar error `"Failed to load policy: {e}"` with `StatusKind::Error`; stay on PolicyList.

### Esc & Navigation
- **D-21:** `Esc` on `Screen::PolicyEdit` while not editing returns to `Screen::PolicyList` via `action_list_policies(app)` (refreshed list). Silent discard — no "unsaved changes" prompt. Matches Phase 14's create-form Esc behavior; low risk because fresh state is always re-loadable via `e`.
- **D-22:** `Esc` on a text field in edit mode cancels the edit (restores pre-edit value), identical to Phase 14.
- **D-23:** `Q` key treated as Esc for navigation (same as Phase 14).

### Delete Access
- **D-24:** `d` key is wired **only** in `handle_policy_list`. `PolicyDetail` and `PolicyEdit` do not accept `d` as a delete shortcut. Single entry point per ROADMAP Phase 15 #4.

### PolicyList Extensions
- **D-25:** `handle_policy_list` in `dispatch.rs` adds two new key branches:
  - `KeyCode::Char('e')` → fire `action_load_policy_for_edit(app, &id, &name)` which runs `GET /admin/policies/{id}` then transitions to `Screen::PolicyEdit { id, form, selected: 0, editing: false, buffer: String::new(), validation_error: None }`.
  - `KeyCode::Char('d')` → transition to `Screen::Confirm { message: "Delete policy '{name}'? [y/n]", yes_selected: false, purpose: ConfirmPurpose::DeletePolicy { id } }`.
- **D-26:** Existing Enter (→ PolicyDetail read-only view) and Up/Down/Esc behaviors are unchanged.
- **D-27:** PolicyList footer/hints bar shows `n: new | e: edit | d: delete | Enter: view | Esc: back` (extends Phase 14 hints — `n` was added there).

### Screen Enum Additions
- `Screen::PolicyEdit { id: String, form: PolicyFormState, selected: usize, editing: bool, buffer: String, validation_error: Option<String> }`
- `CallerScreen::PolicyEdit` (for ConditionsBuilder round-trip)

### Server Routes Assumed Existing
- `GET /admin/policies/{id}` (already used by `action_get_policy`)
- `PUT /admin/policies/{id}` (already used by legacy `action_update_policy`, file-path flow)
- `DELETE /admin/policies/{id}` (already used by `action_delete_policy`)
All three are authenticated admin endpoints; no server-side work needed for Phase 15.

### Claude's Discretion
- Exact layout of the Enabled row label padding (follows the 22-char label column from Phase 14 UI-SPEC)
- Whether to add a bool-row helper function shared between render and dispatch (researcher/planner decides based on code-reuse calculus)
- Whether `action_load_policy_for_edit` internally delegates to or replaces `action_get_policy` (one returns PolicyDetail, the other returns PolicyEdit — likely a new function)
- Unit test structure: planner decides whether to add new tests to `#[cfg(test)]` modules in dispatch.rs or introduce an edit-specific test module

### Folded Todos
None — no matching pending todos in the backlog for Phase 15 scope.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Core Types
- `dlp-common/src/abac.rs` — `Policy` struct, `PolicyCondition` enum (serde tags), `Decision` enum (authoritative `DenyWithAlert` variant spelling), `Classification`, `DeviceTrust`, `NetworkLocation`, `AccessContext`
- `dlp-admin-cli/src/app.rs` — `Screen` enum (extend with `PolicyEdit`), `CallerScreen` enum (extend with `PolicyEdit`), `ConfirmPurpose::DeletePolicy { id }` (already exists), `PolicyFormState` (has `enabled: bool`, already in place), `ACTION_OPTIONS` const (4 wire strings), `StatusKind`
- `dlp-admin-cli/src/client.rs` §245–§272 — `EngineClient::put` and `EngineClient::delete` (already in place; no client additions required)

### Phase 14 Template (Copy-and-Adapt Source)
- `dlp-admin-cli/src/screens/dispatch.rs` §1100–§1300 — `handle_policy_create`, `handle_policy_create_editing`, `handle_policy_create_nav`, `action_submit_policy`, `handle_conditions_*` — these are the functions to clone and adapt for `PolicyEdit` and `action_submit_policy_update`
- `dlp-admin-cli/src/screens/render.rs` — `draw_policy_create`, `draw_conditions_builder` — clone `draw_policy_create` into `draw_policy_edit` with the new title and row-7 label change; `draw_conditions_builder` reused as-is
- `.planning/phases/14-policy-create/14-UI-SPEC.md` — entire spec carries forward as the Edit form's visual contract; only deltas are the title string, the `[Save]` label, and the new Enabled row at index 4

### Existing Wiring (No Changes Needed)
- `dlp-admin-cli/src/screens/dispatch.rs` §337–§362 — `handle_confirm` (extend with `Char('y')` and `Char('n')` branches alongside existing Left/Right/Enter; `ConfirmPurpose::DeletePolicy { id }` already routes to `action_delete_policy`)
- `dlp-admin-cli/src/screens/dispatch.rs` §386–§409 — `handle_policy_list` (extend with `Char('e')` and `Char('d')` branches)
- `dlp-admin-cli/src/screens/dispatch.rs` §504–§516 — `action_delete_policy` (already correct; only return destination is changed: call `action_list_policies(app)` on success instead of `Screen::PolicyMenu`)
- `dlp-admin-cli/src/screens/dispatch.rs` §484–§502 — `action_update_policy` (legacy file-path; Phase 15 adds a new `action_submit_policy_update(app, id, form)` that parallels `action_submit_policy` but uses PUT instead of POST)
- `dlp-admin-cli/src/screens/render.rs` §932 — `draw_confirm` (reused as-is; key-binding change is in `handle_confirm` only)

### Prior Phase Contracts
- `.planning/phases/13-conditions-builder/13-CONTEXT.md` — modal invariants: Esc-at-Step-1 closes modal, `pending` pre-population via `form_snapshot`, `CallerScreen` enum round-trip, delete-and-recreate pattern (Phase 13 D-07)
- `.planning/phases/13-conditions-builder/13-UI-SPEC.md` — ConditionsBuilder visual contract (unchanged for Phase 15)
- `.planning/phases/14-policy-create/14-UI-SPEC.md` — **authoritative form design contract** for color, spacing, highlight style, cursor convention `[{buffer}_]`, validation-error paragraph pattern

### Requirements & Roadmap
- `.planning/REQUIREMENTS.md` § POLICY-03 — edit scope: name, description, priority, action, enabled flag, conditions; PUT endpoint; cache invalidation (server-side)
- `.planning/REQUIREMENTS.md` § POLICY-04 — delete scope: confirmation prompt, `d` keypress on list row, DELETE endpoint, cache invalidation (server-side)
- `.planning/ROADMAP.md` § Phase 15 — 5 success criteria (authoritative)

### State
- `.planning/STATE.md` § Decisions (2026-04-16) — PolicyFormState struct, PolicyStore uses parking_lot::RwLock, conditions-builder modal pattern
- `.planning/STATE.md` § Patterns — TUI screens: ratatui + crossterm; generic `get::<serde_json::Value>` HTTP client pattern; Policy forms: PolicyFormState holds all fields + conditions to avoid borrow-split

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets (No Changes Needed)
- `PolicyFormState` already has `pub enabled: bool` with a `#[allow(dead_code)]` comment saying "used by Phase 15 policy edit form" — Phase 15 consumes this field, removes the `allow(dead_code)`.
- `ConfirmPurpose::DeletePolicy { id }` already exists (app.rs §44) — Phase 15 just needs to transition PolicyList → Confirm with this purpose.
- `action_delete_policy` already performs DELETE /admin/policies/{id} (dispatch.rs §504). Only its post-success screen transition needs updating (PolicyMenu → PolicyList via action_list_policies).
- `EngineClient::put` / `EngineClient::delete` already implemented (client.rs §245, §271).
- `handle_confirm` already exists and already routes DeletePolicy purpose to action_delete_policy — only needs new `Char('y')` / `Char('n')` branches added.
- `draw_confirm` renders the existing centered-modal confirm dialog — reusable as-is.
- `draw_policy_create` renders the existing 7-row form — will be extended in-place to 8 rows for the Enabled toggle (Phase 15 D-09 scope note).
- `ConditionsBuilder` modal (`draw_conditions_builder`, `handle_conditions_*`) works identically for edit as for create; only `CallerScreen::PolicyEdit` needs adding to the round-trip enum.

### Established Patterns to Follow
- **8-row form layout:** Extend Phase 14's `List`-based field-row pattern; single helper row-index → label mapping. Prefer adding `POLICY_FIELD_LABELS: [&str; 8]` constant for the new shared layout.
- **Action-style select row on Enter:** Row 3 (Action) cycles `ACTION_OPTIONS`; Row 4 (Enabled) flips bool. Generic pattern — Enter on a non-text row dispatches a select/toggle handler.
- **Validation error paragraph:** `Option<String>` field on the Screen variant; rendered in `Color::Red` below `[Save]`/`[Submit]` row when `Some`. Cleared on navigation away.
- **Reload on success:** Call `action_list_policies(app)` after PUT/DELETE success — it already sets `Screen::PolicyList` with fresh data.
- **Copy-and-adapt:** dispatch.rs already follows the pattern of parallel `handle_*` and `action_*` functions per screen; adding `handle_policy_edit*` and `action_submit_policy_update` is consistent.

### Integration Points
- `Screen` enum (`app.rs`): add `PolicyEdit { id, form, selected, editing, buffer, validation_error }` variant
- `CallerScreen` enum (`app.rs`): add `PolicyEdit` variant for ConditionsBuilder round-trip
- `handle_event` dispatch (`dispatch.rs`): add match arm for `Screen::PolicyEdit { .. }` → `handle_policy_edit`
- `handle_policy_list` (`dispatch.rs`): add `Char('e')` and `Char('d')` branches
- `handle_confirm` (`dispatch.rs`): add `Char('y')` / `Char('n')` branches
- `draw_screen` (`render.rs`): add match arm for `Screen::PolicyEdit { .. }` → `draw_policy_edit`
- `action_submit_policy` (`dispatch.rs`): update POST body to include `"enabled": form.enabled` (was hardcoded true)
- `draw_policy_create` + Phase 14 dispatch: extend to 8 rows to accommodate the new Enabled row (D-09)

### What Does NOT Change
- Server-side code: no admin_api.rs, policy_store.rs, or auth layer changes needed
- Phase 13 ConditionsBuilder modal: no behavior changes; only `CallerScreen` enum extension
- Cache invalidation: already handled server-side on PUT/DELETE
- Existing SIEM/Alert/Policy legacy file-based flows: untouched (they remain on PolicyMenu menu items for import/export compatibility in Phase 17)

</code_context>

<specifics>
## Specific Ideas

- The existing `ConfirmPurpose::DeletePolicy { id }` was scaffolded in anticipation — Phase 15 is the phase that finally wires a real entry point to it (the `d` key on PolicyList). The legacy `InputPurpose::DeletePolicyId` text-entry flow (PolicyMenu → type ID → confirm) remains callable from PolicyMenu but is superseded by the direct `d`-on-row UX.
- When building `draw_policy_edit`, start by cloning `draw_policy_create` verbatim then change:
  1. Title string: `" Create Policy "` → `" Edit Policy: {name} "`
  2. Submit row label: `[Submit]` → `[Save]`
  3. Row 4 becomes the Enabled toggle (same change also lands in `draw_policy_create`)
- The Enabled toggle rendering is a two-branch string: `if form.enabled { "Yes" } else { "No" }`. Style with `Color::White` when unselected; standard highlight when selected.
- For the delete confirm prompt, the `{name}` value comes from `policies[selected]["name"].as_str().unwrap_or("<unnamed>")` at the time the `d` key is pressed. The name is frozen at confirm-open time; if the server state changes mid-confirm, the admin still sees the name they clicked on.
- In `handle_confirm`, map `Char('y')` → `*yes_selected = true; fire purpose; clear screen` and `Char('n')` → same path as Esc.

</specifics>

<deferred>
## Deferred Ideas

- **Dirty-tracking Esc confirm:** "Discard changes? [y/n]" prompt on Esc when the edit form has unsaved changes. Low priority — edit is easily redone and the 8-row form is short enough that admins typically don't lose significant work. Could be added as a v0.5.0 quality-of-life improvement.
- **In-place condition edit:** Selecting a pending condition and pressing Enter to modify it (instead of delete-and-recreate). Tracked in REQUIREMENTS POLICY-F2 deferred. Phase 15 explicitly keeps the Phase 13 delete-and-recreate contract.
- **Bulk delete:** Selecting multiple policies in PolicyList and deleting them together. Out of Phase 15 scope; candidate for v0.5.0.
- **PolicyDetail `e` shortcut:** Pressing `e` from the read-only detail view to jump into the edit form. Deferred — adds dispatch complexity for marginal benefit.
- **Optimistic UI on delete:** Remove the row from the in-memory list immediately without re-fetching. Rejected here in favor of a `GET /admin/policies` refresh for correctness against concurrent admin edits.

### Reviewed Todos (not folded)
None — no relevant pending todos matched Phase 15 scope.

</deferred>

---

*Phase: 15-policy-edit-delete*
*Context gathered: 2026-04-17*
