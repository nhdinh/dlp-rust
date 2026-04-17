# Phase 15: Policy Edit + Delete - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-17
**Phase:** 15-policy-edit-delete
**Areas discussed:** Edit screen structure, Enabled toggle row, Delete confirm UX, Post-action return

---

## Gray Area Selection

| Option | Description | Selected |
|--------|-------------|----------|
| Edit screen structure | Separate PolicyEdit vs extend PolicyCreate vs shared helper | ✓ |
| Enabled toggle row | Row position, toggle UX, create parity, display copy | ✓ |
| Delete confirm UX | Keys, prompt text, success return, failure handling | ✓ |
| Post-action return | PUT return destination, error display, Esc behavior, delete access | ✓ |

---

## Edit Screen Structure

### Q1: How should the edit form be represented in the Screen enum?

| Option | Description | Selected |
|--------|-------------|----------|
| Separate PolicyEdit variant (Recommended) | New Screen::PolicyEdit { id, form, selected, editing, buffer, validation_error }. Clean routing — dispatch matches on variant name; no 'if id.is_some()' branches. More boilerplate (parallel handlers), but Phase 14's code is the template — copy-and-adapt is trivial. | ✓ |
| Extend PolicyCreate with Option<String> policy_id | Screen::PolicyCreate gains an optional id. None = create, Some = edit. Less duplication, but every dispatch branch becomes 'if id.is_some()', and submit logic gets branching (POST vs PUT). Risk: future edit-only features bleed into create path. | |
| Shared form in helper, thin variant wrappers | Both variants exist, but rendering and dispatch delegate to a shared render_policy_form() / handle_policy_form() helper parameterized by a mode enum. Maximum reuse, but adds one more abstraction layer. | |

**User's choice:** Separate PolicyEdit variant

### Q2: What label goes on the submit action row in Edit mode?

| Option | Description | Selected |
|--------|-------------|----------|
| [Save] | Edit-specific verb. Distinguishes from Create's [Submit]. Matches SIEM/Alert config forms which also use [Save]. | ✓ |
| [Submit] (same as Create) | Identical label regardless of mode. Simpler, but less informative — admin can't tell by the row text whether they're creating or updating. | |
| [Update] | HTTP-semantic verb matching PUT. More technical; less conventional in TUIs. | |

**User's choice:** [Save]

### Q3: What should the edit form's block title show?

| Option | Description | Selected |
|--------|-------------|----------|
| Edit Policy: {name} (Recommended) | Shows which policy is being edited. Name is human-readable; matches the delete confirmation which also uses {name}. ID shown only on validation errors. | ✓ |
| Edit Policy ({id}) | Shows the UUID. Unambiguous but 36 characters of noise in the title bar. | |
| Edit Policy (plain) | No identifier in title. Admin must remember what they selected. Minimal. | |

**User's choice:** Edit Policy: {name}

### Q4: How should the policy ID appear on the form itself?

| Option | Description | Selected |
|--------|-------------|----------|
| Not shown on form (Recommended) | ID is in the title bar only; not a form row. ID is immutable anyway (PUT uses it in the URL), so showing it as a row suggests editability. | ✓ |
| Read-only top row, labeled 'ID:' | Row 0 shows 'ID: {uuid}' in DarkGray, not selectable. Makes it visible but clutters the form. Navigation skip logic needed. | |
| Shown in footer/status bar | ID appears in the hints bar as 'Editing {id}'. Keeps form clean; visible for debugging. | |

**User's choice:** Not shown on form

---

## Enabled Toggle Row

### Q1: Where should the Enabled toggle row sit on the Edit form?

| Option | Description | Selected |
|--------|-------------|----------|
| Row 4, after Action (Recommended) | 0:Name, 1:Description, 2:Priority, 3:Action, 4:Enabled, 5:[Add Conditions], 6:Conditions, 7:[Save]. Groups scalar fields together before action rows. 8 total rows. | ✓ |
| Row 0, top of form | Enabled is prominent as first row. Matches 'is this policy live?' being a top-level question. Shifts Name to row 1. | |
| Row 7, just before [Save] | Toggle right next to Save. Ensures admin confirms state before submitting. Less discoverable. | |

**User's choice:** Row 4, after Action

### Q2: How should the Enabled toggle behave when Enter is pressed?

| Option | Description | Selected |
|--------|-------------|----------|
| Enter toggles true<->false (Recommended) | Same pattern as Phase 14's Action row (cycle on Enter). Display shows 'Enabled: Yes' or 'Enabled: No'. Consistent with existing form idioms. | ✓ |
| Space toggles, Enter does nothing | Space bar is the conventional checkbox toggle key. But no other row uses Space — breaks consistency. | |
| Two-option select (cycle like Action) | Technically same as toggle but rendered as index into ['Yes', 'No']. Same behavior, slightly more ceremony. | |

**User's choice:** Enter toggles true<->false

### Q3: Should Phase 14's Create form also expose the Enabled toggle, or stay hardcoded to enabled=true?

| Option | Description | Selected |
|--------|-------------|----------|
| Add Enabled row to Create too (Recommended) | Create and Edit use the exact same 8-row layout. One render helper, one dispatch handler pattern. Default enabled=true in PolicyFormState::default() so new policies still start enabled. Tiny scope bump into Phase 14 territory, but keeps forms symmetric. | ✓ |
| Leave Create hardcoded true; Edit-only row | Create stays 7 rows; Edit is 8 rows. Two render paths diverge. Scope-clean for Phase 15, but forms are no longer symmetric — future maintainer must remember the difference. | |
| Add to Create but default to false | Forces admin to explicitly enable. Safer default but breaks current behavior (Phase 14 currently creates enabled policies automatically). | |

**User's choice:** Add Enabled row to Create too

**Notes:** This means Phase 14's row count changes from 7 to 8 and Phase 14's POST body gains the `enabled` field. Captured as Phase 15 D-09 scope note.

### Q4: What text renders for the enabled value?

| Option | Description | Selected |
|--------|-------------|----------|
| Yes / No (Recommended) | Matches admin-facing language; readable at a glance. Maps to bool at submit time. | ✓ |
| true / false | Exact JSON wire value; no mapping needed. Slightly more technical. | |
| Enabled / Disabled | Verbose but self-describing. Row reads 'Enabled: Enabled' which is redundant. | |

**User's choice:** Yes / No

---

## Delete Confirm UX

### Q1: Which keys should the delete confirm dialog accept?

| Option | Description | Selected |
|--------|-------------|----------|
| y/n + Left/Right/Enter (Recommended) | Both work. y = confirm, n = cancel, plus existing Left/Right/Enter still functions. Matches ROADMAP's '[y/n]' spec without regressing the existing Confirm flow. Escape cancels (existing). | ✓ |
| Only y/n (remove Left/Right) | Strict to ROADMAP spec. Simpler dispatch. But existing Confirm tests/usage break if they rely on Left/Right; dispatch.rs handle_confirm would need modification that affects current import-delete flow. | |
| Only Left/Right/Enter (ignore ROADMAP wording) | Keep existing Confirm behavior unchanged. Consistent with SIEM/Alert confirms. But violates ROADMAP Phase 15 criterion #4 verbatim. | |

**User's choice:** y/n + Left/Right/Enter

### Q2: What exact text appears in the delete prompt?

| Option | Description | Selected |
|--------|-------------|----------|
| Delete policy '{name}'? [y/n] (Recommended) | Matches ROADMAP wording verbatim. Includes name for recognition, not id. Key hints inline. | ✓ |
| Delete policy '{name}'? (key hints in footer) | Cleaner message; hints moved to the footer/hints bar. Requires updating draw_confirm to render a hints bar. | |
| Are you sure you want to delete '{name}'? [y/n] | More verbose. Adds no info; ROADMAP wording is already explicit. | |

**User's choice:** Delete policy '{name}'? [y/n]

### Q3: Where should the delete action return the user after a successful DELETE?

| Option | Description | Selected |
|--------|-------------|----------|
| Reload PolicyList (Recommended) | Re-issue GET /admin/policies and show refreshed list. User sees the row is gone; natural continuation. Status bar shows 'Policy deleted'. | ✓ |
| PolicyMenu | Matches existing Phase 14 create-success behavior. User has to re-enter PolicyList to confirm deletion. Less immediate feedback. | |
| Stay on current list view, just drop the row locally | No round-trip; mutate the in-memory PolicyList::policies vec. Fastest, but if server state diverges (concurrent admin), the UI lies. | |

**User's choice:** Reload PolicyList

### Q4: What happens if DELETE returns an error (network or 4xx/5xx)?

| Option | Description | Selected |
|--------|-------------|----------|
| Status bar error, stay on PolicyList (Recommended) | app.set_status("Failed: {e}", Error). PolicyList still shows the row. Admin can retry. Matches existing action_delete_policy pattern. | ✓ |
| Status bar error, return to PolicyMenu | Existing code already does this (dispatch.rs line 513: PolicyMenu { selected: 4 }). Consistent with the current legacy file-based delete flow. | |
| Full-screen error with retry prompt | More prominent; forces acknowledgment. Heavier UX; inconsistent with other admin errors which all use status bar. | |

**User's choice:** Status bar error, stay on PolicyList

---

## Post-action Return

### Q1: After a successful PUT /admin/policies/{id}, where should the user land?

| Option | Description | Selected |
|--------|-------------|----------|
| Reload PolicyList (Recommended) | Same as delete flow — PolicyList is the natural starting point. Admin sees updated row details (priority/action/enabled) immediately. Status bar shows 'Policy updated'. | ✓ |
| PolicyMenu | Matches Phase 14 create-success destination. Consistent across create/edit, but admin has to navigate back to the list to verify. | |
| PolicyDetail of the just-edited policy | Drops admin on the read-only detail view of their policy. Maximum verification, but extra click to return to list for further work. | |

**User's choice:** Reload PolicyList

### Q2: Where should validation and server errors surface on the Edit form?

| Option | Description | Selected |
|--------|-------------|----------|
| Inline red Paragraph below [Save] (Recommended) | Exactly mirrors Phase 14's validation_error pattern. Same copywriting contract ('Name is required.', 'Priority must be a valid integer (0 or greater).', 'Server error: {msg}'). Form stays mounted; admin fixes and retries. | ✓ |
| Status bar only | No inline paragraph; errors appear in the global status bar. Less immediate; admin may miss transient messages. | |
| Both (inline + status bar) | Duplicate signal. Redundant in a single-user TUI where status bar is always visible. | |

**User's choice:** Inline red Paragraph below [Save]

### Q3: When admin presses Esc on the Edit form with unsaved changes, what happens?

| Option | Description | Selected |
|--------|-------------|----------|
| Silent discard (match Create) (Recommended) | Esc returns to PolicyList without warning. Consistent with Phase 14 create-form behavior. Low-risk — edit can be redone by pressing 'e' again and GET reloads fresh state. | ✓ |
| Confirm if dirty | If any field changed, show 'Discard changes? [y/n]'. Safer against accidental data loss but adds a dirty-tracking flag on PolicyFormState and a new Confirm purpose. | |
| Esc does nothing; explicit [Cancel] row | Forces deliberate cancel. Adds a row. Breaks Phase 14 parity. | |

**User's choice:** Silent discard (match Create)

### Q4: Besides 'd' on PolicyList, should delete also be reachable from other screens?

| Option | Description | Selected |
|--------|-------------|----------|
| PolicyList only (Recommended) | Single entry point per ROADMAP #4. Minimal scope. PolicyDetail and PolicyEdit stay read-only/edit-only. | ✓ |
| PolicyList + PolicyDetail | 'd' works in detail view too. Common pattern but adds another key binding and dispatch branch. | |
| PolicyList + PolicyEdit (as a [Delete] row) | Edit form gains a [Delete] row at the bottom. Extra discoverability but risks accidental delete during edit. | |

**User's choice:** PolicyList only

---

## Claude's Discretion

- Exact layout of the Enabled row label padding (follows the 22-char label column from Phase 14 UI-SPEC)
- Whether to add a bool-row helper function shared between render and dispatch (researcher/planner decides based on code-reuse calculus)
- Whether `action_load_policy_for_edit` internally delegates to or replaces `action_get_policy` (one returns PolicyDetail, the other returns PolicyEdit — likely a new function)
- Unit test structure: planner decides whether to add new tests to `#[cfg(test)]` modules in dispatch.rs or introduce an edit-specific test module

## Deferred Ideas

- Dirty-tracking Esc confirm: "Discard changes? [y/n]" prompt on Esc when the edit form has unsaved changes
- In-place condition edit (POLICY-F2 deferred; stays on delete-and-recreate in Phase 15)
- Bulk delete from PolicyList (v0.5.0 candidate)
- PolicyDetail 'e' shortcut to jump into edit form
- Optimistic UI on delete (rejected in favor of GET /admin/policies refresh)
