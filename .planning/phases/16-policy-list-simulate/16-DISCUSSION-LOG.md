# Phase 16: Policy List + Simulate - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-17
**Phase:** 16-policy-list-simulate
**Areas discussed:** PolicyList columns & sort, Simulate entry point, Simulate form layout & selects, Simulate response & error rendering

---

## Gray Area Selection

**Question:** Which areas do you want to discuss for Phase 16 (Policy List + Simulate)?

| Option | Description | Selected |
|--------|-------------|----------|
| PolicyList columns & sort | Drop ID+Version or keep? Tie-breaker on same priority? Add `n` key + footer hint. | ✓ |
| Simulate entry point | MainMenu (top-level) vs PolicyMenu (nested) vs both; Esc destination. | ✓ |
| Simulate form layout & selects | Section headers vs flat vs split; select UX; groups input shape; timestamp/session_id visibility. | ✓ |
| Simulate response & error rendering | Inline vs separate screen vs side panel; error surfacing; clearing behavior; validation gate. | ✓ |

**User's choice:** All four areas selected for discussion.

---

## PolicyList columns & sort

### Columns

| Option | Description | Selected |
|--------|-------------|----------|
| Exactly per ROADMAP | Priority / Name / Action / Enabled. Drop ID and Version from the table entirely. | ✓ |
| ROADMAP + ID column | Priority / Name / Action / Enabled / ID. Keep ID for admin debugging. | |
| ROADMAP + ID + Version | Priority / Name / Action / Enabled / ID / Version. Preserve current debug info. | |

**User's choice:** Exactly per ROADMAP.
**Notes:** ID and Version remain visible in PolicyDetail (Enter-to-open read-only view); keeping the list table clean.

### Sort

| Option | Description | Selected |
|--------|-------------|----------|
| Client-side, priority asc, name tiebreak | Sort in `action_list_policies` after GET; stable ordering for ties. | ✓ |
| Client-side, priority asc only | Sort by priority only; leave ties in server order. | |
| Trust server order | No client-side sort; couple TUI to server contract. | |

**User's choice:** Client-side, priority asc, name tiebreak.
**Notes:** Tiebreak is case-insensitive name ascending. Malformed priorities sort last (u32::MAX fallback).

### n key

| Option | Description | Selected |
|--------|-------------|----------|
| n = new policy from list | Press `n` on PolicyList → `Screen::PolicyCreate` with fresh `PolicyFormState`. | ✓ |
| Leave n unbound | Don't wire `n`; violates ROADMAP §1 footer-hint requirement. | |

**User's choice:** n = new policy from list.
**Notes:** Footer hint becomes `n: new | e: edit | d: delete | Enter: view | Esc: back`. Re-introduces the `n` hint that commit `21fab87` removed as dead code.

---

## Simulate entry point

### Entry point

| Option | Description | Selected |
|--------|-------------|----------|
| Top-level in MainMenu | New `Simulate Policy` peer of Password/Policy/System. | |
| Second-level under PolicyMenu | Under PolicyMenu alongside List/Create/Import/Export. | |
| Both entry points | Appear in MainMenu AND PolicyMenu. | ✓ |

**User's choice:** Both entry points.
**Notes:** `SimulateCaller` enum captures the return destination so Esc resumes the correct parent menu.

### Screen name

| Option | Description | Selected |
|--------|-------------|----------|
| Screen::PolicySimulate | Matches `Policy*` prefix convention. | ✓ |
| Screen::Simulate | Shorter; breaks convention. | |
| Screen::EvaluateRequest | Matches payload type; more technical. | |

**User's choice:** Screen::PolicySimulate.

---

## Simulate form layout & selects

### Form layout

| Option | Description | Selected |
|--------|-------------|----------|
| Section headers + flat rows | Non-selectable section-header rows interleaved; linear row index. | ✓ |
| Three-column split | `Layout::horizontal` split Subject / Resource+Environment. New pattern. | |
| Flat list, no headers | No section labels, same style as PolicyCreate. | |

**User's choice:** Section headers + flat rows.
**Notes:** Section-header rows are skipped by Up/Down navigation; `selected` only counts editable rows.

### Select rows

| Option | Description | Selected |
|--------|-------------|----------|
| Enter cycles value | PolicyCreate Action row pattern. Zero new UI patterns. | ✓ |
| Dropdown overlay | Enter opens picker overlay; new pattern. | |
| Left/Right cycles in place | Breaks Up/Down row nav consistency. | |

**User's choice:** Enter cycles value.
**Notes:** Applies to device_trust, network_location, classification, action, access_context.

### Groups field

| Option | Description | Selected |
|--------|-------------|----------|
| Single text field, comma-split | One row: `Groups (comma-separated SIDs)`; split on submit. | ✓ |
| Multi-entry list with Add/Remove | Row is a list of SIDs; sub-controls to add/remove. | |

**User's choice:** Single text field, comma-split.
**Notes:** Split by `,`, trim each segment, drop empties. Raw buffer preserved across edits so admin formatting survives re-editing.

### Hidden fields

| Option | Description | Selected |
|--------|-------------|----------|
| Auto-default, hide from form | `timestamp = now()`, `session_id = 0` at submit; not rendered. | ✓ |
| Show with sensible defaults | Editable rows pre-filled. Supports corner-case simulations. | |
| Expose session_id, hide timestamp | Hybrid. | |

**User's choice:** Auto-default, hide from form.
**Notes:** Matches ROADMAP §2 field list (which omits timestamp/session_id/agent).

---

## Simulate response & error rendering

### Response

| Option | Description | Selected |
|--------|-------------|----------|
| Inline below [Simulate] row | `SimulateOutcome` enum; bordered `Paragraph` block. Form state preserved. | ✓ (Claude's pick) |
| Separate SimulateResult screen | Transition to dedicated screen; Esc returns to filled form. | |
| Side panel split | Horizontal split: form left, result pinned right. | |

**User's choice:** User deferred to Claude with "Choose the best option for all questions" — Claude selected **Inline below [Simulate] row**.
**Notes:** Reasoning: lowest complexity, matches Phase 14 `validation_error` pattern, preserves form state, and keeps the same inline region hosting both success and error so the error-rendering decision stays coherent.

### Errors

| Option | Description | Selected |
|--------|-------------|----------|
| Same inline region, red text | `SimulateOutcome::Error(String)`; red text in the result block. | ✓ |
| Status bar + inline | Short status-bar message plus inline detail. | |
| Status bar only | Violates ROADMAP §4. | |

**User's choice:** Same inline region, red text.
**Notes:** Prefix `"Network error: "` for transport failures, `"Server error: "` for 4xx/5xx.

### Clearing

| Option | Description | Selected |
|--------|-------------|----------|
| Only on next submit | Result persists through field edits; overwritten only by next submit. | ✓ |
| Clear on any field edit | Edits wipe the result. | |
| Manual clear only | Requires a key binding like `c`. | |

**User's choice:** Only on next submit.
**Notes:** Lets admin iterate on fields while the most recent decision stays visible for reference.

### Validation

| Option | Description | Selected |
|--------|-------------|----------|
| No client validation | Server handles `EvaluateRequest::default()` gracefully. | ✓ |
| Require user_sid + path | Client-side guard. | |
| Warn but submit anyway | Yellow warning beside Submit row but POST still fires. | |

**User's choice:** No client validation.
**Notes:** ROADMAP §4 only requires network/server error display, not client pre-validation.

---

## Claude's Discretion

The following implementation details were left to downstream agents:

- Label column width for the simulate form (planner picks to match Phase 14 UI-SPEC's 22-char label column).
- Exact rendering of section-header rows (dim `---` line vs bold label + empty line vs `Block::title` per section).
- Whether the Select-row cycle handler is generic or per-field.
- Whether `action_open_simulate` is parameterized or split.
- Whether `SimulateFormState` lives in `app.rs` or a new module.

## Deferred Ideas

- Simulate-from-PolicyList shortcut (`s` key pre-fill)
- History of simulate runs (scrollable log)
- Dropdown-style select overlays
- Per-SID group list with Add/Remove
- Timestamp / session_id exposure
- Dirty-tracking Esc confirm
