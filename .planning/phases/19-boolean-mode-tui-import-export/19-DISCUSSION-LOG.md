# Phase 19: Boolean Mode in TUI + Import/Export - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-20
**Phase:** 19-boolean-mode-tui-import-export
**Areas discussed:** Mode picker widget style, Mode row position, Empty-conditions UX hint, Export mode field presence

---

## Mode picker widget style

| Option | Description | Selected |
|--------|-------------|----------|
| a. Cycle on Enter/Space | Same pattern as `enabled` bool toggle and `action` enum cycler; no new keybindings | ✓ |
| b. Inline segmented with `h`/`l` | `Mode: [ALL] ANY NONE` with horizontal navigation | |
| c. Popup dropdown | Modal picker like file dialog | |

**User's choice:** a — cycle on Enter/Space
**Notes:** Matches existing TUI form conventions. `ACTION_OPTIONS` precedent at `dlp-admin-cli/src/app.rs` §142-147.

---

## Mode row position in the form

| Option | Description | Selected |
|--------|-------------|----------|
| a. Between Enabled and [Add Conditions] | Groups editable leaf fields; separates data rows from action-trigger rows | ✓ |
| b. Between [Add Conditions] and Conditions | Puts Mode visually directly above the list it governs | |

**User's choice:** a
**Notes:** Post-change form has 9 rows: Name, Description, Priority, Action, Enabled, **Mode**, [Add Conditions], Conditions, [Submit]. Row-index renumber is the single highest-risk refactor.

---

## Empty-conditions UX hint

| Option | Description | Selected |
|--------|-------------|----------|
| a. Silent | No UI hint; matches D-13 exactly | |
| b. Footer hint | Advisory line when `mode != ALL && conditions.is_empty()` | ✓ |
| c. Block submit | Client-side validation; diverges from D-13 | |

**User's choice:** b — footer hint
**Notes:** Advisory only — does not block submit. Preserves Phase 18 D-13 (server accepts the payload). Recommended wording captured in CONTEXT.md D-04.

---

## Export mode field presence

| Option | Description | Selected |
|--------|-------------|----------|
| a. Always write mode | Explicit; lossless round-trip; matches milestone criterion 3 verbatim | ✓ |
| b. Omit when default | Smaller files; indistinguishable from legacy | |

**User's choice:** a — always write mode (user said "use all recommended options")
**Notes:** Transitively satisfied by Phase 18's server-side serialization (mode is always present in `PolicyResponse`). Phase 19 adds an integration test assertion as a regression guard (D-15).

## Claude's Discretion

- Exact wording of footer hint messages (D-04)
- Whether `PolicyFormState.mode` stores the enum directly or a usize index like `action`
- Whether to factor a `cycle_mode` helper vs inline three-way match
- Whether the integration test file is separate (`mode_end_to_end.rs`) or folded into `admin_audit_integration.rs`

## Deferred Ideas

- Nested boolean trees (out of milestone scope)
- Mode-aware conflict diff on import UX
- Expanded operators (Phase 20)
- In-place condition editing (Phase 21)
- Client-side validation on empty conditions (rejected in favor of advisory hint)
- Export format version header / schema wrapper
