# Phase 13: Conditions Builder - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-16
**Phase:** 13-conditions-builder
**Areas discussed:** Entry point, Modal UX

---

## Entry point

| Option | Description | Selected |
|--------|-------------|----------|
| Separate screen | Full-screen `Screen::ConditionsBuilder` variant. Esc returns to parent. | |
| Modal overlay | Centered box drawn over parent form. Parent dimmed but visible. | ✓ |
| Embedded rows | "Add Conditions" adds an inline row that walks Steps 1-3 in-place. No navigation away. | |

**User's choice:** Modal overlay
**Notes:** Keeps the parent form visible behind the modal — admin can see context while building conditions. Fits well with the existing modal pattern from `draw_confirm`.

---

## Modal UX

| Option | Description | Selected |
|--------|-------------|----------|
| Builder steps + inline pending list | Modal shows both step picker and pending list simultaneously. | ✓ |
| Single condition per modal session | Modal closes after one condition added. Re-open to add another. Simpler but more back-and-forth. | |
| Separate summary/confirmation screen | After Step 3, show full-screen summary before returning to form. | |

**User's choice:** Builder steps + inline pending list (recommended default)
**Notes:** Most seamless UX — admin can see what they've already added while continuing to build. Reopening the modal preserves the pending list in `PolicyFormState`.

---

## Deferred Ideas

- Operator display strategy (which operators to show, enforcement annotations) — not discussed; covered by REQUIREMENTS.md § Open Design Decisions
- Step 3 value picker UX details (free-text vs select per attribute) — not discussed in detail; covered by success criteria and D-11 through D-15 in CONTEXT.md
