---
status: partial
phase: 16-policy-list-simulate
source: 16-01-PLAN.md, 16-02-PLAN.md, 16-CONTEXT.md
started: 2026-04-20T00:00:00.000Z
updated: 2026-04-20T00:00:00.000Z
---

## Current Test

[testing complete — all 11 tests pass]

## Tests

### 1. PolicyList columns and hints
expected: PolicyList shows Priority / Name / Action / Enabled columns (not ID/Version). Enabled renders as "Yes" or "No" (not true/false). Footer shows: "n: new | e: edit | d: delete | Enter: view | Esc: back"
result: pass

### 2. PolicyList sort order
expected: Policies sort by priority ascending (lower number = higher priority at top). Ties broken by name case-insensitive ascending. Malformed/missing priority sinks to bottom.
result: pass

### 3. 'n' key creates new policy
expected: On PolicyList, pressing 'n' transitions to the PolicyCreate screen with empty form.
result: pass

### 4. MainMenu Simulate Policy entry
expected: MainMenu shows 5 items: Password Management, Policy Management, System, Simulate Policy, Exit. Selecting Simulate Policy and pressing Enter opens the PolicySimulate form.
result: pass

### 5. PolicyMenu Simulate Policy entry
expected: PolicyMenu shows 7 items with "Simulate Policy" at position 6 (before Back). Enter on Simulate Policy opens the PolicySimulate form.
result: pass

### 6. PolicySimulate form — section headers
expected: Form displays "--- Subject ---", "--- Resource ---", "--- Environment ---", "--- Submit ---" section headers with cyan highlight on selected row.
result: pass

### 7. PolicySimulate text field editing
expected: User SID, User Name, Groups, Path rows are editable. Select a row and press Enter → type → Enter commits. Esc cancels without losing the current field value.
result: pass

### 8. PolicySimulate select cycling
expected: Device Trust, Network Location, Classification, Action, Access Context rows cycle on Enter (e.g. Device Trust: Managed→Unmanaged→Compliant→Unknown→Managed).
result: pass

### 9. PolicySimulate — submit via [Simulate] button
expected: Select the [Simulate] row (index 9) and press Enter → POST to /evaluate. While awaiting: no crash. On response: result block appears below the form showing matched_policy_id, decision (ALLOW/DENY colored), and reason.
result: pass

### 10. PolicySimulate — error rendering
expected: If /evaluate returns a network error or server error, the result area shows red-bordered "Error" block with the error message (not silent drop).
result: pass

### 11. PolicySimulate Esc returns to caller
expected: Pressing Esc (or 'q') on the PolicySimulate form returns to the screen that opened it: MainMenu with "Simulate Policy" selected, or PolicyMenu with "Simulate Policy" selected.
result: pass

## Summary

total: 11
passed: 11
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

_All gaps resolved._