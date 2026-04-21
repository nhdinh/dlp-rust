---
status: partial
phase: 21-in-place-condition-editing
source: [21-VERIFICATION.md]
started: 2026-04-21T08:00:00+07:00
updated: 2026-04-21T08:00:00+07:00
---

## Current Test

[awaiting human testing]

## Tests

### 1. Modal title switch
expected: Press 'e' on a pending condition in the ConditionsBuilder; modal title must switch from "Conditions Builder" to "Edit Condition", and Step 1 attribute row must be pre-highlighted on the condition's attribute.
result: [pending]

### 2. Multi-step Esc chaining
expected: With edit_index active (after pressing 'e'), pressing Esc at Steps 3, 2, and 1 in sequence must leave the pending conditions list completely untouched — the original condition remains at its original index throughout.
result: [pending]

### 3. SC-5 operator reset visual
expected: During an edit, change the attribute in Step 1 from Classification to DeviceTrust; Step 2 must show only the 2 operators valid for DeviceTrust (eq, neq) with no stale selection from the previous attribute's operator set.
result: [pending]

## Summary

total: 3
passed: 0
issues: 0
pending: 3
skipped: 0
blocked: 0

## Gaps
