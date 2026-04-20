---
status: partial
phase: 20-operator-expansion
source: [20-VERIFICATION.md]
started: 2026-04-20T20:34:04Z
updated: 2026-04-20T20:34:04Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. Step 2 Operator Picker — Classification
expected: Pick Classification in Step 1 of Conditions Builder; Step 2 list shows exactly 4 operators: eq, neq, gt, lt (no others)
result: [pending]

### 2. Step 2 Operator Picker — MemberOf
expected: Pick MemberOf in Step 1; Step 2 list shows exactly 3 operators: eq, neq, contains
result: [pending]

### 3. Step 2 Operator Picker — Enum Attributes
expected: Pick DeviceTrust, NetworkLocation, or AccessContext in Step 1; Step 2 list shows exactly 2 operators: eq, neq
result: [pending]

### 4. MemberOf Partial-Match Title
expected: In MemberOf Step 3, the input box title reads "AD Group SID (partial match)" (not "AD Group SID")
result: [pending]

### 5. SC-1 Stale Operator Reset
expected: Select Classification, pick gt in Step 2, Esc back to Step 1, switch to DeviceTrust, advance to Step 2 — gt is NOT pre-selected (operator is reset)
result: [pending]

## Summary

total: 5
passed: 0
issues: 0
pending: 5
skipped: 0
blocked: 0

## Gaps
