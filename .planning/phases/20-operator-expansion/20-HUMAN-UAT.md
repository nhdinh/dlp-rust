---
status: passed
phase: 20-operator-expansion
source: [20-VERIFICATION.md]
started: 2026-04-20T20:34:04Z
updated: 2026-04-21T09:30:00+07:00
---

## Current Test

[UAT complete — all 5 manual TUI tests pass]

## Tests

### 1. Step 2 Operator Picker — Classification
expected: Pick Classification in Step 1 of Conditions Builder; Step 2 list shows exactly 4 operators: eq, neq, gt, lt (no others)
result: pass

### 2. Step 2 Operator Picker — MemberOf
expected: Pick MemberOf in Step 1; Step 2 list shows exactly 3 operators: eq, neq, contains
result: pass

### 3. Step 2 Operator Picker — Enum Attributes
expected: Pick DeviceTrust, NetworkLocation, or AccessContext in Step 1; Step 2 list shows exactly 2 operators: eq, neq
result: pass

### 4. MemberOf Partial-Match Title
expected: In MemberOf Step 3, the input box title reads "AD Group SID (partial match)" (not "AD Group SID")
result: pass

### 5. SC-1 Stale Operator Reset
expected: Select Classification, pick gt in Step 2, Esc back to Step 1, switch to DeviceTrust, advance to Step 2 — gt is NOT pre-selected (operator is reset)
result: pass

## Summary

total: 5
passed: 5
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps
