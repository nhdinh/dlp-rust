---
status: partial
phase: 26-abac-enforcement-convergence
source: [26-VERIFICATION.md]
started: 2026-04-22T15:51:18Z
updated: 2026-04-22T16:15:00Z
---

## Current Test

UATs 2-4 deferred — require Windows agent + USB hardware

## Tests

### 1. Live SourceApplication/DestinationApplication policy evaluation
expected: Create a policy with a SourceApplication condition (e.g., publisher eq "Notepad"). Trigger an evaluate request via HTTP POST /evaluate or a real clipboard event. Verify the decision reflects the app-identity match — DENY when publisher matches, ALLOW when it doesn't.
result: PASSED — DENY returned for publisher="Notepad", ALLOW for publisher="Chrome" (2026-04-22)

### 2. Blocked USB device denies all I/O
expected: With a USB device registered as Blocked in the device registry, mount it on the agent machine and attempt any file operation (read, write, create, delete, move). All actions should be blocked and an audit event emitted.
result: [deferred — requires Windows agent + USB hardware]

### 3. ReadOnly USB device allows reads, denies writes
expected: With a USB device registered as ReadOnly, attempt a file read (should be allowed) and a file write (should be denied). Confirm the enforcement distinction between the two action types.
result: [deferred — requires Windows agent + USB hardware]

### 4. Cache refresh reflects registry update within 30 s without restart
expected: Update a device's trust tier in the device registry via the admin API. Without restarting the agent, wait up to 30 seconds and attempt the corresponding file action. Verify the new tier is enforced (e.g., tier changed from FullAccess to Blocked — next write should be denied within the poll window).
result: [deferred — requires Windows agent + USB hardware]

## Summary

total: 4
passed: 1
issues: 0
pending: 0
skipped: 0
blocked: 3

## Gaps
