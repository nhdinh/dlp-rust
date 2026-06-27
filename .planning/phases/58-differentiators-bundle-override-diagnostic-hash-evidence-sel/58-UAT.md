---
status: testing
phase: 58-differentiators-bundle-override-diagnostic-hash-evidence-sel
source: 58-04-SUMMARY.md
started: 2026-06-22T00:00:00Z
updated: 2026-06-22T00:00:00Z
---

## Current Test
<!-- OVERWRITE each test - shows where we are -->

number: 2
name: Admin Diagnostics Endpoint - Authentication
expected: |
  A request to GET /admin/diagnostics without a valid JWT returns 401 Unauthorized.
awaiting: user response

## Tests

### 1. Cold Start Smoke Test
expected: Kill any running dlp-server. Clear ephemeral state (temp DBs, caches, lock files). Start dlp-server from scratch. Server boots without errors, migrations complete, and a primary query (health check or GET /admin/diagnostics with JWT) returns live data.
result: issue
reported: "guide me"
severity: major

### 2. Admin Diagnostics Endpoint - Authentication
expected: A request to GET /admin/diagnostics without a valid JWT returns 401 Unauthorized.
result: [pending]

### 3. Admin Diagnostics Endpoint - Pagination and Filtering
expected: With a valid admin JWT, GET /admin/diagnostics returns a paginated list. Query parameters since, user_sid, policy_id, limit, offset filter results correctly, and the limit is capped at 1000 entries.
result: [pending]

### 4. Audit Events Evidence Hashing
expected: Inserting audit events with content produces a content_sha256 value. Querying the audit event returns the same SHA-256 hash, and null content yields null hash.
result: [pending]

### 5. Agent Service Aggregator Startup
expected: Starting dlp-agent service initializes DiagnosticAggregator and HealthAggregator without panic and begins listening on the hook IPC named pipe.
result: [pending]

### 6. Hook IPC Server Diagnostics/Health Handlers
expected: A PullDiagnostics request to the hook IPC server returns a valid response, and a PullHealth request returns a HookHealthSnapshot (default if no history exists).
result: [pending]

## Summary

total: 6
passed: 0
issues: 1
pending: 5
skipped: 0

## Gaps

- truth: "Server boots cleanly from scratch and a primary admin query returns live data"
  status: failed
  reason: "User reported: guide me"
  severity: major
  test: 1
  artifacts: []
  missing: []
