---
status: complete
phase: 02-require-jwt-secret-in-production
source: [02-require-jwt-secret-in-production/SUMMARY.md]
started: 2026-04-14T09:28:00Z
updated: 2026-04-14T09:28:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Cold Start Smoke Test
expected: |
  Kill any running server/service. Clear ephemeral state (temp DBs, caches,
  lock files). Start the application from scratch. Server boots without errors,
  any seed/migration completes, and a primary query (health check, homepage
  load, or basic API call) returns live data.
result: pass

### 2. JWT_SECRET Required — Production Mode
expected: |
  Start dlp-server WITHOUT JWT_SECRET set. Server prints a user-readable error
  and exits before binding the listener. Then start with JWT_SECRET set — server
  starts normally.
result: pass

### 3. --dev Flag Enables Insecure Fallback
expected: |
  Start dlp-server with --dev flag (no JWT_SECRET needed). Server starts using
  the hardcoded dev secret and logs a visible warning that it is running in
  insecure mode.
result: pass

### 4. Admin Login with Valid Credentials
expected: |
  With server running in dev mode, POST /admin/login with valid credentials
  returns a JWT token. The token can be used in Authorization: Bearer <token>
  to access a protected endpoint.
result: pass

### 5. Invalid / Expired JWT Rejected
expected: |
  Sending a request with an expired token, invalid token, or missing token
  to a protected endpoint returns HTTP 401 Unauthorized.
result: pass

## Summary

total: 5
passed: 5
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

[none]
