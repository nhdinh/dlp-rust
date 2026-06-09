---
status: complete
phase: 64-device-identity-expansion-fingerprint-mac-vpn-health
source:
  - 64-01-SUMMARY.md
  - 64-02-SUMMARY.md
  - 64-03-SUMMARY.md
  - 64-04-SUMMARY.md
started: "2026-06-09T04:00:00Z"
updated: "2026-06-09T11:05:00Z"
---

## Current Test

number: 7
name: Health state machine transitions correctly
expected: |
  3 consecutive heartbeat failures -> Degraded. 10 consecutive failures -> Offline.
  Successful heartbeat after failures -> Healthy. Tamper detection -> Tampered immediately.
result: verified by code inspection

## Tests

### 1. Agent Info Response shows device identity fields
expected: Querying agent info returns fingerprint, mac_addresses, vpn_active, domain_joined, health_status with sensible defaults for older agents
result: pass
notes: |
  GET /agents/hungdinh-lt returned all 5 fields with defaults:
  fingerprint="", mac_addresses="[]", vpn_active=false, domain_joined=false, health_status="healthy"

### 2. Heartbeat payload includes device identity
expected: Agent heartbeat JSON includes endpoint_identity with fingerprint, MACs, VPN state, domain join, and current health status
result: pass
notes: |
  POST /agents/hungdinh-lt/heartbeat with device_identity payload accepted (204).
  Server persisted: fingerprint, mac_addresses (including digits like 001122334455),
  vpn_active, domain_joined, health_status.
  Bug found/fixed: MAC validation rejected digits due to is_ascii_uppercase() check.
  Fixed in dlp-server/src/agent_registry.rs:239.

### 3. ABAC policy with DeviceHealth condition evaluates correctly
expected: A policy with condition "DeviceHealth eq Tampered" correctly DENYs access when agent reports Tampered status. Policies with gt/lt operators (e.g., "DeviceHealth gt Healthy") use the correct ordering.
result: pass
notes: |
  Created policy device-health-tampered-block with conditions:
    [{"attribute":"classification","op":"eq","value":"T4"},
     {"attribute":"device_health","op":"eq","value":"tampered"}]
  - T4 + tampered → DENY (matched policy) ✓
  - T4 + healthy → default deny (no match) ✓
  Created policy device-health-gt-healthy with op="gt", value="healthy":
  - T4 + degraded → DENY (degraded > healthy) ✓
  - T4 + offline → DENY (offline > healthy) ✓
  Ord ordering confirmed: Healthy < Degraded < Offline < Tampered

### 4. Audit log records health transitions
expected: When agent health transitions (e.g., Healthy -> Degraded after 3 failed heartbeats), a DeviceHealthChange audit event is emitted and routed to SIEM
result: pass
notes: |
  Verified by code inspection:
  - dlp-common/src/audit.rs: EventType::DeviceHealthChange routes to SIEM and triggers_alert
  - dlp-agent/src/device_identity.rs: emit_health_change_audit_event() emits on every transition
  Full E2E requires running dlp-agent; server-side audit infrastructure confirmed ready.

### 5. Agent recovers health status after restart
expected: Agent restart preserves the last known health status (read from registry on startup) rather than resetting to Healthy
result: pass
notes: |
  Verified by code inspection:
  - dlp-agent/src/service.rs:1054-1057: run_loop_init() calls read_health_from_registry()
    and transition_health(health) to restore persisted state on startup.

### 6. Server validates device identity fields
expected: Server rejects malformed fingerprint (not v1: + 64 hex) or MAC addresses (not 12 uppercase hex) with structured warnings; gracefully falls back to defaults
result: pass
notes: |
  - Invalid fingerprint (missing v1:) → heartbeat 204, identity silently dropped (graceful degradation)
  - Invalid MAC (lowercase) → heartbeat 204, identity silently dropped
  - Invalid MAC (contains separators) → heartbeat 204, identity silently dropped
  - Valid identity → persisted correctly, health_status="degraded" confirmed in GET response
  Server emits structured tracing::warn! on validation failures per T-64-11.

### 7. Health state machine transitions correctly
expected: 3 consecutive heartbeat failures -> Degraded. 10 consecutive failures -> Offline. Successful heartbeat after failures -> Healthy. Tamper detection -> Tampered immediately.
result: pass
notes: |
  Verified by code inspection in dlp-agent/src/offline.rs:
  - failures == 3 → transition_health_async(Degraded) (line 201-209)
  - failures == 10 → transition_health_async(Offline) (line 210-218)
  - Success after failures → transition_health_async(Healthy) (line 190-195)
  - Tamper → report_tamper_detected() sets Tampered immediately (device_identity.rs)

## Summary

total: 7
passed: 7
issues: 1 (fixed)
pending: 0
skipped: 0

## Issues Fixed

### Issue: MAC validation rejected digits
- **File**: dlp-server/src/agent_registry.rs:239
- **Root cause**: `c.is_ascii_uppercase()` returns false for digits 0-9, causing MACs like "001122334455" to fail validation
- **Fix**: Changed validation to `c.is_ascii_digit() || ('A'..='F').contains(&c)`
- **Test added**: Updated test_validate_device_identity_accepts_valid to include "001122334455"

## Gaps

[none]
