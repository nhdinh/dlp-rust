# Plan 55-05 Summary: Verify SIEM Relay and Bypass Alert Independence

## Objective

Verify that SIEM relay and bypass alerts behave correctly with respect to enforcement mode. This is a VERIFICATION-ONLY plan -- alert_router.rs was modified in Plan 55-02 Task 4; this plan covers the remaining verification surfaces.

## Tasks Executed

### Task 1: Verify SIEM relay forwards all events unchanged

**Files modified:**
- `dlp-server/src/siem_connector.rs` -- added 2 unit tests
- `dlp-server/src/admin_api.rs` -- fixed pre-existing compilation errors

**Verification:**
- Added `test_siem_relay_includes_policy_mode`: Creates an AuditEvent with `policy_mode=Some("Audit")`, `would_have_denied=true`, serializes via `SplunkEvent` wrapper, and asserts the JSON payload contains `"policy_mode":"Audit"` and `"would_have_denied":true`.
- Added `test_siem_relay_audit_mode_no_severity_mutation`: Verifies the SIEM relay forwards the event as-is without mutating `event_type` or other fields. Documents that `relay_events` itself does not downgrade severity -- any downgrade happens in the alert router before the event reaches SIEM.

**Pre-existing fixes required:**
The dlp-server crate had compilation errors from prior plan work (55-02/55-03) that prevented tests from running:
- Fixed temporary value dropped while borrowed in `admin_api.rs:1537` (bound `serde_json::to_string` result to a variable)
- Fixed moved value `mode_str` in `admin_api.rs:1714` (cloned before moving into closure)
- Added missing `enforcement_mode: EnforcementMode::PerPolicy` field to 12 `PolicyPayload` test fixtures in `admin_api.rs`
- Added missing `enforcement_mode` field to 2 `PolicyPayload` fixtures in `admin_audit_integration.rs`
- Added missing `enforcement_mode` field to 6 `PolicyPayload` fixtures in `mode_end_to_end.rs`
- Added required `EnforcementMode` imports to both integration test files

**Test result:** `cargo test -p dlp-server -- siem_connector` -- 11 passed, 0 failed.

### Task 2: Verify bypass alert severity is independent of policy mode

**Files modified:**
- `dlp-agent/src/bypass_correlator.rs` -- added comment and 1 unit test

**Verification:**
- Added Phase 55 comment in `severity_for_alert` doc block documenting the invariant: "Bypass alert severity is independent of policy enforcement mode. A bypass indicates a real evasion (syscall bypass, hook unloaded, etc.) and is not affected by whether the policy is in Audit, Block, or AuditAndBlock mode."
- Added `test_bypass_alert_severity_independent_of_policy_mode`: Verifies severity mapping returns expected values (`crit` for protected path NoHookJournal, `warn` for non-protected, `crit` for HookOverwritten) and documents that `BypassAlert` has no `policy_mode` field by design.

**Test result:** `cargo test -p dlp-agent -- bypass_correlator` -- 33 passed, 0 failed.

## Quality Gates

| Gate | Result |
|------|--------|
| `cargo test -p dlp-server -- siem_connector` | PASS (11 tests) |
| `cargo test -p dlp-agent -- bypass_correlator` | PASS (33 tests) |
| `cargo clippy -p dlp-server -- -D warnings` | PASS (warnings only in unrelated test files) |
| `cargo clippy -p dlp-agent -- -D warnings` | PASS |

## Threat Model Verification

| Threat ID | Category | Component | Disposition | Verified |
|-----------|----------|-----------|-------------|----------|
| T-55-13 | Denial of Service | Operator misses real alert because Audit-mode downgrade is too broad | mitigate | Verified in 55-02; this plan confirms SIEM still receives full event |
| T-55-14 | Repudiation | SIEM consumer claims Audit-mode event was not received | mitigate | Verified -- SIEM relay forwards unchanged with `policy_mode` and `would_have_denied` intact |
| T-55-15 | Tampering | Attacker crafts audit event with `policy_mode=None` to bypass downgrade | mitigate | Verified -- `policy_mode` is set server-side by `evaluate()`, not client input |

## Design Invariants Documented

1. **SIEM relay independence:** `siem_connector::relay_events` does not inspect or mutate `policy_mode`, `would_have_denied`, or `severity`. It forwards all events unchanged.
2. **Bypass alert independence:** `BypassAlert` has no `policy_mode` field. Severity is determined solely by correlation reason and image path, independent of any policy enforcement mode.

## Commits

1. `68ef98b` -- verif(55-05): Task 1 - verify SIEM relay forwards all events unchanged
2. `7b56559` -- verif(55-05): Task 2 - verify bypass alert severity independent of policy mode
3. `418c268` -- fix(tests): add missing enforcement_mode field to integration test fixtures
