---
phase: 58
slug: differentiators-bundle-override-diagnostic-hash-evidence-sel
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-02
---

# Phase 58 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Built-in `#[test]` + `cargo test` |
| **Config file** | None — per-crate test modules |
| **Quick run command** | `cargo test -p dlp-hook-dll` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~60 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p <affected_crate>`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 58-01-01 | 01 | 1 | DIFF-03 | T-58-03 | SHA-256 hash only on DENY, capped at 100MB, offloaded to thread pool | unit | `cargo test -p dlp-hook-dll hash_compute` | Yes | green |
| 58-01-02 | 01 | 1 | DIFF-03 | T-58-03 | 100MB cap truncates hash correctly, hash_skipped on pool saturation | unit | `cargo test -p dlp-hook-dll test_hash_truncation` | Yes | green |
| 58-02-01 | 02 | 1 | DIFF-02 | T-58-02 | Diagnostic snapshot captures on DENY with correct ABAC context | unit | `cargo test -p dlp-hook-dll test_ring_buffer_push_and_drain` | Yes | green |
| 58-02-02 | 02 | 1 | DIFF-02 | T-58-02 | Ring buffer bounds to 1000 entries and overwrites old | unit | `cargo test -p dlp-hook-dll test_ring_buffer_capacity` | Yes | green |
| 58-03-01 | 03 | 2 | DIFF-02 | T-58-02 | Agent polls and aggregates diagnostic snapshots correctly | unit | `cargo test -p dlp-agent test_diagnostic_poll` | Yes | green |
| 58-03-02 | 03 | 2 | DIFF-04 | T-58-04 | Health counters increment and snapshot emission works | unit | `cargo test -p dlp-hook-dll test_health_counters` | No — impl missing | ESCALATED |
| 58-04-01 | 04 | 2 | DIFF-04 | T-58-04 | Health snapshot computes cache hit rate and thresholds correctly | unit | `cargo test -p dlp-agent test_hit_rate_computation` | Yes | green |
| 58-04-02 | 04 | 2 | DIFF-04 | T-58-04 | Auto-alert emits on health transition (Degraded, Critical) | integration | `cargo test -p dlp-agent test_health_alert` | Yes | green |
| 58-05-01 | 05 | 3 | DIFF-01 | T-58-01 | Override request flows through pipe to agent to user UI | unit + integration | `cargo test -p dlp-hook-dll test_request_override` | No — impl gap | ESCALATED |
| 58-05-02 | 05 | 3 | DIFF-01 | T-58-01 | Approval token caching and verification works end-to-end | integration | `cargo test -p dlp-agent test_approval_cache` | Yes | green |
| 58-06-01 | 06 | 3 | DIFF-02 | T-58-02 | Admin API serves paginated diagnostics with filters | integration | `cargo test -p dlp-server --test diagnostics_api_integration` | Yes | green |
| 58-06-02 | 06 | 3 | DIFF-03 | T-58-03 | Audit event includes content_sha256 on blocked write | integration | `cargo test -p dlp-server test_audit_hash_field` | Yes | green |
| 58-07-01 | 07 | 4 | DIFF-02 | T-58-02 | TUI renders diagnostic list with detail popup | unit | `cargo test -p dlp-admin-cli test_diagnostic_list_render` | Yes | green |
| 58-07-02 | 07 | 4 | DIFF-04 | T-58-04 | TUI renders self-health dashboard with sparkline | unit | `cargo test -p dlp-admin-cli test_sparkline_render` | Yes | green |

*Status: pending / green / red / flaky / ESCALATED*

---

## Wave 0 Requirements

- [x] `dlp-hook-dll/src/diagnostic_ring.rs` — unit tests for push/drain/capacity (6 tests, 5 ignored due to shared OnceLock)
- [x] `dlp-hook-dll/src/hash_compute.rs` — unit tests for known hashes, truncation, null buffer (9 tests)
- [ ] `dlp-hook-dll/src/health_counters.rs` — **IMPLEMENTATION MISSING** — unit tests for counter increment, snapshot emission (ESCALATED)
- [x] `dlp-agent/src/diagnostic_aggregator.rs` — unit tests for poll, aggregate, filter (7 tests)
- [x] `dlp-agent/src/health_aggregator.rs` — unit tests for threshold computation, alert emission (11 tests)
- [x] `dlp-server/tests/diagnostics_api_integration.rs` — integration tests for GET /admin/diagnostics (5 tests)
- [x] `dlp-admin-cli/src/screens/diagnostic_list.rs` — unit tests for dispatch/render (7 tests)
- [x] `dlp-admin-cli/src/screens/self_health_dashboard.rs` — unit tests for sparkline render (2 tests)

---

## Gap Details

### Gap 58-03-02: health_counters.rs missing

**Requirement:** Health counters increment and snapshot emission works (DIFF-04, T-58-04)

**Status:** ESCALATED — implementation missing

**Details:**
- `dlp-hook-dll/src/health_counters.rs` does not exist
- Plan 58-02 Task 1 specified creating this file with `HealthCounters` struct, atomic increment methods, and `emit_health_snapshot()`
- `perf_telemetry.rs` does not call `emit_health_snapshot()` (Plan 58-02 Task 2 incomplete)
- Without `health_counters.rs`, no health counter tracking exists in the hook DLL

**Evidence:**
```bash
$ find . -name "health_counters.rs" -type f
# No results
```

**Recommendation:** Implement `health_counters.rs` per Plan 58-02 Task 1 specification.

---

### Gap 58-05-01: Override flow behavioral test blocked by implementation

**Requirement:** Override request flows through pipe to agent to user UI (DIFF-01, T-58-01)

**Status:** ESCALATED — cannot test without mocking infrastructure

**Details:**
- `HookResponse.approval_override` field exists and is checked in `trampolines.rs` (lines 206-217, 266-274, 341-349)
- `dlp-common/src/hook_ipc.rs` has roundtrip tests for `approval_override` field
- `dlp-agent/src/approval_cache.rs` has comprehensive tests for token verification (14 tests)
- **Missing:** Behavioral test that verifies when `classify_path` returns `approval_override: Some(true)` with `decision: DENY`, the trampoline returns `None` (allow) instead of `Some(deny)`
- **Blocker:** `classify_path` is `pub(crate)` and performs a real named pipe round-trip. Cannot be mocked from tests without changing implementation to accept a trait object or function pointer.

**Evidence:**
```rust
// trampolines.rs lines 206-217: approval_override check exists
Ok(ref resp)
    if (resp.decision == crate::Decision::DENY
        || resp.decision == crate::Decision::DenyWithAlert)
        && resp.approval_override == Some(true) =>
{
    // DIFF-01: Approval override granted — allow the operation.
    fail_state.record_pipe_success(cache_version);
    ...
    None
}
```

**Recommendation:** Either:
1. Refactor `classify_and_log_path` to accept a `classify_fn` parameter for test injection, OR
2. Add an integration test that spins up a mock agent listening on a named pipe

---

### Gap 58-02 (Plan 58-02): Trampoline integration incomplete

**Requirement:** HookWriteFile/HookWriteFileEx trampolines compute content hash and emit diagnostic snapshot on DENY (DIFF-02, DIFF-03)

**Status:** ESCALATED — implementation incomplete

**Details:**
- `trampolines.rs` does NOT call `compute_content_hash` or `push_snapshot` (verified by grep)
- Plan 58-02 Task 3 specified wiring these into the DENY path of WriteFile/WriteFileEx trampolines
- The hash computation and diagnostic snapshot modules exist and are tested, but are not called from the hot path

**Evidence:**
```bash
$ grep -n "compute_content_hash\|push_snapshot" dlp-hook-dll/src/trampolines.rs
# No matches
```

**Recommendation:** Wire `compute_content_hash` and `push_snapshot` calls into `classify_and_log_path` or the individual trampolines on the DENY path, per Plan 58-02 Task 3.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Override dialog appears on DENY in real Windows process | DIFF-01 | Requires actual Windows UI interaction | 1. Block a WriteFile operation 2. Verify modal dialog appears 3. Enter justification and submit 4. Verify approval request created in DB |
| Self-health dashboard shows live data from injected process | DIFF-04 | Requires actual DLL injection | 1. Inject hook DLL into notepad.exe 2. Verify counters increment 3. Verify dashboard shows green status 4. Simulate degradation and verify alert |

---

## Validation Sign-Off

- [x] All tasks have automated verify or Wave 0 dependencies (11/13 green, 2/13 escalated)
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (where implementation exists)
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter — BLOCKED by 2 escalated gaps

**Approval:** pending — 2 implementation gaps require developer attention

---

## Tests Added This Session

| Gap | File | Tests | Command | Status |
|-----|------|-------|---------|--------|
| 58-06-01 | `dlp-server/tests/diagnostics_api_integration.rs` | 5 integration tests for GET /admin/diagnostics | `cargo test -p dlp-server --test diagnostics_api_integration` | green |

### Test Details

1. `test_diagnostics_standalone_returns_empty` — Verifies standalone server mode returns empty list
2. `test_diagnostics_with_data_returns_snapshots` — Verifies populated store returns snapshots with correct fields
3. `test_diagnostics_pagination` — Verifies limit/offset pagination works correctly
4. `test_diagnostics_requires_auth` — Verifies 401 without JWT
5. `test_diagnostics_filter_by_user_sid` — Verifies user_sid query parameter filtering
