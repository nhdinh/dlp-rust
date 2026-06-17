---
phase: 18
slug: boolean-mode-engine-wire-format
status: verified
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-17
verified: 2026-06-17
---

# Phase 18 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Phase 18 implementation is already present in the codebase; this validation strategy covers verification of existing behavior.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (built-in Rust test harness) |
| **Config file** | none — existing workspace configuration |
| **Quick run command** | `cargo test -p dlp-server --lib -- policy_store::tests::test_evaluate` |
| **Full suite command** | `cargo test --lib --all && cargo clippy --all -- -D warnings` |
| **Estimated runtime** | ~90 seconds |

---

## Sampling Rate

- **After every task commit:** Run the quick run command for the relevant test module
- **After every plan wave:** Run `cargo test --lib --all`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 120 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 18-01-01 | 01 | 1 | POLICY-09 | T-18-04 | ALL/ANY/NONE modes evaluate correctly | unit | `cargo test -p dlp-server --lib -- policy_store::tests::test_evaluate_all_mode` | ✅ | ✅ green |
| 18-01-01 | 01 | 1 | POLICY-09 | T-18-04 | ANY mode evaluates correctly (4 tests) | unit | `cargo test -p dlp-server --lib -- policy_store::tests::test_evaluate_any_mode` | ✅ | ✅ green |
| 18-01-01 | 01 | 1 | POLICY-09 | T-18-04 | NONE mode evaluates correctly (2 tests) | unit | `cargo test -p dlp-server --lib -- policy_store::tests::test_evaluate_none_mode` | ✅ | ✅ green |
| 18-01-01 | 01 | 1 | POLICY-09 | T-18-04 | Empty-conditions edge cases match documented semantics | unit | `cargo test -p dlp-server --lib -- policy_store::tests::test_evaluate_empty_conditions` | ✅ | ✅ green |
| 18-01-01 | 01 | 1 | POLICY-12 | T-18-01 | Legacy v0.4.0 policy without mode behaves like ALL | unit | `cargo test -p dlp-server --lib -- policy_store::tests::test_legacy_v040` | ✅ | ✅ green |
| 18-01-02 | 01 | 1 | POLICY-12 | T-18-01 | PolicyPayload missing mode defaults to ALL | unit | `cargo test -p dlp-server --lib -- admin_api::tests::test_policy_payload_deserializes_without_mode_as_all` | ✅ | ✅ green |
| 18-01-02 | 01 | 1 | POLICY-12 | T-18-01 | PolicyPayload mode roundtrips (ANY, NONE) | unit | `cargo test -p dlp-server --lib -- admin_api::tests::test_policy_payload_json_with_mode_any_roundtrip && cargo test -p dlp-server --lib -- admin_api::tests::test_policy_payload_none_mode_roundtrip` | ✅ | ✅ green |
| 18-01-02 | 01 | 1 | POLICY-12 | T-18-01 | PolicyResponse missing mode defaults to ALL | unit | `cargo test -p dlp-server --lib -- admin_api::tests::test_policy_response_deserializes_without_mode_as_all` | ✅ | ✅ green |
| 18-01-02 | 01 | 1 | POLICY-12 | T-18-02 | Migration adds mode column idempotently and backfills ALL | unit | `cargo test -p dlp-server --lib -- db::tests::test_migration_add_mode_column` | ✅ | ✅ green |
| 18-01-03 | 01 | 1 | POLICY-09, POLICY-12 | — | Full workspace builds and tests pass with zero warnings | integration | `cargo build --workspace && cargo clippy --all -- -D warnings && cargo test --lib --all` | ✅ | red — `cargo test --lib --all` fails due to pre-existing `dlp-hook-dll::hook_journal::tests::windows_tests::test_error_already_exists_opens_existing` (escalated, see Manual-Only) |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements.

- [x] `cargo test` workspace harness
- [x] `clippy` lint gate
- [x] `dlp-server` lib test modules

---

## Manual-Only Verifications

| Task ID | Reason | Escalation |
|---------|--------|------------|
| 18-01-03 | `cargo test --lib --all` fails on a pre-existing Windows hook-journal test (`dlp-hook-dll::hook_journal::tests::windows_tests::test_error_already_exists_opens_existing`) unrelated to Phase 18 | Escalate to `dlp-hook-dll` maintainers; Phase 18 behavior verified independently via targeted tests |

Phase 18-specific behaviors are fully automated. The full-workspace regression gate cannot be green until the external failure above is resolved.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter (Phase 18 targeted verification is green)
- [ ] Full-workspace regression gate (`cargo test --lib --all`) is red due to an escalated, pre-existing `dlp-hook-dll` failure

**Approval:** verified 2026-06-17 — all Phase 18 tests pass, clippy clean, build clean; full-workspace test run blocked by external failure escalated to Manual-Only.

---

## Validation Audit 2026-06-17

| Metric | Count |
|--------|-------|
| Gaps found | 1 |
| Resolved | 0 |
| Escalated | 1 |

### Findings

- **COVERED:** All Phase 18 targeted automated tests pass (21 tests across evaluator modes, wire format, migration, and legacy parity).
- **PARTIAL:** Task 18-01-03 full-workspace regression command fails because `dlp-hook-dll::hook_journal::tests::windows_tests::test_error_already_exists_opens_existing` panics. This test is outside Phase 18 scope.
- **ACTION:** Escalated the `dlp-hook-dll` failure to Manual-Only. Phase 18 retains `nyquist_compliant: true` for its own requirements; the full-workspace gate should be re-run after the external failure is fixed.
