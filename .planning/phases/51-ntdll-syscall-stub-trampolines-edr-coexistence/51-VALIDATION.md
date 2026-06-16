---
phase: 51
slug: ntdll-syscall-stub-trampolines-edr-coexistence
status: final
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-22
---

# Phase 51 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (built-in) + custom chaos-test fixture |
| **Config file** | none — workspace-level |
| **Quick run command** | `cargo test --workspace --lib` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~60 seconds (unit) + manual chaos test on Windows host |

---

## Sampling Rate

- **After every task commit:** Run `cargo test --workspace --lib`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 51-01-01 | 01 | 1 | BLOCK-08 | T-51-01 | EDR detected before patch, stub skipped | unit | `cargo test --package dlp-hook-dll edr_detector -- --test-threads=1` | ✅ | ✅ green |
| 51-01-02 | 01 | 1 | BLOCK-08 | T-51-02 | Thread-suspend protocol aborts on RIP conflict | unit | `cargo test --package dlp-hook-dll thread_suspender -- --test-threads=1` | ✅ | ✅ green |
| 51-02-01 | 02 | 1 | BLOCK-08 | T-51-03 | Trampoline routes direct-syscall to classification | unit | `cargo test --package dlp-hook-dll ntdll_patcher -- --test-threads=1` | ✅ | ✅ green |
| 51-03-01 | 03 | 2 | BLOCK-09 | T-51-04 | Re-verification emits HookOverwritten alert | unit | `cargo test --package dlp-hook-dll ntdll_patcher -- --test-threads=1` | ✅ | ✅ green |
| 51-04-01 | 04 | 2 | BLOCK-09 | T-51-05 | SIEM event emitted at boot when flag enabled | unit | `cargo test --package dlp-agent test_emit_ntdll_patching_enabled_event -- --test-threads=1` | ✅ | ✅ green |
| 51-05-01 | 05 | 3 | BLOCK-08 | T-51-06 | Chaos test: 1000 threads, 100 cycles, zero crashes | manual | Run `cargo test -p dlp-hook-dll --test ntdll_chaos_test -- --ignored --nocapture` on Windows 11 host | ✅ | ⚠️ manual |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky · ⚠️ manual*

---

## Wave 0 Requirements

- [x] `dlp-hook-dll/src/ntdll_patcher.rs` — module with `#[cfg(test)]` tests
- [x] `dlp-hook-dll/src/edr_detector.rs` — module with mock EDR module tests
- [x] `dlp-hook-dll/src/thread_suspender.rs` — suspend/resume protocol unit tests (mock Nt APIs)
- [x] `dlp-common/src/audit.rs` — `ntdll_patching_enabled` event type test

*Wave 0 infrastructure covers all phase requirements.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Direct-syscall bypass blocked on real Windows | BLOCK-08 | Requires real ntdll + kernel | 1. Build `direct_syscall_test.exe` (Go or syswhispers-style). 2. Enable `ntdll_patching`. 3. Attempt `NtWriteFile` to T4 path. 4. Verify `STATUS_ACCESS_DENIED`. |
| EDR coexistence on CrowdStrike endpoint | BLOCK-08 | Requires real EDR installation | 1. Install CrowdStrike Falcon on Windows 11 VM. 2. Enable `ntdll_patching`. 3. Verify agent boots with `ntdll_patching_edr_detected` event. 4. Verify IAT hooks still operational. |
| Chaos test: torn-instruction safety | BLOCK-08 | Requires real threads + scheduler | 1. Run `cargo test -p dlp-hook-dll --test ntdll_chaos_test -- --ignored --nocapture` on Windows 11. 2. 1000 threads spin on `NtCreateFile`. 3. Main thread performs 100 patch/unpatch cycles. 4. Monitor for WER events, crashes, or torn reads. |

*Manual-only items are environmental/integration tests that cannot run safely in CI.*

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 60s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved

---

## Validation Audit 2026-06-16

| Metric | Count |
|--------|-------|
| Gaps found | 3 |
| Resolved | 3 |
| Escalated | 0 |

### Gaps Resolved

1. **Flaky thread enumeration (PARTIAL → COVERED)** — `enumerate_process_threads` now retries on `STATUS_INFO_LENGTH_MISMATCH` and the full `cargo test -p dlp-hook-dll --lib -- --test-threads=1` suite is green.
2. **Missing SIEM emission test (MISSING → COVERED)** — Added `test_emit_ntdll_patching_enabled_event` in `dlp-agent/src/service.rs` using an in-process audit capture sink.
3. **Draft validation documentation** — Updated per-task map, Wave 0 checklist, and sign-off to reflect final state.

### Test Results

| Command | Result |
|---------|--------|
| `cargo test -p dlp-hook-dll --lib -- --test-threads=1` | 281 passed, 0 failed, 1 ignored |
| `cargo test -p dlp-common --lib -- --test-threads=1` | 308 passed, 0 failed |
| `cargo test -p dlp-agent --lib -- --test-threads=1` | 845 passed, 0 failed |
| `cargo clippy -p dlp-hook-dll -p dlp-agent -p dlp-common -- -D warnings` | Clean |
| `cargo fmt --check` | Clean |
