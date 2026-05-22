---
phase: 51
slug: ntdll-syscall-stub-trampolines-edr-coexistence
status: draft
nyquist_compliant: false
wave_0_complete: false
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
| 51-01-01 | 01 | 1 | BLOCK-08 | T-51-01 | EDR detected before patch, stub skipped | unit | `cargo test --package dlp-hook-dll edr_detection` | ❌ W0 | ⬜ pending |
| 51-01-02 | 01 | 1 | BLOCK-08 | T-51-02 | Thread-suspend protocol aborts on RIP conflict | unit | `cargo test --package dlp-hook-dll thread_suspend` | ❌ W0 | ⬜ pending |
| 51-02-01 | 02 | 1 | BLOCK-08 | T-51-03 | Trampoline routes direct-syscall to classification | unit | `cargo test --package dlp-hook-dll ntdll_trampoline` | ❌ W0 | ⬜ pending |
| 51-03-01 | 03 | 2 | BLOCK-09 | T-51-04 | Re-verification emits HookOverwritten alert | unit | `cargo test --package dlp-hook-dll reverify` | ❌ W0 | ⬜ pending |
| 51-04-01 | 04 | 2 | BLOCK-09 | T-51-05 | SIEM event emitted at boot when flag enabled | unit | `cargo test --package dlp-agent ntdll_siem` | ❌ W0 | ⬜ pending |
| 51-05-01 | 05 | 3 | BLOCK-08 | T-51-06 | Chaos test: 1000 threads, 100 cycles, zero crashes | manual | Run `chaos_test.exe` on Windows 11 host | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-hook-dll/src/ntdll_patcher.rs` — module stub with `#[cfg(test)]` tests
- [ ] `dlp-hook-dll/src/edr_detector.rs` — module stub with mock EDR module tests
- [ ] `dlp-hook-dll/src/thread_control.rs` — suspend/resume protocol unit tests (mock Nt APIs)
- [ ] `dlp-common/src/audit.rs` — `ntdll_patching_enabled` event type test

*If none: "Existing infrastructure covers all phase requirements."*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Direct-syscall bypass blocked on real Windows | BLOCK-08 | Requires real ntdll + kernel | 1. Build `direct_syscall_test.exe` (Go or syswhispers-style). 2. Enable `ntdll_patching`. 3. Attempt `NtWriteFile` to T4 path. 4. Verify `STATUS_ACCESS_DENIED`. |
| EDR coexistence on CrowdStrike endpoint | BLOCK-08 | Requires real EDR installation | 1. Install CrowdStrike Falcon on Windows 11 VM. 2. Enable `ntdll_patching`. 3. Verify agent boots with `ntdll_patching_edr_detected` event. 4. Verify IAT hooks still operational. |
| Chaos test: torn-instruction safety | BLOCK-08 | Requires real threads + scheduler | 1. Run `chaos_test.exe` on Windows 11. 2. 1000 threads spin on `NtCreateFile`. 3. Main thread performs 100 patch/unpatch cycles. 4. Monitor for WER events, crashes, or torn reads. |

*If none: "All phase behaviors have automated verification."*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
