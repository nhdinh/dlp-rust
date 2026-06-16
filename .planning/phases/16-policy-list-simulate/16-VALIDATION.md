---
phase: 16
slug: policy-list-simulate
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-16
---

# Phase 16 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (built-in Rust test framework) |
| **Config file** | none (tests use `#[cfg(test)]` modules inline) |
| **Quick run command** | `cargo test -p dlp-admin-cli` |
| **Full suite command** | `cargo test -p dlp-admin-cli` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-admin-cli`
- **After every plan wave:** Run `cargo test -p dlp-admin-cli`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 16-01a-01 | 01a | 1 | POLICY-01 | — | PolicyList renders 5 columns with Mode and global_mode | grep | `grep "Priority.*Name.*Action.*Enabled.*Mode" render.rs` | ✅ | ✅ green |
| 16-01a-02 | 01a | 1 | POLICY-01 | — | Client-side sort with priority ascending + name tiebreak | grep | `grep "sort_by" dispatch.rs` | ✅ | ✅ green |
| 16-01b-01 | 01b | 1 | POLICY-06 | — | Simulate types exist in app.rs | grep | `grep "SimulateOutcome\|SimulateFormState\|SimulateCaller" app.rs` | ✅ | ✅ green |
| 16-01b-02 | 01b | 1 | POLICY-06 | — | Screen::PolicySimulate variant with all 6 fields | grep | `grep "PolicySimulate" app.rs` | ✅ | ✅ green |
| 16-01b-03 | 01b | 1 | POLICY-06 | — | Dispatch and render wiring for simulate | grep | `grep "handle_policy_simulate\|draw_policy_simulate" dispatch.rs render.rs` | ✅ | ✅ green |
| 16-02-01 | 02 | 2 | POLICY-06 | — | Context decisions revised to 5-column reality | grep | `grep "Priority.*Name.*Action.*Enabled.*Mode" 16-CONTEXT.md` | ✅ | ⬜ pending |
| 16-02-02 | 02 | 2 | POLICY-06 | — | SimulateOutcome::Loading variant exists | grep | `grep "SimulateOutcome::Loading" app.rs` | ✅ | ⬜ pending |
| 16-02-03 | 02 | 2 | POLICY-06 | — | App.terminal field stores Tui for forced redraw | grep | `grep "terminal: Option" app.rs` | ✅ | ⬜ pending |
| 16-02-04 | 02 | 2 | POLICY-06 | — | Client-side validation rejects empty user_sid/path | unit | `cargo test -p dlp-admin-cli simulate_tests` | ✅ | ⬜ pending |
| 16-02-05 | 02 | 2 | POLICY-06 | — | Group normalization: dedupe + lowercase | unit | `cargo test -p dlp-admin-cli simulate_tests` | ✅ | ⬜ pending |
| 16-02-06 | 02 | 2 | POLICY-06 | — | Granular error classification (timeout/connection/decode/network/server) | grep | `grep "is_timeout\|is_connect\|is_decode" dispatch.rs` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No new test framework needed.

---

## Manual-Only Verifications

All phase behaviors have automated verification via grep assertions and cargo test.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter (after all plans complete)

**Approval:** pending
