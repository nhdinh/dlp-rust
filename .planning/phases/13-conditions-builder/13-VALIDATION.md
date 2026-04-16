---
phase: 13
slug: conditions-builder
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-16
---

# Phase 13 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust built-in) |
| **Config file** | none — existing infrastructure |
| **Quick run command** | `cargo test -p dlp-admin-cli 2>&1` |
| **Full suite command** | `cargo test --all 2>&1` |
| **Estimated runtime** | ~10 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-admin-cli 2>&1`
- **After every plan wave:** Run `cargo test --all 2>&1`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 13-01-01 | 01 | 1 | POLICY-05 | — | N/A | unit | `cargo test -p dlp-admin-cli conditions` | ✅ existing | ⬜ pending |
| 13-01-02 | 01 | 1 | POLICY-05 | — | N/A | unit | `cargo test -p dlp-admin-cli dispatch` | ✅ existing | ⬜ pending |
| 13-01-03 | 01 | 1 | POLICY-05 | — | N/A | unit | `cargo build -p dlp-admin-cli` | ✅ existing | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No new test stubs needed before Wave 1.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Step 1→2→3 picker flow renders correctly in terminal | POLICY-05 | TUI rendering requires visual inspection | Run `cargo run -p dlp-admin-cli`, navigate to conditions builder, verify each step advances and resets |
| Delete binding removes condition from pending list | POLICY-05 | TUI interaction requires visual inspection | Add 2 conditions, press `d` on first, verify list updates |
| Tab focus switch between picker and pending list | POLICY-05 | TUI focus state requires visual inspection | Navigate to conditions builder with conditions added, press Tab, verify focus indicator moves |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
