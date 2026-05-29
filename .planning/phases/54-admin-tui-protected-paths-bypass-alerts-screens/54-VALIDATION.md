---
phase: 54
slug: admin-tui-protected-paths-bypass-alerts-screens
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-28
---

# Phase 54 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (built-in) |
| **Config file** | none — uses default `#[cfg(test)]` modules |
| **Quick run command** | `cargo test -p dlp-admin-cli` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~60 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-admin-cli`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 54-01-01 | 01 | 1 | UX-01 | T-54-01 | Path input validated server-side | unit | `cargo test -p dlp-admin-cli` | ⬜ W0 | ⬜ pending |
| 54-01-02 | 01 | 1 | UX-01/UX-02 | T-54-03 | Only manual entries deletable | unit | `cargo test -p dlp-admin-cli` | ⬜ W0 | ⬜ pending |
| 54-02-01 | 02 | 1 | UX-01/UX-02 | T-54-04 | Query params encoded safely | unit | `cargo test -p dlp-admin-cli` | ⬜ W0 | ⬜ pending |
| 54-03-01 | 03 | 2 | UX-01 | T-54-03 | Delete guarded by source==manual | unit | `cargo test -p dlp-admin-cli` | ⬜ W0 | ⬜ pending |
| 54-04-01 | 04 | 2 | UX-02 | T-54-09 | Optimistic ack reverted on failure | unit | `cargo test -p dlp-admin-cli` | ⬜ W0 | ⬜ pending |
| 54-05-01 | 05 | 2 | UX-02 | — | Detail view read-only | unit | `cargo test -p dlp-admin-cli` | ⬜ W0 | ⬜ pending |
| 54-06-01 | 06 | 3 | UX-01/UX-02 | T-54-14 | No orphaned dead code | unit | `cargo test -p dlp-admin-cli` | ⬜ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- Existing infrastructure covers all phase requirements (Rust built-in test framework, TestBackend for ratatui).

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| TUI visual layout at 80x24 | UX-01/UX-02 | Visual rendering requires human verification | Open Protected Paths and Bypass Alerts screens, verify table columns align, badges display correctly, footer hints visible |
| Keyboard navigation flow | UX-01/UX-02 | Interactive input requires human verification | Navigate MainMenu -> SystemMenu -> Protected Paths -> add path -> confirm -> back. Repeat for Bypass Alerts. |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
