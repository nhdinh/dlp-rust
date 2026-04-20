---
phase: 19
slug: boolean-mode-tui-import-export
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-20
---

# Phase 19 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (built-in Rust test harness) |
| **Config file** | Cargo.toml workspace (no test config needed) |
| **Quick run command** | `cargo test -p dlp-admin-cli -p dlp-common --lib` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~30–45 seconds (admin-cli + common lib); ~60–90 seconds full |

---

## Sampling Rate

- **After every task commit:** Run `cargo check --workspace` (fast type-check, ~5s)
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd-verify-work`:** Full suite must be green plus `cargo fmt --check` and `cargo clippy -- -D warnings`
- **Max feedback latency:** 90 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | Status |
|---------|------|------|-------------|-----------|-------------------|--------|
| 19-01-01 | 01 | 1 | POLICY-09 | unit/compile | `cargo check -p dlp-admin-cli` | ⬜ pending |
| 19-01-02 | 01 | 1 | POLICY-09 | unit | `cargo test -p dlp-admin-cli policy_payload_mode` | ⬜ pending |
| 19-01-03 | 01 | 1 | POLICY-09 | unit | `cargo test -p dlp-admin-cli policy_payload_legacy_default` | ⬜ pending |
| 19-02-01 | 02 | 2 | POLICY-09 | unit/compile | `cargo check -p dlp-admin-cli` | ⬜ pending |
| 19-02-02 | 02 | 2 | POLICY-09 | unit | `cargo test -p dlp-admin-cli policy_form_mode_cycle` | ⬜ pending |
| 19-02-03 | 02 | 2 | POLICY-09 | integration | `cargo test -p dlp-server --test mode_end_to_end` | ⬜ pending |
| 19-02-04 | 02 | 2 | POLICY-09 | integration | `cargo test -p dlp-server --test mode_end_to_end mode_all` | ⬜ pending |
| 19-02-05 | 02 | 2 | POLICY-09 | integration | `cargo test -p dlp-server --test mode_end_to_end mode_any` | ⬜ pending |
| 19-02-06 | 02 | 2 | POLICY-09 | integration | `cargo test -p dlp-server --test mode_end_to_end mode_none` | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- No new test framework install needed — `cargo test` is built-in and already used throughout the workspace.
- `dlp-server/tests/admin_audit_integration.rs` is the template for the new `mode_end_to_end.rs` file; no shared conftest extraction needed.

*Existing infrastructure covers all Phase 19 requirements.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Footer advisory hint renders with `Color::DarkGray` when `mode != ALL && conditions.is_empty()` | POLICY-09 / D-04 | `ratatui::TestBackend` not yet wired in the project; visual assertion is UAT-scope | Launch TUI → Policy Create → cycle mode to ANY → observe footer line `Note: mode=ANY with no conditions will never match.` |
| Mode cycler responds to Enter/Space in Policy Create | POLICY-09 / D-01 | Keypress routing is easier to UAT than to unit-test | Launch TUI → Policy Create → select Mode row → press Enter 3× and observe `ALL → ANY → NONE → ALL` |
| Legacy v0.4.0 export file imports with `mode = ALL` | POLICY-09 / D-11 | End-to-end file round-trip in the TUI depends on the file dialog | Export on v0.4.0 build → import on v0.5.0 build → verify policies evaluate identically |

---

## Validation Sign-Off

- [ ] All tasks have automated verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (N/A — no Wave 0 needed)
- [ ] No watch-mode flags (cargo test is single-shot)
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter (pending planner confirmation)

**Approval:** pending
