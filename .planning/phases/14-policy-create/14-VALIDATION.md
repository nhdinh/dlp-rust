---
phase: 14
slug: policy-create
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-16
---

# Phase 14 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust built-in) |
| **Config file** | none — existing test infrastructure |
| **Quick run command** | `cargo test -p dlp-admin-cli` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-admin-cli`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 14-01-01 | 01 | 1 | POLICY-02 | — | form_snapshot preserves caller form on ConditionsBuilder round-trip | unit | `cargo test -p dlp-admin-cli form_snapshot` | ❌ W0 | ⬜ pending |
| 14-01-02 | 01 | 1 | POLICY-02 | — | validation rejects empty name and non-integer priority | unit | `cargo test -p dlp-admin-cli validate_policy_form` | ❌ W0 | ⬜ pending |
| 14-01-03 | 01 | 1 | POLICY-02 | — | POST /admin/policies payload serializes with correct action wire format (deny_with_alert not deny_with_log) | unit | `cargo test -p dlp-admin-cli policy_payload_serialization` | ❌ W0 | ⬜ pending |
| 14-02-01 | 02 | 2 | POLICY-02 | — | PolicyCreate screen renders all form fields | manual | visual inspection | N/A | ⬜ pending |
| 14-02-02 | 02 | 2 | POLICY-02 | — | Add Conditions key opens ConditionsBuilder; conditions display on return | manual | visual inspection | N/A | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-admin-cli/src/dispatch.rs` — stubs for POLICY-02 form validation unit tests
- [ ] Unit tests for `form_snapshot` round-trip, `validate_policy_form`, and `policy_payload_serialization`

*Existing `cargo test` infrastructure covers all phase requirements.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| PolicyCreate renders correctly in TUI | POLICY-02 | TUI rendering requires live terminal | Launch dlp-admin-cli, navigate to Policy Create, verify all fields render |
| Add Conditions key opens builder | POLICY-02 | TUI interaction requires live terminal | Press the designated key on PolicyCreate, verify ConditionsBuilder opens |
| Network error shows descriptive text | POLICY-02 | Requires admin server to be running | Kill server mid-submit, verify error message displayed |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
