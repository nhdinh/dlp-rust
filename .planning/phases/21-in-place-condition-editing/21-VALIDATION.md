---
phase: 21
slug: in-place-condition-editing
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-21
---

# Phase 21 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in (`#[test]`, `cargo test`) |
| **Config file** | none — uses existing Cargo workspace |
| **Quick run command** | `cargo test -p dlp-admin-cli conditions` |
| **Full suite command** | `cargo test --all` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-admin-cli conditions`
- **After every plan wave:** Run `cargo test --all`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 21-01-01 | 01 | 1 | POLICY-10 | — | edit_index field present; `condition_to_prefill()` roundtrip correct | unit | `cargo test -p dlp-admin-cli condition_to_prefill` | ❌ W0 | ⬜ pending |
| 21-01-02 | 01 | 1 | POLICY-10 | — | 'e' key transitions to step 1 with pre-filled state | unit | `cargo test -p dlp-admin-cli edit_mode_enter` | ❌ W0 | ⬜ pending |
| 21-01-03 | 01 | 1 | POLICY-10 | — | Step 3 commit on edit replaces at original index (not push) | unit | `cargo test -p dlp-admin-cli edit_mode_save` | ❌ W0 | ⬜ pending |
| 21-01-04 | 01 | 1 | POLICY-10 | — | Esc cancel returns pending list unchanged | unit | `cargo test -p dlp-admin-cli edit_mode_cancel` | ❌ W0 | ⬜ pending |
| 21-01-05 | 01 | 1 | POLICY-10 | — | Delete binding ('d') still works after edit-mode addition | unit | `cargo test -p dlp-admin-cli delete_no_regression` | ❌ W0 | ⬜ pending |
| 21-01-06 | 01 | 1 | POLICY-10 | — | Attribute change in edit mode resets operator (SC-5) | unit | `cargo test -p dlp-admin-cli edit_attribute_change_resets_operator` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-admin-cli/src/tui/dispatch.rs` — `#[cfg(test)]` module with stubs for the 6 tests above

*Existing `cargo test` infrastructure covers compilation and execution — only new test functions need to be added.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| TUI renders modal title change for edit vs new | POLICY-10 | ratatui frame output not unit-testable | Launch TUI, open conditions builder, press 'e' on a condition, verify header says "Edit Condition" (or equivalent) |
| Visual position preservation after save | POLICY-10 | List render order requires visual inspection | Add 3 conditions, edit middle one, verify it stays at index 1 in the rendered list |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
