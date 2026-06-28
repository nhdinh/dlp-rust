---
phase: 54
slug: admin-tui-protected-paths-bypass-alerts-screens
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-28
updated: 2026-06-28
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
| 54-01-01 | 01 | 1 | UX-01 | T-54-01 | Path input validated server-side | unit | `cargo test -p dlp-admin-cli -- handle_text_input_add_protected_path_passes_raw_value_without_prevalidation` | ✅ | ✅ green |
| 54-01-02 | 01 | 1 | UX-01/UX-02 | T-54-03 | Only manual entries deletable | unit | `cargo test -p dlp-admin-cli -- handle_protected_path_list_d_on_manual_opens_confirm handle_protected_path_list_d_on_auto_shows_error` | ✅ | ✅ green |
| 54-02-01 | 02 | 1 | UX-01/UX-02 | T-54-04 | Query params encoded safely | unit | `cargo test -p dlp-admin-cli -- list_bypass_alerts_encodes_severity_in_query_string` | ✅ | ✅ green |
| 54-03-01 | 03 | 2 | UX-01 | T-54-03 | Delete guarded by source==manual | unit | `cargo test -p dlp-admin-cli -- handle_protected_path_list_d_on_manual_opens_confirm handle_protected_path_list_d_on_auto_shows_error` | ✅ | ✅ green |
| 54-04-01 | 04 | 2 | UX-02 | T-54-09 | Optimistic ack reverted on failure | unit | `cargo test -p dlp-admin-cli -- handle_bypass_alert_list_ack_reverts_on_server_failure` | ✅ | ✅ green |
| 54-05-01 | 05 | 2 | UX-02 | — | Detail view read-only | unit | `cargo test -p dlp-admin-cli -- draw_bypass_alert_detail_renders_all_fields` | ✅ | ✅ green |
| 54-06-01 | 06 | 3 | UX-01/UX-02 | T-54-14 | No orphaned dead code | unit | `cargo test -p dlp-admin-cli` | ✅ | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- Existing infrastructure covers all phase requirements (Rust built-in test framework, TestBackend for ratatui, wiremock for HTTP integration tests).

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| TUI visual layout at 80x24 | UX-01/UX-02 | Visual rendering requires human verification | Open Protected Paths and Bypass Alerts screens, verify table columns align, badges display correctly, footer hints visible |
| Keyboard navigation flow | UX-01/UX-02 | Interactive input requires human verification | Navigate MainMenu -> SystemMenu -> Protected Paths -> add path -> confirm -> back. Repeat for Bypass Alerts. |

---

## Validation Audit 2026-06-28

| Metric | Count |
|--------|-------|
| Gaps found | 3 |
| Resolved | 3 |
| Escalated | 0 |

### Resolved Gaps

| Task ID | Requirement | Test File | Test Name |
|---------|-------------|-----------|-----------|
| 54-01-01 | UX-01 / T-54-01 | `dlp-admin-cli/src/screens/dispatch.rs` | `handle_text_input_add_protected_path_passes_raw_value_without_prevalidation` |
| 54-02-01 | UX-01/UX-02 / T-54-04 | `dlp-admin-cli/src/client.rs` | `list_bypass_alerts_encodes_severity_in_query_string` |
| 54-04-01 | UX-02 / T-54-09 | `dlp-admin-cli/src/screens/dispatch.rs` | `handle_bypass_alert_list_ack_reverts_on_server_failure` |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 60s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-28
