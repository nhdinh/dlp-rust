---
phase: 19
slug: boolean-mode-tui-import-export
status: audited
nyquist_compliant: false
wave_0_complete: true
created: 2026-04-20
updated: 2026-06-17
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
| 19-01-01 | 01 | 1 | POLICY-09 | unit/compile | `cargo check -p dlp-admin-cli` | green |
| 19-01-02 | 01 | 1 | POLICY-09 | unit | `cargo test -p dlp-admin-cli --lib test_policy_response_defaults_missing_mode_to_all` | green |
| 19-01-02 | 01 | 1 | POLICY-09 | unit | `cargo test -p dlp-admin-cli --lib test_policy_response_preserves_explicit_mode_any` | green |
| 19-01-03 | 01 | 1 | POLICY-09 | unit | `cargo test -p dlp-admin-cli --lib test_policy_payload_roundtrips_all_three_modes` | green |
| 19-01-03 | 01 | 1 | POLICY-09 | unit | `cargo test -p dlp-admin-cli --lib test_policy_payload_legacy_default_on_missing_mode` | green |
| 19-01-03 | 01 | 1 | POLICY-09 | unit | `cargo test -p dlp-admin-cli --lib test_policy_response_into_payload_copies_mode` | green |
| 19-01-03 | 01 | 1 | POLICY-09 | unit | `cargo test -p dlp-admin-cli --lib test_policy_form_state_default_mode_is_all` | green |
| 19-02-01 | 02 | 2 | POLICY-09 | unit/compile | `cargo check -p dlp-admin-cli` | green |
| 19-02-02 | 02 | 2 | POLICY-09 | unit | `cargo test -p dlp-admin-cli --lib test_cycle_mode_cycles_all_any_none` | green |
| 19-02-03 | 02 | 2 | POLICY-09 | integration | `cargo test -p dlp-server --test mode_end_to_end test_mode_all_matches_when_all_conditions_hit` | green |
| 19-02-04 | 02 | 2 | POLICY-09 | integration | `cargo test -p dlp-server --test mode_end_to_end test_mode_any_matches_when_one_condition_hits` | green |
| 19-02-05 | 02 | 2 | POLICY-09 | integration | `cargo test -p dlp-server --test mode_end_to_end test_mode_none_matches_when_no_conditions_hit` | green |
| 19-02-06 | 02 | 2 | POLICY-09 | integration | `cargo test -p dlp-server --test mode_end_to_end test_policy_payload_roundtrip_preserves_all_three_modes` | green |

*Status: green · red · flaky · pending*

---

## Wave 0 Requirements

- No new test framework install needed — `cargo test` is built-in and already used throughout the workspace.
- `dlp-server/tests/admin_audit_integration.rs` is the template for the new `mode_end_to_end.rs` file; no shared conftest extraction needed.

*Existing infrastructure covers all Phase 19 requirements.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Footer advisory hint renders with `Color::DarkGray` when `mode != ALL && conditions.is_empty()` | POLICY-09 / D-04 | `ratatui::TestBackend` is wired in the project, but the exact color/visual placement is easier to verify with a human eye | Launch TUI → Policy Create → cycle mode to ANY → observe footer line `Note: mode=ANY with no conditions will never match.` |
| Mode cycler responds to Enter/Space in Policy Create | POLICY-09 / D-01 | The `cycle_mode` helper is unit-tested; the Enter/Space dispatch arms are one-line matchers that call it. Keypress routing is easier to UAT than to unit-test | Launch TUI → Policy Create → select Mode row → press Enter 3× and observe `ALL → ANY → NONE → ALL` |
| Legacy v0.4.0 export file imports with `mode = ALL` | POLICY-09 / D-11 | End-to-end file round-trip in the TUI depends on the file dialog | Export on v0.4.0 build → import on v0.5.0 build → verify policies evaluate identically |

---

## Validation Audit 2026-06-17

| Metric | Count |
|--------|-------|
| Gaps found | 1 |
| Resolved | 1 |
| Escalated | 0 |

### Details
- **Gap:** 19-02-02 had no automated test for the `cycle_mode` behavior.
- **Resolution:** Added `test_cycle_mode_cycles_all_any_none` to `dlp-admin-cli/src/screens/dispatch.rs`.
- **Verification:** `cargo test -p dlp-admin-cli --lib test_cycle_mode_cycles_all_any_none` passes.

### Updated Test Names
The original validation map referenced non-existent test names (`policy_payload_mode`, `policy_payload_legacy_default`, `policy_form_mode_cycle`, `mode_all`, `mode_any`, `mode_none`). This audit replaced them with the actual test names from the codebase.

### Pre-existing Workspace-Wide Issues
The following failures are unrelated to Phase 19 and exist on the base branch. They do not block Phase 19 validation:
- `cargo test --workspace` fails on `dlp-agent` doc-tests with `E0460` (duplicate `hyper` crate metadata).
- `cargo clippy --workspace --tests -- -D warnings` fails in `dlp-common/src/usb.rs` with `clippy::match_like_matches_macro`.

For Phase 19, the practical green gates are:
- `cargo test -p dlp-admin-cli --lib`
- `cargo test -p dlp-server --test mode_end_to_end`
- `cargo clippy -p dlp-admin-cli --lib -- -D warnings`
- `cargo clippy -p dlp-server --lib -- -D warnings`

---

## Validation Sign-Off

- [x] All tasks have automated verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (N/A — no Wave 0 needed)
- [x] No watch-mode flags (cargo test is single-shot)
- [x] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter (blocked by 3 manual-only verifications)

**Approval:** audited 2026-06-17

**Note:** Phase 19 is not marked `nyquist_compliant: true` because three behaviors remain manual-only (visual footer color, TUI keypress round-trip, and legacy export file dialog round-trip). All core POLICY-09 semantics have passing automated tests.
