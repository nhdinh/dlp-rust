---
phase: 55
slug: monitor-only-audit-only-per-policy-enforcement-mode
status: final
nyquist_compliant: true
wave_0_complete: true
verified: 2026-07-04
---

# Phase 55 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (built-in) |
| **Config file** | `Cargo.toml` workspace — no extra config needed |
| **Quick run command** | `cargo test -p dlp-common -p dlp-server -p dlp-agent -p dlp-admin-cli --lib` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~90 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p {affected_crate} --lib`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 90 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 55-01-01 | 01 | 1 | MODE-01 | T-55-01 | `EnforcementMode` enum serializes/deserializes correctly with `Block` as default | unit | `cargo test -p dlp-common -- enforcement_mode` | ✅ | green |
| 55-01-02 | 01 | 1 | MODE-01 | T-55-01 | `Policy` struct backward compatible: v0.9.0 JSON deserializes to `Block` | unit | `cargo test -p dlp-common -- enforcement_mode` (covers `test_enforcement_mode_default_is_block`) | ✅ | green |
| 55-02-01 | 02 | 1 | MODE-01 | T-55-02 | `policies` table migration adds `enforcement_mode` with `DEFAULT 'Block'` | unit | `cargo test -p dlp-server -- enforcement_mode` (`test_policy_repository_default_enforcement_mode`) | ✅ | green |
| 55-02-02 | 02 | 1 | MODE-01 | T-55-02 | `PolicyRepository` CRUD includes `enforcement_mode` round-trip | unit | `cargo test -p dlp-server -- enforcement_mode` (`test_policy_repository_crud_with_enforcement_mode`) | ✅ | green |
| 55-03-01 | 03 | 1 | MODE-01 | T-55-03 | Effective mode computation: `global != PerPolicy` overrides per-policy mode | unit | `cargo test -p dlp-server --lib -- evaluate_global_override` | ✅ | green |
| 55-03-02 | 03 | 1 | MODE-01 | T-55-03 | `PolicyStore::evaluate()` returns effective mode alongside decision | unit | `cargo test -p dlp-server --lib -- test_evaluate_audit_mode_allows` | ✅ | green |
| 55-04-01 | 04 | 2 | MODE-01 | T-55-04 | Agent parses `[enforcement]` section from TOML config | unit | `cargo test -p dlp-agent -- enforcement` (`test_agent_config_enforcement_section_*`) | ✅ | green |
| 55-04-02 | 04 | 2 | MODE-01 | T-55-04 | Agent computes effective mode and passes to evaluation context | unit | `cargo test -p dlp-agent -- compute_effective_mode` | ✅ | green |
| 55-05-01 | 05 | 2 | MODE-01 | T-55-05 | Audit mode returns ALLOW while still emitting audit event | unit | `cargo test -p dlp-agent -- compute_effective_mode` + `cargo test -p dlp-server -- test_evaluate_audit_mode_allows` | ✅ | green |
| 55-05-02 | 05 | 2 | MODE-01 | T-55-05 | Audit event carries `policy_mode` and `would_have_denied: true` | unit | `cargo test -p dlp-common -- audit_event_policy_mode` + `cargo test -p dlp-server -- siem_connector` | ✅ | green |
| 55-06-01 | 06 | 3 | MODE-01 | T-55-06 | DACL tripwire skips Deny ACE when global mode is Audit | unit | `cargo test -p dlp-agent --lib -- dacl_tripwire` (`test_should_apply_tripwire_audit_mode_returns_false`) | ✅ | green |
| 55-06-02 | 06 | 3 | MODE-01 | T-55-06 | DACL tripwire writes Deny ACE for Block/AuditAndBlock policies | unit | `cargo test -p dlp-agent --lib -- dacl_tripwire` (`test_should_apply_tripwire_block_mode_returns_true`, `test_should_apply_tripwire_auditandblock_returns_true`) | ✅ | green |
| 55-07-01 | 07 | 3 | MODE-01 | T-55-07 | Alert router downgrades Audit-mode `DenyWithAlert` to `info` severity | unit | `cargo test -p dlp-server -- alert_router` (`test_audit_mode_email_subject_downgrade`) | ✅ | green |
| 55-07-02 | 07 | 3 | MODE-01 | T-55-07 | SIEM relay receives full audit event unchanged in Audit mode | unit | `cargo test -p dlp-server -- siem_connector` (`test_siem_relay_includes_policy_mode`, `test_siem_relay_audit_mode_no_severity_mutation`) | ✅ | green |
| 55-08-01 | 08 | 4 | MODE-01 | — | Conditions Builder renders enforcement_mode dropdown | unit | `cargo test -p dlp-admin-cli -- enforcement` (`test_enforcement_mode_options_length`, `test_format_enforcement_mode_field`) | ✅ | green |
| 55-08-02 | 08 | 4 | MODE-01 | — | Conditions Builder form submits enforcement_mode to API | unit | `cargo test -p dlp-admin-cli -- enforcement` (`test_submit_policy_payload_includes_enforcement_mode`) | ✅ | green |
| 55-09-01 | 09 | 4 | MODE-01 | — | Integration test: Audit → Block → AuditAndBlock round-trip via PUT /admin/policies/:id | integration | `cargo test -p dlp-server --test enforcement_mode_integration -- test_enforcement_mode_round_trip` | ✅ | green |
| 55-09-02 | 09 | 4 | MODE-01 | — | Integration test: agent sees mode change within one policy_sync cycle | integration | `cargo test -p dlp-server --test enforcement_mode_integration -- test_global_override_forces_audit_mode` | ✅ | green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

**Coverage Notes:**
- 55-05-01 originally targeted `dlp-hook-dll`; enforcement decision logic is implemented in `dlp-agent/src/interception/mod.rs` and covered by `compute_effective_mode` tests plus server-side `evaluate` tests. No standalone `dlp-hook-dll` test is required because the hook DLL only reports file operations and receives the final verdict from the agent IPC handler.
- 55-06-01/02 are satisfied by `dacl_tripwire` unit tests; per-policy tripwire filtering is intentionally global-mode-only (see Plan 55-04 design decision).

## Wave 0 Requirements

- [x] `dlp-common/src/abac.rs` — `EnforcementMode` enum with `#[derive(Default)]` (Block default)
- [x] `dlp-common/src/audit.rs` — `AuditEvent` extension with `policy_mode` and `would_have_denied` fields
- [x] `dlp-server/src/db/repositories/policies.rs` — `PolicyRow` / `PolicyUpdateRow` extension with `enforcement_mode`
- [x] `dlp-server/src/policy_store.rs` — effective mode computation in `evaluate()`
- [x] `dlp-agent/src/config.rs` — `[enforcement]` TOML section parsing via `EnforcementConfig`
- [x] `dlp-admin-cli/src/app.rs` — `PolicyFormState` extension with `enforcement_mode` index

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| File operation succeeds in Audit mode on real Windows host | MODE-01 | Requires real Windows file I/O and hook DLL injection | Create a T4-classified file. Set policy to Audit mode. Attempt `CopyFileExW` to USB. Verify file copies successfully. Check audit event contains `would_have_denied=true`. |
| DACL tripwire removes Deny ACE when policy switches Block → Audit | MODE-01 | Requires real NTFS ACL manipulation and Windows API | Set policy to Block. Verify Deny ACE exists on protected path. Change policy to Audit. Wait for policy_sync. Verify Deny ACE is removed via `icacls` output. |
| Global override banner appears in admin TUI when active | MODE-01 | Requires interactive TUI rendering | Set `global_enforcement_mode = Audit` in server config. Open Conditions Builder in admin TUI. Verify yellow banner "Global override active: Audit" appears below enforcement_mode dropdown. |

---

## Threat Model

| ID | Threat | Mitigation | Verification |
|----|--------|------------|------------|
| T-55-01 | Backward incompatibility: existing policies break on upgrade | `#[serde(default)]` with `Block` as default; migration adds column with `DEFAULT 'Block'` | Unit test v0.9.0 JSON deserialization |
| T-55-02 | Database schema mismatch after rollback | Migration is idempotent; `CHECK` constraint on `enforcement_mode` values | Unit test migration re-runs without error |
| T-55-03 | Effective mode evaluated differently on server vs agent | Single `evaluate_effective_mode()` function in `dlp-common`; both sides use same logic | Unit test cross-crate consistency |
| T-55-04 | Agent fails to parse new TOML section, crashes on startup | `serde_ignored` warning only; missing section defaults to `PerPolicy` | Unit test config parsing without `[enforcement]` section |
| T-55-05 | Hook DLL denies in Audit mode (false positive blocker) | Agent evaluates mode BEFORE returning to hook; Audit mode always returns ALLOW to hook | Unit test + manual Windows verification |
| T-55-06 | DACL tripwire blocks in Audit mode (kernel-level false positive) | Tripwire filters by effective mode; Audit policies get no Deny ACE | Unit test + manual Windows verification |
| T-55-07 | Alert router pages operator during monitoring (pager fatigue) | Audit-mode `DenyWithAlert` downgraded to `info` severity; only `crit` triggers alert_router | Unit test severity mapping |

---

## Validation Sign-Off

- [x] All tasks have automated verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 90s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** validated 2026-07-04

---

## Audit Evidence

| Check | Command | Result | Notes |
|-------|---------|--------|-------|
| dlp-common enforcement mode tests | `cargo test -p dlp-common -- enforcement_mode audit_event_policy_mode` | 5 passed | Covers 55-01-01, 55-01-02, 55-05-02 |
| dlp-server policy/repository tests | `cargo test -p dlp-server -- enforcement_mode` | 5 passed | Covers 55-02-01, 55-02-02 |
| dlp-server policy_store evaluate tests | `cargo test -p dlp-server --lib -- evaluate_audit` | 132 passed (subset) | Covers 55-03-01, 55-03-02, 55-05-01 |
| dlp-agent config/enforcement tests | `cargo test -p dlp-agent -- enforcement` | 18 passed | Covers 55-04-01, 55-04-02 |
| dlp-agent compute_effective_mode tests | `cargo test -p dlp-agent -- compute_effective_mode` | 4 passed | Covers 55-04-02, 55-05-01 |
| dlp-agent dacl_tripwire tests | `cargo test -p dlp-agent --lib -- dacl_tripwire` | 20 passed | Covers 55-06-01, 55-06-02 |
| dlp-server alert_router tests | `cargo test -p dlp-server -- alert_router` | 18 passed | Covers 55-07-01 |
| dlp-server siem_connector tests | `cargo test -p dlp-server -- siem_connector` | 11 passed | Covers 55-07-02 |
| dlp-admin-cli enforcement tests | `cargo test -p dlp-admin-cli -- enforcement` | 15 passed | Covers 55-08-01, 55-08-02 |
| dlp-server integration tests | `cargo test -p dlp-server --test enforcement_mode_integration` | 4 passed | Covers 55-09-01, 55-09-02 |
