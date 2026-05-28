---
phase: 55
slug: monitor-only-audit-only-per-policy-enforcement-mode
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-28
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
| 55-01-01 | 01 | 1 | MODE-01 | T-55-01 | `EnforcementMode` enum serializes/deserializes correctly with `Block` as default | unit | `cargo test -p dlp-common enforcement_mode` | ⬜ W0 | pending |
| 55-01-02 | 01 | 1 | MODE-01 | T-55-01 | `Policy` struct backward compatible: v0.9.0 JSON deserializes to `Block` | unit | `cargo test -p dlp-common policy_backward_compat` | ⬜ W0 | pending |
| 55-02-01 | 02 | 1 | MODE-01 | T-55-02 | `policies` table migration adds `enforcement_mode` with `DEFAULT 'Block'` | unit | `cargo test -p dlp-server policy_migration` | ⬜ W0 | pending |
| 55-02-02 | 02 | 1 | MODE-01 | T-55-02 | `PolicyRepository` CRUD includes `enforcement_mode` round-trip | unit | `cargo test -p dlp-server policy_repo_enforcement_mode` | ⬜ W0 | pending |
| 55-03-01 | 03 | 1 | MODE-01 | T-55-03 | Effective mode computation: `global != PerPolicy` overrides per-policy mode | unit | `cargo test -p dlp-server effective_mode` | ⬜ W0 | pending |
| 55-03-02 | 03 | 1 | MODE-01 | T-55-03 | `PolicyStore::evaluate()` returns effective mode alongside decision | unit | `cargo test -p dlp-server policy_store_effective_mode` | ⬜ W0 | pending |
| 55-04-01 | 04 | 2 | MODE-01 | T-55-04 | Agent parses `[enforcement]` section from TOML config | unit | `cargo test -p dlp-agent enforcement_config` | ⬜ W0 | pending |
| 55-04-02 | 04 | 2 | MODE-01 | T-55-04 | Agent computes effective mode and passes to evaluation context | unit | `cargo test -p dlp-agent effective_mode_context` | ⬜ W0 | pending |
| 55-05-01 | 05 | 2 | MODE-01 | T-55-05 | Hook DLL returns ALLOW in Audit mode while still emitting audit event | unit | `cargo test -p dlp-hook-dll audit_mode_allow` | ⬜ W0 | pending |
| 55-05-02 | 05 | 2 | MODE-01 | T-55-05 | Audit event carries `policy_mode: "Audit"` and `would_have_denied: true` | unit | `cargo test -p dlp-common audit_event_mode` | ⬜ W0 | pending |
| 55-06-01 | 06 | 3 | MODE-01 | T-55-06 | DACL tripwire skips Deny ACE for Audit-mode policies | unit | `cargo test -p dlp-agent dacl_audit_mode_skip` | ⬜ W0 | pending |
| 55-06-02 | 06 | 3 | MODE-01 | T-55-06 | DACL tripwire writes Deny ACE for Block/AuditAndBlock policies | unit | `cargo test -p dlp-agent dacl_block_mode_write` | ⬜ W0 | pending |
| 55-07-01 | 07 | 3 | MODE-01 | T-55-07 | Alert router downgrades Audit-mode `DenyWithAlert` to `info` severity | unit | `cargo test -p dlp-server alert_router_audit_info` | ⬜ W0 | pending |
| 55-07-02 | 07 | 3 | MODE-01 | T-55-07 | SIEM relay receives full audit event unchanged in Audit mode | unit | `cargo test -p dlp-server siem_relay_audit_full` | ⬜ W0 | pending |
| 55-08-01 | 08 | 4 | MODE-01 | — | Conditions Builder renders enforcement_mode dropdown | unit | `cargo test -p dlp-admin-cli enforcement_dropdown` | ⬜ W0 | pending |
| 55-08-02 | 08 | 4 | MODE-01 | — | Conditions Builder form submits enforcement_mode to API | unit | `cargo test -p dlp-admin-cli form_submit_mode` | ⬜ W0 | pending |
| 55-09-01 | 09 | 4 | MODE-01 | — | Integration test: Audit → Block → AuditAndBlock round-trip via PUT /admin/policies/:id | integration | `cargo test -p dlp-server policy_mode_roundtrip` | ⬜ W0 | pending |
| 55-09-02 | 09 | 4 | MODE-01 | — | Integration test: agent sees mode change within one policy_sync cycle | integration | `cargo test -p dlp-server policy_sync_mode` | ⬜ W0 | pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-common/src/abac.rs` — `EnforcementMode` enum spec with `#[derive(Default)]` (Block default)
- [ ] `dlp-common/src/audit.rs` — `AuditEvent` extension spec with `policy_mode` and `would_have_denied` fields
- [ ] `dlp-server/src/db/repositories/policies.rs` — `PolicyRow` / `PolicyUpdateRow` extension spec
- [ ] `dlp-server/src/policy_store.rs` — effective mode computation spec
- [ ] `dlp-agent/src/engine_client.rs` — `[enforcement]` TOML section parsing spec
- [ ] `dlp-admin-cli/src/app.rs` — `PolicyFormState` extension spec

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

- [ ] All tasks have automated verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
