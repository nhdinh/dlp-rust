---
phase: 37
slug: server-side-disk-registry
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-04
---

# Phase 37 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in `#[test]` + `#[tokio::test]` |
| **Config file** | None (cargo test standard) |
| **Quick run command** | `cargo test -p dlp-server db::repositories::disk_registry` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-server db::repositories::disk_registry`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 37-01-01 | 01 | 1 | ADMIN-01 | — | disk_registry table created with correct schema | unit | `cargo test -p dlp-server test_disk_registry_table` | Wave 0 | ⬜ pending |
| 37-01-02 | 01 | 1 | ADMIN-01 | T-37-01 | CHECK constraint rejects invalid encryption_status | unit | `cargo test -p dlp-server test_disk_registry_check_constraint` | Wave 0 | ⬜ pending |
| 37-01-03 | 01 | 1 | ADMIN-01 | T-37-02 | UNIQUE(agent_id, instance_id) constraint enforced | unit | `cargo test -p dlp-server test_disk_registry_unique_constraint` | Wave 0 | ⬜ pending |
| 37-02-01 | 02 | 1 | ADMIN-02 | — | list_all returns all rows ordered by registered_at ASC | unit | `cargo test -p dlp-server test_disk_registry_list_all` | Wave 0 | ⬜ pending |
| 37-02-02 | 02 | 1 | ADMIN-02 | — | list_all with agent_id filter returns only matching rows | unit | `cargo test -p dlp-server test_disk_registry_list_filtered` | Wave 0 | ⬜ pending |
| 37-03-01 | 03 | 2 | ADMIN-03 | T-37-03 | insert creates row and returns 201 | unit | `cargo test -p dlp-server test_insert_disk_registry_handler` | Wave 0 | ⬜ pending |
| 37-03-02 | 03 | 2 | ADMIN-03 | T-37-04 | insert on duplicate (agent_id, instance_id) returns 409 | unit | `cargo test -p dlp-server test_insert_disk_registry_conflict` | Wave 0 | ⬜ pending |
| 37-03-03 | 03 | 2 | ADMIN-03 | — | delete by UUID removes row and returns 204 | unit | `cargo test -p dlp-server test_delete_disk_registry_handler` | Wave 0 | ⬜ pending |
| 37-03-04 | 03 | 2 | ADMIN-03 | — | delete on missing UUID returns 404 | unit | `cargo test -p dlp-server test_delete_disk_registry_not_found` | Wave 0 | ⬜ pending |
| 37-03-05 | 03 | 2 | AUDIT-03 | — | DiskRegistryAdd audit event emitted after insert | unit | `cargo test -p dlp-server test_disk_registry_add_audit_event` | Wave 0 | ⬜ pending |
| 37-03-06 | 03 | 2 | AUDIT-03 | — | DiskRegistryRemove audit event emitted after delete | unit | `cargo test -p dlp-server test_disk_registry_remove_audit_event` | Wave 0 | ⬜ pending |
| 37-03-07 | 03 | 2 | ADMIN-03 | T-37-05 | invalid encryption_status returns 422 | unit | `cargo test -p dlp-server test_disk_registry_invalid_status` | Wave 0 | ⬜ pending |
| 37-04-01 | 04 | 2 | ADMIN-02 | T-37-06 | GET without filter requires JWT — 401 without token | unit | `cargo test -p dlp-server test_list_disk_registry_no_filter` | Wave 0 | ⬜ pending |
| 37-05-01 | 05 | 3 | ADMIN-03 | — | agent config_poll_loop applies disk_allowlist update | unit | `cargo test -p dlp-agent test_config_poll_applies_disk_allowlist` | Wave 0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-server/src/db/repositories/disk_registry.rs` — test module covering ADMIN-01/02/03 repository functions
- [ ] Handler test stubs in `dlp-server/src/admin_api.rs` `#[cfg(test)]` module — covers all handler-level tests
- [ ] Agent-side test stub in `dlp-agent/src/service.rs` `#[cfg(test)]` module — covers D-03 config poll update

*Existing infrastructure (`cargo test`) covers all framework needs — no new test runner installation required.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Config push delivery latency | ADMIN-03 (D-02) | Requires running server + agent pair and measuring actual poll cycle time | Start server and agent, add disk via POST, wait up to `heartbeat_interval_secs` (default 30s), verify agent's `disk_allowlist` TOML file updated |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
