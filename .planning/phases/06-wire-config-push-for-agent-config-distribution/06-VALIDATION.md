---
phase: 6
slug: wire-config-push-for-agent-config-distribution
status: draft
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-12
---

# Phase 6 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in `#[test]` + `cargo test` |
| **Config file** | none — uses existing workspace test setup |
| **Quick run command** | `cargo test -p dlp-server -p dlp-agent 2>&1` |
| **Full suite command** | `cargo test --workspace 2>&1` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-server -p dlp-agent 2>&1`
- **After every plan wave:** Run `cargo test --workspace 2>&1`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 06-01-01 | 01 | 0 | R-04 | — | N/A | unit | `cargo test -p dlp-server test_global_agent_config` | ❌ W0 | ⬜ pending |
| 06-01-02 | 01 | 0 | R-04 | — | N/A | unit | `cargo test -p dlp-server test_agent_config_override` | ❌ W0 | ⬜ pending |
| 06-01-03 | 01 | 1 | R-04 | — | N/A | unit | `cargo test -p dlp-server test_db_init_agent_config_tables` | ❌ W0 | ⬜ pending |
| 06-01-04 | 01 | 1 | R-04 | T-06-01 | Unauthenticated GET /agent-config/{id} returns resolved config | integration | `cargo test -p dlp-server test_get_agent_config_public` | ❌ W0 | ⬜ pending |
| 06-01-05 | 01 | 1 | R-04 | T-06-02 | JWT-protected PUT /admin/agent-config rejects unauthenticated | integration | `cargo test -p dlp-server test_put_admin_agent_config_requires_jwt` | ❌ W0 | ⬜ pending |
| 06-01-06 | 01 | 1 | R-04 | — | N/A | integration | `cargo test -p dlp-server test_agent_config_fallback_to_global` | ❌ W0 | ⬜ pending |
| 06-01-07 | 01 | 1 | R-04 | — | N/A | integration | `cargo test -p dlp-server test_delete_agent_config_override` | ❌ W0 | ⬜ pending |
| 06-02-01 | 02 | 0 | R-04 | — | N/A | unit | `cargo test -p dlp-agent test_agent_config_save_toml` | ❌ W0 | ⬜ pending |
| 06-02-02 | 02 | 1 | R-04 | — | N/A | unit | `cargo test -p dlp-agent test_fetch_agent_config_from_server` | ❌ W0 | ⬜ pending |
| 06-02-03 | 02 | 1 | R-04 | — | N/A | unit | `cargo test -p dlp-agent test_config_hot_reload_applies` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-server/src/agent_config_store.rs` — unit test stubs for global config CRUD and override resolution
- [ ] `dlp-agent/src/config.rs` — unit test stubs for `save()` method and TOML round-trip
- [ ] `dlp-agent/src/server_client.rs` — unit test stub for `fetch_agent_config()` unreachable-server case

*All stubs must compile and be marked `#[ignore]` until implementation completes.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Agent TOML file updated on disk after config poll | R-04 | Requires running agent service + file system check | Start agent, push config via API, wait one poll interval, read `C:\ProgramData\DLP\agent-config.toml` and verify new `monitored_paths` present |
| `cargo build --all` produces no warnings | R-04 | Build-level check | Run `cargo build --all 2>&1` and verify zero warnings |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
