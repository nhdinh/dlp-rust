---
phase: 99
slug: refactor-db-layer-to-repository-unit-of-work
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-15
---

# Phase 99 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust built-in) |
| **Config file** | Cargo.toml workspace |
| **Quick run command** | `cargo test -p dlp-server --lib 2>&1 \| tail -5` |
| **Full suite command** | `cargo test --workspace 2>&1 \| tail -20` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-server --lib 2>&1 | tail -5`
- **After every plan wave:** Run `cargo test --workspace 2>&1 | tail -20`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 99-01-01 | 01 | 1 | db/ submodule structure | — | N/A | compile | `cargo check -p dlp-server` | ❌ W0 | ⬜ pending |
| 99-01-02 | 01 | 1 | UnitOfWork RAII rollback | — | Transaction auto-rolls back on drop | unit | `cargo test -p dlp-server --lib unit_of_work` | ❌ W0 | ⬜ pending |
| 99-01-03 | 01 | 1 | Repository stubs compile | — | N/A | compile | `cargo check -p dlp-server` | ❌ W0 | ⬜ pending |
| 99-02-01 | 02 | 2 | audit_store migrated | — | N/A | integration | `cargo test -p dlp-server --lib audit` | ✅ | ⬜ pending |
| 99-02-02 | 02 | 2 | agent_registry migrated | — | N/A | integration | `cargo test -p dlp-server --lib agent_registry` | ✅ | ⬜ pending |
| 99-02-03 | 02 | 2 | exception_store migrated | — | N/A | integration | `cargo test -p dlp-server --lib exception` | ✅ | ⬜ pending |
| 99-02-04 | 02 | 2 | siem_connector migrated | — | N/A | integration | `cargo test -p dlp-server --lib siem` | ✅ | ⬜ pending |
| 99-02-05 | 02 | 2 | admin_auth migrated | — | Auth hash never logged | integration | `cargo test -p dlp-server --lib admin_auth` | ✅ | ⬜ pending |
| 99-02-06 | 02 | 2 | alert_router migrated | — | N/A | integration | `cargo test -p dlp-server --lib alert_router` | ✅ | ⬜ pending |
| 99-03-01 | 03 | 3 | admin_api migrated | — | N/A | integration | `cargo test -p dlp-server --lib admin_api` | ✅ | ⬜ pending |
| 99-03-02 | 03 | 3 | full workspace passes | — | N/A | integration | `cargo test --workspace` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-server/src/db/unit_of_work.rs` — UnitOfWork struct + `test_uow_rollback_on_drop`
- [ ] `dlp-server/src/db/repositories/*.rs` — stub structs with compile-check coverage

*Existing test infrastructure (cargo test) covers all other phase requirements. No new test framework needed.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Pool exhaustion under concurrent load | Performance | No load-test harness in CI | Run with `wrk` against the admin API endpoint and confirm no deadlocks |
| Hot-reload config reads (not in spawn_blocking) | alert_router / siem hot-reload | Requires timing-sensitive test | Manually trigger a config change during request handling and verify no panic |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
