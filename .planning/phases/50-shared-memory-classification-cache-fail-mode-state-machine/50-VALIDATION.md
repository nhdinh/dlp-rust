---
phase: 50
slug: shared-memory-classification-cache-fail-mode-state-machine
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-20
---

# Phase 50 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in (`#[test]`) + `cargo test` |
| **Config file** | None — workspace-level via `Cargo.toml` dev-dependencies |
| **Quick run command** | `cargo test --workspace --lib` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~45 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test --workspace --lib`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TBD | TBD | TBD | CACHE-01 | T-50-01 | Cache shared memory created with correct ACL | unit | `cargo test -p dlp-agent classification_cache` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | CACHE-02 | T-50-02 | DLL maps cache read-only after self-allowlist | unit | `cargo test -p dlp-hook-dll cache_map` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | CACHE-03 | T-50-03 | HookRequest/HookResponse carry cache_version and cache_hint | unit | `cargo test -p dlp-common hook_ipc` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | CACHE-04 | T-50-04 | CacheDelta push flips atomic version word | unit | `cargo test -p dlp-agent cache_delta` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | CACHE-05 | T-50-05 | Trusted paths bypass cache and pipe | unit | `cargo test -p dlp-hook-dll trusted_path` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | CACHE-06 | T-50-06 | Per-process host allowlist bypasses pipe | unit | `cargo test -p dlp-hook-dll host_allowlist` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | FAIL-01 | T-50-07 | State machine transitions correctly | unit | `cargo test -p dlp-hook-dll fail_mode` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | FAIL-02 | T-50-08 | Asymmetric tier-gated fail decisions | unit | `cargo test -p dlp-hook-dll tier_fail` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | FAIL-03 | T-50-09 | Per-tier TTL budgets enforced | unit | `cargo test -p dlp-hook-dll ttl_budget` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-hook-dll/src/cache_lookup.rs` — cache lookup module with unit tests
- [ ] `dlp-hook-dll/src/fail_mode.rs` — fail-mode state machine with unit tests
- [ ] `dlp-agent/src/classification_cache.rs` — shared-memory cache manager with unit tests
- [ ] `dlp-common/src/hook_ipc.rs` — extended HookRequest/HookResponse types
- [ ] `dlp-hook-dll/src/allowlist.rs` — trusted-path and host allowlist with tests
- [ ] Benchmark harness: `dlp-hook-dll/benches/cache_hit_latency.rs` — QueryPerformanceCounter p95

*Wave 0 creates module stubs and test infrastructure before Wave 1 implementation begins.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| p95 latency <= 50 us on real Windows | CRIT-04 | Requires real Windows host with QPC; cannot simulate in CI | Run `cargo build --workspace --release` with hooks enabled; compare wall-clock vs hooks-disabled baseline; verify p95 via benchmark output |
| HEALTHY → DEGRADED → ISOLATED transition with agent stopped | FAIL-01 | Requires stopping real agent service and observing hooked process behavior | Stop `dlp-agent` service; attempt T3/T4 write → denied; attempt T1/T2 write → allowed; check event log for transition telemetry |
| ISOLATED → RESYNC → HEALTHY after agent restart | FAIL-01 | Requires real agent restart and pipe reconnection | Restart agent with higher cache_version; verify DLL transitions within 1s; check no in-flight decisions lost |
| Cross-session shared memory (`Global\` prefix) | CACHE-01 | Requires multiple Windows sessions or UAC elevation | Elevated agent creates `Global\DlpClassificationCache`; non-elevated hooked process maps it read-only; verify visibility |
| x86/x64 DLL compatibility with shared memory | CACHE-02 | Requires building and testing both architectures | Build `i686-pc-windows-msvc` target; verify x86 DLL maps same shared memory layout correctly |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
