---
phase: 50
slug: shared-memory-classification-cache-fail-mode-state-machine
status: verified
nyquist_compliant: true
wave_0_complete: true
updated: 2026-06-05
---

# Phase 50 — Validation Strategy

> Shared-Memory Classification Cache + Fail-Mode State Machine
> Per-phase validation contract: all 9 requirements verified through automated tests.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in (`#[test]`) + `cargo test` |
| **Config file** | Workspace `Cargo.toml` dev-dependencies |
| **Quick run command** | `cargo test --workspace --lib` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~45 seconds |

---

## Per-Requirement Verification Map

| Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | Test File | Status |
|-------------|------------|-----------------|-----------|-------------------|-----------|--------|
| CACHE-01 | T-50-04, T-50-07 | Cache shared memory created with SYSTEM write / BA read ACL | unit | `cargo test -p dlp-agent --lib` | `dlp-agent/src/classification_cache.rs` | green |
| CACHE-02 | T-50-08, T-50-09 | DLL maps cache read-only (FILE_MAP_READ) with validation | unit | `cargo test -p dlp-hook-dll -- classification_cache` | `dlp-hook-dll/src/classification_cache.rs` | green |
| CACHE-03 | T-50-01, T-50-24 | HookRequest/HookResponse carry cache_version and cache_hint; bincode stable | unit + integration | `cargo test -p dlp-common --lib` + `cargo test -p dlp-e2e --test bincode_compat` | `dlp-common/src/hook_ipc.rs` + `dlp-e2e/tests/bincode_compat.rs` | green |
| CACHE-04 | T-50-09, T-50-26 | Cache rebuild performs sequence-lock atomic version flip | unit | `cargo test -p dlp-agent --lib` | `dlp-agent/src/classification_cache.rs` | green |
| CACHE-05 | T-50-12, T-50-17 | Trusted paths (System32, SysWOW64, WinSxS, etc.) bypass cache and pipe | unit | `cargo test -p dlp-hook-dll -- allowlist` | `dlp-hook-dll/src/allowlist.rs` | green |
| CACHE-06 | T-50-17, T-50-32, T-50-33 | Build-tool allowlist with basename + parent + user-writable + signer checks | unit | `cargo test -p dlp-hook-dll -- allowlist` | `dlp-hook-dll/src/allowlist.rs` | green |
| FAIL-01 | T-50-13, T-50-14, T-50-30 | State machine transitions: HEALTHY->DEGRADED->ISOLATED->RESYNC->HEALTHY | unit | `cargo test -p dlp-hook-dll -- fail_mode` | `dlp-hook-dll/src/fail_mode.rs` | green |
| FAIL-02 | T-50-12, T-50-31 | Asymmetric tier-gated decisions: T3/T4 deny, T1/T2 allow, reads always allow | unit | `cargo test -p dlp-hook-dll -- fail_mode` | `dlp-hook-dll/src/fail_mode.rs` | green |
| FAIL-03 | T-50-16, T-50-30 | Per-tier TTL budgets enforced (T4=30s, T3=60s, T2=300s, T1=1800s) | unit | `cargo test -p dlp-hook-dll -- fail_mode` | `dlp-hook-dll/src/fail_mode.rs` | green |

---

## Integration Test Coverage

| Suite | Tests | Command | Status |
|-------|-------|---------|--------|
| Bincode compatibility | 8 | `cargo test -p dlp-e2e --test bincode_compat` | green |
| Cache benchmarks | 5 + 1 ignored | `cargo test -p dlp-e2e --test cache_benchmark` | green |
| Phase 50 requirements | 21 | `cargo test -p dlp-e2e --test phase50_requirements` | green |

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| p95 latency <= 50 us on real Windows | CRIT-04 | Requires real Windows host with QPC; synthetic benchmark approximates | Run `cargo test -p dlp-e2e --test cache_benchmark -- --ignored` on Windows host with hooks enabled |
| HEALTHY -> DEGRADED -> ISOLATED with agent stopped | FAIL-01 | Requires stopping real agent service | Stop `dlp-agent` service; attempt T3/T4 write -> denied; T1/T2 -> allowed; check event log |
| ISOLATED -> RESYNC -> HEALTHY after agent restart | FAIL-01 | Requires real agent restart and pipe reconnection | Restart agent with higher cache_version; verify transitions within 1s |
| Cross-session shared memory (`Global\` prefix) | CACHE-01 | Requires multiple Windows sessions or UAC elevation | Elevated agent creates cache; non-elevated hooked process maps it read-only |
| x86/x64 DLL compatibility | CACHE-02 | Requires building and testing both architectures | Build `i686-pc-windows-msvc` target; verify x86 DLL maps same layout |

---

## Validation Audit Trail

| Audit Date | Requirements Total | Covered | Partial | Missing | Run By |
|------------|-------------------|---------|---------|---------|--------|
| 2026-05-20 | 9 | 0 | 0 | 9 | Plan-time draft |
| 2026-06-05 | 9 | 9 | 0 | 0 | UAT verification + gsd-nyquist-auditor |

---

## Sign-Off

- [x] All requirements have automated verification (9/9 covered)
- [x] Sampling continuity: all plans verified after each task commit
- [x] No watch-mode flags
- [x] Feedback latency < 60s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** verified 2026-06-05
