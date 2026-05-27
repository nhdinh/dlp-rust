---
phase: 53
slug: etw-kernel-file-consumer-bypass-correlator-hook-journal-ring
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-27
---

# Phase 53 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (built-in) |
| **Config file** | `Cargo.toml` workspace — no extra config needed |
| **Quick run command** | `cargo test -p dlp-agent -p dlp-hook-dll -p dlp-server -p dlp-common --lib` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~120 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p {affected_crate} --lib`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 120 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 53-01-01 | 01 | 1 | ETW-01 | T-53-01 | ETW consumer starts without panic; parses CREATE/WRITE/DELETE events | unit | `cargo test -p dlp-agent etw_kernel_file` | ❌ W0 | pending |
| 53-01-02 | 01 | 1 | ETW-01 | T-53-01 | Buffer config 256KB x 200 prevents lost events under stress | integration | `cargo test -p dlp-agent etw_stress -- --ignored` | ❌ W0 | pending |
| 53-02-01 | 02 | 1 | ETW-02 | T-53-02 | Hook DLL creates journal shared memory lazily on first invocation | unit | `cargo test -p dlp-hook-dll journal_create` | ❌ W0 | pending |
| 53-02-02 | 02 | 1 | ETW-02 | T-53-02 | Journal entry format is 48 bytes; write_index wraps correctly | unit | `cargo test -p dlp-hook-dll journal_layout` | ❌ W0 | pending |
| 53-02-03 | 02 | 1 | ETW-02 | T-53-02 | Journal write happens BEFORE decision return in every trampoline | unit | `cargo test -p dlp-hook-dll journal_ordering` | ❌ W0 | pending |
| 53-03-01 | 03 | 2 | ETW-03 | T-53-03 | Correlator discovers journal via ProcessWatcher event | unit | `cargo test -p dlp-agent correlator_discovery` | ❌ W0 | pending |
| 53-03-02 | 03 | 2 | ETW-03 | T-53-03 | Path normalization produces identical FNV-1a hash in DLL and agent | unit | `cargo test -p dlp-common path_hash_roundtrip` | ❌ W0 | pending |
| 53-03-03 | 03 | 2 | ETW-03 | T-53-03 | +/-5ms QPC tolerance matches journal entries correctly | unit | `cargo test -p dlp-agent correlator_tolerance` | ❌ W0 | pending |
| 53-03-04 | 03 | 2 | ETW-03 | T-53-03 | Allowlisted PIDs (Defender, CrowdStrike) are dropped pre-correlation | unit | `cargo test -p dlp-agent allowlist_filter` | ❌ W0 | pending |
| 53-03-05 | 03 | 2 | ETW-03 | T-53-03 | Missing journal entry produces BypassAlert with correct reason | unit | `cargo test -p dlp-agent bypass_alert_emit` | ❌ W0 | pending |
| 53-04-01 | 04 | 2 | ETW-04 | T-53-04 | `bypass_alerts` table schema matches ARCHITECTURE.md spec | unit | `cargo test -p dlp-server bypass_alerts_schema` | ❌ W0 | pending |
| 53-04-02 | 04 | 2 | ETW-04 | T-53-04 | `POST /audit/bypass` batch ingest accepts max 100 alerts with JWT | integration | `cargo test -p dlp-server bypass_ingest` | ❌ W0 | pending |
| 53-04-03 | 04 | 2 | ETW-04 | T-53-04 | `GET /admin/bypass-alerts` returns paginated filtered results | integration | `cargo test -p dlp-server bypass_list` | ❌ W0 | pending |
| 53-04-04 | 04 | 2 | ETW-04 | T-53-04 | `POST /admin/bypass-alerts/:id/ack` is idempotent; 404 on missing | integration | `cargo test -p dlp-server bypass_ack` | ❌ W0 | pending |
| 53-05-01 | 05 | 3 | ETW-05 | T-53-05 | `crit` severity alerts trigger alert_router::send | unit | `cargo test -p dlp-server alert_router_crit` | ❌ W0 | pending |
| 53-05-02 | 05 | 3 | ETW-05 | T-53-05 | `warn`/`info` severity alerts route to SIEM only (no alert router) | unit | `cargo test -p dlp-server siem_only_warn` | ❌ W0 | pending |
| 53-05-03 | 05 | 3 | ETW-05 | T-53-05 | BypassAlert event type serializes correctly for SIEM relay | unit | `cargo test -p dlp-common bypass_alert_serde` | ❌ W0 | pending |

*Status: pending | green | red | flaky*

---

## Wave 0 Requirements

- [ ] `dlp-agent/src/etw_kernel_file.rs` — module stub with `EtwKernelFileConsumer` struct
- [ ] `dlp-agent/src/bypass_correlator.rs` — module stub with `BypassCorrelator` struct
- [ ] `dlp-hook-dll/src/hook_journal.rs` — module stub with `JournalEntry` and `HookJournal` types
- [ ] `dlp-common/src/path_hash.rs` — extracted `normalize_path` + `fnv1a_64` for cross-crate reuse
- [ ] `dlp-server/src/db/repositories/bypass_alerts.rs` — repository stub
- [ ] `dlp-server/tests/bypass_alerts_integration.rs` — integration test scaffold
- [ ] `dlp-agent/tests/etw_consumer_integration.rs` — integration test scaffold (Windows-only, skip on non-Windows)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| 10,000 events/sec stress with zero lost ETW events | ETW-01 | Requires dedicated Windows host with sustained I/O load; not reproducible in CI | Run `dlp-agent/tests/stress_etw.rs` on physical Windows 11 host with `fsstress.exe` generating 10K file ops/sec. Verify Event Viewer shows zero Event ID 2 from Microsoft-Windows-Kernel-EventTracing/Admin. |
| Zero Defender/CrowdStrike bypass alerts in soak test | ETW-03 | Requires real AV/EDR software installed | Deploy agent on endpoint with Defender ATP enabled. Run normal workloads for 24h. Verify `bypass_alerts` table contains zero entries from `MsMpEng.exe` or `C:\\Windows\\System32\\svchost.exe` (Defender service host). |
| End-to-end hook-uninstalled bypass detection | ETW-03 | Requires deliberately removing hook DLL from a process | Launch `notepad.exe`, verify hook is injected (check `Global\\DlpHookJournal_<pid>` exists). Use Process Hacker to unload `dlp_hook_dll.dll`. Create a file in a T3 path. Verify `BypassAlert` appears within 5 seconds with `correlation_reason=NoHookJournal`. |

---

## Threat Model

| ID | Threat | Mitigation | Verification |
|----|--------|------------|------------|
| T-53-01 | ETW events lost due to undersized buffers | 256KB x 200 buffers (52MB total); lost-event monitoring | Stress test + Event ID 2 check |
| T-53-02 | Journal shared memory exhausted or corrupted | 64KB fixed size; single-producer; versioned header; graceful fallback on failure | Unit test layout + corruption recovery |
| T-53-03 | False-positive bypass alerts from timing skew | +/-5ms QPC tolerance; path-hash exact match; allowlist pre-filter | Tolerance unit test + allowlist test |
| T-53-04 | Agent impersonates another agent to inject fake bypass alerts | `POST /audit/bypass` validates `agent_id` against JWT claims | Integration test with mismatched agent_id |
| T-53-05 | Bypass alert severity escalation bypasses alert router | Severity mapping is fixed (not user-configurable); `crit` always triggers router | Unit test severity-to-router mapping |

---

## Validation Sign-Off

- [ ] All tasks have automated verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
