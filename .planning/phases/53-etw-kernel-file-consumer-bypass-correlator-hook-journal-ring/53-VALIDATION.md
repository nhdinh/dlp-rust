---
phase: 53
slug: etw-kernel-file-consumer-bypass-correlator-hook-journal-ring
status: planned
nyquist_compliant: true
wave_0_complete: true
review_cycle: 3
review_concerns_addressed: CR-08, CR-09, WR-10, WR-11, WR-12, IN-05, IN-06
created: 2026-05-27
updated: 2026-05-27
---

# Phase 53 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> **Revised 2026-05-27** incorporating Cycle 2 cross-AI review feedback.

---

## Review Feedback Addressed

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| CR-08: file_object extraction not explicitly wired | HIGH | Plan 04 Task 2 step 8: explicit `alert.file_object = event.file_object` sub-step; test `test_file_object_and_version_from_etw_event` verifies 0xDEADBEEF flows unchanged |
| CR-09: GatedOff emits EtwConsumerStopped (conflates lifecycle) | HIGH | Plan 01 Task 1: new `EventType::EtwConsumerGatedOff` distinct from `EtwConsumerStopped`; Plan 01 Task 2 step 7: gated-off path emits GatedOff event; tests verify correct event type |
| WR-10: Batch retry lacks per-alert retry tracking + batch_id reuse | Warning | Plan 04 Task 2 step 8c: failed alerts re-added with `retry_count += 1` and NEW `batch_id` (UUID v4); test `test_batch_retry_new_batch_id` verifies different batch_ids per retry |
| WR-11: nt_path_to_dos_path called twice creates hash mismatch risk | Warning | Plan 01 Task 2 step 10: `EtwFileEvent.nt_path_converted: bool` field; Plan 04 Task 2 step 8b: correlator skips events where `nt_path_converted=false` with `tracing::warn!` |
| WR-12: BypassAlert v1 backward compat missing serde(default) | Warning | Plan 04 Task 1 step 2: `#[serde(default)]` on ALL new fields; Plan 05 Task 1 step 1: `file_object` has `DEFAULT 0` in schema; tests verify v1 alert deserializes without error |
| IN-05: Test count bloat (28 tests, some redundant) | Info | Plan 04 Task 3: combined tests 25+26 (on-demand discovery + backoff) and 27+28 (file_object + version) reducing count from 28 to 26 without losing coverage |
| IN-06: VALIDATION.md stale (nyquist_compliant: false) | Info | This file updated: nyquist_compliant=true, wave_0_complete=true, per-task map reflects reviewed plan specs |

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
| 53-01-01 | 01 | 1 | ETW-01 | T-53-01 | ETW consumer starts without panic; parses CREATE/WRITE/DELETE events | unit | `cargo test -p dlp-agent etw_kernel_file` | ✅ Specified | planned |
| 53-01-02 | 01 | 1 | ETW-01 | T-53-01 | GatedOff emits EtwConsumerGatedOff (not Stopped) per CR-09 | unit | `cargo test -p dlp-agent etw_kernel_file::tests::test_consumer_start_gated_off_emits_gated_off_event` | ✅ Specified | planned |
| 53-01-03 | 01 | 1 | ETW-01 | T-53-01 | Buffer config 256KB x 200 prevents lost events under stress | integration | `cargo test -p dlp-agent etw_stress -- --ignored` | ✅ Specified | planned |
| 53-02-01 | 02 | 1 | ETW-02 | T-53-02 | Hook DLL creates journal shared memory lazily on first invocation | unit | `cargo test -p dlp-hook-dll journal_create` | ✅ Specified | planned |
| 53-02-02 | 02 | 1 | ETW-02 | T-53-02 | Journal entry format is 56 bytes; write_index wraps correctly | unit | `cargo test -p dlp-hook-dll journal_layout` | ✅ Specified | planned |
| 53-02-03 | 02 | 1 | ETW-02 | T-53-02 | Journal write happens BEFORE decision return in every trampoline | unit | `cargo test -p dlp-hook-dll journal_ordering` | ✅ Specified | planned |
| 53-03-01 | 03 | 1 | ETW-03 | T-53-03 | Path normalization extracted to dlp-common; identical in DLL and agent | unit | `cargo test -p dlp-common path_hash_roundtrip` | ✅ Specified | planned |
| 53-03-02 | 03 | 1 | ETW-03 | T-53-03 | NT path to DOS path conversion works for ETW FileName | unit | `cargo test -p dlp-common path_hash::tests::test_nt_path_to_dos_path_harddisk_volume` | ✅ Specified | planned |
| 53-04-01 | 04 | 2 | ETW-03 | T-53-03 | Correlator discovers journal via on-demand + exponential backoff | unit | `cargo test -p dlp-agent bypass_correlator::tests::test_on_demand_journal_discovery_and_backoff` | ✅ Specified | planned |
| 53-04-02 | 04 | 2 | ETW-03 | T-53-03 | file_object explicitly wired from ETW event per CR-08 | unit | `cargo test -p dlp-agent bypass_correlator::tests::test_file_object_and_version_from_etw_event` | ✅ Specified | planned |
| 53-04-03 | 04 | 2 | ETW-03 | T-53-03 | +/-5ms QPC tolerance matches journal entries correctly | unit | `cargo test -p dlp-agent bypass_correlator::tests::test_journal_entry_within_tolerance` | ✅ Specified | planned |
| 53-04-04 | 04 | 2 | ETW-03 | T-53-03 | Allowlisted PIDs (Defender, CrowdStrike) are dropped pre-correlation | unit | `cargo test -p dlp-agent bypass_correlator::tests::test_allowlist_hardcoded_system_exact_match` | ✅ Specified | planned |
| 53-04-05 | 04 | 2 | ETW-03 | T-53-03 | Unconverted NT paths skipped per WR-11 | unit | `cargo test -p dlp-agent bypass_correlator::tests::test_skip_unconverted_nt_path` | ✅ Specified | planned |
| 53-04-06 | 04 | 2 | ETW-03 | T-53-03 | Missing journal entry produces BypassAlert with correct reason | unit | `cargo test -p dlp-agent bypass_correlator::tests::test_severity_no_hook_journal_protected_path` | ✅ Specified | planned |
| 53-05-01 | 05 | 3 | ETW-04 | T-53-04 | `bypass_alerts` table schema matches ARCHITECTURE.md spec | unit | `cargo test -p dlp-server bypass_alerts_schema` | ✅ Specified | planned |
| 53-05-02 | 05 | 3 | ETW-04 | T-53-04 | `POST /audit/bypass` batch ingest accepts max 100 alerts with JWT | integration | `cargo test -p dlp-server bypass_ingest` | ✅ Specified | planned |
| 53-05-03 | 05 | 3 | ETW-04 | T-53-04 | v1 backward compat: missing fields deserialize with defaults per WR-12 | integration | `cargo test -p dlp-server bypass_alerts_integration::test_bypass_alert_v1_backward_compat` | ✅ Specified | planned |
| 53-05-04 | 05 | 3 | ETW-04 | T-53-04 | `GET /admin/bypass-alerts` returns paginated filtered results | integration | `cargo test -p dlp-server bypass_list` | ✅ Specified | planned |
| 53-05-05 | 05 | 3 | ETW-04 | T-53-04 | `POST /admin/bypass-alerts/:id/ack` is idempotent; 404 on missing | integration | `cargo test -p dlp-server bypass_ack` | ✅ Specified | planned |
| 53-06-01 | 06 | 4 | ETW-05 | T-53-05 | `crit` severity alerts trigger alert_router::send | unit | `cargo test -p dlp-server alert_router_crit` | ✅ Specified | planned |
| 53-06-02 | 06 | 4 | ETW-05 | T-53-05 | `warn`/`info` severity alerts route to SIEM only (no alert router) | unit | `cargo test -p dlp-server siem_only_warn` | ✅ Specified | planned |
| 53-06-03 | 06 | 4 | ETW-05 | T-53-05 | BypassAlert event type serializes correctly for SIEM relay | unit | `cargo test -p dlp-common bypass_alert_serde` | ✅ Specified | planned |
| 53-06-04 | 06 | 4 | ETW-05 | T-53-05 | EtwConsumerGatedOff routes through SIEM per CR-09 | unit | `cargo test -p dlp-common audit::tests::test_etw_consumer_gated_off_routed_to_siem` | ✅ Specified | planned |

*Status: planned | green | red | flaky*

---

## Wave 0 Requirements

- [x] `dlp-agent/src/etw_kernel_file.rs` — module spec with `EtwKernelFileConsumer` struct, `nt_path_converted` field (WR-11)
- [x] `dlp-agent/src/bypass_correlator.rs` — module spec with explicit `file_object` wiring (CR-08), new batch_id per retry (WR-10)
- [x] `dlp-hook-dll/src/hook_journal.rs` — module spec with `JournalEntry` and `HookJournal` types
- [x] `dlp-common/src/path_hash.rs` — extracted `normalize_path` + `fnv1a_64` for cross-crate reuse
- [x] `dlp-server/src/db/repositories/bypass_alerts.rs` — repository spec with v1 compat (WR-12)
- [x] `dlp-server/tests/bypass_alerts_integration.rs` — integration test spec with file_object E2E test (CR-08)
- [x] `dlp-agent/tests/etw_consumer_integration.rs` — integration test scaffold (Windows-only, skip on non-Windows)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| 10,000 events/sec stress with zero lost ETW events | ETW-01 | Requires dedicated Windows host with sustained I/O load; not reproducible in CI | Run `dlp-agent/tests/stress_etw.rs` on physical Windows 11 host with `fsstress.exe` generating 10K file ops/sec. Verify Event Viewer shows zero Event ID 2 from Microsoft-Windows-Kernel-EventTracing/Admin. |
| Zero Defender/CrowdStrike bypass alerts in soak test | ETW-03 | Requires real AV/EDR software installed | Deploy agent on endpoint with Defender ATP enabled. Run normal workloads for 24h. Verify `bypass_alerts` table contains zero entries from `MsMpEng.exe` or `C:\Windows\System32\svchost.exe` (Defender service host). |
| End-to-end hook-uninstalled bypass detection | ETW-03 | Requires deliberately removing hook DLL from a process | Launch `notepad.exe`, verify hook is injected (check `Global\DlpHookJournal_<pid>` exists). Use Process Hacker to unload `dlp_hook_dll.dll`. Create a file in a T3 path. Verify `BypassAlert` appears within 5 seconds with `correlation_reason=NoHookJournal`. |
| GatedOff event appears in SIEM on policy disable | CR-09 | Requires real SIEM endpoint | Set `enable_bypass_correlator=false` in agent config. Restart agent. Verify SIEM receives `EtwConsumerGatedOff` event with reason="gated_by_policy". Re-enable via hot-reload. Verify `EtwConsumerStarted` event appears (no backwards Stopped event). |

---

## Threat Model

| ID | Threat | Mitigation | Verification |
|----|--------|------------|------------|
| T-53-01 | ETW events lost due to undersized buffers | 256KB x 200 buffers (52MB total); lost-event monitoring | Stress test + Event ID 2 check |
| T-53-02 | Journal shared memory exhausted or corrupted | 64KB fixed size; single-producer; versioned header; graceful fallback on failure | Unit test layout + corruption recovery |
| T-53-03 | False-positive bypass alerts from timing skew | +/-5ms QPC tolerance; path-hash exact match; allowlist pre-filter; nt_path_converted skip (WR-11) | Tolerance unit test + allowlist test + unconverted skip test |
| T-53-04 | Agent impersonates another agent to inject fake bypass alerts | `POST /audit/bypass` validates `agent_id` against JWT claims | Integration test with mismatched agent_id |
| T-53-05 | Bypass alert severity escalation bypasses alert router | Severity mapping is fixed (not user-configurable); `crit` always triggers router | Unit test severity-to-router mapping |

---

## Validation Sign-Off

- [x] All tasks have automated verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter
- [x] Cycle 2 review concerns CR-08 and CR-09 addressed in plan text
- [x] Cycle 2 review concerns WR-10, WR-11, WR-12 addressed in plan text
- [x] Cycle 2 info items IN-05, IN-06 addressed in plan text

**Approval:** ready for execution
