---
phase: 49
slug: universal-injection-etw-process-watcher-allowlist-appinit-fa
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-05-19
audited: 2026-06-14
---

# Phase 49 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Audited on 2026-06-14: 9/9 gaps filled by Nyquist auditor; 0 escalated. 49-03-04 startup sweep remains manual-only due to real Windows APIs.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Built-in `#[test]` + `cargo test` (Rust standard) |
| **Config file** | None — inline `#[cfg(test)]` modules |
| **Quick run command** | `cargo test -p dlp-agent` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~45 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-agent`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 49-01-01 | 01 | 1 | BLOCK-05/06/07 | T-49-01 | Dependencies compile without "unknown crate" errors | build | `cargo check -p dlp-agent` | Yes | green |
| 49-01-02 | 01 | 1 | BLOCK-05 | T-49-02 | ProcessRegistry uses (PID, creation_time) composite key with atomic claim/transition API | unit | `cargo test -p dlp-agent process_registry` | Yes | green |
| 49-01-03 | 01 | 1 | BLOCK-06 | T-49-03 | AllowlistMatcher uses canonical paths, trusted-dir checks, directory-boundary prefix matching | unit | `cargo test -p dlp-agent allowlist` | Yes | green |
| 49-01-04 | 01 | 1 | BLOCK-06 | T-49-04 | Authenticode signer extraction with 5-minute TTL cache | unit | `cargo test -p dlp-agent allowlist` | Yes | green |
| 49-01-05 | 01 | 1 | BLOCK-07 | T-49-05 | AppInit_DLLs registry read-only at boot with Secure Boot detection | unit | `cargo test -p dlp-agent appinit` | Yes | green |
| 49-01-06 | 01 | 1 | BLOCK-05 | T-49-06 | Unit tests for process_registry.rs | unit | `cargo test -p dlp-agent process_registry` | Yes | green |
| 49-01-07 | 01 | 1 | BLOCK-06 | T-49-07 | Unit tests for allowlist.rs | unit | `cargo test -p dlp-agent allowlist` | Yes | green |
| 49-02-01 | 02 | 1 | BLOCK-06 | T-49-08 | allowlist_entries + allowlist_audit_log tables with CHECK constraints | build | `cargo check -p dlp-server` | Yes | green |
| 49-02-02 | 02 | 1 | BLOCK-06 | T-49-09 | AllowlistRepository + AllowlistAuditRepository CRUD + version query | unit | `cargo test -p dlp-server db::repositories::allowlist` | Yes | green |
| 49-02-03 | 02 | 1 | BLOCK-06 | T-49-10 | /admin/allowlist CRUD endpoints with validation and audit logging | integration | `cargo test -p dlp-server admin_api::tests::test_ allowlist` | Yes | green |
| 49-02-04 | 02 | 1 | BLOCK-06 | T-49-11 | Unit tests for AllowlistRepository | unit | `cargo test -p dlp-server db::repositories::allowlist` | Yes | green |
| 49-02-05 | 02 | 1 | BLOCK-06 | T-49-12 | Unit tests for admin API handlers | integration | `cargo test -p dlp-server admin_api::tests::test_create_allowlist_handler` | Yes | green |
| 49-03-01 | 03 | 2 | BLOCK-05 | T-49-13 | ETW primary + WMI backstop on dedicated thread with bounded channel | unit | `cargo test -p dlp-agent process_watcher` | Yes | green |
| 49-03-02 | 03 | 2 | BLOCK-05/06 | T-49-14 | UniversalInjector orchestrates claim, allowlist, PPL detection, injection, latency tracking | unit | `cargo test -p dlp-agent universal_injector` | Yes | green |
| 49-03-03 | 03 | 2 | BLOCK-05/06 | T-49-15 | ProcessWatcher + UniversalInjector integrated into service.rs | build | `cargo check -p dlp-agent` | Yes | green |
| 49-03-04 | 03 | 2 | BLOCK-05 | T-49-16 | Startup EnumProcesses sweep with Semaphore(32) and 5s timeout | integration | Manual — see Manual-Only table | Yes | manual |
| 49-03-05 | 03 | 2 | BLOCK-05 | T-49-17 | Periodic 5-minute EnumProcesses backstop sweep | integration | Manual — see Manual-Only table | Yes | manual |
| 49-03-06 | 03 | 2 | BLOCK-05 | T-49-18 | Delayed retry queue (+200ms) for transient failures | unit | `cargo test -p dlp-agent test_retry_queue` | Yes | green |
| 49-03-07 | 03 | 2 | BLOCK-05/06 | T-49-19 | Unit tests for universal_injector.rs and process_watcher.rs | unit | `cargo test -p dlp-agent universal_injector process_watcher` | Yes | green |
| 49-04-01 | 04 | 2 | BLOCK-06/07 | T-49-20 | AgentConfig extended with allowlist_entries + allowlist_version | unit | `cargo test -p dlp-agent test_agent_config_allowlist` | Yes | green |
| 49-04-02 | 04 | 2 | BLOCK-06/07 | T-49-21 | AgentConfigPayload extended with allowlist fields | unit | `cargo test -p dlp-agent test_agent_config_payload_allowlist` | Yes | green |
| 49-04-03 | 04 | 2 | BLOCK-06/07 | T-49-22 | Config poll sends If-None-Match; 304 skips update | unit | `cargo test -p dlp-agent test_fetch_agent_config_with_version` | Yes | green |
| 49-04-04 | 04 | 2 | BLOCK-06/07 | T-49-23 | Server returns 304 when If-None-Match matches allowlist version | integration | `cargo test -p dlp-server test_agent_config_304` | Yes | green |
| 49-04-05 | 04 | 2 | BLOCK-06 | T-49-24 | Admin TUI allowlist screen (list/add/edit/disable/delete) | smoke | Manual — TUI screen verification | Yes | manual |
| 49-04-06 | 04 | 2 | BLOCK-06 | T-49-25 | Allowlist screen wired into app.rs/dispatch/render/client | build | `cargo check -p dlp-admin-cli` | Yes | green |
| 49-04-07 | 04 | 2 | BLOCK-06/07 | T-49-26 | Config wiring tests: TOML roundtrip + invalid entry handling | unit | `cargo test -p dlp-agent test_agent_config_allowlist` | Yes | green |
| 49-05-01 | 05 | 3 | BLOCK-05/06/07 | T-49-27 | Telemetry aggregation with latency percentiles and coverage percent | unit | `cargo test -p dlp-agent test_process_registry_telemetry_snapshot` | Yes | green |
| 49-05-02 | 05 | 3 | BLOCK-05/06/07 | T-49-28 | Periodic 60s telemetry task emits injection_telemetry | integration | `cargo test -p dlp-agent --test universal_injection` | Yes | green |
| 49-05-03 | 05 | 3 | BLOCK-05 | T-49-29 | Failed-state retention cap at 1000 entries with LRU eviction | unit | `cargo test -p dlp-agent registry_eviction` | Yes | green |
| 49-05-04 | 05 | 3 | BLOCK-07 | T-49-30 | Installer AppInit_DLLs setup with backup/restore | smoke | Manual — see Manual-Only table | Yes | manual |
| 49-05-05 | 05 | 3 | BLOCK-07 | T-49-31 | Post-install verification spawns test process and confirms DLL load | smoke | Manual — see Manual-Only table | Yes | manual |
| 49-05-06 | 05 | 3 | BLOCK-05 | T-49-32 | Simulated ETW event stream (100 events) | integration | `cargo test -p dlp-agent --test universal_injection test_simulated_etw_stream` | Yes | green |
| 49-05-07 | 05 | 3 | BLOCK-05 | T-49-33 | PID reuse integration scenarios | integration | `cargo test -p dlp-agent --test universal_injection test_pid_reuse` | Yes | green |
| 49-05-08 | 05 | 3 | BLOCK-06 | T-49-34 | Allowlist update propagation | unit | `cargo test -p dlp-agent test_update_entries` | Yes | green |
| 49-05-09 | 05 | 3 | BLOCK-05 | T-49-35 | Stress test 1000 processes in <10s | integration | `cargo test -p dlp-agent --test universal_injection test_high_churn_1000_processes` | Yes | green |
| 49-05-10 | 05 | 3 | BLOCK-05/06/07 | T-49-36 | Full workspace test suite passes | integration | `cargo test --workspace` | Yes | green |

*Status: pending · green · red · flaky · manual · escalated*

---

## Wave 0 Requirements

Existing test infrastructure covers all Phase 49 requirements. No Wave 0 stub files needed.

- [x] `dlp-agent/src/process_registry.rs` — unit tests
- [x] `dlp-agent/src/allowlist.rs` — unit tests
- [x] `dlp-agent/src/appinit.rs` — unit tests
- [x] `dlp-agent/src/universal_injector.rs` — unit tests
- [x] `dlp-agent/src/process_watcher.rs` — unit tests
- [x] `dlp-agent/tests/universal_injection.rs` — integration tests
- [x] `dlp-server/src/db/repositories/allowlist.rs` — unit tests
- [x] `dlp-server/src/admin_api.rs` — integration tests

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Startup EnumProcesses sweep completes within 5s with bounded concurrency | BLOCK-05 | Requires real Windows process enumeration (`K32EnumProcesses`, `OpenProcess`) and injection into live processes | Start agent service with `universal_injection_enabled=true`; verify `startup sweep complete` log appears within 5s of service start; verify no more than 32 concurrent injection attempts via tracing spans |
| Periodic 5-minute EnumProcesses backstop sweep fires and catches missed processes | BLOCK-05 | Requires live process fleet and ETW disable simulation | Run agent for >5 minutes; temporarily block ETW callback; verify `periodic backstop sweep starting` log and injection attempts for newly launched processes |
| Installer AppInit_DLLs setup with backup/restore | BLOCK-07 | Requires Windows registry writes and installer execution | Run `installer/build.ps1` on a test endpoint; verify `HKLM\SOFTWARE\DLP\Backup\AppInit_DLLs` contains original values; verify AppInit_DLLs includes DLP hook DLL path; uninstall and verify restore |
| Post-install verification confirms DLL load in test process | BLOCK-07 | Requires live process spawn and module enumeration on Windows | After installer completes, verify log message "Post-install verification PASSED" or inspect spawned notepad.exe modules for `dlp_hook_dll.dll` |
| Admin TUI allowlist screen navigation and CRUD | BLOCK-06 | Requires interactive terminal UI | Launch `dlp-admin-cli`, navigate to Allowlist screen, press `a` to add, `e` to edit, `d` to disable, `x` to delete, `F5` to refresh; verify screen updates and server API calls succeed |
| ETW 500ms latency from ProcessStart to injection | BLOCK-05 | Requires real Windows process spawning with QPC timing | Spawn notepad.exe, verify hook DLL module appears within 500ms via Process Hacker |
| Coverage telemetry >= 99% | BLOCK-05 | Requires real process fleet over time | Run for 10 min with normal workload, check `siem.injection_telemetry` events |
| AV/EDR signer-cert matching against real vendors | BLOCK-06 | Requires installed AV/EDR products | Install CrowdStrike/SentinelOne/Defender, verify processes are skipped in log |
| Secure Boot detection on real UEFI system | BLOCK-07 | Requires UEFI firmware variable access | Run on Secure Boot enabled endpoint, verify `siem.appinit_dlls_disabled` fires once |

---

## Validation Audit 2026-06-13

| Metric | Count |
|--------|-------|
| Gaps found | 10 |
| Resolved | 8 |
| Escalated | 2 |

### Resolved Gaps

| # | Task ID | Requirement | File | Command |
|---|---------|-------------|------|---------|
| 1 | 49-03-06 | Retry queue receives failed injection with +200ms delay | `dlp-agent/src/universal_injector.rs` | `cargo test -p dlp-agent test_retry_queue_receives_failed_injection` |
| 2 | 49-03-06 | Retry queue only queues one retry (no infinite loop) | `dlp-agent/src/universal_injector.rs` | `cargo test -p dlp-agent test_retry_queue_only_one_retry` |
| 3 | 49-04-03 | AgentConfig fetch with version returns 304 when matches | `dlp-agent/src/server_client.rs` | `cargo test -p dlp-agent test_fetch_agent_config_with_version_304_returns_none` |
| 4 | 49-04-03 | AgentConfigPayload allowlist version roundtrip | `dlp-agent/src/server_client.rs` | `cargo test -p dlp-agent test_agent_config_payload_allowlist_version_roundtrip` |
| 5 | 49-04-03 | AgentConfigPayload allowlist default when missing | `dlp-agent/src/server_client.rs` | `cargo test -p dlp-agent test_agent_config_payload_allowlist_default_when_missing` |
| 6 | 49-04-04 | Server returns 304 Not Modified when version matches | `dlp-server/src/admin_api.rs` | `cargo test -p dlp-server test_agent_config_304_not_modified` |
| 7 | 49-04-04 | Server returns 200 when version mismatches | `dlp-server/src/admin_api.rs` | `cargo test -p dlp-server test_agent_config_200_when_version_mismatch` |
| 8 | 49-04-07 | AgentConfig allowlist_entries TOML roundtrip | `dlp-agent/src/config.rs` | `cargo test -p dlp-agent test_agent_config_allowlist_entries_toml_roundtrip` |
| 9 | 49-04-07 | AgentConfig allowlist_version TOML roundtrip | `dlp-agent/src/config.rs` | `cargo test -p dlp-agent test_agent_config_allowlist_version_roundtrip` |
| 10 | 49-04-07 | AgentConfig allowlist empty by default | `dlp-agent/src/config.rs` | `cargo test -p dlp-agent test_agent_config_allowlist_empty_by_default` |
| 11 | 49-04-07 | AgentConfig allowlist backwards compatible | `dlp-agent/src/config.rs` | `cargo test -p dlp-agent test_agent_config_allowlist_backwards_compatible` |
| 12 | 49-05-06 | Simulated ETW stream 100 events processed | `dlp-agent/tests/universal_injection.rs` | `cargo test -p dlp-agent --test universal_injection test_simulated_etw_stream_100_events` |
| 13 | 49-05-07 | Same PID different creation_time both tracked | `dlp-agent/tests/universal_injection.rs` | `cargo test -p dlp-agent --test universal_injection test_pid_reuse_same_pid_different_creation_time` |
| 14 | 49-05-07 | Rapid claim/unclaim/claim cycle works | `dlp-agent/tests/universal_injection.rs` | `cargo test -p dlp-agent --test universal_injection test_pid_reuse_rapid_claim_unclaim_claim` |
| 15 | 49-05-09 | High churn 1000 processes in <10s | `dlp-agent/tests/universal_injection.rs` | `cargo test -p dlp-agent --test universal_injection test_high_churn_1000_processes` |
| 16 | 49-05-03 | Failed-state retention cap at 1000 entries with LRU eviction | `dlp-agent/src/process_registry.rs` | `cargo test -p dlp-agent registry_eviction` |

### Escalated Gaps

_No remaining escalated gaps. 49-03-04 startup sweep is documented as manual-only above._

---

## Validation Audit 2026-06-14

| Metric | Count |
|--------|-------|
| Gaps found | 1 |
| Resolved | 1 |
| Escalated | 0 |

### Resolved Gaps

| # | Task ID | Requirement | File | Command |
|---|---------|-------------|------|---------|
| 1 | 49-05-03 | Failed-state retention cap at 1000 entries with LRU eviction | `dlp-agent/src/process_registry.rs` | `cargo test -p dlp-agent registry_eviction` |

## Validation Sign-Off

- [x] All tasks have automated verify, Wave 0 dependency, or documented manual-only justification
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 60s
- [x] `nyquist_compliant: true` — Phase 49 is Nyquist-compliant. 49-03-04 startup sweep has a documented manual-only justification.

**Approval:** approved — all automated gaps resolved; remaining manual-only verifications are accepted.

---

*Phase: 49-universal-injection-etw-process-watcher-allowlist-appinit-fa*
*Audited: 2026-06-14*
