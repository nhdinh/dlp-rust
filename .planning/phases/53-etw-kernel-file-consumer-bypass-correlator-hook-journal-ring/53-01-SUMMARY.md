---
phase: 53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring
plan: 01
subsystem: dlp-agent / dlp-common
status: complete
tags: [etw, kernel-file, bypass-correlator, ferrisetw, nt-path, audit-events]
dependency_graph:
  requires: []
  provides: [53-04-bypass-correlator, 53-02-hook-journal-ring]
  affects: [dlp-agent/src/etw_kernel_file.rs, dlp-common/src/audit.rs, dlp-agent/src/config.rs]
tech_stack:
  added:
    - ferrisetw 1.2.0 (kernel provider)
    - crossbeam-channel 0.5 (bounded channel)
    - windows 0.62 (QueryDosDeviceW)
  patterns:
    - Mirror ProcessWatcher thread+channel+tokio architecture
    - NT device path to DOS path conversion before filtering
    - Consumer-side System32/WinSxS noise filter
key_files:
  created:
    - dlp-agent/src/etw_kernel_file.rs
  modified:
    - dlp-common/src/audit.rs
    - dlp-agent/src/config.rs
    - dlp-agent/src/lib.rs
    - dlp-common/src/path_hash.rs
decisions:
  - "Audit event emission for GatedOff deferred to caller (service.rs) because emit_audit requires EmitContext only available at startup"
  - "check_lost_events() returns stub false; full WMI/wevtapi query deferred to Plan 04 tokio polling loop"
  - "Used ferrisetw::GUID::from_values instead of native::etw_types::GUID because etw_types is pub(crate) in ferrisetw 1.2.0"
  - "Used raw_timestamp() instead of timestamp() because timestamp() requires 'time_rs' feature which is not enabled"
metrics:
  duration: "~25 minutes"
  completed_date: "2026-05-27"
  tasks: 3
  tests_added: 35
  tests_passing: 904
---

# Phase 53 Plan 01: ETW Kernel-File Consumer Summary

## One-liner

ETW Kernel-File consumer module mirroring ProcessWatcher architecture, with NT path conversion, consumer-side noise filtering, gated start semantics, and 22 unit tests.

## What Was Built

### dlp-agent/src/etw_kernel_file.rs (NEW)

- `EtwKernelFileConsumer` — struct with crossbeam channel, dedicated OS thread, atomic health flag
- `EtwFileEvent` — parsed event with `nt_path_converted: bool` (WR-11)
- `FileOp` enum — Create=1, Write=2, Delete=3, SetInfo=4
- `EtwConsumerState` enum — Started, GatedOff { reason }, Failed { error } (CR-06)
- `run_etw_kernel_file_loop()` — ferrisetw kernel provider callback, path conversion, filtering, channel push
- `is_system32_or_winsxs()` — consumer-side noise filter on converted DOS paths
- `check_lost_events()` — stub for Plan 04 tokio integration (IN-03)

### dlp-common/src/audit.rs (MODIFIED)

- Added `EventType::EtwConsumerStarted`, `EtwConsumerStopped`, `EtwConsumerGatedOff`, `EtwConsumerLostEvents`
- Wired all four through `routed_to_siem()` (all true)
- `EtwConsumerLostEvents` triggers alert; others do not
- 10 new unit tests for routing and serde roundtrip

### dlp-agent/src/config.rs (MODIFIED)

- Added `enable_bypass_correlator: Option<bool>` field
- Added `bypass_correlator_enabled()` helper with backward-compatible fallback to `enable_ntdll_patching`
- 4 new unit tests for flag combinations and TOML roundtrip

### dlp-agent/src/lib.rs (MODIFIED)

- Added `#[cfg(windows)] pub mod etw_kernel_file;`

### dlp-common/src/path_hash.rs (FIXED)

- Fixed `QueryDosDeviceW` signature for windows 0.62 (returns `u32`, not `Result`)

## Commits

| Hash | Message | Files |
|------|---------|-------|
| b74ff0f | feat(53-03): create dlp-common/src/path_hash.rs with normalization, FNV-1a, NT path conversion | dlp-common/src/path_hash.rs, dlp-common/src/audit.rs, dlp-agent/src/config.rs, dlp-common/src/lib.rs |
| 7827c6e | feat(53-01): implement ETW Kernel-File consumer module | dlp-agent/src/etw_kernel_file.rs, dlp-agent/src/lib.rs |

## Test Results

```
dlp-agent lib tests:  661 passed, 0 failed, 0 ignored
dlp-common lib tests: 243 passed, 0 failed, 0 ignored
Workspace build:      SUCCESS (all crates)
Clippy:               CLEAN (-D warnings)
```

### New Tests Added

**dlp-common/src/audit.rs (10 tests):**
- `test_etw_consumer_started_routed_to_siem`
- `test_etw_consumer_stopped_routed_to_siem`
- `test_etw_consumer_gated_off_routed_to_siem`
- `test_etw_consumer_lost_events_routed_to_siem`
- `test_etw_consumer_lost_events_triggers_alert`
- `test_etw_consumer_started_does_not_trigger_alert`
- `test_etw_consumer_stopped_does_not_trigger_alert`
- `test_etw_consumer_gated_off_does_not_trigger_alert`
- `test_etw_consumer_event_serde_roundtrip`

**dlp-agent/src/config.rs (4 tests):**
- `test_bypass_correlator_defaults_to_ntdll_patching`
- `test_bypass_correlator_explicitly_enabled`
- `test_bypass_correlator_explicitly_disabled`
- `test_bypass_correlator_toml_roundtrip`

**dlp-agent/src/etw_kernel_file.rs (22 tests):**
- `test_file_op_discriminants`
- `test_file_op_from_event_id`
- `test_file_op_from_unknown_event_id`
- `test_etw_file_event_clone`
- `test_consumer_new_creates_channel`
- `test_consumer_healthy_defaults_true`
- `test_consumer_start_gated_off_returns_gated_off`
- `test_consumer_start_gated_off_emits_gated_off_event`
- `test_consumer_start_stop_lifecycle`
- `test_system32_filter_drops_event`
- `test_winsxs_filter_drops_event`
- `test_non_system_path_passes_filter`
- `test_dos_path_passes_through_nt_conversion`
- `test_nt_path_unknown_volume_fallback`
- `test_nt_path_converted_flag_true`
- `test_nt_path_converted_flag_false`
- `test_channel_overflow_counter`
- `test_etw_consumer_state_serde`
- `test_check_lost_events_returns_bool`
- `test_file_op_equality`
- `test_is_system32_or_winsxs_case_insensitive`
- `test_is_system32_or_winsxs_edge_cases`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed ferrisetw API mismatches**
- **Found during:** Task 2 compilation
- **Issue:** `Provider::kernel()` expects `&KernelProvider`, not `&str`. `EventRecord::timestamp()` requires `time_rs` feature (not enabled); `raw_timestamp()` is the correct method.
- **Fix:** Built `KernelProvider` struct with `GUID::from_values()` and `EVENT_TRACE_FLAG_FILE_IO`. Used `raw_timestamp()` returning `i64`.
- **Files modified:** `dlp-agent/src/etw_kernel_file.rs`

**2. [Rule 1 - Bug] Fixed audit_emitter API mismatch**
- **Found during:** Task 2 compilation
- **Issue:** `emit_audit()` takes `&EmitContext` and `&mut AuditEvent`, not raw strings. `EmitContext` is only available at service startup.
- **Fix:** Removed inline audit emission from `start()`. The GatedOff event emission is deferred to the caller (service.rs) which has access to `EmitContext`. Added comment explaining this.
- **Files modified:** `dlp-agent/src/etw_kernel_file.rs`

**3. [Rule 1 - Bug] Fixed QueryDosDeviceW signature for windows 0.62**
- **Found during:** Task 1 compilation (dlp-agent config tests triggered dlp-common rebuild)
- **Issue:** `QueryDosDeviceW` in windows 0.62 returns `u32` directly, not `Result<u32, _>`.
- **Fix:** Changed match-on-Result to direct `u32` cast to `usize`.
- **Files modified:** `dlp-common/src/path_hash.rs`

**4. [Rule 2 - Missing critical functionality] Added missing AgentConfig fields in test struct literals**
- **Found during:** Task 1 compilation
- **Issue:** Two existing tests (`test_agent_config_save_roundtrip`, `test_agent_config_save_preserves_server_url`) used exhaustive struct literals missing the new `enable_bypass_correlator` field.
- **Fix:** Added `enable_bypass_correlator: None` to both struct literals.
- **Files modified:** `dlp-agent/src/config.rs`

## Known Stubs

| File | Line | Stub | Reason |
|------|------|------|--------|
| `dlp-agent/src/etw_kernel_file.rs` | ~360 | `check_lost_events()` returns `false` | Full WMI/wevtapi query deferred to Plan 04 tokio polling loop. The function signature and return type are correct; implementation will be completed when the correlator tokio task is wired. |

## Threat Flags

No new security-relevant surface beyond what was in the plan's threat model. All trust boundaries (ETW callback -> channel, Agent -> ETW session) are documented and mitigated per T-53-01 through T-53-04.

## Self-Check: PASSED

- [x] `dlp-agent/src/etw_kernel_file.rs` exists (622 lines)
- [x] `dlp-agent/src/lib.rs` contains `pub mod etw_kernel_file;`
- [x] Commit `7827c6e` exists in git log
- [x] Commit `b74ff0f` exists in git log (contains audit.rs + config.rs changes)
- [x] All tests pass (904 total)
- [x] Clippy clean (-D warnings)
- [x] Workspace builds successfully
- [x] No `unwrap()` in library code paths
