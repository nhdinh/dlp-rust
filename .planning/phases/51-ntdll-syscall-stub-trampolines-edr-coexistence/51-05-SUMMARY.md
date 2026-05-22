---
phase: 51-ntdll-syscall-stub-trampolines-edr-coexistence
plan: 05
subsystem: cross-crate
 tags: [ntdll, config, ipc, audit, siem, bypass-alert, phase-51]

requires:
  - phase: 51-03
    provides: NtdllTrampoline* functions and NTDLL_STUBS constant wired
  - phase: 51-04
    provides: StubIntegrity verification and background re-verification thread
provides:
  - BypassAlert struct and BypassReason enum in dlp-common
  - Three new EventType variants: NtdllPatchingEnabled, NtdllPatchingEdrDetected, HookOverwritten
  - enable_ntdll_patching config flag in AgentConfig
  - Service startup SIEM emission for NtdllPatchingEnabled
  - All new event types route to SIEM via routed_to_siem()
affects:
  - 51-06 (chaos test + BypassAlert IPC wiring)
  - 53 (ETW Kernel-File consumer will convert BypassAlert to audit events)

tech-stack:
  added: []
  patterns:
    - Option<bool> with serde(default) for agent config flags
    - Bincode serialization for IPC types (BypassAlert)
    - SCREAMING_SNAKE_CASE serde rename for EventType variants
    - AuditEvent::new + emit() for SIEM event emission at service startup

key-files:
  created: []
  modified:
    - dlp-common/src/hook_ipc.rs - Added BypassAlert and BypassReason types + 2 tests
    - dlp-common/src/audit.rs - Added 3 EventType variants + SIEM routing + 3 tests
    - dlp-agent/src/config.rs - Added enable_ntdll_patching field + 2 tests
    - dlp-agent/src/service.rs - Added startup SIEM emission for NtdllPatchingEnabled

key-decisions:
  - "Action::PolicyUpdate used instead of non-existent Action::CONFIG_CHANGE for NtdllPatchingEnabled event"
  - "agent_id resolved via DLP_AGENT_ID env var with hostname fallback (same pattern as build_audit_ctx)"
  - "emit() used instead of emit_audit() because EmitContext is not yet available at hook injector init site"

patterns-established:
  - "Cross-crate type contract: dlp-common defines BypassAlert, dlp-hook-dll emits it, dlp-agent receives and converts to AuditEvent"
  - "Service startup config flag read + conditional SIEM emission pattern for feature enablement events"

requirements-completed: [BLOCK-08, BLOCK-09]

duration: 10min
completed: 2026-05-22
---

# Phase 51 Plan 05: Agent Config, IPC Types, and SIEM Audit Events Summary

**BypassAlert and BypassReason types in dlp-common, three new EventType variants with SIEM routing, enable_ntdll_patching config flag, and service startup SIEM emission**

## Performance

- **Duration:** 10 min
- **Started:** 2026-05-22T07:02:47Z
- **Completed:** 2026-05-22T07:12:47Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

### Task 1: Extend dlp-common types

- Added `BypassAlert` struct to `dlp-common/src/hook_ipc.rs` with `reason`, `stub_name`, `pid`, `timestamp_secs` fields
- Added `BypassReason` enum with `HookOverwritten`, `PatchRaced`, `EdrDetected` variants
- Added three `EventType` variants to `dlp-common/src/audit.rs`: `NtdllPatchingEnabled`, `NtdllPatchingEdrDetected`, `HookOverwritten`
- Wired all three new variants into `routed_to_siem()` matches expression
- Added 5 tests:
  - `bypass_alert_roundtrip` — bincode serialize/deserialize
  - `bypass_reason_serde` — JSON roundtrip for all 3 variants
  - `event_type_ntdll_patching_enabled_routed_to_siem`
  - `event_type_ntdll_patching_edr_detected_routed_to_siem`
  - `event_type_hook_overwritten_routed_to_siem`
- All 197 dlp-common tests pass; clippy clean (-D warnings)

### Task 2: Extend AgentConfig and service.rs

- Added `enable_ntdll_patching: Option<bool>` to `AgentConfig` with `#[serde(default)]`
- Added `test_agent_config_enable_ntdll_patching_default` — verifies default is None
- Added `test_agent_config_enable_ntdll_patching_deserialize` — verifies TOML parsing
- Updated `test_agent_config_save_roundtrip` to include `enable_ntdll_patching: None`
- Updated `test_agent_config_save_preserves_server_url` to include the new field
- Service startup reads `enable_ntdll_patching` and emits `EventType::NtdllPatchingEnabled` audit event via `crate::audit_emitter::emit()` when true
- All 585 dlp-agent tests pass; clippy clean (-D warnings)

## Task Commits

Each task was committed atomically:

1. **Task 1: Extend dlp-common types** — `9a3ef9d` (feat)
2. **Task 2: Extend AgentConfig and service.rs** — `7684fae` (feat)

## Files Created/Modified

- `dlp-common/src/hook_ipc.rs` — Added `BypassAlert` struct, `BypassReason` enum, 2 tests
- `dlp-common/src/audit.rs` — Added 3 `EventType` variants, wired to `routed_to_siem()`, 3 tests
- `dlp-agent/src/config.rs` — Added `enable_ntdll_patching` field, 2 tests, updated roundtrip tests
- `dlp-agent/src/service.rs` — Added startup SIEM emission for `NtdllPatchingEnabled`

## Decisions Made

- **`Action::PolicyUpdate` instead of `Action::CONFIG_CHANGE`:** The `Action` enum in `dlp-common/src/abac.rs` does not have a `CONFIG_CHANGE` variant. `PolicyUpdate` is the closest semantic match for a configuration change event. This is a deviation from the plan's example code but matches the actual type system.
- **`emit()` instead of `emit_audit()`:** The `EmitContext` (with `agent_id`, `session_id`, etc.) is constructed later in `build_audit_ctx()`. At the hook injector initialization site, we use the lower-level `emit()` function with an explicitly constructed `AuditEvent`. Both functions write to the same audit log.
- **`agent_id` resolved via env var + hostname fallback:** Same pattern as `build_audit_ctx()` — reads `DLP_AGENT_ID` env var, falls back to `hostname::get()`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `Action::CONFIG_CHANGE` does not exist in dlp-common::Action**
- **Found during:** Task 2 compilation
- **Issue:** The plan's example code used `dlp_common::Action::CONFIG_CHANGE` for the `NtdllPatchingEnabled` audit event, but the `Action` enum in `dlp-common/src/abac.rs` has no such variant (it has `PolicyCreate`, `PolicyUpdate`, `PolicyDelete`, etc.)
- **Fix:** Used `dlp_common::Action::PolicyUpdate` instead, which is the closest semantic match for a configuration change event.
- **Files modified:** `dlp-agent/src/service.rs`
- **Verification:** `cargo check -p dlp-agent` passes; all 585 tests pass
- **Committed in:** `7684fae` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Minor — used existing enum variant instead of non-existent one.

## Issues Encountered

None.

## Known Stubs

| File | Line | Stub | Resolution Plan |
|------|------|------|-----------------|
| `ntdll_patcher.rs` | ~520 | `emit_bypass_alert()` logs only via `debug_log` | Plan 06 — wire to `pipe_client::send_raw_request` using new `BypassAlert` type |
| `service.rs` | ~1156 | `enable_ntdll_patching` flag is read but not yet passed to hook injector | Plan 06 — add `set_ntdll_patching_enabled()` to `HookInjector` and pass flag |

## Threat Flags

None — all security-relevant surface (SIEM routing, IPC serialization, config flag) is explicitly covered in the plan's threat model (T-51-17 through T-51-20).

## Next Phase Readiness

- Plan 06 can wire `emit_bypass_alert()` to pipe IPC using the new `BypassAlert` type
- Plan 06 can add `set_ntdll_patching_enabled()` to `HookInjector` and pass the flag through to the hook DLL
- Plan 53 (ETW consumer) can convert received `BypassAlert` messages to `AuditEvent` with `EventType::HookOverwritten` or `NtdllPatchingEdrDetected`

## Self-Check: PASSED

- [x] `dlp-common/src/hook_ipc.rs` contains `BypassAlert` and `BypassReason`
- [x] `dlp-common/src/audit.rs` contains `NtdllPatchingEnabled`, `NtdllPatchingEdrDetected`, `HookOverwritten`
- [x] All three new event types are in `routed_to_siem()`
- [x] `cargo test -p dlp-common` passes (197 tests)
- [x] `cargo test -p dlp-agent` passes (585 tests)
- [x] `cargo clippy --workspace -- -D warnings` is clean
- [x] Commit `9a3ef9d` exists (Task 1)
- [x] Commit `7684fae` exists (Task 2)

---
*Phase: 51-ntdll-syscall-stub-trampolines-edr-coexistence*
*Completed: 2026-05-22*
