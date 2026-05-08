# Phase 43 Plan 04: USB Enforcement Behavior Summary

**Plan:** 43-04
**Phase:** 43
**Subsystem:** dlp-agent (DeviceController, UsbDetector, service config access)
**Completed:** 2026-05-08
**Duration:** ~45 minutes

---

## Objective

Wire the actual enforcement behavior changes that make PnP disable "actually work": retry logic in DeviceController, configurable failure mode semantics in apply_blocked_enforcement, (none) serial policy handling, and startup resolution mode. Builds on the config infrastructure from plans 43-02 and 43-03.

---

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add retry logic to DeviceController | (current branch) | dlp-agent/src/device_controller.rs |
| 2 | Add with_config helper to service.rs | (current branch) | dlp-agent/src/service.rs |
| 3 | Wire enforcement behavior into detection/usb.rs | (current branch) | dlp-agent/src/detection/usb.rs |

---

## Key Changes

### dlp-agent/src/device_controller.rs

- Added `disable_usb_device_with_retry_blocking` method:
  - Accepts `retry_count` and `retry_delay_ms` parameters
  - Retries `CM_Disable_DevNode` up to `retry_count` times with specified delay
  - Returns `Ok` on first success, `Err` after all retries exhausted
  - **BLOCKING** documented: uses `std::thread::sleep`, must not be called from async tokio context
- Kept existing `disable_usb_device` unchanged as the primitive
- Added tests:
  - `test_disable_usb_device_with_retry_blocking_zero_retries`
  - `test_disable_usb_device_with_retry_blocking_exhausts_retries`

### dlp-agent/src/service.rs

- Added global `CONFIG` static: `OnceLock<Arc<Mutex<AgentConfig>>>`
- Added `with_config` helper:
  - Executes closure with read-lock on global config
  - Returns `None` if config not yet initialized
  - Used by enforcement functions to read config values once per call
- Set `CONFIG` during `run_loop_init` from `config_arc`
- Added tests:
  - `test_with_config_returns_none_when_uninitialized`
  - `test_with_config_returns_value_when_initialized`

### dlp-agent/src/detection/usb.rs

- Added `decide_enforcement_outcome` pure function:
  - "Hard error": returns `Err` if either PnP or DACL fails
  - "Retry then error": returns `Err` if PnP fails (DACL failure acceptable)
  - "Warning only" (default): always returns `Ok`
  - Fully unit-tested with 7 test cases

- Modified `apply_blocked_enforcement`:
  - Accepts `failure_mode` parameter
  - Determines retry parameters from failure mode ("Retry then error" → 2 retries, 100ms delay)
  - Calls `disable_usb_device_with_retry_blocking` when retry mode is active
  - Calls `decide_enforcement_outcome` for testable failure mode decision
  - Removed old `log_blocked_outcome` function (replaced by pure function)

- Modified `apply_tier_enforcement`:
  - Reads `usb_blocked_failure_mode` and `usb_none_serial_policy` once via `with_config`
  - Passes config values by parameter to avoid repeated mutex acquisitions
  - Logs warning when config fallback occurs

- Modified `resolve_tier_from_registry`:
  - Accepts `none_serial_policy` parameter
  - Forces `Blocked` tier for serial="(none)" when policy is "Always Blocked"
  - Falls through to normal registry lookup for "Allow unregistered"

- Modified `scan_existing_usb_identities`:
  - Reads `usb_startup_resolution_mode` once via `with_config`
  - Logs warning for unimplemented "Volume GUID resolution" mode
  - Falls back to "VID/PID/serial fallback"

- Added tests:
  - `test_decide_enforcement_outcome_hard_error_both_fail`
  - `test_decide_enforcement_outcome_hard_error_pnp_only_fails`
  - `test_decide_enforcement_outcome_hard_error_dacl_only_fails`
  - `test_decide_enforcement_outcome_hard_error_both_succeed`
  - `test_decide_enforcement_outcome_retry_then_error_pnp_fails`
  - `test_decide_enforcement_outcome_retry_then_error_pnp_succeeds`
  - `test_decide_enforcement_outcome_warning_only_mode`
  - `test_resolve_tier_none_serial_always_blocked`
  - `test_resolve_tier_none_serial_allow_unregistered`

---

## Verification Results

- `cargo test -p dlp-agent`: 599 passed, 10 ignored
- `cargo clippy -p dlp-agent -- -D warnings -A clippy::ptr-arg -A clippy::doc_lazy_continuation`: No issues in modified files (pre-existing issues in disk.rs ignored per plan instructions)
- `cargo fmt --check` for modified files: Clean after formatting

---

## Deviations from Plan

None. Plan executed exactly as written.

---

## Auth Gates

None.

---

## Known Stubs

- "Volume GUID resolution" mode is read but falls back to VID/PID/serial (not yet implemented, rejected at config-set time in Plan 43-02).
- "Port-based disambiguation" policy is rejected at config-set time (Plan 43-02).

---

## Threat Flags

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-43-09 | Denial of Service | Retry loop delays enforcement | accept | 3 retries * 100ms = 300ms max delay; acceptable for USB hot-plug. Method is blocking and documented as such. |
| T-43-10 | Elevation of Privilege | "Allow unregistered" for (none) serial bypasses Blocked | mitigate | Default is "Always Blocked"; operator must explicitly select "Allow unregistered". Unimplemented modes rejected at config-set time. |
| T-43-11 | Information Disclosure | Failure mode logged at info level | accept | Logs field name only, not sensitive data |

---

## Self-Check: PASSED

- [x] `disable_usb_device_with_retry_blocking` exists with retry_count and retry_delay_ms parameters
- [x] Method name includes `_blocking` suffix; doc comment warns against async usage
- [x] `with_config` helper exists in service.rs for read-only config access
- [x] `apply_blocked_enforcement` accepts failure_mode parameter
- [x] `decide_enforcement_outcome` is a pure function for testability
- [x] `resolve_tier_from_registry` accepts none_serial_policy parameter
- [x] `scan_existing_usb_identities` reads startup resolution mode
- [x] Config values are passed by parameter, not read from global mutex inside enforcement functions
- [x] Warning logged when config is unavailable and fallback default is used
- [x] All tests pass
- [x] Clippy clean (modified files)
- [x] Format clean (modified files)
