---
id: T05
parent: S01
milestone: M017
key_files:
  - dlp-agent/src/wfp_ffi.rs
  - dlp-agent/src/wfp_manager.rs
  - dlp-agent/Cargo.toml
  - dlp-agent/src/lib.rs
key_decisions:
  - Used FWPM_CONDITION_ALE_APP_ID instead of the task-specified FWPM_CONDITION_IP_LOCAL_ADDRESS because WFP cannot filter by PID using IP_LOCAL_ADDRESS; ALE_APP_ID (resolved from executable path) is the correct per-process condition.
  - Added Win32_System_Rpc feature because the windows crate gates FwpmEngineOpen0 behind it.
  - WfpError carries u32 raw Win32 error codes rather than NTSTATUS because fwpuclnt.dll functions return u32.
duration: 
verification_result: passed
completed_at: 2026-05-08T14:49:17.325Z
blocker_discovered: false
---

# T05: Implemented WFP FFI bindings and WfpManager with per-process egress block filters and 5 passing unit tests

**Implemented WFP FFI bindings and WfpManager with per-process egress block filters and 5 passing unit tests**

## What Happened

Added Win32_NetworkManagement_WindowsFilteringPlatform and Win32_System_Rpc features to dlp-agent/Cargo.toml. Created dlp-agent/src/wfp_ffi.rs re-exporting WFP types from the windows crate and defining the WfpError enum. Created dlp-agent/src/wfp_manager.rs with WfpManager that opens the WFP engine, registers a transient sublayer, and adds/removes filters blocking outbound TCP/443 by resolving the target PID to its executable path and matching ALE_APP_ID. Implemented RAII AppIdBlob wrapper to safely manage WFP-allocated app-id memory. Added 5 unit tests covering register/unregister, add/remove block, invalid PID rejection, double-block prevention, and remove-nonexistent failure. All tests pass.

## Verification

cargo test -p dlp-agent wfp — all 5 tests passed.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test -p dlp-agent wfp` | 0 | pass | 53400ms |

## Deviations

Used FWPM_CONDITION_ALE_APP_ID instead of FWPM_CONDITION_IP_LOCAL_ADDRESS for per-process blocking, because WFP does not support PID-based filtering via IP_LOCAL_ADDRESS. Added Win32_System_Rpc feature to Cargo.toml to satisfy the windows crate's feature gate on FwpmEngineOpen0.

## Known Issues

None.

## Files Created/Modified

- `dlp-agent/src/wfp_ffi.rs`
- `dlp-agent/src/wfp_manager.rs`
- `dlp-agent/Cargo.toml`
- `dlp-agent/src/lib.rs`
