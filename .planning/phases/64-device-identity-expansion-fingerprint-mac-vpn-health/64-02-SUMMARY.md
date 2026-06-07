---
phase: 64-device-identity-expansion-fingerprint-mac-vpn-health
plan: 02
subsystem: agent
tags: [windows-api, registry, sha256, fingerprint, mac-address, vpn, domain-join]

requires:
  - phase: 64-device-identity-expansion-fingerprint-mac-vpn-health
    plan: 01
    provides: EndpointIdentity struct, DeviceHealthStatus enum, DeviceHealth PolicyCondition variant

provides:
  - Agent-side MAC address collection via GetAdaptersAddresses
  - VPN detection via IF_TYPE_TUNNEL + keyword heuristics
  - Domain join detection via NetGetJoinInformation
  - Stable OS version string from registry (CurrentMajor/Minor/Build)
  - SHA-256 device fingerprint with v1: prefix and sorted MACs
  - Registry persistence for fingerprint at HKLM\SOFTWARE\DLP\Agent
  - build_endpoint_identity() composing all fields into EndpointIdentity

affects:
  - dlp-server policy_store (DeviceHealth condition matching)
  - All agent Subject constructors (device_health field)

tech-stack:
  added: []
  patterns:
    - "Two-call GetAdaptersAddresses pattern: size probe + alloc + fill"
    - "Registry read/write with wide strings and raw Windows APIs"
    - "#[cfg(windows)] / #[cfg(not(windows))] gating for cross-platform tests"

key-files:
  created:
    - dlp-agent/src/device_identity.rs - MAC collection, VPN detection, domain join, fingerprint computation, registry I/O
  modified:
    - dlp-agent/src/lib.rs - Added pub mod device_identity
    - dlp-agent/Cargo.toml - Added Win32_NetworkManagement_IpHelper, NetManagement, WinSock, Ndis features
    - dlp-server/src/policy_store.rs - Added DeviceHealth match arm in condition_matches
    - dlp-agent/src/identity.rs - Added device_health to Subject constructors
    - dlp-agent/src/interception/mod.rs - Added device_health to Subject constructor
    - dlp-agent/src/interception/drag_drop.rs - Added device_health to Subject constructor
    - dlp-agent/src/offline.rs - Added device_health to Subject constructors
    - dlp-agent/src/print_watcher.rs - Added device_health to Subject constructor
    - dlp-agent/src/chrome/handler.rs - Added device_health to Subject constructor

key-decisions:
  - "IF_TYPE_TUNNEL constant (131) used inline with comment instead of importing from Ndis module, since Ndis feature does not export IF_TYPE_TUNNEL in windows 0.62"
  - "NetGetJoinInformation return value checked with != 0 instead of .is_err(), since it returns u32 not WIN32_ERROR in windows 0.62"
  - "RegSetValueExW called with Option<&[u8]> per windows 0.62 signature, not pointer+size separately"
  - "collect_mac_addresses test adapted for Windows runner (real MACs returned) vs non-Windows stub"

patterns-established:
  - "Registry helpers read_reg_string/read_reg_dword as private #[cfg(windows)] functions shared across module"
  - "Fingerprint computation as pure function (no cfg gating) for deterministic testability"

requirements-completed:
  - DEVICE-01
  - DEVICE-02
  - DEVICE-03
  - DEVICE-04

# Metrics
duration: 45min
completed: 2026-06-07
---

# Phase 64 Plan 02: Agent-side device identity collection

**MAC address collection, VPN detection, domain join check, stable fingerprint computation, and registry persistence in dlp-agent**

## Performance

- **Duration:** 45 min
- **Started:** 2026-06-07T01:00:00Z
- **Completed:** 2026-06-07T01:45:00Z
- **Tasks:** 3
- **Files modified:** 10

## Accomplishments

- Created `dlp-agent/src/device_identity.rs` with 8 public functions and 2 private registry helpers
- MAC collection uses `GetAdaptersAddresses` two-call pattern with `OperStatusUp` filter and uppercase no-colon normalization
- VPN detection combines `IF_TYPE_TUNNEL` (131) with 11 documented keyword heuristics
- Domain join detection wraps `NetGetJoinInformation` with proper `NetApiBufferFree`
- Fingerprint uses SHA-256 of `v1:hostname|sorted_MACs|os_version|install_date` with `v1:` prefix in returned value
- Registry I/O reads/writes `device_fingerprint` to `HKLM\SOFTWARE\DLP\Agent` as REG_SZ
- `build_endpoint_identity()` composes all subfunctions into a fully populated `EndpointIdentity`
- Added `DeviceHealth` match arm to `dlp-server` policy store condition evaluation
- Added `device_health` field to all 7 agent `Subject` constructors for compilation compatibility

## Task Commits

All tasks committed as a single commit (plan is small and cohesive):

1. **Task 1-3: Device identity module with MAC, VPN, domain, fingerprint, registry, tests** - `f65fede` (feat)

## Files Created/Modified

- `dlp-agent/src/device_identity.rs` (new) - Full module: MAC collection, VPN detection, domain join, OS version, install date, fingerprint computation, registry I/O, build_endpoint_identity, 13 tests
- `dlp-agent/src/lib.rs` - Added `pub mod device_identity;`
- `dlp-agent/Cargo.toml` - Added Windows features: IpHelper, NetManagement, WinSock, Ndis
- `dlp-server/src/policy_store.rs` - Added `DeviceHealth` match arm in `condition_matches()`
- `dlp-agent/src/identity.rs` - Added `device_health` to two `Subject` constructors
- `dlp-agent/src/interception/mod.rs` - Added `device_health` to `Subject` constructor
- `dlp-agent/src/interception/drag_drop.rs` - Added `device_health` to `Subject` constructor
- `dlp-agent/src/offline.rs` - Added `device_health` to two `Subject` constructors
- `dlp-agent/src/print_watcher.rs` - Added `device_health` to `Subject` constructor
- `dlp-agent/src/chrome/handler.rs` - Added `device_health` to `Subject` constructor

## Decisions Made

- Used inline `131u32` for `IF_TYPE_TUNNEL` because the `Win32_NetworkManagement_Ndis` feature in windows 0.62 does not export `IF_TYPE_TUNNEL` (it lives in `IpHelper` module but importing it from there created a naming conflict). The constant value is well-documented in MSDN.
- Checked `NetGetJoinInformation` result with `!= 0` rather than `.is_err()` because the windows 0.62 binding returns `u32` directly, not `WIN32_ERROR`.
- Used `Option<&[u8]>` for `RegSetValueExW` data parameter per the windows 0.62 signature (which takes 5 args, not 6).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed IF_TYPE_TUNNEL import path**
- **Found during:** Task 1 (VPN detection implementation)
- **Issue:** `windows::Win32::NetworkManagement::Ndis::IF_TYPE_TUNNEL` does not exist in windows 0.62; the constant is in `IpHelper` module but importing it there created a naming conflict with the `Ndis` feature gate
- **Fix:** Used inline `131u32` with a doc comment `// IF_TYPE_TUNNEL` instead of importing the constant
- **Files modified:** `dlp-agent/src/device_identity.rs`
- **Verification:** `cargo build -p dlp-agent` compiles with zero errors

**2. [Rule 1 - Bug] Fixed NetGetJoinInformation result checking**
- **Found during:** Task 1 (domain join implementation)
- **Issue:** Called `.is_err()` on `NetGetJoinInformation` return value, but windows 0.62 binding returns `u32`, not `WIN32_ERROR`
- **Fix:** Changed `result.is_err()` to `result != 0`
- **Files modified:** `dlp-agent/src/device_identity.rs`
- **Verification:** `cargo build -p dlp-agent` compiles with zero errors

**3. [Rule 1 - Bug] Fixed RegSetValueExW signature mismatch**
- **Found during:** Task 2 (registry write implementation)
- **Issue:** Passed 6 arguments to `RegSetValueExW` (including separate size arg), but windows 0.62 binding takes 5 arguments with `Option<&[u8]>` for data
- **Fix:** Constructed `&[u8]` slice from wide string bytes and passed as `Some(wide_bytes)`
- **Files modified:** `dlp-agent/src/device_identity.rs`
- **Verification:** `cargo build -p dlp-agent` compiles with zero errors

**4. [Rule 2 - Missing Critical] Added DeviceHealth policy condition matching in dlp-server**
- **Found during:** Task 1 (compilation verification)
- **Issue:** Adding `DeviceHealth` variant to `PolicyCondition` in dlp-common caused non-exhaustive pattern match error in `dlp-server/src/policy_store.rs`
- **Fix:** Added `PolicyCondition::DeviceHealth { op, value }` match arm that calls `compare_op(op, &ctx.subject.device_health, value)`
- **Files modified:** `dlp-server/src/policy_store.rs`
- **Verification:** Full workspace compiles

**5. [Rule 2 - Missing Critical] Added device_health field to all Subject constructors**
- **Found during:** Task 1 (compilation verification)
- **Issue:** Adding `device_health: DeviceHealthStatus` field to `Subject` struct in dlp-common broke compilation in 7 agent files that construct `Subject` directly
- **Fix:** Added `device_health: dlp_common::DeviceHealthStatus::default()` to all 7 `Subject` constructor sites across the agent
- **Files modified:** `dlp-agent/src/identity.rs`, `interception/mod.rs`, `interception/drag_drop.rs`, `offline.rs`, `print_watcher.rs`, `chrome/handler.rs`
- **Verification:** `cargo build -p dlp-agent` compiles with zero errors

**6. [Rule 1 - Bug] Fixed collect_mac_addresses test for Windows runner**
- **Found during:** Task 3 (test execution)
- **Issue:** Test asserted stub MAC value `000000000000`, but on Windows runner `collect_mac_addresses()` returns real MAC addresses
- **Fix:** Changed test to verify format contract (uppercase hex, no separators) rather than exact stub value
- **Files modified:** `dlp-agent/src/device_identity.rs`
- **Verification:** `cargo test -p dlp-agent --lib device_identity` passes

---

**Total deviations:** 6 auto-fixed (4 Rule 1 bugs, 2 Rule 2 missing critical)
**Impact on plan:** All auto-fixes necessary for compilation correctness and cross-crate compatibility. No scope creep.

## Issues Encountered

- Windows crate API signatures differed from plan assumptions (return types, argument counts). Resolved by checking actual generated bindings in `.cargo/registry`.
- Plan 01 types (`EndpointIdentity`, `DeviceHealthStatus`) were already present in `dlp-common` from prior execution, but `dlp-common/src/lib.rs` re-exports were correct.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Device identity collection module is complete and tested
- Ready for Plan 03 (heartbeat integration) which will call `build_endpoint_identity()`
- Ready for Plan 04 (ABAC evaluation + health state machine) which will use `DeviceHealthStatus` in policy conditions

---
*Phase: 64-device-identity-expansion-fingerprint-mac-vpn-health*
*Completed: 2026-06-07*
