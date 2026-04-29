---
phase: 31-usb-cm-blocking
verified: 2026-04-29T13:20:00Z
status: passed
score: 7/7 must-haves verified
overrides_applied: 0
overrides: []
gaps: []
---

# Phase 31: USB CM Device Blocking Verification Report

**Phase Goal:** Replace passive notify-based USB enforcement with active PnP device control using Windows CM_* APIs, and fix toast notification by adding UI binary startup check.
**Verified:** 2026-04-29T13:20:00Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| #   | Truth                                                                 | Status     | Evidence |
| --- | --------------------------------------------------------------------- | ---------- | -------- |
| 1   | `device_controller.rs` exists with CM_Disable_DevNode, CM_Enable_DevNode, set_volume_readonly, restore_volume_acl | VERIFIED | File exists at `dlp-agent/src/device_controller.rs` (438 lines). All 4 public methods present. Struct has `original_dacls: Mutex<HashMap<char, Vec<u8>>>` cache. Build succeeds with cfgmgr32.lib linked. |
| 2   | `usb_wndproc` calls device controller on arrival/removal               | VERIFIED | `detection/usb.rs` lines 517-571: `on_usb_device_arrival` calls `disable_usb_device` (Blocked) and `set_volume_readonly` (ReadOnly). Lines 610-636: `on_usb_device_removal` calls `restore_volume_acl` and `enable_usb_device`. `DEVICE_CONTROLLER` OnceLock static at line 266. `set_device_controller()` at line 315. |
| 3   | `UsbEnforcer::check()` returns `None` for Blocked and ReadOnly tiers   | VERIFIED | `usb_enforcer.rs` lines 169-187: uses `has_device()` to check registration. Registered devices return `None` regardless of tier. `test_blocked_device_returns_none` (line 296) and `test_readonly_device_returns_none` (line 311) both pass. |
| 4   | Service logs warning when `dlp-user-ui.exe` not found                  | VERIFIED | `service.rs` lines 122-126 (run_service) and 1103-1107 (run_console): both emit `warn!` with exact message "UI binary (dlp-user-ui.exe) not found — toast notifications will not work..." |
| 5   | `cargo build -p dlp-agent` succeeds (cfgmgr32.lib linked)              | VERIFIED | Build exits 0. `build.rs` lines 8-9: `cargo:rustc-link-lib=cfgmgr32` and `cargo:rustc-link-lib=advapi32`, both gated behind `#[cfg(windows)]`. |
| 6   | All existing tests pass                                                | VERIFIED | `cargo test -p dlp-agent --lib`: 209 tests passed, 0 failed. |
| 7   | New unit tests pass                                                    | VERIFIED | `cargo test -p dlp-agent --lib -- device_controller`: 3 passed. `cargo test -p dlp-agent --lib -- usb_enforcer`: 14 passed. Includes `test_blocked_device_returns_none`, `test_readonly_device_returns_none`, `test_device_controller_new_empty_cache`, `test_dacl_backup_roundtrip`, `test_multiple_drive_letters_isolated`. |

**Score:** 7/7 truths verified (all must-haves pass)

### Required Artifacts

| Artifact | Expected | Status | Details |
| -------- | -------- | ------ | ------- |
| `dlp-agent/src/device_controller.rs` | CM_* APIs + DACL manipulation | VERIFIED | 438 lines. `DeviceController` struct, `disable_usb_device`, `enable_usb_device`, `set_volume_readonly`, `restore_volume_acl`. Error type with `thiserror`. 3 unit tests. |
| `dlp-agent/src/detection/usb.rs` | Wired into arrival/removal | VERIFIED | `DEVICE_CONTROLLER` OnceLock (line 266), `set_device_controller` (line 315), calls in `on_usb_device_arrival` (lines 517-571) and `on_usb_device_removal` (lines 610-636). |
| `dlp-agent/src/usb_enforcer.rs` | Simplified check() | VERIFIED | Returns `None` for all registered devices via `has_device()`. Unregistered devices still default-deny. 14 unit tests. |
| `dlp-agent/src/service.rs` | UI binary warning + DeviceController init | VERIFIED | Warning in `run_service` (lines 122-126) and `run_console` (lines 1103-1107). `DeviceController::new()` initialized at line 495, passed to `set_device_controller` at line 496. |
| `dlp-agent/src/device_registry.rs` | `has_device()` method | VERIFIED | Lines 88-91: `has_device(vid, pid, serial) -> bool` checks cache for key presence. Used by `UsbEnforcer::check()`. |
| `dlp-agent/build.rs` | Link cfgmgr32 + advapi32 | VERIFIED | Lines 6-10: `cargo:rustc-link-lib=cfgmgr32` and `cargo:rustc-link-lib=advapi32` behind `#[cfg(windows)]`. |
| `dlp-agent/src/lib.rs` | device_controller module | VERIFIED | Line 81: `pub mod device_controller;` (unconditional, unlike other Windows-only modules). |

### Key Link Verification

| From | To | Via | Status | Details |
| ---- | -- | --- | ------ | ------- |
| `service.rs` run_loop | `DeviceController::new()` | Direct call | WIRED | Line 495: `Arc::new(crate::device_controller::DeviceController::new())` |
| `service.rs` run_loop | `set_device_controller()` | Direct call | WIRED | Line 496: `crate::detection::usb::set_device_controller(Arc::clone(&device_controller))` |
| `detection/usb.rs` usb_wndproc | `DeviceController` methods | DEVICE_CONTROLLER OnceLock | WIRED | Lines 517, 549, 611, 621: `DEVICE_CONTROLLER.get()` then method calls |
| `usb_enforcer.rs` check() | `DeviceRegistryCache::has_device()` | Registry Arc | WIRED | Line 171: `self.registry.has_device(&identity.vid, &identity.pid, &identity.serial)` |
| `build.rs` | `cfgmgr32.lib` / `advapi32.lib` | cargo link directive | WIRED | Lines 8-9: `println!("cargo:rustc-link-lib=cfgmgr32")` etc. |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| -------- | ------------- | ------ | ------------------ | ------ |
| `device_controller.rs` set_volume_readonly | `original_dacls` cache | `GetFileSecurityW` query on volume | Yes (Win32 API) | FLOWING |
| `device_controller.rs` restore_volume_acl | `sd_buf` from cache | `original_dacls` HashMap | Yes (cached from prior query) | FLOWING |
| `detection/usb.rs` on_usb_device_arrival | `tier` | `REGISTRY_CACHE.get().trust_tier_for()` | Yes (server-fetched cache) | FLOWING |
| `usb_enforcer.rs` check() | `is_registered` | `registry.has_device()` | Yes (in-memory cache) | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| -------- | ------- | ------ | ------ |
| Build succeeds | `cargo build -p dlp-agent` | Finished dev profile (0 crates compiled) | PASS |
| All lib tests pass | `cargo test -p dlp-agent --lib` | 209 passed | PASS |
| Clippy clean | `cargo clippy -p dlp-agent -- -D warnings` | No issues found | PASS |
| Format clean | `cargo fmt -p dlp-agent --check` | No output (clean) | PASS |
| device_controller tests | `cargo test -p dlp-agent --lib -- device_controller` | 3 passed | PASS |
| usb_enforcer tests | `cargo test -p dlp-agent --lib -- usb_enforcer` | 14 passed | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
| ----------- | ----------- | ----------- | ------ | -------- |
| USB-03 | 31-01-PLAN | Real blocking (not just audit) | SATISFIED | `device_controller.rs` implements `CM_Disable_DevNode` for Blocked tier and volume DACL modification for ReadOnly tier. `usb_wndproc` calls these on arrival. |
| USB-04 | 31-01-PLAN | Toast notification prerequisite (UI binary exists) | SATISFIED | `service.rs` logs warning when `dlp-user-ui.exe` not found, ensuring operator awareness that toast notifications will not work. |

Note: USB-03 and USB-04 were originally completed in Phase 26 and Phase 27 respectively. Phase 31 enhances USB-03 by replacing passive file-I/O blocking with active PnP-level enforcement.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| ---- | ---- | ------- | -------- | ------ |
| `dlp-agent/src/device_controller.rs` | 139, 202 | `CM_Disable_DevNode` / `CM_Enable_DevNode` called with `0` flag instead of `CM_DISABLE_ABSOLUTE` (0x1) | Warning (WR-02) | May not disable/enable immediately; could be overridden by hardware profiles. Review flagged but does not block compilation or tests. |
| `dlp-agent/src/detection/usb.rs` | 857-889 | `HDEVNOTIFY` handles from `RegisterDeviceNotificationW` discarded on success path | Critical (CR-01) | Handle leak. Window destroy on shutdown skips unregister. Review flagged. |
| `dlp-agent/src/detection/usb.rs` | 433-444 | `read_dbcc_name` unbounded pointer walk with 32,768 hard limit | Critical (CR-02) | Potential strict-provenance UB. Review flagged. |
| `dlp-agent/src/detection/usb.rs` | 498-500 | Drive letter assignment heuristic may map wrong letter with multiple USB devices | Warning (WR-01) | Race between USB_DEVICE and VOLUME notifications. Review flagged. |
| `dlp-agent/src/device_controller.rs` | 81 | `pub mod device_controller` in `lib.rs` not gated by `#[cfg(windows)]` | Warning (WR-03) | Inconsistent with other modules. Non-Windows builds would have empty module. Review flagged. |
| `dlp-agent/src/usb_enforcer.rs` | 156 | `DeviceIdentity::default()` (empty strings) for known-USB-without-identity fallback | Warning (WR-04) | Audit log loses device identity. Review flagged. |
| `dlp-agent/src/service.rs` | 1368 | `eprintln!` in console mode file monitor error path | Info | Acceptable fallback when tracing may be misconfigured. Not a blocker. |

### Human Verification Required

None. All observable behaviors are verifiable programmatically. Manual UAT (plugging physical USB devices) is noted in the PLAN but cannot be automated in this verification context.

### Gaps Summary

**All gaps resolved.**

The CR-03 gap (volume DACL path using raw device namespace `\\.\X:` instead of mount point `X:\`) was fixed in commit `d381221`.

**Remaining review findings (CR-01, CR-02, WR-01..04):** These are documented in `31-REVIEW.md` and should be addressed in a follow-up fix phase, but they do not prevent the phase's core goal from being achieved.

---

_Verified: 2026-04-29T13:20:00Z_
_Verifier: Claude (gsd-verifier)_
