---
phase: 31
plan: "01"
subsystem: usb-enforcement
tags: [rust, windows, usb, cfgmgr32, dacl, pnp]

requires:
  - phase: 26-abac-enforcement-convergence
    plan: "04"
  - phase: 26-abac-enforcement-convergence
    plan: "05"
  - phase: 27
    plan: "01"
  - phase: 23
    plan: "02"

provides:
  - dlp-agent/src/device_controller.rs - CM_Disable_DevNode / CM_Enable_DevNode / DACL manipulation
  - Active USB I/O blocking at the PnP level (not passive observation)
  - ReadOnly enforcement via volume DACL modification
  - Toast notification startup check (warn when UI binary missing)

affects:
  - dlp-agent/src/detection/usb.rs
  - dlp-agent/src/usb_enforcer.rs
  - dlp-agent/src/service.rs
  - dlp-agent/build.rs

tech-stack:
  added:
    - cfgmgr32.lib (Windows Configuration Manager)
    - advapi32.lib (ACL manipulation)
  patterns:
    - "DeviceController: singleton wrapping CM_* APIs and in-memory DACL cache"
    - "Fail-safe: CM_Locate_DevNode failure = log warning, do NOT panic"
    - "DACL backup keyed by drive letter (char) in parking_lot::Mutex<HashMap>"

key-files:
  created:
    - dlp-agent/src/device_controller.rs
  modified:
    - dlp-agent/src/detection/usb.rs
    - dlp-agent/src/usb_enforcer.rs
    - dlp-agent/src/service.rs
    - dlp-agent/src/device_registry.rs
    - dlp-agent/build.rs
    - dlp-agent/src/lib.rs

key-decisions:
  - "Device controller fires from usb_wndproc (not from interception event loop) — this is where the OS tells us about device arrival/removal"
  - "Blocked tier: disable device immediately on arrival, no need to wait for file events"
  - "ReadOnly tier: modify volume DACL on arrival; restore on removal"
  - "UsbEnforcer::check() simplified to return None for all registered devices (Blocked/ReadOnly/FullAccess) — unregistered devices still default-deny at I/O level as defence-in-depth"
  - "DeviceRegistryCache::has_device() added to distinguish registered vs unregistered devices"
  - "UI binary check is a WARN log + early return, NOT a fatal error — agent runs without UI if binary missing"

requirements-completed:
  - USB-03 (real blocking, not just audit)
  - USB-04 (toast notification — prerequisite: UI binary exists)
---

# Phase 31 Plan 01: USB CM Device Blocking Summary

**Active PnP-level USB enforcement replacing passive file-I/O-based blocking. DeviceController disables Blocked-tier USB devices via CM_Disable_DevNode and modifies volume DACLs for ReadOnly tier. UsbEnforcer simplified to defence-in-depth fallback for unregistered devices only.**

## Tasks Completed

| Task | Description | Commit |
|------|-------------|--------|
| 1 | Create `device_controller.rs` with CM_* APIs and DACL manipulation | 0a380e0 |
| 2 | Wire device controller into `usb_wndproc` arrival/removal handlers | f8b9750 |
| 3 | Simplify `UsbEnforcer::check()` — remove active blocking, keep fallback | b09664b |
| 4 | Add UI binary missing startup warning in service and console mode | 19542a7 |
| 5 | Link `cfgmgr32.lib` and `advapi32.lib` in `build.rs` | 9e29546 |
| 6 | Integration verification — all lib tests pass, clippy clean, fmt clean | 9349c54 |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 — Bug] UsbEnforcer::check() returned None for unregistered devices too**
- **Found during:** Task 3
- **Issue:** The plan said `Blocked => None` and `ReadOnly => None`, but `trust_tier_for` returns `Blocked` for unregistered devices (default-deny). This would have caused unregistered devices to fall through to ABAC instead of being denied.
- **Fix:** Added `DeviceRegistryCache::has_device()` to distinguish "registered as Blocked" (handled by DeviceController) from "unregistered" (default-deny at I/O level). `UsbEnforcer::check()` now returns `None` only for registered devices, and `Some(DENY)` for unregistered devices.
- **Files modified:** `dlp-agent/src/device_registry.rs`, `dlp-agent/src/usb_enforcer.rs`
- **Commit:** b09664b

**2. [Rule 1 — Bug] Windows API type mismatches in device_controller.rs**
- **Found during:** Task 1
- **Issue:** Multiple Windows crate API signature mismatches: `CONFIGRET` vs `u32`, `GetFileSecurityW` takes `PCWSTR` not `HANDLE`, `DACL_SECURITY_INFORMATION` is `OBJECT_SECURITY_INFORMATION`, `PSECURITY_DESCRIPTOR` needs `*mut c_void`, `LocalFree` takes `HLOCAL` not `Option<HLOCAL>`.
- **Fix:** Rewrote volume ACL functions to use path-based APIs (`GetFileSecurityW`/`SetFileSecurityW` with `PCWSTR`) instead of handle-based, used `.0` to extract raw values from newtype wrappers, cast pointers to `*mut c_void`.
- **Files modified:** `dlp-agent/src/device_controller.rs`
- **Commit:** 0a380e0 (amended in place before first commit)

## Known Stubs

None — all functionality is wired to real data sources.

## Threat Flags

None — no new network endpoints, auth paths, or file access patterns introduced.

## Verification Results

- `cargo build -p dlp-agent`: PASS (0 warnings)
- `cargo test -p dlp-agent --lib`: PASS (209 tests)
- `cargo clippy -p dlp-agent -- -D warnings`: PASS (0 issues)
- `cargo fmt -p dlp-agent --check`: PASS

## Self-Check: PASSED

- [x] `dlp-agent/src/device_controller.rs` exists
- [x] `dlp-agent/src/detection/usb.rs` modified (DEVICE_CONTROLLER, set_device_controller)
- [x] `dlp-agent/src/usb_enforcer.rs` modified (simplified check, has_device usage)
- [x] `dlp-agent/src/service.rs` modified (UI binary warning, DeviceController init)
- [x] `dlp-agent/src/device_registry.rs` modified (has_device method)
- [x] `dlp-agent/build.rs` modified (cfgmgr32, advapi32 linkage)
- [x] `dlp-agent/src/lib.rs` modified (device_controller module)
- [x] All commits exist in git log
