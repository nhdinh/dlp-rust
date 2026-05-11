---
phase: 43
plan: 01
subsystem: dlp-common/usb
phase_name: pnp-disable-fix
tags: [usb, setupdi, exact-match, windows]
dependency_graph:
  requires: []
  provides: [USB-07, USB-08]
  affects: [dlp-agent/usb-event-handling, dlp-admin-cli/usb-scan]
tech_stack:
  added: []
  patterns:
    - "SetupDiEnumDeviceInterfaces + SetupDiGetDeviceInterfaceDetailW exact path matching"
    - "Two-tier match: exact path primary, VID+PID+serial fallback"
    - "Case-insensitive ASCII path comparison (eq_ignore_ascii_case)"
key_files:
  created: []
  modified:
    - dlp-common/src/usb.rs
decisions:
  - "Split setupdi_description_for_device into two internal helpers: setupdi_description_by_exact_path (primary) and setupdi_description_by_vid_pid_serial (fallback) for clarity and testability"
  - "Extracted get_device_interface_path_and_devinfo helper to share the SetupDiGetDeviceInterfaceDetailW pattern from disk.rs while also capturing SP_DEVINFO_DATA for property reading"
  - "Preserved the existing safety valve (index > 1024) in both enumeration paths to prevent runaway loops"
  - "Used eq_ignore_ascii_case for path comparison to handle Windows path casing differences (e.g., USB#VID_0781 vs USB#vid_0781)"
metrics:
  duration: "~5 minutes"
  completed_date: "2026-05-07"
---

# Phase 43 Plan 01: Exact Path Matching for SetupDi Description Lookup

## One-liner

Refactored `setupdi_description_for_device` to use exact device interface path matching via `SetupDiGetDeviceInterfaceDetailW` as the primary strategy, with VID+PID+serial fallback for startup scan compatibility.

## What Changed

### `dlp-common/src/usb.rs`

1. **Added imports** (lines 13-16):
   - `SetupDiEnumDeviceInterfaces`
   - `SetupDiGetDeviceInterfaceDetailW`
   - `SP_DEVICE_INTERFACE_DATA`
   - `SP_DEVICE_INTERFACE_DETAIL_DATA_W`

2. **Rewrote `setupdi_description_for_device`** (lines 121-129):
   - Now a thin orchestrator that tries exact-path matching first, then falls back to VID+PID+serial matching.
   - Returns the first non-empty description found, or an empty string if no match.

3. **Added `setupdi_description_by_exact_path`** (lines 137-200):
   - Enumerates `GUID_DEVINTERFACE_USB_DEVICE` interfaces using `SetupDiEnumDeviceInterfaces`.
   - For each interface, calls `SetupDiGetDeviceInterfaceDetailW` to get the actual device path.
   - Compares the returned path to `device_path` using `eq_ignore_ascii_case` (case-insensitive).
   - On match, reads `SPDRP_FRIENDLYNAME` / `SPDRP_DEVICEDESC` via `read_string_property`.
   - Includes safety valve `index > 1024` to prevent infinite loops.

4. **Added `setupdi_description_by_vid_pid_serial`** (lines 208-284):
   - Extracted the original VID+PID+serial matching logic into a dedicated fallback function.
   - Preserves all existing behavior for the startup scan path where only VID/PID/serial are known.

5. **Added `get_device_interface_path_and_devinfo`** (lines 294-357):
   - Reusable helper that calls `SetupDiGetDeviceInterfaceDetailW` (size probe + detail fetch).
   - Returns both the device path string and the associated `SP_DEVINFO_DATA` for property reading.
   - Follows the proven pattern from `disk.rs:705-756`.

6. **Updated tests** (lines 896-918):
   - `test_setupdi_description_exact_path_no_crash` (Windows-only): Verifies the function does not panic on a nonexistent path and returns an empty string.
   - `test_setupdi_description_signature_compiles` (non-Windows): Compile-time signature check asserting `fn(&str) -> String`.

## Deviations from Plan

None -- plan executed exactly as written.

## Verification Results

| Check | Command | Result |
|-------|---------|--------|
| Tests | `cargo test -p dlp-common` | 144 passed (3 suites) |
| Clippy | `cargo clippy -p dlp-common -- -D warnings` | No issues |
| Format | `cargo fmt --check -p dlp-common` | Clean |

## Threat Model Compliance

| Threat ID | Disposition | Verification |
|-----------|-------------|--------------|
| T-43-01 (Tampering) | mitigate | `device_path` is from trusted `WM_DEVICECHANGE` callback; prefix validation in `resolve_instance_id_from_dbcc_name` |
| T-43-02 (DoS) | mitigate | Safety valve `index > 1024` in both enumeration paths; buffer size validated before allocation |

## Auth Gates

None.

## Known Stubs

None.

## Self-Check: PASSED

- [x] `dlp-common/src/usb.rs` modified as specified
- [x] All imports added (`SetupDiEnumDeviceInterfaces`, `SetupDiGetDeviceInterfaceDetailW`, `SP_DEVICE_INTERFACE_DATA`, `SP_DEVICE_INTERFACE_DETAIL_DATA_W`)
- [x] `setupdi_description_for_device` uses exact path matching with `eq_ignore_ascii_case`
- [x] VID+PID+serial fallback preserved in `setupdi_description_by_vid_pid_serial`
- [x] Safety valve `index > 1024` present in both enumeration paths
- [x] Tests `test_setupdi_description_exact_path_no_crash` and `test_setupdi_description_signature_compiles` exist and pass
- [x] All existing dlp-common tests pass (144/144)
- [x] Clippy passes with `-D warnings`
- [x] `cargo fmt --check` passes
