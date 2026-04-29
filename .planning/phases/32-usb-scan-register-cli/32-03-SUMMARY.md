---
phase: 32-usb-scan-register-cli
plan: 03
status: complete
completed: "2026-04-29"
---

# Plan 32-03 Summary: Dispatch Wiring and Concurrent USB Scan

## What Was Built

Wired the full event-handling and concurrent-scan logic for `Screen::UsbScan`, completing Phase 32.

## Files Modified

| File | Lines | Change |
|------|-------|--------|
| `dlp-admin-cli/Cargo.toml` | 54-55 | Added `wiremock = "0.6` dev-dependency |
| `dlp-admin-cli/src/screens/dispatch.rs` | 8 | Added `UsbScanEntry` to imports |
| `dlp-admin-cli/src/screens/dispatch.rs` | 49 | Added `Screen::UsbScan { .. } => handle_usb_scan(app, key)` arm |
| `dlp-admin-cli/src/screens/dispatch.rs` | 3563-3581 | Updated `handle_devices_menu`: nav count 2->3, idx-2 -> `action_open_usb_scan` |
| `dlp-admin-cli/src/screens/dispatch.rs` | 3618-3631 | Added `action_open_usb_scan` helper |
| `dlp-admin-cli/src/screens/dispatch.rs` | 3633-3708 | Added `build_registry_map`, `merge_registry_with_usb`, `format_usb_scan_status` |
| `dlp-admin-cli/src/screens/dispatch.rs` | 3708-3744 | Added `action_usb_scan` with `tokio::join!` concurrent scan |
| `dlp-admin-cli/src/screens/dispatch.rs` | 3746-3809 | Added `handle_usb_scan` key handler |
| `dlp-admin-cli/src/screens/dispatch.rs` | 3870-3925 | Updated `handle_device_tier_picker` to branch on `TierPickerCaller` |
| `dlp-admin-cli/src/screens/dispatch.rs` | 4758-4817 | Added 5 usb_scan_dispatch_tests |
| `dlp-admin-cli/src/screens/dispatch.rs` | 4819-4876 | Added 7 usb_scan_merge_tests |
| `dlp-admin-cli/src/screens/dispatch.rs` | 4878-4976 | Added 4 usb_scan_routing_tests (wiremock-driven) |

## Key Decisions

- **Concurrent scan architecture**: `tokio::join!` of `client.get` + `tokio::task::spawn_blocking(enumerate_connected_usb_devices)`. `EngineClient` is Arc-backed so clone is O(1).
- **Error handling**: HTTP errors show Error status but USB devices still display (unregistered). `JoinError` from spawn_blocking returns empty Vec (doesn't crash TUI).
- **Post-registration routing (D-03)**: `TierPickerCaller::UsbScan` re-runs the full scan via `action_usb_scan()` then overwrites status with success message. This ensures the newly-registered device's tier appears immediately in the Registered column.
- **wiremock is mandatory**: 4 routing tests exercise real HTTP round-trips against mock endpoints. No skip path.

## Test Count

- usb_scan_dispatch_tests: 5 tests (open, nav wrap, esc, enter empty, up empty)
- usb_scan_merge_tests: 7 tests (registry map extraction, default tier, matching, unregistered, usb-driven rows, empty status, nonzero status)
- usb_scan_routing_tests: 4 tests (DeviceList success, UsbScan success, both error paths) — wiremock-driven

## Build Status

- `cargo build -p dlp-admin-cli`: clean (zero warnings)
- `cargo test -p dlp-admin-cli --lib`: 64 passed
- `cargo clippy -p dlp-admin-cli -- -D warnings`: clean
- `cargo clippy -p dlp-common -- -D warnings`: clean

## Phase 32 Closeout

All three plans (32-01, 32-02, 32-03) are complete. The full user flow is operational:
DevicesMenu -> UsbScan (idx 2) -> r (concurrent scan) -> Enter (DeviceTierPicker with caller=UsbScan) -> Enter (POST + auto re-scan + success status).
