---
phase: 32-usb-scan-register-cli
plan: 02
status: complete
completed: "2026-04-29"
---

# Plan 32-02 Summary: Type System and Rendering Layer for USB Scan

## What Was Built

Extended the dlp-admin-cli TUI type system and rendering layer with the new `Screen::UsbScan` variant, supporting types, and a 5-column Table renderer.

## Files Modified

| File | Lines | Change |
|------|-------|--------|
| `dlp-admin-cli/src/app.rs` | 160-186 | Added `TierPickerCaller` enum (DeviceList, UsbScan), `UsbScanEntry` struct |
| `dlp-admin-cli/src/app.rs` | 598-607 | Added `caller: TierPickerCaller` to `DeviceTierPicker` variant |
| `dlp-admin-cli/src/app.rs` | 608-620 | Added `Screen::UsbScan { devices, selected }` variant |
| `dlp-admin-cli/src/app.rs` | 583 | Updated DevicesMenu doc comment: "2 items" -> "3 items" |
| `dlp-admin-cli/src/app.rs` | 883-915 | Added 3 unit tests in `import_export_tests` module |
| `dlp-admin-cli/src/screens/dispatch.rs` | 8 | Added `TierPickerCaller` to imports |
| `dlp-admin-cli/src/screens/dispatch.rs` | ~328 | Added `caller: TierPickerCaller::DeviceList` to DeviceTierPicker construction |
| `dlp-admin-cli/src/screens/dispatch.rs` | ~3684 | Added `..` rest-pattern to destructure (compile fix) |
| `dlp-admin-cli/src/screens/render.rs` | 11-15 | Added `UsbScanEntry` import |
| `dlp-admin-cli/src/screens/render.rs` | 236-244 | Updated DevicesMenu to 3 items |
| `dlp-admin-cli/src/screens/render.rs` | 259-261 | Replaced placeholder UsbScan arm with real `draw_usb_scan` call |
| `dlp-admin-cli/src/screens/render.rs` | 1977-2048 | Added `draw_usb_scan` function (5-column Table) |
| `dlp-admin-cli/src/screens/render.rs` | 2143-2204 | Added 3 TestBackend tests |

## Key Decisions

- `TierPickerCaller` mirrors the existing `CallerScreen` pattern used by ConditionsBuilder for return routing.
- `UsbScanEntry.registered_tier` is `Option<String>` (not `Option<UsbTrustTier>`) to match the raw server response format and avoid deserialization overhead in the TUI loop.
- The hint string `"r: Scan   Up/Down: Navigate   Enter: Register   Esc: Back"` is the authoritative form per D-06; draft shorter forms in research docs are non-authoritative.

## Test Count

- app.rs: +3 tests (TierPickerCaller Copy, UsbScanEntry construction, Screen::UsbScan variant)
- render.rs: +3 tests (headers+row render, empty list, 3-item menu)

## Build Status

- `cargo build -p dlp-admin-cli`: clean (zero warnings)
- `cargo test -p dlp-admin-cli --lib usb_scan_render_tests`: 3 passed
- `cargo clippy -p dlp-admin-cli -- -D warnings`: clean

## Remaining Work

All Plan 02 tasks complete. Plan 03 owns ALL UsbScan event handling, concurrent scan logic, and post-registration routing.
