---
phase: 23-usb-enumeration-in-dlp-agent
plan: "01"
subsystem: dlp-agent/detection
tags:
  - rust
  - dlp-agent
  - usb
  - detection
  - pure-rust
dependency_graph:
  requires:
    - dlp-common::DeviceIdentity (Phase 22 Plan 01)
  provides:
    - UsbDetector.device_identities field
    - parse_usb_device_path helper
    - device_identity_for_drive accessor
    - Win32_Devices_DeviceAndDriverInstallation feature flag
  affects:
    - Phase 23 Plan 02 (wires WM_DEVICECHANGE handler calling parse_usb_device_path)
    - Phase 26 (reads device_identities at enforcement time)
tech_stack:
  added: []
  patterns:
    - parking_lot::RwLock<HashMap<char, T>> keyed by drive letter (mirrors blocked_drives)
    - Module-private pure-Rust parser with best-effort field extraction, never panics
    - TDD RED/GREEN/REFACTOR cycle with 9 new unit tests
key_files:
  created: []
  modified:
    - dlp-agent/src/detection/usb.rs (+165 lines: imports, field, accessor, parser, 9 tests)
    - dlp-agent/Cargo.toml (+3 lines: Win32_Devices_DeviceAndDriverInstallation feature)
decisions:
  - "#[allow(dead_code)] on parse_usb_device_path: function only used in tests until Plan 02 wires the WM_DEVICECHANGE call site"
  - "vid/pid extracted as lowercase from source (case-insensitive prefix match on VID_/PID_) — Plan 02 may normalize to uppercase if needed"
metrics:
  duration: "7m"
  completed_date: "2026-04-22"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 2
---

# Phase 23 Plan 01: USB Identity Seam (Pure Rust) Summary

**One-liner:** Pure-Rust `parse_usb_device_path` parser + `device_identities: RwLock<HashMap<char, DeviceIdentity>>` field added to `UsbDetector`, with 9 unit tests and `Win32_Devices_DeviceAndDriverInstallation` Cargo feature flag for Plan 02.

## What Was Built

### Task 1: device_identities field, parse_usb_device_path, device_identity_for_drive (TDD)

Added to `dlp-agent/src/detection/usb.rs`:

**Imports added:**
- `use std::collections::HashMap;`
- Extended `use dlp_common::Classification;` to `use dlp_common::{Classification, DeviceIdentity};`

**Struct field added to `UsbDetector`:**
```rust
pub device_identities: RwLock<HashMap<char, DeviceIdentity>>,
```
Defaults to empty via `#[derive(Default)]` — no manual `new()` change required.

**Public accessor added:**
```rust
pub fn device_identity_for_drive(&self, drive_letter: char) -> Option<DeviceIdentity>
```
Case-insensitive lookup via `to_ascii_uppercase()`. No `unwrap()` or `expect()` inside.

**Module-private parser added:**
```rust
#[allow(dead_code)]
fn parse_usb_device_path(dbcc_name: &str) -> DeviceIdentity
```
- Splits on `#`, extracts `VID_`/`PID_` tokens from segment 1 (case-insensitive)
- Maps empty or `&`-prefixed segment 2 to `"(none)"` serial sentinel (D-05)
- Returns best-effort `DeviceIdentity::default()` fields on malformed input (D-04)
- Never panics; no `unwrap()` inside the function body
- No `#[cfg(windows)]` guard — pure Rust, cross-platform testable

**Nine new unit tests (pre-plan baseline: 7; post-plan total: 16):**

| Test | Assertion |
|------|-----------|
| `test_parse_happy_path` | Standard path yields vid=0951, pid=1666, serial=1234567890 |
| `test_parse_no_serial_empty_segment` | Empty serial segment yields serial=(none) |
| `test_parse_no_serial_ampersand_synthesized` | &0 synthesized serial yields serial=(none) |
| `test_parse_lowercase_vid_pid_accepted` | vid_/pid_ lowercase prefix accepted, values preserved |
| `test_parse_malformed_missing_vid_pid_segment` | Garbage segment yields vid="", pid="", serial=best-effort |
| `test_parse_empty_string` | Empty input safe, serial=(none) |
| `test_parse_does_not_panic_on_unusual_input` | Two-segment path yields (none) serial, no panic |
| `test_device_identities_default_empty` | UsbDetector::new().device_identities defaults empty |
| `test_device_identity_for_drive_present_and_absent` | Insert at E, read E/e returns Some, read Z returns None |

### Task 2: Win32_Devices_DeviceAndDriverInstallation Cargo feature

Added to `dlp-agent/Cargo.toml` `windows` dependency features array:
```toml
# detection/usb.rs Plan 02: SetupDiGetClassDevsW, SetupDiEnumDeviceInfo,
# SetupDiGetDeviceRegistryPropertyW for device friendly-name lookup.
"Win32_Devices_DeviceAndDriverInstallation",
```
Windows crate version pin `"0.58"` unchanged.

## Verification Results

- `cargo test --lib -p dlp-agent detection::usb::tests` — 16 passed, 0 failed
- `cargo build --workspace` — zero warnings
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo fmt --all --check` — clean (formatting applied and committed)
- `parse_usb_device_path` confirmed module-private (no `pub fn` prefix)
- No `unwrap()` or `.expect(` inside `parse_usb_device_path` or `device_identity_for_drive`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Clippy dead_code warning on parse_usb_device_path**
- **Found during:** Task 1 GREEN phase verification
- **Issue:** `parse_usb_device_path` is module-private and only called from tests; clippy `-D warnings` flagged it as dead code
- **Fix:** Added `#[allow(dead_code)]` attribute with doc comment explaining Plan 02 will add the production call site in `usb_wndproc`. The attribute will be removed when Plan 02 wires the `WM_DEVICECHANGE` handler.
- **Files modified:** `dlp-agent/src/detection/usb.rs`
- **Commit:** 6b5e4e1

**2. [Rule - Style] rustfmt reformatted multi-line assert_eq!**
- **Found during:** Final fmt check
- **Issue:** `assert_eq!(detector.device_identity_for_drive('E'), Some(identity.clone()))` exceeded 100-char line limit
- **Fix:** Applied `cargo fmt --all` automatically; committed as style fix
- **Files modified:** `dlp-agent/src/detection/usb.rs`
- **Commit:** 7472e1e

## TDD Gate Compliance

| Gate | Commit | Status |
|------|--------|--------|
| RED (failing tests) | dbfbb8c | Passed — 13 compile errors confirmed |
| GREEN (implementation) | 6b5e4e1 | Passed — 16 tests passing |
| REFACTOR | N/A | Not needed — code clean after GREEN |

## Known Stubs

None — no UI rendering paths, no placeholder text, no hardcoded empty values flowing to output. `parse_usb_device_path` returns `description: String::new()` by design (doc comment: "filled in by SetupDi lookup wired in Plan 02").

## Threat Flags

None — Plan 01 adds only pure-Rust string parsing and an in-memory HashMap field. No new network endpoints, auth paths, or file access patterns introduced. The T-23-03 threat (unbounded map growth) is mitigated by the drive-letter key constraint (max 26 entries), as documented in the plan's threat model.

## Self-Check: PASSED

- `dlp-agent/src/detection/usb.rs` — exists, modified
- `dlp-agent/Cargo.toml` — exists, modified
- Commits verified in git log: dbfbb8c, 6b5e4e1, 6612f12, 7472e1e
