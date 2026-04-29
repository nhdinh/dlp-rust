---
phase: 32
plan: 01
status: complete
completed: "2026-04-29"
---

# Plan 32-01 Summary: dlp-common USB Module + Agent Refactor

## Objective
Extract USB enumeration and path-parsing helpers from `dlp-agent/src/detection/usb.rs` into a new shared module `dlp-common/src/usb.rs`, add `enumerate_connected_usb_devices()`, and refactor `dlp-agent` to consume the shared API.

## Tasks Completed

### Task 1: Add Win32_Devices_DeviceAndDriverInstallation feature to dlp-common Cargo.toml
- Added `"Win32_Devices_DeviceAndDriverInstallation"` as the 7th feature in the windows dependency block
- Existing 6 features preserved
- Commit: `42baa1b`

### Task 2: Create dlp-common/src/usb.rs
- New file with 4 public items:
  - `parse_usb_device_path(dbcc_name: &str) -> DeviceIdentity` (cross-platform)
  - `setupdi_description_for_device(device_path: &str) -> String` (cfg(windows))
  - `enumerate_connected_usb_devices() -> Vec<DeviceIdentity>` (cfg-dispatched)
  - `enumerate_connected_usb_devices_windows() -> Vec<DeviceIdentity>` (private, cfg(windows))
- Uses `GUID_DEVINTERFACE_USB_DEVICE` for enumeration (existing proven path from agent)
- 7 historical parse tests moved from agent + 2 new enumerate smoke tests
- Commit: `45c3ab4`

### Task 3: Refactor dlp-agent to import shared helpers
- Added `use dlp_common::usb::{parse_usb_device_path, setupdi_description_for_device};`
- Deleted local functions: `parse_usb_device_path`, `setupdi_description_for_device`, `read_string_property`
- Deleted constants: `SPDRP_FRIENDLYNAME`, `SPDRP_DEVICEDESC`
- Removed unused `Win32::Devices::DeviceAndDriverInstallation` import block
- Deleted 7 parse tests (now in dlp-common)
- Commit: `refactor(32-01): dlp-agent imports shared usb helpers from dlp-common`

## Files Modified
| File | Change |
|------|--------|
| `dlp-common/Cargo.toml` | Added Win32_Devices_DeviceAndDriverInstallation feature |
| `dlp-common/src/usb.rs` | New shared USB module (387 lines) |
| `dlp-common/src/lib.rs` | Added `pub mod usb;` + re-export of public fns |
| `dlp-agent/src/detection/usb.rs` | Deleted local copies, imports from dlp-common |

## Verification
- `cargo build --workspace` : PASS (zero warnings)
- `cargo test -p dlp-common --lib usb` : 12 passed (7 parse + 2 enumerate smoke + 3 existing)
- `cargo test -p dlp-agent --lib detection::usb` : 11 passed (7 parse tests removed)
- `cargo clippy --workspace -- -D warnings` : PASS
- `cargo fmt --all -- --check` : PASS

## Test Counts
| Crate | Before | After | Delta |
|-------|--------|-------|-------|
| dlp-common | 5 | 12 | +7 (moved from agent) |
| dlp-agent | 18 | 11 | -7 (moved to dlp-common) |

## GUID Strategy
`GUID_DEVINTERFACE_USB_DEVICE` was selected per Q1 resolution in 32-CONTEXT.md — it matches the existing proven enumeration path in the agent (not GUID_DEVINTERFACE_DISK).

## Why setupdi_description_for_device was promoted to pub fn
The agent's `on_usb_device_arrival` handler calls it directly to look up device descriptions. Promoting it to `pub fn` in dlp-common allows the agent to re-import it without duplication.

## Self-Check: PASSED
