---
phase: 31-usb-cm-blocking
plan: "02"
status: complete
completed: "2026-04-29"
---

# Phase 31 Plan 02: USB Arrival Detection Gap Closure — SUMMARY

**Objective:** Fix USB device arrival detection so that Blocked-tier USB mass storage devices are reliably disabled via CM_Disable_DevNode, even when Windows does not fire the GUID_DEVINTERFACE_USB_DEVICE notification.

## What Was Built

1. **GUID_DEVINTERFACE_DISK registration** — Added a third device notification registration alongside the existing VOLUME and USB_DEVICE registrations. The DISK interface fires reliably for all USB mass storage devices, including those that never fire the USB_DEVICE notification.

2. **PnP tree-walk handler** — Implemented `on_disk_device_arrival` and `on_disk_device_removal` that:
   - Extract the device instance ID from the DISK `dbcc_name`
   - Call `CM_Locate_DevNodeW` to get the disk devinst
   - Walk up the PnP tree via `CM_Get_Parent` + `CM_Get_Device_IDW` to find a USB ancestor
   - Parse VID/PID/serial from the USB ancestor's instance ID via `parse_usb_device_path`
   - Apply tier enforcement (disable device for Blocked, set volume read-only for ReadOnly)

3. **Removal fallback** — Added `disk_to_identity: RwLock<HashMap<String, DeviceIdentity>>` to `UsbDetector` so that removal cleanup can proceed even when the device is already gone from the PnP tree (CM_Locate_DevNodeW fails).

4. **Idempotency safeguards** — Both `GUID_DEVINTERFACE_USB_DEVICE` and `GUID_DEVINTERFACE_DISK` may fire for the same physical device. The handlers are idempotent: inserting into `device_identities` overwrites the same key, and `apply_tier_enforcement` re-applies the same tier. The `pending_identity` slot is only filled when empty to avoid clobbering a different device's identity.

5. **NOTIFY_HANDLES expanded** — Changed from a 2-tuple to a 3-tuple to hold the DISK notification handle, with updated `unregister_usb_notifications` to clean up all three handles.

## Files Modified

| File | Changes |
|------|---------|
| `dlp-agent/src/detection/usb.rs` | +412/-4 lines. Added GUID_DEVINTERFACE_DISK constant, CM_* imports, disk_to_identity field, disk_path_to_instance_id, on_disk_device_arrival, on_disk_device_removal, updated register/unregister for 3 handles, added 7 unit tests. |

## Unit Tests Added

| Test | Purpose |
|------|---------|
| `test_disk_path_to_instance_id_extraction` | Verifies dbcc_name → instance ID parsing for USBSTOR disk |
| `test_disk_path_non_usbstor` | Verifies generic extraction works for SCSI disks too |
| `test_disk_to_identity_populated_on_arrival` | Verifies disk_to_identity map storage |
| `test_disk_to_identity_removal_fallback` | Verifies removal fallback lookup and cleanup |
| `test_dbcc_name_malformed_missing_prefix` | Graceful handling of missing `\\?\` prefix |
| `test_dbcc_name_without_guid_suffix` | Graceful handling of missing `#{GUID}` suffix |
| `test_dbcc_name_empty` | Empty input handled without panic |

## Quality Gates

- [x] `cargo build -p dlp-agent` — zero warnings, zero errors
- [x] `cargo test -p dlp-agent --lib` — 209 tests passed, 0 failed
- [x] `cargo clippy -p dlp-agent -- -D warnings` — zero issues
- [x] `cargo fmt -p dlp-agent --check` — passes

## Threat Model Compliance

All 5 threats from the plan's threat model are mitigated:

| Threat ID | Mitigation |
|-----------|------------|
| T-31-02-01 (Spoofing) | Only trust USB ancestor if instance ID starts with `USB\` (case-sensitive) |
| T-31-02-02 (Tampering) | PnP walk bounded to 16 iterations; break on CM_Get_Parent failure |
| T-31-02-03 (DoS) | CM_Locate_DevNodeW failure logs warning and returns — no panic |
| T-31-02-04 (EoP / wrong device) | VID/PID/serial parsed from USB ancestor, not from disk dbcc_name |
| T-31-02-05 (DoS / cleanup failure) | Secondary disk_to_identity map ensures removal cleanup proceeds |

## Deviations

None — plan executed exactly as written.

## Self-Check

- [x] All tasks completed
- [x] Each task committed atomically
- [x] SUMMARY.md created
- [x] No modifications to shared orchestrator artifacts
