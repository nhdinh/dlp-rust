---
status: diagnosed
phase: 33-disk-enumeration
source: [33-VERIFICATION.md]
started: 2026-04-29T19:35:17Z
updated: 2026-05-04T09:00:00Z
---

## Current Test

[testing complete — 0 passed, 1 issue, 1 skipped]

## Tests

### 1. Multi-disk bus type accuracy
expected: On systems with multiple fixed disks, bus types (SATA, NVMe, USB-bridged) are correctly attributed to each disk instance_id
result: issue
reported: "3 disks detected: internal NVMe (C:) correctly nvme, but external USB-C NVMe enclosure (Lexar E6, E:) and external USB NVMe enclosure (SanDisk Extreme, D:) both reported as nvme instead of usb. PnP tree walk fallback not catching USB NVMe bridges."
severity: major

### 2. Non-standard boot drive letter
expected: Boot disk detection correctly identifies the system boot drive even when Windows is installed on a drive letter other than C:
result: skipped
reason: system has Windows on C: (standard configuration); non-C: boot drive not available for testing

## Summary

total: 2
passed: 0
issues: 1
pending: 0
skipped: 1
blocked: 0

## Gaps

- truth: "USB-bridged NVMe enclosures show bus_type='usb', not 'nvme'"
  status: diagnosed
  reason: "User reported: External USB-C NVMe enclosure (Lexar E6) and USB NVMe enclosure (SanDisk Extreme) both reported as nvme. PnP tree walk fallback not detecting USB NVMe bridges on this multi-disk system."
  severity: major
  test: 1
  root_cause: "query_bus_type_ioctl iterates PhysicalDrive0-31 and returns the first successful IOCTL result without validating the handle matches the requested instance_id. The _instance_id param in query_bus_type_for_handle is intentionally unused (underscore prefix). Internal NVMe (PhysicalDrive0) responds first with BusTypeNvme, poisoning results for all disks. USB NVMe bridges (UAS/uaspstor) also report BusTypeNvme via STORAGE_DEVICE_DESCRIPTOR — physical USB ancestry is only visible via PnP tree. PnP fallback only runs on Err(_), so it is permanently bypassed when IOCTL returns wrong-but-successful result."
  artifacts:
    - path: "dlp-common/src/disk.rs"
      issue: "query_bus_type_ioctl (lines 480-516): iterates PhysicalDriveN, returns first successful IOCTL without instance_id correlation"
    - path: "dlp-common/src/disk.rs"
      issue: "query_bus_type_for_handle (lines 520-581): _instance_id param accepted but never used — no identity validation"
    - path: "dlp-common/src/disk.rs"
      issue: "enumerate_fixed_disks_windows (lines 405-413): PnP fallback only on Err, never reached when IOCTL returns wrong result"
  missing:
    - "Run PnP walk unconditionally alongside IOCTL — if PnP says USB, override IOCTL result (short-term fix)"
    - "OR correlate PhysicalDriveN handle to instance_id via IOCTL_STORAGE_GET_DEVICE_NUMBER before accepting IOCTL bus type (accurate fix)"
