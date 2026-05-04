---
status: partial
phase: 33-disk-enumeration
source: [33-VERIFICATION.md]
started: 2026-04-29T19:35:17Z
updated: 2026-05-04T12:00:00Z
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
  status: fix_implemented
  reason: "33-GAP-01 implemented the fix: resolve_bus_type_with_pnp_override runs is_usb_bridged_pnp_walk unconditionally for every disk. PnP-confirmed USB ancestry overrides any IOCTL result. 9 unit tests pin the truth table. Re-test on Lexar E6 / SanDisk Extreme hardware needed to confirm fix works on physical hardware."
  severity: major
  test: 1
  root_cause: "IOCTL_STORAGE_QUERY_PROPERTY (STORAGE_DEVICE_DESCRIPTOR.BusType) reports the tunneled storage PROTOCOL (NVMe), not the physical connection (USB). Windows Get-Disk correctly shows Lexar E6 and SanDisk Extreme as BusType=USB, but the DLP agent's IOCTL path returns NVMe for all three disks. This is a fundamental API limitation — the IOCTL will always misclassify USB NVMe bridges. Additionally, query_bus_type_ioctl iterates PhysicalDrive0-31 returning the first successful handle without instance_id correlation, compounding the error. PnP fallback (is_usb_bridged_pnp_walk) is correct and would produce the right answer, but only runs on Err(_) — bypassed when IOCTL returns wrong-but-successful result."
  fix: "33-GAP-01 (commit 4b3c4a2): resolve_bus_type_with_pnp_override helper; is_usb_bridged_pnp_walk called unconditionally in enumerate_fixed_disks_windows; old conditional Err(_) fallback removed"
  hardware_evidence: "Get-Disk: Lexar E6 = USB (2TB), SanDisk Extreme 55AE = USB (1TB), PVC10 SK hynix = NVMe (512GB). DLP audit: all three as nvme. Confirms IOCTL fundamentally cannot distinguish USB NVMe bridges from native NVMe."
