---
status: complete
phase: 33-disk-enumeration
source: [33-VERIFICATION.md, 33-GAP-01-SUMMARY.md]
started: 2026-04-29T19:35:17Z
updated: 2026-05-04T13:00:00Z
---

## Current Test

[testing complete — 1 passed, 0 issues, 1 skipped]

## Tests

### 1. Multi-disk bus type accuracy (re-test after 33-GAP-01 fix)
expected: |
  Plug in the Lexar E6 and SanDisk Extreme USB NVMe enclosures (or any USB-bridged
  disk). Run the DLP agent and check the DiskDiscovery audit event JSON.
  Expected: internal NVMe shows bus_type="nvme", USB-bridged enclosures show
  bus_type="usb". Previously both were reported as "nvme".
result: pass
evidence: "Lexar E6 -> bus_type=usb, SanDisk Extreme 55AE -> bus_type=usb, PVC10 SK hynix (internal NVMe) -> bus_type=nvme. All three correct."

### 2. Non-standard boot drive letter
expected: Boot disk detection correctly identifies the system boot drive even when Windows is installed on a drive letter other than C:
result: skipped
reason: system has Windows on C: (standard configuration); non-C: boot drive not available for testing

## Summary

total: 2
passed: 1
issues: 0
pending: 0
skipped: 1
blocked: 0

## Gaps

- truth: "USB-bridged NVMe enclosures show bus_type='usb', not 'nvme'"
  status: resolved
  reason: "33-GAP-01 implemented the fix: resolve_bus_type_with_pnp_override runs is_usb_bridged_pnp_walk unconditionally for every disk. PnP-confirmed USB ancestry overrides any IOCTL result. 9 unit tests pin the truth table. Re-test on Lexar E6 / SanDisk Extreme hardware needed to confirm fix works on physical hardware."
  severity: major
  test: 1
  root_cause: "IOCTL_STORAGE_QUERY_PROPERTY (STORAGE_DEVICE_DESCRIPTOR.BusType) reports the tunneled storage PROTOCOL (NVMe), not the physical connection (USB). Windows Get-Disk correctly shows Lexar E6 and SanDisk Extreme as BusType=USB, but the DLP agent's IOCTL path returns NVMe for all three disks. This is a fundamental API limitation — the IOCTL will always misclassify USB NVMe bridges. Additionally, query_bus_type_ioctl iterates PhysicalDrive0-31 returning the first successful handle without instance_id correlation, compounding the error. PnP fallback (is_usb_bridged_pnp_walk) is correct and would produce the right answer, but only runs on Err(_) — bypassed when IOCTL returns wrong-but-successful result."
  fix: "33-GAP-01 (commit 4b3c4a2): resolve_bus_type_with_pnp_override helper; is_usb_bridged_pnp_walk called unconditionally in enumerate_fixed_disks_windows; old conditional Err(_) fallback removed"
  hardware_evidence: "Get-Disk: Lexar E6 = USB (2TB), SanDisk Extreme 55AE = USB (1TB), PVC10 SK hynix = NVMe (512GB). DLP audit: all three as nvme. Confirms IOCTL fundamentally cannot distinguish USB NVMe bridges from native NVMe."
