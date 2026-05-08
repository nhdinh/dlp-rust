---
id: M011
title: "v0.7.0 Disk Exfiltration Prevention"
status: complete
completed_at: 2026-05-08T05:52:30.214Z
key_decisions:
  - Device instance ID as canonical key for disk identity
  - USB-bridged SATA/NVMe distinguished via IOCTL_STORAGE_QUERY_PROPERTY
  - BitLocker status via WMI; unencrypted disks flagged not hard-blocked
  - PnP CM_Disable_DevNode + Volume DACL deny-all as dual enforcement layers
  - DefineDosDeviceW + IOCTL_VOLUME_OFFLINE for mount-time blocking (deferred to v0.8.1)
key_files:
  - dlp-agent/src/detection/disk.rs
  - dlp-agent/src/detection/encryption.rs
  - dlp-agent/src/disk_enforcer.rs
  - dlp-agent/src/device_controller.rs
lessons_learned:
  - SetupDi device enumeration requires careful handle management
  - WMI CoSetProxyBlanket requires PktPrivacy for remote WMI
  - Volume DACL operations require admin privileges and careful ACL construction
  - PnP disable requires actual CM instance ID, not constructed VID/PID/serial
---

# M011: v0.7.0 Disk Exfiltration Prevention

**v0.7.0 Disk Exfiltration Prevention shipped with disk enumeration, BitLocker, allowlist, enforcement, and admin registry.**

## What Happened

v0.7.0 prevented data exfiltration via unregistered fixed disks with install-time enumeration, BitLocker verification, allowlist persistence, runtime I/O blocking, server-side registry, admin TUI, and USB enforcement fix. All 15 requirements validated.

## Success Criteria Results

- Disk enumeration working — PASS (S01)
- BitLocker verification working — PASS (S02)
- Disk allowlist persistence working — PASS (S03)
- Runtime disk enforcement working — PASS (S04)
- Server-side registry and admin TUI working — PASS (S05)
- USB enforcement fix working — PASS (S06)
- All 15 requirements validated — PASS (coverage audit)

## Definition of Done Results

All slices complete with verification evidence. All 15 requirements validated. Cross-slice integration verified. Milestone audit passed.

## Requirement Outcomes

| Requirement | Status | Evidence |
|-------------|--------|----------|
| DISK-01 | validated | S01: Fixed disk enumeration with identity |
| DISK-02 | validated | S01: USB-bridged detection |
| DISK-03 | validated | S03: TOML allowlist persistence |
| DISK-04 | validated | S04: I/O blocking for unregistered disks |
| DISK-05 | validated | S04: WM_DEVICECHANGE handling |
| CRYPT-01 | validated | S02: WMI BitLocker queries |
| CRYPT-02 | validated | S02: Unencrypted disk audit warnings |
| ADMIN-01..05 | validated | S05: Registry, API, TUI screens |
| AUDIT-01..03 | validated | S01,S04,S05: Discovery, block, admin action events |

## Deviations

Phase 34 HUMAN-UAT deferred (unencrypted disk warning requires physical machine). Phase 38.2 HUMAN-UAT deferred (drive-letter correlation approved from prior session).

## Follow-ups

None.
