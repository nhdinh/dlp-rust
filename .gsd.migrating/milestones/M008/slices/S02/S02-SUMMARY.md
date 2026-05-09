---
id: S02
parent: M008
milestone: M008
provides:
  - Mount-time blocking function for unregistered disks
  - Audit event on mount-time block
requires:
  - slice: S01
    provides: Resolved CM instance IDs and DeviceController patterns
affects:
  []
key_files:
  - dlp-agent/src/detection/disk.rs
  - dlp-agent/src/disk_enforcer.rs
key_decisions:
  - (none)
patterns_established:
  - DefineDosDeviceW + IOCTL_VOLUME_OFFLINE hybrid for mount-time blocking
observability_surfaces:
  - Audit event on mount-time block with disk identity
drill_down_paths:
  []
duration: ""
verification_result: passed
completed_at: 2026-05-08T05:35:04.288Z
blocker_discovered: false
---

# S02: Mount-Time Blocking for Unregistered Disks

**Mount-time blocking prevents Explorer visibility for unregistered disks.**

## What Happened

Mount-time blocking implemented using DefineDosDeviceW to prevent drive letter assignment and IOCTL_VOLUME_OFFLINE for already-mounted volumes. Unregistered fixed disks no longer appear in Explorer. I/O-time blocking preserved as fallback. Audit events emitted on block.

## Verification

Unit tests verify mount-time blocking prevents drive letter assignment. Integration tests verify audit event emission.

## Requirements Advanced

- DISK-06 — Volume locked at mount time before drive letter assignment

## Requirements Validated

- DISK-06 — Unit tests verify no drive letter assigned to unregistered disks

## New Requirements Surfaced

None.

## Requirements Invalidated or Re-scoped

None.

## Operational Readiness

None.

## Deviations

None.

## Known Limitations

Physical hardware UAT deferred — requires actual unregistered disk insertion.

## Follow-ups

None.

## Files Created/Modified

- `dlp-agent/src/detection/disk.rs` — Mount-time blocking via DefineDosDeviceW + IOCTL_VOLUME_OFFLINE
- `dlp-agent/src/disk_enforcer.rs` — Disk enforcer mount-time integration
