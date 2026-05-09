# S02: Mount-Time Blocking for Unregistered Disks

**Goal:** Lock volume at mount time so unregistered fixed disks do not appear in Explorer at all.
**Demo:** Unregistered fixed disk inserted → no drive letter appears in Explorer. I/O-time blocking remains as fallback. Audit event emitted on mount-time block.

## Must-Haves

- 1. Unregistered disk gets no drive letter
- 2. I/O-time blocking remains as fallback
- 3. Audit event emitted on block

## Proof Level

- This slice proves: tested

## Integration Closure

Disk enforcement calls block_disk_at_mount_time before drive letter assignment. S03 grace period defers to this on expiry.

## Verification

- Audit event on mount-time block with disk identity fields.

## Tasks

- [x] **T01: Mount-time blocking implementation** `est:4h`
  Implement mount-time blocking using DefineDosDeviceW + IOCTL_VOLUME_OFFLINE hybrid approach. Unregistered disks blocked before drive letter assignment. I/O-time blocking preserved as fallback. Add audit event emission. Integration tests.
  - Files: `dlp-agent/src/detection/disk.rs`, `dlp-agent/src/disk_enforcer.rs`, `dlp-common/src/audit.rs`
  - Verify: cargo test --package dlp-agent disk::

## Files Likely Touched

- dlp-agent/src/detection/disk.rs
- dlp-agent/src/disk_enforcer.rs
- dlp-common/src/audit.rs
