# S01: Disk Enumeration (Phase 33)

**Goal:** Agent discovers and accurately classifies all fixed disks with device identity and bus type.
**Demo:** All fixed disks discovered at install time with device identity, bus type, and encryption status.

## Must-Haves

- 1. All fixed disks enumerated with instance_id, bus_type, model, drive_letter
- 2. USB-bridged SATA/NVMe distinguished from internal disks
- 3. Disk discovery audit events emitted

## Proof Level

- This slice proves: tested

## Integration Closure

Provides canonical device instance ID for all downstream disk operations.

## Verification

- Disk discovery audit events with full identity.

## Tasks

- [x] **T01: Disk enumeration implementation** `est:6h`
  Implement SetupDi-based disk enumeration at install time or first startup. Capture device instance ID, bus type, model, and drive letter. Distinguish USB-bridged SATA/NVMe from genuine internal disks via IOCTL_STORAGE_QUERY_PROPERTY or PnP tree walk. Emit audit events with full disk identity.
  - Files: `dlp-agent/src/detection/disk.rs`, `dlp-common/src/audit.rs`
  - Verify: cargo test --package dlp-agent disk::

## Files Likely Touched

- dlp-agent/src/detection/disk.rs
- dlp-common/src/audit.rs
