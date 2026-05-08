# S04: Disk Enforcement (Phase 36)

**Goal:** Agent blocks I/O to unregistered fixed disks and handles device arrivals/removals.
**Demo:** I/O to unregistered fixed disks blocked at runtime. WM_DEVICECHANGE handled for arrivals/removals.

## Must-Haves

- 1. File Create/Write/Move blocked for unregistered disks
- 2. WM_DEVICECHANGE handled for arrivals/removals
- 3. Block events include disk identity

## Proof Level

- This slice proves: tested

## Integration Closure

Consumes allowlist cache from S03. Emits audit events.

## Verification

- Disk block audit events with full identity.

## Tasks

- [x] **T01: Disk enforcement implementation** `est:5h`
  Implement pre-ABAC volume-level I/O blocking in run_event_loop. Block FileAction::Create/Write/Move for unregistered fixed disks. Handle WM_DEVICECHANGE DBT_DEVICEARRIVAL/DBT_DEVICEREMOVECOMPLETE for GUID_DEVINTERFACE_DISK. Evaluate newly arrived disks against allowlist. Emit audit events with disk identity.
  - Files: `dlp-agent/src/disk_enforcer.rs`, `dlp-agent/src/service.rs`, `dlp-agent/src/detection/device_watcher.rs`
  - Verify: cargo test --package dlp-agent disk_enforcer::

## Files Likely Touched

- dlp-agent/src/disk_enforcer.rs
- dlp-agent/src/service.rs
- dlp-agent/src/detection/device_watcher.rs
