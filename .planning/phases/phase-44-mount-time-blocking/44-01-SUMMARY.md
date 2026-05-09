---
phase: 44-mount-time-blocking
plan: 01
subsystem: enforcement
tags: [windows-api, DefineDosDeviceW, IOCTL_VOLUME_OFFLINE, FSCTL_DISMOUNT_VOLUME, mount-time-blocking, disk-enforcement]

requires:
  - phase: 36
    provides: DiskEnforcer I/O-time blocking with drive_letter_map / instance_id_map
  - phase: 33-35
    provides: DiskEnumerator, frozen allowlist, disk enumeration

provides:
  - block_disk_at_mount_time function (DefineDosDeviceW + IOCTL_VOLUME_OFFLINE)
  - emit_disk_mount_blocked audit helper (EventType::DiskMountBlocked)
  - on_disk_arrival_inner allowlist-before-insertion check
  - Unregistered disks invisible to Explorer (never enter drive_letter_map)
  - I/O-time blocking remains as fallback defense-in-depth

affects:
  - disk-enforcement
  - audit-events
  - device-watcher

tech-stack:
  added: []
  patterns:
    - "Mount-time blocking before drive_letter_map insertion"
    - "Defense-in-depth: DefineDosDeviceW primary, IOCTL_VOLUME_OFFLINE secondary"
    - "Audit event on every mount-time block with DiskIdentity"

key-files:
  created: []
  modified:
    - dlp-agent/src/detection/disk.rs - block_disk_at_mount_time, emit_disk_mount_blocked, on_disk_arrival_inner
    - dlp-common/src/audit.rs - EventType::DiskMountBlocked variant

key-decisions:
  - "Windows 0.62.2 API: DefineDosDeviceW returns Result<(), Error> (not BOOL); CreateFileW returns Result<HANDLE, Error>; DeviceIoControl is in Win32::System::IO (not Ioctl)"
  - "Removed emit_disk_discovery_for_arrival (now dead code) since unregistered disks are blocked at mount time instead of merely audited"
  - "FSCTL_DISMOUNT_VOLUME constant inlined as u32 (589856) because windows 0.62.2 does not export it from System::Ioctl module"

patterns-established:
  - "Allowlist check BEFORE state mutation: prevents TOCTOU and ensures unregistered disks never enter visible state"
  - "Graceful degradation: mount-time block failure logs warning and falls back to I/O-time blocking"

requirements-completed:
  - DISK-06

metrics:
  duration: 35min
  completed: 2026-05-08
---

# Phase 44 Plan 01: Mount-Time Blocking Summary

**Mount-time blocking for unregistered fixed disks via DefineDosDeviceW drive-letter removal and IOCTL_VOLUME_OFFLINE volume takedown, with DiskMountBlocked audit events and I/O-time fallback**

## Performance

- **Duration:** 35 min
- **Started:** 2026-05-08T02:30:00Z
- **Completed:** 2026-05-08T03:05:00Z
- **Tasks:** 3
- **Files modified:** 2

## Accomplishments

- Added `block_disk_at_mount_time()` that removes drive letters from DOS namespace and offlines volumes
- Added `emit_disk_mount_blocked()` audit helper with `EventType::DiskMountBlocked`
- Modified `on_disk_arrival_inner` to check frozen allowlist BEFORE `drive_letter_map` insertion
- Unregistered disks never appear in Explorer (skipped in `drive_letter_map`)
- I/O-time blocking in `DiskEnforcer` remains functional as fallback
- Added 3 new tests covering mount-time blocking behavior

## Task Commits

Each task was committed atomically:

1. **Task 2: Add EventType::DiskMountBlocked** - `2576391` (feat)
2. **Task 1: Add block_disk_at_mount_time function + on_disk_arrival_inner modification** - `a3774c7` (feat)
3. **Task 3: Add tests** - included in `a3774c7` (test coverage within feat commit)

## Files Created/Modified

- `dlp-common/src/audit.rs` - Added `DiskMountBlocked` variant to `EventType` enum, included in `routed_to_siem()`
- `dlp-agent/src/detection/disk.rs` - Added `block_disk_at_mount_time()`, `emit_disk_mount_blocked()`, modified `on_disk_arrival_inner` for allowlist-first check, removed dead `emit_disk_discovery_for_arrival`, added 3 new tests

## Decisions Made

- Windows 0.62.2 API signatures differ from plan's assumed API: `DefineDosDeviceW` returns `Result<(), Error>`, `CreateFileW` returns `Result<HANDLE, Error>`, `DeviceIoControl` lives in `Win32::System::IO` not `System::Ioctl`
- `FSCTL_DISMOUNT_VOLUME` (value 589856) is not exported by windows 0.62.2's `System::Ioctl` module, so it was inlined as a `const u32`
- `emit_disk_discovery_for_arrival` was removed rather than kept with `#[allow(dead_code)]` because the new mount-time block flow completely replaces its purpose

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Windows API signature mismatch in block_disk_at_mount_time**
- **Found during:** Task 1 (implementing block_disk_at_mount_time)
- **Issue:** Plan assumed older windows crate API where `DefineDosDeviceW` returns `BOOL`, `CreateFileW` returns `HANDLE`, `DeviceIoControl` is in `System::Ioctl`, and `Error::from_win32()` exists. With windows 0.62.2, these all have different signatures.
- **Fix:** Updated to windows 0.62.2 API: `DefineDosDeviceW` returns `Result<(), Error>` checked with `if let Err(e)`, `CreateFileW` returns `Result<HANDLE, Error>` matched with `if let Ok(handle)`, `DeviceIoControl` imported from `Win32::System::IO`, `FSCTL_DISMOUNT_VOLUME` inlined as `const u32`
- **Files modified:** `dlp-agent/src/detection/disk.rs`
- **Verification:** `cargo test -p dlp-agent` passes (602/602)
- **Committed in:** `a3774c7` (Task 1 commit)

**2. [Rule 1 - Bug] Existing test broken by new allowlist-first logic**
- **Found during:** Task 1 (running tests after implementation)
- **Issue:** `test_on_disk_arrival_inner_updates_drive_letter_map_only` used an unregistered disk (not in `instance_id_map`) and expected it to be inserted into `drive_letter_map`. With Phase 44 logic, unregistered disks are now blocked at mount time and skipped.
- **Fix:** Added `instance_id_map` seeding in the test so the disk is treated as registered, preserving the test's original purpose (verifying drive_letter_map update behavior)
- **Files modified:** `dlp-agent/src/detection/disk.rs`
- **Verification:** Test passes after fix
- **Committed in:** `a3774c7` (Task 1 commit)

**3. [Rule 1 - Bug] Dead code warning after removing emit_disk_discovery_for_arrival call site**
- **Found during:** Task 1 (clippy check)
- **Issue:** `emit_disk_discovery_for_arrival` became unused after `on_disk_arrival_inner` was rewritten to call `block_disk_at_mount_time` instead
- **Fix:** Removed the now-unused function entirely (cleaner than `#[allow(dead_code)]`)
- **Files modified:** `dlp-agent/src/detection/disk.rs`
- **Verification:** Clippy no longer reports dead_code for this function
- **Committed in:** `a3774c7` (Task 1 commit)

---

**Total deviations:** 3 auto-fixed (all Rule 1 - bugs/compatibility issues)
**Impact on plan:** All auto-fixes necessary for compilation correctness against the actual windows crate version. No scope creep.

## Issues Encountered

- Windows crate API differences between plan assumptions and actual version (0.62.2). Resolved by checking crate source and adapting signatures.
- Pre-existing clippy warnings in `disk.rs` (`doc_lazy_continuation` at line 182, `ptr_arg` at line 300) are out of scope (not caused by this plan's changes).

## Known Stubs

None. All functions are fully implemented with real Windows API calls.

## Threat Flags

None. No new security-relevant surface beyond the planned mount-time blocking enforcement.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Mount-time blocking is complete and tested
- Ready for Phase 44 Plan 02 (grace period / quarantine for new disk arrivals, DISK-F2)
- I/O-time blocking fallback remains tested and functional

---
*Phase: 44-mount-time-blocking*
*Completed: 2026-05-08*
