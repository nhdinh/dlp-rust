---
phase: 33-disk-enumeration
plan: 01
subsystem: api
tags: [win32, setupdi, ioctl, disk-enumeration, serde, abac, audit]

requires:
  - phase: 32-usb-scan-register-cli
    provides: dlp-common/src/usb.rs pattern for shared Win32 enumeration modules

provides:
  - DiskIdentity struct with instance_id, bus_type, model, drive_letter, serial, size_bytes, is_boot_disk
  - BusType enum (Unknown, Sata, Nvme, Usb, Scsi) with snake_case serde
  - DiskError type using thiserror with 6 descriptive variants
  - enumerate_fixed_disks() with Windows SetupDi enumeration + non-Windows stub
  - is_usb_bridged() with IOCTL_STORAGE_QUERY_PROPERTY primary + PnP tree walk fallback
  - get_boot_drive_letter() via GetSystemDirectoryW
  - EventType::DiskDiscovery variant with SIEM routing
  - AuditEvent.discovered_disks field with builder method

affects:
  - phase 34: BitLocker verification (consumes DiskIdentity)
  - phase 35: Allowlist persistence (consumes DiskIdentity for TOML serialization)
  - phase 36: Runtime blocking (consumes is_usb_bridged, enumerate_fixed_disks)
  - phase 37-38: Admin TUI/API (consumes enumerate_fixed_disks for scan screen)

tech-stack:
  added: []
  patterns:
    - "#[cfg(windows)] guarded Win32 functions with non-Windows stub returning safe defaults"
    - "IOCTL_STORAGE_QUERY_PROPERTY + PnP tree walk two-tier detection for USB-bridged disks"
    - "serde(skip_serializing_if = Option::is_none) on optional struct fields"

key-files:
  created:
    - dlp-common/src/disk.rs - Shared disk enumeration module (DiskIdentity, BusType, DiskError, Win32 enumeration)
  modified:
    - dlp-common/src/audit.rs - Added EventType::DiskDiscovery, discovered_disks field, builder method, tests
    - dlp-common/src/lib.rs - Added pub mod disk and pub use disk::* re-exports
    - dlp-common/Cargo.toml - Added Win32_System_Ioctl, Win32_System_SystemInformation, Win32_Storage_FileSystem, Win32_System_IO, Win32_Security features
    - dlp-common/src/usb.rs - Minor formatting change from cargo fmt

key-decisions:
  - "Used STORAGE_PROPERTY_ID(0) / STORAGE_QUERY_TYPE(0) newtype constructors for windows 0.61 compatibility (windows 0.58 used raw u32)"
  - "Used GENERIC_READ as raw u32 (0x8000_0000) for CreateFileW dwDesiredAccess parameter (windows 0.61 expects u32, not FILE_ACCESS_RIGHTS)"
  - "Added #[serde(skip_serializing_if = Option::is_none)] to DiskIdentity optional fields to prevent null serialization in audit events"

patterns-established:
  - "Two-tier USB-bridged detection: IOCTL primary + PnP tree walk fallback per D-12/D-13"
  - "Boot disk detection via GetSystemDirectoryW cross-reference, set at enumeration time, never user-modifiable"

requirements-completed: [DISK-01, DISK-02]

duration: 12min
completed: 2026-04-29
---

# Phase 33 Plan 01: Disk Enumeration Module Summary

**Shared disk enumeration module with DiskIdentity types, Win32 IOCTL + PnP USB detection, and DiskDiscovery audit events**

## Performance

- **Duration:** 12 min
- **Started:** 2026-04-29T18:52:59Z
- **Completed:** 2026-04-29T19:05:23Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Created dlp-common/src/disk.rs with full DiskIdentity data model, BusType enum, DiskError type
- Implemented enumerate_fixed_disks() using SetupDiGetClassDevsW + GUID_DEVINTERFACE_DISK
- Implemented is_usb_bridged() with IOCTL_STORAGE_QUERY_PROPERTY primary and CM_Get_Parent PnP fallback
- Implemented get_boot_drive_letter() via GetSystemDirectoryW
- Added EventType::DiskDiscovery to audit.rs with SIEM routing and discovered_disks field
- Wired disk module into lib.rs exports for downstream crate consumption
- Added required Windows feature flags to Cargo.toml for windows 0.61 compatibility
- 101 tests pass (84 existing + 17 new), zero compiler warnings, clippy clean

## Task Commits

Each task was committed atomically:

1. **Task 1: Create dlp-common/src/disk.rs with DiskIdentity, BusType, and enumeration API** - `cd132e8` (feat)
2. **Task 2: Add EventType::DiskDiscovery to audit.rs and wire disk module into lib.rs** - `63e6e67` (feat)

## Files Created/Modified

- `dlp-common/src/disk.rs` - Shared disk enumeration module: DiskIdentity, BusType, DiskError, Win32 enumeration, IOCTL + PnP USB detection, boot disk logic, non-Windows stubs (804 lines)
- `dlp-common/src/audit.rs` - Added EventType::DiskDiscovery, discovered_disks field, with_discovered_disks builder, 5 new unit tests
- `dlp-common/src/lib.rs` - Added `pub mod disk` and `pub use disk::*` re-exports
- `dlp-common/Cargo.toml` - Added Win32_System_Ioctl, Win32_System_SystemInformation, Win32_Storage_FileSystem, Win32_System_IO, Win32_Security features
- `dlp-common/src/usb.rs` - Minor cargo fmt formatting change (whitespace)

## Decisions Made

- Used `STORAGE_PROPERTY_ID(0)` / `STORAGE_QUERY_TYPE(0)` newtype constructors for windows 0.61 API compatibility (the plan assumed raw u32 values used in windows 0.58)
- Used `0x8000_0000u32` (GENERIC_READ) as raw u32 for CreateFileW dwDesiredAccess because windows 0.61 expects u32 not FILE_ACCESS_RIGHTS
- Added `#[serde(skip_serializing_if = "Option::is_none")]` to DiskIdentity optional fields (drive_letter, serial, size_bytes) to prevent null serialization in audit event JSON

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed windows 0.61 API type mismatches**
- **Found during:** Task 1 (disk.rs compilation)
- **Issue:** `STORAGE_PROPERTY_QUERY` fields `PropertyId` and `QueryType` require `STORAGE_PROPERTY_ID` and `STORAGE_QUERY_TYPE` newtype wrappers in windows 0.61, not raw u32. `CreateFileW` dwDesiredAccess expects raw u32, not `FILE_ACCESS_RIGHTS`. `STORAGE_BUS_TYPE` does not exist as an importable type in windows 0.61.
- **Fix:** Changed `PropertyId: 0` to `PropertyId: STORAGE_PROPERTY_ID(0)`, `QueryType: 0` to `QueryType: STORAGE_QUERY_TYPE(0)`, used `0x8000_0000u32` for GENERIC_READ, removed `STORAGE_BUS_TYPE` from imports.
- **Files modified:** dlp-common/src/disk.rs, dlp-common/Cargo.toml
- **Verification:** `cargo check -p dlp-common` passes, `cargo test -p dlp-common` passes
- **Committed in:** 63e6e67 (Task 2 commit)

**2. [Rule 1 - Bug] Fixed DiskIdentity serde null serialization**
- **Found during:** Task 2 (test run)
- **Issue:** `test_disk_identity_serde_skips_none_fields` failed because `Option<char>` and `Option<String>` fields serialized as `"field":null` instead of being omitted.
- **Fix:** Added `#[serde(skip_serializing_if = "Option::is_none")]` to `drive_letter`, `serial`, and `size_bytes` fields on `DiskIdentity`.
- **Files modified:** dlp-common/src/disk.rs
- **Verification:** `cargo test -p dlp-common` passes (101 tests)
- **Committed in:** 63e6e67 (Task 2 commit)

**3. [Rule 3 - Blocking] Added missing Win32_Security feature for CreateFileW**
- **Found during:** Task 2 (compilation after Cargo.toml update)
- **Issue:** `CreateFileW` is gated behind `Win32_Security` feature in windows 0.61, causing unresolved import error.
- **Fix:** Added `"Win32_Security"` to the windows features list in dlp-common/Cargo.toml.
- **Files modified:** dlp-common/Cargo.toml
- **Verification:** `cargo check -p dlp-common` passes
- **Committed in:** 63e6e67 (Task 2 commit)

---

**Total deviations:** 3 auto-fixed (2 bugs, 1 blocking)
**Impact on plan:** All auto-fixes necessary for windows 0.61 API compatibility and correct serde behavior. No scope creep.

## Issues Encountered

- windows crate 0.61 API differences from 0.58 (documented in STATE.md as a known blocker): `STORAGE_PROPERTY_ID`/`STORAGE_QUERY_TYPE` are newtype wrappers, `CreateFileW` requires `Win32_Security` feature, `STORAGE_BUS_TYPE` is not importable as a standalone type. All resolved by using the correct 0.61 APIs.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- DiskIdentity data model is ready for Phase 34 (BitLocker verification) to add encryption status fields
- enumerate_fixed_disks() is ready for Phase 35 (allowlist persistence) to serialize to TOML
- is_usb_bridged() is ready for Phase 36 (runtime blocking) to classify disks at enforcement time
- AuditEvent::DiskDiscovery is ready for Phase 36 to emit aggregated disk discovery events

---
*Phase: 33-disk-enumeration*
*Completed: 2026-04-29*
