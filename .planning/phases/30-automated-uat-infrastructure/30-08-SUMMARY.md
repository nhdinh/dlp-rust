---
phase: 30-automated-uat-infrastructure
plan: 08
subsystem: testing
tags: [powershell, wmi, usb, uat, deviceio-control, p-invoke, admin-api]

# Dependency graph
requires:
  - phase: 24
    provides: Device registry admin API (POST/DELETE /admin/device-registry)
  - phase: 26
    provides: USB enforcement convergence (UsbEnforcer check() with trust tiers)
  - phase: 27
    provides: USB toast notification (UsbBlockResult with notify flag)
provides:
  - Real-hardware USB write-protection verification PowerShell script
  - Interactive drive selection menu via WMI auto-detection
  - Kernel-level IOCTL_DISK_SET_DISK_ATTRIBUTES cleanup via C# P/Invoke
  - Comprehensive UAT documentation with troubleshooting guide
affects:
  - 30-09 (UAT orchestration may invoke this script)
  - Release verification pipeline

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "PowerShell strict mode with typed parameters and colour-coded output"
    - "C# P/Invoke inline Add-Type for kernel IOCTL operations"
    - "WMI Win32_DiskDrive -> DiskPartition -> LogicalDisk association chain"
    - "Admin API JWT Bearer authentication from PowerShell"

key-files:
  created:
    - scripts/Uat-UsbBlock.ps1
    - scripts/Uat-ReadMe.md
  modified: []

key-decisions:
  - "PNPDeviceID regex VID_/PID_ extraction with 0000 fallback for non-standard devices"
  - "HResult 0x80070013 (ERROR_WRITE_PROTECT) plus message regex for robust write-block detection"
  - "finally block with registeredIds accumulator ensures cleanup even on Ctrl+C or exception"
  - "Add-Type SilentlyContinue on duplicate type load prevents re-run failures"

patterns-established:
  - "UAT script pattern: detect -> select -> register -> verify -> cleanup -> summarise"
  - "PowerShell P/Invoke wrapper: inline C# with kernel32.dll imports for DeviceIoControl"

requirements-completed: []

# Metrics
duration: 5min
completed: 2026-04-28
---

# Phase 30 Plan 08: USB Write-Protection UAT Summary

**Real-hardware USB write-protection verification script with WMI auto-detection,
admin API registration, kernel IOCTL cleanup, and comprehensive troubleshooting documentation**

## Performance

- **Duration:** 5 min
- **Started:** 2026-04-28T13:10:06Z
- **Completed:** 2026-04-28T13:14:51Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Created `scripts/Uat-UsbBlock.ps1` (607 lines) — full-featured PowerShell UAT script
- Created `scripts/Uat-ReadMe.md` (182 lines) — complete execution and troubleshooting guide
- Script auto-detects removable USB drives via WMI with drive letter resolution
- Interactive numbered menu for safe drive selection
- Registers device via admin API with JWT Bearer auth
- Verifies `blocked` tier (writes return ERROR_WRITE_PROTECT)
- Verifies `read_only` tier (reads allowed, writes denied)
- Kernel-level cleanup via `IOCTL_DISK_SET_DISK_ATTRIBUTES` C# P/Invoke
- Colour-coded PASS/FAIL/WARN/INFO console output
- Comprehensive error handling with try/catch around all operations
- Supports `-SkipBlockedTest` and `-SkipReadOnlyTest` switches

## Task Commits

Each task was committed atomically:

1. **Task 1: Write Uat-UsbBlock.ps1 PowerShell script** - `2db8a48` (feat)
2. **Task 2: Write Uat-ReadMe.md documentation** - `fc4e909` (docs)

## Files Created/Modified

- `scripts/Uat-UsbBlock.ps1` - Real-hardware USB write-protection verification script
  - `Get-RemovableUsbDrives()` — WMI query with Win32_DiskDrive/Partition/LogicalDisk association
  - `Show-DriveMenu()` — Interactive numbered selection with input validation
  - `Register-Device()` — POST /admin/device-registry with JWT Bearer header
  - `Remove-Device()` — DELETE /admin/device-registry/{id}
  - `Test-WriteBlocked()` — File write attempt with HResult 0x80070013 detection
  - `Test-ReadAllowed()` — Get-ChildItem directory listing verification
  - `Clear-DiskReadOnly()` — C# P/Invoke DeviceIoControl IOCTL_DISK_SET_DISK_ATTRIBUTES
  - Main orchestration with finally-block cleanup and PASS/FAIL summary
- `scripts/Uat-ReadMe.md` — Prerequisites, setup, execution, interpretation, troubleshooting, safety

## Decisions Made

- **PNPDeviceID regex with 0000 fallback:** VID_/PID_ extraction from PNPDeviceID uses regex
  `VID_([0-9A-F]{4})&PID_([0-9A-F]{4})` with "0000" fallback. Non-standard USB devices without
  standard PNP IDs will register with placeholder values, which is acceptable for UAT since the
  admin API upserts on (vid, pid, serial) and the serial number is the primary key discriminator.
- **HResult + message regex dual detection:** Write-block detection checks both HResult
  -2147024877 (0x80070013 = ERROR_WRITE_PROTECT) and message text containing "write-protect"
  or "media is write protected". This covers both the numeric error code path and localized
  exception message variations.
- **finally block with registeredIds accumulator:** The main script body is wrapped in
  `try/finally` with a `$registeredIds` array that tracks all device IDs registered during
  the test run. Even if the script is interrupted with Ctrl+C (which triggers the finally
  block in PowerShell), all registry entries are removed and disk attributes are cleared.
- **Add-Type SilentlyContinue on duplicate load:** The C# type definition uses
  `-ErrorAction SilentlyContinue` because re-running the script in the same PowerShell session
  would otherwise fail with "type already exists". This is a common PowerShell P/Invoke pattern.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

- PowerShell profile loading error (unrelated): The test command `Get-Command scripts/Uat-UsbBlock.ps1`
  emitted a profile signature error before successfully returning the script info. This is a
  pre-existing execution policy issue on the test machine and does not affect the script itself.

## Known Stubs

None. All functions are fully implemented with real WMI queries, real HTTP API calls, real
file I/O tests, and real kernel IOCTL operations. No placeholder or mock data.

## Threat Flags

None. The script operates within the same trust boundary as dlp-admin-cli (JWT Bearer auth
to local admin API) and requires elevation only for the cleanup IOCTL, which is documented
and guarded by `#Requires -RunAsAdministrator`.

## User Setup Required

**External hardware required.** See plan frontmatter `user_setup`:

- Physical USB removable drive must be inserted before running the script
- dlp-server and dlp-agent must be running
- `DLP_ADMIN_JWT` environment variable must contain a valid admin JWT token
- PowerShell must be launched as Administrator

## Self-Check: PASSED

- [x] `scripts/Uat-UsbBlock.ps1` exists (607 lines)
- [x] `scripts/Uat-ReadMe.md` exists (182 lines)
- [x] Commit `2db8a48` exists in git log
- [x] Commit `fc4e909` exists in git log
- [x] No file deletions in commits
- [x] No modifications to STATE.md or ROADMAP.md

---
*Phase: 30-automated-uat-infrastructure*
*Completed: 2026-04-28*
