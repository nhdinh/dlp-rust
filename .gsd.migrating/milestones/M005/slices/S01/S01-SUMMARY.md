---
sliceId: S01
title: Disk enumeration
status: complete
completedAt: 2026-05-01
tasksCompleted: 3
---

# S01: Disk enumeration

## What was delivered

Install-time disk enumeration using Win32 SetupDi APIs and IOCTL_STORAGE_GET_DEVICE_NUMBER. Agent discovers all connected disks at startup, assigns unique volume GUID identifiers, extracts device number and drive letter, and distinguishes USB (DRIVE_REMOVABLE) from internal (DRIVE_FIXED) disks.

## Key files

- `dlp-agent/src/detection/disk.rs` — disk enumeration logic
- `dlp-common/src/disk.rs` — DiskIdentity struct and shared types

## Decisions made

- Volume GUID used as canonical identifier (drive letters are volatile)
- DRIVE_FIXED vs DRIVE_REMOVABLE for USB distinction
- GetVolumePathNamesForVolumeNameW for drive letter resolution from volume GUID path
