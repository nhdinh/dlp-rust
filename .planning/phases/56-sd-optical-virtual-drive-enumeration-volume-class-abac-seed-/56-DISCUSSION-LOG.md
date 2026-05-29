# Phase 56: SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004) - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-29
**Phase:** 56-SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004)
**Areas discussed:** Volume Class Detection Method, ABAC Attribute Integration, Admin TUI UX, WM_DEVICECHANGE and Virtual Mounts
**Mode:** --auto (autonomous selection)

---

## Volume Class Detection Method

| Option | Description | Selected |
|--------|-------------|----------|
| Extend GetDriveTypeW + WMI hybrid | Use Win32_DiskDrive/Win32_LogicalDisk to disambiguate removable into USB vs SD, and fixed into LocalNTFS vs Virtual | ✓ |
| Pure WMI approach | Replace GetDriveTypeW entirely with WMI queries for all classifications | |
| Windows Storage API | Use modern Windows.Storage APIs (WinRT) for volume classification | |

**Auto-selected:** Extend GetDriveTypeW + WMI hybrid (recommended default)
**Notes:** [auto] Follows existing codebase pattern (usb.rs already uses GetDriveTypeW; disk.rs uses WMI). Minimizes new dependencies. Single Virtual class for all virtual drives per success criteria.

---

## ABAC Attribute Integration

| Option | Description | Selected |
|--------|-------------|----------|
| Add to AbacContext | source_volume_class and destination_volume_class as Option<VolumeClass> on AbacContext | ✓ |
| Add to Resource | Treat volume class as a property of the resource being accessed | |
| Create new VolumeContext | Separate struct for volume-specific runtime context | |

**Auto-selected:** Add to AbacContext (recommended default)
**Notes:** [auto] Volume class describes the runtime I/O environment, not the resource itself. Matches existing pattern (source_application, destination_application live on AbacContext). New PolicyCondition variants SourceVolumeClass and DestinationVolumeClass with eq/ne/in operators.

---

## Admin TUI UX

| Option | Description | Selected |
|--------|-------------|----------|
| Extend existing screens | Add ConditionAttribute variants and allowlist column/badge | ✓ |
| Create separate screens | Dedicated SD/Optical/Virtual screens | |
| Unified device screen | Merge USB/disk/SD/optical/virtual into one screen | |

**Auto-selected:** Extend existing screens (recommended default)
**Notes:** [auto] Matches success criteria explicitly: "existing USB/disk allowlist screens render SD/Optical/Virtual rows alongside USB without UI breakage." Conditions Builder follows same three-step flow as DeviceTrust/NetworkLocation.

---

## WM_DEVICECHANGE and Virtual Mounts

| Option | Description | Selected |
|--------|-------------|----------|
| Extend GUID_DEVINTERFACE_VOLUME handler | Reuse existing registration; classify all volume arrivals | ✓ |
| Add new GUID registrations | Register for GUID_DEVINTERFACE_CDROM, GUID_DEVINTERFACE_VHD, etc. | |
| Polling-based detection | Periodically scan volumes instead of event-driven | |

**Auto-selected:** Extend GUID_DEVINTERFACE_VOLUME handler (recommended default)
**Notes:** [auto] GUID_DEVINTERFACE_VOLUME already fires for all volume arrivals (physical and virtual). No new Win32 registrations needed. 500ms deferred processing preserved. Virtual mount audit events use new EventType::VolumeArrival.

---

## Claude's Discretion

- VolumeClass enum derives: Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display, Default (LocalNTFS default)
- Hook DLL volume class cache: thread-local RefCell<HashMap<char, (VolumeClass, Instant)>> with 30s TTL
- WMI queries batched at agent startup; refreshed on WM_DEVICECHANGE
- Integration test for DRIVE-02: mock WMI response if no optical drive present on test endpoint
- Admin TUI volume class badges colored by class: LocalNTFS=blue, USBRemovable=yellow, SDCard=magenta, Optical=cyan, Virtual=red, NetworkShare=green

## Deferred Ideas

- Virtual drive sub-classification (Daemon Tools vs VHD vs ISO) — future phase
- Volume-class-specific grace periods — future phase
- Volume-class-based mount-time blocking — future phase
- Network share server-specific classification — future phase
