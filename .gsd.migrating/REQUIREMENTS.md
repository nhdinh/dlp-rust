# Requirements

This file is the explicit capability and coverage contract for the project.

## Active

### R001 — Untitled
- Status: active
- Validation: S01 validated: Hook DLL exports and IAT patching work in test processes; named pipe protocol achieves p99 < 50ms; CloudEnforcer blocks T3/T4 in placeholder sync paths. Full validation deferred to S02 when dynamic sync path resolver and real sync client injection are integrated.

## Validated

### DISK-06 — Untitled
- Status: validated
- Validation: Validated by M008-S02: Mount-time blocking prevents drive letter assignment for unregistered disks via DefineDosDeviceW + IOCTL_VOLUME_OFFLINE.

### DISK-07 — Untitled
- Status: validated
- Validation: Validated by M008-S03: Configurable grace period with read-only quarantine before hard block; timer state machine verified.

### UAT-05 — Untitled
- Status: validated
- Validation: Validated by M008-S04: SanDisk re-registered with full 128-char serial; ReadOnly/FullAccess trust tiers verified per user.

### USB-07 — Untitled
- Status: validated
- Validation: Validated by M008-S01: CM instance ID resolution via SetupDi; unit tests verify correct resolution from device interface path.

### USB-08 — Untitled
- Status: validated
- Validation: Validated by M008-S01: Precise path matching in SetupDi enumeration distinguishes similar devices.

### USB-09 — Untitled
- Status: validated
- Validation: Validated by M008-S01: Hard error returned when both PnP disable and DACL deny-all fail; no silent failures.

## Deferred

## Out of Scope

## Traceability

| ID | Class | Status | Primary owner | Supporting | Proof |
|---|---|---|---|---|---|
| DISK-06 |  | validated | none | none | Validated by M008-S02: Mount-time blocking prevents drive letter assignment for unregistered disks via DefineDosDeviceW + IOCTL_VOLUME_OFFLINE. |
| DISK-07 |  | validated | none | none | Validated by M008-S03: Configurable grace period with read-only quarantine before hard block; timer state machine verified. |
| R001 |  | active | none | none | S01 validated: Hook DLL exports and IAT patching work in test processes; named pipe protocol achieves p99 < 50ms; CloudEnforcer blocks T3/T4 in placeholder sync paths. Full validation deferred to S02 when dynamic sync path resolver and real sync client injection are integrated. |
| UAT-05 |  | validated | none | none | Validated by M008-S04: SanDisk re-registered with full 128-char serial; ReadOnly/FullAccess trust tiers verified per user. |
| USB-07 |  | validated | none | none | Validated by M008-S01: CM instance ID resolution via SetupDi; unit tests verify correct resolution from device interface path. |
| USB-08 |  | validated | none | none | Validated by M008-S01: Precise path matching in SetupDi enumeration distinguishes similar devices. |
| USB-09 |  | validated | none | none | Validated by M008-S01: Hard error returned when both PnP disable and DACL deny-all fail; no silent failures. |

## Coverage Summary

- Active requirements: 1
- Mapped to slices: 1
- Validated: 6 (DISK-06, DISK-07, UAT-05, USB-07, USB-08, USB-09)
- Unmapped active requirements: 0
