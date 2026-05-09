# Requirements

This file is the explicit capability and coverage contract for the project.

## Active

### R004 — Untitled
- Status: active
- Validation: S01 validated: WfpManager registers/unregisters filters cleanly; add_process_block/remove_process_block work for specified PIDs; unit tests cover registration, double-block, and invalid-PID edge cases. Full validation against actual HTTPS upload bypass deferred to S02.

## Validated

### DISK-06 — Untitled
- Status: validated
- Validation: Validated by M008-S02: Mount-time blocking prevents drive letter assignment for unregistered disks via DefineDosDeviceW + IOCTL_VOLUME_OFFLINE.

### DISK-07 — Untitled
- Status: validated
- Validation: Validated by M008-S03: Configurable grace period with read-only quarantine before hard block; timer state machine verified.

### R001 — Untitled
- Status: validated
- Validation: Fully validated by M017: S01 built IAT hook DLL + WFP filter + named pipe protocol; S02 added registry-based sync path discovery + real ABAC classification wiring + sync-client process watcher; S03 added share-link detection with TC-34..TC-37 passing; S04 built print spooler interception with XPS extraction + SetJob cancellation, TC-50..TC-52 passing; S05 added admin CLI cloud/print config screens + DB migrations. All 172 comprehensive tests and 116 admin-cli tests pass.

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
| R001 |  | validated | none | none | Fully validated by M017: S01 built IAT hook DLL + WFP filter + named pipe protocol; S02 added registry-based sync path discovery + real ABAC classification wiring + sync-client process watcher; S03 added share-link detection with TC-34..TC-37 passing; S04 built print spooler interception with XPS extraction + SetJob cancellation, TC-50..TC-52 passing; S05 added admin CLI cloud/print config screens + DB migrations. All 172 comprehensive tests and 116 admin-cli tests pass. |
| R004 |  | active | none | none | S01 validated: WfpManager registers/unregisters filters cleanly; add_process_block/remove_process_block work for specified PIDs; unit tests cover registration, double-block, and invalid-PID edge cases. Full validation against actual HTTPS upload bypass deferred to S02. |
| UAT-05 |  | validated | none | none | Validated by M008-S04: SanDisk re-registered with full 128-char serial; ReadOnly/FullAccess trust tiers verified per user. |
| USB-07 |  | validated | none | none | Validated by M008-S01: CM instance ID resolution via SetupDi; unit tests verify correct resolution from device interface path. |
| USB-08 |  | validated | none | none | Validated by M008-S01: Precise path matching in SetupDi enumeration distinguishes similar devices. |
| USB-09 |  | validated | none | none | Validated by M008-S01: Hard error returned when both PnP disable and DACL deny-all fail; no silent failures. |

## Coverage Summary

- Active requirements: 1
- Mapped to slices: 1
- Validated: 7 (DISK-06, DISK-07, R001, UAT-05, USB-07, USB-08, USB-09)
- Unmapped active requirements: 0
