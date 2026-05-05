# M005: Disk Exfiltration Prevention (v0.7.0)

**Vision:** Close the disk exfiltration gap by enumerating, classifying, and enforcing access control on all connected disk devices — extending the USB-only model to cover SATA/NVMe and hardening the USB enforcement layer to actually block I/O.

## Success Criteria

- All connected disks are enumerated at agent startup with unique identification
- BitLocker encryption status is detected and reported for each volume
- Disk allowlist persists across agent restarts
- Writes to unregistered disks are blocked in real-time with user toast notification
- Server-side disk registry provides CRUD API for disk tier management
- Admin TUI has a functional disk registry management screen
- USB Blocked-tier devices cannot write data (PnP disable + DACL deny-all)
- LDAP configuration is manageable via Admin TUI

## Key Risks / Unknowns

- USB_DEVICE to VOLUME arrival race — identity reconciliation timing may fail under certain plug sequences
- Drive-letter volatility — letters can change between boots, requiring volume GUID as canonical ID

## Proof Strategy

- USB/VOLUME race → retire in S07 by proving all 5 timing paths handle reconciliation correctly
- Drive-letter volatility → retire in S01 by proving volume GUID is used as canonical identifier

## Verification Classes

- Contract verification: cargo test per crate, integration tests for disk/USB flows
- Integration verification: real USB device plug/unplug with PowerShell UAT scripts
- Operational verification: agent restart with pre-existing disk state, service lifecycle
- UAT / human verification: physical USB device blocked-tier write attempt fails

## Milestone Definition of Done

This milestone is complete only when all are true:

- All slice deliverables are complete
- Agent enumerates disks, checks BitLocker, and enforces policy on startup
- USB Blocked-tier device physically cannot write (verified with hardware)
- Admin TUI disk registry screen is functional end-to-end
- LDAP config screen is wired and functional
- All requirements (DISK-01..05, CRYPT-01..02, ADMIN-01..02, AUDIT-01) are satisfied

## Requirement Coverage

- Covers: DISK-01, DISK-02, DISK-03, DISK-04, DISK-05, CRYPT-01, CRYPT-02, ADMIN-01, ADMIN-02, AUDIT-01
- Partially covers: ADMIN-03, ADMIN-04, ADMIN-05 (TUI screens for other admin functions)
- Leaves for later: AUDIT-02, AUDIT-03 (advanced audit event types)
- Orphan risks: none

## Slices

- [x] **S01: Disk enumeration** `risk:high` `depends:[]`
  > After this: Agent enumerates all connected disks at startup with unique volume GUID identification
- [x] **S02: BitLocker verification** `risk:high` `depends:[S01]`
  > After this: Each enumerated disk has BitLocker encryption status detected and reported
- [x] **S03: Disk allowlist persistence** `risk:medium` `depends:[S01]`
  > After this: Registered disk list survives agent restart without re-enumeration from server
- [x] **S04: Disk enforcement** `risk:high` `depends:[S01,S03]`
  > After this: Writes to unregistered disks are blocked with user notification toast
- [x] **S05: Server-side disk registry** `risk:medium` `depends:[S01]`
  > After this: Server stores disk registry with CRUD API; agents can sync disk tiers
- [x] **S06: LDAP config TUI** `risk:low` `depends:[]`
  > After this: Admin can configure LDAP connection settings via the TUI
- [x] **S07: USB enforcement fix** `risk:high` `depends:[]`
  > After this: USB Blocked-tier devices are physically unable to write via PnP disable + DACL deny-all
- [ ] **S08: Admin TUI disk registry** `risk:medium` `depends:[S05]`
  > After this: Admin can view, register, unregister, and set tier for disks via the TUI

## Boundary Map

### S01 → S02

Produces:
- `DiskIdentity` struct with volume_guid, device_number, drive_letter fields
- `enumerate_disks()` returning Vec<DiskIdentity>

Consumes:
- nothing (first slice)

### S01 → S03

Produces:
- `DiskIdentity` with serializable fields for persistence

Consumes:
- nothing (first slice)

### S01,S03 → S04

Produces:
- Persisted allowlist (S03) + disk identity (S01)

Consumes:
- S01: DiskIdentity for identification
- S03: allowlist for registered/unregistered check

### S05 → S08

Produces:
- Server disk registry CRUD API endpoints
- `DiskRegistryEntry` response type

Consumes:
- S05: REST API for disk operations
