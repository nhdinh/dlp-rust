---
sliceId: S08
title: Admin TUI disk registry
status: pending
risk: medium
depends: [S05]
requirements: [ADMIN-02]
---

# S08: Admin TUI Disk Registry

## Objective

Build the Admin TUI screen for disk registry management. The admin should be able to view all registered disks, register new disks, unregister existing ones, and change disk tier assignments — all through the ratatui-based TUI interface.

## Success Criteria

- Admin TUI has a "Disk Registry" screen accessible from the main menu
- Screen displays all registered disks with volume GUID, model, drive letter, and tier
- Admin can register a new disk (from discovered but unregistered list)
- Admin can change tier (FullAccess/ReadOnly/Blocked) for existing entries
- Admin can unregister a disk
- All operations sync with the server-side disk registry API (S05)

## Tasks

- [ ] **T01: Disk registry list screen** `est:2h`
- [ ] **T02: Register/unregister actions** `est:2h`
- [ ] **T03: Tier change UI and API wiring** `est:1h`

## Key Files

- `dlp-admin-cli/src/screens/` — new disk registry screen module
- `dlp-admin-cli/src/client.rs` — API client methods for disk registry
- `dlp-server/src/admin_api.rs` — existing disk registry endpoints (from S05)

## Dependencies

- S05 server-side disk registry must be complete (provides REST API)
- Follows existing TUI patterns from device registry and LDAP config screens
