# Requirements

This file is the explicit capability and coverage contract for the project.

## Active

## Validated

### ADMIN-04 — Untitled
- Status: validated
- Primary owning slice: S01
- Validation: Disk Registry TUI screen implemented under Devices menu (index 3). Admin can list disks in a 5-column table (Agent ID, Instance ID, Bus Type, Encrypted, Model), add entries via 5-field text input flow (POST /admin/disk-registry), and delete selected entries (DELETE /admin/disk-registry/{id}). 77 tests pass including 6 new disk registry tests covering menu navigation, key dispatch, and rendering. Build and clippy clean.

## Deferred

## Out of Scope

## Traceability

| ID | Class | Status | Primary owner | Supporting | Proof |
|---|---|---|---|---|---|
| ADMIN-04 |  | validated | S01 | none | Disk Registry TUI screen implemented under Devices menu (index 3). Admin can list disks in a 5-column table (Agent ID, Instance ID, Bus Type, Encrypted, Model), add entries via 5-field text input flow (POST /admin/disk-registry), and delete selected entries (DELETE /admin/disk-registry/{id}). 77 tests pass including 6 new disk registry tests covering menu navigation, key dispatch, and rendering. Build and clippy clean. |

## Coverage Summary

- Active requirements: 0
- Mapped to slices: 0
- Validated: 1 (ADMIN-04)
- Unmapped active requirements: 0
