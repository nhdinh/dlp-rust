---
phase: 24-device-registry-db-admin-api
plan: "01"
subsystem: dlp-server/db
tags: [sqlite, repository, device-registry, tdd, usb]
dependency_graph:
  requires: []
  provides: [DeviceRegistryRepository, DeviceRegistryRow, device_registry table]
  affects: [dlp-server/src/db/mod.rs, dlp-server/src/db/repositories/]
tech_stack:
  added: []
  patterns:
    - stateless repository (Pool for reads, UnitOfWork for writes)
    - ON CONFLICT DO UPDATE upsert preserving UUID primary key
    - DB CHECK constraint for trust_tier enum enforcement
key_files:
  created:
    - dlp-server/src/db/repositories/device_registry.rs
  modified:
    - dlp-server/src/db/mod.rs
    - dlp-server/src/db/repositories/mod.rs
decisions:
  - "ON CONFLICT DO UPDATE preferred over INSERT OR REPLACE to preserve UUID PK on duplicate (vid,pid,serial)"
  - "In-memory pool test fix: write conn must be dropped (returned to pool) before list_all acquires read conn"
metrics:
  duration_seconds: 447
  completed_date: "2026-04-22"
  tasks_completed: 2
  files_changed: 3
---

# Phase 24 Plan 01: Device Registry DB — Summary

**One-liner:** SQLite `device_registry` table with CHECK/UNIQUE constraints and a stateless `DeviceRegistryRepository` (list_all, upsert, delete_by_id) following the PolicyRepository pattern.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 (RED) | Add failing tests for device_registry table | 620ecd3 | dlp-server/src/db/mod.rs |
| 1 (GREEN) | Add device_registry table to init_tables | 91c369e | dlp-server/src/db/mod.rs |
| 2 (GREEN) | Create DeviceRegistryRepository | 883e6e6 | dlp-server/src/db/repositories/device_registry.rs, repositories/mod.rs |

## Verification Results

- `cargo test -p dlp-server`: 134 passed, 0 failed, 2 ignored
- `cargo build --all`: zero warnings
- `cargo clippy -p dlp-server -- -D warnings`: zero warnings
- `grep "device_registry" dlp-server/src/db/mod.rs`: CREATE TABLE block found at line 138
- `grep "pub mod device_registry" dlp-server/src/db/repositories/mod.rs`: found at line 12

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed test_upsert_insert_and_list connection scope**
- **Found during:** Task 2 GREEN phase
- **Issue:** The test held the write `PooledConnection` open while calling `list_all`, which attempted to acquire a second connection from the same in-memory pool. Since r2d2 in-memory SQLite pools share the same file handle, the read connection saw "no such table: device_registry" because the write connection's schema wasn't visible.
- **Fix:** Wrapped the write block in an explicit `{}` scope so the connection is returned to the pool before `list_all` is called.
- **Files modified:** `dlp-server/src/db/repositories/device_registry.rs` (test only)
- **Commit:** 883e6e6 (included in GREEN commit)

## Known Stubs

None — all methods are fully implemented with real SQL.

## Threat Surface Scan

All mitigations from the plan's threat model are implemented:

| Threat ID | Mitigation | Status |
|-----------|------------|--------|
| T-24-01 | CHECK(trust_tier IN ('blocked','read_only','full_access')) in DDL | Implemented |
| T-24-02 | All SQL uses rusqlite params![] positional binding | Implemented |
| T-24-03 | UNIQUE(vid,pid,serial) + ON CONFLICT DO UPDATE | Implemented |

No new threat surface introduced beyond what the plan anticipated.

## Self-Check: PASSED

- [x] `dlp-server/src/db/repositories/device_registry.rs` exists
- [x] `dlp-server/src/db/mod.rs` contains device_registry CREATE TABLE
- [x] `dlp-server/src/db/repositories/mod.rs` contains pub mod device_registry
- [x] Commits 620ecd3, 91c369e, 883e6e6 all present in git log
- [x] All 9 new tests pass (4 table tests + 5 repository tests)
- [x] All 134 dlp-server tests pass
