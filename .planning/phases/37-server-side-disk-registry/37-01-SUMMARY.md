---
phase: 37
plan: 01
subsystem: server-db
tags: [disk-registry, sqlite, abac, action-enum, repository, tdd]
dependency_graph:
  requires: []
  provides:
    - dlp-common::Action::DiskRegistryAdd (AUDIT-03 action variant)
    - dlp-common::Action::DiskRegistryRemove (AUDIT-03 action variant)
    - disk_registry SQLite table (ADMIN-01 schema)
    - DiskRegistryRepository (list_all, list_by_agent, insert, delete_by_id)
  affects:
    - dlp-server/src/db/repositories/mod.rs (disk_registry added alphabetically)
    - dlp-common/src/abac.rs (Action enum extended)
tech_stack:
  added: []
  patterns:
    - Pure INSERT (no ON CONFLICT) for security allowlist repository (D-05)
    - Optional filter branching in list_all via match on Option<&str>
    - TDD with separate test module (phase37_action_tests) for Action enum variants
key_files:
  created:
    - dlp-server/src/db/repositories/disk_registry.rs (484 lines)
  modified:
    - dlp-common/src/abac.rs (747 lines; +53 lines: 2 variants + 44-line test module)
    - dlp-server/src/db/mod.rs (741 lines; +140 lines: DDL block + 5 tests)
    - dlp-server/src/db/repositories/mod.rs (32 lines; +2 lines: pub mod + pub use)
decisions:
  - "Pure INSERT with no conflict-update clause in DiskRegistryRepository::insert (D-05 compliance)"
  - "list_all branches on Option<&str> using match rather than conditional SQL string; avoids type mismatch"
  - "phase37_action_tests placed in separate cfg(test) module at end of abac.rs (plan requirement)"
metrics:
  duration: "16 minutes"
  completed: "2026-05-04"
  tasks_completed: 3
  files_changed: 4
---

# Phase 37 Plan 01: Server-Side Disk Registry Foundation Summary

SQLite disk_registry table + DiskRegistryRepository (pure INSERT) + Action enum extended with DiskRegistryAdd/DiskRegistryRemove.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Extend Action enum with DiskRegistryAdd and DiskRegistryRemove | 261caa0 | dlp-common/src/abac.rs |
| 2 | Add disk_registry table DDL to init_tables | 807b1de | dlp-server/src/db/mod.rs |
| 3 | Create DiskRegistryRepository with pure INSERT semantics | 0c5358f, 50541cb | dlp-server/src/db/repositories/disk_registry.rs, dlp-server/src/db/repositories/mod.rs |

## Test Results

| Test Suite | Pass | Fail |
|-----------|------|------|
| dlp-common phase37_action_tests (4 tests) | 4 | 0 |
| dlp-server db schema tests (5 tests) | 5 | 0 |
| dlp-server disk_registry repo tests (10 tests) | 10 | 0 |
| **Total** | **19** | **0** |

## Files Created / Modified

| File | Status | Lines |
|------|--------|-------|
| dlp-server/src/db/repositories/disk_registry.rs | CREATED | 484 |
| dlp-common/src/abac.rs | MODIFIED | 747 (+53) |
| dlp-server/src/db/mod.rs | MODIFIED | 741 (+140) |
| dlp-server/src/db/repositories/mod.rs | MODIFIED | 32 (+2) |

## Anti-Upsert Invariant Confirmation

`grep -c "ON CONFLICT" dlp-server/src/db/repositories/disk_registry.rs` returns **0**.

No ON CONFLICT clause exists anywhere in the new repository file. The insert is a pure INSERT SQL statement; duplicate (agent_id, instance_id) pairs surface as rusqlite UNIQUE errors to be mapped to HTTP 409 by the Plan 02 handler.

## Deviations from Plan

### Auto-fixed Issues

**1. [Style] Removed ON CONFLICT phrase from doc comments**
- **Found during:** Task 3 acceptance criteria check
- **Issue:** Plan acceptance criteria specifies `grep -c "ON CONFLICT" disk_registry.rs` must return 0. The initial implementation had the phrase in doc comments (explaining the pattern's absence).
- **Fix:** Replaced "ON CONFLICT DO UPDATE" and "ON CONFLICT" in doc comments with "conflict-update clause" and neutral wording.
- **Files modified:** dlp-server/src/db/repositories/disk_registry.rs
- **Commit:** 50541cb

**2. [Environment] Worktree path disambiguation**
- **Found during:** Task 1
- **Issue:** Read/Edit/Write tool calls using Windows-style paths (`C:\Users\...`) resolved to the main repository, not the git worktree. Tests were compiled from the old file.
- **Fix:** All subsequent file operations used POSIX paths rooted at the worktree (`/c/Users/nhdinh/dev/dlp-rust/.claude/worktrees/agent-af10a9df702180572/...`).
- **Impact:** No code changes; path resolution clarification only.

### Pre-existing Issues (Out of Scope)

- `cargo clippy -p dlp-server --lib -- -D warnings` fails with 1 pre-existing warning in `dlp-server/src/alert_router.rs:202` ("useless conversion to the same type: String"). This issue predates Plan 37-01 and is outside scope. Logged in deferred-items.

### Integration Test Build Errors (Environment)

- Several dlp-server integration tests fail to link with "paging file too small" (OS error 1455) when building in the worktree. This is a Windows virtual memory exhaustion error when mmapping large rlib files in a parallel worktree build. All unit tests (`--lib` flag) pass; only the external integration test binaries fail to link. Pre-existing environment issue, not a code defect.

## Threat Surface Scan

No new network endpoints, auth paths, or schema changes at trust boundaries introduced in Plan 01. The disk_registry table's security-relevant surface (CHECK constraint, UNIQUE constraint) is covered by the plan's threat model (T-37-01, T-37-02, T-37-03).

## Handoff Note

Plan 02 may now use:
- `DiskRegistryRepository::list_all(pool, agent_id_filter)` — returns `Vec<DiskRegistryRow>` ordered by registered_at ASC
- `DiskRegistryRepository::list_by_agent(pool, agent_id)` — convenience wrapper
- `DiskRegistryRepository::insert(uow, row)` — pure INSERT; propagates UNIQUE error for 409 mapping
- `DiskRegistryRepository::delete_by_id(uow, id)` — returns affected row count
- `dlp_common::Action::DiskRegistryAdd` and `dlp_common::Action::DiskRegistryRemove` for AUDIT-03 audit events

All types are re-exported from `dlp_server::db::repositories` (pub use disk_registry::{DiskRegistryRepository, DiskRegistryRow}).

## Self-Check: PASSED

- dlp-server/src/db/repositories/disk_registry.rs: FOUND (484 lines)
- dlp-common/src/abac.rs: FOUND (modified, 747 lines)
- dlp-server/src/db/mod.rs: FOUND (modified, 741 lines)
- dlp-server/src/db/repositories/mod.rs: FOUND (modified, 32 lines)
- Commit 261caa0: FOUND
- Commit 807b1de: FOUND
- Commit 0c5358f: FOUND
- Commit 50541cb: FOUND
- 19/19 tests pass
- ON CONFLICT count in disk_registry.rs: 0
