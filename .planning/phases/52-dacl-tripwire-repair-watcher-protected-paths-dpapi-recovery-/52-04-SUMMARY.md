---
phase: 52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-
plan: 04
subsystem: dlp-agent
tags: [dacl, staging, sqlite, concurrency, state-machine]
dependency_graph:
  requires: [52-01]
  provides: [52-07]
  affects: [dlp-agent/src/service.rs]
tech_stack:
  added: [dashmap, parking_lot]
  patterns: [per-path-locking, state-machine, ttl-gc]
key_files:
  created:
    - dlp-agent/src/dacl_staging.rs
  modified:
    - dlp-agent/src/lib.rs
    - dlp-agent/src/service.rs
decisions:
  - "Used Arc<parking_lot::Mutex<()>> in DashMap for per-path locking to avoid borrow checker issues with returning guards across DashMap entry boundaries"
  - "Used with_path_lock closure pattern instead of returning MutexGuard to sidestep lifetime constraints"
  - "State machine uses database-derived state (applied_at + operation) rather than persisting enum to SQLite for simplicity"
  - "WatcherSuppressed is a runtime-only state (Plan 52-07 integration), not persisted in DB"
metrics:
  duration: "~25 minutes"
  completed_date: "2026-05-27"
---

# Phase 52 Plan 04: DACL Staging Data Layer Summary

**One-liner:** SQLite-backed staging table with explicit state machine, per-path locking via DashMap, and TTL GC for the two-phase staged update protocol.

## What Was Built

### 1. `dlp-agent/src/dacl_staging.rs` (new, ~900 lines)

A complete data layer module providing:

- **`StagingState` enum**: `Staged -> WatcherSuppressed -> AclRemoved -> Applied -> GC`
- **`StagingRow` struct**: Path, operation, staged_at, applied_at, derived state
- **`DaclStagingError`**: `thiserror`-based errors covering SQLite, invalid operations, state machine violations, and lock poisoning
- **`init_staging_table(conn)`**: Creates `protected_paths_staging` table with:
  - `path TEXT PRIMARY KEY`
  - `operation TEXT NOT NULL CHECK(operation IN ('add', 'remove'))`
  - `staged_at TEXT NOT NULL`
  - `applied_at TEXT`
  - Two indexes: `idx_staging_applied`, `idx_staging_staged_at`
- **`DaclStaging` struct**: Owns SQLite connection + per-path locks
  - `new(db_path)`: Opens connection, initializes table
  - `from_connection(conn)`: For tests
  - `stage_removal(path)`: INSERT OR REPLACE 'remove' row
  - `stage_add(path)`: INSERT OR REPLACE 'add' row
  - `mark_applied(path)`: UPDATE applied_at = now
  - `is_staged(path)`: True if any row exists
  - `is_staged_and_applied(path)`: True if row with applied_at NOT NULL
  - `get_state(path)`: Returns `Option<StagingState>`
  - `get_row(path)`: Returns `Option<StagingRow>`
  - `list_all()`: Returns all rows
  - `gc_expired_rows(ttl_minutes)`: DELETE applied rows older than TTL
- **`stage_removals(db, paths)`**: Free function for batch integration with config diff logic (Plan 52-07)
- **`spawn_gc_task(staging, interval, ttl, shutdown_rx)`**: Background tokio task for periodic GC

### 2. `dlp-agent/src/service.rs` (modified)

- `init_agent_db()` now calls `crate::dacl_staging::init_staging_table(&conn)` after `offline_audit_queue` init

### 3. `dlp-agent/src/lib.rs` (modified)

- Added `#[cfg(windows)] pub mod dacl_staging;`

## Test Coverage

15 unit tests (all passing):

| Test | Coverage |
|------|----------|
| `test_staging_state_machine_transitions` | Staged -> AclRemoved -> Applied |
| `test_per_path_lock_serializes_concurrent_ops` | 10 threads, same path, no SQLite busy |
| `test_per_path_lock_allows_concurrent_different_paths` | 5 threads, different paths, no deadlock |
| `test_gc_removes_expired_applied_rows` | 6-min-old applied row deleted with 5-min TTL |
| `test_gc_preserves_unapplied_rows` | Unapplied row preserved regardless of age |
| `test_gc_preserves_recent_applied_rows` | 2-min-old applied row preserved |
| `test_staging_add_operation` | Add operation inserts correctly |
| `test_mark_applied_idempotent` | Double mark_applied is no-op |
| `test_staging_row_roundtrip` | get_row returns correct fields |
| `test_batch_stage_removals` | 3 paths staged via free function |
| `test_is_staged_and_applied` | Both states checked correctly |
| `test_list_all` | All rows returned |
| `test_init_staging_table_creates_schema` | Table + CHECK constraint verified |
| `test_get_row_returns_none_for_missing` | Missing path returns None |
| `test_stage_removal_replaces_existing` | INSERT OR REPLACE behavior |

## Quality Gates

| Gate | Status |
|------|--------|
| `cargo test -p dlp-agent --lib -- dacl_staging::tests` | PASS (15/15) |
| `cargo clippy -p dlp-agent -- -D warnings` | PASS (0 errors) |
| `cargo fmt --check -p dlp-agent` | PASS |
| `cargo build -p dlp-agent` | PASS |

## Deviations from Plan

### Auto-fixed Issues (Rule 3 — blocking)

**1. [Rule 3 — Blocking] Fixed `dacl_repair_watcher.rs` compilation errors**
- **Found during:** Task 1 (compilation blocked)
- **Issue:** `dacl_repair_watcher.rs` (Plan 52-02, untracked) had three compilation errors:
  - `WIN32_ERROR(0x80004005_u32)` literal out of range for `i32` in `HRESULT` constructor
  - `ReadDirectoryChangesW` called with `&mut bytes_returned` but API expects `Option<*mut u32>`
  - Unused constants `DEBOUNCE_MIN`, `MAX_BACKSTOP_FILES` and unused import `WIN32_ERROR`
- **Fix:** Changed to `0x80004005u32 as i32`, wrapped arg in `Some()`, removed unused items
- **Files modified:** `dlp-agent/src/dacl_repair_watcher.rs`
- **Note:** This file is from Plan 52-02 and remains untracked; fixes were needed to unblock build

### Design Adjustments

**1. Per-path locking implementation**
- **Plan specified:** `DashMap<PathBuf, Mutex<()>>` with returned guard
- **Actual:** `DashMap<String, Arc<parking_lot::Mutex<()>>>` with `with_path_lock` closure pattern
- **Reason:** Returning a `MutexGuard` that borrows from a `DashMap` entry violates Rust borrow checker (entry is local). The closure pattern encapsulates the lock lifetime correctly.

**2. State machine persistence**
- **Plan specified:** `StagingRow.state` field stored in struct
- **Actual:** `state` is derived at read time from `operation` + `applied_at`
- **Reason:** Avoids schema migration and denormalization. The state is unambiguously derivable.

## Known Stubs

None. All planned functionality is implemented and tested.

## Threat Flags

None beyond what is documented in the plan's threat model. No new network endpoints, auth paths, or file access patterns introduced.

## Self-Check: PASSED

- [x] `dlp-agent/src/dacl_staging.rs` exists (903 lines)
- [x] `dlp-agent/src/lib.rs` exports `dacl_staging`
- [x] `dlp-agent/src/service.rs` calls `init_staging_table`
- [x] Commit `c8c2787` exists and contains the changes
- [x] All 15 tests pass
- [x] Clippy passes with `-D warnings`
- [x] `cargo fmt --check` passes
- [x] `cargo build -p dlp-agent` succeeds
