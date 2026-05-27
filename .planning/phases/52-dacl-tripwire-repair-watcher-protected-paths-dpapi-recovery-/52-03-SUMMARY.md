---
phase: 52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-
plan: 03
subsystem: dlp-server
tags: [database, repository, protected-paths, dacl-tripwire, sqlite]
dependency_graph:
  requires: []
  provides: [52-05, 52-06]
  affects: [dlp-server/src/db/mod.rs, dlp-server/src/db/repositories/protected_paths.rs, dlp-server/src/db/repositories/mod.rs]
tech_stack:
  added: []
  patterns: [stateless-associated-function-repository, unit-of-work, parameterized-queries]
key_files:
  created:
    - dlp-server/src/db/repositories/protected_paths.rs
  modified:
    - dlp-server/src/db/mod.rs
    - dlp-server/src/db/repositories/mod.rs
decisions:
  - "Added UNIQUE constraint on protected_path_aces.protected_path_id to enable ON CONFLICT upsert for ACE snapshots"
  - "Used i64 != 0 pattern for boolean mapping (is_override) to match existing codebase conventions"
  - "sync_from_labels returns count of newly inserted rows only (not updates), making it idempotent-safe for callers"
metrics:
  duration_seconds: 959
  completed_date: "2026-05-27T04:09:31Z"
  tasks_completed: 3
  tests_added: 14
---

# Phase 52 Plan 03: Protected Paths DB Schema and Repository Summary

**One-liner:** SQLite schema and stateless CRUD repository for the protected paths registry, with conflict-aware auto-population from confirmed T3/T4 labels and canonical ACE snapshot support.

## What Was Built

### 1. Database Schema (dlp-server/src/db/mod.rs)

Two new tables added to `init_tables()`:

- **`protected_paths`** -- The single source of truth for DACL tripwire protection targets:
  - `id` (TEXT PRIMARY KEY), `path` (TEXT NOT NULL UNIQUE), `source` (CHECK 'auto'/'manual')
  - `is_override` (INTEGER NOT NULL DEFAULT 0), `tier` (CHECK 'T3'/'T4')
  - `label_id` (soft FK to labels(id) ON DELETE SET NULL)
  - `created_at`, `updated_at` (TEXT NOT NULL)
  - Indexes: path, source, tier, label_id

- **`protected_path_aces`** -- Canonical ACE snapshots per protected path:
  - `id` (TEXT PRIMARY KEY), `protected_path_id` (TEXT NOT NULL UNIQUE REFERENCES ... ON DELETE CASCADE)
  - `sddl` (TEXT NOT NULL), `created_at`, `updated_at`
  - Index on protected_path_id

### 2. ProtectedPathsRepository (dlp-server/src/db/repositories/protected_paths.rs)

Stateless associated-function pattern matching `AllowlistRepository`:

| Function | Pattern | Description |
|----------|---------|-------------|
| `list_all(pool)` | Pool read | All paths ordered by path ASC |
| `get_by_id(pool, id)` | Pool read | Single path by UUID |
| `insert(uow, row)` | UoW write | Insert new protected path |
| `update(uow, row)` | UoW write | Update existing path |
| `delete_by_id(uow, id)` | UoW write | Delete path (cascades to ACE) |
| `get_ace_by_path_id(pool, path_id)` | Pool read | Get ACE snapshot for path |
| `upsert_ace(uow, row)` | UoW write | Insert or update ACE via ON CONFLICT |
| `sync_from_labels(pool)` | Pool read + UoW write | Auto-populate from confirmed T3/T4 labels |

**Conflict rules for `sync_from_labels`:**
- `source='manual'` exists: SKIP (never overwrite manual entries)
- `source='auto'` exists, same tier: SKIP (idempotent)
- `source='auto'` exists, different tier: UPDATE to stricter tier (T4 > T3)
- No entry exists: INSERT with `source='auto'`

### 3. Module Export (dlp-server/src/db/repositories/mod.rs)

Added `pub mod protected_paths;` and re-exported `ProtectedPathRow`, `ProtectedPathAceRow`, `ProtectedPathsRepository`.

## Test Coverage

14 unit tests in `protected_paths.rs` (all passing):

| Test | What it verifies |
|------|-----------------|
| `test_list_all_empty` | Empty DB returns empty vec |
| `test_insert_and_get_by_id` | Roundtrip insert + read all fields |
| `test_insert_duplicate_path_fails` | UNIQUE constraint on path |
| `test_update_changes_fields` | Update persists tier, is_override, updated_at |
| `test_delete_by_id_cascades_to_aces` | ON DELETE CASCADE removes ACE rows |
| `test_delete_by_id_nonexistent_returns_zero` | Graceful no-op on missing ID |
| `test_sync_from_labels_auto_populates` | Confirmed T3/T4 labels create auto entries |
| `test_sync_from_labels_idempotent` | Second sync is 0 inserts |
| `test_sync_preserves_manual_entries` | Manual entries never overwritten |
| `test_sync_updates_auto_tier_conflict` | Auto T3 -> T4 updates to stricter tier |
| `test_sync_skips_non_confirmed_labels` | Temporary and T2 labels ignored |
| `test_upsert_ace_roundtrip` | Insert then update ACE via ON CONFLICT |
| `test_check_constraint_rejects_invalid_source` | CHECK constraint on source |
| `test_check_constraint_rejects_invalid_tier` | CHECK constraint on tier |

Plus updated `test_tables_created` in `db/mod.rs` to assert both new tables exist.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Missing UNIQUE constraint on protected_path_aces.protected_path_id**
- **Found during:** Task 2 (test execution)
- **Issue:** `upsert_ace` used `ON CONFLICT(protected_path_id)` but the column had no UNIQUE constraint, causing "ON CONFLICT clause does not match any PRIMARY KEY or UNIQUE constraint"
- **Fix:** Added `UNIQUE` to `protected_path_id` column in `protected_path_aces` table DDL
- **Files modified:** `dlp-server/src/db/mod.rs`
- **Commit:** 6376d2f

**2. [Rule 1 - Bug] Unused import and variable warnings**
- **Found during:** Task 2 (compilation)
- **Issue:** `LabelRepository` and `LabelUpsertRow` imports unused in tests; `existing_tier` binding unused in manual-entry match arm
- **Fix:** Removed unused import; prefixed unused binding with underscore
- **Files modified:** `dlp-server/src/db/repositories/protected_paths.rs`
- **Commit:** 6376d2f

## Quality Gates

| Gate | Status |
|------|--------|
| `cargo test -p dlp-server` | PASSED (all 518 tests) |
| `cargo clippy -p dlp-server -- -D warnings` | PASSED |
| `cargo build -p dlp-server` | PASSED |
| All new functions have doc comments | YES |
| All new functions have unit tests | YES (14 tests) |

## Self-Check: PASSED

- [x] `dlp-server/src/db/repositories/protected_paths.rs` exists
- [x] `dlp-server/src/db/mod.rs` modified with new tables
- [x] `dlp-server/src/db/repositories/mod.rs` modified with module declaration
- [x] Commit f0a919a exists (table schema)
- [x] Commit 6376d2f exists (repository)

## Commits

- `f0a919a` -- feat(52-03): add protected_paths and protected_path_aces tables to DB schema
- `6376d2f` -- feat(52-03): create ProtectedPathsRepository with CRUD and conflict-aware sync
