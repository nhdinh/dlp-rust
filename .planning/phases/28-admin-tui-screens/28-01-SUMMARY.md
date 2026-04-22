---
phase: 28-admin-tui-screens
plan: "01"
subsystem: dlp-server
tags: [managed-origins, sqlite, repository, http-api, axum]
dependency_graph:
  requires: []
  provides: [managed-origins-api, managed-origins-repository]
  affects: [dlp-server/src/db/mod.rs, dlp-server/src/db/repositories/managed_origins.rs, dlp-server/src/admin_api.rs, dlp-server/src/lib.rs]
tech_stack:
  added: []
  patterns: [repository-pattern, unit-of-work, spawn-blocking, appstate-arc]
key_files:
  created:
    - dlp-server/src/db/repositories/managed_origins.rs
  modified:
    - dlp-server/src/db/mod.rs
    - dlp-server/src/db/repositories/mod.rs
    - dlp-server/src/admin_api.rs
    - dlp-server/src/lib.rs
decisions:
  - "AppError::Conflict added as new variant (409) — no existing variant covered UNIQUE constraint violations cleanly"
  - "GET /admin/managed-origins is unauthenticated per D-08 — Phase 29 connector polls without JWT"
  - "Duplicate origin detection uses SQLite extended error code 2067 (SQLITE_CONSTRAINT_UNIQUE) — mirrors existing device registry error pattern"
metrics:
  duration_seconds: 377
  completed_date: "2026-04-22"
  tasks_completed: 2
  files_changed: 5
---

# Phase 28 Plan 01: Managed Origins DB + API Summary

**One-liner:** SQLite `managed_origins` table with `ManagedOriginsRepository` (list/insert/delete) and three axum HTTP handlers (`GET` unauthenticated, `POST`/`DELETE` JWT-protected) wired into `admin_router`.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| T-28-01-01 | managed_origins DDL + repository | c23da04 | db/mod.rs, repositories/managed_origins.rs, repositories/mod.rs |
| T-28-01-02 | managed-origins HTTP handlers + route registration | aabdf05 | admin_api.rs, lib.rs |

## What Was Built

### Task 1: DDL + Repository

- Added `managed_origins` table DDL inside the existing `init_tables` `execute_batch` call in `dlp-server/src/db/mod.rs`. Schema: `id TEXT PRIMARY KEY, origin TEXT NOT NULL UNIQUE`.
- Created `dlp-server/src/db/repositories/managed_origins.rs` following the `device_registry.rs` pattern exactly: `ManagedOriginRow` plain data struct, stateless `ManagedOriginsRepository` with `list_all`, `insert`, `delete_by_id`.
- Added `pub mod managed_origins` and re-export of `ManagedOriginRow`/`ManagedOriginsRepository` to `repositories/mod.rs`.
- 4 unit tests all pass: `test_list_all_empty`, `test_insert_and_list`, `test_delete_removes_row`, `test_duplicate_origin_errors`.

### Task 2: HTTP Handlers + Routes

- Added `AppError::Conflict(String)` variant to `lib.rs` (maps to HTTP 409); added match arm in `IntoResponse`.
- Added `ManagedOriginRequest` (Deserialize) and `ManagedOriginResponse` (Serialize) structs to `admin_api.rs`.
- Implemented three handlers:
  - `list_managed_origins_handler` — `GET /admin/managed-origins`, unauthenticated, `spawn_blocking` pool read.
  - `create_managed_origin_handler` — `POST /admin/managed-origins`, JWT-protected, UUID generated server-side, detects duplicate via SQLite extended error code 2067, returns `AppError::Conflict` (409).
  - `delete_managed_origin_handler` — `DELETE /admin/managed-origins/{id}`, JWT-protected, returns 204 on success, 404 on missing id.
- Registered GET in `public_routes` block; POST and DELETE in `protected_routes` block.
- All 169 dlp-server tests pass after changes.

## Deviations from Plan

### Auto-added: AppError::Conflict variant

**Rule 2 — Missing critical functionality**
- **Found during:** Task 2, pre-implementation review
- **Issue:** `AppError` had no `Conflict` variant; the plan's handler code required `AppError::Conflict("origin already exists")` to return 409 but the enum did not define it.
- **Fix:** Added `Conflict(String)` variant to the `AppError` enum in `lib.rs` with `#[error("conflict: {0}")]` and a `StatusCode::CONFLICT` arm in `IntoResponse`.
- **Files modified:** `dlp-server/src/lib.rs`
- **Commit:** aabdf05

## Known Stubs

None — all three endpoints are fully wired to the live SQLite pool.

## Threat Flags

None — all endpoints follow the established trust boundary pattern (GET unauthenticated per D-08 design decision; POST/DELETE behind `require_auth` middleware).

## Self-Check: PASSED

- `dlp-server/src/db/repositories/managed_origins.rs` — EXISTS
- `dlp-server/src/db/mod.rs` contains `CREATE TABLE IF NOT EXISTS managed_origins` — VERIFIED
- `dlp-server/src/db/repositories/mod.rs` contains `pub mod managed_origins` — VERIFIED
- `dlp-server/src/admin_api.rs` contains `list_managed_origins_handler` — VERIFIED
- Commit c23da04 — EXISTS (`feat(28-01): add managed_origins DDL and repository`)
- Commit aabdf05 — EXISTS (`feat(28-01): add managed-origins HTTP handlers and route registration`)
- `cargo build -p dlp-server` errors: 0
- `cargo test -p dlp-server` failures: 0 (169 passed)
