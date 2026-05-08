# S04: SQLite Connection Pool (Phase 10)

**Goal:** Replace single mutex with connection pool for concurrent API handling.
**Demo:** r2d2 SQLite connection pool replaces single Mutex<Connection>. Concurrent requests execute in parallel.

## Must-Haves

- 1. r2d2 pool in AppState
- 2. All handlers use pool.get()
- 3. Concurrent requests parallelize
- 4. 220 workspace tests pass

## Proof Level

- This slice proves: tested

## Integration Closure

Enables concurrent handler execution for all server endpoints.

## Verification

- None — performance improvement.

## Tasks

- [x] **T01: SQLite connection pool** `est:3h`
  Replace parking_lot::Mutex<Connection> with r2d2/r2d2_sqlite connection pool. Update AppState { pool: db::Pool } to derive Clone. Update all handlers to use pool.get(). Add From<r2d2::Error> implementations on AppError, SiemError, AlertError. Verify 220 workspace tests pass.
  - Files: `dlp-server/src/db.rs`, `dlp-server/src/lib.rs`, `dlp-server/src/main.rs`
  - Verify: cargo test --workspace

## Files Likely Touched

- dlp-server/src/db.rs
- dlp-server/src/lib.rs
- dlp-server/src/main.rs
