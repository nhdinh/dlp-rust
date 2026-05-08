---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: SQLite connection pool

Replace parking_lot::Mutex<Connection> with r2d2/r2d2_sqlite connection pool. Update AppState { pool: db::Pool } to derive Clone. Update all handlers to use pool.get(). Add From<r2d2::Error> implementations on AppError, SiemError, AlertError. Verify 220 workspace tests pass.

## Inputs

- `r2d2_sqlite crate`
- `Existing handler patterns`

## Expected Output

- `Connection pool in AppState`
- `Handler updates`
- `Error conversions`
- `Passing tests`

## Verification

cargo test --workspace
