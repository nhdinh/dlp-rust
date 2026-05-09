# S06: Repository + Unit of Work (Phase 99)

**Goal:** Migrate raw SQL to typed repositories with unit-of-work transactions.
**Demo:** 49 raw SQL call sites migrated to typed Repository structs. All writes go through UnitOfWork RAII transaction.

## Must-Haves

- 1. Repository structs under db/repositories/
- 2. UnitOfWork<'conn> for transactions
- 3. 49 call sites migrated
- 4. All tests pass

## Proof Level

- This slice proves: tested

## Integration Closure

Cross-milestone refactor that stabilizes all DB access patterns.

## Verification

- None — internal refactor.

## Tasks

- [x] **T01: Repository and unit of work refactor** `est:6h`
  Create typed Repository structs under dlp-server/src/db/repositories/ for each entity. Implement UnitOfWork<'conn> as RAII transaction wrapper. Migrate 49 raw pool.get() + SQL call sites to use Repository methods. Ensure all writes go through UnitOfWork. Verify all tests pass.
  - Files: `dlp-server/src/db/repositories/`, `dlp-server/src/db.rs`
  - Verify: cargo test --workspace

## Files Likely Touched

- dlp-server/src/db/repositories/
- dlp-server/src/db.rs
