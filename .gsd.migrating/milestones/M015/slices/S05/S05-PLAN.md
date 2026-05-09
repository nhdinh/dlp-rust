# S05: Policy Engine Separation (Phase 11)

**Goal:** Separate policy evaluation into dedicated store with caching and background refresh.
**Demo:** PolicyStore with in-memory cache, sync evaluate(), tiered default-deny, cache invalidation on CRUD, background refresh every 5 min.

## Must-Haves

- 1. RwLock<Vec<Policy>> in-memory cache
- 2. Sync evaluate() hot path
- 3. Cache invalidation on CRUD
- 4. Background refresh every 5 min
- 5. 23 policy store unit tests

## Proof Level

- This slice proves: tested

## Integration Closure

Central policy evaluation for all server paths. Cache invalidation wired to admin CRUD.

## Verification

- Cache miss/hit not currently surfaced.

## Tasks

- [x] **T01: Policy engine separation** `est:6h`
  Create PolicyStore with parking_lot::RwLock<Vec<Policy>> in-memory cache. Implement sync evaluate() hot path with tiered default-deny (T1/T2→ALLOW, T3/T4→DENY). Wire cache invalidation on every policy CRUD commit. Add background refresh via tokio::time::interval (5-minute). Create PolicyEngineError enum. Wire POST /evaluate into public_routes. Write 23 unit tests.
  - Files: `dlp-server/src/policy_store.rs`, `dlp-server/src/policy_engine_error.rs`, `dlp-server/src/policy_api.rs`, `dlp-server/tests/policy_store_tests.rs`
  - Verify: cargo test --package dlp-server policy_store::

## Files Likely Touched

- dlp-server/src/policy_store.rs
- dlp-server/src/policy_engine_error.rs
- dlp-server/src/policy_api.rs
- dlp-server/tests/policy_store_tests.rs
