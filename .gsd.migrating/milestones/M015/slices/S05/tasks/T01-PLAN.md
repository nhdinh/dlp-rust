---
estimated_steps: 1
estimated_files: 4
skills_used: []
---

# T01: Policy engine separation

Create PolicyStore with parking_lot::RwLock<Vec<Policy>> in-memory cache. Implement sync evaluate() hot path with tiered default-deny (T1/T2→ALLOW, T3/T4→DENY). Wire cache invalidation on every policy CRUD commit. Add background refresh via tokio::time::interval (5-minute). Create PolicyEngineError enum. Wire POST /evaluate into public_routes. Write 23 unit tests.

## Inputs

- `Existing policy DB schema`
- `ABAC evaluator`

## Expected Output

- `PolicyStore module`
- `PolicyEngineError enum`
- `Evaluate endpoint`
- `Cache invalidation`
- `Background refresh`
- `23 unit tests`

## Verification

cargo test --package dlp-server policy_store::
