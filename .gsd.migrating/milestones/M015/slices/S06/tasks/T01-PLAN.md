---
estimated_steps: 1
estimated_files: 2
skills_used: []
---

# T01: Repository and unit of work refactor

Create typed Repository structs under dlp-server/src/db/repositories/ for each entity. Implement UnitOfWork<'conn> as RAII transaction wrapper. Migrate 49 raw pool.get() + SQL call sites to use Repository methods. Ensure all writes go through UnitOfWork. Verify all tests pass.

## Inputs

- `Existing raw SQL patterns`
- `Entity schemas`

## Expected Output

- `Repository modules`
- `UnitOfWork struct`
- `49 migrated call sites`
- `Passing tests`

## Verification

cargo test --workspace
