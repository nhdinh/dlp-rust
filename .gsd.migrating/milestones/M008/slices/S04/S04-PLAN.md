# S04: UAT & Regression Validation

**Goal:** Complete outstanding UAT and verify no regressions across all enforcement paths.
**Demo:** SanDisk re-registered with full 128-char serial. ReadOnly and FullAccess trust tiers enforced correctly. All workspace tests pass. SonarQube gate clean.

## Must-Haves

- 1. SanDisk full 128-char serial registration works
- 2. All workspace tests pass
- 3. Clippy/fmt clean
- 4. No regressions

## Proof Level

- This slice proves: tested

## Integration Closure

Final validation gate. No downstream dependencies.

## Verification

- Regression test results in CI artifacts.

## Tasks

- [x] **T01: UAT and regression validation** `est:3h`
  Complete SanDisk re-registration with full 128-char serial for ReadOnly/FullAccess enforcement test. Run full workspace test suite. Verify clippy clean and fmt clean. Run SonarQube scan if token available. Document any physical-hardware UAT gaps.
  - Verify: cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt -- --check
