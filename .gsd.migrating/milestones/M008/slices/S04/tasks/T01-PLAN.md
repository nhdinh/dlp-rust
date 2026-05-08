---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: UAT and regression validation

Complete SanDisk re-registration with full 128-char serial for ReadOnly/FullAccess enforcement test. Run full workspace test suite. Verify clippy clean and fmt clean. Run SonarQube scan if token available. Document any physical-hardware UAT gaps.

## Inputs

- `All prior slices complete`
- `Physical SanDisk device`

## Expected Output

- `UAT validation report`
- `Test suite results`
- `SonarQube results (if available)`

## Verification

cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt -- --check
