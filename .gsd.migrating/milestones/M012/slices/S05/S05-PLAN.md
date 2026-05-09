# S05: Automated UAT Infrastructure (Phase 30)

**Goal:** Replace manual human UAT with automated verification.
**Demo:** Headless TUI tests, E2E agent TOML write-back, hot-reload verification, CI build gates.

## Must-Haves

- 1. Headless TUI tests for Device Registry, Origins, Conditions Builder
- 2. E2E agent TOML write-back test
- 3. Hot-reload verification
- 4. GitHub Actions CI gate
- 5. PowerShell real-hardware USB verification script

## Proof Level

- This slice proves: tested

## Integration Closure

Validates all prior slices end-to-end.

## Verification

- CI artifacts for all test suites.

## Tasks

- [x] **T01: Automated UAT infrastructure** `est:8h`
  Create dlp-e2e workspace member. Write headless TUI tests for Device Registry, Managed Origins, and Conditions Builder screens. Write E2E agent TOML write-back test. Write hot-reload verification for all config types. Write USB unit tests with mocked Win32 APIs. Write PowerShell script for real-hardware USB verification. Add cargo test --workspace to GitHub Actions. Add nightly CI for release-mode build.
  - Files: `dlp-e2e/src/lib.rs`, `.github/workflows/build.yml`, `dlp-agent/tests/usb_mock.rs`
  - Verify: cargo test --workspace

## Files Likely Touched

- dlp-e2e/src/lib.rs
- .github/workflows/build.yml
- dlp-agent/tests/usb_mock.rs
