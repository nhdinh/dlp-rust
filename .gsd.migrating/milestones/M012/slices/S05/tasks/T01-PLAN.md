---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Automated UAT infrastructure

Create dlp-e2e workspace member. Write headless TUI tests for Device Registry, Managed Origins, and Conditions Builder screens. Write E2E agent TOML write-back test. Write hot-reload verification for all config types. Write USB unit tests with mocked Win32 APIs. Write PowerShell script for real-hardware USB verification. Add cargo test --workspace to GitHub Actions. Add nightly CI for release-mode build.

## Inputs

- `Existing test patterns`
- `ratatui test harness`
- `GitHub Actions`

## Expected Output

- `dlp-e2e crate`
- `Headless TUI tests`
- `E2E TOML test`
- `Hot-reload tests`
- `Mocked USB tests`
- `PowerShell script`
- `GitHub Actions workflow`

## Verification

cargo test --workspace
