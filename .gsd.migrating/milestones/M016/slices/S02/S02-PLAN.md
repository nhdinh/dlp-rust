# S02: Comprehensive DLP Test Suite (Phases 04.1, 12)

**Goal:** Build comprehensive test coverage across all DLP test cases.
**Demo:** 32 agent TCs + 15 server TCs + 6 E2E TCs covering all 28 test cases. Comprehensive intercept→classify→engine→audit→JSONL pipeline.

## Must-Haves

- 1. 32 agent test cases
- 2. 15 server test cases
- 3. 6 E2E integration tests
- 4. 364/364 workspace tests pass
- 5. Full intercept pipeline covered

## Proof Level

- This slice proves: tested

## Integration Closure

Validates all v0.2.0 features end-to-end. Gates future refactoring.

## Verification

- CI test results.

## Tasks

- [x] **T01: Comprehensive DLP test suite** `est:8h`
  Write 32 agent test cases in comprehensive.rs covering file_ops, email_alert, cloud, clipboard_tier, print, detective. Write 15 server test cases in admin_api.rs. Write 6 E2E integration tests covering full intercept→classify→engine→audit→JSONL pipeline. Ensure 364/364 workspace tests pass.
  - Files: `dlp-agent/tests/comprehensive.rs`, `dlp-server/tests/integration.rs`, `dlp-agent/tests/integration.rs`
  - Verify: cargo test --workspace

## Files Likely Touched

- dlp-agent/tests/comprehensive.rs
- dlp-server/tests/integration.rs
- dlp-agent/tests/integration.rs
