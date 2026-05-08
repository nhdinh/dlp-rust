---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Comprehensive DLP test suite

Write 32 agent test cases in comprehensive.rs covering file_ops, email_alert, cloud, clipboard_tier, print, detective. Write 15 server test cases in admin_api.rs. Write 6 E2E integration tests covering full intercept→classify→engine→audit→JSONL pipeline. Ensure 364/364 workspace tests pass.

## Inputs

- `Test case specifications`
- `Existing test harnesses`

## Expected Output

- `Agent comprehensive tests`
- `Server admin API tests`
- `E2E integration tests`
- `364 passing tests`

## Verification

cargo test --workspace
