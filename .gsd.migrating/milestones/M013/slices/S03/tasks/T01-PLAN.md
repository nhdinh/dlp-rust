---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Operator expansion

Add gt, lt, ne, contains operators to PolicyCondition. Filter operator picker by attribute type in conditions builder step 2. Implement evaluator branches: gt/lt for Classification (T1<T2<T3<T4), ne as negation, contains as substring for MemberOf. Reset operator selection when attribute changes. Add unit tests.

## Inputs

- `Existing PolicyCondition`
- `S02 conditions builder`

## Expected Output

- `Expanded operator enum`
- `Filtered operator picker`
- `Evaluator branches`
- `Unit tests`

## Verification

cargo test --package dlp-server policy_store:: && cargo test --package dlp-admin-cli
