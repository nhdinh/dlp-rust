# S03: Operator Expansion (Phase 20)

**Goal:** Expand per-condition operator set with attribute-type-aware filtering.
**Demo:** Conditions builder shows attribute-type-aware operators (gt, lt, ne, contains). Evaluator honors expanded operators.

## Must-Haves

- 1. Operator picker filtered by attribute type
- 2. gt/lt for Classification, contains for MemberOf
- 3. v0.4.0 policies evaluate identically
- 4. Unit tests for each new operator

## Proof Level

- This slice proves: tested

## Integration Closure

Consumes S02 conditions builder. Touches evaluator and TUI together.

## Verification

- None — engine behavior.

## Tasks

- [x] **T01: Operator expansion** `est:4h`
  Add gt, lt, ne, contains operators to PolicyCondition. Filter operator picker by attribute type in conditions builder step 2. Implement evaluator branches: gt/lt for Classification (T1<T2<T3<T4), ne as negation, contains as substring for MemberOf. Reset operator selection when attribute changes. Add unit tests.
  - Files: `dlp-common/src/abac.rs`, `dlp-admin-cli/src/screens/render.rs`, `dlp-server/src/policy_store.rs`
  - Verify: cargo test --package dlp-server policy_store:: && cargo test --package dlp-admin-cli

## Files Likely Touched

- dlp-common/src/abac.rs
- dlp-admin-cli/src/screens/render.rs
- dlp-server/src/policy_store.rs
