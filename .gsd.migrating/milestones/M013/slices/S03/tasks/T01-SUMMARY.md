---
id: T01
parent: S03
milestone: M013
key_files:
  - dlp-common/src/abac.rs
  - dlp-admin-cli/src/screens/render.rs
  - dlp-server/src/policy_store.rs
key_decisions:
  - (none)
duration: 
verification_result: passed
completed_at: 2026-05-08T05:45:45.348Z
blocker_discovered: false
---

# T01: Attribute-type-aware operator expansion in evaluator and TUI.

**Attribute-type-aware operator expansion in evaluator and TUI.**

## What Happened

Added gt, lt, ne, contains operators to PolicyCondition. Filtered operator picker by attribute type. Implemented evaluator branches: gt/lt for Classification, contains for MemberOf. Reset operator on attribute change. Added unit tests for each operator.

## Verification

Policy store and admin TUI tests pass.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test --package dlp-server policy_store:: && cargo test --package dlp-admin-cli` | 0 | ✅ pass | 20000ms |

## Deviations

None. Completed during original v0.5.0 phase execution (2026-04-21).

## Known Issues

None.

## Files Created/Modified

- `dlp-common/src/abac.rs`
- `dlp-admin-cli/src/screens/render.rs`
- `dlp-server/src/policy_store.rs`
