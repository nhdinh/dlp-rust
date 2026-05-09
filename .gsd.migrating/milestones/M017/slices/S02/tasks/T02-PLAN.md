---
estimated_steps: 10
estimated_files: 3
skills_used: []
---

# T02: Wire real ABAC classification into CloudEnforcer::check() and update all call sites

Replace `provisional_sync_classification()` with an explicit `Classification` parameter on `check()`. Update `interception/mod.rs` to resolve classification via `AbacEvaluator` before calling `enforcer.check()`. Update all test call sites (11 unit tests in `cloud_enforcer.rs`, TC-30..TC-33 in `comprehensive.rs`) to pass explicit `Classification` values.

**Steps:**
1. In `cloud_enforcer.rs`, change `check()` signature from `pub fn check(&self, path: &str, action: &FileAction) -> Option<CloudBlockResult>` to `pub fn check(&self, path: &str, action: &FileAction, classification: Classification) -> Option<CloudBlockResult>`. Remove `provisional_sync_classification()` entirely (deletion, not dead-code comment).
2. Inside `check()`, use the passed `classification` directly in the T3/T4 block condition: `if classification >= Classification::T3 && action is write/create/move`.
3. In `dlp-agent/src/interception/mod.rs`, at the cloud enforcer call site (currently `enforcer.check(&path, &action)`): call the existing `PolicyMapper`/`AbacEvaluator` to resolve `Classification` for the path before the cloud check. The evaluator is already in scope. Extract a `classification` value from it (or use `Classification::T2` as the pre-ABAC default if the evaluator call fails — log at WARN). Pass `classification` as the third arg.
4. Update all 11 unit tests in `cloud_enforcer.rs`'s `#[cfg(test)]` block to pass `Classification::T4`, `Classification::T3`, or `Classification::T2` as the third argument, matching what the test is asserting about. The keyword-based mapping (`"confidential"` → T3, `"restricted"` → T4) should be explicit in the test setup, not inferred from path text.
5. Update TC-30, TC-31, TC-32, TC-33 in `dlp-agent/tests/comprehensive.rs` to pass the appropriate `Classification` third argument.
6. Verify `#[allow(dead_code)]` or removal of `PipeError::Timeout` variant if still flagged — leave it with `#[allow(dead_code)]` since S02 does not implement timeout yet.
7. Run `cargo clippy --workspace -- -D warnings` and fix any new warnings introduced by the signature change.

**Key constraint:** The block condition logic in `check()` must not regress — T4 writes to sync folders must still block, T1 reads must still pass. Ensure the classification comparison uses `>=` on the Classification enum (verify that `Classification` derives `PartialOrd` in `dlp-common/src/abac.rs`).

## Inputs

- `dlp-agent/src/cloud_enforcer.rs`
- `dlp-agent/src/interception/mod.rs`
- `dlp-agent/tests/comprehensive.rs`
- `dlp-common/src/abac.rs`

## Expected Output

- `dlp-agent/src/cloud_enforcer.rs`
- `dlp-agent/src/interception/mod.rs`
- `dlp-agent/tests/comprehensive.rs`

## Verification

cargo test -p dlp-agent cloud_enforcer && cargo test -p dlp-agent --test comprehensive -- cloud_tc 2>&1 | tail -10

## Observability Impact

ABAC resolution failure in cloud check path logs `path_hash` + error at WARN and fails open (allows) to avoid blocking legitimate I/O on evaluator unavailability. Classification result logged at TRACE level with provider and path_hash for debugging.
