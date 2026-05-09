---
id: T02
parent: S02
milestone: M017
key_files:
  - dlp-agent/src/cloud_enforcer.rs
  - dlp-agent/src/interception/mod.rs
  - dlp-agent/tests/comprehensive.rs
key_decisions:
  - Used classification >= Classification::T3 comparison (PartialOrd on Classification) instead of is_sensitive() to keep the condition explicit and auditable at the call site
  - Kept provisional_classification() as the fail-safe path in interception/mod.rs since it is infallible — avoided unnecessary catch_unwind overhead
  - Added fnv1a_hex() private helper in mod.rs rather than exposing cache.rs hash_str() — keeps the hashing local to the observability need
  - Changed ALLOW branch log from tracing::info! to tracing::trace! to reduce log volume on non-blocking cloud events
duration: 
verification_result: passed
completed_at: 2026-05-09T00:44:00.141Z
blocker_discovered: false
---

# T02: Wire real ABAC classification into CloudEnforcer::check() by adding explicit Classification parameter, removing provisional_sync_classification(), and updating all 22 call sites (18 unit tests + 4 TC-30..33)

**Wire real ABAC classification into CloudEnforcer::check() by adding explicit Classification parameter, removing provisional_sync_classification(), and updating all 22 call sites (18 unit tests + 4 TC-30..33)**

## What Happened

Changed `CloudEnforcer::check()` signature from `(path, action)` to `(path, action, classification: Classification)`. Removed `provisional_sync_classification()` entirely — no dead-code comment, just deleted. The block condition now uses `classification >= Classification::T3` (PartialOrd is derived on Classification, ordering T1 < T2 < T3 < T4).

In `interception/mod.rs`, added classification resolution before the cloud enforcer call site using `PolicyMapper::provisional_classification(&path)`. Added a private `fnv1a_hex()` helper to compute a non-sensitive path hash for the TRACE log (avoids logging raw paths to external sinks). The TRACE log emits `path_hash` + `classification` for each cloud check. `provisional_classification` is infallible so no catch_unwind needed; a comment documents the fail-open T2 policy for any future fallible evaluator integration.

Updated all 11 unit tests in `cloud_enforcer.rs` to pass explicit `Classification` values matching what the test is asserting — T4 for empty/UNC/outside-folder path tests (verifying short-circuit before classification matters), T1/T2 for allow cases, T3/T4 for block cases. Path names in blocking tests were cleaned up to not rely on path-text heuristics (removed "confidential"/"restricted" substrings from test filenames that would have given away the classification — callers now own that mapping).

Updated TC-30..TC-33 in `comprehensive.rs` to pass explicit Classification values: T2 for TC-30 (allow), T3 for TC-31 (confidential block), T4 for TC-32 (restricted block), T4 for TC-33 (outside sync folder — verifies that path outside sync folder returns None regardless of classification).

Added one new test `test_t2_file_in_sync_folder_returns_none` to explicitly cover T2 returning None, which was previously only implicit via the old path-text heuristic default branch.

## Verification

cargo test -p dlp-agent --lib cloud_enforcer: 18 passed, 0 failed. cargo test -p dlp-agent --test comprehensive -- cloud_tc: 4 passed (TC-30..TC-33), 0 failed. cargo build -p dlp-agent: compiles cleanly. Clippy errors in dlp-agent are all pre-existing (service.rs, hook_injector.rs, wfp_manager.rs, and the pre-existing too_many_arguments on run_event_loop) — none introduced by this task.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo build -p dlp-agent` | 0 | ✅ pass | 10580ms |
| 2 | `cargo test -p dlp-agent --lib cloud_enforcer` | 0 | ✅ pass — 18 passed, 0 failed | 420ms |
| 3 | `cargo test -p dlp-agent --test comprehensive -- cloud_tc` | 0 | ✅ pass — 4 passed (TC-30..TC-33), 0 failed | 320ms |

## Deviations

Added one extra test (test_t2_file_in_sync_folder_returns_none) beyond the 11 specified to explicitly cover T2 allow path. Changed ALLOW branch log level from INFO to TRACE (reduces log noise on non-blocking events). Test path names were cleaned of embedded classification keywords to decouple test setup from path-text heuristics.

## Known Issues

None.

## Files Created/Modified

- `dlp-agent/src/cloud_enforcer.rs`
- `dlp-agent/src/interception/mod.rs`
- `dlp-agent/tests/comprehensive.rs`
