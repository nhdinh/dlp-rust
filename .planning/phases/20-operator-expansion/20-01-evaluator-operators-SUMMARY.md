---
phase: 20-operator-expansion
plan: 01
subsystem: policy-engine
tags: [abac, policy-store, evaluator, rust, classification, memberof, operators]

# Dependency graph
requires:
  - phase: 18-boolean-mode-engine-wire-format
    provides: PolicyMode enum, boolean evaluate() switch — engine foundation for this work
  - phase: 19-boolean-mode-tui-import-export
    provides: condition_matches() stable call pattern this extends
provides:
  - compare_op_classification() — ordinal gt/lt for Classification conditions
  - classification_ord() — private helper mapping T1=1..T4=4 (per D-03)
  - memberof_matches() "contains" arm — case-sensitive SID substring match
  - 6 new unit tests covering all new operators and boundary conditions
affects:
  - 20-02-tui-operator-picker (TUI now surfaces operators the evaluator honors)
  - 21-in-place-condition-editing (condition editing builds on the operator set)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Ordinal comparison via private helper rather than PartialOrd derive on shared enum (D-03)"
    - "Specialised compare_op_classification() separate from generic compare_op<T: PartialEq> for type-specific semantics"

key-files:
  created: []
  modified:
    - dlp-server/src/policy_store.rs

key-decisions:
  - "compare_op_classification() is separate from compare_op<T> because ordinal semantics differ from PartialEq (D-02)"
  - "classification_ord() lives in policy_store.rs, not dlp-common, to avoid coupling risk on shared enum (D-03)"
  - "contains arm in memberof_matches performs case-sensitive substring match on raw SID string — no AD round-trip (D-05)"

patterns-established:
  - "Attribute-specific comparison functions (compare_op_classification) for semantics that differ from generic PartialEq"

requirements-completed:
  - POLICY-11

# Metrics
duration: 18min
completed: 2026-04-21
---

# Phase 20 Plan 01: Evaluator Operators Summary

**ABAC evaluator extended with ordinal gt/lt for Classification and case-sensitive contains for MemberOf SID substring match, backed by 6 new unit tests**

## Performance

- **Duration:** ~18 min
- **Started:** 2026-04-20T20:00:00Z
- **Completed:** 2026-04-20T20:17:32Z
- **Tasks:** 1 (all 6 plan steps are a single atomic implementation task)
- **Files modified:** 1

## Accomplishments

- Added `compare_op_classification()` for ordinal `gt`/`lt` on Classification conditions (T1=1, T2=2, T3=3, T4=4)
- Added private `classification_ord()` helper — keeps ordinal logic out of `dlp-common`'s shared `Classification` enum (D-03)
- Updated `condition_matches()` Classification arm to use `compare_op_classification` instead of generic `compare_op`
- Added `"contains"` arm to `memberof_matches()` for case-sensitive SID substring match (D-05)
- Added 6 unit tests: `test_compare_op_classification_gt`, `test_compare_op_classification_lt`, `test_compare_op_classification_boundary`, `test_memberof_matches_contains`, `test_memberof_matches_contains_no_match`, `test_memberof_matches_neq`
- All 125 + 12 integration tests pass, zero clippy warnings, rustfmt clean

## Task Commits

1. **Evaluator operator extension** - `4f4ee6a` (feat)

**Plan metadata:** (see final commit below)

## Files Created/Modified

- `dlp-server/src/policy_store.rs` — added `compare_op_classification()`, `classification_ord()`, `"contains"` arm in `memberof_matches()`, updated `condition_matches()` call site, 6 new tests

## Decisions Made

- Used a separate `compare_op_classification()` function rather than extending the generic `compare_op<T: PartialEq>` — ordinal semantics (tier numbers) are fundamentally different from structural equality comparison (D-02)
- `classification_ord()` placed in `policy_store.rs` as a private helper, not added to `dlp-common::Classification` — avoids coupling risk where a `PartialOrd` derive or method on the shared enum could have unintended side effects on all consumers across crates (D-03)
- `contains` in `memberof_matches` performs substring match on the raw SID string (case-sensitive) — no AD lookup required, SIDs are the canonical identifier in the ABAC system (D-05/D-06)

## Deviations from Plan

None - plan executed exactly as written. The `cargo fmt` step required one application of `cargo fmt -p dlp-server` (expected — test assertions exceeded line length and were reformatted by rustfmt).

## Issues Encountered

- `cargo build -p dlp-server` failed with "Access is denied" on `target/debug/dlp-server.exe` — the running dlp-server process holds the lock. Resolved using the documented workaround: `CARGO_TARGET_DIR=target-test cargo build -p dlp-server` (known issue recorded in STATE.md).

## User Setup Required

None - no external service configuration required.

## Known Stubs

None — all new functionality is fully wired: `compare_op_classification` is called from `condition_matches`, `classification_ord` is called from `compare_op_classification`, and `contains` is in `memberof_matches`.

## Next Phase Readiness

- Phase 20-02 (TUI operator picker) can now extend `operators_for()` in `dispatch.rs` knowing the evaluator will honor the full operator set: `["eq", "neq", "gt", "lt"]` for Classification, `["eq", "neq", "contains"]` for MemberOf, `["eq", "neq"]` for others
- No blockers

---
*Phase: 20-operator-expansion*
*Completed: 2026-04-21*
