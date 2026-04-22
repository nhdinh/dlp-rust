---
phase: 26-abac-enforcement-convergence
plan: "01"
subsystem: abac
tags: [rust, serde, abac, policy-condition, app-identity]

requires:
  - phase: 22-dlp-common-foundation
    provides: AbacContext, EvaluateRequest, AbacContext fields (source_application, destination_application)
  - phase: 25-app-identity-capture-in-dlp-user-ui
    provides: AppIdentity, AppTrustTier, SignatureState types in dlp-common/src/endpoint.rs

provides:
  - AppField enum (Publisher, ImagePath, TrustTier) with snake_case serde in dlp-common::abac
  - PolicyCondition::SourceApplication variant with field/op/value structure
  - PolicyCondition::DestinationApplication variant with field/op/value structure
  - From<EvaluateRequest> for AbacContext impl (drops agent field per D-06)

affects:
  - 26-02 (policy_store.rs condition_matches — adds SourceApplication/DestinationApplication arms)
  - 26-03 (public_routes.rs evaluate handler — uses From<EvaluateRequest> for AbacContext at boundary)
  - 28-admin-tui-screens (AppField variants needed for condition authoring UI)

tech-stack:
  added: []
  patterns:
    - "AppField enum selects AppIdentity field for policy condition dispatch (Publisher/ImagePath/TrustTier)"
    - "From<EvaluateRequest> for AbacContext drops agent metadata at the boundary — not an ABAC attribute"
    - "PolicyCondition serde tag = attribute with snake_case rename — wire format: {attribute: source_application, field: publisher, op: eq, value: ...}"

key-files:
  created: []
  modified:
    - dlp-common/src/abac.rs

key-decisions:
  - "AppField defined in dlp-common/src/abac.rs (not endpoint.rs) — it is a policy DSL type, not an identity type"
  - "From<EvaluateRequest> for AbacContext placed before PolicyCondition definition — both structs fully defined at that point"
  - "SourceApplication/DestinationApplication fail closed on None identity (D-03) — enforced in Plan 02 condition_matches arms"

patterns-established:
  - "AppField dispatch: condition_matches arms will match field to AppIdentity struct fields by enum variant"

requirements-completed:
  - APP-03

duration: 4min
completed: "2026-04-22"
---

# Phase 26 Plan 01: ABAC Type Contracts Summary

**AppField enum + SourceApplication/DestinationApplication PolicyCondition variants + From<EvaluateRequest> for AbacContext — type contracts enabling app-identity policy matching (APP-03)**

## Performance

- **Duration:** 4 min
- **Started:** 2026-04-22T14:57:43Z
- **Completed:** 2026-04-22T15:00:58Z
- **Tasks:** 1 (TDD)
- **Files modified:** 1

## Accomplishments

- Added `AppField` enum with three variants (`Publisher`, `ImagePath`, `TrustTier`) serializing as snake_case
- Added `PolicyCondition::SourceApplication` and `DestinationApplication` variants with `field: AppField`, `op: String`, `value: String` structure; JSON tag `"attribute": "source_application"` / `"destination_application"` (D-01 wire format)
- Implemented `From<EvaluateRequest> for AbacContext` — drops `agent` field (tracing metadata, not an ABAC attribute per D-06); forwards all five other fields unchanged
- Added 5 new tests covering `AppField` serde, `PolicyCondition` round-trips for both new variants, and both `From` conversion paths

## Task Commits

Each task was committed atomically:

1. **Task 1: Add AppField enum and new PolicyCondition variants (TDD)** - `07c3872` (feat)

**Plan metadata:** (pending)

_Note: TDD — RED (test-only edit, compile failure confirmed) then GREEN (implementation) in single atomic commit after fmt fix._

## Files Created/Modified

- `dlp-common/src/abac.rs` — Added `AppField` enum, `SourceApplication`/`DestinationApplication` `PolicyCondition` variants, `From<EvaluateRequest> for AbacContext` impl, and 5 new test cases

## Decisions Made

- `AppField` placed before `PolicyCondition` in file to satisfy forward reference in variant field types
- `From<EvaluateRequest> for AbacContext` placed immediately before `PolicyCondition` definition — both source and target structs are fully defined at that point in the file
- Test for `From` conversion split into two tests: one verifying `agent` is dropped and one verifying all non-agent fields are forwarded correctly

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

`cargo fmt` reformatted two assert expressions after initial implementation (collapsing multi-line assert to single line, expanding method chain). Fixed with `cargo fmt -p dlp-common` before committing.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Plan 02 (`policy_store.rs`) can now add `SourceApplication`/`DestinationApplication` match arms to `condition_matches()` and migrate `evaluate()` to `&AbacContext`
- Plan 03 (`public_routes.rs`) can use `From<EvaluateRequest> for AbacContext` at the HTTP handler boundary
- All type contracts required by Plans 02 and 03 are present and compile-verified in `dlp-common`

## Self-Check

- [x] `dlp-common/src/abac.rs` exists and modified
- [x] Commit `07c3872` exists (`git log --oneline | grep 07c3872`)
- [x] `grep "pub enum AppField" dlp-common/src/abac.rs` matches line 261
- [x] `grep "SourceApplication" dlp-common/src/abac.rs` matches line 334
- [x] `grep "DestinationApplication" dlp-common/src/abac.rs` matches line 347
- [x] `grep "impl From<EvaluateRequest> for AbacContext" dlp-common/src/abac.rs` matches line 270
- [x] `cargo test -p dlp-common` — 16 abac tests pass, 0 failures
- [x] `cargo clippy -p dlp-common -- -D warnings` — clean
- [x] `cargo fmt -p dlp-common --check` — clean

## Self-Check: PASSED

---
*Phase: 26-abac-enforcement-convergence*
*Completed: 2026-04-22*
