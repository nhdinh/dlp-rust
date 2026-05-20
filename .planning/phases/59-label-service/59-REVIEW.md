---
phase: 59-label-service
reviewed: 2026-05-21T06:45:00Z
depth: deep
files_reviewed: 4
files_reviewed_list:
  - .planning/phases/59-label-service/59-01-PLAN.md
  - .planning/phases/59-label-service/59-02-PLAN.md
  - .planning/phases/59-label-service/59-03-PLAN.md
  - .planning/phases/59-label-service/59-04-PLAN.md
findings:
  critical: 5
  warning: 5
  info: 3
  total: 13
status: issues_found
---

# Phase 59: Code Review Report

**Reviewed:** 2026-05-21T06:45:00Z
**Depth:** deep
**Files Reviewed:** 4
**Status:** issues_found

## Summary

Reviewed the revised Phase 59 plan documents (59-01 through 59-04) that were updated to address Cycle 3 cross-AI review feedback and the prior adversarial review (59-REVIEW.md from d78e92d). The revisions correctly address several prior concerns: schema verification task added (59-01), `ResolvedTier` defined in dlp-server (59-01), strictness comparison specified (59-01), transactional audit helper designed (59-02), expire endpoint added (59-02), SQL-level pagination specified (59-02), auth tests required (59-02), fail-closed behavior matrix documented (59-03), cached `label_aware_enabled` in AppState (59-03), persisted audit for classification overrides (59-03), expire client method (59-04), pagination in TUI (59-04), and `ActionResult` non-existence acknowledged (59-04).

However, verified against actual source code, several critical issues remain: a compile-error in Plan 59-03's audit emission snippet, the "mandatory attempt" audit model still contradicts D-14 without amending it, the existing codebase already has 11 best-effort audit sites that Plan 59-02 must refactor, a redundant schema test task in 59-01, and Plan 59-02 Task 2's expire endpoint is explicitly best-effort despite D-14 saying audit is mandatory.

## Critical Issues

### CR-01: Plan 59-03 Task 3 Has Compile-Error in Audit Emission Code

**File:** `.planning/phases/59-label-service/59-03-PLAN.md:295`
**Issue:** The plan's action snippet shows:
```rust
audit_store::store_events_sync(&self.pool, &[audit_event])
```
But the actual function signature in `dlp-server/src/audit_store.rs:62` is:
```rust
pub fn store_events_sync(uow: &UnitOfWork<'_>, events: &[AuditEvent]) -> Result<(), AppError>
```
It takes `&UnitOfWork`, not `&Pool`. Passing `&self.pool` will not compile. The plan says "using a fresh UnitOfWork from the pool" but the code snippet contradicts this. The correct code must acquire a connection, create a `UnitOfWork`, pass `&uow` to `store_events_sync`, then commit.

**Fix:**
```rust
let mut conn = self.pool.get().map_err(...)?;
let uow = db::UnitOfWork::new(&mut conn).map_err(...)?;
audit_store::store_events_sync(&uow, &[audit_event])?;
uow.commit().map_err(...)?;
```

### CR-02: "Mandatory Attempt" Audit Model Still Contradicts D-14 Without Amendment

**File:** `.planning/phases/59-label-service/59-03-PLAN.md:24` (must_haves) and `.planning/phases/59-label-service/59-CONTEXT.md:93` (D-14)
**Issue:** D-14 states: "Audit emission is mandatory (not best-effort). Label mutations use a transactional helper that includes audit event insertion within the UnitOfWork. If audit insertion fails, the transaction rolls back." Plan 59-03's must_haves now say: "Evaluation audit is mandatory attempt: if persistence fails, error is logged but evaluation proceeds (documented tradeoff)." This is best-effort audit with rebranded terminology. The plan does NOT amend D-14 in 59-CONTEXT.md to explicitly carve out an exception for the evaluation path. The contradiction remains: D-14 says "mandatory (not best-effort)" for ALL label mutations and audit events, but 59-03 creates a class of audit events (classification overrides) that are explicitly best-effort. An attacker who triggers a classification override and then DoS's the audit store leaves no trace.

**Fix:** Either (a) make evaluation audit mandatory by failing closed (deny access if audit cannot be persisted), or (b) formally amend D-14 in 59-CONTEXT.md to explicitly state that evaluation-path audit is best-effort with documented risk acceptance, and update the D-14 text to remove the universal "not best-effort" claim.

### CR-03: Existing Codebase Has 11 Best-Effort Audit Sites That Plan 59-02 Must Refactor

**File:** `dlp-server/src/admin_api.rs` (11 occurrences, lines 2814, 2917, 3345, 3491, 3575, 3651, 4112, 4243, 4365, 4486, 4574)
**Issue:** The existing label CRUD handlers (create, update, confirm, reject, delete) and other admin handlers already use best-effort audit emission:
```rust
if let Err(e) = tokio::task::spawn_blocking(move || -> Result<(), AppError> {
    let mut conn = pool.get().map_err(AppError::from)?;
    let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
    audit_store::store_events_sync(&uow, &[audit_event])?;
    uow.commit().map_err(AppError::Database)?;
    Ok(())
}) ... {
    tracing::warn!(error = %e, "audit emission failed for label_create (best-effort)");
}
```
Plan 59-02 Task 3 claims to make audit "transactional" but the existing 11 sites are already implemented as best-effort post-commit. The plan does not include a task to refactor these EXISTING sites to use `with_mutation`. If only new handlers use `with_mutation` while existing handlers remain best-effort, the audit model is inconsistent and D-14 is violated for the majority of admin operations.

**Fix:** Add a Task 0 (or expand Task 3) to refactor ALL 11 existing best-effort audit sites in `admin_api.rs` to use `with_mutation` before adding new handlers.

### CR-04: Plan 59-01 Task 1 Is Redundant — Schema Test Already Exists

**File:** `.planning/phases/59-label-service/59-01-PLAN.md:104-154` and `dlp-server/src/db/repositories/labels.rs:586-623`
**Issue:** Plan 59-01 Task 1 says to add `test_labels_schema_constraints` that "attempts to insert invalid values (bad object_type, bad tier, bad label_state)" and "asserts each INSERT fails with a CHECK constraint error." However, `test_labels_check_constraints` already exists in `dlp-server/src/db/repositories/labels.rs` (lines 586-623) and verifies all 3 CHECK constraints with the exact same test pattern. The plan frames this as new work but it is a duplicate. Executing this task would add a redundant test.

**Fix:** Remove Task 1 or reframe it as "Verify existing `test_labels_check_constraints` covers all constraints; if gaps exist, extend it." The task should also verify the 6 indexes exist (not just CHECK constraints), which the existing test does NOT cover.

### CR-05: Plan 59-02 Task 2's Expire Endpoint Is Explicitly Best-Effort

**File:** `.planning/phases/59-label-service/59-02-PLAN.md:210-212`
**Issue:** The plan's Task 2 action for the expire endpoint says: "Emit audit event via `audit_store::store_events_sync` (best-effort post-commit for this task; made transactional in Task 3)." This means the expire endpoint will be implemented with the SAME best-effort pattern that D-14 explicitly prohibits. Task 3 only makes audit transactional for handlers that use `with_mutation`, but if Task 2's expire handler is implemented before Task 3's `with_mutation` helper exists, it will be best-effort. The plan should implement expire USING `with_mutation` in Task 3, not as a separate best-effort step in Task 2.

**Fix:** Remove the expire endpoint from Task 2. Add it in Task 3 as the FIRST handler to use `with_mutation`, demonstrating the pattern. Or, restructure so Task 3 (with_mutation) comes before Task 2 (expire endpoint).

## Warnings

### WR-01: `ClassificationOverride` EventType Addition Is Incomplete

**File:** `.planning/phases/59-label-service/59-03-PLAN.md:310-314`
**Issue:** The plan says to add `ClassificationOverride` to `EventType` in `dlp-common/src/audit.rs` but does not mention updating `EventType::routed_to_siem()` to include it. If `ClassificationOverride` is not added to `routed_to_siem()`, classification override audit events will not be forwarded to SIEM, creating a compliance gap.

**Fix:** Add `Self::ClassificationOverride` to the `matches!` expression in `routed_to_siem()`.

### WR-02: Plan 59-02 Task 3's `with_mutation` Helper Has Design Risk

**File:** `.planning/phases/59-label-service/59-02-PLAN.md:283-306`
**Issue:** The plan shows:
```rust
pub fn with_mutation<F>(
    &self,
    pool: &Pool,
    mutation: F,
) -> Result<MutationContext, AppError>
where
    F: FnOnce(&UnitOfWork) -> Result<MutationContext, AppError>,
```
The helper acquires a connection, creates a `UnitOfWork`, calls the closure with `&UnitOfWork`, then emits audit inside the same UOW, then commits. This design is correct in principle, but the plan does not show how the closure performs DB mutations. Existing repository methods like `LabelRepository::insert(&uow, ...)` take `&UnitOfWork`, so the closure can call them. However, the plan should verify that all mutating repository methods accept `&UnitOfWork` (not `&Pool`) before designing the helper.

**Fix:** Add a `read_first` item to verify all mutating `LabelRepository` methods (`insert`, `update`, `update_state`, `delete`) accept `&UnitOfWork`.

### WR-03: Plan 59-04 Task 3's Compile-Time Assertion Is Trivial

**File:** `.planning/phases/59-label-service/59-04-PLAN.md:283`
**Issue:** The plan proposes:
```rust
const _: () = assert!(std::mem::size_of::<Screen>() > 0);
```
This assertion passes for any non-ZST type and does NOT verify the recursive enum issue. A `Screen` containing `LabelDetail { label: serde_json::Value, caller: Screen }` would fail to compile entirely (infinite size), so the assertion would never even be evaluated. The assertion is trivial and provides no value.

**Fix:** Replace with a test that constructs `Screen::LabelDetail` and verifies it compiles:
```rust
#[test]
fn test_label_detail_non_recursive() {
    let detail = Screen::LabelDetail { label: serde_json::json!({}) };
    // If LabelDetail had a Screen-typed field, this would not compile.
    assert!(matches!(detail, Screen::LabelDetail { .. }));
}
```

### WR-04: Plan 59-03's `files_modified` Omits `dlp-common/src/audit.rs`

**File:** `.planning/phases/59-label-service/59-03-PLAN.md:8-12`
**Issue:** The `files_modified` list includes `dlp-server/src/policy_store.rs`, `dlp-server/src/lib.rs`, `dlp-server/src/main.rs`, and `dlp-server/src/admin_api.rs`. But Task 3 says to add `ClassificationOverride` to `EventType` in `dlp-common/src/audit.rs`. This file is not listed.

**Fix:** Add `dlp-common/src/audit.rs` to `files_modified`.

### WR-05: Plan 59-02's `LabelFilter` Struct Modification Risk

**File:** `.planning/phases/59-label-service/59-02-PLAN.md:223-240`
**Issue:** The plan adds `limit` and `offset` fields to `LabelFilter` with `#[serde(default)]`. `LabelFilter` is used as an axum `Query` extractor (verified in actual code at `admin_api.rs:3960`). Adding fields with `serde(default)` to a Query struct is safe. However, the plan should verify that `LabelFilter` is not also used as a JSON body extractor elsewhere, where missing fields could cause deserialization errors in older clients.

**Fix:** Add a grep verification step: `rg "LabelFilter" dlp-server/src/ --type rust` to confirm it's only used as Query params.

## Info

### IN-01: Arrow Character Inconsistency Persists

**File:** All 4 plan files and 59-CONTEXT.md
**Issue:** Unicode arrows (`→`) are still used in 59-CONTEXT.md D-17 (`temporary → confirmed/rejected`) while the plans use ASCII arrows (`->`). This inconsistency remains from the prior review.

**Fix:** Standardize on `->` across all Phase 59 documents.

### IN-02: `dlp-common/src/lib.rs` Removal from files_modified Is Correct

**File:** `.planning/phases/59-label-service/59-01-PLAN.md:8-11`
**Issue:** The revised plan removes `dlp-common/src/lib.rs` from `files_modified` (it was in the original plan). This is correct because `Tier::strictness_rank()` and `Tier::is_stricter_than()` are added to `dlp-common/src/label.rs`, which is already a `pub mod label;` in `lib.rs`. No lib.rs changes are needed.

**Fix:** No action needed. This is correct.

### IN-03: Plan 59-04 Correctly Acknowledges `ActionResult` Non-Existence

**File:** `.planning/phases/59-label-service/59-04-PLAN.md:112-116`
**Issue:** The plan adds a "Note on ActionResult" section correctly stating that "no such enum exists in the codebase" and that "The TUI uses direct `app.screen = Screen::...` mutations." This addresses the prior review's WR-04 concern.

**Fix:** No action needed. This is correct.

---

_Reviewed: 2026-05-21T06:45:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
