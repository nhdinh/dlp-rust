---
phase: 59-label-service
reviewed: 2026-05-21T00:45:00Z
depth: standard
files_reviewed: 4
files_reviewed_list:
  - .planning/phases/59-label-service/59-01-PLAN.md
  - .planning/phases/59-label-service/59-02-PLAN.md
  - .planning/phases/59-label-service/59-03-PLAN.md
  - .planning/phases/59-label-service/59-04-PLAN.md
findings:
  critical: 2
  warning: 4
  info: 3
  total: 9
status: issues_found
---

# Phase 59: Code Review Report

**Reviewed:** 2026-05-21T00:45:00Z
**Depth:** standard
**Files Reviewed:** 4
**Status:** issues_found

## Summary

Reviewed the revised Phase 59 plan documents (59-01 through 59-04) that were updated to address Cycle 3 cross-AI review feedback. The revision narrows scope from full implementation to "fix gaps" and adds traceability (read_first, acceptance_criteria) per checker requirements. However, several issues remain: two HIGH-severity concerns from Cycle 3 are not actually resolved by the revised plans (only acknowledged), there are internal contradictions in the audit model, and the plans contain untested assumptions about existing code state that could cause compilation failures during execution.

## Critical Issues

### CR-01: DB Schema/Indexes Under-Specified — Still Unresolved (Plan 59-01)

**File:** `.planning/phases/59-label-service/59-01-PLAN.md:1` (cross-cutting concern)
**Issue:** Cycle 3 review flagged this as HIGH: "DB schema/index work is claimed but not actually planned." The revised plan acknowledges this via D-20 justification ("single labels table is sufficient") but does NOT add any schema task. The `must_haves` no longer claims schema constraints exist, but the plan also does not verify that the existing schema actually has the required CHECK constraints and 5 indexes mentioned in 59-CONTEXT.md. If the prior-phase schema is incomplete, Plan 59-01 has no task to fix it.

**Fix:** Add a verification task to 59-01 that inspects `dlp-server/src/db/mod.rs` (init_tables) and confirms CHECK constraints on tier, object_type, label_state and the 5 indexes (path, tier, state, owner, parent) exist. If missing, add a schema migration task.

### CR-02: Two-Tier Audit Model Contradicts D-14 (Plan 59-03)

**File:** `.planning/phases/59-label-service/59-03-PLAN.md:275-306`
**Issue:** Plan 59-03 Task 3 implements "evaluation audit" as best-effort ("If audit persistence fails, log tracing::error! but do NOT fail the evaluation"). However, 59-CONTEXT.md D-14 states: "Audit emission is mandatory (not best-effort)." The plan tries to resolve this contradiction by inventing a "two-tier audit model" distinction that does not exist in the architecture. This creates a compliance gap: classification overrides (the security-critical event) are not mandatorily audited, while label CRUD (admin busywork) is. An attacker who triggers a classification override and then DoS's the audit store leaves no trace.

**Fix:** Either (a) make evaluation audit mandatory by failing closed (deny access if audit cannot be persisted), or (b) formally amend D-14 in 59-CONTEXT.md to explicitly state that evaluation-path audit is best-effort, with documented risk acceptance.

## Warnings

### WR-01: `store_events_sync_uow` Assumed to Exist (Plan 59-02)

**File:** `.planning/phases/59-label-service/59-02-PLAN.md:193-219`
**Issue:** Task 2's `with_mutation` helper calls `audit_store::store_events_sync_uow(&UnitOfWork)` but the plan only says "If it does not exist, add it." There is no verification step to confirm whether `AuditEventRepository::insert_batch(uow, ...)` actually exists or takes the expected parameters. If the repository API differs, the transactional audit guarantee cannot be implemented as planned.

**Fix:** Add a `read_first` item for `dlp-server/src/db/repositories/audit_events.rs` to verify `insert_batch` signature before implementing `with_mutation`.

### WR-02: `AbacContext.resource_path` Assumed to Exist (Plan 59-03)

**File:** `.planning/phases/59-label-service/59-03-PLAN.md:96-103`
**Issue:** The plan states `resource_path: Option<String>` "Already exists per D-09" but D-09 is a decision in 59-CONTEXT.md, not verified code. If `AbacContext` was never actually extended in a prior phase, Plan 59-03's evaluate() signature change will not compile. The original Plan 59-03 (before revision) had a Task 1 to extend AbacContext; that task was removed in the revision.

**Fix:** Add a pre-flight verification task to confirm `AbacContext` has `resource_path` field. If missing, add it before proceeding with Plan 59-03 tasks.

### WR-03: `list_by_filters` and `count_by_filters` Assumed to Exist (Plan 59-02)

**File:** `.planning/phases/59-label-service/59-02-PLAN.md:146-150`
**Issue:** Task 1 says "Update `LabelRepository::list_by_filters` to accept limit/offset" and "Add `count_by_filters` repository method." But the Key Interfaces section only shows `list_by_filters` without limit/offset parameters. There is no verification that `list_by_filters` exists with the expected signature, or that it can be modified without breaking other callers.

**Fix:** Add `read_first` for `dlp-server/src/db/repositories/labels.rs` to verify `list_by_filters` signature and identify all callers before modifying.

### WR-04: `ActionResult::LabelListLoaded` Variant Assumed Extendable (Plan 59-04)

**File:** `.planning/phases/59-label-service/59-04-PLAN.md:514`
**Issue:** Task 2 proposes adding `ActionResult::LabelListLoaded { labels, filter, page, page_size, total }` but there is no verification that `ActionResult` is an enum that can be extended, or that adding fields won't break existing match arms. If `ActionResult` is used exhaustively elsewhere, this change could cause compile errors in unrelated modules.

**Fix:** Add `read_first` for wherever `ActionResult` is defined to verify it can be extended, and grep for all match sites to assess blast radius.

## Info

### IN-01: Arrow Character Replacement Inconsistent

**File:** All 4 plan files
**Issue:** Unicode arrows (`→`) were replaced with ASCII arrows (`->`) in some places but not all. For example, 59-02-PLAN.md line 20 has `temporary->confirmed/rejected` while 59-CONTEXT.md D-17 still uses `→`. This inconsistency is cosmetic but indicates the replacement was done manually rather than systematically.

**Fix:** Standardize on `->` across all Phase 59 documents, or revert to `→` if the checker only flagged specific occurrences.

### IN-02: Removed `path_norm.rs` Without Migration Path

**File:** `.planning/phases/59-label-service/59-01-PLAN.md`
**Issue:** The original plan included `dlp-common/src/path_norm.rs` with `normalize_path()`, `is_path_prefix_of()`, and `parent_components()`. The revised plan removes this file from scope but does not verify whether any existing code depends on it. If `normalize_path()` was already implemented in a prior phase, removing it from files_modified is correct but should be noted. If not, label resolution has no path normalization.

**Fix:** Verify whether `path_norm.rs` exists in the codebase. If it does not, add path normalization to 59-01 scope or document that `LabelRepository` handles normalization internally.

### IN-03: `LabelDetail` Caller Field Contradiction

**File:** `.planning/phases/59-label-service/59-04-PLAN.md:127-128`
**Issue:** The plan claims "NO caller field (review HIGH concern #5 already fixed in actual code)" but 59-CONTEXT.md D-13b still states: "`LabelDetail` uses `Box<Screen>` for the caller field to avoid recursive enum compilation error." If the actual code has no caller field, D-13b is stale and should be updated. If the actual code DOES have a caller field, the plan's claim is wrong.

**Fix:** Verify actual `Screen::LabelDetail` definition in `dlp-admin-cli/src/app.rs` and update either the plan or 59-CONTEXT.md D-13b to match reality.

---

_Reviewed: 2026-05-21T00:45:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
