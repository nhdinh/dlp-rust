---
phase: 59
reviewers: [codex, opencode]
reviewed_at: 2026-05-13T22:00:00Z
plans_reviewed: [59-01-PLAN.md, 59-02-PLAN.md, 59-03-PLAN.md, 59-04-PLAN.md]
cycle: 3
prior_review: 2026-05-13T21:30:00Z
---

# Cross-AI Plan Review — Phase 59 (Cycle 3)

## Codex Review

## Summary

Cycle 3 is materially better than Cycle 2: the expire endpoint, missing-path fail-closed behavior, cache bounds, path normalization, pagination, and TUI/API alignment are now addressed in plan text. However, several issues are still not resolved, and a few new plan-level defects were introduced. The biggest remaining risks are: schema requirements are still not fully planned, folder inheritance may violate “unless stricter explicit label,” Plan 04 contains a Rust recursive enum design that will not compile, and audit/event consistency is overstated.

## Prior HIGH Concern Status

| Prior HIGH Concern | Status | Assessment |
|---|---:|---|
| Missing expire endpoint | **FULLY RESOLVED** | Plan 59-02 adds `POST /admin/labels/:id/expire`; Plan 59-04 calls the same endpoint. |
| Authorization not mentioned for admin API | **PARTIALLY RESOLVED** | Plan 59-02 states `/admin/*` JWT middleware applies and role handling is in JWT validation, but it does not require tests proving label CRUD is admin-only or operator-scoped. |
| Database schema/indexes under-specified | **STILL OPEN** | Plan 59-01 claims constraints and uniqueness, but no task modifies schema/migrations. It also does not plan `label_paths` or `label_inheritance` tables from the roadmap success criteria. |
| ABAC evaluate() blast radius / call sites | **PARTIALLY RESOLVED** | Plan 59-03 adds call-site discovery and requires enforcement path verification, but it is still text-driven and has at least one import/signature issue. |
| Missing path behavior when flag enabled | **FULLY RESOLVED** | Plan 59-03 explicitly fail-closes to T4 when label-aware mode is on and `resource_path` is missing. |

## Plan 59-01 — Label Types, Path Normalization, LabelService

### Strengths

- Strong path-normalization test matrix, including UNC, long-path prefixes, dot segments, drive-relative paths, and component-boundary checks.
- Bounded LRU cache with TTL and metrics addresses the previous unbounded/stale cache concerns.
- `ResolvedTier` distinguishes exact, inherited, fallback, and lookup failure, which is good for auditability.
- `parent_label_id` is explicitly documented as separate from filesystem inheritance.

### Concerns

- **HIGH:** DB schema/index work is claimed but not actually planned. `must_haves` says unique constraints and CHECK constraints exist, but the task list only expands repository methods. No schema/migration file is modified.
- **HIGH:** The roadmap success criterion names `labels`, `label_paths`, and `label_inheritance` tables. This plan only covers `labels`; the other two tables are not planned or explicitly deferred.
- **HIGH:** Folder inheritance semantics may violate LABEL-02. The requirement says child files inherit parent folder labels unless the child has a stricter explicit label. The plan uses exact match before parent walk without comparing tier strictness, so an explicit lower-tier child label could weaken a stricter folder label.
- **MEDIUM:** Cache stores only `Tier`, so a cached inherited result later returns as `ResolvedTier::Exact`. That loses source semantics and can make audit/logging misleading.
- **MEDIUM:** `parent_components("C:\\Data\\Sub\\file.txt")` returns `C:` rather than `C:\`; this may not match repository path storage or root handling.

### Suggestions

- Add an explicit schema task modifying the actual DB initialization/migration file with `labels`, `label_paths`, `label_inheritance`, foreign keys, CHECK constraints, and indexes.
- Resolve the inheritance rule: either implement “effective tier = stricter(parent, explicit)” or formally amend LABEL-02.
- Cache the full `ResolvedTier` or a cache record containing `{tier, source, parent_path}`.
- Add tests for “explicit lower tier under stricter parent folder” and “explicit stricter child under lower parent folder.”

### Risk Assessment

**MEDIUM-HIGH.** The service design is strong, but schema coverage and the inheritance strictness rule are core phase requirements, not polish items.

## Plan 59-02 — Admin Label API

### Strengths

- Expire endpoint is now aligned with the TUI.
- State transition rules are explicit.
- Duplicate normalized path conflict handling is specified.
- Delete rejects children before removal.
- Pagination, cache invalidation, and audit payload fields are much clearer than Cycle 2.

### Concerns

- **HIGH:** Audit guarantees are overstated. `with_mutation()` commits the DB write, invalidates cache, then emits audit best-effort. If audit emission fails, mutation succeeds without an audit event, contradicting “all mutations emit audit events.”
- **MEDIUM:** Authorization is asserted, not verified. The plan should require tests that unauthenticated users cannot access endpoints and that non-admin/operator scopes cannot mutate labels.
- **MEDIUM:** `tier` and `owner_sid` filtering is done in memory after pagination, so `total` and returned pages can be incorrect.
- **MEDIUM:** `validate_label_request` is described as querying DB but its proposed signature does not accept `pool`/state.
- **LOW:** The plan says cache invalidation is transactional, but it happens after commit. That is acceptable if documented as post-commit consistency, but not truly transactional.

### Suggestions

- Make audit emission part of the transaction where feasible, or fail the mutation if audit insertion fails.
- Add auth/authorization tests for every mutating endpoint.
- Move `tier` and `owner_sid` filters into repository SQL before pagination/counting.
- Fix helper signatures before execution so DB-backed validation is implementable.

### Risk Assessment

**MEDIUM.** API surface is mostly complete, but audit integrity and filtered pagination need correction before implementation.

## Plan 59-03 — Label-Aware ABAC Integration

### Strengths

- Feature flag defaults off and is cached in `AtomicBool`, avoiding per-evaluation DB reads.
- Missing `resource_path` and lookup failures fail closed to T4.
- Behavior matrix is a good addition.
- Call-site discovery is explicitly required.
- NTFS/ABAC deny invariant is documented.

### Concerns

- **HIGH:** The plan imports `ResolvedTier` from `dlp_common::label`, but Plan 59-01 defines it in `dlp-server/src/label_service.rs`. That will not compile as written.
- **MEDIUM:** Test 11 says label-aware enabled but `LabelService` is `None` uses request classification for backward compatibility. That creates a fail-open path if an enforcement call site forgets to pass the service.
- **MEDIUM:** “Audit trail logs” are only `tracing::info!`, not persisted audit events. If this is meant to satisfy auditability, it is weaker than the API mutation audit model.
- **MEDIUM:** `AbacContext` direct construction updates are planned via `rg`, but impact on external crates/tests is broad and not enumerated.
- **LOW:** The import includes `LabelState`, apparently unused.

### Suggestions

- Import `ResolvedTier` from `crate::label_service`.
- Consider making `LabelService` mandatory when `label_aware_enabled == true`, or fail closed if it is `None` in production call paths.
- Add a persisted audit event or metric for classification overrides if compliance auditability is required.
- Add regression tests for every enforcement call site, not only `policy_store::`.

### Risk Assessment

**MEDIUM.** The behavior is much safer than Cycle 2, but the `None` service fallback and compile issue need correction.

## Plan 59-04 — Admin TUI

### Strengths

- TUI now includes list, detail, review queue, create/edit, delete, expire, filters, and pagination.
- Expired state is included in filter cycle.
- Destructive actions require confirmation with path and tier.
- Client methods align with the 8 API endpoints.

### Concerns

- **HIGH:** `LabelDetail { label, caller: Screen }` is a recursive enum variant and will not compile in Rust without indirection, e.g. `Box<Screen>`, or a smaller `LabelDetailCaller` enum.
- **MEDIUM:** The plan says “InputPurpose flow” in must-haves but then implements `Screen::LabelForm`. That is probably fine, but the plan should remove the contradiction.
- **MEDIUM:** The form’s text-entry behavior is under-specified. `Screen::LabelForm` holds field strings but does not clearly integrate with existing `TextInput` editing mechanics.
- **MEDIUM:** Async client calls from dispatch handlers need to follow the existing CLI async/action pattern; the plan names helpers but does not show how futures are scheduled.
- **LOW:** Adding menu items by fixed index is brittle and should include tests or central menu constants.

### Suggestions

- Replace `caller: Screen` with `caller: LabelDetailCaller` or `caller: Box<Screen>`.
- Choose either `InputPurpose` or `Screen::LabelForm` as the implementation pattern and update must-haves accordingly.
- Specify how text editing buffers are handled for path, owner SID, and parent label ID.
- Add compile-focused tests for new enum variants and navigation.

### Risk Assessment

**MEDIUM-HIGH.** Feature coverage is good, but the recursive enum issue is a hard compile blocker.

## Overall Risk Assessment

**MEDIUM-HIGH.** Cycle 3 resolves several prior review blockers, especially the expire endpoint and fail-closed ABAC path behavior. The phase still has unresolved core risks around DB schema completeness, inheritance strictness, audit guarantees, and a TUI compile blocker. The plans are close, but they should not be treated as execution-ready until those issues are fixed in the plan text.

---

## OpenCode Review

OpenCode review failed: quota exceeded.

---

## Consensus Summary

### Agreed Strengths

- **Expire endpoint alignment** (Codex): Plan 59-02 now includes `POST /admin/labels/:id/expire`; Plan 59-04 calls it. Cross-plan inconsistency from Cycle 2 is resolved.
- **Fail-closed ABAC behavior** (Codex): Missing `resource_path` and lookup failures both fail closed to T4. Behavior matrix documents all combinations.
- **Path normalization test matrix** (Codex): Covers UNC, long-path prefixes, dot segments, drive-relative paths, component boundaries.
- **Bounded LRU cache** (Codex): TTL, metrics, bounded capacity address prior unbounded growth concerns.
- **State transition enforcement** (Codex): Rules are explicit with 409 Conflict on violations.
- **Duplicate path conflict handling** (Codex): Normalized path uniqueness check specified.

### Agreed Concerns (from Codex — sole reviewer this cycle)

| Concern | Severity | Plan | Status |
|---------|----------|------|--------|
| DB schema/indexes under-specified | **HIGH** | 59-01 | **STILL OPEN** — no task modifies schema/migrations; `label_paths` and `label_inheritance` tables from roadmap success criteria not planned |
| Folder inheritance strictness violation | **HIGH** | 59-01 | **NEW** — exact match before parent walk without comparing tier strictness; explicit lower-tier child could weaken stricter folder label |
| Audit guarantees overstated | **HIGH** | 59-02 | **NEW** — `with_mutation()` emits audit best-effort after commit; failure leaves mutation without audit event |
| ResolvedTier import location | **HIGH** | 59-03 | **NEW** — plan imports from `dlp_common::label` but type is defined in `dlp-server/src/label_service.rs`; will not compile |
| Recursive enum variant | **HIGH** | 59-04 | **NEW** — `LabelDetail { label, caller: Screen }` is recursive and will not compile without `Box<Screen>` |
| Authorization not verified | **MEDIUM** | 59-02 | **PARTIALLY RESOLVED** — JWT middleware mentioned but no auth tests required |
| LabelService None fallback | **MEDIUM** | 59-03 | **NEW** — test 11 creates fail-open path if enforcement call site forgets service |
| Audit trail only tracing::info! | **MEDIUM** | 59-03 | **NEW** — not persisted audit events; weaker than API mutation audit model |
| Cache stores only Tier | **MEDIUM** | 59-01 | **NEW** — cached inherited result returns as Exact, losing source semantics |
| In-memory filter after pagination | **MEDIUM** | 59-02 | **NEW** — tier/owner_sid filtering done post-pagination; total and pages incorrect |
| Form flow contradiction | **MEDIUM** | 59-04 | **PARTIALLY RESOLVED** — must-haves claim InputPurpose flow but plan implements Screen::LabelForm |
| AbacContext construction impact | **MEDIUM** | 59-03 | **NEW** — broad impact via rg search, not enumerated |

### Divergent Views

- No divergent views this cycle — only Codex produced a review (OpenCode quota exceeded).
- Codex rates overall risk **MEDIUM-HIGH** (unchanged from Cycle 2), citing schema gaps, inheritance strictness, audit guarantees, and TUI compile blocker as remaining blockers.

---

## Round 2 -> Round 3 Progress

| Round 2 Concern | Status | How Addressed |
|-----------------|--------|---------------|
| Missing expire endpoint | **FULLY RESOLVED** | Added to Plan 59-02; TUI calls it in Plan 59-04 |
| Missing path behavior when flag enabled | **FULLY RESOLVED** | Plan 59-03 fail-closes to T4 when resource_path missing |
| ABAC evaluate() blast radius | **PARTIALLY RESOLVED** | Call-site discovery required but compile issue (ResolvedTier import) introduced |
| Authorization not mentioned | **PARTIALLY RESOLVED** | Mentioned as JWT middleware but no auth tests required |
| DB schema/indexes under-specified | **STILL OPEN** | No schema task added; `label_paths`/`label_inheritance` tables still unplanned |
| Optimistic locking claimed but not implemented | **NOT ADDRESSED** | Still a gap between threat model claim and actual tasks |
| Multi-step form implementation ambiguity | **PARTIALLY RESOLVED** | Screen::LabelForm chosen but contradicts must-have InputPurpose claim |

### New in Round 3

| Concern | Severity | Plan |
|---------|----------|------|
| Folder inheritance strictness violation | **HIGH** | 59-01 |
| Audit guarantees overstated | **HIGH** | 59-02 |
| ResolvedTier import location | **HIGH** | 59-03 |
| Recursive enum variant | **HIGH** | 59-04 |
| LabelService None fallback | **MEDIUM** | 59-03 |
| Audit trail only tracing::info! | **MEDIUM** | 59-03 |
| Cache stores only Tier | **MEDIUM** | 59-01 |
| In-memory filter after pagination | **MEDIUM** | 59-02 |
| AbacContext construction impact | **MEDIUM** | 59-03 |

---

## Action Items for Planner

1. **Add schema task to Plan 59-01** (HIGH): Add explicit task modifying DB initialization/migration with `labels`, `label_paths`, `label_inheritance` tables, foreign keys, CHECK constraints, and indexes. Or formally defer `label_paths`/`label_inheritance` with justification.
2. **Fix inheritance strictness** (HIGH): Implement "effective tier = stricter(parent, explicit)" or amend LABEL-02 requirement. Add tests for explicit lower-tier child under stricter parent folder.
3. **Fix audit guarantee** (HIGH): Make audit emission part of the transaction, or fail mutation if audit fails. Remove "best-effort" language if audit is mandatory.
4. **Fix ResolvedTier import** (HIGH): Import from `crate::label_service` not `dlp_common::label` in Plan 59-03.
5. **Fix recursive enum** (HIGH): Change `LabelDetail { label, caller: Screen }` to use `Box<Screen>` or a separate `LabelDetailCaller` enum in Plan 59-04.
6. **Fix LabelService None fallback** (MEDIUM): Make LabelService mandatory when label_aware_enabled is true, or fail closed (deny) if None in production paths.
7. **Fix in-memory filter** (MEDIUM): Move tier/owner_sid filters into repository SQL before pagination/counting in Plan 59-02.
8. **Fix form flow contradiction** (MEDIUM): Update must-haves to match Screen::LabelForm implementation, or switch to InputPurpose pattern.
9. **Add persisted audit for ABAC overrides** (MEDIUM): Add audit event insertion (not just tracing::info!) for classification overrides in Plan 59-03.
10. **Cache full ResolvedTier** (MEDIUM): Cache `{tier, source, parent_path}` instead of just Tier to preserve source semantics.

---

*Review completed: 2026-05-13*
*Cycle: 3 (prior review: 2026-05-13T21:30:00Z)*
*To incorporate feedback into planning: /gsd-plan-phase 59 --reviews*
