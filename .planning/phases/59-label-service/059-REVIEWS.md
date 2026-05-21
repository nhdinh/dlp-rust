---
phase: 59
reviewers: [codex, opencode]
reviewed_at: 2026-05-21T07:38:00Z
plans_reviewed: [59-01-PLAN.md, 59-02-PLAN.md, 59-03-PLAN.md, 59-04-PLAN.md]
cycle: 4
prior_review: 2026-05-13T22:00:00Z
---

# Cross-AI Plan Review — Phase 59 (Cycle 4)

## Codex Review

### Summary

The revised plans address most Cycle 3 HIGH findings at the planning level, especially the strictest-tier inheritance bug, `ResolvedTier` ownership, recursive TUI enum issue, SQL pagination, and the move from best-effort audit logging toward transactional mutation auditing. The remaining risk is that several fixes are still expressed as assertions rather than mechanically precise implementation steps, especially DB schema compliance versus roadmap success criteria, transaction boundaries for audit/cache invalidation, ABAC evaluation-path audit behavior, and authorization coverage. I would call these plans close to execution-ready, but not yet fully locked until the schema decision and audit transaction design are made explicit enough to prevent divergent implementations.

### PLAN 59-01 — Label Types, Path Normalization, LabelService

#### Strengths

- Correctly fixes the prior inheritance flaw by requiring exact and parent labels to be compared using strictest-tier-wins.
- Keeps `ResolvedTier` in `dlp-server`, matching D-19.
- Cache now preserves source metadata instead of only caching `Tier`, which is important for audit, debugging, and review UI behavior.
- Explicit tier ordering is included, including `UnclassifiedBlocked` as stricter than T4.
- Good dependency placement as Wave 1 foundation work.

#### Concerns

- **HIGH:** Roadmap success criteria still say SQLite must include `labels`, `label_paths`, and `label_inheritance`. D-20 says a single `labels` table is sufficient, but the plan only says "verify indexes," not "update/record the accepted deviation from roadmap success criteria." This may cause verification failure later.
- **MEDIUM:** Task 1 verifies indexes but does not explicitly verify foreign keys and CHECK constraints from LABEL-01. The plan says those already exist, but execution readiness depends on confirming them.
- **MEDIUM:** Path normalization is in the plan title but not clearly specified in tasks. Case folding, separator normalization, trailing slash behavior, UNC paths, drive letters, and canonical parent traversal need explicit rules.
- **MEDIUM:** Strictest-tier comparison needs clear tie behavior. If explicit child and inherited parent have equal strictness but different states or sources, the selected source should be deterministic.
- **LOW:** Cache invalidation is deferred to later plans, but this plan changes cache shape. The cache API should be designed now so later invalidation is not bolted on awkwardly.

#### Suggestions

- Add a task to document D-20 as an explicit accepted deviation from roadmap table names, or add compatibility views/tables if success criteria are treated literally.
- Verify `PRAGMA foreign_keys`, CHECK constraints, and all required columns as part of Task 1, not just indexes.
- Define path normalization behavior in tests: drive-letter case, trailing separators, mixed slash/backslash, relative paths rejection, UNC handling.
- Add tests for explicit lower tier under stricter parent, explicit stricter child under lower parent, equal-tier explicit/parent tie, and no-label fallback.

#### Risk Assessment

**MEDIUM.** The core logic fix is directionally sound, but schema compliance and path normalization ambiguity remain meaningful risks.

---

### PLAN 59-02 — Admin Label API

#### Strengths

- Directly addresses the prior audit concern by requiring all existing mutating handlers to use transactional audit.
- Adds SQL-level filtering, pagination, and accurate counts, fixing the in-memory pagination defect.
- Auth tests for all 8 endpoints are a strong security improvement.
- Adds the missing expire endpoint and aligns it with manual expiry decisions.
- Correctly depends on 59-01.

#### Concerns

- **HIGH:** "Transactional audit" needs a precise definition. If the label mutation and audit insert are not in the same DB transaction, the prior HIGH concern is not truly fixed.
- **HIGH:** Cache invalidation via transactional callback can be wrong if it fires before commit or if commit succeeds but callback fails. The plan should specify after-commit invalidation semantics.
- **MEDIUM:** Auth tests verify `401` without JWT, but not authorization/role checks with a valid non-admin token. That leaves the prior authorization concern only partially addressed.
- **MEDIUM:** State machine constraints are not explicit enough. Confirm/reject/expire should reject invalid transitions, especially downgrade-like changes without approval.
- **MEDIUM:** Delete semantics are under-specified. Hard delete may break historical audit references or FK relationships unless constrained or converted to soft delete.
- **LOW:** Stable ordering is mentioned, but the exact ordering should be defined, for example `updated_at DESC, id ASC`.

#### Suggestions

- Specify that `with_mutation` opens one UnitOfWork/transaction, performs mutation, writes `AdminAction` audit event, commits, then invalidates cache only after successful commit.
- Add role/permission tests for all endpoints, not just missing JWT tests.
- Add transition tests for temporary -> confirmed, temporary -> rejected, confirmed -> expired, rejected/expired invalid transitions, and downgrade rejection.
- Define delete behavior explicitly: soft delete, tombstone state, or hard delete with FK/audit implications covered.
- Include request validation tests for tier enum, label state, path normalization, invalid object type, pagination bounds, and malformed IDs.

#### Risk Assessment

**MEDIUM-HIGH.** This plan is much improved, but audit/cache transaction semantics and authorization depth are critical enough that ambiguity could still produce a flawed implementation.

---

### PLAN 59-03 — Label-Aware ABAC Integration

#### Strengths

- Correctly changes `LabelService None` while label-aware mode is enabled to fail closed instead of preserving a fail-open path.
- Preserves existing behavior when label-aware mode is off.
- Adds persisted audit events for classification overrides and routes them to SIEM.
- Fixes the prior wrong `ResolvedTier`/audit signature direction by using `UnitOfWork`.
- Includes a cached feature flag, avoiding per-evaluation config DB reads.

#### Concerns

- **HIGH:** "Label lookup failures are fail-closed (deny T4)" is conceptually confused if `UnclassifiedBlocked` is stricter than T4. The plan should consistently say fallback tier is `UnclassifiedBlocked`, or explain why "deny T4" is the enforcement representation.
- **HIGH:** Persisted audit during ABAC evaluation can be dangerous if evaluation is on a hot path or inside existing locks. The plan does not specify backpressure, failure handling, deduplication, or latency budget.
- **MEDIUM:** D-14 amendment creates an "evaluation-path audit exception," but the exact exception is unclear. If audit emission is mandatory generally, evaluation audit failure behavior must be specified: deny, continue, buffer, or degrade.
- **MEDIUM:** `AtomicBool` refresh every 30 seconds creates a consistency window. That may be acceptable, but security-sensitive disable/enable behavior should be documented.
- **MEDIUM:** PolicyStore integration likely has broad blast radius. The plan names files but does not enumerate affected call sites, tests, or existing behavior expectations.
- **LOW:** `spawn_blocking` refresh should include shutdown behavior and error logging to avoid background task leaks/noise.

#### Suggestions

- Replace "deny T4" with a single precise fail-closed outcome: `UnclassifiedBlocked` resource tier and final deny, unless the codebase requires T4 as a policy sentinel.
- Define audit failure behavior for evaluation overrides. For example: mutation audit is rollback-mandatory; evaluation override audit is best-effort persisted with failure counter and deny still proceeds.
- Add tests for all behavior matrix cases: flag off, flag on + label service missing, lookup error, no label, explicit label, inherited label, stricter child, stricter parent.
- Add performance-oriented tests or benchmarks around evaluation with cached flag and cached label resolution.
- Ensure classification override audits include original tier, resolved tier, source, path, policy id if available, and reason.

#### Risk Assessment

**HIGH.** The security posture is improved, but ABAC evaluation is central enforcement logic. Ambiguous fail-closed semantics and audit behavior on the evaluation path are still significant risks.

---

### PLAN 59-04 — Admin TUI

#### Strengths

- Fixes the recursive enum issue by removing `caller: Screen`.
- Resolves the prior contradiction by using `Screen::LabelForm` rather than `InputPurpose`.
- Adds pagination support in the TUI to match server-side pagination.
- Includes confirmation for destructive actions with path and tier, which is appropriate.
- Keeps dependency on 59-02, so it builds on completed API support.

#### Concerns

- **MEDIUM:** Plan claims full label management, but tasks only mention expire, pagination, confirmation, and render updates. Create/edit/delete/review queue behavior may already exist, but the plan does not verify it.
- **MEDIUM:** Review queue confirm/reject flows are listed in must-haves but not concretely represented in tasks.
- **MEDIUM:** Error handling is not specified for API failures, stale pagination pages, auth expiry, validation errors, or deleted labels.
- **LOW:** Keyboard actions `n/e/d/v/f/x` need collision checks against existing screen conventions.
- **LOW:** "Meaningful construction test" is vague. It should include compile-time screen construction and at least one render/dispatch path test.

#### Suggestions

- Add explicit tasks or verification steps for create, edit, delete, confirm, reject, expire, filter cycle, and pagination.
- Add client/UI tests for confirm/reject/expire dispatch, confirmation cancel, API error display, and empty page handling.
- Define pagination behavior after delete/expire when the current page becomes empty.
- Include state rendering for `temporary`, `confirmed`, `rejected`, `expired`, and `Unclassified-Blocked`.

#### Risk Assessment

**MEDIUM.** The prior compile blocker appears fixed, but the plan is thinner than the API/server plans and may under-deliver the "full label management" success criterion unless existing implementation is already substantial.

---

### Cross-Plan Findings

#### Prior HIGH Concerns Status

- **DB schema/indexes under-specified:** Partially fixed. Index verification is added, but the roadmap conflict around `label_paths` and `label_inheritance` remains unresolved.
- **Folder inheritance strictness violation:** Fixed in plan text, assuming tests enforce strictest-tier comparison.
- **Audit guarantees overstated:** Partially fixed. Mutation audit is now transactional in 59-02, but transaction/callback semantics need precision. Evaluation audit in 59-03 remains ambiguous.
- **ResolvedTier import location:** Fixed.
- **Recursive enum variant:** Fixed.

#### New Or Remaining Risks

- **HIGH:** Schema success criteria conflict with D-20 single-table decision.
- **HIGH:** ABAC fail-closed wording is inconsistent between `UnclassifiedBlocked` and "deny T4."
- **HIGH:** Transactional audit/cache invalidation must be specified at the UnitOfWork boundary.
- **MEDIUM:** Authorization testing should include valid-but-insufficient roles, not only missing JWT.
- **MEDIUM:** Path normalization needs concrete rules and tests.
- **MEDIUM:** TUI plan may not fully cover review queue and create/edit/delete behavior.

### Overall Risk Assessment

**MEDIUM-HIGH.** The revised plans are materially better and likely executable by a careful implementer, but they still rely on several implicit interpretations in security-critical areas. Before execution, I would tighten three things: explicitly reconcile the schema/table discrepancy, define transactional audit plus after-commit cache invalidation mechanics, and make ABAC fail-closed/evaluation-audit behavior unambiguous. Once those are clarified, the phase should be execution-ready.

---

## OpenCode Review

### Plan 59-01 — Label Types, Path Normalization, LabelService

#### Summary
This revision meaningfully addresses the prior inheritance and caching concerns, and correctly relocates `ResolvedTier`. However, the database concern is only partially addressed (verification != implementation), and there are still gaps around schema ownership and enforcement of invariants.

#### Strengths
- Strictness comparison (explicit vs parent) is now explicitly required -> fixes prior inheritance violation.
- Cache now stores full resolution metadata (`tier`, `source`, `parent_path`) -> resolves prior semantic loss.
- `ResolvedTier` correctly scoped to `dlp-server` (D-19) -> fixes import mismatch.
- Clear invariant on strictness ordering -> reduces ambiguity in comparisons.

#### Concerns
- **HIGH:** DB schema still not implemented, only "verified".
  - Plan checks for 6 indexes via `sqlite_master` but does not define or migrate them.
  - If indexes don't exist, this plan silently passes responsibility downstream.
- **HIGH:** "6 indexes" requirement is implicit, not enumerated.
  - No definition of which columns or composite indexes -> unverifiable correctness.
- **MEDIUM:** No handling of path normalization/canonicalization.
  - Label resolution correctness depends heavily on normalized paths (case, separators, symlinks).
- **MEDIUM:** Parent traversal algorithm unspecified.
  - How many levels? How are root boundaries handled? Performance implications?
- **LOW:** Cache invalidation not referenced here (relies on later plan).

#### Suggestions
- Explicitly define required indexes (columns + uniqueness) and enforce via migration or startup check with failure.
- Add deterministic path normalization function (Windows-specific: case-insensitive, canonical separators).
- Define parent traversal algorithm:
  - Max depth
  - Root stop condition
  - Early exit on highest tier
- Add unit tests for:
  - Mixed explicit + inherited tiers
  - Deep folder chains
  - Cache correctness vs DB

#### Risk Assessment
**MEDIUM** — Core logic is improved, but DB correctness and path handling remain under-specified and can cause subtle correctness bugs.

---

### Plan 59-02 — Admin Label API

#### Summary
This plan significantly improves audit guarantees and pagination correctness. The transactional audit fix is a strong correction of a prior HIGH issue. However, the plan assumes a lot about transaction boundaries and doesn't fully specify failure modes or concurrency behavior.

#### Strengths
- Transactional audit (`with_mutation`) directly fixes prior HIGH concern.
- Refactoring ALL handlers removes inconsistent behavior -> good systemic fix.
- SQL-level pagination + `count_by_filters` -> fixes incorrect totals issue.
- Auth tests across all endpoints -> closes security gap.
- Cache invalidation tied to mutation lifecycle -> aligns with D-15.

#### Concerns
- **HIGH:** Transaction boundary ambiguity.
  - Does `with_mutation` wrap DB + audit in a single SQLite transaction?
  - If audit store is separate, true atomicity may not be achievable.
- **HIGH:** No idempotency or retry semantics for mutation endpoints.
  - Risk of duplicate operations on retries (especially confirm/reject).
- **MEDIUM:** Concurrency not addressed.
  - Two admins confirming/rejecting same label -> race conditions.
- **MEDIUM:** Authorization depth unclear.
  - Only 401 tested; no role-based authorization (who can confirm/reject/delete?).
- **LOW:** Validation rules not explicitly enumerated (tier transitions, state machine enforcement).

#### Suggestions
- Define `with_mutation` contract clearly:
  - Single DB transaction?
  - Audit persisted in same DB or guaranteed atomic write?
- Add optimistic locking (e.g., `updated_at` check) for state transitions.
- Add idempotency keys or safe retry semantics for POST endpoints.
- Expand auth tests to include:
  - 403 cases (insufficient permissions)
- Add explicit validation matrix for LABEL-03 state machine transitions.

#### Risk Assessment
**MEDIUM** — Major correctness issues fixed, but transactional guarantees and concurrency semantics need tightening to avoid edge-case corruption.

---

### Plan 59-03 — Label-Aware ABAC Integration

#### Summary
This plan correctly fixes the fail-open behavior and audit persistence issues, and aligns with the fail-closed philosophy. The integration is mostly sound, but introduces system-wide behavioral changes that are high-impact and not fully tested or scoped.

#### Strengths
- Fail-closed semantics fully enforced -> fixes critical security gap.
- `LabelService None -> deny` eliminates bypass path.
- Persisted audit event (not tracing) -> resolves prior audit concern.
- Correct `UnitOfWork` usage -> fixes integration bug.
- Feature flag caching with `AtomicBool` -> avoids per-request overhead.

#### Concerns
- **HIGH:** Behavior change is global and potentially breaking.
  - Enabling flag without full label coverage -> system-wide deny.
- **HIGH:** No rollout/migration strategy.
  - How to safely enable label-aware mode in production?
- **MEDIUM:** Background refresh thread unspecified.
  - Error handling? What if refresh fails repeatedly?
- **MEDIUM:** Performance impact not addressed.
  - `resolve_tier` now on hot path; cache TTL + miss cost unclear.
- **MEDIUM:** Audit event volume risk.
  - "classification override" could generate high-volume events.
- **LOW:** Definition of "classification override" ambiguous.

#### Suggestions
- Add rollout strategy:
  - Dry-run / audit-only mode before enforce
  - Metrics on "would deny" decisions
- Define cache TTL and eviction policy explicitly.
- Add circuit breaker for label lookup failures (avoid cascading denial storms).
- Rate-limit or batch classification override audit events.
- Define precisely when override event is emitted.

#### Risk Assessment
**HIGH** — Security posture is correct, but operational risk is significant without rollout and observability safeguards.

---

### Plan 59-04 — Admin TUI

#### Summary
This plan cleanly resolves prior structural issues (recursive enum, form flow) and is largely straightforward. It is execution-ready, with only minor UX and integration gaps.

#### Strengths
- Recursive enum issue fully resolved -> compile-safe.
- Form flow aligned with `Screen::LabelForm` -> consistent architecture.
- Pagination handled server-side -> scalable.
- Confirmation for destructive actions -> good UX safety.
- Review queue aligns with API design.

#### Concerns
- **MEDIUM:** No error-state UX defined.
  - API failures, validation errors, empty states.
- **MEDIUM:** No loading/async state handling.
  - Risk of blocking UI or poor responsiveness.
- **LOW:** No keyboard accessibility details beyond basics.
- **LOW:** No test coverage mentioned (render + navigation).

#### Suggestions
- Add explicit error rendering states (toast/banner/panel).
- Add loading indicators for API calls.
- Add basic integration tests for:
  - Navigation flows
  - Pagination correctness
- Ensure consistent keybindings with existing screens.

#### Risk Assessment
**LOW** — Mostly UI wiring; prior critical issues resolved.

---

### Overall Assessment

#### Are Cycle 3 HIGH concerns fixed?

- DB schema/indexes -> PARTIALLY FIXED (verification only, not implementation)
- Folder inheritance strictness -> FIXED
- Audit guarantees -> MOSTLY FIXED (depends on transaction implementation)
- ResolvedTier location -> FIXED
- Recursive enum -> FIXED

#### New Risks Introduced

- Fail-closed ABAC without rollout strategy (HIGH)
- Transactional audit assumptions may not hold (HIGH)
- Schema ownership ambiguity persists (MEDIUM)

#### Execution Readiness

- Plans 01-02: close but need tighter DB + transaction definitions
- Plan 03: functionally correct but operationally risky
- Plan 04: ready

### Final Risk: MEDIUM-HIGH

The core architecture is now coherent and most correctness bugs are addressed, but:
- DB schema enforcement is still weak
- Transactional guarantees are assumed, not proven
- ABAC integration introduces high operational risk without rollout safeguards

Tightening those areas would bring this to LOW risk.

---

## Consensus Summary

### Agreed Strengths

- **Strictness comparison fixed** (Codex + OpenCode): Plan 59-01 now requires exact vs parent tier comparison using `strictness_rank()`; prior inheritance violation resolved.
- **ResolvedTier correctly scoped** (Codex + OpenCode): Defined in `dlp-server/src/label_service.rs` per D-19; import mismatch resolved.
- **Cache stores full metadata** (Codex + OpenCode): `CacheEntry { tier, source, parent_path }` replaces bare `Tier` caching.
- **Transactional audit pattern** (Codex + OpenCode): `with_mutation` helper wraps DB write + audit emission; all 5 existing handlers refactored from best-effort.
- **SQL-level pagination** (Codex + OpenCode): `count_by_filters` + LIMIT/OFFSET in repository; in-memory post-pagination fixed.
- **Fail-closed ABAC** (Codex + OpenCode): All error/missing paths deny when label-aware is ON; `LabelService None` no longer falls back to request classification.
- **Recursive enum fixed** (Codex + OpenCode): `LabelDetail` has no `caller: Screen` field.
- **Auth tests added** (Codex + OpenCode): 8 endpoints verified for 401 without JWT.

### Agreed Concerns

| Concern | Severity | Plan | Status | Reviewers |
|---------|----------|------|--------|-----------|
| Schema success criteria vs D-20 conflict | **HIGH** | 59-01 | **STILL OPEN** — roadmap says 3 tables, D-20 says 1 table; no formal deviation recorded | Codex, OpenCode |
| Transactional audit boundary ambiguity | **HIGH** | 59-02 | **PARTIALLY FIXED** — `with_mutation` described but UnitOfWork boundary not precisely specified | Codex, OpenCode |
| ABAC fail-closed wording inconsistency | **HIGH** | 59-03 | **NEW** — "deny T4" vs `UnclassifiedBlocked` terminology is confused | Codex, OpenCode |
| ABAC operational risk without rollout strategy | **HIGH** | 59-03 | **NEW** — enabling flag without full label coverage causes system-wide deny | OpenCode |
| Evaluation-path audit ambiguity | **MEDIUM** | 59-03 | **PARTIALLY FIXED** — D-14 amendment claimed but not verified in actual 59-CONTEXT.md | Codex |
| Path normalization unspecified | **MEDIUM** | 59-01 | **STILL OPEN** — no concrete rules for case, separators, UNC, trailing slash | Codex, OpenCode |
| Authorization depth (403, not just 401) | **MEDIUM** | 59-02 | **STILL OPEN** — no role-based permission tests | Codex, OpenCode |
| Concurrency / optimistic locking | **MEDIUM** | 59-02 | **NEW** — no handling for simultaneous confirm/reject by two admins | OpenCode |
| TUI coverage gaps | **MEDIUM** | 59-04 | **STILL OPEN** — create/edit/delete/review queue not explicitly in tasks | Codex, OpenCode |
| Audit event volume / backpressure | **MEDIUM** | 59-03 | **NEW** — classification override audit on hot path without rate limiting | OpenCode |

### Divergent Views

- **Plan 59-03 risk level**: Codex rates **HIGH** due to ambiguous fail-closed semantics and evaluation audit behavior. OpenCode also rates **HIGH** but emphasizes operational risk (rollout strategy) rather than semantic ambiguity.
- **Plan 59-04 risk level**: Codex rates **MEDIUM** due to coverage gaps. OpenCode rates **LOW** considering it mostly UI wiring with prior blockers resolved.
- **Overall risk**: Both reviewers agree **MEDIUM-HIGH**, but Codex leans toward "close to execution-ready with 3 tightenings" while OpenCode emphasizes "assumed, not proven" transactional guarantees.

---

## Round 3 -> Round 4 Progress

| Round 3 Concern | Status | How Addressed |
|-----------------|--------|---------------|
| Missing expire endpoint | **FULLY RESOLVED** | Plan 59-02 Task 3 adds expire using `with_mutation`; Plan 59-04 Task 1 adds client method |
| Folder inheritance strictness violation | **FULLY RESOLVED** | Plan 59-01 Task 3 implements strictness comparison; tests specified |
| ResolvedTier import location | **FULLY RESOLVED** | Plan 59-01 Task 2 defines in dlp-server; Plan 59-03 uses `crate::label_service::ResolvedTier` |
| Recursive enum variant | **FULLY RESOLVED** | Plan 59-04 confirms `LabelDetail { label: serde_json::Value }` with no caller field |
| Cache stores only Tier | **FULLY RESOLVED** | Plan 59-01 Task 2 adds `CacheEntry { tier, source, parent_path, inserted }` |
| Audit guarantees overstated | **MOSTLY RESOLVED** | Plan 59-02 Task 2 adds `with_mutation` for transactional audit; evaluation path in 59-03 still ambiguous |
| In-memory filter after pagination | **FULLY RESOLVED** | Plan 59-02 Task 1 adds `count_by_filters` + SQL-level LIMIT/OFFSET per D-21 |
| LabelService None fallback | **FULLY RESOLVED** | Plan 59-03 Task 2 denies (T4) when `LabelService` is None and flag is ON |
| Audit trail only tracing::info! | **FULLY RESOLVED** | Plan 59-03 Task 3 adds persisted audit event with correct `&UnitOfWork` signature |
| DB schema/indexes under-specified | **PARTIALLY RESOLVED** | Index verification added (Task 1), but roadmap/D-20 table conflict remains unrecorded |
| Authorization not verified | **PARTIALLY RESOLVED** | Auth tests for 401 added (Task 4), but no 403 role-based tests |
| Form flow contradiction | **FULLY RESOLVED** | Plan 59-04 uses `Screen::LabelForm`; InputPurpose contradiction removed |

### New in Round 4

| Concern | Severity | Plan |
|---------|----------|------|
| Schema success criteria conflict with D-20 | **HIGH** | 59-01 |
| Transactional audit boundary ambiguity | **HIGH** | 59-02 |
| ABAC fail-closed wording inconsistency | **HIGH** | 59-03 |
| ABAC operational risk without rollout strategy | **HIGH** | 59-03 |
| Path normalization unspecified | **MEDIUM** | 59-01 |
| Authorization depth (403 role tests) | **MEDIUM** | 59-02 |
| Concurrency / optimistic locking | **MEDIUM** | 59-02 |
| TUI coverage gaps (create/edit/delete/review queue) | **MEDIUM** | 59-04 |
| Audit event volume / backpressure | **MEDIUM** | 59-03 |

---

## Action Items for Planner

1. **Record D-20 deviation from roadmap** (HIGH): Add a formal note to 59-CONTEXT.md or ROADMAP.md that Phase 59 success criteria #1 is amended: single `labels` table with `find_parent_label()` replaces the three-table design. This prevents verification failure during milestone review.
2. **Specify `with_mutation` transaction contract** (HIGH): In Plan 59-02, add explicit text that `with_mutation` opens ONE `UnitOfWork`, performs mutation, calls `audit_store::store_events_sync(&uow, ...)`, commits, THEN calls `invalidate_cache()`. Clarify that audit failure prevents commit (rolls back on drop).
3. **Unify ABAC fail-closed terminology** (HIGH): In Plan 59-03, consistently use `UnclassifiedBlocked` as the resolved tier (not "deny T4"). Document that `UnclassifiedBlocked` maps to `Classification::T4` for policy engine consumption, but the label-service tier is `UnclassifiedBlocked`.
4. **Add rollout strategy to 59-03** (HIGH): Document a safe enablement path: dry-run mode (log would-deny without blocking), metrics on unlabeled resources, gradual path allowlisting before full enforcement.
5. **Add path normalization rules** (MEDIUM): In Plan 59-01 Task 3 or as a new task, specify: case-insensitive comparison, backslash canonicalization, trailing slash stripping, UNC prefix handling, relative path rejection.
6. **Add 403 authorization tests** (MEDIUM): In Plan 59-02 Task 4, add tests for valid JWT with insufficient role (e.g., operator token attempting admin-only operations).
7. **Add optimistic locking** (MEDIUM): In Plan 59-02, add `updated_at` check or version column for state transitions to prevent race conditions on confirm/reject.
8. **Expand TUI task coverage** (MEDIUM): In Plan 59-04, add explicit tasks or verification for create, edit, delete, confirm, reject flows — not just expire and pagination.
9. **Add audit backpressure** (MEDIUM): In Plan 59-03, specify rate limiting or batching for classification override audit events on the evaluation hot path.
10. **Verify D-14 amendment in 59-CONTEXT.md** (MEDIUM): Confirm the D-14 amendment text from Plan 59-03 Task 3 step 5 is actually present in the canonical 59-CONTEXT.md file.

---

*Review completed: 2026-05-21*
*Cycle: 4 (prior review: 2026-05-13T22:00:00Z)*
*Reviewers: Codex, OpenCode*
*To incorporate feedback into planning: /gsd-plan-phase 59 --reviews*
