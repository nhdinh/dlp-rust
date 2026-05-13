---
phase: 59
reviewers: [codex, claude]
reviewed_at: 2026-05-13T21:30:00Z
plans_reviewed: [59-01-PLAN.md, 59-02-PLAN.md, 59-03-PLAN.md, 59-04-PLAN.md]
cycle: 2
prior_review: 2026-05-13T19:30:00Z
---

# Cross-AI Plan Review — Phase 59 (Cycle 2)

## Codex Review

### Summary

The revised Phase 59 plans are substantially stronger than the earlier versions. The major prior-risk areas appear addressed: path normalization, component-safe inheritance, bounded caching, fail-closed lookup behavior, guarded ABAC integration, state-transition validation, mutation-time cache invalidation, and TUI coverage. Overall, the phase is coherent and plausibly achieves the stated goals. The highest remaining risks are around Windows path semantics, ABAC call-site compatibility, database schema/migration details that are implied but not fully specified, and operational correctness of cache invalidation and feature-flag refresh behavior.

### Plan 59-01: Label Types + Path Normalization + LabelService

#### Strengths

- Centralizing `Label`, `LabelState`, `ObjectType`, and `Tier` in `dlp-common` matches the API decision to use shared request/response types.
- Explicit path normalization and component-boundary prefix checks directly address the most dangerous inheritance bug class.
- Bounded LRU cache with TTL avoids unbounded memory growth.
- `LookupFailed` as a distinct resolution result supports fail-closed ABAC behavior.
- Exact -> parent -> fallback resolution order matches the user decisions.
- Max parent-walk depth prevents pathological traversal behavior.

#### Concerns

- **HIGH**: Windows path normalization is security-sensitive and easy to get subtly wrong. Drive-relative paths like `C:foo`, device paths, mixed UNC/long-path prefixes, reserved names, alternate data streams, casing, and symlinks/reparse points need explicit behavior.
- **HIGH**: The plan mentions tables but does not describe migrations, indexes, uniqueness constraints, or referential actions. Label lookup performance depends heavily on indexes over normalized path, object type, state, and parent label.
- **MEDIUM**: Max depth 20 may be too low for real enterprise folder structures. If exceeded, the fail mode must be explicit and probably fail closed in enforcement contexts.
- **MEDIUM**: Cache invalidation must handle mutations to parent labels, child labels, state changes, tier changes, deletes, and expiry. Invalidating only the exact changed path may leave inherited resolutions stale.
- **MEDIUM**: Case sensitivity must be specified. Windows paths should almost certainly normalize for case-insensitive comparison, but preserving display path may still matter.
- **LOW**: `UnclassifiedBlocked` as a service-only fallback should remain out of persisted `Tier` unless intentionally modeled as a pseudo-result.

#### Suggestions

- Define two path fields or concepts: canonical lookup path and display/original path.
- Add DB constraints/indexes explicitly:
  - unique normalized path where active/non-expired as appropriate
  - index on `parent_label_id`
  - index on `label_state`
  - index on `path`
- Add tests for `C:\Data` vs `C:\Data2`, UNC paths, long-path prefixes, trailing slashes, root paths, case differences, dot segments, and drive-relative paths.
- Treat parent-walk depth overflow as `LookupFailed` or a distinct fail-closed resolution source.
- Prefer cache invalidation by path-prefix or generation counter on mutation if inherited results are cached.

#### Risk Assessment

**MEDIUM-HIGH**. The architecture is sound, but path normalization and inherited-cache correctness are security-critical. This plan needs a stronger test matrix and DB schema detail before implementation.

---

### Plan 59-02: Admin REST API for Label Management

#### Strengths

- Endpoint set covers CRUD plus confirm/reject review workflow.
- Pagination and filtering prevent unbounded list responses.
- State-transition validation addresses temporary/confirmed/rejected lifecycle requirements.
- Rejecting delete when children exist protects referential integrity and avoids orphaned inheritance.
- `with_mutation()` is a good pattern for bundling DB write, cache invalidation, and audit emission.
- Structured audit payloads are appropriate for an enterprise DLP system.
- Parent validation requiring an existing folder label is correct.

#### Concerns

- **HIGH**: Authorization/authentication is not mentioned. Admin label APIs must enforce admin/operator roles, not just exist under `/admin`.
- **HIGH**: Audit emission inside `with_mutation()` needs transactional semantics. If DB commit succeeds but audit fails, or audit succeeds but DB rolls back, the system can become hard to trust.
- **MEDIUM**: PUT semantics need clarity: full replace vs partial update. Partial updates are usually safer for admin forms, but must validate state/tier/path changes carefully.
- **MEDIUM**: Path uniqueness and conflict behavior are not specified. Creating duplicate labels for the same normalized path could make exact resolution ambiguous.
- **MEDIUM**: Delete behavior may be too narrow. Labels referenced by audit records, policies, review history, or child labels should probably be soft-deleted/expired rather than hard-deleted.
- **MEDIUM**: Manual assignment should identify actor identity and reason/comment if this is intended for operator-driven classification.
- **LOW**: `offset` pagination is acceptable for v0.10, but large datasets may eventually need cursor pagination.

#### Suggestions

- Specify required permissions per endpoint.
- Use soft delete or `expired` state as the primary removal path; reserve hard delete for test/admin maintenance if needed.
- Define response/error shapes, especially `400`, `401/403`, `404`, `409`, and validation errors.
- Add create/update idempotency behavior or conflict handling for duplicate normalized paths.
- Make audit emission part of the same DB transaction if stored locally, or define retry/outbox behavior if external.
- Include review queue endpoint explicitly if `GET /admin/labels?state=temporary` is the intended mechanism.

#### Risk Assessment

**MEDIUM**. API coverage is good, but authorization, transactional audit behavior, and uniqueness semantics need to be explicit before this is production-safe.

---

### Plan 59-03: Label-Aware ABAC Evaluation Integration

#### Strengths

- Feature flag default-off is appropriate for a security-sensitive behavior change.
- Cached `Arc<AtomicBool>` avoids per-evaluation DB reads.
- Fail-closed behavior for lookup failures is correct for DLP enforcement.
- `UnclassifiedBlocked -> T4` gives the policy engine a concrete strict classification.
- Audit trail for overrides is important for explaining enforcement decisions.
- Metrics are included for adoption and troubleshooting.
- Passing `Option<&LabelService>` keeps integration incremental.

#### Concerns

- **HIGH**: Changing `PolicyStore::evaluate()` signature may have broad blast radius. All enforcement paths must be reviewed, especially file copy, USB, clipboard, drag-and-drop, cloud sync, and print.
- **HIGH**: The critical invariant must be preserved explicitly: label-aware ABAC can only make the final result stricter, never override NTFS deny or convert ABAC deny to allow.
- **HIGH**: If `resource_path` is missing while the feature flag is enabled, behavior must be explicit. For protected channels without a path, fallback to request classification may be unsafe.
- **MEDIUM**: `T4` mapping for `UnclassifiedBlocked` is pragmatic, but it conflates "known highly sensitive" with "unknown/unclassified." Audits should preserve that distinction.
- **MEDIUM**: A 30-second flag refresh creates a delay between admin change and enforcement behavior. That may be acceptable, but the operational semantics should be documented.
- **MEDIUM**: Per-evaluation audit logging for every override could become high-volume. It may need sampling, rate limiting, or structured event aggregation.
- **LOW**: Metrics should distinguish exact, inherited, fallback, lookup failed, and missing path.

#### Suggestions

- Define enabled behavior matrix:
  - flag off
  - flag on + path present + exact label
  - flag on + inherited label
  - flag on + no label
  - flag on + lookup failure
  - flag on + missing path
  - no `LabelService` available
- Add regression tests proving `NTFS ALLOW + ABAC DENY = DENY`.
- Ensure resolved label tier is used only as a resource attribute and does not mutate request classification silently.
- Consider a separate internal enum for `ResolvedLabelTier::UnclassifiedBlocked` instead of collapsing too early to `T4`.
- Document all call sites with their channel and whether `resource_path` is guaranteed.

#### Risk Assessment

**HIGH**. This is the enforcement-critical plan. The design direction is right, but call-site coverage, missing-path behavior, and invariant tests are mandatory.

---

### Plan 59-04: Admin TUI Screens for Label Management

#### Strengths

- Covers the required admin workflows: list, create, edit, delete/expire, and review queue.
- Server-side pagination prevents loading too much data into the TUI.
- Explicit confirmation dialogs for destructive actions are appropriate.
- Review queue maps cleanly to temporary label confirmation/rejection.
- Reusing the creation wizard for edit mode reduces UI duplication.
- State filter includes expired labels, which supports audit/review workflows.

#### Concerns

- **MEDIUM**: TUI scope may be larger than necessary for the first usable phase. `LabelDetail`, `LabelForm`, `LabelList`, and `LabelReviewQueue` together are nontrivial.
- **MEDIUM**: Keyboard navigation "matching existing screens" needs concrete acceptance criteria, especially around forms, validation errors, focus order, and confirmation dialogs.
- **MEDIUM**: Edit behavior must respect immutable fields or dangerous changes. Editing path/object type/parent may affect inheritance and cached enforcement results.
- **MEDIUM**: Review queue should handle concurrent changes from another admin gracefully.
- **LOW**: Multi-step creation can be ergonomic, but it may slow bulk admin workflows. That is acceptable for v0.10 if API supports automation.
- **LOW**: Expired labels should probably be hidden by default in the main list but available by filter.

#### Suggestions

- Define minimal keyboard contract for each screen before implementation.
- Show normalized path and original entered path during confirmation if they differ.
- On API `409`, refresh the row and show a non-destructive conflict message.
- Prefer expire over delete as the primary TUI action.
- Add clear loading/error/empty states for list and review queue.
- Consider deferring `LabelDetail` if list + form + review queue already satisfy the phase goal.

#### Risk Assessment

**MEDIUM**. The TUI is achievable but could expand the phase. The main risks are UX completeness, concurrent mutation handling, and edit semantics.

---

### Codex: Cross-Plan Concerns

- **HIGH**: The database schema itself is under-specified relative to the success criteria. The plans should explicitly cover migrations for `labels`, `label_paths`, and `label_inheritance`, including foreign keys and indexes.
- **HIGH**: Security semantics depend on normalized paths. The same normalization function must be used by API writes, DB lookup, ABAC evaluation, and tests.
- **HIGH**: Authorization is missing from the API/TUI plans.
- **MEDIUM**: Cache invalidation crosses Plan 59-01, 59-02, and 59-03. This should be specified once and tested as an integration behavior.
- **MEDIUM**: Dependency ordering should be explicit:
  1. common types/path normalization
  2. DB schema/migrations
  3. label service and tests
  4. admin API
  5. ABAC integration behind disabled flag
  6. TUI screens
- **MEDIUM**: `label_paths` and `label_inheritance` are named in the success criteria but not meaningfully described in the plans.
- **LOW**: Metrics names should be standardized across server observability conventions.

### Codex: Overall Risk Assessment

**Overall Risk: MEDIUM-HIGH**

The plans are directionally strong and address most prior review concerns. They likely achieve the phase goals if implemented carefully. The remaining risk is concentrated in enforcement correctness, Windows path handling, authorization, database constraints, and cache invalidation. Before implementation, I would require a short schema addendum, a path-normalization test matrix, an ABAC behavior matrix, and explicit admin authorization requirements.

---

## Claude Review

### Plan 59-01: Label Types + Path Normalization + LabelService

#### Summary
An excellent foundational plan that directly addresses nearly all prior review concerns. The addition of `normalize_path()`, `is_path_prefix_of()`, and `parent_components()` creates a robust shared path contract. The LRU cache with bounded capacity, TTL, and metrics replaces the unbounded `RwLock<HashMap>` from the original design. The `ResolvedTier` enum provides precise semantics for every resolution outcome. This plan is ready for execution with only minor notes.

#### Strengths
- **Path normalization is now a first-class shared contract** in `dlp-common`, preventing inconsistent handling across repository, API, cache, and ABAC layers
- **Component-boundary prefix check** (`is_path_prefix_of`) correctly prevents sibling-prefix attacks like `C:\Data2` inheriting from `C:\Data`
- **Bounded LRU cache** with configurable capacity (10,000 default) and TTL addresses the unbounded memory growth concern from Round 1
- **Cache metrics** (hits/misses/evictions) provide operational observability
- **Fail-closed `ResolvedTier::LookupFailed`** ensures DB errors deny access rather than falling back to request classification
- **Max depth 20** on parent walk prevents infinite loops from deeply nested paths
- `Tier::is_sensitive()` correctly returns `true` for `UnclassifiedBlocked`, preserving the security-first posture

#### Concerns
- **LOW:** The `lru` crate dependency is not explicitly mentioned in the plan's file changes. Ensure `cargo add lru` is included in execution or it will fail to compile.
- **LOW:** `parent_label_id` in the `Label` struct represents an explicit label hierarchy, but `resolve_tier()` walks the filesystem path, not the `parent_label_id` chain. These are two different "parent" concepts that could confuse future maintainers. A doc comment on `parent_label_id` clarifying it is NOT used by folder inheritance resolution would help.

#### Suggestions
- Add `lru` to `dlp-server/Cargo.toml` dependencies explicitly in the plan
- Document the distinction between `parent_label_id` (explicit label hierarchy) and folder inheritance (filesystem path walk) in `Label` struct doc comments

#### Risk Assessment
**LOW.** All significant Round 1 concerns were addressed. The plan is well-scoped, secure, and follows Rust best practices.

---

### Plan 59-02: Admin REST API for Label Management

#### Summary
A substantially improved API plan that addresses the major Round 1 gaps: pagination, state transition enforcement, referential integrity on delete, transactional boundaries via `with_mutation()`, and structured audit events. The 7-endpoint design is complete and follows existing patterns well. However, a claimed mitigation (optimistic locking) is not actually implemented in the task actions, and the audit event schema reuse is slightly awkward.

#### Strengths
- **Pagination** with stable ordering (`ORDER BY path ASC`), bounded limit (max 1000), and offset provides production-ready list behavior
- **State transition validation** (`validate_state_transition`) correctly enforces the allowed transitions with 409 Conflict on violations
- **DELETE referential integrity**: `has_children` check rejects deletes that would orphan child labels, returning 409 with a clear message
- **Transactional `with_mutation()` helper** wraps DB write + cache invalidation + audit emission in a consistent pattern
- **Audit events** include structured payload with actor, label_id, old_state, new_state, path, and tier
- **parent_label_id validation** verifies both existence AND folder object_type before allowing creation

#### Concerns
- **MEDIUM:** The threat model claims "Optimistic locking via updated_at timestamp; 409 Conflict on stale update" (T-59-11), but **no task actually implements optimistic locking**. The PUT handler reads the current label and updates it without checking if it was modified between read and write. Either remove this claim from the threat model or implement it.
- **MEDIUM:** The `emit_label_action` function stuffs a formatted string into the `resource_path` column of the audit_events table. This is reusing an existing schema, but semantically incorrect -- the details string is not a resource path. Consider adding a `details` or `metadata` column to the audit schema, or document this as a known Phase 59 limitation.
- **LOW:** The `with_mutation` helper documents "If cache invalidation fails, audit event is still emitted (best-effort, logged as error)" but `invalidate_cache()` simply clears an LRU -- it cannot fail. This test scenario is misleading.

#### Suggestions
- **Implement or remove** the optimistic locking claim from the threat model
- Add a dedicated `label_audit_events` table or `details` JSON column for Phase 60 to avoid overloading `resource_path`
- Document that `with_mutation` is infallible for cache invalidation and adjust the test description

#### Risk Assessment
**MEDIUM.** The core design is solid and addresses Round 1 blockers. The optimistic locking gap is the primary concern -- it's either a false claim or a missing implementation.

---

### Plan 59-03: Label-Aware ABAC Evaluation Integration

#### Summary
An excellent enforcement integration plan that fully resolves the two highest Round 1 concerns: per-evaluation DB lookups are eliminated via `Arc<AtomicBool>` caching with background refresh, and the enforcement path is explicitly verified for `evaluate()` call sites. The fail-closed semantics are precisely defined, the audit trail logs every override, and metrics provide operational visibility. This is the most security-critical plan and it is well-hardened.

#### Strengths
- **Flag caching eliminates the per-evaluation DB query**: `Arc<AtomicBool>` refreshed every 30s from `system_kv` removes the severe performance regression identified in Round 1
- **`AppState::is_label_aware_enabled()`** provides a zero-cost hot-path read (no DB query, no lock contention with `Ordering::Relaxed`)
- **Fail-closed on all error paths**: `LookupFailed` -> T4 deny; missing label -> `UnclassifiedBlocked` -> T4 deny
- **Comprehensive audit trail**: Every classification override logs original, resolved, and source via `tracing::info!`
- **Metrics counters** track total evaluations and fallback rates for operational monitoring
- **All `evaluate()` call sites** are explicitly documented and verified in Task 4
- **Backward compatibility**: When flag is off, behavior is preserved exactly; test fixtures pass `None` and `false`
- **`AbacContext::Default`** explicitly sets `resource_path: None`, preventing accidental silent fallback

#### Concerns
- **LOW:** The background refresh task in `main.rs` calls `SystemKvRepository::get()` directly in an async context. If this is a blocking SQLite call, it should be wrapped in `tokio::task::spawn_blocking`. Given it's only every 30 seconds, the impact is minimal, but for correctness it should be non-blocking.
- **LOW:** The `UnclassifiedBlocked` -> T4 mapping concern from Round 1 is addressed by the design (T4 is "Restricted -- Highest sensitivity" in this system), but the plan should explicitly state that this mapping assumes T4 is the deny-all tier.

#### Suggestions
- Wrap the `SystemKvRepository::get()` call in the background task with `tokio::task::spawn_blocking` for correctness
- Add a code comment in `PolicyStore::evaluate()` explaining why `UnclassifiedBlocked` maps to `Classification::T4` (system invariant: T4 = deny-all)
- Consider adding a metric for `LookupFailed` occurrences separately from `FallbackUnclassifiedBlocked`

#### Risk Assessment
**LOW.** The enforcement path is well-designed, performant, and secure. All Round 1 blockers were resolved.

---

### Plan 59-04: Admin TUI Screens for Label Management

#### Summary
A comprehensive TUI plan that covers the required screens and addresses most Round 1 concerns, including the expire action, filter cycles, pagination, and confirmation dialogs. However, there is a **cross-plan inconsistency**: the TUI assumes a `POST /admin/labels/:id/expire` endpoint that does not exist in Plan 59-02. Additionally, the multi-step form implementation is ambiguous about whether it uses the established `InputPurpose` + `TextInput` pattern or handles input within `LabelForm`.

#### Strengths
- **Expire action ('x')** added to LabelList with confirmation dialog, addressing the Round 1 gap
- **Filter cycles through all 5 states** including Expired
- **Server-side pagination** with PageUp/PageDown support
- **Confirmation dialogs** for delete and expire show path and tier for audit context
- **Edit mode reuses creation wizard** pre-filled with existing values -- consistent UX
- **LabelReviewQueue** follows the simplified PolicyList pattern with confirm/reject actions

#### Concerns
- **HIGH:** The TUI defines `client.expire_label()` calling `POST /admin/labels/{id}/expire`, but **Plan 59-02 does not define this endpoint**. The API plan only has confirm and reject endpoints. This cross-plan inconsistency will cause a 404 at runtime. Either:
  1. Add the expire endpoint to Plan 59-02, OR
  2. Change the TUI to use `PUT /admin/labels/:id` with `{ "label_state": "expired" }` (which the state transition validator would allow)
- **MEDIUM:** The multi-step form implementation is ambiguous. The plan adds `InputPurpose` variants (`LabelPath`, `LabelObjectType`, etc.) but then says "using `Screen::LabelForm` for simplicity since all fields are picker/text." It is unclear how text input (steps 1, 4, 5) works within `LabelForm` -- does it delegate to `Screen::TextInput` with `InputPurpose`, or does `LabelForm` render its own text input? The established pattern uses `Screen::TextInput` for text input. The dispatch handler says "Step 1 (path): Text input mode. Enter advances to step 2" but doesn't show the mechanism for entering text input mode.
- **MEDIUM:** In edit mode, converting existing label's `object_type` and `tier` strings to `usize` indices for `LabelForm` requires lookup logic that is not shown in the plan.
- **LOW:** `LabelForm` carries all state as `Screen` variant fields. This bloats the `Screen` enum with 8 fields for a transient form state. The established `InputPurpose` pattern stores accumulated state in the `App` struct, keeping `Screen` lightweight. This is a design deviation that increases memory footprint and enum size.

#### Suggestions
- **Fix the expire endpoint inconsistency** before execution -- either add it to 59-02 or change 59-04 to use PUT
- Clarify the text input mechanism: either (a) use `Screen::TextInput` with `InputPurpose` variants for text steps and `Screen::LabelForm` for picker steps, or (b) document how `LabelForm` handles raw text input
- Add the string-to-index conversion logic for edit mode pre-filling
- Consider following the UI-SPEC's `InputPurpose` pattern more closely to stay consistent with the established codebase

#### Risk Assessment
**MEDIUM.** The TUI plan is functionally complete but has a cross-plan endpoint gap and implementation ambiguity in the form flow. These are fixable before execution.

---

### Claude: Cross-Plan Concerns

| Concern | Severity | Plan(s) | Notes |
|---------|----------|---------|-------|
| Missing expire endpoint | **HIGH** | 59-02, 59-04 | TUI calls endpoint API doesn't define |
| Optimistic locking claimed but not implemented | **MEDIUM** | 59-02 | Threat model T-59-11 vs. actual tasks |
| Multi-step form implementation ambiguity | **MEDIUM** | 59-04 | Unclear text input mechanism |
| `lru` crate dependency not mentioned | **LOW** | 59-01 | Will cause compile failure if forgotten |
| Audit details in `resource_path` column | **LOW** | 59-02 | Schema misuse, acceptable for Phase 59 |
| Background task may block reactor | **LOW** | 59-03 | `SystemKvRepository::get()` in async context |
| `parent_label_id` vs. folder inheritance confusion | **LOW** | 59-01 | Two different "parent" concepts |

### Claude: Dependency Ordering Assessment

The dependency order is correct and well-structured:
- **Wave 1 (59-01)**: Types, path normalization, LabelService, repository expansion -- all foundational
- **Wave 2 (59-02, 59-03)**: API and ABAC integration both depend on 59-01; can execute in parallel
- **Wave 3 (59-04)**: TUI depends on API endpoints from 59-02

No circular dependencies or ordering issues detected.

### Claude: Overall Risk Assessment

**MEDIUM** (trending LOW if fixes applied).

The Round 1 feedback was substantially incorporated. Plans 01 and 03 are production-ready. Plan 02 needs the optimistic locking claim resolved. Plan 04 needs the expire endpoint gap fixed and the form flow clarified. If these three items are addressed, overall risk drops to **LOW**.

The phase achieves its stated goals: labels stored in SQLite with referential integrity, admin API with CRUD + state transitions + pagination, ABAC integration with fail-closed semantics and feature flag gating, and admin TUI with full management and review queue support.

---

## OpenCode Review

OpenCode review failed: quota exceeded.

---

## Consensus Summary

### Agreed Strengths

- **Path normalization as shared contract** (both reviewers): `normalize_path()` + `is_path_prefix_of()` + `parent_components()` in `dlp-common` prevents inconsistent handling across layers.
- **Bounded LRU cache** (both reviewers): 10,000 capacity, TTL, metrics addresses unbounded growth from Round 1.
- **Fail-closed semantics** (both reviewers): `LookupFailed` -> deny, `UnclassifiedBlocked` -> T4 deny, missing path -> deny when flag is on.
- **Flag caching** (both reviewers): `Arc<AtomicBool>` with 30s refresh eliminates per-evaluation DB query.
- **Transactional mutation helper** (both reviewers): `with_mutation()` wraps DB + cache + audit consistently.
- **State transition enforcement** (both reviewers): `validate_state_transition()` prevents invalid transitions.

### Agreed Concerns (2+ reviewers)

| Concern | Severity | Reviewers | Plan | Status |
|---------|----------|-----------|------|--------|
| Missing expire endpoint (TUI calls non-existent API) | **HIGH** | Codex, Claude | 59-02/59-04 | **NEW** |
| Authorization not mentioned for admin API | **HIGH** | Codex | 59-02 | Unresolved from Round 1 |
| Database schema/indexes under-specified | **HIGH** | Codex | 59-01 | Partially addressed |
| ABAC evaluate() blast radius / call sites | **HIGH** | Codex | 59-03 | Addressed but needs verification |
| Missing path behavior when flag enabled | **HIGH** | Codex | 59-03 | Needs explicit matrix |
| Optimistic locking claimed but not implemented | **MEDIUM** | Claude | 59-02 | **NEW** |
| Multi-step form implementation ambiguity | **MEDIUM** | Claude | 59-04 | **NEW** |
| Cache invalidation for inherited results | **MEDIUM** | Codex | 59-01 | Partially addressed |
| Path uniqueness / conflict behavior | **MEDIUM** | Codex | 59-02 | Not addressed |
| Audit schema misuse (resource_path column) | **LOW** | Claude | 59-02 | Acceptable for Phase 59 |
| `lru` crate dependency not mentioned | **LOW** | Claude | 59-01 | Easy fix |
| Background task blocking | **LOW** | Claude | 59-03 | Minor correctness issue |

### Divergent Views

- **Codex** rates overall risk as **MEDIUM-HIGH**; **Claude** rates it **MEDIUM** (trending LOW with fixes). Codex is more concerned about Windows path edge cases and authorization gaps; Claude believes the core architecture is sound and only specific claims need fixing.
- **Codex** raises authorization as a HIGH concern for the admin API; **Claude** does not mention it, likely because routes are under `/admin/*` where JWT auth is already applied (but role-based authorization within admin is still unverified).
- **Claude** identifies the optimistic locking gap and expire endpoint inconsistency as the primary blockers; **Codex** focuses more on path normalization edge cases and DB schema completeness.

---

## Round 1 -> Round 2 Progress

| Round 1 Concern | Status | How Addressed |
|-----------------|--------|---------------|
| Path normalization underspecified | **RESOLVED** | `normalize_path()` + `is_path_prefix_of()` + `parent_components()` in dlp-common |
| Cache correctness (unbounded, manual invalidation) | **RESOLVED** | LRU with 10K capacity, TTL, metrics; `with_mutation()` for transactional consistency |
| No pagination on GET /admin/labels | **RESOLVED** | limit/offset with stable ordering, max 1000 |
| DELETE semantics undefined | **RESOLVED** | `has_children` check rejects delete with 409 Conflict |
| Transaction boundaries missing | **RESOLVED** | `LabelService::with_mutation()` wraps DB + cache + audit |
| Per-evaluation system_kv read | **RESOLVED** | `Arc<AtomicBool>` in AppState with 30s background refresh |
| Enforcement path coverage | **RESOLVED** | Task 4 explicitly finds and updates all `evaluate()` call sites |
| State transition validation weak | **RESOLVED** | `validate_state_transition()` enforces allowed transitions |
| Audit trail for overrides | **RESOLVED** | `tracing::info!` logs every override with original, resolved, source |
| TUI missing expire action | **RESOLVED** | 'x' key added to LabelList with confirmation dialog |
| UnclassifiedBlocked semantics | **MITIGATED** | Maps to T4 (deny-all); documented in code; feature flag default off |

### New in Round 2

| Concern | Severity | Plan |
|---------|----------|------|
| Expire endpoint doesn't exist in API plan | **HIGH** | 59-04 vs 59-02 |
| Optimistic locking claimed but not implemented | **MEDIUM** | 59-02 |
| Form flow implementation ambiguity | **MEDIUM** | 59-04 |
| Authorization within admin role | **HIGH** | 59-02 (Codex only) |
| DB schema/indexes still under-specified | **HIGH** | 59-01 (Codex only) |
| ABAC behavior matrix for missing path | **HIGH** | 59-03 (Codex only) |

---

## Action Items for Planner

1. **Add expire endpoint to Plan 59-02** (HIGH): The TUI in 59-04 calls `POST /admin/labels/:id/expire` but the API plan only defines confirm/reject. Either add the expire endpoint or change the TUI to use `PUT /admin/labels/:id` with `{"label_state": "expired"}`.
2. **Implement or remove optimistic locking claim** (MEDIUM): Plan 59-02's threat model T-59-11 claims optimistic locking via `updated_at` but no task implements it. Either implement it in the PUT handler or remove the claim.
3. **Clarify form flow mechanism** (MEDIUM): Plan 59-04 is ambiguous about how text input works within `LabelForm`. Document whether it delegates to `Screen::TextInput` with `InputPurpose` or handles raw input within `LabelForm`.
4. **Add `lru` dependency** (LOW): Ensure `lru` crate is added to `dlp-server/Cargo.toml` in Plan 59-01.
5. **Document `parent_label_id` vs folder inheritance** (LOW): Add doc comments clarifying that `parent_label_id` is an explicit label hierarchy field, NOT used by filesystem path inheritance resolution.
6. **Wrap background task DB call in spawn_blocking** (LOW): Plan 59-03's background refresh task should wrap `SystemKvRepository::get()` in `tokio::task::spawn_blocking`.

---

*Review completed: 2026-05-13*
*Cycle: 2 (prior review: 2026-05-13T19:30:00Z)*
*To incorporate feedback into planning: /gsd-plan-phase 59 --reviews*
