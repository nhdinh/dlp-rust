---
phase: 59
reviewers: [codex, claude]
reviewed_at: 2026-05-13T19:30:00Z
plans_reviewed: [59-01-PLAN.md, 59-02-PLAN.md, 59-03-PLAN.md, 59-04-PLAN.md]
---

# Cross-AI Plan Review — Phase 59

## Codex Review

### Summary

The Phase 59 plan is mostly coherent and covers the core Label Service lifecycle: shared types, central resolution service, REST management, ABAC integration, and operator UI. The dependency order is sensible: common types and service first, API/ABAC integration second, TUI last. The biggest risks are around semantic consistency between `Tier`, `Classification`, and `UnclassifiedBlocked`; cache correctness; path normalization; and the ABAC integration boundary. The plans achieve the phase goals in broad terms, but several details need tightening before implementation to avoid security regressions or inconsistent enforcement.

### Plan 59-01: Label Types + LabelService

#### Strengths

- Establishes shared label types in `dlp-common`, which is the right place for cross-crate API payloads and enforcement inputs.
- Keeps `Classification` unchanged while introducing label-service-specific `Tier`, matching the user decision.
- Explicit resolution order is correct: exact match, parent folder, fallback.
- 30-second TTL cache with invalidation is a reasonable first implementation for server-side lookup performance.
- Initializing `LabelService` in `AppState` gives later API and ABAC work a stable integration point.

#### Concerns

- **HIGH:** Path matching and inheritance are underspecified. Windows paths need canonicalization rules for drive-letter casing, slashes, trailing separators, UNC paths, long-path prefixes, symlinks/junctions, and case-insensitive comparison.
- **HIGH:** "Parent folder" resolution can be wrong or insecure if implemented with naive string prefix matching. `C:\Data2` must not inherit from `C:\Data`.
- **MEDIUM:** Cache key strategy is unclear. Exact-path and parent lookup caching may need different invalidation behavior.
- **MEDIUM:** `UnclassifiedBlocked.is_sensitive() returns true` is directionally right, but the mapping to ABAC/classification must be documented precisely to preserve the deny-by-default invariant.
- **LOW:** `Tier bridges to/from Classification` risks quietly collapsing distinctions if `UnclassifiedBlocked` has no true `Classification` equivalent.

#### Suggestions

- Define a path normalization helper early and use it everywhere: repository, API validation, cache keys, and ABAC lookup.
- Add tests for inheritance boundaries: sibling prefixes, root drive labels, UNC shares, mixed separators, casing differences, and trailing slash behavior.
- Treat `UnclassifiedBlocked` as a first-class fallback result, not just a lossy conversion to `Classification`.
- Consider cache entries keyed by normalized path plus resolution type, with full invalidation on mutation for Phase 59.

#### Risk Assessment

**MEDIUM-HIGH.** The service is foundational and security-sensitive. The design is sound, but path resolution details can directly affect enforcement correctness.

---

### Plan 59-02: Admin REST API for Label Management

#### Strengths

- Endpoint shape matches existing registry-style admin patterns, which should reduce implementation risk.
- Validation requirements are explicit and aligned with the planning decisions.
- Cache invalidation after all mutations is correctly called out.
- Audit events for all mutating operations are required, which is important for operator accountability.
- Review queue operations are separated from generic update, making state transitions clearer.

#### Concerns

- **HIGH:** Authorization is not mentioned. These endpoints mutate enforcement metadata and should require admin/operator privileges consistent with other admin APIs.
- **HIGH:** State transition validation needs to enforce allowed transitions, not just enum validity. For example, `rejected -> confirmed` should not slip through via `PUT`.
- **HIGH:** `DELETE /admin/labels/:id` semantics are risky. Physical deletion can erase audit-relevant history and break child `parent_label_id` references.
- **MEDIUM:** Parent validation says `parent_label_id -> folder`, but also needs cycle prevention and path consistency checks.
- **MEDIUM:** Filtering and pagination are missing. `GET /admin/labels` can become expensive and noisy without `limit`, `offset`/cursor, and stable ordering.
- **MEDIUM:** Audit event payload content is unspecified. It should include actor, label id, old state, new state, path, tier, owner, and reason where applicable.
- **LOW:** `PUT` may be too broad unless immutable fields are defined. Updating `id`, timestamps, and possibly `created_at` should be impossible.

#### Suggestions

- Prefer soft delete or state transition to `expired` unless hard delete is explicitly required.
- Add `reason` fields to confirm/reject/delete/expire operations if audit workflows need review context.
- Define which fields are mutable through `PUT`.
- Add pagination and deterministic sorting to list endpoint.
- Add API tests for invalid transitions, unauthorized access, parent cycles, bad paths, and cache invalidation.

#### Risk Assessment

**HIGH.** This API controls enforcement state. Without strict authorization, transition rules, and delete semantics, it could weaken the DLP model.

---

### Plan 59-03: Label-Aware ABAC Evaluation Integration

#### Strengths

- Feature flag defaulting off is the right compatibility strategy for a breaking enforcement change.
- Passing `Option<&LabelService>` preserves old call sites and allows incremental migration.
- Reading the feature flag once per evaluation is better than per-policy reads.
- Overriding `resource.classification` before policy evaluation fits the existing ABAC pipeline with minimal disruption.
- Explicit fallback to `UnclassifiedBlocked` supports fail-closed behavior.

#### Concerns

- **HIGH:** Mapping `UnclassifiedBlocked` to `T4` may be insufficient if policies treat `T4` as "highly sensitive but allowed under conditions" rather than "unknown must block." The requirement says fallback to `Unclassified-Blocked`, not merely T4.
- **HIGH:** The critical invariant must be tested directly: NTFS allow plus ABAC deny must still deny after label-aware resolution.
- **MEDIUM:** `PolicyStore::evaluate() accepts Option<&LabelService>` may blur responsibilities. If policy evaluation silently behaves differently depending on an optional parameter, test coverage must be strong.
- **MEDIUM:** Failure behavior is unspecified. If label DB lookup fails, the secure default should likely be deny / `UnclassifiedBlocked`, not fallback to request classification.
- **MEDIUM:** `resource_path` population from `resource.path` assumes all relevant evaluate requests include a reliable path.
- **LOW:** `Default` for `AbacContext` could accidentally produce contexts without `resource_path`, causing silent fallback behavior.

#### Suggestions

- Add explicit tests for feature flag off, feature flag on with exact label, inherited label, missing label, label service error, and no resource path.
- Decide whether lookup errors are fail-closed. For DLP, fail-closed is usually the safer default.
- Consider returning a richer resolved label result from `LabelService`, such as `Exact`, `Inherited`, `FallbackUnclassifiedBlocked`, `LookupFailed`.
- Avoid treating `UnclassifiedBlocked` as just another classification if the policy language cannot express "block unknown" reliably.

#### Risk Assessment

**HIGH.** This is the enforcement-critical part of the phase. The plan is directionally correct but needs sharper failure semantics and tests around deny behavior.

---

### Plan 59-04: Admin TUI Screens for Label Management

#### Strengths

- Correctly depends on the REST API and avoids blocking earlier backend work.
- Screen set covers the necessary operator workflows: list, review queue, detail, create/edit.
- Reuses established TUI patterns, reducing design and implementation risk.
- Client method list maps cleanly to the planned REST API.
- Multi-step creation flow is appropriate for structured label creation.

#### Concerns

- **MEDIUM:** Edit flow may conflict with API mutability rules if those are not defined in 59-02.
- **MEDIUM:** Review queue needs clear error handling for stale labels, already-reviewed labels, failed confirms/rejects, and refresh after mutation.
- **MEDIUM:** Large label lists need pagination or incremental loading, otherwise the TUI may become slow or unwieldy.
- **LOW:** Parent label selection can become awkward if it requires manually typing IDs.
- **LOW:** Delete action needs confirmation and should reflect whether delete is hard delete, soft delete, or expire.

#### Suggestions

- Implement the TUI after API response shapes and mutability rules are finalized.
- Add clear refresh behavior after confirm/reject/delete.
- Include server-side pagination support before building the list UI around unbounded results.
- Use folder-label search/selection for `parent_label_id` if practical.
- Make destructive actions require confirmation and show audit-relevant context.

#### Risk Assessment

**MEDIUM.** The TUI is less security-critical than ABAC/API, but it depends heavily on API semantics being precise.

---

### Codex: Cross-Plan Concerns

- **HIGH:** Path normalization should be a shared contract, not independently implemented in service, API, and ABAC layers.
- **HIGH:** Enforcement fallback behavior must be fail-closed and explicitly tested.
- **HIGH:** `UnclassifiedBlocked` needs precise semantics across `Tier`, `Classification`, policy evaluation, API payloads, and UI display.
- **MEDIUM:** Repository capabilities may need expansion for filtered list, pagination, parent validation, and state transition helpers.
- **MEDIUM:** Cache invalidation is mentioned in the API plan, but any non-API mutation path also needs invalidation.
- **MEDIUM:** Audit event schema additions may be needed before API work can cleanly emit `label_*` events.
- **LOW:** `sonar-scanner` in every backend plan may be excessive for inner-loop verification unless this project already runs it locally.

### Codex: Overall Risk Assessment

**HIGH.** The phase is achievable and the implementation order is reasonable, but the label service becomes part of the enforcement decision path. The main risks are not missing files or endpoints; they are semantic correctness risks: path inheritance, fail-closed behavior, state transitions, authorization, and `UnclassifiedBlocked` handling. Tightening those contracts before implementation would significantly reduce the chance of a security-affecting regression.

---

## Claude Review

### Plan 59-01: Label Types + LabelService

#### Summary
A well-structured foundational plan that cleanly separates types (`dlp-common`) from service logic (`dlp-server`). The caching strategy and resolution hierarchy are pragmatically designed with a security-first mindset (UnclassifiedBlocked → most restrictive). However, several operational concerns around cache correctness and concurrency at scale need attention before execution.

#### Strengths
- Clean domain separation: types in `dlp-common`, service/cache in `dlp-server`
- Resolution order (exact → parent → fallback) is deterministic and secure
- TTL cache with explicit invalidation is simple and predictable
- `UnclassifiedBlocked.is_sensitive() == true` correctly implements the security-first principle
- `AppState` extension follows existing server patterns

#### Concerns
- **HIGH** — Cache invalidation is manual/cooperative: every mutating code path must remember to call `invalidate()`. A missed invalidation (in future maintenance, a new endpoint, or a direct DB update) results in stale tier data and potential security bypass (ABAC evaluates on stale T1 instead of current T4).
- **HIGH** — `RwLock<HashMap>` with no size bound: in a large enterprise deployment with millions of labeled paths, this is an unbounded memory growth risk. No LRU or eviction policy is mentioned.
- **MEDIUM** — 30-second TTL on security-critical data means a file could be accessed with an incorrect (stale) tier for up to 30 seconds after a label change. For a DLP system, this window may be unacceptable for high-sensitivity environments.
- **MEDIUM** — No cycle detection in `parent_label_id` resolution. A circular reference (A → B → A) would cause infinite recursion or stack overflow.
- **LOW** — No cache metrics (hit rate, miss rate, eviction count) for operational observability.

#### Suggestions
- Replace manual invalidation with an event-based invalidation mechanism (channel or callback) so that `LabelRepository` mutations automatically trigger cache invalidation
- Add a bounded cache (e.g., `lru::LruCache` or `moka`) with a configurable max capacity
- Consider making TTL configurable via `system_kv` so admins can trade freshness for performance
- Add cycle detection in parent resolution with a max depth limit (e.g., 10 levels)
- Export cache metrics via `tracing` spans or a metrics counter

#### Risk Assessment
**MEDIUM-HIGH.** The service is foundational and security-sensitive. Path resolution and cache correctness are the primary risks.

---

### Plan 59-02: Admin REST API for Label Management

#### Summary
A comprehensive CRUD API following established server patterns with good input validation and audit event coverage. The 7-endpoint design is complete for Phase 59 requirements. However, the plan lacks critical operational concerns around pagination, referential integrity on delete, and transactional consistency between DB mutations, cache invalidation, and audit emission.

#### Strengths
- Follows proven patterns from `disk_registry` and `device_registry`
- Strong input validation: absolute path, enum bounds, parent type constraints
- Audit events emitted for all mutations — satisfies compliance requirements
- Cache invalidation after every mutating operation

#### Concerns
- **HIGH** — No pagination on `GET /admin/labels`. In an enterprise with millions of files, this endpoint will OOM the server or timeout. This is a production readiness blocker.
- **HIGH** — `DELETE /admin/labels/:id` with no discussion of referential integrity. Child labels with `parent_label_id` referencing the deleted label become orphaned. SQLite FK constraints (if enabled) may prevent deletion or cascade — behavior must be explicitly defined.
- **HIGH** — No transaction boundaries. A mutation involves: (1) DB write, (2) cache invalidation, (3) audit event emit. If (1) succeeds but (2) or (3) fails, the system is inconsistent (stale cache or missing audit trail).
- **MEDIUM** — `parent_label_id` validation checks type but does not verify the parent label actually exists. A POST with `parent_label_id` pointing to a deleted/non-existent label would succeed.
- **MEDIUM** — No bulk operations. Creating labels for 100k files in a folder one-by-one via REST is operationally infeasible. At minimum, a bulk import endpoint should be planned for Phase 60.
- **LOW** — No rate limiting or concurrency control on mutations. Two admins simultaneously updating the same label could race.

#### Suggestions
- Add `limit`/`offset` pagination to `GET /admin/labels`; consider cursor-based pagination for very large datasets
- Define DELETE behavior explicitly: either soft-delete (`deleted_at` timestamp), cascade delete children, or reject if children exist
- Wrap DB write + cache invalidation + audit emit in a single unit of work; use a repository-level method that returns an invalidation token, or use a channel-based async commit
- Add existence validation for `parent_label_id`
- Add `409 Conflict` handling for concurrent updates (optimistic locking with `updated_at` or version field)

#### Risk Assessment
**HIGH.** This API controls enforcement state. Without pagination, referential integrity, and transactional boundaries, it has production readiness gaps.

---

### Plan 59-03: Label-Aware ABAC Evaluation Integration

#### Summary
A carefully designed integration plan that introduces label-aware evaluation behind a feature flag, preserving backward compatibility. The AbacContext extension is minimal and clean. The critical weakness is the per-evaluation database lookup for the feature flag, which will severely impact throughput, and a potential gap in enforcement-path coverage.

#### Strengths
- Feature flag (`label_aware_evaluation_enabled`) enables safe, gradual rollout
- `UnclassifiedBlocked` → `T4` mapping is the correct security choice
- `AbacContext` extension with `resource_path` is backward-compatible (optional field)
- All existing call sites passing `None` provides a clean migration path

#### Concerns
- **HIGH** — `system_kv` flag read **once per `evaluate()` call**. In high-throughput enforcement scenarios (every file open, every clipboard paste), this adds an SQLite query to every policy evaluation. This is a severe performance regression. The flag should be cached in memory with a TTL, or loaded into `AppState` at startup.
- **HIGH** — "Overrides `resource.classification` before policy evaluation" changes the core semantics of policy evaluation without explicit visibility. Existing policies may have been written assuming the original classification; silently overriding could violate security invariants that admins depend on. The override must be auditable and visible.
- **MEDIUM** — The plan states "Admin API evaluate handler passes `Some(&state.label_service)`" but does not verify that the **enforcement path** (dlp-agent → server → evaluate) also passes it. If enforcement calls `evaluate()` without the label service, the actual protection is not active in production. This is the most critical call site.
- **MEDIUM** — No audit trail when classification is overridden by the label service. An admin debugging why access was denied has no visibility into whether the label service changed the tier.
- **LOW** — No metrics on label resolution: how often is the fallback used? What's the cache hit rate? Operational blind spot.

#### Suggestions
- Cache `label_aware_evaluation_enabled` in `AppState` as an `Arc<RwLock<bool>>` or `Arc<AtomicBool>`, refreshed from `system_kv` periodically (e.g., 30s), not per-call
- Add the resolved tier and whether it was overridden to the evaluation response (or at least log it at `debug`/`info` level)
- Explicitly verify and document all `evaluate()` call sites: admin API, enforcement API, test fixtures — ensure enforcement path passes `Some(label_service)`
- Add a counter metric for label-aware evaluations (resolved vs fallback)
- Consider logging at `tracing::info!` level whenever a label overrides a classification for the first time on a given path (to aid debugging)

#### Risk Assessment
**HIGH.** This is the enforcement-critical part of the phase. The per-evaluation DB lookup and enforcement-path coverage gap are blockers for production use.

---

### Plan 59-04: Admin TUI Screens for Label Management

#### Summary
A well-scoped TUI plan following established UI patterns with appropriate screen decomposition. The multi-step creation flow is suitable for the complex label object. However, the plan has gaps in supporting the full state machine (especially expiry transitions) and clarity around the edit flow.

#### Strengths
- Screen decomposition mirrors proven patterns (`PolicyList`, `InputPurpose`)
- Multi-step form (path → type → tier → owner → parent → confirm) reduces cognitive load
- Separation of `LabelList` and `LabelReviewQueue` is good UX — admins have distinct workflows for browsing vs reviewing
- Full client API coverage (7 methods)

#### Concerns
- **MEDIUM** — D-15 defines state transitions: `temporary→confirmed`, `temporary→rejected`, `confirmed→expired`, `any→expired`. The TUI only supports `c/r` (confirm/reject) in the review queue. There is no UI path to expire a confirmed label. This is a gap in state machine coverage.
- **MEDIUM** — The `LabelForm` is described as "multi-step creation/edit". Multi-step flows are typically appropriate for creation (wizard-style), but editing usually requires direct field modification. Clarify whether editing reuses the creation wizard or uses a different form.
- **LOW** — No mention of handling the `expired` state in list filters. If expired labels accumulate, the default view may become cluttered.
- **LOW** — No confirmation dialog mentioned for destructive actions (delete). Given the security impact of deleting a label (reverting a file to `UnclassifiedBlocked`), this deserves an explicit confirmation.

#### Suggestions
- Add an "expire" action (`e` key) to `LabelList` for confirmed labels, or extend `LabelReviewQueue` to also show confirmed labels pending expiry review
- Clarify edit UX: either (a) edit uses the same multi-step wizard pre-populated, or (b) create a simpler direct-edit form for updates
- Ensure `LabelList` state filter cycles through all 4 states including `expired`
- Add a confirmation dialog for `delete` and `expire` actions showing the path and current tier
- Consider adding a "show inherited labels" toggle in `LabelList` to help admins understand why a file has a particular tier

#### Risk Assessment
**MEDIUM.** The TUI is less security-critical than ABAC/API, but it depends heavily on API semantics being precise.

---

### Claude: Overall Risk Assessment

**MEDIUM.**

The plans are architecturally sound and follow established project patterns, which reduces implementation risk. However, there are **three HIGH-severity concerns** that must be addressed before this phase can be considered production-ready:

1. **Performance**: Plan 59-03's per-evaluation `system_kv` lookup will bottleneck the enforcement path. This needs to be fixed before the feature flag is enabled in production.
2. **Consistency**: Plan 59-02 lacks transactional boundaries across DB write → cache invalidation → audit emit. In a distributed/concurrent system, partial failures create security holes (stale cache) or compliance gaps (missing audit).
3. **Completeness**: Plan 59-04 does not support the `expired` state transition, and Plan 59-03 may miss the enforcement-path integration if not explicitly verified.

If the HIGH items are resolved in the plans before execution, the risk drops to **LOW**. If they are executed as written, the phase will have operational and security gaps that require remediation in Phase 60.

---

## OpenCode Review

OpenCode review failed or returned empty output.

---

## Consensus Summary

### Agreed Strengths

- **Clean domain separation** (both reviewers): Types in `dlp-common`, service in `dlp-server`, API follows existing patterns — reduces implementation risk.
- **Feature flag strategy** (both reviewers): Default-off `label_aware_evaluation_enabled` is the right compatibility approach for a breaking enforcement change.
- **Resolution order** (both reviewers): Exact match → parent folder → UnclassifiedBlocked fallback is deterministic and security-first.
- **Established pattern reuse** (both reviewers): TUI follows proven PolicyList/InputPurpose patterns; API follows disk_registry/device_registry patterns.

### Agreed Concerns (2+ reviewers)

| Concern | Severity | Reviewers | Plan |
|---------|----------|-----------|------|
| Path normalization underspecified | HIGH | Codex, Claude | 59-01 |
| Cache correctness risks (manual invalidation, unbounded growth, stale data) | HIGH | Codex, Claude | 59-01 |
| No pagination on GET /admin/labels | HIGH | Codex, Claude | 59-02 |
| DELETE semantics / referential integrity undefined | HIGH | Codex, Claude | 59-02 |
| Transaction boundaries missing (DB write → cache → audit) | HIGH | Codex, Claude | 59-02 |
| Per-evaluation system_kv flag read is a performance regression | HIGH | Codex, Claude | 59-03 |
| Enforcement path may not pass LabelService to evaluate() | HIGH | Codex, Claude | 59-03 |
| UnclassifiedBlocked → T4 mapping may be semantically insufficient | HIGH | Codex, Claude | 59-03 |
| State transition validation weak (rejected→confirmed via PUT) | HIGH | Codex | 59-02 |
| No audit trail when classification is overridden | MEDIUM | Claude | 59-03 |
| TUI missing expire action for confirmed labels | MEDIUM | Claude | 59-04 |

### Divergent Views

- **Claude** rates overall risk as **MEDIUM** (with 3 HIGH items to fix), while **Codex** rates it **HIGH**. Codex is more pessimistic about the semantic correctness risks in the enforcement path; Claude believes the patterns are sound enough that fixing the identified HIGH items would drop risk to LOW.
- **Codex** raises authorization as a HIGH concern for the admin API; **Claude** does not mention it, likely because the plan states routes are under `/admin/*` where JWT auth is already applied.
- **Claude** suggests event-based cache invalidation and bounded caches (LRU/moka); **Codex** focuses more on path normalization as a shared contract across layers.

---

## Action Items for Planner

1. **Path normalization contract** (HIGH): Define a single `normalize_path()` helper used by repository, API validation, cache keys, and ABAC lookup. Add tests for sibling prefixes, casing, separators, UNC, long-path prefixes.
2. **Cache hardening** (HIGH): Add LRU bound to LabelCache; consider making TTL configurable via system_kv; add cache metrics.
3. **Pagination** (HIGH): Add `limit`/`offset` to `GET /admin/labels` before TUI implementation.
4. **DELETE semantics** (HIGH): Define behavior for child `parent_label_id` references on delete (reject if children exist, or cascade).
5. **Transaction boundaries** (HIGH): Wrap DB write + cache invalidation + audit emit in a single unit of work or callback mechanism.
6. **Flag caching** (HIGH): Cache `label_aware_evaluation_enabled` in AppState (AtomicBool refreshed periodically), not per-evaluation DB read.
7. **Enforcement path verification** (HIGH): Explicitly verify and document all `evaluate()` call sites, especially dlp-agent → server enforcement path.
8. **State transition enforcement** (HIGH): Add transition validation to prevent invalid state changes via PUT (e.g., rejected → confirmed).
9. **Audit trail for overrides** (MEDIUM): Log when label service overrides classification; include resolved tier in evaluation response or logs.
10. **TUI expire action** (MEDIUM): Add expire support to LabelList or LabelReviewQueue for confirmed labels.

---

*Review completed: 2026-05-13*
*To incorporate feedback into planning: /gsd-plan-phase 59 --reviews*
