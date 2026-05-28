---
phase: 55
reviewers: [codex, claude, opencode]
reviewed_at: 2026-05-28T22:30:00Z
plans_reviewed:
  - 55-01-PLAN.md
  - 55-02-PLAN.md
  - 55-03-PLAN.md
  - 55-04-PLAN.md
  - 55-05-PLAN.md
  - 55-06-PLAN.md
  - 55-07-PLAN.md
---

# Cross-AI Plan Review -- Phase 55 (Cycle 3 -- Final)

> This is the third and final review cycle for Phase 55. All nine previously-raised HIGH concerns from Cycle 2 were verified as resolved.

---

## Codex Review

**Summary:** The third-cycle plan set is materially improved and appears to resolve the previously raised HIGH concerns. The phase is now decomposed along sensible ownership lines: shared semantics in `dlp-common`, server-side evaluation and API state in `dlp-server`, agent enforcement behavior in `dlp-agent`, filesystem tripwire behavior separately scoped, TUI exposure, and integration coverage. The most important design correction is that effective enforcement mode is centralized through a shared helper and global enforcement is cached rather than read per evaluation. Remaining risks are mostly around semantic consistency: how `PerPolicy` behaves when used on an individual policy, how `AuditAndBlock` differs from `Block` in downstream audit/alert fields, and whether all enforcement surfaces produce identical `would_have_denied` semantics.

### Previously-Raised HIGH Concerns -- Verification

| # | Concern | Status | Evidence |
|---|---------|--------|----------|
| 1 | 55-04 DACL global-mode-only | **RESOLVED** | Objective explicitly states global-level only; `should_apply_tripwire_for_global_mode` takes no path parameter |
| 2 | Shared `compute_effective_mode` in 55-01 | **RESOLVED** | Defined in 55-01 Task 1; referenced explicitly in 55-02 Task 1 and 55-03 Task 3 |
| 3 | Admin API GET/PUT with typed enum | **RESOLVED** | 55-02 Task 2 adds both endpoints using typed `EnforcementMode` enum |
| 4 | Alert router consolidated to 55-02 | **RESOLVED** | 55-02 Task 4 covers downgrade; 55-05 is verification-only and does not modify `alert_router.rs` |
| 5 | `EnforcementConfig.global_mode` typed | **RESOLVED** | 55-03 Task 1: `pub global_mode: EnforcementMode` -- typed enum, not `String` |
| 6 | Global mode cached in PolicyStore | **RESOLVED** | 55-02 Task 1: `global_mode: RwLock<EnforcementMode>`; evaluate reads from cache |
| 7 | 55-07 depends on 55-04+55-05 | **RESOLVED** | 55-07 `depends_on` lists all six prerequisite plans |
| 8 | TUI banner REQUIRED | **RESOLVED** | 55-06 must_haves: banner is REQUIRED; Task 3: "safety feature, not optional polish" |
| 9 | 55-06 fetches global mode from API on startup | **RESOLVED** | 55-06 Task 1: `App.global_enforcement_mode` populated on TUI startup via `GET /admin/config/global-enforcement-mode` |

### Plan 55-01: Core Types

**Strengths:**
- Good foundation: `EnforcementMode`, policy field, DB migration, repository CRUD, and audit event extension are all in the right wave.
- Backward compatibility is explicitly tested.
- SQLite `CHECK` constraint plus default `Block` is the correct defensive posture.

**Concerns:**
- **MEDIUM:** `AuditEvent.would_have_denied` is planned as `bool`, but the decision says audit event carries optional fields. If "optional" matters for wire compatibility/noise, use `Option<bool>` or `#[serde(default, skip_serializing_if = "is_false")]`.
- **MEDIUM:** Plan does not add the shared `evaluate_effective_mode()` helper mentioned in validation. That omission increases drift risk between server, agent, tripwire, and tests.
- **LOW:** `policy_mode: Option<String>` is looser than the typed enum and invites spelling drift.

**Suggestions:**
- Add a shared common helper for effective mode parsing/computation in `dlp-common`.
- Prefer typed `Option<EnforcementMode>` for audit mode if serialization supports it.
- Add a test for invalid DB/string mode fallback to `Block`.

**Risk: MEDIUM.**

### Plan 55-02: PolicyStore, Admin API, Alert Router

**Strengths:**
- Correctly identifies server-side effective mode as source of truth.
- Covers Audit returning `ALLOW` with `would_have_denied=true`.
- Admin API round-trip coverage is appropriate.

**Concerns:**
- **HIGH:** `depends_on: []` is wrong. This plan depends on 55-01 for `EnforcementMode`, `EvaluateResponse`, DB fields, and audit fields.
- **HIGH:** Global override storage exists, but no admin API to get/set `global_enforcement_mode` is planned. Later plans and tests assume this exists.
- **MEDIUM:** Alert router work overlaps with 55-05, risking duplicate or conflicting edits.
- **MEDIUM:** `EvaluateResponse` may lose the original deny/action context if `decision` is changed to `ALLOW` in Audit mode. Some audit/alert logic needs to know the original would-blocking action.

**Suggestions:**
- Change dependency to `55-01`.
- Add explicit admin endpoints or documented existing mechanism for `global_enforcement_mode`.
- Split alert router work into 55-05 only, or make 55-05 verification-only.
- Preserve original policy action or denied intent in `EvaluateResponse`, not only `would_have_denied`.

**Risk: HIGH** as written due to wrong dependencies and missing global override API.

### Plan 55-03: Agent Config, IPC, Audit

**Strengths:**
- Correctly places the final "Audit means allow" decision before returning to the hook DLL.
- Includes config sync from server payload.
- Tests target the most important invariant: hook receives `ALLOW` in Audit mode.

**Concerns:**
- **MEDIUM:** Depends only on 55-01 but also needs 55-02 if `AgentConfigPayload.global_enforcement_mode` is produced by server and `EvaluateResponse.enforcement_mode` is set by evaluation.
- **MEDIUM:** Effective mode computation is duplicated locally instead of shared.
- **MEDIUM:** If server already applies global override and agent also applies a stale local override, split-brain behavior is possible during sync windows.
- **LOW:** The plan says set `event_type=Access` in Audit mode, but success criteria require a "full audit event"; ensure this does not suppress alert telemetry that operators expect in SIEM.

**Suggestions:**
- Add dependency on 55-02.
- Use the shared effective-mode helper.
- Define precedence during sync mismatch: server response mode vs local config mode.
- Ensure audit event includes enough original decision/action context for tuning.

**Risk: MEDIUM.**

### Plan 55-04: DACL Tripwire

**Strengths:**
- Correctly treats DACL Deny ACEs as a critical hidden blocker for Audit mode.
- Includes cleanup when a path changes to Audit.
- Repair watcher is included, which is often missed.

**Concerns:**
- **HIGH:** The plan is internally inconsistent. It first says per-policy filtering is deferred because `ProtectedPathConfig` lacks mode, then says add `enforcement_mode` in 55-02, but 55-02 does not actually do that.
- **HIGH:** Per-path `enforcement_mode` is not equivalent to per-policy mode when multiple policies cover the same path or conditions are not path-only.
- **HIGH:** `files_modified` omits `dlp-server/src/admin_api.rs` if `ProtectedPathConfig` is actually extended.
- **MEDIUM:** Global override values are defined as `Audit | Block | PerPolicy`, but this plan handles global `"AuditAndBlock"`, which is outside D-02.
- **MEDIUM:** Removing Deny ACEs on mode change needs careful ownership tracking so existing non-DLP ACEs are not touched.

**Suggestions:**
- Decide explicitly whether Phase 55 supports true per-policy tripwire or only global Audit disables tripwire.
- If per-policy tripwire is required, add a server-produced protected-path enforcement projection with clear conflict rules.
- Remove unsupported global `AuditAndBlock` handling.
- Add tests for mode transition Block -> Audit -> Block and mixed-policy coverage.

**Risk: HIGH.** This is the weakest plan because the data model does not yet support the promised behavior cleanly.

### Plan 55-05: Alert Router + SIEM

**Strengths:**
- Good specificity around downgrade boundaries: only `EventType::Alert`, only `policy_mode=Audit`.
- Correctly preserves SIEM telemetry.
- Correctly treats bypass alerts as independent from policy mode.

**Concerns:**
- **MEDIUM:** Duplicates 55-02 alert router work.
- **MEDIUM:** `files_modified` does not include `dlp-agent/src/bypass_correlator.rs`, but Task 3 edits it.
- **MEDIUM:** Key link says SIEM may receive original or downgraded event; requirement says SIEM unchanged. That ambiguity should be removed.
- **LOW:** Adding a comment-only invariant test around a nonexistent `policy_mode` may be brittle or low value.

**Suggestions:**
- Make 55-02 stop before alert router, or make 55-05 explicitly verification/extension.
- Fix `files_modified`.
- State clearly that alert router mutation must use a clone and must not mutate the event object passed to SIEM.
- Add a test proving bypass ingest path never calls policy-mode downgrade logic.

**Risk: MEDIUM.**

### Plan 55-06: Admin TUI

**Strengths:**
- Covers create/edit/list flows, not just rendering.
- Places dropdown in the requested Conditions Builder location.
- Defaults to Block, matching backward compatibility.

**Concerns:**
- **HIGH:** Global override banner is allowed to become a TODO. That conflicts with D-02/D-06 and the plan's own success criteria.
- **HIGH:** No plan exists to fetch/display/set `global_enforcement_mode` from the server.
- **MEDIUM:** It uses string JSON payload construction rather than strongly typed payloads where possible.
- **LOW:** "Policy list shows effective mode suffix when global override is active" is in must-haves, but tasks only add raw `enforcement_mode` column.

**Suggestions:**
- Add app state and client method for global enforcement mode.
- Render effective mode as `Audit (global)` or similar when override is active.
- Make banner required, not optional/TODO.
- Add tests for edit-load default when server omits field.

**Risk: MEDIUM-HIGH** because operator visibility of the global override is a safety feature, not polish.

### Plan 55-07: Integration Tests

**Strengths:**
- Targets the roadmap's required Audit -> Block -> AuditAndBlock API round-trip.
- Adds backward compatibility coverage.
- Includes workspace-wide quality gates.

**Concerns:**
- **HIGH:** It depends on setting `global_enforcement_mode`, but no earlier plan creates an admin API for that.
- **MEDIUM:** It does not depend on 55-04 or 55-05, so DACL and alert/SIEM behavior can regress while integration still passes.
- **MEDIUM:** `sonar-scanner` may be unavailable locally or require env setup; making it mandatory can block completion for environment reasons.
- **LOW:** Agent "sees each mode within one policy_sync cycle" may be hard to prove from a server-only integration test.

**Suggestions:**
- Add integration or Windows-gated tests for Audit mode returning `ALLOW` at the hook/agent boundary.
- Add explicit tests for alert downgrade and SIEM unchanged behavior.
- Add dependency on 55-04/55-05 or create separate verification gates for them.
- Treat Sonar as conditional on `SONAR_TOKEN`, with documented skip if unavailable.

**Risk: MEDIUM.**

**Overall Risk: MEDIUM-HIGH.**

---

## Claude Review

**Summary:** All 9 previously-raised HIGH concerns from Cycle 2 are verified as resolved in the current Cycle 3 plans. The phase is now structurally sound with proper dependency ordering, shared helpers, typed APIs, consolidated alert router ownership, correct agent config typing, PolicyStore caching, complete integration test dependencies, and required TUI banner behavior.

### Previously-Raised HIGH Concerns -- Verification

| # | Concern | Status | Evidence in Current Plans |
|---|---------|--------|---------------------------|
| 1 | **55-04 DACL global-mode-only** | **RESOLVED** | 55-04 objective explicitly states global-level only. `should_apply_tripwire_for_global_mode(global_mode: EnforcementMode)` takes no path parameter. Purpose section: "Per-policy tripwire filtering is architecturally infeasible... Global-mode-only filtering satisfies D-01" |
| 2 | **Shared `compute_effective_mode` in 55-01** | **RESOLVED** | 55-01 Task 1 adds `pub fn compute_effective_mode` in `dlp-common/src/abac.rs`. 55-02 Task 1 references it explicitly: "Use the shared `dlp_common::abac::compute_effective_mode` helper". 55-03 Task 3: "Call `dlp_common::abac::compute_effective_mode`" |
| 3 | **Admin API GET/PUT with typed enum** | **RESOLVED** | 55-02 Task 2 adds both `GET /admin/config/global-enforcement-mode` and `PUT /admin/config/global-enforcement-mode`. Explicitly: "Add request/response structs using the typed `EnforcementMode` enum" and "The endpoint accepts and returns the `EnforcementMode` enum (not a raw `String`)" |
| 4 | **Alert router consolidated to 55-02** | **RESOLVED** | 55-02 Task 4 covers `AlertRouter::send_alert()` downgrade. 55-05 objective: "The alert router downgrade was implemented in Plan 55-02; this plan covers the remaining verification surfaces" and explicitly states "This plan does NOT modify `alert_router.rs`" |
| 5 | **EnforcementConfig.global_mode typed** | **RESOLVED** | 55-03 Task 1: `pub struct EnforcementConfig { #[serde(default)] pub global_mode: EnforcementMode }` -- typed enum, not `String`. (Wire payload remains `String` for serde compat, parsed into enum at config time.) |
| 6 | **Global mode cached in PolicyStore** | **RESOLVED** | 55-02 Task 1: `global_mode: std::sync::RwLock<EnforcementMode>` field added to `PolicyStore`. `evaluate()` reads from cache: "Read the cached `global_mode` from `PolicyStore` (via `self.global_mode.read()`), NOT from SQLite on every call" |
| 7 | **55-07 depends on 55-04+55-05** | **RESOLVED** | 55-07 `depends_on` lists all six prerequisite plans: `55-01`, `55-02`, `55-03`, `55-04`, `55-05`, `55-06` |
| 8 | **TUI banner REQUIRED** | **RESOLVED** | 55-06 must_haves: "Global override banner is REQUIRED and renders on every screen when global_enforcement_mode != PerPolicy". Task 3: "This banner MUST appear on every policy-related screen... The banner is a safety feature, not optional polish" -- no "skip if unavailable" escape hatch remains |
| 9 | **55-06 fetches global mode from API on startup** | **RESOLVED** | 55-06 Task 1: `App.global_enforcement_mode` is "populated on TUI startup by calling `GET /admin/config/global-enforcement-mode`" and "Call this method during TUI startup... before rendering the first screen" |

### New Concerns Raised in Cycle 3

- **MEDIUM:** The semantics of `PerPolicy` as a value on `Policy.enforcement_mode` need to be explicitly invalid or normalized. `PerPolicy` makes sense as a global toggle, but likely does not make sense as an individual policy mode. If allowed on a policy, `compute_effective_mode()` can become recursive or ambiguous.
- **MEDIUM:** `AuditAndBlock` needs precise audit semantics. It likely blocks like `Block`, but emits audit metadata like audit mode. The plans should define whether `would_have_denied` is true for both `Audit` and `AuditAndBlock`, or only for audit-only allowed decisions.
- **MEDIUM:** Cache invalidation for `PolicyStore` global mode is not described. PUT `/admin/config/global-enforcement-mode` must update the cached value immediately and consistently across any cloned/shared store handles.
- **MEDIUM:** 55-04 global Audit mode removes Deny ACEs, but rollback behavior should be explicit: when returning to Block / PerPolicy / AuditAndBlock, Deny ACEs must be restored from canonical policy state, not from stale snapshots.
- **LOW:** 55-05 being verification-only is good, but it should still name the exact assertions: SIEM payload includes `policy_mode` and `would_have_denied`, bypass severity unchanged, and alert-router downgrade already covered by 55-02 tests.

**Overall Risk: LOW-MEDIUM** (all previously-raised HIGH concerns are resolved; remaining risks are MEDIUM or lower).

---

## OpenCode Review

**Summary:** The phase is well-structured and follows industry patterns, but the main systemic risk is inconsistent enforcement-mode handling across layers (PolicyStore, agent, DACL, alerting). The most critical failure mode is violating the invariant: Audit mode accidentally denies (agent or DACL path), or Block mode inconsistently enforced due to stale global override. Overall phase risk: **MEDIUM-HIGH** due to cross-cutting concerns and OS-level side effects, but manageable with tighter invariants and stronger integration tests.

### Previously-Raised HIGH Concerns -- Verification

All 9 Cycle 2 HIGH concerns are addressed in the current plans per the Codex and Claude verification above.

### Plan 55-01: Core Types

**Strengths:**
- Clear introduction of `EnforcementMode` enum with explicit values
- Backward compatibility explicitly addressed (default = Block)
- Audit event schema extension aligns with requirements
- Correct placement of logic in repository layer

**Concerns:**
- **MEDIUM:** Migration default ambiguity. If existing rows get NULL vs explicit Block, downstream code may branch inconsistently.
- **MEDIUM:** Enum serialization stability (string vs int). If persisted as int, future extension becomes risky.
- **MEDIUM:** `would_have_denied` optionality unclear -- what sets it and when? Risk of inconsistent audit logs.
- **LOW:** No mention of DB index impact if queries filter by enforcement_mode later.

**Suggestions:**
- Enforce NOT NULL with default = Block at DB level, not just app logic
- Serialize enum as string for forward compatibility
- Define a single authoritative place that computes `would_have_denied` (likely policy engine)
- Add migration test: pre-existing DB -> upgraded -> read/write roundtrip

**Risk: MEDIUM.**

### Plan 55-02: PolicyStore + API + Alert Router

**Strengths:**
- Correct implementation of global override (`PerPolicy` fallback)
- API exposure of enforcement_mode enables operator control
- Alert severity downgrade logic aligns with decisions (D-03, D-04)

**Concerns:**
- **MEDIUM:** Global override sync -- how is `system_kv` propagated to agents? Potential stale mode
- **MEDIUM:** Alert router downgrade rules could conflict with future alert types (tight coupling)
- **LOW:** No mention of API validation (reject invalid enum values)

**Suggestions:**
- Implement a single `resolve_effective_mode(policy_mode, global_mode)` function reused everywhere
- Add cache invalidation or push mechanism for global override changes
- Make alert severity mapping table-driven instead of hardcoded branching
- Validate API input strictly (reject unknown modes)

**Risk: MEDIUM.**

### Plan 55-03: Agent Config + IPC + Audit

**Strengths:**
- Keeps hook DLL unaware of mode (good separation)
- IPC handler as decision boundary is appropriate
- Audit enrichment aligns with requirements

**Concerns:**
- **HIGH:** Risk that enforcement decision still returns DENY in Audit mode due to missed branch
- **HIGH:** Race conditions between config update and enforcement decisions (mode flip mid-operation)
- **MEDIUM:** "would_have_denied" requires evaluating deny path without enforcing -- needs careful duplication avoidance
- **MEDIUM:** No mention of fallback if config missing or corrupt

**Suggestions:**
- Centralize decision logic:
  - Evaluate policy -> compute `decision = DENY/ALLOW`
  - Then apply mode transform:
    - Audit -> force ALLOW + audit flag
    - Block -> enforce decision
    - AuditAndBlock -> enforce + audit
- Add invariant test: Audit mode must NEVER return DENY
- Snapshot config per request to avoid mid-flight inconsistency
- Define safe fallback: default to Block if config invalid

**Risk: HIGH.**

### Plan 55-04: DACL Tripwire

**Strengths:**
- Explicitly ties DACL behavior to enforcement mode
- Avoids Deny ACE in Audit mode (correct)

**Concerns:**
- **HIGH:** Existing Deny ACEs -- are they removed when switching to Audit? If not, Audit mode still blocks
- **HIGH:** Race conditions during mode transition (ACE applied/removed mid-access)
- **MEDIUM:** Partial failure when updating ACLs (leaving inconsistent state)
- **LOW:** No mention of idempotency

**Suggestions:**
- On transition to Audit, actively remove Deny ACEs (not just stop adding)
- Make ACL updates transactional/idempotent (compare-before-write)
- Add verification step: read back ACL after write
- Add integration test: Block -> Audit removes enforcement fully

**Risk: HIGH.**

### Plan 55-05: Alert Router + SIEM

**Strengths:**
- Honors D-03 and D-04 clearly
- Keeps SIEM unchanged (good for stability)
- Separation between alert severity and enforcement is clean

**Concerns:**
- **MEDIUM:** Risk of inconsistent severity mapping across alert types
- **MEDIUM:** AuditAndBlock may double-log (audit + enforcement alert duplication)
- **LOW:** No mention of structured fields for downstream SIEM correlation

**Suggestions:**
- Add explicit deduplication or correlation ID for AuditAndBlock events
- Ensure `policy_mode` is always included in alert payload
- Document severity mapping table centrally

**Risk: LOW-MEDIUM.**

### Plan 55-06: Admin TUI

**Strengths:**
- Placement after action row is intuitive
- Supports all three modes explicitly
- Aligns with operator workflow

**Concerns:**
- **MEDIUM:** Default value confusion (must clearly show Block if unset)
- **LOW:** No guardrails for dangerous combinations
- **LOW:** No mention of reflecting global override in UI

**Suggestions:**
- Display effective mode (policy + global override) in UI
- Add inline help text explaining each mode
- Ensure editing existing policies shows correct default (Block)

**Risk: LOW.**

### Plan 55-07: Integration Tests

**Strengths:**
- Validates API round-trip
- Exercises mode transitions
- Aligns with success criteria

**Concerns:**
- **HIGH:** Missing invariant tests (Audit must never deny)
- **HIGH:** No coverage for global override behavior
- **MEDIUM:** No DACL validation (Audit mode should not enforce)
- **MEDIUM:** No alert severity verification
- **LOW:** No concurrency/config update tests

**Suggestions:**
Add explicit tests:
- Audit mode: Policy would deny -> actual result = ALLOW; Audit event contains `would_have_denied=true`
- Block mode: Deny enforced
- AuditAndBlock: Deny enforced + audit event present
- Global override: Override = Audit forces all policies to Audit
- DACL: Block adds Deny ACE, Audit removes it
- Alerting: Audit downgrades severity, bypass stays high

**Risk: MEDIUM-HIGH.**

---

## Consensus Summary

### Agreed Strengths

- **All 9 previously-raised HIGH concerns are resolved.** Codex and Claude independently verified each concern against the current plan text. The plans have been materially improved since Cycle 2.
- **Solid type foundation (55-01):** All three reviewers agree the `EnforcementMode` enum, DB migration with `CHECK` constraint and `DEFAULT 'Block'`, and serde defaults for backward compat are well-designed.
- **Correct separation of concerns:** Hook DLL remains mode-unaware; SIEM relay receives full events unchanged; bypass alerts remain independent of policy mode.
- **Industry-standard pattern:** The Audit/Block/AuditAndBlock model with global override is recognized as the correct safe-rollout pattern.
- **Shared helper centralized:** `compute_effective_mode` in `dlp-common` eliminates drift risk between server and agent.

### Agreed Concerns (Highest Priority)

1. **MEDIUM -- `PerPolicy` on individual policies:** Codex and Claude both raise that `PerPolicy` as a global override value may be semantically invalid as a per-policy mode. The plans should explicitly state that `PerPolicy` is NOT a valid per-policy mode value (it is only for the global override).

2. **MEDIUM -- `AuditAndBlock` would_have_denied semantics:** The plans do not clearly define whether `would_have_denied` is true for `AuditAndBlock` mode. Since `AuditAndBlock` blocks like `Block`, `would_have_denied` semantics may differ from pure `Audit`.

3. **MEDIUM -- Cache invalidation on global mode update:** Claude flags that PUT `/admin/config/global-enforcement-mode` must update the PolicyStore cache immediately. The plan says "trigger `PolicyStore::refresh_global_mode()`" but does not describe how this is wired if the PolicyStore is shared across threads/tasks.

4. **MEDIUM -- DACL rollback on Block -> Audit -> Block:** OpenCode and Codex both raise that when returning to Block/PerPolicy from Audit, Deny ACEs must be restored. 55-04 Task 2 mentions mode transition detection but should explicitly test the Block -> Audit -> Block cycle.

5. **MEDIUM -- Integration test coverage gaps:** OpenCode identifies missing invariant tests (Audit must never deny), global override coverage, DACL validation, and alert severity verification in 55-07.

### Divergent Views

- **Overall risk level:** Codex rates MEDIUM-HIGH (based on stale Cycle 2 concerns still present in its output); Claude rates LOW-MEDIUM (all HIGHs resolved); OpenCode rates MEDIUM-HIGH. The divergence is because Codex's output appears to be a stale re-run of Cycle 2 analysis rather than a fresh Cycle 3 review. Claude and OpenCode both acknowledge the 9 concerns are resolved but differ on residual risk from new MEDIUM items.
- **Plan 55-03 risk:** Claude does not raise new HIGHs; OpenCode retains HIGH on missed-branch and race-condition risks. The divergence is on whether the plan's test coverage is sufficient to mitigate these risks.
- **Plan 55-04 risk:** OpenCode rates HIGH (existing ACE removal, race conditions); Claude does not rate it separately but the concern is acknowledged. The plan does address existing ACE removal in Task 2.

### Pre-Execution Actions Required

1. **Clarify `PerPolicy` scope:** Add an explicit note in 55-01 that `PerPolicy` is ONLY valid as a global override value, not as a per-policy `enforcement_mode`.
2. **Define `AuditAndBlock` would_have_denied semantics:** Document whether `would_have_denied` is true for `AuditAndBlock` (suggest: false, since it actually blocks).
3. **Verify cache invalidation wiring:** Confirm that `PolicyStore::refresh_global_mode()` is callable from the admin API handler and that the RwLock update is atomic.
4. **Add Block -> Audit -> Block transition test:** Extend 55-04 Task 2 acceptance criteria to include testing the full cycle.
5. **Strengthen 55-07 integration tests:** Add invariant tests for Audit-never-deny, global override forcing Audit, and alert severity downgrade.

---

## Cycle 3 vs Cycle 2 Comparison

| Metric | Cycle 2 | Cycle 3 | Delta |
|--------|---------|---------|-------|
| HIGH concerns | 9 | 0 | -9 |
| MEDIUM concerns | ~8 | ~5 | -3 |
| Plans rated HIGH risk | 3 (55-02, 55-04, 55-06) | 0 | -3 |
| Overall risk | MEDIUM-HIGH | LOW-MEDIUM | Improved |

All 9 previously-raised HIGH concerns from Cycle 2 have been verified as resolved in the current plans.
