---
phase: 55
reviewers: [codex, claude, opencode]
reviewed_at: 2026-05-28T20:30:00Z
plans_reviewed:
  - 55-01-PLAN.md
  - 55-02-PLAN.md
  - 55-03-PLAN.md
  - 55-04-PLAN.md
  - 55-05-PLAN.md
  - 55-06-PLAN.md
  - 55-07-PLAN.md
---

# Cross-AI Plan Review -- Phase 55 (Cycle 2 -- Post-Revision)

> This review was conducted against the **revised** Phase 55 plans (commit `aa0f411` -- "Replan Phase 55 incorporating cross-AI review feedback from REVIEWS.md").
> For the prior cycle's review, see git history of this file.

---

## Codex Review

**Summary:** The revised plans are directionally strong and cover the main Phase 55 surfaces. The largest remaining risks are coordination gaps: dependency metadata is still wrong in places (55-02 `depends_on: []`), alert routing is duplicated across 55-02 and 55-05, global override management lacks a clear admin API/TUI path, and DACL per-policy tripwire behavior remains underspecified. Overall plan set rated **MEDIUM-HIGH risk** until those are tightened.

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

**Summary:** The revised plans are well-structured and cover all critical surfaces, but contain several cross-plan coordination gaps and one architectural mismatch in Plan 55-04. The core type design (55-01) is solid, the server evaluator (55-02) has a performance concern, the agent plan (55-03) duplicates logic that should be shared, the DACL plan (55-04) is architecturally infeasible as specified, the alert plan (55-05) overlaps with 55-02, the TUI plan (55-06) has ordering ambiguity, and the integration test plan (55-07) has missing dependencies. Overall risk is **MEDIUM-HIGH**, dropping to **MEDIUM** if the four pre-execution checklist items are resolved.

### Plan 55-01: Core Types

**Strengths:**
- Block as `#[default]` preserves v0.9.0 behavior exactly.
- `CHECK` constraint on the DB column prevents invalid values at the storage layer.
- `serde(skip_serializing_if = "Option::is_none")` on `EvaluateResponse.enforcement_mode` keeps wire format clean for default-deny cases.
- Comprehensive unit test coverage for serde round-trip and backward compat.

**Concerns:**
- **LOW:** `EvaluateResponse.enforcement_mode` is `Option<EnforcementMode>` while `Policy.enforcement_mode` is non-optional `EnforcementMode`. The inconsistency is justified (default-deny has no mode) but may confuse consumers. Consider a doc comment explaining why.
- **LOW:** The migration inserts `global_enforcement_mode` into `system_kv` but no plan documents how to update it (admin API endpoint, CLI command, or direct SQL). This is acceptable for v0.10.0 but should be noted.

**Suggestions:**
- Add `impl EnforcementMode { pub fn is_blocking(self) -> bool { matches!(self, Self::Block | Self::AuditAndBlock) } }` as a convenience helper.
- Consider adding `impl Display for EnforcementMode` so `to_string()` works uniformly.

**Risk: LOW.**

### Plan 55-02: PolicyStore, Admin API, Alert Router

**Strengths:**
- `deserialize_policy_row` defensive fallback to `Block` for unrecognized DB values is the right choice for fail-safe behavior.
- Alert downgrade only affects `EventType::Alert` (not `Block`), preserving blocking notifications.
- `AgentConfigPayload` carries `global_enforcement_mode` for agent sync.

**Concerns:**
- **MEDIUM:** `evaluate()` reads `system_kv` on every call. For a file-intensive workload, this is an unnecessary SQLite round-trip per file operation. Cache `global_enforcement_mode` in `PolicyStore` and refresh on policy sync interval (5 min) or subscribe to changes.
- **MEDIUM:** `ProtectedPathConfig` is **not** extended with `enforcement_mode`, but Plan 55-04 Task 1 explicitly assumes it was: *"Add `#[serde(default)] pub enforcement_mode: String` to `ProtectedPathConfig` in `dlp-server/src/admin_api.rs` (this was done in Plan 55-02 Task 2)"* -- it was **not** done. This is a cross-plan dependency gap.
- **LOW:** `deserialize_policy_row` does `to_lowercase()` matching on DB values, but the `CHECK` constraint stores PascalCase (`'Block'`). This works functionally but is slightly inconsistent.
- **LOW:** Plan 55-02 Task 3 and Plan 55-05 Task 1 both modify `AlertRouter::send_alert()` with nearly identical logic. The overlap is wasteful.

**Suggestions:**
- Cache global mode in `PolicyStore` with a `RwLock<String>` or similar, initialized at startup and updated via the existing policy cache refresh mechanism.
- Add `enforcement_mode: String` to `ProtectedPathConfig` in this plan's Task 2 if per-path tripwire filtering is desired. However, see the architectural concern below in Plan 55-04.
- Merge Plan 55-05 into 55-02; the additional test cases in 55-05 can be added as extra acceptance criteria in 55-02 Task 3.

**Risk: MEDIUM.**

### Plan 55-03: Agent Config, IPC, Audit

**Strengths:**
- `AgentConfig` uses `#[serde(default)]` so old TOML configs without `[enforcement]` load correctly.
- `tracing::info!` log when global mode changes gives operators visibility.
- Audit event enrichment with `policy_mode` and `would_have_denied` is correctly placed in the IPC handler.

**Concerns:**
- **MEDIUM:** Agent re-computes effective mode (`cfg.enforcement.global_mode` + `response.enforcement_mode`) that the server already computed. If server and agent global modes are out of sync (sync delay), they diverge. A shared helper in `dlp-common` would guarantee consistency.
- **MEDIUM:** `global_mode` is stored as `String` in `EnforcementConfig`, not as `EnforcementMode`. This forces string matching (`== "Audit"`) everywhere instead of type-safe enum matching. The server side uses the enum; the agent should too.
- **LOW:** The plan says `run_event_loop` reads global_mode via `with_config` but doesn't specify what happens if the config isn't loaded yet (race at startup). Default should be `Block` (fail-safe), not `PerPolicy`.

**Suggestions:**
- Define a shared `compute_effective_mode(global: EnforcementMode, policy: EnforcementMode) -> EnforcementMode` in `dlp-common` and use it in both `PolicyStore::evaluate()` (server) and `run_event_loop` (agent).
- Change `EnforcementConfig.global_mode` to `EnforcementMode` with `#[serde(default)]` -- serde handles enum deserialization from string automatically with `rename_all = "PascalCase"`.
- Document the startup race default explicitly: if config unavailable, default to `Block`.

**Risk: MEDIUM.**

### Plan 55-04: DACL Tripwire

**Strengths:**
- Correctly identifies that Audit mode must not write Deny ACEs.
- `should_apply_tripwire_for_mode` helper with unit tests is a clean abstraction.
- Repair watcher snapshot logic correctly tied to mode.

**Concerns:**
- **HIGH:** **Per-policy tripwire filtering is architecturally infeasible.** `protected_paths` has no `enforcement_mode` column, no FK to `policies`, and `ProtectedPathConfig` has no such field. Policies match paths via dynamic `conditions`, not static FKs. You cannot determine a path's enforcement mode without evaluating all policies against that path.
- **HIGH:** False dependency: *"Add `enforcement_mode` to `ProtectedPathConfig` (this was done in Plan 55-02 Task 2)"* -- it was **not** done. No plan adds this field.
- **MEDIUM:** Even if `ProtectedPathConfig` gets the field, `ProtectedPathsRepository::sync_from_labels()` auto-populates paths from labels. Labels have no enforcement_mode, so auto-populated paths would need a default. This cascades into schema changes on `protected_paths` and `labels` tables -- out of scope for Phase 55.

**Suggestions:**
**Simplify the plan to global-mode-only tripwire filtering:**
- Global `Audit`: skip ALL tripwire ACEs.
- Global `Block` or `PerPolicy`: apply tripwire to ALL protected paths (existing behavior).
- Remove per-path mode filtering and the dependency on `ProtectedPathConfig.enforcement_mode`.
- Update `should_apply_tripwire_for_mode` to take only `global_mode` (no path_mode).
- Add a `TODO` or deferred issue for per-path tripwire filtering when a path-to-policy mapping is designed.

This still satisfies D-01 for the common case (global monitor mode) without scope creep.

**Risk: HIGH.**

### Plan 55-05: Alert Router + SIEM

**Strengths:**
- Comprehensive test matrix: Audit, Block, AuditAndBlock, Access, None policy_mode -- all covered.
- SIEM relay verification ensures Audit-mode events reach SIEM with full severity intact.
- Bypass correlator independence check (D-04) is correctly identified and tested.

**Concerns:**
- **LOW:** Near-complete overlap with 55-02 Task 3. The alert router downgrade logic is specified twice. An implementer could apply conflicting changes if both plans are executed by different agents.
- **LOW:** Plan modifies `dlp-agent/src/bypass_correlator.rs` but the file is not in `files_modified`.

**Suggestions:**
- Consolidate into Plan 55-02 as extended test cases and verification steps.
- If kept separate, add a cross-reference note in both plans.

**Risk: LOW.**

### Plan 55-06: Admin TUI

**Strengths:**
- `cycle_enforcement_mode` follows the established `(idx + 1) % len` pattern.
- Form load-for-edit correctly maps string values to index defaults (Block = 1).
- Policy list column addition gives operators visibility into mode.

**Concerns:**
- **MEDIUM:** **Row ordering conflict.** Plan 55-06 says `POLICY_ENFORCEMENT_MODE_ROW = 4` (between Action=3 and Enabled=5). `55-PATTERNS.md` says `POLICY_ENFORCEMENT_MODE_ROW = 6` (after Mode=5). These are contradictory.
- **MEDIUM:** Global override banner requires `global_enforcement_mode` in `App` state, but no plan wires this. The plan says *"If the field is not readily available in App state, skip the banner for now"* -- this is a self-admitted partial implementation. The banner is important for operator safety.
- **LOW:** `PolicyFormState.enforcement_mode` defaults to `1` (Block) in app.rs, but the `From<PolicyResponse>` mapping and JSON payload construction both use the same default. This is consistent but duplicated.

**Suggestions:**
- Resolve row ordering by reading the actual `dispatch.rs` constants at implementation time.
- Add a lightweight task to fetch `global_enforcement_mode` from the server on TUI startup.
- Consider whether enforcement mode should come BEFORE Action (row 3) rather than after it.

**Risk: MEDIUM.**

### Plan 55-07: Integration Tests

**Strengths:**
- Round-trip test covers all three modes plus backward compat.
- Tests agent config sync for global mode propagation.
- Uses existing in-memory SQLite + TestClient harness.

**Concerns:**
- **MEDIUM:** **Missing dependencies.** `depends_on` lists 55-01, 55-02, 55-03, 55-06 but omits 55-04 and 55-05. The tripwire mode filtering and alert router downgrade are both part of the end-to-end feature and should be verified in integration.
- **MEDIUM:** *"Evaluate a request against the policy via the evaluate endpoint (if exposed)"* -- uncertainty about whether an evaluate endpoint exists.
- **LOW:** `sonar-scanner` in Task 2 verification is a CI tool, not a test framework. It should not gate integration test completion.
- **LOW:** No integration test for the actual hook DLL behavior (Audit mode returns ALLOW).

**Suggestions:**
- Add 55-04 and 55-05 to `depends_on`.
- Verify whether an evaluate endpoint exists before executing.
- Remove `sonar-scanner` from integration test verification; keep it as a phase-exit gate.
- Add an integration test for global override.

**Risk: MEDIUM.**

### Cross-Cutting Issues

1. **Missing Shared Helper for Effective Mode Computation:** Both server (55-02) and agent (55-03) compute `if global != PerPolicy { global } else { policy }` independently. Add a pure function in `dlp-common` and use it everywhere.

2. **`policy_sync.rs` Is Not a Real Source File:** `policy_sync.rs` is referenced in CONTEXT.md and PATTERNS.md as the agent config sync module, but it does not exist in the source tree. The actual agent config endpoint is in `dlp-server/src/admin_api.rs`. The documentation should be updated to remove the stale `policy_sync.rs` reference.

3. **VALIDATION.md Task IDs Don't Match Plan IDs:** The validation table references task IDs like `55-05-01` (hook DLL audit mode) but Plan 55-05 is alert router/SIEM, not hook DLL. The hook DLL behavior is in Plan 55-03. The validation matrix needs alignment.

**Overall Risk: MEDIUM-HIGH.**

**Pre-Execution Checklist:**
1. [ ] **Decide tripwire scope:** Global-mode-only or per-path? If global-only, rewrite 55-04 accordingly.
2. [ ] **Add shared `effective_mode()` helper** to `dlp-common` and update 55-02 and 55-03 to use it.
3. [ ] **Change `EnforcementConfig.global_mode`** from `String` to `EnforcementMode` in 55-03.
4. [ ] **Resolve TUI row ordering:** Read actual `dispatch.rs` and align 55-06 with PATTERNS.md.
5. [ ] **Merge or cross-reference** 55-05 with 55-02 to avoid duplicate alert router changes.
6. [ ] **Add 55-04 and 55-05** to 55-07 `depends_on`.
7. [ ] **Verify evaluate endpoint exists** or adjust 55-07 integration test scope.

---

## OpenCode Review

**Summary:** The phase is well-structured and follows industry patterns, but the main systemic risk is inconsistent enforcement-mode handling across layers (PolicyStore, agent, DACL, alerting). The most critical failure mode is violating the invariant: Audit mode accidentally denies (agent or DACL path), or Block mode inconsistently enforced due to stale global override. Overall phase risk: **MEDIUM-HIGH** due to cross-cutting concerns and OS-level side effects, but manageable with tighter invariants and stronger integration tests.

### Plan 55-01: Core Types

**Strengths:**
- Clear introduction of `EnforcementMode` enum with explicit values
- Backward compatibility explicitly addressed (default = Block)
- Audit event schema extension aligns with requirements
- Correct placement of logic in repository layer

**Concerns:**
- **HIGH:** Migration default ambiguity. If existing rows get NULL vs explicit Block, downstream code may branch inconsistently.
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
- **HIGH:** Risk of duplicated "effective mode" logic across layers -> divergence bugs
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

- **Solid type foundation (55-01):** All three reviewers agree the `EnforcementMode` enum, DB migration with `CHECK` constraint and `DEFAULT 'Block'`, and serde defaults for backward compat are well-designed. Block as default preserves v0.9.0 behavior.
- **Correct separation of concerns:** Hook DLL remains mode-unaware; SIEM relay receives full events unchanged; bypass alerts remain independent of policy mode.
- **Industry-standard pattern:** The Audit/Block/AuditAndBlock model with global override is recognized as the correct safe-rollout pattern.
- **Audit event enrichment:** Adding `policy_mode` and `would_have_denied` to `AuditEvent` is the right telemetry shape.

### Agreed Concerns (Highest Priority)

1. **HIGH -- Plan 55-04 architectural infeasibility:** All reviewers identify that per-policy DACL tripwire filtering is not supported by the data model. `protected_paths` has no FK to policies, and policies match via dynamic conditions. Codex and Claude both recommend simplifying to global-mode-only filtering (global Audit = skip all tripwire ACEs; global Block/PerPolicy = apply all). OpenCode raises the related concern that existing Deny ACEs must be actively removed on transition to Audit.

2. **HIGH -- Missing shared effective mode helper:** All three reviewers note that effective mode computation is duplicated between server (55-02) and agent (55-03). Codex and Claude explicitly recommend adding a shared `effective_mode()` or `compute_effective_mode()` function in `dlp-common` and using it everywhere.

3. **HIGH -- Missing global override admin API:** Codex and Claude both flag that no plan creates an admin API or TUI path to get/set `global_enforcement_mode`. The integration test plan (55-07) depends on this capability but it is not specified anywhere.

4. **HIGH -- Duplicate alert router work:** Codex and Claude both identify that 55-02 Task 3 and 55-05 Task 1 specify nearly identical alert router downgrade logic. This risks conflicting edits. Consensus: consolidate into one plan or make 55-05 verification-only.

5. **MEDIUM -- Agent uses String instead of EnforcementMode enum:** Claude specifically flags that `EnforcementConfig.global_mode` is a `String` in 55-03, while the server uses the typed enum. This creates a type-safety gap and forces string matching. All reviewers agree the agent should use the enum.

6. **MEDIUM -- Plan 55-02 reads system_kv on every evaluation:** Claude flags a performance concern -- reading `global_enforcement_mode` from SQLite on every `evaluate()` call is wasteful. Should be cached.

7. **MEDIUM -- Plan 55-07 missing dependencies:** Codex and Claude both note that 55-07's `depends_on` omits 55-04 and 55-05, meaning DACL and alert behavior can regress while integration tests still pass.

8. **MEDIUM -- Plan 55-06 global override banner is a TODO:** Codex flags this as a HIGH concern -- the banner is a safety feature, not polish. The plan admits it may be skipped.

### Divergent Views

- **Overall risk level:** Codex and Claude rate MEDIUM-HIGH; OpenCode also rates MEDIUM-HIGH. All three converge on the same overall assessment.
- **Plan 55-03 risk:** Claude rates MEDIUM; OpenCode rates HIGH (due to enforcement boundary risk). Codex rates MEDIUM. The divergence is on whether the duplicated logic is a critical or moderate concern.
- **Plan 55-01 risk:** Claude rates LOW; OpenCode rates MEDIUM; Codex rates MEDIUM. Divergence is on whether the missing shared helper and type looseness are significant.

### Pre-Execution Actions Required

1. **Rewrite Plan 55-04** to use global-mode-only tripwire filtering. Remove per-path mode filtering. Add explicit removal of existing Deny ACEs when global mode switches to Audit.
2. **Add shared `effective_mode()` helper** in `dlp-common` and update 55-02 and 55-03 to use it.
3. **Change `EnforcementConfig.global_mode`** from `String` to `EnforcementMode` in 55-03.
4. **Add admin API endpoint** for getting/setting `global_enforcement_mode` (or document the existing mechanism if one exists).
5. **Consolidate alert router work** -- either merge 55-05 into 55-02 or make 55-05 verification-only with cross-references.
6. **Fix 55-07 dependencies** -- add 55-04 and 55-05 to `depends_on`.
7. **Resolve TUI row ordering** -- read actual `dispatch.rs` and align 55-06 with PATTERNS.md.
8. **Make global override banner required** in 55-06, not optional/TODO.
9. **Cache global mode** in PolicyStore (55-02) instead of reading system_kv per evaluation.
