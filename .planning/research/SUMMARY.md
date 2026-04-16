# Project Research Summary

**Project:** dlp-rust / dlp-admin-cli -- v0.4.0 Policy Authoring TUI
**Domain:** TUI policy lifecycle management (ratatui, Rust, single-admin DLP system)
**Researched:** 2026-04-16
**Confidence:** HIGH

---

## Executive Summary

v0.4.0 adds fully structured policy authoring to the existing dlp-admin-cli TUI, replacing the current raw-JSON file-path workflows with in-TUI forms, a stepped condition builder, a simulate screen, and import/export. The system is built on a mature ratatui 0.29 state-machine with proven patterns for multi-field forms (SiemConfig, AlertConfig). Two crate additions cover everything: tui-textarea 0.7 for real text editing in forms, and toml 0.8 hoisted to the workspace (already used by dlp-agent). No ratatui upgrade, no form framework, no popup crate is needed.

The recommended build order follows a strict dependency graph: the conditions builder (ConditionStep types + picker render) must be built first as a reusable sub-state, then the create form wraps it, then the edit form reuses the create form, and import/export comes last once the PolicyFileEntry shape is stable. The simulate screen has no internal dependency and can be built in parallel with the create/edit forms.

**The single most consequential design decision is the export format. TOML is blocked for policy files.** The toml crate (v0.5/v0.8) does not support internally tagged enums (#[serde(tag = "attribute")]), and PolicyCondition uses exactly that pattern. Attempting toml::to_string on Vec<PolicyCondition> panics or returns UnsupportedType at runtime. STACK.md recommended TOML for import/export -- that recommendation is overridden: **JSON is the only valid format for policy files in v0.4.0.** serde_json is already in the workspace -- no additional dependency needed. The toml crate is still required in the workspace but solely for dlp-agent agent config; it must not be used on any code path that serializes PolicyCondition.

---

## Key Findings

### Recommended Stack

The dependency delta for dlp-admin-cli is minimal. The existing ratatui 0.29 / crossterm 0.28 stack is the correct version pin: upgrading to ratatui 0.30 would rename Alignment to HorizontalAlignment, change Flex enum variants, and bump MSRV to 1.86.0 -- all churn with no v0.4.0 value. The tui-textarea 0.7 crate (rhysd) is the only textarea crate that targets exactly ratatui 0.29 + crossterm 0.28. All other textarea alternatives require ratatui 0.30.

**Core technologies:**

- `tui-textarea = "0.7"` (rhysd): multi-field text editing with cursor, backspace, paste -- required for the 6-field simulate form and policy name/description fields. Single-line mode via Enter suppression. Add with `features = ["crossterm"]` to match crossterm 0.28.
- `toml = "0.8"` (workspace): already used by dlp-agent; hoist to `[workspace.dependencies]` so both crates share the same resolution. **Used only for agent config. Must not be applied to any policy file serialization path.**
- `serde_json` (already in workspace): the only safe serializer for PolicyCondition and for the policy import/export file format. PolicyCondition uses #[serde(tag = "attribute")] which serde_json handles correctly and toml does not.

No external popup crate, no form library, no multi-select widget crate is needed. The existing ratatui List + ListState, Table + TableState, Clear-overlay popup pattern, and the SiemConfig/AlertConfig row-cursor form pattern cover all required UI components.

### Expected Features

All eight POLICY-01 through POLICY-08 requirements are in scope for v0.4.0. The research confirms this is the right scope -- no individual feature is blocked by missing infrastructure.

**Must have (table stakes):**

- POLICY-01: Scrollable policy list with id, name, priority, action, enabled columns; inline action keys (n, e, d) matching k9s-style TUI patterns; color-coded enabled/disabled badge.
- POLICY-02: Policy create form -- name, description, priority, action, enabled -- using the existing SiemConfig/AlertConfig row-nav + edit-mode pattern.
- POLICY-03: Policy edit form -- same form pre-filled from PolicyResponse; requires deserializing `conditions: serde_json::Value` back to `Vec<PolicyCondition>`.
- POLICY-04: Policy delete with confirmation dialog (already wired; extend to trigger from list and detail screens).
- POLICY-05: Structured 3-step condition builder (attribute -> operator -> value) as embedded sub-state in create/edit forms. Enum-driven pickers; free-text only for MemberOf SID.
- POLICY-06: Simulate / dry-run screen -- fill EvaluateRequest, call `POST /evaluate`, show decision + matched_policy_id + reason inline in the same screen.
- POLICY-07: Export all policies to a JSON file with a timestamped default filename.
- POLICY-08: Import policies from a JSON file with pre-import conflict detection (count_new, count_conflict) and a conflict strategy picker (skip / overwrite).

**Should have (differentiators within v0.4.0):**

- Inline condition preview: show the serialized PolicyCondition JSON as the admin builds each condition -- confirms exact shape before committing.
- Human-readable condition labels in the conditions list ("Classification == T3", not raw JSON).
- Simulate pre-fill from selected policy: default form values derived from the active policy conditions to reduce test-data entry friction.
- `is_dirty()` guard on form Esc: confirm discard when any field is non-empty or conditions list is non-empty.
- Auto-refresh policy list after every successful create/edit/delete operation.
- Timestamped export filename default (`dlp-policies-YYYY-MM-DD.json`).
- Per-import error log: show `(policy_name, result)` pairs when individual policies fail.

**Defer (v0.5.0+):**

- Boolean AND/OR/NOT logic between conditions (engine change required).
- TOML export format (blocked by serde constraint -- see Executive Summary).
- Batch simulate / persistent simulation mode.
- Condition reordering within a policy (order does not affect AND-connected conditions).
- Diff view on import (high layout complexity; skip-or-overwrite sufficient for v0.4.0).
- Column sorting on policy list.

### Architecture Approach

v0.4.0 extends the existing Screen enum state machine with 5 new top-level Screen variants and one critical sub-state type (ConditionStep embedded inside create/edit forms). Every new screen follows the established triple: add a Screen variant to app.rs, a handle_* function to dispatch.rs, and a draw_* function to render.rs. A new policy_file.rs module in dlp-admin-cli holds the import/export types (PolicyFile, PolicyFileEntry). No changes are needed in dlp-common, dlp-server, or dlp-agent for TUI features -- with one exception: PITFALL-02 requires a `POST /admin/policies/import` batch endpoint on the server to avoid N cache invalidations during bulk import.

**Major components:**

1. `app.rs` -- Add PolicyCreateForm, PolicyEditForm, PolicySimulate, PolicyImport, PolicyExport variants; add PolicyDraft, PolicyFormState (boxed), ConditionStep, AttributeKind, PendingCondition structs; add OverwriteExportFile + DiscardPolicyForm to ConfirmPurpose.
2. `screens/dispatch.rs` -- Add 5 new handle_* functions; extend handle_policy_menu (new items), handle_policy_list (n/e/d keys), handle_view (e/d keys).
3. `screens/render.rs` -- Add 5 new draw_* functions; add `centered_rect` helper for the condition picker panel overlay.
4. `policy_file.rs` (new) -- `PolicyFile { version, exported_at, policies }` and `PolicyFileEntry { id, name, description, priority, conditions: Vec<PolicyCondition>, action, enabled }`. JSON only via serde_json. Excludes version and updated_at to prevent audit trail corruption on import.
5. `dlp-server/src/admin_api.rs` (server change) -- Add `POST /admin/policies/import` batch endpoint: single DB transaction, single `invalidate()` call. Blocker for POLICY-08.

**Key pattern constraint:** All condition construction must go through `serde_json::to_value::<PolicyCondition>(...)` -- never hand-crafted JSON strings. The #[serde(tag = "attribute", rename_all = "snake_case")] contract on PolicyCondition plus variant-specific rename_all rules (UPPERCASE for Classification, PascalCase for DeviceTrust/NetworkLocation, lowercase for AccessContext) make hand-crafted JSON error-prone and silent when wrong.

### Critical Pitfalls

**PITFALL-08 (RESOLVED -- format decision):** TOML serialization of Vec<PolicyCondition> panics at runtime because toml v0.8 does not support internally tagged enums. Resolution: JSON only for all policy file import/export. STACK.md TOML recommendation is superseded. This is decided -- not an open question.

1. **PITFALL-01 -- PolicyCondition JSON tag shape mismatch:** If the condition builder emits any JSON shape other than `serde_json::to_value(&condition)?`, the server `load_from_db` silently skips the policy (logs `warn!`, no error returned). Prevention: always construct a typed PolicyCondition variant and serialize via serde -- never hand-craft condition JSON.

2. **PITFALL-02 -- N cache invalidations on bulk import:** Each `POST /admin/policies` call triggers a full PolicyStore reload (SQLite read + RwLock write), blocking `POST /evaluate` for the duration. For a 50-policy file this is 50 sequential cache reloads. Prevention: add a `POST /admin/policies/import` batch endpoint with a single transaction and single `invalidate()`.

3. **PITFALL-04 -- Borrow split with complex form state:** The existing inline (selected, editing, buffer) pattern in Screen variants breaks at 6+ fields. Prevention: introduce `Box<PolicyFormState>` inside the Screen variant, with `clear_edit_state()` on every Esc.

4. **PITFALL-03 -- Duplicate ID collision on import:** `POST /admin/policies` with an existing ID returns a generic 500 Database error. Partial imports leave the DB inconsistent. Prevention: pre-import diff (`GET /admin/policies` to collect existing IDs), show count_new/count_conflict summary, present skip/overwrite choice before any write.

5. **PITFALL-06 -- Action string mismatch silently becomes DENY:** `deserialize_policy_row` uses a match with `_ => Decision::DENY` fallback. Prevention: picker maps display labels to exact lowercase strings ("allow", "deny", "allow_with_log", "deny_with_alert"); unit test every action string round-trip.

---

## Implications for Roadmap

Research confirms a 5-phase build order (A through E) driven by the dependency graph. One additional server-side task (batch import endpoint) must be tracked within Phase E.

### Phase A -- Conditions Builder Types + Picker

**Rationale:** ConditionStep, AttributeKind, and PendingCondition are consumed by every subsequent phase. Building them first with full unit tests validates PITFALL-01 / PITFALL-08 constraints before any form code is written. Zero API dependency -- pure local TUI state and type definitions.

**Delivers:** ConditionStep state machine, AttributeKind enum, PendingCondition, `draw_condition_builder` render function, unit tests for all 5 PolicyCondition variant round-trips.

**Addresses:** POLICY-05 (structured conditions builder core).

**Avoids:** PITFALL-01 (serde tag contract validated by tests before form code is written), PITFALL-05 (incomplete condition blocked by state machine -- only `Complete` state can append to list).

**Research flag:** Standard patterns -- no additional research needed.

---

### Phase B -- Policy Create Form (depends on A)

**Rationale:** Create comes before edit because edit is a parameterized version of create. Create also establishes the PolicyDraft / PolicyFormState struct shape that Phase E import/export must mirror. Getting this right first prevents file format rework.

**Delivers:** PolicyCreateForm screen variant, PolicyDraft, `Box<PolicyFormState>`, handle_policy_create_form, draw_policy_create_form, action_create_policy, updated PolicyMenu routing. Condition builder sub-state wired into form. Auto-refresh to PolicyList after successful create.

**Addresses:** POLICY-02 (create form), POLICY-05 (conditions wired into create flow).

**Avoids:** PITFALL-04 (boxed form state struct), PITFALL-06 (exact action lowercase strings), PITFALL-10 (is_dirty Esc guard), PITFALL-12 (auto-refresh on success), PITFALL-13 (numeric priority classifier), PITFALL-14 (empty description normalized to None before submit).

**Stack:** `tui-textarea = "0.7"` used for name and description fields.

**Research flag:** Standard patterns -- follows SiemConfig/AlertConfig form precedent.

---

### Phase C -- Policy Edit + Delete (depends on B, reuses A)

**Rationale:** Edit is a thin wrapper over the create form with pre-filled state. Delete is already wired via `ConfirmPurpose::DeletePolicy` -- this phase only adds entry points from PolicyList (e/d keys) and PolicyDetail (e/d keys). Bundling edit and delete together minimizes the number of dispatch/render extension passes needed.

**Delivers:** PolicyEditForm screen variant, action_update_policy (PUT), extended handle_policy_list with n/e/d keypresses, extended handle_view with e/d keypresses. Updated PolicyDetail to show [e]dit and [d]elete hints in the key legend.

**Addresses:** POLICY-01 (list with inline action keys), POLICY-03 (edit form), POLICY-04 (delete from list and detail screens).

**Avoids:** PITFALL-12 (auto-refresh after edit/delete), PITFALL-04 (shared form state reuse between create and edit).

**Research flag:** Standard patterns.

---

### Phase D -- Policy Simulate (parallel-capable with B/C; depends on A types only)

**Rationale:** Simulate depends only on dlp-common EvaluateRequest/EvaluateResponse and the existing `POST /evaluate` endpoint -- both shipped in v0.3.0. It shares no state with the create/edit forms. Can be built in parallel with Phase B/C after Phase A is complete. Scheduling it as Phase D (sequential) is conservative; teams comfortable with parallel work can move it alongside Phase B.

**Delivers:** PolicySimulate screen variant with SimulateDraft (all EvaluateRequest fields), handle_policy_simulate, draw_policy_simulate, action_simulate_policy. Pre-populated sensible defaults (`timestamp = Utc::now()`, session_id = 1, access_context = Local, device_trust = Managed, network_location = Corporate, action = COPY). Inline result panel (no screen transition on submit). Decision color coding (ALLOW=green, DENY=red, ALLOW_WITH_LOG=yellow, DENY_WITH_ALERT=red bold).

**Addresses:** POLICY-06 (simulate/dry-run).

**Avoids:** PITFALL-09 (required field guards before submit; sensible defaults pre-filled to reduce empty-field deserialization errors from server).

**Stack:** `tui-textarea = "0.7"` for user_sid, user_name, groups, resource_path fields.

**Research flag:** Standard patterns -- follows SiemConfig multi-field form precedent exactly.

---

### Phase E -- Import / Export + Server Batch Endpoint (depends on B)

**Rationale:** PolicyFileEntry shape must mirror the stable PolicyDraft fields from Phase B. The server-side batch endpoint (PITFALL-02) must be implemented at the start of this phase before the TUI import action is written.

**Delivers:**

Server: `POST /admin/policies/import` batch endpoint -- single transaction, single `invalidate()`, accepts `Vec<PolicyPayload>` with conflict_strategy enum (skip/overwrite).

CLI: `policy_file.rs` with `PolicyFile { version: u32, exported_at: String, policies: Vec<PolicyFileEntry> }`. JSON-only via serde_json. PolicyFileEntry excludes version and updated_at (prevents audit trail corruption on cross-environment import).

CLI: PolicyExport and PolicyImport screen variants, action_export_policies, action_import_policies. Pre-import conflict diff. Conflict strategy picker. Per-import error log. Timestamped default export filename. `Path::display()` in status messages.

**Addresses:** POLICY-07 (export), POLICY-08 (import).

**Avoids:** PITFALL-02 (batch endpoint, single invalidate), PITFALL-03 (pre-import conflict diff before any writes), PITFALL-07 (dedicated export schema excludes server-managed fields), PITFALL-08 (JSON only -- toml not used here), PITFALL-11 (single batch call eliminates terminal freeze), PITFALL-15 (`Path::display()` for Windows paths in status bar).

**Stack:** `serde_json` (existing). toml crate NOT used on any import/export code path.

**Research flag:** Validate conflict_strategy API design against PolicyRepository::insert before coding the batch endpoint. Confirm endpoint is under admin Bearer token auth guard.

---

### Phase Ordering Rationale

- A before B/C/D: ConditionStep and PolicyCondition serialization correctness proven before any form code. Phase A unit tests become the regression guard for all subsequent phases.
- B before C: Edit form reuses PolicyDraft and PolicyFormState from create.
- B before E: PolicyFileEntry must mirror the stable field set from PolicyDraft.
- D parallel with B/C: Simulate has no shared state; can be built concurrently to compress the timeline.
- E last: Only phase with a cross-crate (server-side) dependency.

### Research Flags

Phases needing additional attention during planning:

- **Phase E (Import/Export):** Validate PolicyRepository supports upsert before committing to the overwrite conflict strategy. Confirm batch endpoint is under admin auth guard.

Phases with standard patterns (no additional research needed):

- **Phase A:** Pure Rust enum + serde -- well-understood. Direct source verified.
- **Phase B:** Follows SiemConfig/AlertConfig form pattern exactly.
- **Phase C:** Subset of Phase B mechanics. No novel mechanics.
- **Phase D:** Follows SiemConfig multi-field form + existing /evaluate API.

---

## Open Design Decisions

These must be resolved before or at the start of implementation. They are not research gaps -- the options are known -- but a choice must be locked in per-phase.

| Decision | Options | Recommendation | Phase |
|----------|---------|----------------|-------|
| Export/import file format | JSON vs TOML (blocked) | JSON only -- TOML blocked by PITFALL-08 | Phase E |
| Import conflict granularity | Per-file vs per-policy | Per-file for v0.4.0; per-policy deferred | Phase E |
| Batch endpoint conflict_strategy | skip / overwrite / abort | skip and overwrite in v0.4.0 | Phase E |
| ConditionBuilder placement | Embedded sub-state vs separate Screen modal | Embedded sub-state | Phase A/B |
| PolicyFormState boxing | Box<PolicyFormState> vs inline fields | Box -- inline fails at 6+ fields | Phase B |
| Simulate result display | Inline vs separate ResultView | Inline -- avoids draft serialization across screens | Phase D |
| POST /evaluate auth status | Currently unauthenticated | Confirm with server source before Phase D begins | Phase D |

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | tui-textarea 0.7 version pin verified via rhysd Cargo.toml. TOML serde constraint verified. serde_json already in workspace. |
| Features | HIGH | All feature decisions from direct codebase inspection (app.rs, dispatch.rs, abac.rs). External DLP references inform UX polish only, not architecture. |
| Architecture | HIGH | All findings from direct source reading of dlp-admin-cli, dlp-common, dlp-server. Existing patterns clear and well-established. |
| Pitfalls | HIGH | PITFALL-01/02/03/06/07/08 from direct source inspection of policy_store.rs, admin_api.rs, abac.rs. PITFALL-08 is a documented toml-rs limitation. |

**Overall confidence:** HIGH

### Gaps to Address

- **Batch import endpoint API surface:** conflict_strategy parameter design must be defined before Phase E coding begins. Schedule at Phase E kickoff (30-minute design decision, not a research task).
- **POST /evaluate authentication:** Research notes it is currently unauthenticated. Confirm this is intentional for the simulate feature before Phase D begins.
- **tui-textarea masked input:** Does not affect v0.4.0 -- policy forms have no password fields.

---

## Sources

### Primary (HIGH confidence -- direct source inspection)

- `dlp-admin-cli/src/app.rs` -- Screen enum, App struct, purpose enums, existing form patterns
- `dlp-admin-cli/src/screens/dispatch.rs` -- full dispatch pattern, all action functions
- `dlp-admin-cli/src/screens/render.rs` -- render pattern, SiemConfig/AlertConfig form examples
- `dlp-admin-cli/src/client.rs` -- EngineClient generic HTTP methods
- `dlp-common/src/abac.rs` -- PolicyCondition, EvaluateRequest, EvaluateResponse, Policy
- `dlp-common/src/classification.rs` -- Classification enum values and serde attributes
- `dlp-server/src/admin_api.rs` -- PolicyPayload, PolicyResponse, routes, /evaluate handler
- `dlp-server/src/policy_store.rs` -- load_from_db, invalidate, deserialize_policy_row
- `.planning/PROJECT.md` -- v0.4.0 requirements POLICY-01 through POLICY-08
- rhysd/tui-textarea Cargo.toml (https://github.com/rhysd/tui-textarea/blob/main/Cargo.toml)

### Secondary (MEDIUM confidence)

- ratatui v0.30.0 breaking changes: https://ratatui.rs/highlights/v030/
- ratatui popup built-in pattern: https://ratatui.rs/examples/apps/popup/
- toml-rs known limitations: https://docs.rs/toml/latest/toml/ -- internally tagged enum support gap confirmed
- Microsoft Purview DLP Policy Design -- feature scope reference only

### Tertiary (LOW confidence -- reference only, not load-bearing)

- k9s Kubernetes TUI (https://k9scli.io/) -- inline action key UX pattern reference
- Check Point Harmony Endpoint import/export -- import/export feature scope reference

---

*Research completed: 2026-04-16*
*Ready for roadmap: yes*
