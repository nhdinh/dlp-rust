<planning_context>
**Phase:** 54
**Mode:** reviews

<files_to_read>
- .planning/STATE.md (Project State)
- .planning/ROADMAP.md (Roadmap)
- .planning/REQUIREMENTS.md (Requirements)
- .planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-CONTEXT.md (USER DECISIONS from /gsd:discuss-phase)
- .planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-RESEARCH.md (Technical Research)
- .planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-REVIEWS.md (Cross-AI Review Feedback)
- .planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-UI-SPEC.md (UI Design Contract)
</files_to_read>

## Reviews Mode Instructions

You are replanning Phase 54 from scratch, incorporating cross-AI review feedback. Read the REVIEWS.md file carefully. The reviews from Codex, OpenCode, and Claude identified specific concerns that MUST be addressed in the new plans.

### Must Address (HIGH severity consensus concerns)

1. **Client method count mismatch**: Phase claims 8 methods but plans list 7 (5 protected + 2 bypass). `update_protected_path` may be unused scope. Resolution: REMOVE `update_protected_path` from this phase. It has no UI workflow. Document that update is deferred. The 7 methods are: `list_protected_paths`, `create_protected_path`, `delete_protected_path`, `sync_protected_paths`, `list_bypass_alerts`, `ack_bypass_alert`, plus the navigation method `action_load_bypass_alert_list` (which is an action helper, not a client method). Actually — the correct count is 6 client methods + action helpers. The phase description should say "7 new client methods" not 8. Fix the count in Plan 02 must_haves.

2. **Optimistic ack state consistency**: Use stable ID (not index) for rollback lookup. Add a `pending_ack_ids: HashSet<i64>` field to `BypassAlertList` screen state to prevent double-ack. On ack failure, find the alert by ID in the alerts vec, not by index position.

3. **Selection invalidation after mutations**: After delete/sync/add, clamp `selected` to `min(selected, paths.len().saturating_sub(1))`. After page change, reset selected to 0.

### Should Address (MEDIUM severity concerns from 2+ reviewers)

4. **Weak client tests**: Add mocked HTTP tests using a mock server or by verifying URL construction. At minimum, add a test that `list_bypass_alerts` builds the correct query string.

5. **Pagination + filter interaction**: Define explicit reset behavior: On filter change or hide-ack toggle, reset to page 0 and selected 0. Document this in Plan 04.

6. **Error handling under-specified**: Add explicit error status setting in every action helper. Document that failed operations set `StatusKind::Error` without corrupting local state.

7. **Menu index fragility**: Add a menu-index assertion test in Plan 06 that verifies SystemMenu item count and label order.

8. **`update_protected_path` dead code**: Remove this method entirely from Plan 02. No downstream plan calls it.

9. **`status_message` dead field**: Remove `status_message` from `BypassAlertList` screen variant. No plan reads it.

10. **Vague Esc routing instruction**: Make Plan 03's `handle_text_input` Esc routing for `AddProtectedPath` explicit with exact insertion point.

### Review Feedback Addressed Table

Each plan MUST include a "Review Feedback Addressed" section in its output showing how review concerns were incorporated.

</planning_context>

<downstream_consumer>
Output consumed by /gsd:execute-phase. Plans need:
- Frontmatter (wave, depends_on, files_modified, autonomous)
- Tasks in XML format with read_first and acceptance_criteria fields (MANDATORY on every task)
- Verification criteria
- must_haves for goal-backward verification
</downstream_consumer>

<deep_work_rules>
## Anti-Shallow Execution Rules (MANDATORY)

Every task MUST include these fields — they are NOT optional:

1. **`<read_first>`** — Files the executor MUST read before touching anything. Always include:
   - The file being modified (so executor sees current state, not assumptions)
   - Any "source of truth" file referenced in CONTEXT.md (reference implementations, existing patterns, config files, schemas)
   - Any file whose patterns, signatures, types, or conventions must be replicated or respected

2. **`<acceptance_criteria>`** — Verifiable conditions that prove the task was done correctly. Rules:
   - Every criterion must be checkable as a source assertion, behavior assertion, test command, or CLI output
   - NEVER use subjective language ("looks correct", "properly configured", "consistent with")
   - Include exact strings, patterns, values, command outputs, or observable behavior where that is the right proof

3. **`<action>`** — Must include CONCRETE values, not references. Rules:
   - NEVER say "align X with Y", "match X to Y", "update to be consistent" without specifying the exact target state
   - Include concrete identifiers and reference values: config keys, function signatures, SQL table names, class names, import paths, env vars, endpoint paths, etc.
   - If CONTEXT.md has a comparison table or expected values, copy only the target identifiers/values needed to remove ambiguity
   - Do not include full file contents, fenced code blocks, or complete implementations in `<action>`
   - The executor should understand the intended target state from `<action>` and use `<read_first>` files for current implementation details, patterns, and source-of-truth context
</deep_work_rules>

<quality_gate>
- [ ] PLAN.md files created in phase directory
- [ ] Each plan has valid frontmatter
- [ ] Tasks are specific and actionable
- [ ] Every task has `<read_first>` with at least the file being modified
- [ ] Every task has `<acceptance_criteria>` with behavior, test-command, CLI, or source assertions
- [ ] Every `<action>` contains concrete identifiers without fenced code blocks or full implementations
- [ ] Dependencies correctly identified
- [ ] Waves assigned for parallel execution
- [ ] must_haves derived from phase goal
- [ ] Review feedback addressed in each plan
</quality_gate>

## Output Instructions

Write the following PLAN.md files to disk:
- `.planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-01-PLAN.md` (Foundation — Types and Constants)
- `.planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-02-PLAN.md` (Client Methods)
- `.planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-03-PLAN.md` (ProtectedPathList Screen)
- `.planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-04-PLAN.md` (BypassAlertList Screen)
- `.planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-05-PLAN.md` (BypassAlertDetail Screen)
- `.planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-06-PLAN.md` (Integration and Quality Gates)

Return `## PLANNING COMPLETE` when all plans are written.
