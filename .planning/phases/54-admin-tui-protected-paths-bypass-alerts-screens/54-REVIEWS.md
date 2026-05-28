---
phase: 54
reviewers: [codex, opencode, claude]
reviewed_at: 2026-05-28T10:15:00Z
plans_reviewed:
  - 54-01-PLAN.md
  - 54-02-PLAN.md
  - 54-03-PLAN.md
  - 54-04-PLAN.md
  - 54-05-PLAN.md
  - 54-06-PLAN.md
---

# Cross-AI Plan Review — Phase 54

## Codex Review

## Summary

The six-plan breakdown is coherent and mostly well-scoped for Phase 54. The wave ordering makes sense: shared TUI types/constants first, client API surface next, then screens, then integration gates. The plans appear capable of delivering the roadmap goals, assuming the existing admin CLI architecture really matches the stated `LabelList` / `ApprovalList` patterns. The main risks are integration drift across state, dispatch, menu indices, and pagination/filter behavior, plus some under-specified error handling and test coverage around failed API operations.

## Strengths

- Clear dependency ordering: types and constants before handlers/renderers, client methods before action helpers.
- Scope stays aligned with the roadmap and explicitly avoids deferred features like bulk operations and auto-refresh.
- Good reuse of existing patterns: `LabelList` for protected paths and `ApprovalList` for bypass alerts.
- User decisions are reflected directly in keybindings, visual badges, filters, confirmation flow, and manual refresh behavior.
- Protected path delete confirmation and manual-only delete rule are correctly called out.
- Bypass alert ack plan includes optimistic UI with revert on failure, which is the right UX behavior if implemented carefully.
- Wave 3 includes meaningful quality gates: build, tests, clippy, fmt, Sonar.

## Concerns

- **HIGH:** Plan 02 says "Eight new client methods," but lists 5 protected path methods plus 2 bypass alert methods, totaling 7. The phase description says eight. This mismatch should be resolved before implementation.
- **HIGH:** Protected path `update` is listed, but the phase does not describe any edit/update UI. If no screen uses update, this may be unnecessary scope or a stale requirement.
- **MEDIUM:** Menu index changes are fragile. Plans mention indices 10 and 11, but Plan 04 "replaces stub from Plan 03" suggests possible coordination risk if both plans touch the same menu wiring.
- **MEDIUM:** Pagination semantics differ between screens: protected paths paginate client-side, bypass alerts server-side. The plans should specify behavior after add/delete/ack/filter changes, especially page bounds and selection reset.
- **MEDIUM:** Bypass alert filters need exact API mapping. Severity values, acknowledged status parameter names, default acknowledged behavior, and offset reset on filter changes should be specified.
- **MEDIUM:** Error display behavior is under-specified. Failed list/load/sync/delete/ack/add operations should surface a status message without corrupting local state.
- **MEDIUM:** Plan 05 says detail screen shows all 13 fields, but the roadmap names a subset plus "all `BypassAlertRow` fields." The plan should bind to the actual struct fields to avoid missing new or renamed fields.
- **LOW:** Relative timestamp rendering needs a stable time source and testable formatting boundary cases.
- **LOW:** URL encoding in Plan 02 is mentioned only for bypass alert list. Protected path create/update/delete may also need careful request body encoding or path-id handling depending on API shape.
- **LOW:** "Compilation/signature tests" for client methods are weak if they do not verify URL, method, body, query params, and response handling.

## Suggestions

- Resolve the client method count mismatch: either correct the roadmap to 7 methods or identify the missing eighth method.
- Drop `update_protected_path` from Phase 54 unless there is an actual edit workflow, or explicitly justify it as API parity.
- Add a small shared menu-index assertion/test so SystemMenu item count and positions cannot silently drift.
- Define selection/page behavior:
  - After refresh: preserve selected item when possible.
  - After delete: clamp selection and page.
  - After add/sync: reload and show status.
  - After filter change: reset bypass alerts to page 0 and first row.
  - After ack: keep row selected and dim it, or remove it if hide-acknowledged is active.
- Add tests for failed optimistic ack revert, delete failure, add failure, empty lists, last-page deletion, and filter/page reset.
- Add client tests using mocked HTTP responses to verify:
  - Correct endpoints and methods.
  - Query params for severity, acknowledged filter, limit, offset.
  - Empty `200 OK` ack response handling.
  - Error propagation for non-2xx responses.
- Specify status/error message handling in each action helper.
- Ensure protected path delete cannot be triggered for `source = "auto"` both in dispatch logic and action helper, not only visually.
- Make detail popup robust to long paths and missing/null optional fields.
- Include keyboard help/footer updates for both screens so operators can discover `a/d/s/r/f/h/Enter/Esc`.
- Add snapshot-style or buffer-level render tests for badges, tier colors, dimmed acknowledged rows, and truncation behavior.

## Per-Plan Notes

### Plan 01: Foundation — Types and Constants

Strong foundation plan. It gives later work stable enum variants, input/confirm purposes, and constants.

Concerns:
- **MEDIUM:** `BypassAlertSeverityFilter` must map exactly to API-supported severity values.
- **LOW:** Adding screen variants may require updates to default title/header/footer logic beyond `screens/mod.rs`.

Suggestions:
- Include unit tests for `next()`, `as_str()`, and `label()`.
- Add a compile-time or unit test covering all `Screen` match arms if the project has exhaustive screen helpers.

Risk: **LOW**. Mostly additive, but downstream compile errors are likely if all match sites are not updated.

### Plan 02: Client Methods

Client work is necessary and correctly isolated before UI actions.

Concerns:
- **HIGH:** Method count mismatch: 7 listed vs 8 required.
- **MEDIUM:** `update` may be unused scope.
- **MEDIUM:** Tests sound too shallow if they only check signatures.

Suggestions:
- Verify exact server API contract from Phases 52/53 before implementation.
- Add mocked HTTP tests for route, method, query encoding, JSON body, and empty response ack handling.

Risk: **MEDIUM** because client/API contract mismatches would block all screens.

### Plan 03: ProtectedPathList Screen

This plan covers the major required behavior for protected paths.

Concerns:
- **MEDIUM:** Add flow after `TextInput` must specify tier/source defaults. The roadmap says T3/T4 protected paths, but free-text add needs to know whether manual additions are T3 or T4, or whether API infers it.
- **MEDIUM:** Delete must be blocked for auto entries in logic, not just via UI affordance.
- **LOW:** Client-side pagination must handle empty list and page clamp after deletion/sync.

Suggestions:
- Specify create payload fields clearly.
- Add tests for manual-only delete, sync reload, add confirmation, empty state, and page clamp.

Risk: **MEDIUM** due to unclear add payload and state transitions.

### Plan 04: BypassAlertList Screen

The list behavior aligns well with user decisions and roadmap.

Concerns:
- **MEDIUM:** Optimistic ack plus hide-acknowledged filter can be tricky. If hide-acknowledged is active, does the row disappear immediately or after reload?
- **MEDIUM:** Server-side pagination with filters requires offset reset and total/has-next behavior.
- **LOW:** Relative timestamp from QPC may not be directly convertible to wall-clock time unless server provides enough context.

Suggestions:
- Define ack behavior under hide-acknowledged mode.
- Add failure tests for optimistic ack revert.
- Confirm QPC timestamp display format with existing API fields.

Risk: **MEDIUM**. The UI is straightforward, but pagination/filter/ack interactions are easy to get subtly wrong.

### Plan 05: BypassAlertDetail Screen

Good narrow plan for the detail popup.

Concerns:
- **MEDIUM:** "All 13 fields" should be tied to the actual DTO, otherwise implementation may drift.
- **LOW:** Long values may overflow popup width without wrapping/truncation rules.
- **LOW:** Human-friendly correlation mapping risks hiding raw diagnostic detail if unmapped values appear.

Suggestions:
- Show mapped correlation reason plus raw value when unknown.
- Add render tests for long paths, missing hash, zero/null file object, and narrow terminal width.

Risk: **LOW** if it is purely presentational and reuses selected row state.

### Plan 06: Integration and Quality Gates

The gate list is strong and appropriate for a TUI integration phase.

Concerns:
- **MEDIUM:** Sonar scanner may not be available locally or may require external credentials/network.
- **LOW:** "Zero warnings" is good, but existing workspace warnings could block unrelated work.

Suggestions:
- Separate mandatory local gates from environment-dependent gates.
- Include targeted admin CLI tests in addition to full workspace gates.
- Add a final manual smoke-test checklist for both screens' key flows.

Risk: **LOW to MEDIUM**. The plan is sound, but Sonar/environment assumptions may cause non-code blockers.

## Overall Risk Assessment

**MEDIUM.**

The plan set is well-structured and likely to achieve Phase 54, but there are a few important gaps to resolve before execution: the client method count mismatch, unclear protected-path add/update semantics, and interaction details around bypass alert filtering, pagination, and optimistic ack. None of these appear architecturally dangerous, but they can cause rework or incomplete UX if left implicit.

---

## OpenCode Review

## Overall Summary

The phase is well-scoped and aligns tightly with the stated UX decisions and prior server capabilities. The plans follow existing TUI patterns (LabelList/ApprovalList), which reduces risk and cognitive load. The separation into waves is sensible, and most critical flows (CRUD, pagination, ack lifecycle, navigation) are covered. The main risks are around state consistency (especially optimistic updates), pagination edge cases, input/selection invalidation, and incomplete error handling. Test coverage is present but shallow in behavioral areas.

---

## Plan 01 — Foundation (Types and Constants)

### Summary
Solid foundational setup with clear enum extensions and constants. This plan is low-risk and consistent with existing architecture.

### Strengths
- Clean extension of `Screen` enum with minimal disruption
- Explicit enums for filters and input purposes improve type safety
- Constants files help avoid magic numbers/strings
- Aligns with existing modular structure

### Concerns
- LOW: `BypassAlertSeverityFilter::next()` cycle logic may become brittle if enum expands later
- LOW: No mention of serialization/deserialization needs if filters are reused elsewhere
- LOW: Potential duplication between constants and inline usage if not enforced

### Suggestions
- Add a `from_str` or mapping helper for severity to ensure consistency with server values
- Consider deriving `Copy + Eq + PartialEq` for filter enums if used frequently in state comparisons
- Ensure constants are actually used (avoid dead code drift)

### Risk Assessment
LOW — straightforward type additions with minimal integration complexity

---

## Plan 02 — Client Methods

### Summary
Covers required API surface correctly, but has moderate risk around error handling, encoding, and consistency with existing client patterns.

### Strengths
- Full CRUD + sync coverage for Protected Paths
- Explicit handling for empty 200 response in ack
- Awareness of `urlencoding` need
- Unit tests included

### Concerns
- HIGH: No explicit error typing strategy (are errors mapped to domain errors or raw reqwest errors?)
- MEDIUM: URL encoding only mentioned for alerts list — path inputs may also need encoding or escaping
- MEDIUM: No timeout/retry strategy (important for admin UX responsiveness)
- MEDIUM: Unit tests are "signature tests" only — no behavior validation
- LOW: Update method may not be needed (not clearly used in UI)

### Suggestions
- Normalize error handling: map HTTP status codes into structured errors (e.g., 400 vs 500 vs network)
- Ensure all path/query inputs are encoded safely (not just alerts)
- Add at least one integration-style test using a mock server (wiremock or similar)
- Validate response schemas explicitly (avoid silent deserialization issues)
- Confirm whether `update` is actually required; remove if unused

### Risk Assessment
MEDIUM — API correctness is critical; weak error handling could degrade UX significantly

---

## Plan 03 — ProtectedPathList Screen

### Summary
Well-aligned with UX decisions and existing patterns. Main risks are around state synchronization and edge cases in list handling.

### Strengths
- Clear separation of dispatch, render, and actions
- Client-side pagination matches endpoint constraints
- Confirmation flow for delete is well defined
- Sync action explicitly idempotent
- Keybindings consistent with spec

### Concerns
- HIGH: Selection invalidation after delete/sync (cursor may point to non-existent item)
- MEDIUM: No explicit loading/error state handling in UI (e.g., spinner, error banner)
- MEDIUM: Client-side pagination on full dataset may become slow if list grows large
- MEDIUM: No deduplication strategy if sync introduces overlapping entries
- LOW: Path truncation may hide important distinctions

### Suggestions
- After delete/sync, clamp selection index to valid range
- Introduce explicit UI states: loading, empty, error
- Consider caching full list vs refetch strategy on every action
- Ensure manual vs auto distinction is enforced client-side before enabling delete
- Add visual indicator if list is stale (after failed refresh)

### Risk Assessment
MEDIUM — mostly UI/state management risks, especially around list mutations

---

## Plan 04 — BypassAlertList Screen

### Summary
Feature-complete and well thought out, but carries the highest risk due to optimistic updates and pagination interactions.

### Strengths
- Optimistic ack improves responsiveness
- Server-side pagination correctly leveraged
- Filters and toggles match UX spec
- Render design is compact and informative

### Concerns
- HIGH: Optimistic ack rollback may fail if item is no longer in current page (pagination/filter change)
- HIGH: No idempotency handling for repeated ack attempts
- MEDIUM: Race condition between refresh (`r`) and in-flight ack
- MEDIUM: Pagination + filtering interaction may produce inconsistent counts or empty pages
- MEDIUM: No backoff/retry on ack failure
- LOW: Relative timestamp calculation may drift or be inconsistent

### Suggestions
- Track ack operations with a temporary "pending" state instead of immediately flipping to acknowledged
- Use stable identifiers (ID) to reconcile rollback, not index position
- Disable ack key while request is in-flight for that item
- Reset pagination when filter changes to avoid empty views
- Add lightweight retry or error indicator for failed ack
- Consider storing last fetch timestamp for consistency

### Risk Assessment
HIGH — optimistic updates + pagination + filtering create multiple failure modes

---

## Plan 05 — BypassAlertDetail Screen

### Summary
Straightforward rendering plan with minimal logic. Low complexity but some formatting and data consistency concerns.

### Strengths
- Clear mapping of all fields
- Formatting decisions (SHA truncation, hex pointer) are consistent
- Simple navigation model

### Concerns
- MEDIUM: No handling for missing/null fields
- LOW: Hardcoded truncation length may not scale or be configurable
- LOW: Correlation reason mapping may drift from server definitions

### Suggestions
- Add fallback display for missing values (e.g., "<unknown>")
- Centralize formatting helpers (SHA truncation, hex formatting)
- Ensure correlation reason mapping is shared with list view (avoid duplication)

### Risk Assessment
LOW — mostly presentation logic

---

## Plan 06 — Integration and Quality Gates

### Summary
Covers standard quality gates but lacks deeper validation of runtime behavior and UX correctness.

### Strengths
- Includes build, clippy, fmt, and sonar checks
- Ensures workspace-wide consistency
- Explicit milestone documentation updates

### Concerns
- HIGH: No end-to-end or integration testing of TUI flows
- MEDIUM: No validation of API contract alignment (client vs server)
- MEDIUM: No manual test checklist for UX behaviors
- LOW: Sonar may not catch Rust-specific issues deeply

### Suggestions
- Add a manual QA checklist (navigation, add/delete, sync, ack, filters)
- Include a mock server integration test for critical flows
- Validate pagination boundaries (first/last page, empty states)
- Add logging around API failures for debugging

### Risk Assessment
MEDIUM — quality gates are necessary but not sufficient for UI-heavy features

---

## Cross-Plan Integration Risks

- HIGH: State consistency between Plan 03 and Plan 04 (shared navigation, pagination helpers)
- HIGH: Error handling inconsistencies between client (Plan 02) and UI (Plans 03/04)
- MEDIUM: Menu index drift (Plan 01 vs Plan 03/04) — easy to break navigation
- MEDIUM: Filter/pagination interplay not centrally managed
- LOW: Constants duplication across plans

---

## Final Risk Assessment

**Overall Risk: MEDIUM-HIGH**

The architecture and scope are solid, and most functionality is covered. However, the combination of:
- optimistic updates,
- pagination + filtering,
- weak error handling,
- and limited behavioral testing

introduces meaningful risk of subtle UI bugs and inconsistent state.

If the suggested fixes around state management, error handling, and testing are applied, this phase would drop to **LOW-MEDIUM risk**.

---

## Claude Review

## Plan 01 (Wave 1): Foundation — Types and Constants

**Summary:** A solid foundation plan that correctly identifies all new types needed downstream. The `BypassAlertSeverityFilter` enum is well-designed with `next()`/`as_str()`/`label()` methods, and the constants files follow the existing `labels.rs` / `approvals.rs` pattern. The module declarations and Screen variants are comprehensive.

**Strengths:**
- `BypassAlertSeverityFilter` derives `Copy`, avoiding clone issues in dispatch handlers.
- Constants files include `#[cfg(test)]` modules verifying hint string contents, following established patterns.
- `Screen::BypassAlertList` includes all state fields needed for filters and pagination.
- Threat model correctly identifies server-side path validation (Phase 52) as the mitigation for path tampering.

**Concerns:**
- **LOW**: `Screen::BypassAlertList` carries a `status_message: String` field that is initialized to `String::new()` in `action_load_bypass_alert_list` (Plan 04) and never read by any render or dispatch logic. This adds dead weight and may confuse future maintainers.
- **LOW**: Plan 01's `BypassAlertDetail` Screen variant stores only `alert: serde_json::Value`. When the user returns from detail to list (Plan 04), the filter/page state is lost because it's not stored in the detail screen. This forces a reload with defaults.

**Suggestions:**
- Consider removing `status_message` from `BypassAlertList` if no plan uses it, or document its purpose if it's for future use.
- Consider storing parent list state in `BypassAlertDetail` so returning from detail preserves filters.

---

## Plan 02 (Wave 1): Client Methods

**Summary:** Seven well-designed HTTP wrapper methods following the established `EngineClient` pattern. The distinction between generic `self.get()`/`self.post()` and raw `self.inner.post()` for the empty-body ack endpoint shows good understanding of the existing client architecture.

**Strengths:**
- Correctly uses `urlencoding::encode` for `list_bypass_alerts` severity parameter.
- Correctly uses raw `self.inner.post()` + `self.apply_auth()` for `ack_bypass_alert` because the server returns empty 200.
- `ack_bypass_alert` takes `i64`, matching the server's `Path<i64>` binding.
- Doc comments on all methods with endpoint, purpose, and error behavior.

**Concerns:**
- **MEDIUM**: `update_protected_path` is added but never called by any downstream plan (Plans 03–05 only use list, create, delete, sync). Plan 06 Task 1 step 2 lists this method for `#[allow(dead_code)]` removal, which will produce a compiler warning and fail the zero-warnings goal.
- **LOW**: The 9 "unit tests" are compilation/signature tests only — they don't verify HTTP behavior. This is consistent with the existing client.rs test pattern but provides no coverage of URL construction, query string formatting, or error paths.

**Suggestions:**
- Either remove `update_protected_path` from this phase (it's not needed for the roadmap scope), or keep its `#[allow(dead_code)]` attribute through Plan 06 with a comment noting it's for a future phase.
- Add at least one test that verifies `list_bypass_alerts` builds the correct query string (e.g., `assert!(url.contains("severity=crit"))`).

---

## Plan 03 (Wave 2): ProtectedPathList Screen

**Summary:** A well-structured vertical slice that delivers the Protected Paths screen end-to-end. The two-phase read-then-mutate pattern is correctly applied, client-side pagination is clearly implemented, and the menu expansion from 12 to 14 items is handled with a temporary stub for Plan 04.

**Strengths:**
- Correctly guards delete behind `source == "manual"` check, with server-side enforcement as defense in depth.
- Client-side pagination cleanly slices the full server response.
- `action_sync_protected_paths` refreshes the list after sync, giving immediate feedback.
- Menu expansion correctly pushes Syslog Config from index 10 to 12 and Back to 13.

**Concerns:**
- **MEDIUM**: The instruction for `handle_text_input` Esc routing is vague: "(Place it in the catch-all `_ => Screen::PolicyMenu { selected: 0 }` pattern, or add an explicit arm before the catch-all.)" The catch-all already exists at line 310. An explicit arm must be added *before* it, but the plan doesn't show the exact insertion point. This is easy to miss during execution.
- **MEDIUM**: No test verifies the `'d'` key behavior: pressing 'd' on an auto-derived entry shows an error toast, while 'd' on a manual entry opens the Confirm dialog. This is a critical UX guard.
- **LOW**: The `handle_system_menu` comment references "Phase 62" for the Syslog Config move, but Syslog Config is being moved in *this* phase (from 10 to 12). The comment should reference Phase 54, not 62.

**Suggestions:**
- Make the Esc routing instruction explicit: "Add an explicit arm `InputPurpose::AddProtectedPath => Screen::SystemMenu { selected: 10 },` before the `_ => Screen::PolicyMenu { selected: 0 }` catch-all at line 310."
- Add a dispatch test that constructs a `ProtectedPathList` with mixed auto/manual entries and verifies 'd' key behavior for each.

---

## Plan 04 (Wave 2): BypassAlertList Screen

**Summary:** The most complex plan in the phase. The optimistic ack pattern with revert-on-error is well-designed and correctly implemented using two-phase borrow patterns. Server-side pagination, filter cycling, and severity badge rendering all follow established patterns.

**Strengths:**
- Optimistic ack: dims row immediately, reverts on server error with error toast. This matches the D-09 requirement perfectly.
- Filter cycling (`f` key) and hide-acknowledged toggle (`h` key) both reset to page 1, which is the correct UX behavior.
- `format_relative_time` uses coarse buckets (`<1m`, `Xm`, `Xh`, `Xd`) which is appropriate for a TUI list.
- Server-side pagination correctly passes `limit`/`offset` to the server.

**Concerns:**
- **HIGH**: No test covers the optimistic ack revert path. This is the most complex logic in the entire phase — it involves mutating `app.screen` twice (optimistic update + revert), calling `block_on` for the server request, and setting status on both success and error. Without a test, a refactor could silently break this behavior.
- **MEDIUM**: `handle_bypass_alert_detail` reloads the list with `BypassAlertSeverityFilter::All, false, 0` on Enter/Esc, losing the user's filter and page state. The comment acknowledges this matches `ApprovalDetail`, but it's still a UX regression from what users would expect.
- **LOW**: No tests for `'f'` filter cycling with page reset, `'h'` toggle, or `PgUp`/`PgDn` pagination guards.
- **LOW**: `format_relative_time` has no direct unit tests — it's only tested indirectly through render tests.

**Suggestions:**
- **Priority**: Add a test that mocks `ack_bypass_alert` failure (e.g., by constructing an `App` with a non-routable client URL), triggers the 'a' key, and asserts that `acknowledged` reverts to `false` and a `StatusKind::Error` toast is set.
- Consider storing parent list state in `BypassAlertDetail` to preserve filters on return.

---

## Plan 05 (Wave 2): BypassAlertDetail Screen

**Summary:** A clean, render-only plan that correctly formats all 13 `BypassAlertRow` fields. The defensive handling of `Option<String>` for `image_sha256` and the human-friendly mapping for `correlation_reason` are well done.

**Strengths:**
- `file_object` formatted as `0x{:016X}` with uppercase hex, exactly matching D-08.
- `image_sha256` truncated to 16 chars with full value on a second line — good balance of brevity and completeness.
- `Paragraph::wrap(Wrap { trim: true })` prevents long paths from overflowing.
- Correlation reason mapping handles both snake_case and PascalCase variants defensively.

**Concerns:**
- **LOW**: No test verifies severity color styling in the detail view (only the label string is asserted).
- **LOW**: `file_object` is cast from `i64` to `u64` with `file_object as u64`. If the server ever returns a negative value (e.g., due to a database corruption), the hex display will show a large positive number. This is unlikely but the assumption that kernel pointers are always positive when stored as `i64` is implicit.

**Suggestions:**
- Add assertions for the ANSI color codes in the `TestBackend` buffer for each severity level.
- Document the invariant that `file_object` is expected to be a non-negative kernel pointer.

---

## Plan 06 (Wave 3): Integration and Quality Gates

**Summary:** A comprehensive integration plan with a strong checklist covering build, tests, clippy, formatting, and SonarQube. The awareness of common pitfalls (borrow checker, menu drift, orphaned imports) shows good integration planning.

**Strengths:**
- Explicitly lists 8 pitfalls to verify from RESEARCH.md.
- Task 1 step 5 verifies the exact 14-item menu order, which catches the D-16 inconsistency.
- Task 1 step 6 and 7 verify Esc routing and cancel routing for all new purpose variants.
- Includes workspace-wide build and test verification.

**Concerns:**
- **MEDIUM**: Plan 06 Task 1 step 2 lists `update_protected_path` for dead_code removal, but this method is never called. Removing `#[allow(dead_code)]` will cause a compiler warning, failing the "zero warnings" goal. The verification `cargo build` grep will catch this, but it's a known integration issue the plan doesn't resolve.
- **MEDIUM**: The build verification uses `grep -c "warning:"` which is fragile — `cargo` or `rustc` might emit "warning:" in paths or dependency output. A more robust check would be `cargo build -p dlp-admin-cli 2>&1 | grep -E "^warning:" | wc -l`.
- **LOW**: Plan 06 assumes all 6 plan SUMMARYs exist. If an executor crashes or forgets to create one, this task will fail. Consider adding a fallback to generate missing SUMMARYs from the plan files.

**Suggestions:**
- Resolve the `update_protected_path` dead code issue before Plan 06 (remove the method, or keep `#[allow(dead_code)]` with a comment).
- Use `grep -E "^warning:"` for more precise warning counting.
- Add a fallback step in Task 5 to create any missing SUMMARYs from the plan files.

---

## Cross-Plan Integration Risks

| Risk | Severity | Description |
|------|----------|-------------|
| Stub cleanup | LOW | Plan 03 adds `action_load_bypass_alert_list_stub`; Plan 04 must remove it. Plan 04 says "if it exists," which is safe, but the conditional wording leaves room for the function to survive. |
| Menu index consistency | LOW | The current SystemMenu has 12 items with Syslog Config at 10 and Back at 11. The plans correctly expand to 14 items. D-16 incorrectly says "pushing Back to 12" — the plans override this with the correct 14-item layout. |
| `status_message` dead field | LOW | Plan 01 adds `status_message` to `BypassAlertList`; no plan reads it. Mild confusion for future maintainers. |
| `update_protected_path` dead code | MEDIUM | Plan 02 adds it; no downstream plan calls it. Plan 06 will fail zero-warnings if `#[allow(dead_code)]` is removed. |
| Optimistic ack untested | HIGH | Plan 04's most complex logic has no test coverage. A bug here would leave the UI in an inconsistent state. |

---

## Overall Risk Assessment: **MEDIUM**

**Justification:** The plans are well-structured, follow existing patterns closely, and have clear wave-based dependencies. The phase goals are achievable with these plans. However, three specific issues elevate the risk from LOW to MEDIUM:

1. **Untested complex logic**: The optimistic ack revert in Plan 04 is the most critical user-facing error path and has zero test coverage. A bug here would leave the UI in an inconsistent state.
2. **Dead code integration failure**: `update_protected_path` will cause a zero-warnings failure in Plan 06 unless resolved earlier.
3. **Vague routing instruction**: The `handle_text_input` Esc routing for `AddProtectedPath` is described ambiguously and could be missed, leaving users stranded in the TextInput screen.

All three are fixable with minor plan amendments before execution begins.

---

## Consensus Summary

### Agreed Strengths

- All three reviewers praised the clear wave ordering (types -> client -> screens -> integration) and tight scope alignment with UX decisions.
- Reuse of existing TUI patterns (LabelList/ApprovalList) was universally recognized as reducing risk.
- Explicit deferred-item list (bulk ops, auto-refresh, graphical browser) keeps scope controlled.
- Optimistic ack with revert on failure is the right UX pattern, though all reviewers flagged implementation risks.
- Quality gates in Plan 06 (build, clippy, fmt, sonar) are appropriate and necessary.

### Agreed Concerns (2+ reviewers)

| Concern | Severity | Reviewers | Description |
|---------|----------|-----------|-------------|
| Client method count mismatch | HIGH | Codex, OpenCode, Claude | Phase claims 8 methods but plans list 7 (5 protected + 2 bypass). `update_protected_path` may be unused scope. |
| Optimistic ack state consistency | HIGH | Codex, OpenCode, Claude | Rollback by index position is fragile under pagination/filter changes. Race between refresh and in-flight ack. No test coverage for revert path. |
| Selection invalidation after mutations | HIGH | Codex, OpenCode, Claude | After delete/sync, cursor may point to non-existent item. No clamping logic specified. |
| Weak client tests | MEDIUM | Codex, OpenCode, Claude | Tests are compilation/signature only — no mocked HTTP behavior validation. |
| Pagination + filter interaction | MEDIUM | Codex, OpenCode, Claude | Filter changes should reset to page 0; ack under hide-acknowledged mode is undefined. |
| Error handling under-specified | MEDIUM | Codex, OpenCode, Claude | Failed operations should surface status without corrupting local state. No structured error mapping. |
| Menu index fragility | MEDIUM | Codex, OpenCode, Claude | Plan 03 and Plan 04 both touch handle_system_menu; coordination risk. |
| `update_protected_path` dead code | MEDIUM | Codex, Claude | Plan 02 adds it; no downstream plan calls it. Plan 06 will fail zero-warnings if `#[allow(dead_code)]` is removed. |
| `status_message` dead field | LOW | Claude | Plan 01 adds `status_message` to `BypassAlertList`; no plan reads it. |
| Vague Esc routing instruction | MEDIUM | Claude | Plan 03's handle_text_input Esc routing for AddProtectedPath is ambiguous. |

### Divergent Views

- **OpenCode** rated Plan 04 (BypassAlertList) as HIGH risk individually, while **Codex** rated it MEDIUM and **Claude** called out the untested optimistic ack as the primary concern.
- **OpenCode** was most concerned about end-to-end/integration testing gaps (HIGH in Plan 06), while **Codex** focused on API contract alignment and **Claude** on specific integration issues like dead code and vague routing.
- **Claude** uniquely identified the `status_message` dead field and the `handle_text_input` Esc routing ambiguity as specific execution risks.
- **Codex** was more concerned about client-side pagination performance for protected paths (MEDIUM), while **OpenCode** focused on server-side pagination consistency for bypass alerts.

### Actionable Recommendations (Prioritized)

1. **Resolve method count mismatch** — Either remove `update_protected_path` (no UI uses it) or identify the 8th method. Document the decision in Plan 02. If kept, retain `#[allow(dead_code)]` through Plan 06.
2. **Fix optimistic ack rollback** — Use stable ID (not index) for rollback lookup. Add a `pending_ack` flag to prevent double-ack. Add a test for the revert path.
3. **Add selection clamping** — After delete/sync/add, clamp `selected` to `min(selected, paths.len().saturating_sub(1))`.
4. **Define filter+pagination reset behavior** — On filter change or hide-ack toggle, reset to page 0 and selected 0.
5. **Add mocked HTTP client tests** — Use a mock server or reqwest mock to verify endpoints, query params, and error propagation.
6. **Add menu-index assertion test** — A single test verifying SystemMenu item count and label order prevents silent drift.
7. **Document ack behavior under hide-acknowledged** — If hide-ack is active and user acks, does the row disappear immediately or after refresh?
8. **Add manual QA checklist to Plan 06** — Navigation, add/delete, sync, ack, filters, pagination boundaries, empty states.
9. **Fix vague Esc routing** — Make Plan 03's handle_text_input Esc routing for AddProtectedPath explicit with exact insertion point.
10. **Remove or document `status_message`** — Either remove the dead field from `BypassAlertList` or document its intended future use.

---

*Review generated by gsd-review skill. To incorporate feedback: /gsd:plan-phase 54 --reviews*
