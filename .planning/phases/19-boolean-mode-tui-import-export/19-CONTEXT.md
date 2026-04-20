# Phase 19: Boolean Mode in TUI + Import/Export - Context

**Gathered:** 2026-04-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Surface the Phase 18 boolean `mode` field in the admin TUI and close
the end-to-end round-trip for POLICY-09. The `PolicyCreate` and
`PolicyEdit` forms gain a `Mode` row that authors the field; the
admin-side `PolicyResponse` / `PolicyPayload` typed structs grow a
`mode` field so export/import preserves it; an integration test
proves the server + TUI + import/export chain behaves identically
for ALL / ANY / NONE.

**Explicitly in scope:**
1. `PolicyFormState` gains a `mode: PolicyMode` field (default `ALL`).
2. Policy Create / Policy Edit form render adds a `Mode` row between
   `Enabled` and `[Add Conditions]`. Cycle on Enter/Space (same key
   pattern as the `Enabled` bool toggle and the `Action` enum cycler).
3. `dlp-admin-cli::app::PolicyResponse` and `PolicyPayload` both
   gain a typed `mode: PolicyMode` field with `#[serde(default)]`.
   `From<PolicyResponse> for PolicyPayload` copies `mode` unchanged.
4. Export writes `mode` unconditionally on every policy (milestone
   criterion 3 — "Export includes the `mode` field on every policy").
5. Import already tolerates missing `mode` via `#[serde(default)]`
   on the admin-cli structs — a file that omits `mode` deserializes
   with `PolicyMode::ALL`, no import failure.
6. Footer hint below the Conditions list when
   `mode != ALL && conditions.is_empty()` — advisory only, does NOT
   block submit (preserves Phase 18 D-13 server-side semantics).
7. End-to-end integration test (new `dlp-server/tests/`): create
   three policies (one per mode) via `POST /admin/policies`, hit
   `/evaluate` with one `EvaluateRequest` per policy, assert the
   decisions differ per the boolean semantics.

**Explicitly out of scope (for this phase):**
- No server-side schema/evaluator change. Phase 18 shipped that.
- No expanded operators. `eq` / `neq` / `in` / `not_in` stay as-is;
  operator expansion lands in Phase 20.
- No in-place condition editing; that's Phase 21.
- No nested boolean trees. Flat top-level mode only.
- No client-side mode validation. `mode=ANY` with empty conditions
  is legal on the wire per D-13; the footer hint is advisory.

</domain>

<decisions>
## Implementation Decisions

### Mode Picker UX (Phase 19 novelty)

- **D-01:** Mode picker uses cycle-on-Enter/Space. `Mode: ALL` →
  press Enter → `Mode: ANY` → press Enter → `Mode: NONE` → press
  Enter → back to `Mode: ALL`. Matches the existing `Enabled` bool
  toggle pattern and the `Action` enum cycler (`PolicyFormState.action:
  usize` index into `ACTION_OPTIONS`). Keeps keybindings consistent
  across the form. No new modal, no horizontal navigation keys, no
  popup overlay.
- **D-02:** Mode row sits between `Enabled` and `[Add Conditions]`.
  Post-change `POLICY_FIELD_LABELS` becomes 9 rows:
  ```
  Name, Description, Priority, Action, Enabled, Mode,
  [Add Conditions], Conditions, [Submit]
  ```
  Rationale: keeps editable leaf fields contiguous, and separates
  the `[Add Conditions]` action-trigger row from all data rows.
  Tab/arrow navigation already groups editable fields together.
- **D-03:** Default on Create is `PolicyMode::ALL`. Pre-fill on
  Edit is read from `PolicyResponse.mode`. Both land in
  `PolicyFormState.mode` via the same code path (the existing
  `load_policy_into_form` function extends to copy `mode`).
- **D-04:** Footer hint below the Conditions list: when
  `form.mode != PolicyMode::ALL && form.conditions.is_empty()`,
  render a single advisory line in the form's footer text block.
  Wording recommendation:
  - `mode=ANY` + `[]`: `Note: mode=ANY with no conditions will never match.`
  - `mode=NONE` + `[]`: `Note: mode=NONE with no conditions matches every request.`
  Advisory only — no validation error, no block-on-submit, no
  colored warning banner. Matches the TUI's existing tone for
  inline hints.

### Admin-CLI Typed Structs (import/export wire format)

- **D-05:** `dlp-admin-cli::app::PolicyPayload` gains
  `pub mode: PolicyMode` with `#[serde(default)]`. Uses the
  `dlp_common::abac::PolicyMode` type from Phase 18 — no local
  duplicate. `#[serde(default)]` ensures legacy v0.4.0 export files
  deserialize cleanly with `mode = ALL`.
- **D-06:** `dlp-admin-cli::app::PolicyResponse` gains the same
  field with the same annotation. Matches server `PolicyResponse`
  shape exactly.
- **D-07:** `From<PolicyResponse> for PolicyPayload` copies
  `mode: r.mode` unchanged. `PolicyMode` derives `Copy` (Phase 18
  D-05) so this is a cheap field copy, not a clone.
- **D-08:** `PolicyFormState` gains `pub mode: PolicyMode`.
  `#[derive(Default)]` on the struct (already present) correctly
  defaults the new field to `PolicyMode::ALL` via
  `PolicyMode::default()` (Phase 18 D-03).

### Export Behavior

- **D-09:** Export writes `mode` unconditionally on every policy.
  The current implementation fetches `Vec<serde_json::Value>` from
  `GET /admin/policies` and writes it verbatim to disk — since the
  Phase 18 server always includes `"mode":"ALL"` (or `"ANY"`/`"NONE"`)
  in `PolicyResponse`, the untyped pipeline already writes the field.
  No code change to `action_export_policies` is required, but the
  integration test MUST verify `mode` appears in every exported
  policy as a regression guard.
- **D-10:** Milestone criterion 3 ("export includes the `mode` field
  on every policy") is satisfied transitively by Phase 18's server
  change. Phase 19 adds a round-trip assertion that proves the file
  shape is stable.

### Import Behavior

- **D-11:** The `serde_json::from_str::<Vec<PolicyResponse>>(json)`
  call in `action_import_policies` starts honoring the new `mode`
  field automatically once D-06 lands. Files that omit `mode` (v0.4.0
  exports) deserialize with `mode = PolicyMode::ALL` via
  `#[serde(default)]`. Files that carry `mode = "ANY"`/`"NONE"`
  round-trip their exact boolean semantics.
- **D-12:** No additional import validation. If a legacy export is
  imported and some of its policies "really wanted" ANY semantics
  (impossible — v0.4.0 only had implicit AND), the defaulted `ALL`
  value preserves the semantics the file was authored against. The
  user does NOT see a warning for legacy files — they look identical
  to a v0.5.0 export with all-ALL policies, which is correct.
- **D-13:** Conflict-resolution UI from Phase 17 (`ImportConfirm`
  screen, abort-on-error) is unchanged. Mode differences between
  source and destination policies with the same ID are NOT surfaced
  as a separate conflict category — they fold into the existing
  "full overwrite or skip" per-policy choice.

### Integration Test (end-to-end proof)

- **D-14:** New integration test lives in
  `dlp-server/tests/mode_end_to_end.rs`. Uses the existing in-memory
  pool + admin router test harness (same pattern as
  `admin_audit_integration.rs`). Three test functions:
  - `test_mode_all_matches_when_all_conditions_hit`
  - `test_mode_any_matches_when_one_condition_hits`
  - `test_mode_none_matches_when_no_conditions_hit`
  Each one: `POST /admin/policies` with the mode, `POST /evaluate`
  with a crafted `EvaluateRequest`, assert the expected decision
  and `matched_policy_id`.
- **D-15:** Additionally, a test exercising export-then-reimport
  round-trip at the data layer: start with three policies (one per
  mode), serialize them through `PolicyPayload` (matching what the
  TUI's export writes), deserialize back, and assert struct equality
  on `mode`. This is a server-side test — the TUI's file dialog is
  not exercised directly, which keeps the test deterministic and
  cross-platform. The UAT (Test 7 in Phase 18) already proved the
  HTTP round-trip.

### Claude's Discretion

- Exact wording of the footer hint messages in D-04 — the two
  recommended strings are a starting point; tweak during
  implementation if the TUI's footer has tonal conventions I missed.
- Whether `PolicyFormState.mode` stores the enum directly or an
  index (like `action: usize`) — the existing pattern uses an index
  for `action`, but since `PolicyMode` only has 3 variants and is
  `Copy`, storing the enum directly may be cleaner. Planner picks
  based on rendering convenience.
- Whether to factor out a `cycle_mode(mode: PolicyMode) -> PolicyMode`
  helper function vs inline the three-way match. Both are fine.
- Whether the integration test file goes in
  `dlp-server/tests/mode_end_to_end.rs` or folds into
  `admin_audit_integration.rs`. Separate file is cleaner; either works.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Roadmap
- `.planning/REQUIREMENTS.md` § POLICY-09 — user-facing contract this phase closes
- `.planning/REQUIREMENTS.md` § POLICY-12 — Phase 18's backward-compat contract (still honored)
- `.planning/milestones/v0.5.0-ROADMAP.md` § Phase 19 — five success criteria
- `.planning/PROJECT.md` § Current Milestone: v0.5.0 Boolean Logic

### Phase 18 Foundation (just shipped)
- `.planning/phases/18-boolean-mode-engine-wire-format/18-CONTEXT.md` — all 26 decisions from Phase 18, especially D-03 (`PolicyMode::default() == ALL`), D-13 (no server-side empty-condition validation), D-14/D-15 (`#[serde(default)]` on wire types)
- `.planning/phases/18-boolean-mode-engine-wire-format/SUMMARY.md` — what was actually built (Wave 1 + Wave 2 + gaps closed)
- `.planning/phases/18-boolean-mode-engine-wire-format/18-UAT.md` — live curl verification of mode round-trip through `POST`/`PUT`/`GET`

### ABAC Core Types (dlp-common)
- `dlp-common/src/abac.rs` §249-268 — `PolicyMode` enum + `Policy.mode` field (Phase 18)
- `dlp-common/src/abac.rs` §266 — `Policy` derives `Default` (Phase 18 D-04)

### Admin CLI: Form State and Screens (dlp-admin-cli)
- `dlp-admin-cli/src/app.rs` §124-140 — `PolicyFormState` struct (gains `mode` field)
- `dlp-admin-cli/src/app.rs` §142-147 — `ACTION_OPTIONS` const (the enum-cycler precedent D-01 mirrors)
- `dlp-admin-cli/src/app.rs` §242-255 — `PolicyResponse` typed struct (gains `mode` field)
- `dlp-admin-cli/src/app.rs` §262-270 — `PolicyPayload` typed struct (gains `mode` field)
- `dlp-admin-cli/src/app.rs` §272-284 — `From<PolicyResponse> for PolicyPayload` (copies `mode` per D-07)
- `dlp-admin-cli/src/app.rs` §293+ — `Screen` enum and `PolicyCreate` / `PolicyEdit` variants
- `dlp-admin-cli/src/screens/render.rs` §141+ — `draw_conditions_builder` (footer hint area per D-04)
- `dlp-admin-cli/src/screens/render.rs` §165-200 — `Screen::PolicyCreate` / `Screen::PolicyEdit` rendering
- `dlp-admin-cli/src/screens/render.rs` §597-607 — `POLICY_FIELD_LABELS` const (extends from 8 to 9 rows per D-02)
- `dlp-admin-cli/src/screens/dispatch.rs` — `handle_policy_create` / `handle_policy_edit` event handlers (add Enter-cycle on the new row)
- `dlp-admin-cli/src/screens/dispatch.rs` §2918-2978 — `action_export_policies` (no code change; validate D-09 in integration test)
- `dlp-admin-cli/src/screens/dispatch.rs` §2984+ — `action_import_policies` (no code change; D-11 is automatic once D-05/D-06 land)

### Server: E2E test target
- `dlp-server/src/admin_api.rs` §97-135 — `PolicyPayload` / `PolicyResponse` (mode field present since Phase 18)
- `dlp-server/src/admin_api.rs` §505-566 — `/evaluate` handler (the target of D-14 test's POST)
- `dlp-server/tests/admin_audit_integration.rs` — existing integration test pattern (in-memory pool + admin router harness, JWT minting) — D-14 reuses this shape

### Phase 17 Prior Art (typed import/export)
- `.planning/phases/17-import-export/17-CONTEXT.md` — import conflict-resolution semantics and typed wire format rationale (D-13 preserves these)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `PolicyFormState` (`dlp-admin-cli/src/app.rs` §124) — derives `Default`, so adding a `PolicyMode` field (which defaults to `ALL`) does not break existing `PolicyFormState::default()` callers.
- `ACTION_OPTIONS` array + `PolicyFormState.action: usize` (§142-147) — direct precedent for enum cycling in the form. The mode picker can follow the same pattern or store the enum directly (Claude's discretion).
- `POLICY_FIELD_LABELS` const array (`screens/render.rs` §597) — the form row-label source of truth. Adding `"Mode"` at index 5 shifts `[Add Conditions]`/`Conditions`/`[Submit]` by one — downstream row-index checks (edge cases in dispatch.rs) must be audited.
- `impl From<PolicyResponse> for PolicyPayload` (§272-284) — one-line extension (`mode: r.mode`).
- `action_export_policies` (dispatch.rs §2918) — uses `serde_json::Value` pipeline; mode field is already in server JSON output and flows through without code change.
- `action_import_policies` (dispatch.rs §2984) — deserializes into `Vec<PolicyResponse>`, so D-06's `#[serde(default)]` on `PolicyResponse.mode` is all that's needed for legacy-file tolerance.

### Established Patterns
- **Cycle-on-Enter for enum fields in forms** — `Action` already does this via `PolicyFormState.action: usize` into `ACTION_OPTIONS[4]`. D-01 adopts this pattern for Mode.
- **Bool toggle on Enter/Space** — `Enabled` uses `[x]`/`[ ]` rendering. The mode picker is NOT a bool, so it uses the enum-cycler pattern instead.
- **Footer hint area** — the form already renders a status/help line at the bottom (not yet read in detail; planner should locate the exact render slot). D-04's advisory hint slots into that existing area, not a new widget.
- **Integration test harness** — `dlp-server/tests/admin_audit_integration.rs` is the template: in-memory pool, `admin_router()`, JWT via `mint_jwt`, tower-service `.oneshot()`. D-14 reuses this structure verbatim.
- **`#[serde(default)]` on typed wire structs for legacy tolerance** — Phase 18 D-14/D-15 established this; Phase 19 D-05/D-06 extend it to the admin-cli side.

### Integration Points
- `dlp-admin-cli::app::PolicyFormState` — one new field (`mode`), defaults via existing `Default` derive.
- `dlp-admin-cli::app::PolicyResponse` / `PolicyPayload` — one new field on each, `#[serde(default)]` shields legacy files.
- `dlp-admin-cli::screens::render` — one row added to labels, one line added to form render, one conditional footer line.
- `dlp-admin-cli::screens::dispatch` — one Enter-handler branch added for the new row index; one field copy added in the `load_policy_into_form` edit-screen population; all other rows' indices shift by one (audit required).
- `dlp-server/tests/` — one new integration test file per D-14.

### Row-Index Renumber Risk
The PolicyCreate/PolicyEdit event handler uses row index to dispatch
on which field is being edited (e.g., row 4 = Enabled toggle, row 5
= [Add Conditions] trigger, row 6 = Conditions list). Adding `Mode`
at index 5 shifts every subsequent row by +1. This is the single
highest-risk refactor in Phase 19 — the planner MUST enumerate every
row-index literal in `dispatch.rs` and migrate them atomically. A
grep for numeric literals near `selected ==` / `match selected` in
the policy create/edit handlers is mandatory pre-plan reconnaissance.

</code_context>

<specifics>
## Specific Ideas

- The footer hint text should be terse and factual, not alarmist.
  The point is "you probably didn't mean this" without second-guessing
  the admin. Examples (from D-04):
  - `Note: mode=ANY with no conditions will never match.`
  - `Note: mode=NONE with no conditions matches every request.`
- The export integration test (D-15) should include a "three policies,
  one per mode" fixture and assert the serialized JSON contains
  `"mode":"ALL"`, `"mode":"ANY"`, and `"mode":"NONE"` verbatim — that
  proves milestone criterion 3 end-to-end.
- The live UAT (Phase 18 UAT Test 7) already proved POST/PUT/GET
  round-trip for mode. Phase 19's integration test adds the missing
  leg: POST three modes, evaluate each, assert decision differs. This
  is the "integration test" the milestone asks for.
- The import-confirm screen already shows a per-policy diff; if two
  policies differ only in `mode`, they look identical today in the
  diff view (because the diff is rendered from fields excluding
  `version`/`updated_at`). Planner should verify the diff renderer
  reads `mode` too, otherwise admins may not notice a mode change
  during import. This is a small UX polish, not a milestone-criterion
  item.

</specifics>

<deferred>
## Deferred Ideas

- **Nested boolean trees** (AND-of-ORs, etc.) — explicitly out of
  milestone scope per PROJECT.md. Flat top-level mode only.
- **Mode-aware conflict diff on import** — currently the
  ImportConfirm screen shows per-field diffs; D-13 folds mode diffs
  into the existing "overwrite or skip" choice without highlighting
  them. A dedicated mode-changed warning row could be added later
  if user feedback warrants.
- **Expanded operators** (`gt`, `lt`, `ne`, `contains`) — Phase 20.
- **In-place condition editing** — Phase 21.
- **Validation errors (block submit on `mode=ANY && conditions=[]`)**
  — considered and rejected (Area 3 option C). Advisory hint per
  D-04 is the chosen middle ground. Revisit if operational feedback
  shows the iterator semantics surprise users in practice.
- **Export format version number / schema header** — the current
  export is a bare `Vec<PolicyResponse>`; a future milestone could
  add a wrapper object with `{ "version": "0.5.0", "policies": [...] }`
  for forward-compat. Not needed for Phase 19.

</deferred>

---

*Phase: 19-boolean-mode-tui-import-export*
*Context gathered: 2026-04-20*
