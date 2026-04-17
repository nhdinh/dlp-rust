# Phase 16: Policy List + Simulate - Context

**Gathered:** 2026-04-17
**Status:** Ready for planning

<domain>
## Phase Boundary

Deliver two admin-TUI capabilities on top of the Phase 14/15 policy CRUD flow:

1. **PolicyList polish (POLICY-01):** Reshape the existing `Screen::PolicyList`
   to match ROADMAP §1 — columns `Priority / Name / Action / Enabled`, sorted
   client-side by priority ascending (name tiebreak), and wire the missing `n`
   key to transition to `Screen::PolicyCreate`. Footer hints become
   `n: new | e: edit | d: delete | Enter: view | Esc: back`.

2. **Policy Simulate (POLICY-06):** Add a brand-new `Screen::PolicySimulate`
   that fills an `EvaluateRequest` (Subject / Resource / Environment / Action),
   POSTs to `/evaluate` on the server's unauthenticated public route, and
   renders the `EvaluateResponse` (`matched_policy_id`, `decision`, `reason`)
   inline below the submit row. Network and server errors render in the same
   inline region as red text (no silent drops, no status-bar-only error
   reporting). Reachable from both `MainMenu` and `PolicyMenu`.

No server-side work is required — `POST /evaluate` is already live in
`dlp-server::admin_api::public_routes` (unauthenticated). PolicyStore cache
refresh is unchanged.

</domain>

<decisions>
## Implementation Decisions

### PolicyList — Column Schema
- **D-01:** Column set is **exactly per ROADMAP §1**: `Priority`, `Name`,
  `Action`, `Enabled`. Drop the current `ID` and `Version` columns from the
  table. ID and version remain available in `PolicyDetail` (read-only view
  reached by Enter) for admin debugging; they are not needed on the overview
  table. This also narrows column widths so long policy names get more
  horizontal space.
- **D-02:** Column widths (target): `Priority` 15%, `Name` 45%, `Action` 20%,
  `Enabled` 20%. Percentages mirror current proportions with wider `Name`.
- **D-03:** `Action` column reads the raw JSON `action` string (e.g. `"ALLOW"`,
  `"DENY"`, `"AllowWithLog"`, `"DenyWithAlert"`) verbatim — server tolerates
  case-insensitive input per `deserialize_policy_row`, and the TUI renders
  whatever the server emits. No client-side mapping.
- **D-04:** `Enabled` column renders as `Yes` / `No` (bool → human string),
  not `true` / `false`. Matches the PolicyCreate/Edit Enabled-row rendering.
- **D-05:** Table title becomes `" Policies (N) "` where `N` is the sorted
  list length (current title format preserved).

### PolicyList — Sort
- **D-06:** Sort is done **client-side in `action_list_policies`** immediately
  after the GET deserializes. Primary key: `priority` ascending (lower first);
  secondary key: `name` case-insensitive ascending for stable ordering when
  priorities tie. Missing or unparseable `priority` values sort last (treated
  as `u32::MAX`) so malformed rows don't disrupt the head of the table.
- **D-07:** Sort happens once per GET. Key presses (Up/Down/e/d/n) never
  resort; the list is only re-sorted when a new GET lands (after create /
  edit / delete success).

### PolicyList — Key Bindings
- **D-08:** `n` key on PolicyList transitions to
  `Screen::PolicyCreate { form: PolicyFormState::default(), selected: 0, editing: false, buffer: String::new(), validation_error: None }`.
  Fresh PolicyFormState preserves `enabled: true` default (Phase 15 D-08
  carry-forward).
- **D-09:** Existing bindings unchanged: `Up`/`Down` nav, `Enter` → PolicyDetail,
  `e` → action_load_policy_for_edit, `d` → Confirm(DeletePolicy), `Esc` →
  PolicyMenu (Phase 15 D-27 hint already listed `n` but was removed as dead
  code per commit `21fab87`; Phase 16 re-introduces `n` with real dispatch).
- **D-10:** Footer hint string: `"n: new | e: edit | d: delete | Enter: view | Esc: back"`.
  Updates `draw_policy_list`'s `draw_hints` call.

### Simulate — Screen Variant & Entry Points
- **D-11:** New `Screen::PolicySimulate` variant holds the entire form state
  and the latest result:
  ```
  PolicySimulate {
      form: SimulateFormState,        // field values
      selected: usize,                 // current editable row index
      editing: bool,                   // text-field edit mode
      buffer: String,                  // edit-mode buffer
      result: SimulateOutcome,         // None | Success(EvaluateResponse) | Error(String)
      caller: SimulateCaller,          // MainMenu | PolicyMenu — for Esc return
  }
  ```
  The `caller` field captures which menu opened the screen so Esc returns to
  the correct parent (MainMenu keeps `selected` at the Simulate row;
  PolicyMenu keeps `selected` at its Simulate row). `SimulateOutcome` and
  `SimulateCaller` are new enums.
- **D-12:** **Two entry points** (per user choice "Both entry points"):
  - `MainMenu` gets a new `Simulate Policy` entry, peer of
    Password / Policy / System.
  - `PolicyMenu` gets a new `Simulate Policy` entry alongside its existing
    items (List / Create / Import / Export).
  Both transition to `Screen::PolicySimulate` with the appropriate `caller`
  value. No shared code path beyond `action_open_simulate(app, caller)`.
- **D-13:** Screen variant name: `Screen::PolicySimulate` (not `Simulate`
  or `EvaluateRequest`) — preserves the `Policy*` prefix convention used by
  PolicyList / PolicyCreate / PolicyEdit / PolicyDetail.
- **D-14:** Esc from `Screen::PolicySimulate` (while not editing) returns to
  the screen indicated by `caller`. Esc while editing cancels the buffer
  edit (Phase 14 D-22 pattern carry-forward). `Q` key treated as Esc
  (Phase 15 D-23 carry-forward).

### Simulate — Form Layout
- **D-15:** Form uses a **single linear row list with non-selectable section
  header rows** (SiemConfig / AlertConfig row-nav pattern with section headers
  added). Section headers are rendered inline between field groups and are
  skipped by Up/Down navigation — the `selected: usize` index only counts
  editable rows.
- **D-16:** Row order (editable index → field):
  ```
  --- Subject ---
   0: User SID            (text)
   1: User Name           (text)
   2: Groups              (text, comma-separated SIDs)
   3: Device Trust        (select: Managed / Unmanaged / Compliant / Unknown)
   4: Network Location    (select: Corporate / CorporateVpn / Guest / Unknown)
  --- Resource ---
   5: Path                (text)
   6: Classification      (select: T1 / T2 / T3 / T4)
  --- Environment ---
   7: Action              (select: READ / WRITE / COPY / DELETE / MOVE / PASTE)
   8: Access Context      (select: Local / Smb)
  --- Submit ---
   9: [Simulate]
  ```
  Section-header rows are visual separators only; `selected` ranges 0..=9.
  No ID or `[Back]` row — Esc alone returns to caller (matches PolicyCreate).
- **D-17:** **Hidden / auto-defaulted fields (not rendered):**
  `environment.timestamp` auto-set to `chrono::Utc::now()` at submit time.
  `environment.session_id` auto-set to `0`. `EvaluateRequest.agent` left as
  `None` (TUI is not an agent endpoint). Matches ROADMAP §2 field list
  (which omits timestamp / session_id / agent).

### Simulate — Field Semantics & Defaults
- **D-18:** `SimulateFormState::default()` matches `EvaluateRequest::default()`
  conventions:
  - `user_sid: ""` / `user_name: ""` / `groups_raw: ""` (raw input buffer,
    split on submit)
  - `device_trust: 1` (index into `[Managed, Unmanaged, Compliant, Unknown]`
    → default `Unmanaged`, matches `DeviceTrust::default()`)
  - `network_location: 3` (index → default `Unknown`, matches
    `NetworkLocation::default()`)
  - `path: ""` / `classification: 0` (T1, matches `Classification::default()`)
  - `action: 0` (READ, matches `Action::default()`)
  - `access_context: 0` (Local, matches `AccessContext::default()`)
  Defaults chosen for zero-friction first-open — admin can `[Simulate]`
  immediately and see a default-deny outcome against the policy set.
- **D-19:** Select rows (`device_trust`, `network_location`, `classification`,
  `action`, `access_context`) use **Enter-cycles-value** pattern: Enter
  advances to the next option and wraps at the end. No dropdown overlay. No
  Left/Right cycling. Up/Down remains row navigation only. Mirrors
  PolicyCreate Action row (Phase 14) so no new UX pattern is introduced.
- **D-20:** `Groups` row is a **single comma-separated text field**
  (label: `Groups (comma-separated SIDs):`). On `[Simulate]` submit:
  split by `,`, trim each segment of surrounding whitespace, drop empty
  segments, collect into `Vec<String>`. Example: `"S-1-5-21-a, S-1-5-21-b"`
  → `vec!["S-1-5-21-a", "S-1-5-21-b"]`. Matches ROADMAP §2 wording verbatim.
  The `groups_raw` buffer is preserved (not re-joined) across edits so the
  admin's formatting survives re-editing.
- **D-21:** Text fields use the established edit-mode pattern: Enter opens
  edit mode, buffer captures keystrokes, Enter commits, Esc cancels. Cursor
  convention `[{buffer}_]` per Phase 14 UI-SPEC.

### Simulate — Submit Flow
- **D-22:** Submit key: `Enter` on the `[Simulate]` row (row 9) fires
  `action_submit_simulate(app)`. No separate hotkey.
- **D-23:** `action_submit_simulate`:
  1. Build `EvaluateRequest` from `SimulateFormState`: splice
     `groups_raw` into `Vec<String>` per D-20, map select indices to
     typed enums, set `timestamp = chrono::Utc::now()`, `session_id = 0`,
     `agent = None`.
  2. `app.rt.block_on(app.client.post::<EvaluateResponse>("evaluate", &req))` —
     uses existing `EngineClient::post` generic. The `/evaluate` route is
     unauthenticated on the server, but sending the bearer header is
     harmless (server ignores it on public routes). No new client method.
  3. On success → `result = SimulateOutcome::Success(response)`.
  4. On error → `result = SimulateOutcome::Error(descriptive_string)` where
     the string is prefixed with `"Network error: "` for transport failures
     and `"Server error: "` for 4xx/5xx (matches Phase 14/15 D-20 copy
     contract).
  5. `selected` stays at row 9 so admin can immediately re-submit or adjust
     fields.
- **D-24:** **No client-side validation.** Empty `user_sid` / `path` /
  `groups` are permitted — the server handles `EvaluateRequest::default()`
  gracefully and the ABAC engine produces a default-deny response for an
  empty subject. This keeps the simulate path maximally useful for poking
  at policy behavior with minimal input. ROADMAP §4 only requires error
  display on network / server failures, not client pre-validation.

### Simulate — Result & Error Rendering
- **D-25:** Result renders **inline below the `[Simulate]` row** as a
  bordered `Paragraph` block. Same visual region serves both success and
  error via `SimulateOutcome`:
  - `None` — block not rendered (form only).
  - `Success(EvaluateResponse)` — three lines:
    ```
    Matched policy:  {id or 'none'}
    Decision:        {DECISION}           <- colored
    Reason:          {reason}
    ```
    Decision line colored by `Decision::is_denied()`:
    `Color::Red` for `DENY` / `DenyWithAlert`, `Color::Green` for `ALLOW` /
    `AllowWithLog`. Other lines use default foreground.
  - `Error(msg)` — single-line red `Paragraph`: `msg` rendered in
    `Color::Red`. Border title `" Error "` vs `" Result "` for Success.
  This is the same inline-region pattern Phase 14 used for
  `validation_error: Option<String>`, extended to an outcome enum so one
  region hosts both states.
- **D-26:** Clearing: result persists across field edits. It is **only
  overwritten by the next `[Simulate]` submit**. A successful submit replaces
  the previous Success or Error; a failed submit replaces with a new Error
  (stale Success is discarded — no mixing). This lets admins iterate on
  fields while the most recent decision stays visible for reference.
- **D-27:** No status-bar use for simulate outcomes. `StatusKind::Error`
  and `StatusKind::Success` are reserved for other operations. Per ROADMAP
  §4: errors appear in the simulate form, not silently or status-bar-only.

### Simulate — Keyboard Summary
- `Up` / `Down`: row navigation (skips section headers)
- `Enter` on text row (0, 1, 2, 5): enter edit mode
- `Enter` on select row (3, 4, 6, 7, 8): cycle value
- `Enter` on `[Simulate]` row (9): submit
- `Enter` while editing: commit buffer to field
- `Esc` while editing: cancel edit, restore prior value
- `Esc` while not editing: return to caller (MainMenu or PolicyMenu)
- `Q` while not editing: same as Esc

### Claude's Discretion
- Exact label column width for the simulate form (planner picks to match
  Phase 14 UI-SPEC's 22-char label column for visual consistency).
- Exact spacing / separators used by section-header rows (planner chooses
  between a dim `---` line, a bold label with empty line, or a Block::title
  wrapping each section).
- Whether the Select-row cycle handler is a single generic helper
  (`cycle_select(options_len, index)`) or per-field helpers (planner decides
  based on code-reuse calculus — generic is preferred since 5 select rows
  exist).
- Whether `action_open_simulate` is one function parameterized by
  `SimulateCaller`, or two (`action_open_simulate_from_main` /
  `_from_policy`) — trivial naming, planner's call.
- Whether `SimulateFormState` lives in `app.rs` alongside `PolicyFormState`,
  or in a new `simulate.rs` module — planner decides based on file-size.

### Folded Todos
None — no matching pending todos for Phase 16 scope.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Core Types
- `dlp-common/src/abac.rs` §167–§189 — `EvaluateRequest`, `EvaluateResponse`
  (authoritative request/response schemas)
- `dlp-common/src/abac.rs` §114–§150 — `Subject`, `Resource`, `Environment`,
  `Action`, `AccessContext`, `DeviceTrust`, `NetworkLocation` (field types
  and serde conventions — PascalCase for DeviceTrust/NetworkLocation,
  lowercase for AccessContext)
- `dlp-common/src/abac.rs` §48–§82 — `Decision` enum (authoritative variant
  spellings including `DenyWithAlert`, `AllowWithLog`); `is_denied()`
  used for red/green coloring of the Decision line
- `dlp-common/src/lib.rs` — `Classification` enum (T1–T4)
- `dlp-admin-cli/src/app.rs` §155–§314 — `Screen` enum (extend with
  `PolicySimulate`); `PolicyFormState`, `ACTION_OPTIONS`, `StatusKind`
- `dlp-admin-cli/src/client.rs` §82–§179 — `EngineClient` public-route
  usage; `post` generic for JSON round-trip

### Server-Side (No Changes)
- `dlp-server/src/admin_api.rs` §44 — `evaluate_handler` (already live)
- `dlp-server/src/admin_api.rs` §392–§395 — `public_routes` mount point
  for `POST /evaluate` (unauthenticated)
- `dlp-server/src/policy_store.rs` §99 — `PolicyStore::evaluate` (the
  backing implementation); default-deny semantics for empty requests

### Phase 14/15 Templates (Copy-and-Adapt)
- `dlp-admin-cli/src/screens/dispatch.rs` §393–§434 — `handle_policy_list`
  (extend with `Char('n')` branch; re-add `n` hint dispatch)
- `dlp-admin-cli/src/screens/dispatch.rs` §458–§500 — `action_list_policies`
  (inject client-side sort after deserialization; priority asc, name
  tiebreak)
- `dlp-admin-cli/src/screens/dispatch.rs` §1100–§1300 — `handle_policy_create`
  functions: row-nav, edit-mode, select-cycle patterns to clone for
  `handle_policy_simulate` / `handle_policy_simulate_editing` /
  `handle_policy_simulate_nav`
- `dlp-admin-cli/src/screens/render.rs` §1137–§1192 — `draw_policy_list`
  (rewrite columns per D-01–D-05; update hints per D-10)
- `dlp-admin-cli/src/screens/render.rs` (policy-create render) — template
  for multi-row form with section headers + validation-error paragraph
  pattern (extend to `SimulateOutcome` block rendering)

### Requirements & Roadmap
- `.planning/REQUIREMENTS.md` § POLICY-01 — policy list scope
  (columns, inline n/e/d hints, priority-asc sort)
- `.planning/REQUIREMENTS.md` § POLICY-06 — simulate scope (Subject /
  Resource / Environment fields, POST /evaluate, response display,
  error surfacing)
- `.planning/ROADMAP.md` § Phase 16 — 5 authoritative success criteria

### Prior Phase Contracts
- `.planning/phases/13-conditions-builder/13-CONTEXT.md` — TUI pattern
  language (Screen enum + handle_*/draw_* pairs, ListState navigation,
  Esc discipline)
- `.planning/phases/14-policy-create/14-UI-SPEC.md` — **authoritative**
  form design contract: color/spacing/highlight style, cursor convention
  `[{buffer}_]`, validation-error paragraph in `Color::Red`. Extends
  to `SimulateOutcome` inline block.
- `.planning/phases/15-policy-edit-delete/15-CONTEXT.md` §D-07 —
  select-row Enter-cycles-value pattern (Action / Enabled rows); §D-27 —
  PolicyList hints include `n` (now wired for real in Phase 16)

### State
- `.planning/STATE.md` § Decisions — `PolicyStore uses parking_lot::RwLock`
  (no impact on simulate; evaluate path is read-only against the store);
  `Wave 3: evaluate_handler in public_routes` (public route, no JWT
  required); `AD client channel-based async` (AD groups still resolved
  server-side during evaluate — TUI supplies raw SIDs via `groups`
  field without hitting LDAP itself)
- `.planning/STATE.md` § Patterns — `TUI screens: ratatui + crossterm;
  generic get::<serde_json::Value> HTTP client pattern`; generic `post`
  used the same way for typed requests

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`EvaluateRequest` / `EvaluateResponse`** already defined in `dlp-common::abac`
  with full serde round-trip tested (§300–§330 round-trip test). The TUI can
  import and use them directly — no new wire types.
- **`EngineClient::post<T>`** already handles JSON body + typed response
  deserialization. Simulate reuses it verbatim: the bearer-token header is
  sent but harmless on the unauthenticated `/evaluate` route.
- **`Screen::PolicyList`** (app.rs §166) already holds `policies` + `selected`
  — Phase 16 only changes column rendering, sort, and `n` dispatch.
- **`handle_policy_list`** (dispatch.rs §393) already has `e`/`d` dispatch
  (Phase 15) — Phase 16 adds `Char('n')` branch in-line.
- **Footer hints mechanism** (`draw_hints` in render.rs §1186) already
  accepts a free-form hint string. One-line change per D-10.
- **Edit-mode / row-nav scaffolding** from PolicyCreate (Phase 14) is
  directly copy-adaptable. The simulate form is structurally a smaller
  variant of PolicyCreate (no conditions, more selects, a Simulate button
  instead of Submit).
- **Section-header rendering** pattern does NOT exist in the codebase today.
  Planner introduces it: likely a `List` of `ListItem`s where non-selectable
  rows carry a distinctive style (dim + bold) and the nav helper (`nav`)
  maps `selected` through a "skip headers" index mapper.
- **`Decision::is_denied()`** (abac.rs §67) already provides the red/green
  coloring discriminant for the Decision line in the result block.
- **`nav` helper** in dispatch.rs (used by `handle_policy_list` line 401)
  is generic for wrap-around Up/Down. Can be reused for simulate row nav
  after a header-skip mapping is applied.

### Established Patterns to Follow
- **Screen + dispatch + render triplet**: new variant requires matching
  `handle_policy_simulate` branch in `handle_event` (dispatch.rs §23-§40)
  and `draw_screen` (render.rs §82+) match arm.
- **Validation-error-region pattern** (Phase 14): `Option<T>` on the Screen
  variant, rendered below the submit row in `Color::Red` when `Some`.
  Phase 16 generalizes to `SimulateOutcome` enum (None / Success / Error)
  hosted in the same screen variant.
- **Select-row Enter cycles** (Phase 14 Action row, Phase 15 Enabled row):
  `form.field = (form.field + 1) % N`. Generic helper candidate.
- **Client-side sort on GET**: this is a new pattern — existing code passes
  server-returned order through. Phase 16 sorts inside
  `action_list_policies` before constructing `Screen::PolicyList`.
- **Menu additions**: `MainMenu` entry list and `PolicyMenu` entry list live
  in `render.rs` (menu draw functions) and `dispatch.rs` (menu Enter
  handlers). Both need one new row each.

### Integration Points
- `Screen` enum (`app.rs`): add `PolicySimulate { form, selected, editing, buffer, result, caller }`
- `SimulateFormState` struct (`app.rs` or new `simulate.rs`): all form
  field values including `groups_raw: String` (not `Vec<String>`)
- `SimulateOutcome` enum (`app.rs`): `None | Success(EvaluateResponse) | Error(String)`
- `SimulateCaller` enum (`app.rs`): `MainMenu | PolicyMenu`
- `handle_event` dispatch (`dispatch.rs`): add match arm for
  `Screen::PolicySimulate { .. }` → `handle_policy_simulate`
- `handle_main_menu` and `handle_policy_menu` (`dispatch.rs`): add new
  Enter branch mapping to `action_open_simulate(app, caller)`
- `action_list_policies` (`dispatch.rs`): inject client-side sort on the
  deserialized Vec before setting `Screen::PolicyList`
- `handle_policy_list` (`dispatch.rs`): add `Char('n')` branch
- `draw_policy_list` (`render.rs`): rewrite Row builder (D-03, D-04);
  rewrite widths; rewrite hint
- `draw_screen` (`render.rs`): add match arm for `Screen::PolicySimulate`
  → `draw_policy_simulate`
- `draw_policy_simulate` (`render.rs`, new): renders the multi-row form
  with section headers + inline result/error block
- `draw_main_menu` and `draw_policy_menu` (`render.rs`): add new row
  per menu

### What Does NOT Change
- Server code (`admin_api.rs`, `policy_store.rs`): `/evaluate` already live
- `EngineClient` (`client.rs`): no new methods; `post` generic is sufficient
- `Screen::PolicyDetail`: unchanged (still shows ID / Version / raw JSON)
- Existing policy CRUD dispatch (`handle_policy_create` / `handle_policy_edit`
  / `handle_confirm` for DeletePolicy): unchanged
- Conditions builder modal: unchanged; not invoked from simulate
- AD client / LDAP: simulate supplies raw `Vec<String>` group SIDs directly;
  no AD lookup is triggered from the TUI

</code_context>

<specifics>
## Specific Ideas

- The simulate form IS structurally a "PolicyCreate with different fields and
  no conditions builder": section headers + linear row nav + submit row +
  inline outcome region. Planner should template from `handle_policy_create`
  verbatim and strip the conditions-related branches.
- For section headers, the simplest skip-nav implementation is a constant
  `SIMULATE_FIELD_ROW_INDICES: &[usize]` that lists the render-row indices
  corresponding to each editable `selected` index — the render function uses
  the full index to position rows, the dispatch function maps
  `selected: 0..=9` → render row via lookup.
- Decision coloring: use `Decision::is_denied()` (already in `abac.rs`).
  Green for `ALLOW` / `AllowWithLog`, red for `DENY` / `DenyWithAlert`.
  Reason line uses default foreground in all cases.
- The table-widths change in `draw_policy_list` lifts the bottleneck where
  long names are truncated. Target widths: `Priority` 15%, `Name` 45%,
  `Action` 20%, `Enabled` 20%. Header strings: `"Priority"`, `"Name"`,
  `"Action"`, `"Enabled"`.
- For the client-side sort: parse `priority` via
  `p["priority"].as_u64().unwrap_or(u64::MAX) as u32` so malformed rows
  sink to the bottom without panicking.
- For the `n` binding on PolicyList: reuse the same transition path that
  `PolicyMenu` → "Create" menu row takes today. That code path already
  initializes `PolicyFormState::default()` correctly.
- `SimulateCaller` captures the return destination so the dual entry point
  is handled without duplicating screen state. When Esc is pressed,
  `caller` drives the next screen assignment (`MainMenu { selected: IDX }`
  or `PolicyMenu { selected: IDX }`).
- A first-time admin opening Simulate and pressing `[Simulate]` immediately
  should see a sensible default-deny outcome (empty Subject + Local Access
  against an existing policy set). This "zero-friction" behavior is why
  D-18 picks defaults aligned with `EvaluateRequest::default()`.

</specifics>

<deferred>
## Deferred Ideas

- **Simulate-from-PolicyList shortcut** (`s` key on a selected row to
  pre-fill the Simulate form with that policy's first condition as a
  starting point). Out of Phase 16 scope per ROADMAP §5 ("independent of
  the policy list"). Candidate for v0.5.0 polish.
- **History of simulate runs** — keep the last N `EvaluateResponse`s in a
  scrollable log within the form. Nice for iterative policy tuning. Not
  in ROADMAP; defer to v0.5.0.
- **Dropdown-style select overlays** for the 5 select rows. Would improve
  discoverability for admins unfamiliar with "Enter cycles" UX. Rejected
  for Phase 16 to match existing form patterns.
- **Per-SID group list** with Add/Remove buttons instead of
  comma-separated text. Rejected because SIDs never contain commas and the
  single-text-field option matches ROADMAP §2 wording verbatim. Could be
  reconsidered if admins complain about long SID lists being hard to read.
- **Timestamp / session_id exposure** on the form for time-based or
  session-scoped policy testing. Rejected because current ABAC policies do
  not use timestamp or session_id in conditions; exposing them would be
  dead input.
- **Dirty-tracking Esc confirm** ("Discard unsaved simulate form?") —
  same rejection rationale as Phase 15: redoable, low cost, not worth
  dispatch complexity.

### Reviewed Todos (not folded)
None — no matching pending todos surfaced for Phase 16 scope.

</deferred>

---

*Phase: 16-policy-list-simulate*
*Context gathered: 2026-04-17*
