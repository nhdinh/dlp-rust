# Phase 19: Boolean Mode in TUI + Import/Export - Research

**Researched:** 2026-04-20
**Domain:** Rust TUI (ratatui/crossterm) form extension + server-side integration testing
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Mode Picker UX**
- **D-01:** Cycle-on-Enter/Space (same pattern as `Enabled` bool toggle and `Action` enum cycler). No new modal, no horizontal navigation keys, no popup overlay.
- **D-02:** Mode row sits between `Enabled` and `[Add Conditions]`. Post-change `POLICY_FIELD_LABELS` becomes 9 rows: `Name, Description, Priority, Action, Enabled, Mode, [Add Conditions], Conditions, [Submit]`.
- **D-03:** Default on Create is `PolicyMode::ALL`. Pre-fill on Edit is read from `PolicyResponse.mode`.
- **D-04:** Footer hint below the Conditions list when `form.mode != PolicyMode::ALL && form.conditions.is_empty()`. Recommended wording: `Note: mode=ANY with no conditions will never match.` and `Note: mode=NONE with no conditions matches every request.` Advisory only — no validation error, no block-on-submit.

**Admin-CLI Typed Structs**
- **D-05:** `PolicyPayload` gains `pub mode: PolicyMode` with `#[serde(default)]` (re-uses `dlp_common::abac::PolicyMode` from Phase 18 — no local duplicate).
- **D-06:** `PolicyResponse` gains the same field with the same annotation.
- **D-07:** `From<PolicyResponse> for PolicyPayload` copies `mode: r.mode` unchanged (`PolicyMode: Copy`).
- **D-08:** `PolicyFormState` gains `pub mode: PolicyMode`. `Default` derive already present; `PolicyMode::default() == ALL` handles it.

**Export Behavior**
- **D-09:** Export writes `mode` unconditionally on every policy (no code change to `action_export_policies`; transitive via Phase 18 server output).
- **D-10:** Milestone criterion 3 satisfied transitively by Phase 18; Phase 19 adds a round-trip assertion.

**Import Behavior**
- **D-11:** `serde_json::from_str::<Vec<PolicyResponse>>(...)` in `action_import_policies` starts honoring `mode` automatically once D-06 lands. Legacy files (no `mode`) deserialize with `mode = ALL`.
- **D-12:** No additional import validation.
- **D-13:** Conflict-resolution UI from Phase 17 unchanged. Mode differences fold into the existing "overwrite or skip" choice.

**Integration Test**
- **D-14:** New integration test at `dlp-server/tests/mode_end_to_end.rs`. Three test functions (`test_mode_all_matches_when_all_conditions_hit`, `test_mode_any_matches_when_one_condition_hits`, `test_mode_none_matches_when_no_conditions_hit`).
- **D-15:** Additional export-then-reimport round-trip test at the data layer (`PolicyPayload` serialize/deserialize).

### Claude's Discretion

- Exact wording of the footer hint messages in D-04 — tweak during implementation.
- Whether `PolicyFormState.mode` stores the enum directly or an index (like `action: usize`). Since `PolicyMode` is `Copy` and has only 3 variants, storing the enum directly is likely cleaner.
- Whether to factor out a `cycle_mode(mode: PolicyMode) -> PolicyMode` helper vs inline the three-way match. Both are fine.
- Whether the integration test file is separate or folded into `admin_audit_integration.rs`. Separate is cleaner; either works.

### Deferred Ideas (OUT OF SCOPE)

- Nested boolean trees (AND-of-ORs, etc.) — out of milestone scope.
- Mode-aware conflict diff on import — D-13 folds mode diffs into the existing "overwrite or skip" choice.
- Expanded operators (`gt`, `lt`, `ne`, `contains`) — Phase 20.
- In-place condition editing — Phase 21.
- Validation errors blocking submit on `mode=ANY && conditions=[]` — rejected (advisory hint per D-04 only).
- Export format version number / schema header — not needed for Phase 19.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| POLICY-09 | Admin can select a top-level boolean mode per policy (ALL/ANY/NONE) via the admin TUI; wire format carries it; export/import round-trips it. | This research surfaces (a) the exact row-index migration path, (b) the two stray numeric literals in render.rs that need updating, (c) the hints-bar slot for the footer advisory, (d) the integration test harness template (`admin_audit_integration.rs` in-memory pool + `oneshot()` pattern), and (e) the two missing `mode` fields in the TUI's `json!()` payloads that must be added so POST/PUT bodies round-trip the field. |
</phase_requirements>

## Summary

Phase 19 is a **contained, low-risk, mostly-additive** phase that sits on top of a mode-aware Phase 18 server. The server already persists/round-trips `mode`; the TUI just needs to author it. Five concrete deltas:

1. **Extend three structs** — `PolicyFormState`, `PolicyResponse`, `PolicyPayload` (all in `dlp-admin-cli/src/app.rs`) each gain a `mode: PolicyMode` field. `PolicyMode` already derives `Default` with `ALL` as `#[default]`, `Copy`, and `Serialize`/`Deserialize`, so `#[serde(default)]` handles legacy-file tolerance automatically.
2. **Add one row to the form** (both Create and Edit). The row-index migration is **smaller than CONTEXT.md suggests** — the dispatch-side row indices are already named constants (`POLICY_*_ROW` at dispatch.rs §874-887), so adding `POLICY_MODE_ROW = 5` and renumbering the trailing three constants is a 5-line change. **The real stray-literal risk lives in render.rs**: `draw_policy_create` (lines 816-898) and `draw_policy_edit` (lines 975-1047) both use `match i { 0 => ..., 1 => ..., ... 7 => ... }` with hardcoded numeric literals for the 8 existing rows, plus `selected == 0/1/2` literals for edit-mode highlighting, and the arrays have hardcoded length `8`. These must be renumbered atomically to avoid mis-labeled fields.
3. **Add two stray `selected > 2` guards** (dispatch.rs §1245, §1538) — these are fine as-is because Name/Desc/Priority stay at rows 0,1,2, but they should be migrated to `selected > POLICY_PRIORITY_ROW` for consistency with the rest of the file.
4. **Add `mode` to two `serde_json::json!()` payloads** in `action_submit_policy` (dispatch.rs §1321-1333) and `action_submit_policy_update` (§1610-1622). **These two omissions are the actual bug that Phase 19 fixes** — right now the TUI sends POST/PUT bodies without `mode`, relying on the server's `#[serde(default)]` to fill in `ALL`. This means mode is effectively unauthorable from the TUI today even with the server accepting it.
5. **One new integration test file** (`dlp-server/tests/mode_end_to_end.rs`) using the `admin_audit_integration.rs` template verbatim (in-memory pool + `admin_router()` + JWT mint + `tower::ServiceExt::oneshot`).

**Primary recommendation:** Split into two waves. Wave 1 = struct/wire changes (D-05 through D-08) + the two JSON-payload bug fixes — ships the invisible-but-critical wire-format completion. Wave 2 = TUI row addition + footer hint + integration tests. Wave 1 can be verified by unit tests alone; Wave 2 benefits from UAT.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Mode form authoring (Create/Edit UX) | TUI client (dlp-admin-cli) | — | Pure keyboard/rendering concern; no server change |
| Mode round-trip on wire | TUI client structs + HTTP payload | API (dlp-server) | Server already accepts; TUI must author into POST/PUT body |
| Mode persistence & evaluation | API / DB | — | Already shipped in Phase 18 (no change) |
| Mode round-trip on export/import | TUI client (via `PolicyResponse`/`PolicyPayload`) | API (passes through) | `#[serde(default)]` on admin-cli structs handles legacy-file tolerance |
| Empty-conditions advisory hint | TUI rendering | — | Pure presentation; server-side D-13 (Phase 18) explicitly allows the wire state |
| E2E decision verification | Server integration test | — | Tests the mode-aware evaluator through the HTTP boundary |

## Standard Stack

### Core (already present in workspace)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| ratatui | 0.29 | TUI widgets + Frame API used by all existing forms | [VERIFIED: dlp-admin-cli/Cargo.toml:17] Already the project's TUI foundation |
| crossterm | 0.28 | Keyboard event source (`KeyCode`, `KeyEvent`) | [VERIFIED: dlp-admin-cli/Cargo.toml:18] Already the project's input layer |
| serde | 1.x (workspace) | `#[derive(Serialize, Deserialize)]` on `PolicyMode`, `PolicyFormState`, `PolicyPayload` | [VERIFIED: Cargo.toml:14] Workspace-level dep |
| serde_json | 1.x (workspace) | `serde_json::json!()` macro for POST/PUT bodies, `to_string_pretty` for export | [VERIFIED: Cargo.toml:15] Already used everywhere |
| dlp_common::abac::PolicyMode | local | The enum gets re-exported into admin-cli | [VERIFIED: dlp-common/src/abac.rs:249-268] Shipped in Phase 18 |

### Supporting (already present — for integration test)

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| axum | 0.8 | `admin_router()` service under test | In `tests/mode_end_to_end.rs` |
| axum::body::Body | (via axum 0.8) | Request body wrapping | `Request::builder().body(Body::from(...))` |
| http | 1.x | `Request`, `StatusCode` | Request construction in test |
| tower::ServiceExt | 0.4 | `.oneshot(req)` service-call pattern | [VERIFIED: admin_audit_integration.rs:25] Existing pattern |
| tempfile::NamedTempFile | 3.x | In-memory SQLite DB for test `new_pool` | [VERIFIED: admin_audit_integration.rs:24] Existing pattern |
| jsonwebtoken | 9.x | `mint_jwt` helper reused verbatim | [VERIFIED: dlp-server/Cargo.toml:35] Existing pattern |
| bcrypt | 0.16 | `seed_admin_user` helper (needed for protected `/admin/policies`) | [VERIFIED: dlp-server/Cargo.toml:36] Existing pattern |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Separate test file `mode_end_to_end.rs` | Add to `admin_audit_integration.rs` | Separate file is cleaner; no test-harness duplication needed — both files use identical helpers. Planner picks (D-14 leans separate). |
| `PolicyFormState.mode: PolicyMode` | `PolicyFormState.mode: usize` (index like `action`) | Direct enum is cleaner for a 3-variant `Copy` enum; index is only warranted when the display labels come from an array (`ACTION_OPTIONS`). Direct enum wins here. |
| Inline three-way match in dispatch | `fn cycle_mode(m: PolicyMode) -> PolicyMode` helper | Tradeoff is 3 lines vs 1 call-site; helper wins if used in both Create and Edit (which it is). |

**Installation:** No new dependencies needed. All crates above are already in the workspace.

**Version verification:** Not applicable — no new crate adds.

## Architecture Patterns

### System Architecture Diagram

```
Admin User (keyboard)
        |
        v
  crossterm KeyEvent
        |
        v
  handle_policy_create / handle_policy_edit         <- (dispatch.rs)
        |                   |
   (text field edit)   (enum cycler on MODE row)    <- NEW in Phase 19
        |                   |
        v                   v
  PolicyFormState.name / .mode  (in-memory)         <- NEW field: mode
        |
    (Enter on Submit/Save)
        |
        v
  action_submit_policy / action_submit_policy_update
        |
        v
  serde_json::json!({ ..., "mode": form.mode, ... }) <- NEW JSON key
        |
        v
  POST/PUT /admin/policies (HTTP)
        |
        v
  dlp-server admin_api::create_policy / update_policy  <- unchanged (Phase 18)
        |
        v
  policies.mode column (SQLite)                        <- unchanged (Phase 18)
        |
        v
  PolicyStore::evaluate (match policy.mode)            <- unchanged (Phase 18)

--- Export path ---

  Action "Export Policies..." -> action_export_policies (dispatch.rs §2918)
        -> GET /policies -> Vec<serde_json::Value> -> to_string_pretty -> rfd save dialog
           (mode field present in server response; passes through untouched)

--- Import path ---

  Action "Import Policies..." -> action_import_policies (dispatch.rs §2984)
        -> rfd open dialog -> serde_json::from_str::<Vec<PolicyResponse>>
        -> (NEW: PolicyResponse has mode field with #[serde(default)])
        -> ImportConfirm screen -> [Confirm] -> POST/PUT per policy via PolicyPayload
        -> (NEW: PolicyPayload has mode field; From impl copies it)
```

### Recommended Project Structure

No new files in `dlp-admin-cli` — all changes land in existing files (`app.rs`, `screens/dispatch.rs`, `screens/render.rs`). One new file in `dlp-server/tests/mode_end_to_end.rs`.

### Pattern 1: Named row-index constants

**What:** Declare one `const POLICY_*_ROW: usize = N` per form row, plus `POLICY_ROW_COUNT`. Use those constants in `match selected { POLICY_SAVE_ROW => ... }` instead of bare numeric literals.

**When to use:** Any ratatui list form where rows are selectable.

**Example (existing, from dispatch.rs §874-887):**
```rust
// Source: dlp-admin-cli/src/screens/dispatch.rs §874-887
const POLICY_NAME_ROW: usize = 0;
const POLICY_DESC_ROW: usize = 1;
const POLICY_PRIORITY_ROW: usize = 2;
const POLICY_ACTION_ROW: usize = 3;
const POLICY_ENABLED_ROW: usize = 4;
const POLICY_ADD_CONDITIONS_ROW: usize = 5;
const POLICY_CONDITIONS_DISPLAY_ROW: usize = 6;
const POLICY_SAVE_ROW: usize = 7;
const POLICY_ROW_COUNT: usize = 8;
```

**Migration for Phase 19:**
```rust
const POLICY_NAME_ROW: usize = 0;
const POLICY_DESC_ROW: usize = 1;
const POLICY_PRIORITY_ROW: usize = 2;
const POLICY_ACTION_ROW: usize = 3;
const POLICY_ENABLED_ROW: usize = 4;
const POLICY_MODE_ROW: usize = 5;                   // NEW
const POLICY_ADD_CONDITIONS_ROW: usize = 6;         // was 5
const POLICY_CONDITIONS_DISPLAY_ROW: usize = 7;     // was 6
const POLICY_SAVE_ROW: usize = 8;                   // was 7
const POLICY_ROW_COUNT: usize = 9;                  // was 8
```

### Pattern 2: Enter-cycle for enum fields on the form

**What:** Store the enum (or its index) on `PolicyFormState`. On `Enter` while the row is focused, rotate to the next variant and stay in navigation mode. No edit-buffer, no modal.

**When to use:** Any small enum with 2-5 variants.

**Example (existing `Action` pattern, from dispatch.rs §1232-1237):**
```rust
// Source: dlp-admin-cli/src/screens/dispatch.rs §1232-1237
POLICY_ACTION_ROW => {
    if let Screen::PolicyCreate { form, .. } = &mut app.screen {
        form.action = (form.action + 1) % ACTION_OPTIONS.len();
    }
}
```

**For Mode (Phase 19, recommended direct-enum variant):**
```rust
POLICY_MODE_ROW => {
    if let Screen::PolicyCreate { form, .. } = &mut app.screen {
        form.mode = match form.mode {
            PolicyMode::ALL => PolicyMode::ANY,
            PolicyMode::ANY => PolicyMode::NONE,
            PolicyMode::NONE => PolicyMode::ALL,
        };
    }
}
```

### Pattern 3: Footer hint as `draw_hints` replacement

**What:** The PolicyCreate/PolicyEdit forms render a 1-row hints bar at the bottom of the form's `area` via `draw_hints(frame, area, "...")` (render.rs §937-943 / §1082-1087). The D-04 advisory should slot in as an *additional* 1-row paragraph **above** the hints bar, OR be inlined into the hints string. Cleaner approach: add a 1-row paragraph above the existing hints bar so the navigation key hints stay visible.

**Slot location (render.rs):**
```rust
// draw_policy_create: just before line 937 (the draw_hints call)
if form.mode != PolicyMode::ALL && form.conditions.is_empty() {
    let hint = match form.mode {
        PolicyMode::ANY => "Note: mode=ANY with no conditions will never match.",
        PolicyMode::NONE => "Note: mode=NONE with no conditions matches every request.",
        PolicyMode::ALL => "",  // unreachable given guard, but exhaustive match
    };
    // Position: area.y + area.height - 2 (one row above hints bar).
    // Reuse the validation_error overlay pattern at lines 922-934.
}
```

The existing `validation_error` overlay (render.rs §922-935) is a direct template: it already renders a 1-row `Paragraph` at `area.y + area.height - 2`. The advisory hint can use the identical pattern but in a different color (e.g., `Color::DarkGray` or `Color::Yellow`) to distinguish it from errors. **Caveat:** the advisory and validation_error share the same row slot — the advisory should NOT render when validation_error is present (show errors first).

### Pattern 4: Integration test harness reuse

**What:** Build a standalone axum `Router` via `admin_router(Arc<AppState>)`, fronted by an in-memory SQLite via `db::new_pool(tempfile_path)`. Mint a JWT via `jsonwebtoken::encode` with the shared test secret. Fire requests via `tower::ServiceExt::oneshot`. All helpers exist in `admin_audit_integration.rs`.

**Example (verbatim reusable harness):**
```rust
// Source: dlp-server/tests/admin_audit_integration.rs §37-80
fn test_app() -> (axum::Router, Arc<db::Pool>) {
    set_jwt_secret(TEST_JWT_SECRET.to_string());
    let tmp = NamedTempFile::new().expect("create temp db");
    let pool = Arc::new(db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let siem = siem_connector::SiemConnector::new(Arc::clone(&pool));
    let alert = alert_router::AlertRouter::new(Arc::clone(&pool));
    let policy_store =
        Arc::new(policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"));
    let state = Arc::new(AppState {
        pool: Arc::clone(&pool),
        policy_store,
        siem,
        alert,
        ad: None,
    });
    (admin_router(state), pool)
}

fn seed_admin_user(pool: &db::Pool, username: &str, password_plain: &str) { /* bcrypt hash + INSERT */ }
fn mint_jwt(username: &str) -> String { /* jsonwebtoken::encode */ }
```

**Usage for Phase 19:**
```rust
// test_mode_any_matches_when_one_condition_hits
let (app, pool) = test_app();
seed_admin_user(&pool, "test-admin", "pw");
let jwt = mint_jwt("test-admin");

// POST /admin/policies with mode=ANY + 2 conditions
let payload = PolicyPayload {
    id: "policy-any".to_string(),
    name: "any mode test".to_string(),
    description: None,
    priority: 1,
    conditions: serde_json::json!([
        { "attribute": "classification", "op": "eq", "value": "T3" },
        { "attribute": "accesscontext",  "op": "eq", "value": "Local" }
    ]),
    action: "DENY".to_string(),
    enabled: true,
    mode: PolicyMode::ANY,
};
// ... request/response assertions
// Then POST /evaluate with a request that hits only the second condition, assert DENY + matched_policy_id
```

### Anti-Patterns to Avoid

- **Hardcoding `match i { 0 => ..., 7 => ... }` for row rendering** — render.rs already has this anti-pattern at §817-898 and §976-1047; Phase 19 must *extend* it to 9 arms, NOT perpetuate the anti-pattern with 10/11 literal arms in future phases. Best to refactor to use `match i` against the `POLICY_*_ROW` consts, but that's discretionary.
- **Storing mode as a string in `PolicyFormState`** — defeats the purpose of Phase 18's typed `PolicyMode`. Use the enum directly.
- **Blocking submit on `mode != ALL && conditions.is_empty()`** — explicitly rejected per D-12 (Phase 18) and D-04 (Phase 19). Iterator short-circuit semantics are the documented behavior.
- **Adding a separate conflict category for mode diffs during import** — D-13 explicitly folds mode diffs into the existing overwrite/skip choice. Do not render a "mode changed" warning row.
- **Using `#[serde(rename_all = "UPPERCASE")]` on `PolicyMode`** — unnecessary; `PolicyMode`'s variant names already match the wire form exactly (`ALL`/`ANY`/`NONE`). Phase 18 D-02 confirms this.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Legacy-file tolerance | Custom `Option<String>` + parse | `#[serde(default)]` on `PolicyMode` field | `PolicyMode::default() == ALL` handles it zero-code (Phase 18 D-03) |
| Row renumbering | Scatter `5`, `6`, `7` literals across dispatch.rs | Named `POLICY_*_ROW` consts (already in place at §874-887) | Dispatch code already uses consts; only render.rs needs migration |
| Integration test scaffolding | Roll new test harness | Copy `test_app()` + `mint_jwt()` from `admin_audit_integration.rs` | Identical state struct, identical auth, zero drift risk |
| Conditions-builder mode propagation | Manually copy mode on every exit path | Existing `..form_snapshot` spread (dispatch.rs §2177, §2190, §2264, §2277) | Adding the field to `PolicyFormState` makes it propagate automatically |
| HTTP client wrapper for integration test | Build a new reqwest client | `tower::ServiceExt::oneshot(req)` against `admin_router` | Existing pattern; no network, no port allocation, deterministic |

**Key insight:** Phase 19 is a **nearly-pure additive change**. The biggest design mistake would be over-engineering: e.g., introducing a `cycle_mode` free function only used in two places, or wrapping the footer advisory in a new widget struct. The existing `validation_error` overlay pattern already handles 1-row advisory rendering — reuse it.

## Runtime State Inventory

Not applicable. Phase 19 is a greenfield feature-add on top of the Phase 18 server — no rename, no refactor, no migration of existing runtime state.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — verified: `policies.mode` column already exists (Phase 18 T3/T4), default `'ALL'` applied to v0.4.0 rows | None |
| Live service config | None — no external service stores this string | None |
| OS-registered state | None — TUI is interactive, no OS-level registrations | None |
| Secrets/env vars | None — `PolicyMode` is a plain enum, no secret material | None |
| Build artifacts | None — no compiled binaries carry the field name | None |

## Common Pitfalls

### Pitfall 1: Forgetting to add `mode` to the two `json!()` macro calls

**What goes wrong:** `action_submit_policy` (dispatch.rs §1321-1333) and `action_submit_policy_update` (§1610-1622) build the POST/PUT body with an explicit `serde_json::json!({...})` literal. If the planner only wires the TUI row and the `PolicyFormState` field but forgets to add `"mode": form.mode` to the two JSON macros, the wire body silently omits `mode`. Server's `#[serde(default)]` fills in `ALL`, which *looks* fine in testing — but the authored `ANY`/`NONE` choice is dropped silently.

**Why it happens:** The two `PolicyPayload` struct definitions (in `dlp-admin-cli/src/app.rs` §262-270) are separate from the JSON macro bodies. Adding the `mode` field to the struct does NOT auto-include it in `serde_json::json!({...})`. The struct is only used for import/export; the submit path uses the macro directly.

**How to avoid:**
1. After extending `PolicyPayload`, audit every `serde_json::json!({"id": ..., "name": ..., "enabled": ...})` in `dispatch.rs`.
2. Add `"mode": form.mode` to each macro (or refactor both call sites to construct a `PolicyPayload` struct and `serde_json::to_value(&payload)?`).
3. Integration test MUST round-trip `mode=ANY` via the TUI's submit code path — not just a hand-authored `PolicyPayload`.

**Warning signs:** A test that sets `form.mode = PolicyMode::ANY`, submits, and then GETs the policy back shows `"mode": "ALL"` in the response — the default-injection masked a silent drop.

### Pitfall 2: Row-index shift in render.rs (NOT dispatch.rs)

**What goes wrong:** CONTEXT.md §246 flags the row-index renumber as the "#1 risk" and points at `dispatch.rs`. Investigation reveals dispatch.rs is **already clean** — every row is named (`POLICY_NAME_ROW` through `POLICY_SAVE_ROW`, dispatch.rs §874-887). The real migration work is in `render.rs`: both `draw_policy_create` (§817-898) and `draw_policy_edit` (§976-1047) use `match i { 0 => ..., 7 => ... }` with hardcoded numeric literals for all 8 existing rows, plus `selected == 0/1/2` literals for edit-mode highlighting, plus the array length `8` in `[&str; 8]`.

**Why it happens:** render.rs was written before the POLICY_*_ROW consts existed, and was never back-migrated. The `const POLICY_FIELD_LABELS: [&str; 8]` at render.rs §598 and its paired `match i` arms are the only part of the codebase that still hardcodes row-index integers.

**How to avoid:**
1. Change the array length to `9` and add `"Mode"` between `"Enabled"` and `"[Add Conditions]"`.
2. In `draw_policy_create` §817-898: every `N => ...` arm for N >= 5 must be renumbered `N+1 => ...`. Add a new `5 => ...` arm that renders `Mode: ALL/ANY/NONE`. Total arms go from 8 to 9.
3. In `draw_policy_edit` §976-1047: same change.
4. The `selected == 0/1/2` literals (for edit-mode highlight) at §820, §833, §846, §978, §990, §1002 are FINE — Name/Desc/Priority stay at 0/1/2.
5. Also update `Vec::with_capacity(POLICY_FIELD_LABELS.len())` at §814 (uses the const; self-healing) and the hardcoded `Vec::with_capacity(8)` at §973 (must become `9`).

**Warning signs:** After the change, pressing Up/Down from the last row wraps correctly to row 0 (POLICY_ROW_COUNT = 9), but the "Enabled" row renders the mode text, or the "Mode" row shows `(empty)` placeholder. Off-by-one in the render arms.

### Pitfall 3: `#[serde(default)]` on nested `PolicyMode` in `PolicyFormState` is NOT needed

**What goes wrong:** A reader might assume `PolicyFormState.mode` also needs `#[serde(default)]`. It doesn't — `PolicyFormState` is an in-memory UI state struct, not a wire type. Adding `#[serde(default)]` is harmless but misleading to future readers.

**Why it happens:** Copy-paste from `PolicyPayload` / `PolicyResponse`, which DO need it for legacy-file tolerance.

**How to avoid:** Only apply `#[serde(default)]` on the two wire structs (`PolicyPayload`, `PolicyResponse`). `PolicyFormState` relies on its own `#[derive(Default)]` for the default-ALL behavior.

### Pitfall 4: Import-confirm "diff renderer" does not exist

**What goes wrong:** CONTEXT.md §273-280 flags a "per-policy diff renderer" as an area of concern, suggesting mode differences may hide silently. Investigation: the `draw_import_confirm` function (render.rs §1493-1573) renders only three aggregate informational rows plus Confirm/Cancel buttons. There is **no per-field diff view at all**. So there is nothing to "make mode-aware" — the concern is moot.

**How to avoid:** Skip this as a planning task. Recording here for completeness so downstream agents don't chase a phantom.

### Pitfall 5: `Screen::PolicyEdit` has a redundant `id` field on both the screen variant and `form.id`

**What goes wrong:** `PolicyFormState.id` exists (app.rs §139) AND `Screen::PolicyEdit { id, form, ... }` has its own `id` (app.rs §436-441). The edit submit path (§1499) uses `form.id`. This isn't a bug, but the planner should be aware when writing the `load_policy_into_form` helper extension — the `mode` pre-fill must write to `form.mode`, not to any screen-variant field.

**How to avoid:** Mirror the existing pattern at §1390-1401 (the `form = PolicyFormState { ... }` literal in `action_load_policy_for_edit`) and add `mode: mode_from_str(policy["mode"].as_str()...)`.

## Code Examples

Verified patterns from this codebase:

### Adding the mode field to the admin-cli PolicyResponse

```rust
// Source: dlp-admin-cli/src/app.rs §241-255 (CURRENT)
// Modification: add mode field with #[serde(default)]
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PolicyResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    #[serde(default)]                                   // EXISTING
    pub version: i64,
    #[serde(default)]                                   // EXISTING
    pub updated_at: String,
    #[serde(default)]                                   // NEW
    pub mode: dlp_common::abac::PolicyMode,             // NEW
}
```

### Extending From<PolicyResponse> for PolicyPayload

```rust
// Source: dlp-admin-cli/src/app.rs §272-284 (CURRENT)
impl From<PolicyResponse> for PolicyPayload {
    fn from(r: PolicyResponse) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            priority: r.priority,
            conditions: r.conditions,
            action: r.action,
            enabled: r.enabled,
            mode: r.mode,   // NEW — PolicyMode is Copy, so no clone needed
        }
    }
}
```

### Adding mode to the POST body macro

```rust
// Source: dlp-admin-cli/src/screens/dispatch.rs §1321-1333 (CURRENT)
// Add a "mode" key to the json!() macro.
let mode_str = match form.mode {
    PolicyMode::ALL => "ALL",
    PolicyMode::ANY => "ANY",
    PolicyMode::NONE => "NONE",
};
let payload = serde_json::json!({
    "id": uuid::Uuid::new_v4().to_string(),
    "name": form.name.trim(),
    "description": if form.description.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(form.description.trim().to_string())
    },
    "priority": priority,
    "conditions": conditions_json,
    "action": action_str,
    "enabled": form.enabled,
    "mode": mode_str,   // NEW
});
```

Alternative (cleaner): construct a `PolicyPayload` struct and `serde_json::to_value(&payload)?` to let serde handle the stringification via `PolicyMode`'s derive. That also means the wire-format string is guaranteed to match `PolicyMode`'s `Serialize` impl — no risk of a typo in a hand-authored match. Recommended.

### Integration test shape for `test_mode_any_matches_when_one_condition_hits`

```rust
// Source: mirror dlp-server/tests/admin_audit_integration.rs §137-180
#[tokio::test]
async fn test_mode_any_matches_when_one_condition_hits() {
    let (app, pool) = test_app();
    seed_admin_user(&pool, "test-admin", "pw");
    let jwt = mint_jwt("test-admin");

    // POST /admin/policies with mode=ANY + 2 unrelated conditions.
    let payload = PolicyPayload {
        id: "policy-any".to_string(),
        name: "any mode test".to_string(),
        description: None,
        priority: 1,
        conditions: serde_json::json!([
            { "attribute": "classification", "op": "eq", "value": "T3" },
            { "attribute": "accesscontext",  "op": "eq", "value": "Smb"  }
        ]),
        action: "DENY".to_string(),
        enabled: true,
        mode: PolicyMode::ANY,
    };
    let body = serde_json::to_vec(&payload).expect("serialise");
    let req = Request::builder()
        .method("POST")
        .uri("/admin/policies")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::CREATED);

    // POST /evaluate with a request that matches ONLY the classification condition.
    let eval_body = serde_json::json!({
        "subject": {
            "user_sid": "S-1-5-21-1", "user_name": "u",
            "groups": [],
            "device_trust": "Unknown", "network_location": "Unknown"
        },
        "resource": { "path": r"C:\x.txt", "classification": "T3" },
        "environment": {
            "timestamp": "2026-04-20T00:00:00Z",
            "session_id": 1,
            "access_context": "local"   // NOT Smb -> second condition misses
        },
        "action": "READ"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/evaluate")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&eval_body).unwrap()))
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // Under ANY mode, one hit is enough -> policy matches -> DENY.
    assert_eq!(body["decision"], "DENY");
    assert_eq!(body["matched_policy_id"], "policy-any");
}
```

### Export/import round-trip test (D-15, data-layer)

```rust
#[test]
fn test_policy_payload_roundtrip_preserves_all_three_modes() {
    // Fixture: three policies, one per mode.
    let policies = vec![
        PolicyPayload { id: "p1".into(), name: "all".into(), description: None, priority: 1,
            conditions: serde_json::json!([]), action: "DENY".into(), enabled: true,
            mode: PolicyMode::ALL },
        PolicyPayload { id: "p2".into(), name: "any".into(), description: None, priority: 2,
            conditions: serde_json::json!([]), action: "DENY".into(), enabled: true,
            mode: PolicyMode::ANY },
        PolicyPayload { id: "p3".into(), name: "none".into(), description: None, priority: 3,
            conditions: serde_json::json!([]), action: "DENY".into(), enabled: true,
            mode: PolicyMode::NONE },
    ];

    // Serialize (as export does).
    let json = serde_json::to_string_pretty(&policies).expect("serialize");
    assert!(json.contains("\"mode\": \"ALL\""));
    assert!(json.contains("\"mode\": \"ANY\""));
    assert!(json.contains("\"mode\": \"NONE\""));

    // Deserialize (as import does).
    let round_trip: Vec<PolicyPayload> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(round_trip.len(), 3);
    assert_eq!(round_trip[0].mode, PolicyMode::ALL);
    assert_eq!(round_trip[1].mode, PolicyMode::ANY);
    assert_eq!(round_trip[2].mode, PolicyMode::NONE);
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Hardcoded `conditions.iter().all(...)` in evaluator | `match policy.mode { ALL => .all(), ANY => .any(), NONE => !.any() }` | Phase 18 (2026-04-20) | Mode-aware evaluation; no hot-path overhead |
| TUI forms with hardcoded row-index literals | Named `POLICY_*_ROW` constants in dispatch.rs | Phase 15 | Row migration is now const-rename, not literal sweep |
| Untyped `Vec<serde_json::Value>` for import/export | Typed `Vec<PolicyResponse>` + `From<PolicyResponse> for PolicyPayload` | Phase 17 | `#[serde(default)]` gives legacy-file tolerance for free |
| Bare `"mode"` absence defaults silently at server only | `#[serde(default)]` on both server + admin-cli structs | Phase 18 (server) + Phase 19 (admin-cli) | Full-stack default-ALL handling; legacy v0.4.0 exports round-trip correctly |

**Deprecated/outdated:**
- None. Phase 19 is additive.

## Project Constraints (from CLAUDE.md)

The following are directly applicable to Phase 19 code:

| Constraint | Source | Implication for Phase 19 |
|------------|--------|--------------------------|
| No `.unwrap()` in prod paths | §9.4, §9.5 | Mode JSON parsing must use `?` or explicit match, not `unwrap` |
| `Result<T, E>` + `thiserror` for errors | §9.5 | Any new error type uses `thiserror`; reuse `AppError` for server handlers |
| `tracing::info!`/`warn!`/`error!` not `println!` | §9.1 | TUI status messages go through `app.set_status()`; server logs via `tracing` |
| `ratatui` + `crossterm` for TUI | §9.1 | Already in use; no new dependency |
| `serde` + `serde_json` for JSON | §9.1 | Already in use |
| `cargo fmt` + `cargo clippy -- -D warnings` | §9.15, §9.17 | Must pass before commit |
| `sonar-scanner` run before pushing | §9.16 | Blocking for push (not commit) |
| 4-space indent, no tabs | §9.2 | `rustfmt.toml` enforces |
| No emoji or emoji-like unicode | §9.2 | Footer hint wording MUST be plain ASCII (no checkmarks, etc.) |
| `snake_case` for functions/vars, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for consts | §9.2 | `POLICY_MODE_ROW` follows convention; `PolicyMode` enum already conforms |
| 100-char line limit | §9.2 | rustfmt default |
| Meaningful doc comments on public items, with `# Arguments` / `# Errors` / `# Examples` | §9.3 | `PolicyFormState.mode` field needs a doc line; the new row-index const needs a doc line |
| Derive `Debug, Clone, PartialEq` where appropriate | §9.7 | `PolicyFormState` already derives the right set |
| Unit test new functions; `cargo test` must pass | §9.8, §9.17 | Wave 2 tests cover this |
| No commented-out code | §9.14 | Applies to the refactor of render.rs if any row arms are temporarily disabled |
| `#[cfg(test)]` module for tests | §9.8 | Integration tests go to `dlp-server/tests/` (standalone bin), unit tests stay in-module |

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The recommended advisory text (`Note: mode=ANY with no conditions will never match.` / `Note: mode=NONE with no conditions matches every request.`) fits the TUI's tonal conventions. | Pattern 3 | Low — D-04 explicitly marks wording as Claude's discretion. |
| A2 | Refactoring the `json!()` macros at dispatch.rs §1321 / §1610 to construct a typed `PolicyPayload` struct + `serde_json::to_value()` is acceptable per Rust/project idiom. | Code Examples | Low — the struct already exists in app.rs; typed serialization is strictly cleaner. If planner prefers literal stringification in the macro, both approaches work. |
| A3 | The 5-day-stale knowledge graph does not contain Phase 18 state and can be ignored for this phase. | (internal) | Low — all Phase 19 files were re-read directly from disk, graph lookup was a sanity check. |

**Three claims remain [ASSUMED]. All are low-risk presentation/idiom choices, not architectural or compliance decisions. No user confirmation needed before proceeding.**

## Open Questions

1. **Should the form-submit JSON payloads be refactored to `PolicyPayload` struct + `serde_json::to_value(&payload)?`, or just add a `"mode": "ANY"` string to the existing `json!()` macro?**
   - What we know: `PolicyPayload` struct already exists (app.rs §262-270) and gains `mode` field in D-05. The macro approach works but risks typo drift.
   - What's unclear: Whether the original author deliberately used the macro for readability.
   - Recommendation: Refactor to struct + `to_value()`. Test coverage proves correctness either way; struct approach auto-inherits `PolicyMode`'s `Serialize` impl and is one less place to sync.

2. **Should the Validation Architecture section's "Test Framework" row be rustc's `cargo test` (unit + integration in one invocation) or split into `cargo test --lib` + `cargo test --test mode_end_to_end`?**
   - What we know: Phase 18 SUMMARY uses `cargo test --lib --all` and `cargo test -p dlp-server --tests` as two separate gates.
   - What's unclear: Whether Phase 19's Nyquist sampling prefers a single quick command.
   - Recommendation: Mirror Phase 18 — `cargo test --lib --all` per task commit (fast, <30s), `cargo test -p dlp-server --tests` per wave merge (includes integration tests, ~60s+).

3. **Does the TUI's current `action_load_policy_for_edit` (dispatch.rs §1363) tolerate a `"mode"` key missing from the GET response?**
   - What we know: The function reads fields with `.as_str().unwrap_or("")` and `.as_bool().unwrap_or(true)` patterns — i.e., it does untyped JSON navigation, not typed deserialize. Adding a mode pre-fill via `policy["mode"].as_str().and_then(|s| match s { "ALL" => Some(PolicyMode::ALL), ... })` with default `PolicyMode::ALL` is the safe pattern.
   - What's unclear: Nothing — this is a straightforward addition.
   - Recommendation: Add a `mode_from_json(v: &serde_json::Value) -> PolicyMode` helper in `app.rs` or inline in `action_load_policy_for_edit`.

## Environment Availability

Phase 19 is a code-only change; no new external dependencies. All crates used by the integration test (`tempfile`, `jsonwebtoken`, `bcrypt`, `tower`, `axum`) are already in `dlp-server/Cargo.toml` as either runtime or dev-dependencies.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| rust toolchain | everything | ✓ | 2021 edition | — |
| cargo | build/test | ✓ | latest | — |
| rustfmt | §9.17 gate | ✓ (rustup component) | — | — |
| clippy | §9.17 gate | ✓ (rustup component) | — | — |
| sonar-scanner | §9.16 pre-push gate | assumed ✓ (CLAUDE.md mentions it) | — | Not run by Phase 19 agents; user-driven |

**Missing dependencies with no fallback:** None.
**Missing dependencies with fallback:** None.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `cargo test` (Rust 2021 edition built-in) |
| Config file | none (workspace-level) |
| Quick run command | `cargo test --lib --all` |
| Full suite command | `cargo test --all --tests` |
| Phase-gate additional | `cargo clippy --all -- -D warnings && cargo fmt --all -- --check` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| POLICY-09 | Policy Create form surfaces a Mode row that cycles ALL→ANY→NONE→ALL on Enter | unit (TUI dispatch) | `cargo test -p dlp-admin-cli --lib test_policy_create_mode_cycles` | ❌ Wave 2 |
| POLICY-09 | Policy Edit form pre-fills mode from loaded PolicyResponse | unit (TUI action) | `cargo test -p dlp-admin-cli --lib test_policy_edit_prefills_mode` | ❌ Wave 2 |
| POLICY-09 | `PolicyPayload` / `PolicyResponse` round-trip through JSON with `mode` preserved | unit (serde) | `cargo test -p dlp-admin-cli --lib test_policy_payload_roundtrip_preserves_modes` | ❌ Wave 2 |
| POLICY-09 | Legacy JSON without `mode` key deserializes with `PolicyMode::ALL` | unit (serde) | `cargo test -p dlp-admin-cli --lib test_policy_response_defaults_missing_mode_to_all` | ❌ Wave 2 |
| POLICY-09 | `From<PolicyResponse> for PolicyPayload` copies `mode` | unit | `cargo test -p dlp-admin-cli --lib test_policy_response_into_payload_copies_mode` | ❌ Wave 2 |
| POLICY-09 | Footer advisory renders when `mode != ALL && conditions.is_empty()`, hidden otherwise | unit (render) | `cargo test -p dlp-admin-cli --lib test_policy_create_footer_advisory` | ❌ Wave 2 (ratatui test harness via `TestBackend`) |
| POLICY-09 | E2E: create policy w/ mode=ALL + 2 conditions, hit eval where all conditions match → matched | integration | `cargo test -p dlp-server --test mode_end_to_end test_mode_all_matches_when_all_conditions_hit` | ❌ Wave 2 |
| POLICY-09 | E2E: create policy w/ mode=ANY + 2 conditions, hit eval where only one matches → matched | integration | `cargo test -p dlp-server --test mode_end_to_end test_mode_any_matches_when_one_condition_hits` | ❌ Wave 2 |
| POLICY-09 | E2E: create policy w/ mode=NONE + 2 conditions, hit eval where none match → matched | integration | `cargo test -p dlp-server --test mode_end_to_end test_mode_none_matches_when_no_conditions_hit` | ❌ Wave 2 |
| POLICY-09 | E2E: same EvaluateRequest against three mode variants produces three different decisions | integration | (above three tests collectively prove this) | ❌ Wave 2 |
| POLICY-09 | Data-layer export/import round-trip: three policies × three modes serialize+deserialize identically | unit (serde) | `cargo test -p dlp-server --test mode_end_to_end test_policy_payload_roundtrip_preserves_all_three_modes` | ❌ Wave 2 |

### Sampling Rate

- **Per task commit:** `cargo test --lib --all` (<30 s; catches unit-test regressions on TUI and server)
- **Per wave merge:** `cargo test --all --tests` (includes integration tests in `dlp-server/tests/`; ~60 s)
- **Phase gate:** `cargo test --all --tests && cargo clippy --all -- -D warnings && cargo fmt --all -- --check` — all green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `dlp-server/tests/mode_end_to_end.rs` — new test file; covers D-14 (three E2E tests) + D-15 (data-layer round-trip test)
- [ ] Unit tests inside `dlp-admin-cli/src/screens/dispatch.rs #[cfg(test)] mod` — D-01 (mode cycles), Load-policy-into-form (D-03)
- [ ] Unit tests inside `dlp-admin-cli/src/app.rs #[cfg(test)] mod` — PolicyResponse/PolicyPayload round-trip, From impl copies mode
- [ ] ratatui `TestBackend` harness for the footer-advisory render test (optional — can defer to UAT if ratatui test harness is not already set up; check for existing uses of `TestBackend` before committing to this)

*(Framework install: none — `cargo test` is built-in; no new dev-dep needed.)*

## Sources

### Primary (HIGH confidence)

- **dlp-common/src/abac.rs** §249-268 — `PolicyMode` enum verified in-place, derives `Default` with `#[default]` on `ALL`, `Copy`, `PartialEq`, `Eq`, `Serialize`, `Deserialize`. File read in full.
- **dlp-common/src/abac.rs** §266-287 — `Policy` struct derives `Default`, has `mode: PolicyMode` with `#[serde(default)]`. Verified.
- **dlp-admin-cli/src/app.rs** §123-140 — `PolicyFormState` struct shape + `#[derive(Default)]`. Verified.
- **dlp-admin-cli/src/app.rs** §241-284 — `PolicyResponse`, `PolicyPayload`, and `From` impl. Verified.
- **dlp-admin-cli/src/screens/dispatch.rs** §874-887 — `POLICY_*_ROW` constants. Verified all existing constants are named (no numeric literal in handlers). **Critical finding: dispatch row-index migration is trivially consts-only.**
- **dlp-admin-cli/src/screens/dispatch.rs** §1110-1273 — `handle_policy_create` event logic. Verified structure (two phases: editing vs nav; nav uses consts).
- **dlp-admin-cli/src/screens/dispatch.rs** §1420-1564 — `handle_policy_edit` event logic. Mirrors create.
- **dlp-admin-cli/src/screens/dispatch.rs** §1280-1356 — `action_submit_policy` (the POST payload `json!()` macro). **Critical finding: mode is MISSING from the current payload; must be added.**
- **dlp-admin-cli/src/screens/dispatch.rs** §1571-1644 — `action_submit_policy_update` (the PUT payload `json!()` macro). Same finding.
- **dlp-admin-cli/src/screens/dispatch.rs** §2163-2290 — `form_snapshot` spread pattern. **Critical finding: adding `mode` to `PolicyFormState` propagates through the conditions-builder round-trip automatically (no dispatch change needed).**
- **dlp-admin-cli/src/screens/dispatch.rs** §2918-3052 — `action_export_policies` + `action_import_policies`. Verified no change needed once D-05/D-06 land.
- **dlp-admin-cli/src/screens/dispatch.rs** §3070-3194 — `handle_import_confirm`. Verified no per-field diff is shown, only aggregate counts.
- **dlp-admin-cli/src/screens/render.rs** §598-607 — `POLICY_FIELD_LABELS`, 8 rows. Verified. **Critical finding: this array length + its paired `match i { 0..=7 => ... }` arms are the row-count renumbering hotspots.**
- **dlp-admin-cli/src/screens/render.rs** §804-944 — `draw_policy_create`. Verified: uses hardcoded `match i { 0 => ..., 7 => ... }` arms and `Vec::with_capacity(POLICY_FIELD_LABELS.len())`.
- **dlp-admin-cli/src/screens/render.rs** §962-1088 — `draw_policy_edit`. Same structure as create.
- **dlp-admin-cli/src/screens/render.rs** §922-935 — `validation_error` overlay pattern. **Critical finding: directly reusable as template for the footer advisory.**
- **dlp-admin-cli/src/screens/render.rs** §1493-1573 — `draw_import_confirm`. **Critical finding: no per-field diff exists; CONTEXT.md's §273-280 concern is moot.**
- **dlp-admin-cli/src/screens/render.rs** §1717-1730 — `draw_hints` helper. Renders at `area.y + area.height - 1`.
- **dlp-server/src/admin_api.rs** §56-81 — `evaluate_handler` (unauthenticated, at `/evaluate`). Verified.
- **dlp-server/src/admin_api.rs** §405-488 — `admin_router` construction. Verified: `/evaluate` is public; `/admin/policies` is protected under JWT middleware.
- **dlp-server/src/admin_api.rs** §107-127 — server-side `PolicyPayload` already has `mode` field with `#[serde(default)]`.
- **dlp-server/tests/admin_audit_integration.rs** (full file) — integration test harness. `test_app()`, `seed_admin_user()`, `mint_jwt()`, `TEST_JWT_SECRET`. Directly reusable.
- **dlp-server/Cargo.toml** + **dlp-admin-cli/Cargo.toml** — all deps confirmed present.
- **.planning/phases/18-boolean-mode-engine-wire-format/SUMMARY.md** — Phase 18 shipped: evaluator switch, DB migration, wire-format serde defaults, mode_str/mode_from_str helpers.
- **.planning/phases/17-import-export/17-CONTEXT.md** — import conflict semantics; typed-struct pattern.
- **.planning/config.json** — `nyquist_validation` not explicitly set → treat as enabled.

### Secondary (MEDIUM confidence)

- **CLAUDE.md** project root — Rust coding standards. Sourced directly from the project.
- **.planning/STATE.md** — current state; confirms Phase 18 complete, Phase 19 ready to plan.

### Tertiary (LOW confidence)

- None. All findings verified directly against the codebase.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — every library already in workspace, versions pinned in Cargo.toml.
- Architecture: HIGH — all file/line locations verified by direct read.
- Pitfalls: HIGH — Pitfalls 1 through 4 were discovered by direct code inspection, not assumption. Pitfall 2 corrects a misdiagnosis in CONTEXT.md §246 (the dispatch.rs row-index issue is already resolved; the real work is in render.rs). Pitfall 4 corrects CONTEXT.md §273-280 (no per-policy diff renderer exists).
- Integration test harness: HIGH — `admin_audit_integration.rs` fully read; pattern directly reusable.
- Validation architecture: HIGH — commands verified against Phase 18 SUMMARY.md and Cargo.toml.

**Research date:** 2026-04-20
**Valid until:** 2026-05-20 (30 days — Phase 19 is additive on a stable codebase; no fast-moving external deps)
