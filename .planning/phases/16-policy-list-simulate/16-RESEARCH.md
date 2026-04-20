# Phase 16: Policy List + Simulate — Research

**Phase:** 16-policy-list-simulate
**Date:** 2026-04-17
**Requirements:** POLICY-01, POLICY-06
**Status:** Ready to plan

---

## 1. What's in Scope

### POLICY-01 — Policy List Polish

Reshape the existing `Screen::PolicyList` table and wire the missing `n` hotkey:

- Columns: `Priority / Name / Action / Enabled` (drop `ID` and `Version`).
  - Widths: 15% / 45% / 20% / 20%.
  - `Action`: render raw JSON string verbatim (e.g. `DENY`, `AllowWithLog`).
  - `Enabled`: `true`/`false` → `Yes`/`No`.
- Sort: client-side, primary key `priority` ascending, secondary key `name`
  case-insensitive ascending for stable tiebreak. Malformed `priority`
  (non-numeric) treated as `u32::MAX` (sinks to bottom).
- `n` key: transition to `Screen::PolicyCreate` with fresh
  `PolicyFormState::default()`.
- Footer hint: `"n: new | e: edit | d: delete | Enter: view | Esc: back"`.
- No server changes. Sort happens once per GET in `action_list_policies`.

### POLICY-06 — Policy Simulate

New `Screen::PolicySimulate` form:

- **Subject fields**: `user_sid` (text), `user_name` (text), `groups`
  (comma-separated SIDs text field), `device_trust` (select, 4 options),
  `network_location` (select, 4 options).
- **Resource fields**: `path` (text), `classification` (select, T1–T4).
- **Environment fields**: `action` (select, 6 options), `access_context`
  (select, 2 options).
- Submit: `POST /evaluate` (unauthenticated public route).
  `environment.timestamp` = `chrono::Utc::now()`, `session_id = 0`,
  `agent = None`. No client-side pre-validation.
- Result: `EvaluateResponse` renders inline below `[Simulate]` row:
  `Matched policy: {id|none}`, `Decision: {DECISION}` (colored red/green via
  `Decision::is_denied()`), `Reason: {reason}`.
- Errors: inline red paragraph with prefix `"Network error: "` or
  `"Server error: "`. No silent drops, no status-bar-only errors.
- Two entry points: `MainMenu → "Simulate Policy"` and `PolicyMenu →
  "Simulate Policy"`. Esc returns to the correct caller.

---

## 2. What I Know From Reading the Code

### Existing `draw_policy_list` (render.rs §1136–1192)

The current table is defined here:

```rust
let header = Row::new(vec!["ID", "Name", "Priority", "Enabled", "Version"])
let widths = [20%, 30%, 15%, 15%, 20%];
let hints = "e: edit | d: delete | Enter: view | Esc: back";
```

**Changes needed:** Replace `header`, row builder (drop `id`/`version` columns,
map `enabled: bool → Yes/No`), `widths`, and `hints` string. The `Table`
widget and `TableState` plumbing stays identical.

### Existing `handle_policy_list` (dispatch.rs §393–434)

```rust
match key.code {
    KeyCode::Up | KeyCode::Down => nav(selected, policies.len(), ...),
    KeyCode::Enter => PolicyDetail,
    KeyCode::Esc => PolicyMenu,
    KeyCode::Char('e') => action_load_policy_for_edit(...),
    KeyCode::Char('d') => Confirm(DeletePolicy),
    // Char('n') branch is MISSING — it was removed as dead code in Phase 15.
}
```

**Changes needed:** Add `KeyCode::Char('n')` branch (D-08 from 16-CONTEXT.md).

### Existing `action_list_policies` (dispatch.rs §458–475)

```rust
fn action_list_policies(app: &mut App) {
    match app.rt.block_on(app.client.get::<Vec<serde_json::Value>>("policies")) {
        Ok(policies) => {
            app.set_status(...);
            app.screen = Screen::PolicyList { policies, selected: 0 };
        }
        Err(e) => app.set_status(...),
    }
}
```

**Changes needed:** After deserialization, sort `policies` by priority asc,
name asc. Replace `policies` binding with the sorted `Vec` before assigning
to `Screen::PolicyList`.

### Existing `handle_main_menu` (dispatch.rs §61–78)

```rust
fn handle_main_menu(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Down => nav(selected, 4, key.code),  // <-- count=4
        KeyCode::Enter => match *selected { 0=>PasswordMenu, 1=>PolicyMenu, 2=>SystemMenu, 3=>quit },
        ...
    }
}
```

**Changes needed:** Change `nav` count from 4 to 5. Add `4 => Simulate Policy`
to Enter branch. Add a new `Simulate Policy` row to `draw_main_menu`.

### Existing `handle_policy_menu` (dispatch.rs §121–170)

```rust
fn handle_policy_menu(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Down => nav(selected, 6, key.code),  // <-- count=6
        KeyCode::Enter => match *selected {
            0=>List, 1=>GetPolicy, 2=>PolicyCreate, 3=>UpdatePolicy,
            4=>DeletePolicy, 5=>MainMenu
        },
        ...
    }
}
```

**Changes needed:** Change `nav` count from 6 to 7. Add `5 => SimulatePolicy`
and renumber `5=>MainMenu` to `6=>MainMenu` in Enter branch. Add a new
`"Simulate Policy"` entry to `draw_policy_menu`.

### Existing `draw_main_menu` and `draw_policy_menu` (render.rs §1048–1078)

These render fixed `&[&str]` arrays. The arrays must be extended by one
element each.

### `Screen` enum (app.rs §156–315)

Two additions:

1. `PolicySimulate { form, selected, editing, buffer, result, caller }`
2. New supporting types: `SimulateFormState`, `SimulateOutcome`, `SimulateCaller`

### `EngineClient::post<T>` (client.rs §221–243)

```rust
pub async fn post<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T>
```

**Key insight:** `apply_auth` attaches the Bearer token. On the
unauthenticated `/evaluate` route, the server ignores the token — this
is confirmed by the codebase. No new client method is needed.

### `dlp_common::abac` — EvaluateRequest / EvaluateResponse

These types are in `dlp-common/src/abac.rs` and already have full serde
round-trip coverage (§298–§326). The TUI imports them via `dlp-common`:

```rust
use dlp_common::abac::{EvaluateRequest, EvaluateResponse, ...};
// also:
use dlp_common::{Classification, Action, AccessContext, DeviceTrust, NetworkLocation};
```

**Critical serde details confirmed:**
- `DeviceTrust`: `#[serde(rename_all = "PascalCase")]` → `"Managed"`, `"Unmanaged"`, `"Compliant"`, `"Unknown"`.
- `NetworkLocation`: same → `"Corporate"`, `"CorporateVpn"`, `"Guest"`, `"Unknown"`.
- `AccessContext`: `#[serde(rename_all = "lowercase")]` → `"local"`, `"smb"`.
- `Classification`: `#[serde(rename_all = "lowercase")]` on the `Classification` enum (defined in `dlp-common/src/classification.rs`), giving `"t1"`…`"t4"` on the wire.
- `Action`: `READ`, `WRITE`, `COPY`, `DELETE`, `MOVE`, `PASTE` (uppercase, no serde rename attribute).
- `Environment.timestamp`: `chrono::DateTime<chrono::Utc>` (chrono is a dlp-common dependency, available transitively via dlp-common).

### `Decision::is_denied()` (abac.rs §64–69)

```rust
pub fn is_denied(self) -> bool {
    matches!(self, Self::DENY | Self::DenyWithAlert)
}
```

Used for red/green coloring of the Decision line in the simulate result block.

### Server endpoint

`POST /evaluate` is already live in `dlp-server/src/admin_api.rs` §44.
Mounted under `public_routes` at §392–395 — no JWT required.

---

## 3. Unknowns (Deferred to Planning)

### U1 — Section Header Skip-Nav Implementation

The simulate form has 13 render rows (4 section headers + 9 editable rows).
`selected` must range 0..=9 (editable only). Two implementation options:

**Option A — Sparse index:** `selected: usize` covers all 13 render positions,
Up/Down advances `selected` by 1 always, but 3 indices are mapped to header
positions (3, 5, 9 are headers in the full list). The handler skips header
indices: if key lands on a header index, advance again in the same direction.

**Option B — Linear editable index:** `selected: usize` covers 0..=9 (10 rows).
Render maps `editable_idx → render_row` via a lookup table. Navigation advances
the editable index (0..=9), renderer applies the offset.

Option B is simpler to implement and reason about. The render-time offset
lookup is a single `usize` array access. **Recommendation: Option B.**

### U2 — `chrono` availability in dlp-admin-cli

`chrono` is a direct dependency of `dlp-common` but NOT of `dlp-admin-cli`.
`dlp-admin-cli` currently uses `tokio`, `reqwest`, `ratatui`, `bcrypt`,
`uuid`. It does not directly depend on `chrono`.

When `action_submit_simulate` calls `chrono::Utc::now()`, it would be pulling
chrono through `dlp-common`. To be safe, the plan should either:
(a) Add `chrono = "0.4"` as a direct dependency of `dlp-admin-cli`, or
(b) Use `std::time::SystemTime::now()` and format to RFC 3339, which
    `chrono::DateTime` parses from.

Option (a) is cleaner. Plan should recommend adding `chrono = "0.4"` to
`dlp-admin-cli/Cargo.toml`.

### U3 — `PolicySimulate` in `app.rs` vs. `simulate.rs`

The existing `PolicyFormState` lives in `app.rs`. `SimulateFormState` is
structurally simpler (no `Vec<PolicyCondition>`, no `id`). Estimated ~80 new
lines for the Screen variant + ~40 for supporting types + ~20 for constants.
Splitting into `simulate.rs` would add file overhead disproportionate to the
size. **Recommendation: keep in `app.rs`.**

### U4 — `chrono::DateTime` serde in EvaluateRequest

The `Environment.timestamp` field is `chrono::DateTime<chrono::Utc>` with
chrono serde features. The `EvaluateRequest::default()` sets `timestamp` to
`DateTime::default()` which is ` timestamp: DateTime::from_timestamp(0, 0)`.
The wire format is an ISO 8601 / RFC 3339 string. `serde_json` handles this
correctly with chrono serde. No special handling needed.

### U5 — Error prefix contract

16-CONTEXT.md §D-23 specifies error prefixes: `"Network error: "` for
transport failures, `"Server error: "` for 4xx/5xx. The `EngineClient::post`
method (client.rs §234) returns `anyhow::Error` on non-success status codes,
and returns `anyhow::Error` on network failure (reqwest error). Both cases
arrive via `?` as `anyhow::Error`. `anyhow::Error::to_string()` produces a
single-line description.

**Implementation:** In `action_submit_simulate`, pattern-match on the error
type to detect network vs server, or unconditionally prefix with `"Server error: "`
(the more common case since `/evaluate` is reachable). For maximum accuracy,
check `err.downcast_ref::<reqwest::Error>()` — if present, prefix
`"Network error: "`. Otherwise prefix `"Server error: "`. This is a planning
detail to specify, not a research blocker.

---

## 4. Key Files to Change

| File | Changes |
|------|---------|
| `dlp-admin-cli/src/app.rs` | Add `SimulateFormState`, `SimulateOutcome`, `SimulateCaller`; add `PolicySimulate` to `Screen` enum |
| `dlp-admin-cli/src/screens/dispatch.rs` | Add `Char('n')` branch in `handle_policy_list`; inject sort in `action_list_policies`; update nav counts + Enter branches for MainMenu + PolicyMenu; add `handle_policy_simulate`, `handle_policy_simulate_nav`, `handle_policy_simulate_editing`, `action_submit_simulate` |
| `dlp-admin-cli/src/screens/render.rs` | Update `draw_policy_list` (columns, widths, hints); update `draw_main_menu` / `draw_policy_menu` arrays; add `draw_policy_simulate` |
| `dlp-admin-cli/Cargo.toml` | Add `chrono = "0.4"` direct dependency |

**No server changes.** `POST /evaluate` is already live and public.

---

## 5. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| `chrono` not available at compile time in dlp-admin-cli | Low | Build failure | Add as direct dep; confirmed `chrono` serde works end-to-end |
| Bearer token sent to unauthenticated route causes server rejection | Very low | Unauthenticated endpoint ignores auth header (confirmed in codebase) | Document in plan |
| Decision coloring uses `is_denied()` which returns false for `AllowWithLog` | Design | `AllowWithLog` renders green — matches ROADMAP intent | Document this edge case |
| Groups comma-split has trailing-space edge case | Low | Groups silently dropped | `trim()` each segment before collecting — already in spec |

---

## 6. Open Questions for the Planner

1. **Error prefix granularity (U5):** Use a single `"Server error: "` prefix for all failures, or detect network vs server separately? (Single prefix is simpler; separate detection is more accurate.)
2. **Column widths:** 16-CONTEXT.md §D-02 specifies 15%/45%/20%/20% for PolicyList. Should `Name` get 50% and `Enabled` 15%, or is the 15%/45%/20%/20% split correct as-is?
3. **Result block height:** The simulate result block uses a `Paragraph` with wrap. The plan should specify the height of the result area (suggest: 3 rows for success, 1 row for error) so the render area allocation is deterministic.
4. **Groups buffer split timing:** `groups_raw` is preserved across edits. Is it also preserved across navigating away and back to the simulate screen, or does re-opening the screen reset it? (Spec says preserved across field edits — clarify whether screen re-entry is in scope.)

---

*Research complete. Awaiting planning decisions on §6 items before plan is written.*
