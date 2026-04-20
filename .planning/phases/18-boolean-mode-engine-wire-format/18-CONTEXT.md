# Phase 18: Boolean Mode Engine + Wire Format - Context

**Gathered:** 2026-04-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Server-side delivery of flat boolean composition. The ABAC evaluator
switches on a per-policy `mode` (`ALL` / `ANY` / `NONE`), the SQLite
schema persists it with a backward-compatible default, and the wire
format carries it round-trip through `PolicyPayload` / `PolicyResponse`.
v0.4.0-authored policies loaded from storage without a `mode` value are
treated as `ALL`, preserving exact prior semantics.

**Explicitly in scope:**
1. `dlp_common::abac::PolicyMode` typed enum (`ALL`/`ANY`/`NONE`) and
   `mode: PolicyMode` field on `dlp_common::abac::Policy`.
2. `policies.mode` SQLite column (`NOT NULL DEFAULT 'ALL'`) added via
   forward-and-migrate pattern that works on both fresh and v0.4.0 DBs.
3. `PolicyPayload` and `PolicyResponse` gain `mode` with `#[serde(default)]`
   for legacy-payload tolerance.
4. `PolicyStore::evaluate` switches on the policy's mode. Cache
   invalidation continues on every mutation (unchanged).
5. Unit tests covering three modes + empty-conditions edge cases +
   legacy-payload parity + migration path.

**Explicitly out of scope (for this phase):**
- No TUI change. The admin TUI implicitly authors `ALL` until Phase 19.
- No expanded operators. `eq`/`neq`/`in`/`not_in` stay as-is; `gt`/`lt`/
  `ne`/`contains` land in Phase 20.
- No in-place condition editing. Delete-and-recreate stays as-is;
  in-place editing lands in Phase 21.
- No nested expression trees. Flat top-level mode only.

</domain>

<decisions>
## Implementation Decisions

### PolicyMode Enum Shape

- **D-01:** `PolicyMode` lives in `dlp-common::abac` co-located with the
  existing `Policy` struct. Shared across crates, matches where
  `Decision` / `PolicyCondition` live.
- **D-02:** Wire form is SCREAMING: `"ALL"` / `"ANY"` / `"NONE"`. Enum
  variants named `ALL`, `ANY`, `NONE` — no `#[serde(rename_all)]`
  needed because variant names match wire strings. Matches `Decision`
  (`ALLOW`/`DENY`) precedent and the REQUIREMENTS.md / milestone-roadmap
  wording verbatim.
- **D-03:** `#[derive(Default)]` on `PolicyMode` with `#[default]` on
  `ALL` variant. `PolicyMode::default() == PolicyMode::ALL`.
- **D-04:** `#[derive(Default)]` on `dlp_common::abac::Policy`. All
  fields default: `id`/`name = String::new()`, `description = None`,
  `priority = 0`, `conditions = vec![]`, `action = Decision::ALLOW`
  (existing Decision default), `enabled = false`, `version = 0`,
  `mode = PolicyMode::ALL`. Tests use `Policy { ..Default::default() }`
  spread for fixture readability. Mirrors `Subject`/`Resource`/
  `Environment` which already derive Default.
- **D-05:** `PolicyMode` derives: `Debug`, `Clone`, `Copy`, `PartialEq`,
  `Eq`, `Serialize`, `Deserialize`, `Default`. `Copy` is cheap (unit
  variants only) and simplifies use in evaluator read path.

### DB Migration Strategy

- **D-06:** `CREATE TABLE IF NOT EXISTS policies` in `init_tables()`
  gains a `mode TEXT NOT NULL DEFAULT 'ALL'` column. Fresh installs
  pick up the full schema in one shot.
- **D-07:** New `run_migrations(conn: &SqliteConn) -> anyhow::Result<()>`
  function in `dlp-server/src/db/mod.rs`, called by `new_pool()` after
  `init_tables()`. Holds all `ALTER TABLE ... ADD COLUMN` statements
  that apply to pre-existing databases. Future column-add migrations
  append to this one place.
- **D-08:** The `ALTER TABLE policies ADD COLUMN mode TEXT NOT NULL
  DEFAULT 'ALL'` statement is wrapped in a helper that swallows only
  the SQLite "duplicate column name" error (message contains "duplicate
  column name: mode"). Any other error bubbles up as
  `anyhow::Error`. Idempotent on re-run.
- **D-09:** Pre-existing v0.4.0 rows are backfilled with `'ALL'`
  automatically by SQLite's `DEFAULT 'ALL'` clause on `ADD COLUMN`
  (SQLite populates existing rows with the default). No explicit
  `UPDATE` statement required.
- **D-10:** Dedicated migration unit test: opens an in-memory SQLite DB,
  manually `CREATE`s the v0.4.0 `policies` table (no `mode` column),
  inserts a sample row, calls `run_migrations()`, asserts: (a) `mode`
  column now exists in `PRAGMA table_info(policies)`, (b) the pre-
  existing row reads back with `mode = 'ALL'`, (c) calling
  `run_migrations()` a second time does not error.

### Evaluator Switch on Mode

- **D-11:** `PolicyStore::evaluate` replaces the hardcoded
  `conditions.iter().all(...)` with a `match policy.mode` branching
  on `ALL` / `ANY` / `NONE`. Signature, read-lock behavior, and
  `default_allow`/`default_deny` fallback logic are unchanged.
- **D-12:** Mapping to iterator semantics:
  - `ALL` → `conditions.iter().all(|c| condition_matches(c, req))`
  - `ANY` → `conditions.iter().any(|c| condition_matches(c, req))`
  - `NONE` → `!conditions.iter().any(|c| condition_matches(c, req))`
- **D-13:** Empty-conditions behavior is the natural iterator short-
  circuit — no custom branch, no validation:
  - `ALL + []` matches unconditionally (preserves v0.4.0 semantics).
  - `ANY + []` never matches.
  - `NONE + []` matches unconditionally.
  The create/update handlers do NOT reject `conditions = []` under any
  mode. Unit tests document each edge case.

### Wire Format: Serde Defaults for Legacy Payloads

- **D-14:** `PolicyPayload.mode: PolicyMode` with
  `#[serde(default)]`. Since `PolicyMode::default() == ALL` (D-03),
  any POST/PUT body omitting `mode` deserializes with `mode = ALL` —
  POLICY-12 contract satisfied via one annotation, no helper fn.
- **D-15:** `PolicyResponse.mode: PolicyMode` with `#[serde(default)]`.
  Same rationale — admin clients parsing responses from a future
  downgraded server (unlikely) still deserialize cleanly.
- **D-16:** `dlp_common::abac::Policy.mode: PolicyMode` with
  `#[serde(default)]`. Not used on the wire today but kept consistent
  so `serde_json::from_str::<Policy>("{...}")` (used in any future
  cached-policy blob format) round-trips.

### DB Row → Policy Deserialization

- **D-17:** `PolicyRow` (in `db/repositories/policies.rs`) gains a
  `mode: String` field. Read queries (`list`, `get_by_id`) add `mode`
  to the SELECT column list in the documented column order.
- **D-18:** `deserialize_policy_row` in `policy_store.rs` parses
  `row.mode.as_str()`: matches `"ALL"`/`"ANY"`/`"NONE"` to the
  enum variant. Any other string returns `serde_json::Error` so the
  row is skipped by the existing `skipped policy with malformed
  conditions` warn-log path (extended to "or malformed mode"). The
  `NOT NULL DEFAULT 'ALL'` schema constraint guarantees this never
  fires in practice — the skip-on-malformed path is a corruption safety
  net, not routine.
- **D-19:** `PolicyUpdateRow` and `PolicyRow` insert path (create
  handler): `mode` is written as a string via `PolicyMode`'s `Serialize`
  impl (e.g., `serde_json::to_value(&policy_mode)?.as_str()`) OR via a
  small helper `fn mode_str(m: PolicyMode) -> &'static str` returning
  `"ALL"` / `"ANY"` / `"NONE"`. Planner picks the cleaner of the two;
  the result on-disk must be the exact SCREAMING string.

### Create / Update Handler Wiring

- **D-20:** `create_policy` in `admin_api.rs`: accept `payload.mode`
  (defaulted by serde), map to DB column via D-19 helper, include in
  the `PolicyRow` built for `PolicyRepository::insert`. `PolicyResponse`
  returned to caller echoes the resolved mode.
- **D-21:** `update_policy` in `admin_api.rs`: same pattern.
  `PolicyUpdateRow` gains a `mode: &str` field. `UPDATE policies SET
  ..., mode = ?N` added to the statement in its repository method.
- **D-22:** `PolicyStore::invalidate()` is already called after every
  successful DB commit in create/update/delete — no change needed.
  Evaluator reads the new mode on the next request.

### Unit Test Coverage

- **D-23:** PolicyStore evaluator tests (new + extended):
  - `evaluate_all_mode_three_conditions_match` — all match, policy hits.
  - `evaluate_all_mode_one_condition_misses` — policy does not hit.
  - `evaluate_any_mode_one_condition_matches` — hits.
  - `evaluate_any_mode_no_condition_matches` — misses.
  - `evaluate_none_mode_no_condition_matches` — hits.
  - `evaluate_none_mode_one_condition_matches` — misses.
  - `evaluate_empty_conditions_all_mode_matches` (edge case).
  - `evaluate_empty_conditions_any_mode_does_not_match` (edge case).
  - `evaluate_empty_conditions_none_mode_matches` (edge case).
- **D-24:** Wire format tests:
  - `policy_payload_json_without_mode_defaults_to_all` (POLICY-12).
  - `policy_payload_json_with_mode_any_roundtrip`.
  - `policy_response_json_without_mode_defaults_to_all`.
- **D-25:** Parity test: a `PolicyPayload` deserialized from a legacy
  v0.4.0-shaped JSON literal (no `mode` key) produces the same
  `EvaluateResponse` as a payload with `mode` explicitly set to
  `"ALL"`, across a 3-condition sample.
- **D-26:** Migration test per D-10.

### Claude's Discretion

- Exact helper placement for the mode-to-SQL-string conversion
  (free function, `impl` method, or inline `match`) — pick the
  cleanest per codebase idiom during execution.
- Exact wording of the extended warn-log message in
  `deserialize_policy_row` when a mode value is malformed.
- Whether `PolicyUpdateRow.mode` is `&str` or `&PolicyMode` — pick
  what matches the surrounding `PolicyUpdateRow` field style.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Roadmap
- `.planning/REQUIREMENTS.md` § POLICY-09 — user-visible contract (completed Phase 19)
- `.planning/REQUIREMENTS.md` § POLICY-12 — backward compatibility contract (this phase)
- `.planning/milestones/v0.5.0-ROADMAP.md` § Phase 18 — four success criteria
- `.planning/PROJECT.md` § Current Milestone: v0.5.0 Boolean Logic
- `.planning/STATE.md` § Decisions (2026-04-20 v0.5.0 entries) — engine-before-TUI split, flat-only boolean mode

### ABAC Core Types (dlp-common)
- `dlp-common/src/abac.rs` §9-46 — `Action`, `AccessContext` enums (serde pattern examples)
- `dlp-common/src/abac.rs` §48-82 — `Decision` enum (SCREAMING precedent for `PolicyMode`)
- `dlp-common/src/abac.rs` §114-168 — `Subject`, `Resource`, `Environment` (Default-derived precedent)
- `dlp-common/src/abac.rs` §213-247 — `PolicyCondition` enum (wire format via `#[serde(tag = "attribute")]`)
- `dlp-common/src/abac.rs` §249-268 — `Policy` struct (gains `mode` field + `Default` derive)

### Server: Wire Types & Handlers (dlp-server)
- `dlp-server/src/admin_api.rs` §97-112 — `PolicyPayload` (gains `mode` field)
- `dlp-server/src/admin_api.rs` §114-135 — `PolicyResponse` (gains `mode` field)
- `dlp-server/src/admin_api.rs` §568-648 — `create_policy` handler (wire `mode` through to DB insert)
- `dlp-server/src/admin_api.rs` §650-757 — `update_policy` handler (wire `mode` through to DB update)
- `dlp-server/src/admin_api.rs` §505-566 — `list_policies` / `get_policy` handlers (include `mode` in response)

### Server: Policy Store (dlp-server)
- `dlp-server/src/policy_store.rs` §30-55 — `PolicyStore` struct + `new()` constructor
- `dlp-server/src/policy_store.rs` §61-89 — `refresh`/`invalidate` (cache churn, unchanged)
- `dlp-server/src/policy_store.rs` §91-124 — `evaluate()` hot path — **this is the function that switches on mode**
- `dlp-server/src/policy_store.rs` §132-151 — `load_from_db` (skip-on-malformed pattern)
- `dlp-server/src/policy_store.rs` §153-178 — `deserialize_policy_row` — **extended to parse `mode` column**
- `dlp-server/src/policy_store.rs` §180-233 — `condition_matches`, `compare_op`, `memberof_matches` (unchanged for Phase 18)

### Server: Database (dlp-server)
- `dlp-server/src/db/mod.rs` §34-52 — `new_pool` — calls `init_tables` then will call new `run_migrations`
- `dlp-server/src/db/mod.rs` §59-204 — `init_tables` — `CREATE TABLE IF NOT EXISTS policies` gains `mode` column
- `dlp-server/src/db/repositories/policies.rs` §9-30 — `PolicyRow` struct (gains `mode: String` field)
- `dlp-server/src/db/repositories/policies.rs` §37-55 — `PolicyUpdateRow` struct (gains `mode: &str` field)
- `dlp-server/src/db/repositories/policies.rs` §60-234 — all SQL statements (list/insert/update extend column list to include `mode`)

### Prior Phase Context
- `.planning/phases/17-import-export/17-CONTEXT.md` — typed wire format pattern; `From<PolicyResponse> for PolicyPayload` conversion is the contract this phase extends with the `mode` field
- `.planning/STATE.md` § Patterns — `DB schema migrations: column adds via ALTER TABLE in dlp-server::db::open with NOT NULL DEFAULT for backward compat (no formal migration framework)`

### Test Infrastructure
- `dlp-server/src/policy_store.rs` §235+ — existing `#[cfg(test)]` module, `make_request` helper, `empty_store` helper (fixture shape that gains `..Default::default()` spread)
- `dlp-server/src/db/mod.rs` §206+ — existing `#[cfg(test)]` module (location for migration test per D-10)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `dlp_common::abac::Decision` — SCREAMING serde precedent (`ALLOW`/`DENY` + explicit `#[serde(rename)]` for compounds). Directly mirrored by `PolicyMode`.
- `dlp_common::abac::Subject` / `Resource` / `Environment` — `#[derive(Default)]` precedent. Extends naturally to `Policy`.
- `PolicyRepository::insert` / `update` / `list` pattern — simple SQL extension (append `mode` to column list and `params!` macro). No new repository method needed.
- `PolicyStore::invalidate` — already called by every create/update/delete handler; no new wiring.
- `skipped policy with malformed conditions` warn-log pattern — extends to cover malformed `mode` values without introducing a new error path.

### Established Patterns
- **Schema migrations** (`STATE.md § Patterns`): `ALTER TABLE` with `NOT NULL DEFAULT` for column adds. Phase 18 is the first phase to realize this pattern in code — `run_migrations()` becomes the canonical home.
- **Sync hot-path evaluator**: `PolicyStore::evaluate` stays sync (no `.await`). Mode switch is a cheap `match` on a `Copy` enum.
- **Serde defaults via `Default`**: The project already uses `#[derive(Default)]` + `#[default]` on enums (e.g., `DeviceTrust::Unmanaged`). `PolicyMode` follows the same idiom.
- **`spawn_blocking` for DB writes**: `create_policy` / `update_policy` already wrap DB work in `tokio::task::spawn_blocking`. The `mode` field flows through the existing cloned-fields pattern.

### Integration Points
- `dlp-common::abac::Policy` — one new field, breaks API; consumers (only `policy_store.rs` currently) updated.
- `dlp-server::admin_api::PolicyPayload` / `PolicyResponse` — one new field on each, `#[serde(default)]` shields all HTTP clients.
- `dlp-server::policy_store::evaluate` — `.all()` call replaced with `match` on mode.
- `dlp-server::db::mod::new_pool` — adds `run_migrations(&conn)?` after `init_tables(&conn)?`.
- `dlp-server::db::repositories::policies` — `PolicyRow` + `PolicyUpdateRow` grow a field; all SQL statements extend column list.
- `dlp-admin-cli` (TUI) — **no change in Phase 18**. Phase 19 adds the mode picker.

### v0.4.0 Wire Compatibility
- The admin TUI and `action_import_policies` from Phase 17 both POST/PUT `PolicyPayload`-shaped JSON without a `mode` field. D-14's `#[serde(default)]` means Phase 18 ships without requiring a coordinated TUI release — Phase 19 will add the field explicitly, but between 18 and 19 the TUI keeps authoring legacy-shaped bodies and the server silently defaults them to `ALL`. Behavior preserved.
- Existing Phase 17 `PolicyResponse` → `PolicyPayload` `From` conversion must copy the new `mode` field.

</code_context>

<specifics>
## Specific Ideas

- The planner should treat "first real ALTER TABLE migration" as a
  deliberate architectural choice. `run_migrations()` is a seed for
  future phases (e.g., Phase 20 may add an `operator_set` column if
  operator metadata ever needs persistence beyond the JSON conditions
  blob). Keep the function simple and idempotent.
- The `#[derive(Default)]` on `Policy` is a side-benefit decision —
  it makes the 15+ existing test fixtures in `policy_store.rs` survive
  the schema change via `..Default::default()` spread. Without it,
  each fixture needs an explicit `mode: PolicyMode::ALL`. The Default
  derive is the net-smaller diff.
- The SQLite "duplicate column name" error surface: rusqlite returns
  `rusqlite::Error::SqliteFailure` with extended error code `SQLITE_ERROR`
  and a message starting with `"duplicate column name:"`. The helper
  that swallows it should match on the message prefix (not the generic
  error code) to avoid swallowing unrelated `SQLITE_ERROR` conditions.
- Any `From<PolicyResponse> for PolicyPayload` conversion added in
  Phase 17 (`dlp-admin-cli`) must also copy the `mode` field — planner
  should include a task to update that conversion.

</specifics>

<deferred>
## Deferred Ideas

- **TUI mode picker** (`ALL` / `ANY` / `NONE` selector above the
  conditions list in Create/Edit forms) — Phase 19.
- **Expanded operators** (`gt`, `lt`, `ne`, `contains`) — Phase 20.
  The `PolicyCondition.op` wire field is already a free-form string;
  Phase 18 does not need to widen it.
- **In-place condition editing** — Phase 21.
- **Nested expression trees** (AND-of-ORs, etc.) — out of milestone
  scope per PROJECT.md.
- **Formal schema_version table** — deferred until the migration count
  justifies the infrastructure; `run_migrations()` with idempotent
  ADD COLUMN suffices for v0.5.0.
- **Mode validation on create/update** (forbid empty conditions under
  `ANY`/`NONE`) — considered and rejected (D-13). Revisit if
  operational feedback shows the iterator short-circuit semantics
  surprise users.
- **Batch import endpoint** (POLICY-F5) — still deferred to v0.5.x
  Server Hardening per STATE.md.

</deferred>

---

*Phase: 18-boolean-mode-engine-wire-format*
*Context gathered: 2026-04-20*
