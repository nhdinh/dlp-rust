# Domain Pitfalls: v0.4.0 Policy Authoring TUI

**Domain:** Adding policy authoring UX to an existing ratatui TUI system
**Researched:** 2026-04-16
**Codebase version:** v0.4.0 (post v0.3.0 operational hardening)

---

## Critical Pitfalls

These mistakes cause silent data corruption, server desync, or full rewrites.

---

### PITFALL-01: PolicyCondition JSON Shape Must Match the `#[serde(tag)]` Contract Exactly

**What goes wrong:**
`PolicyCondition` uses `#[serde(tag = "attribute", rename_all = "snake_case")]`. This means the
serialized form of a `Classification` condition is:

```json
{"attribute": "classification", "op": "eq", "value": "T3"}
```

The `attribute` tag field drives deserialization on the server. If the conditions builder emits
ANY other shape — e.g., `{"type": "classification", ...}`, or omits `"attribute"`, or uses
`"Classification"` (PascalCase) instead of `"classification"` — the server's
`serde_json::from_str::<Vec<PolicyCondition>>` in `deserialize_policy_row` will fail silently.
The `load_from_db` path logs a `warn!` and **skips the policy** rather than returning an error.
The admin sees "Policy created" but the policy is never evaluated.

**Root cause:**
The TUI builds conditions as `serde_json::Value` objects (passed through `PolicyPayload.conditions`),
so there is no compile-time type check. The conditions builder must manually construct JSON that
matches the server's enum tag schema.

**Exact required shapes (from `abac.rs`):**

| Variant | Required JSON shape |
|---------|---------------------|
| `Classification` | `{"attribute":"classification","op":"eq","value":"T3"}` — `value` must be `"T1"/"T2"/"T3"/"T4"` (UPPERCASE, from `#[serde(rename_all = "UPPERCASE")]` on `Classification`) |
| `MemberOf` | `{"attribute":"member_of","op":"in","group_sid":"S-1-5-..."}` — uses `group_sid` not `value` |
| `DeviceTrust` | `{"attribute":"device_trust","op":"eq","value":"Managed"}` — value must be PascalCase (`Managed/Unmanaged/Compliant/Unknown`) |
| `NetworkLocation` | `{"attribute":"network_location","op":"eq","value":"Corporate"}` — PascalCase (`Corporate/CorporateVpn/Guest/Unknown`) |
| `AccessContext` | `{"attribute":"access_context","op":"eq","value":"local"}` — lowercase (`local/smb`, from `#[serde(rename_all = "lowercase")]`) |

**Prevention:**
- The conditions builder must serialize each completed condition through `serde_json::to_value`
  of the actual `PolicyCondition` enum, not hand-craft strings. Construct a `PolicyCondition`
  variant in Rust and call `serde_json::to_value` — the compiler enforces the field names.
- Unit test: round-trip each variant through `serde_json::to_string` then
  `serde_json::from_str::<PolicyCondition>` and assert the tag value.

**Phase:** Policy Conditions Builder (POLICY-05)

---

### PITFALL-02: N Invalidations on Import of N Policies

**What goes wrong:**
The import flow calls `POST /policies` once per policy in the file. Each call succeeds and the
server handler calls `state.policy_store.invalidate()` after every individual write. For a 50-policy
import file, this triggers 50 sequential DB reads inside `load_from_db` — each acquires the
r2d2 pool, re-reads the entire `policies` table, and swaps the `RwLock<Vec<Policy>>` 50 times.
The last 49 invalidations are wasted work. On slow storage this adds visible latency. More
importantly, each invalidation acquires a **write lock** on the cache, blocking any concurrent
`POST /evaluate` call for the duration of the reload.

**Root cause:**
The existing CRUD handlers each invalidate immediately — correct for single operations but
wrong for bulk operations. The TUI import path loops over parsed policies and calls
`client.post("policies", &payload)` one at a time, inheriting per-call invalidation.

**Consequences:**
- Evaluation requests blocked for 50 x (SQLite read time) during import.
- Unnecessary load on SQLite connection pool.

**Prevention:**
- Add a `POST /admin/policies/import` batch endpoint on the server that inserts all policies
  in a single `UnitOfWork` transaction and calls `invalidate()` exactly once after the
  transaction commits.
- The TUI import action calls this single endpoint with the parsed policy array. If a batch
  endpoint is not added, the TUI must buffer all policies in memory, issue the N individual
  POSTs, then display a single progress indicator — but it cannot avoid N invalidations without
  server-side support.
- Do NOT batch individual POST calls and call a separate "refresh" endpoint — this creates a
  window where policies are partially committed but the cache has not been updated.

**Phase:** Policy Import/Export (POLICY-07/08)

---

### PITFALL-03: Import Conflict Creates Duplicate IDs / Wrong Version

**What goes wrong:**
`PolicyPayload.id` is caller-supplied on `POST /policies`. If the export file contains existing
IDs and the admin imports without conflict detection, `PolicyRepository::insert` calls
`INSERT INTO policies ... VALUES (...)` with a duplicate primary key. SQLite returns
`UNIQUE constraint failed: policies.id`, the server returns `500`, and the TUI shows "Failed"
with no indication of which policy ID collided or how many succeeded before the failure.

**Root cause:**
The current `create_policy` handler does not detect duplicates before inserting. The DB error
surfaces as a generic `AppError::Database`.

**Consequences:**
- Partial import: some policies land, the rest fail silently with the same opaque error.
- Admin cannot distinguish "policy already exists" from "server error".

**Prevention:**
- Import screen must: (1) call `GET /policies` first to fetch existing IDs, (2) diff the file
  against existing IDs, (3) present a conflict report showing `count_new`, `count_conflict`,
  `count_update` before committing anything.
- The batch import endpoint (see PITFALL-02) should accept a `conflict_strategy` parameter:
  `"skip"` (ignore duplicates), `"overwrite"` (upsert), or `"abort"` (reject the whole batch
  if any duplicate exists).
- The TUI import screen must expose this choice as a picker before committing the import.

**Phase:** Policy Import/Export (POLICY-08)

---

### PITFALL-04: Screen Variant Borrow Split — Editing State Left Behind

**What goes wrong:**
The existing `SiemConfig` and `AlertConfig` screens use a `(selected, editing, buffer)` triple
inline in the `Screen` enum variant. The new policy create/edit forms will have more fields
(name, description, priority, action, enabled, plus a variable-length conditions list). The
pattern used in the existing code — `let (selected, editing) = match &app.screen { ... }` then
a second mutable borrow inside the match arm — fails at larger scale when multiple mutable
fields need simultaneous update.

In the `handle_siem_config_editing` handler, `selected` is copied out before the mutable borrow
of `app.screen`. This works for two fields but becomes error-prone when the form has 6+ fields
and cursor focus must be shared between the top-level form fields and a nested conditions list.
The risk: a key-event handler updates `editing = false` but forgets to clear `buffer`, leaving
stale data pre-filled when the user reopens a field.

**Prevention:**
- Introduce a dedicated `PolicyFormState` struct (not inline in `Screen`) containing all mutable
  form state: `fields: Vec<String>`, `focused_field: usize`, `conditions: Vec<ConditionDraft>`,
  `focused_condition: Option<usize>`, `condition_focus: ConditionCursor`.
- Store `Box<PolicyFormState>` inside the `Screen::PolicyCreate` and `Screen::PolicyEdit`
  variants to keep the `Screen` enum clone cheap.
- Introduce a `clear_edit_state()` method on `PolicyFormState` called on every Esc press.

**Phase:** Policy CRUD Forms (POLICY-02, POLICY-03)

---

### PITFALL-05: Condition Builder Focus Trap — Incomplete Condition Submitted

**What goes wrong:**
A three-step picker (attribute → operator → value) must enforce that all three steps are
complete before a condition can be added. In a ratatui form, the user can press Enter to
"add condition" at step 1 or 2 if the handler does not validate completeness. An incomplete
condition — e.g., `{"attribute":"classification"}` without `"op"` or `"value"` — will fail
deserialization on the server and the policy will be silently skipped by `load_from_db`
(see PITFALL-01).

Additionally, after completing step 3 (value selection), the cursor must return to the
conditions list, not stay inside the value picker. Failure to reset the `ConditionCursor` state
causes the picker to appear to accept a second value when the user presses Down, adding a
duplicate or overwriting the just-completed condition.

**Prevention:**
- Model the condition builder as a state machine: `Idle → AttributePicked(attr) →
  OperatorPicked(attr, op) → Complete(condition)`. Only the `Complete` state can be appended
  to `conditions`. The "Add" button is only focusable when the state is `Idle` or `Complete`.
- After completing step 3, immediately reset to `Idle` and shift focus to the conditions list.
- The `conditions` list in the form state must hold `Vec<PolicyCondition>` (typed), not
  `Vec<serde_json::Value>`, so incompleteness is caught at the type level before serialization.

**Phase:** Conditions Builder (POLICY-05)

---

### PITFALL-06: Action String Mismatch — Server Silently Downgrades to DENY

**What goes wrong:**
`deserialize_policy_row` in `policy_store.rs` maps the `action` string to a `Decision` via
a hand-written `match`:

```rust
"allow" => Decision::ALLOW,
"deny" => Decision::DENY,
"allow_with_log" | "allowwithlog" => Decision::AllowWithLog,
"deny_with_alert" | "denywithalert" => Decision::DenyWithAlert,
_ => Decision::DENY,  // silent fallback
```

The mapping is case-insensitive on the input (`to_lowercase()`), but the TUI must not emit
arbitrary strings. If the picker emits `"ALLOW_WITH_LOG"` (from a `Decision` `Display` or
debug representation) instead of `"Allow_With_Log"` or `"allow_with_log"`, it will match the
`"allow_with_log"` arm. But if it emits `"AllowWithLog"` without an underscore, it hits only
the `"allowwithlog"` arm — subtle and easy to miss. The `_ => Decision::DENY` catch-all means
a misnamed action silently becomes DENY, which is a security-relevant behavior change with no
error.

**Prevention:**
- The action picker must map display labels to the exact lowercase strings the server accepts:
  `"allow"`, `"deny"`, `"allow_with_log"`, `"deny_with_alert"`.
- Add a unit test asserting that every possible picker output round-trips through
  `deserialize_policy_row` to the expected `Decision` variant.
- Alternatively, change `PolicyPayload.action` to accept `Decision` directly (serde handles
  it) and remove the hand-written match. This is a server-side change but eliminates the class
  of bugs entirely.

**Phase:** Policy CRUD Forms (POLICY-02, POLICY-03)

---

## Moderate Pitfalls

---

### PITFALL-07: Export Includes `version` and `updated_at` — Import Rejects or Misuses Them

**What goes wrong:**
`PolicyResponse` (the GET response shape) includes `version: i64` and `updated_at: String`.
If the export file is a direct serialization of `Vec<PolicyResponse>` and the import path
deserializes each entry as `PolicyPayload`, `serde` will fail on unknown fields if
`PolicyPayload` uses `#[serde(deny_unknown_fields)]`, or silently ignore them otherwise.
More dangerously: if the import passes `version` through as part of the POST body, the server
currently ignores it (version is set to 1 on insert), but future schema changes could cause
conflicts.

Additionally, exporting `updated_at` from one environment and importing into another means the
timestamp in the DB does not reflect when the import happened — audit trails become misleading.

**Prevention:**
- Define a dedicated export schema (`PolicyExport`) that includes only the fields needed for
  re-import: `id`, `name`, `description`, `priority`, `conditions`, `action`, `enabled`.
  Exclude `version`, `updated_at`. Derive `Serialize`/`Deserialize` on `PolicyExport` in
  `dlp-common`.
- The export action serializes `Vec<PolicyExport>` to TOML or JSON.
- The import action deserializes `Vec<PolicyExport>` and maps each to `PolicyPayload`.

**Phase:** Policy Import/Export (POLICY-07/08)

---

### PITFALL-08: TOML Serialization of Conditions Array Loses Type Tag

**What goes wrong:**
`PolicyCondition` uses `#[serde(tag = "attribute")]` (internally tagged). The `toml` crate
(v0.5/v0.8) does not support internally tagged enums when the inner value is not a map — this
is a known limitation of `toml-rs`. Attempting to serialize `Vec<PolicyCondition>` via
`toml::to_string` panics or produces `Error::UnsupportedType` at runtime.

**Prevention:**
- For TOML export: serialize conditions as a `serde_json::Value` first (via
  `serde_json::to_value`), then include the raw JSON string inside the TOML document as a
  `conditions_json` text field. On import, parse the JSON string back to
  `Vec<PolicyCondition>`.
- Alternatively, use JSON as the only export format and offer "TOML" as a display-only feature.
  This is simpler and avoids the `toml` crate limitation entirely.
- Do not attempt to round-trip `PolicyCondition` through `toml::to_string` / `toml::from_str`
  directly.

**Phase:** Policy Import/Export (POLICY-07/08) — HIGH priority design decision before coding

---

### PITFALL-09: Simulate Form Uses Stale Cache, Not Live Server State

**What goes wrong:**
The simulate/dry-run screen calls `POST /evaluate`. The `/evaluate` endpoint is NOT under
`/admin/` — it is the unauthenticated evaluation endpoint (see `admin_api.rs` line 395). It
evaluates against the server's `PolicyStore` cache. If the admin just created a policy but the
background refresh interval (300s) has not fired yet, `/evaluate` will use the cache built
before the CRUD write. However, `invalidate()` is called immediately after each CRUD write, so
the cache IS current — this is only a risk if the admin is using a read-only replica that does
not receive push-sync from `PolicySyncer`.

The real risk is that the simulate form requires the admin to manually fill in a complete
`EvaluateRequest` with `subject.user_sid`, `subject.groups` (SID array), `resource.path`,
`resource.classification`, `environment.timestamp`, `environment.session_id`,
`environment.access_context`, and `action`. If any required field is missing or incorrectly
typed, the server returns a deserialization error. The TUI must not allow the admin to submit
with empty required fields.

**Prevention:**
- Pre-populate the `EvaluateRequest` form with sensible defaults: `timestamp = Utc::now()`,
  `session_id = 1`, `access_context = Local`, `device_trust = Managed`,
  `network_location = Corporate`, `action = COPY`.
- Required fields that must be filled: `user_sid` (non-empty string check), `resource.path`
  (non-empty), `resource.classification` (picker, not free-text).
- Show the `EvaluateResponse.reason` and `matched_policy_id` prominently in the result view.

**Phase:** Policy Simulate (POLICY-06)

---

### PITFALL-10: Esc From Create/Edit Form — Unsaved State Warning Not Present in Current Pattern

**What goes wrong:**
The current Esc handlers (e.g., `handle_siem_config_nav`) immediately transition to the parent
screen with no confirmation. For a SIEM config with 7 fields this is acceptable — the admin
can re-navigate quickly. For a policy create form with a name, description, priority, action,
and a conditions list containing multiple completed conditions, silently discarding on Esc is
a poor UX that will cause accidental data loss.

**Prevention:**
- When the form has any non-default state (any field non-empty, or conditions list non-empty),
  Esc should transition to a `Confirm { message: "Discard unsaved policy?", purpose:
  DiscardPolicyForm }` screen rather than directly to `PolicyMenu`.
- Implement `PolicyFormState::is_dirty() -> bool` that returns true when any field differs
  from its initial value.
- The `DiscardPolicyForm` confirm purpose transitions to `PolicyMenu { selected: 0 }` on Yes
  and returns to the form on No.

**Phase:** Policy CRUD Forms (POLICY-02, POLICY-03)

---

### PITFALL-11: `block_on` in Event Loop Freezes Terminal Render During HTTP Calls

**What goes wrong:**
The existing dispatch handlers call `app.rt.block_on(...)` synchronously during key event
processing. For fast local operations this is invisible. For the import flow (N sequential
HTTP POSTs) or for the simulate call (network round trip to server), the terminal is
completely frozen for the duration. The user sees no progress and cannot cancel.

This is the same pattern already in use for SIEM config save (a single PUT), which is
acceptable because it completes in <100ms. An import of 50 policies with N invalidations
could block for 2-5 seconds.

**Prevention:**
- For multi-step operations (import with N items), show a progress message in the status bar
  before starting: `app.set_status("Importing 50 policies...", StatusKind::Info)`.
- After the blocking call returns, show the result count:
  `"Imported 48/50 policies (2 conflicts skipped)"`.
- Do not implement background tasks or tokio channels for this — the single-threaded TUI model
  is intentional. The batch import endpoint (PITFALL-02) is the correct solution because it
  reduces N blocking calls to 1.

**Phase:** Policy Import/Export (POLICY-08)

---

### PITFALL-12: Policy List Shows Stale Data After CRUD

**What goes wrong:**
`Screen::PolicyList` stores `policies: Vec<serde_json::Value>` in the enum variant. After
creating, updating, or deleting a policy, navigating back to `Screen::PolicyList` shows the
previously fetched list — not the updated state. The existing implementation navigates to
`PolicyMenu` after CRUD (not back to `PolicyList`), so the admin must manually re-list. This
is acceptable for the current file-based workflow but becomes a UX problem when the TUI
supports inline create/edit.

**Prevention:**
- After a successful create, edit, or delete operation, call `action_list_policies(app)` to
  automatically refresh and navigate to `PolicyList`.
- Do not cache the list in the screen variant across navigation events — always re-fetch on
  entry to `PolicyList`.

**Phase:** Policy CRUD Forms (POLICY-02, POLICY-03, POLICY-04)

---

## Minor Pitfalls

---

### PITFALL-13: `priority: u32` in Form — Free-Text Field Accepts Non-Numeric Input

**What goes wrong:**
The existing numeric field handling (demonstrated by `smtp_port` in `AlertConfig`) requires
explicit `alert_is_numeric` classification and parse-on-commit. If the policy create form
treats `priority` as a plain text field (like the existing `TextInput` screen), the admin can
enter `"high"` and the server rejects the payload at the `u32` deserialization step with a
400 response. The error message from the server (`"Failed to parse priority as u32"`) may
not surface clearly in the status bar.

**Prevention:**
- Classify the priority field as numeric in the form row classifier, identical to
  `smtp_port`. Parse on commit and reject non-numeric input in the TUI before sending the
  request.

**Phase:** Policy CRUD Forms (POLICY-02, POLICY-03)

---

### PITFALL-14: `description: Option<String>` — Empty String vs. Absent

**What goes wrong:**
`PolicyPayload.description` is `Option<String>`. The server stores `NULL` in SQLite when
`None`. If the TUI form commits an empty string as `description: Some("")`, the server stores
an empty string (not `NULL`), and a subsequent GET returns `"description": ""` instead of
`null`. This breaks the TUI's display logic if it uses `Option::is_none()` to decide whether
to show the description row.

**Prevention:**
- Normalize the description field before sending: if the input buffer is empty or all
  whitespace, set `description: None` in the payload. The form state should represent
  description as `String` (buffer) and convert to `Option<String>` only at submission.

**Phase:** Policy CRUD Forms (POLICY-02, POLICY-03)

---

### PITFALL-15: Export File Path Validation — Windows Path Separators in TUI Input

**What goes wrong:**
The export/import screens accept a file path from the user via the existing `TextInput` screen
pattern. On Windows, paths use backslashes (`C:\Exports\policies.json`), but users may also
type forward slashes. `std::fs::write` and `std::fs::read_to_string` on Windows accept both
forms. The problem is path display: if the TUI renders the raw input buffer in the status bar
as `"Exported to C:\E..."` the backslash may be interpreted as an escape in terminal output.

**Prevention:**
- Display the canonical path via `std::path::Path::display()` in the status message, not the
  raw input string.
- Validate that the parent directory exists before attempting to write; report a clear error
  if it does not.

**Phase:** Policy Import/Export (POLICY-07/08)

---

## Phase-Specific Warning Matrix

| Phase | Requirement | Pitfall | Mitigation |
|-------|-------------|---------|------------|
| Conditions Builder | POLICY-05 | PITFALL-01: Wrong JSON tag shape | Serialize via `serde_json::to_value::<PolicyCondition>`, not hand-crafted JSON |
| Conditions Builder | POLICY-05 | PITFALL-05: Incomplete condition submitted | State-machine approach; only `Complete` state appends to list |
| Conditions Builder | POLICY-05 | PITFALL-06: Action string mismatch | Picker maps display labels to exact server-accepted strings; unit test every action string |
| Policy CRUD Forms | POLICY-02/03 | PITFALL-04: Borrow split with complex state | `PolicyFormState` struct, not inline variant fields |
| Policy CRUD Forms | POLICY-02/03 | PITFALL-10: Silent Esc discard | `is_dirty()` guard before Esc; confirmation dialog |
| Policy CRUD Forms | POLICY-02/03 | PITFALL-13: Non-numeric priority input | Numeric field classification; parse on commit |
| Policy CRUD Forms | POLICY-02/03 | PITFALL-14: Empty string vs. None | Normalize empty → `None` at submission |
| Policy CRUD Forms | POLICY-02/03/04 | PITFALL-12: Stale list after CRUD | Auto-refresh list after every successful write |
| Policy Simulate | POLICY-06 | PITFALL-09: Incomplete EvaluateRequest | Sensible defaults pre-populated; required field guards |
| Policy Import | POLICY-08 | PITFALL-02: N cache invalidations | Batch import endpoint with single `invalidate()` after transaction |
| Policy Import | POLICY-08 | PITFALL-03: Duplicate ID collision | Pre-import conflict diff; conflict strategy picker |
| Policy Import/Export | POLICY-07/08 | PITFALL-07: `version`/`updated_at` in export | Dedicated `PolicyExport` schema without server-managed fields |
| Policy Import/Export | POLICY-07/08 | PITFALL-08: TOML + internally-tagged enum | Use JSON only, or store conditions as JSON string inside TOML |
| Policy Import | POLICY-08 | PITFALL-11: Terminal freeze during bulk import | Batch endpoint reduces N calls to 1; progress status before call |
| Policy Import/Export | POLICY-07/08 | PITFALL-15: Windows path in status bar | `Path::display()` for output; parent dir validation |

---

## Integration Pitfalls: TUI Client vs. PolicyStore Cache

The following summarize the integration contract between the TUI client and the server's
`PolicyStore`:

**Contract 1 — Invalidation is after-write, not before-write.**
`policy_store.invalidate()` is called after `UnitOfWork.commit()` succeeds. If the TUI calls
`GET /policies` immediately after a POST (e.g., to refresh the list), it will see the new
policy because the cache is already updated. There is no race between write and read here for
single operations.

**Contract 2 — Bulk import breaks the single-invalidation contract.**
The current per-handler `invalidate()` call is correct for single writes. N sequential POST
calls from the TUI break this — each triggers a full cache reload. The only correct fix is a
server-side batch endpoint.

**Contract 3 — `load_from_db` silently skips malformed rows.**
A conditions blob that fails `serde_json::from_str::<Vec<PolicyCondition>>` causes the policy
to be skipped with a `warn!` log. From the TUI's perspective, the POST returned `201 Created`,
the cache was invalidated, but the policy is absent from evaluation. The TUI must not rely on
"POST succeeded" as proof the policy is active — it should verify by calling
`GET /policies/{id}` and checking that the conditions field matches what was sent.

**Contract 4 — Background refresh interval is 300 seconds.**
If the TUI and a direct SQLite modification happen concurrently (e.g., a migration script),
the cache may be stale for up to 5 minutes. For manual admin operations through the TUI this
is not a risk because every TUI write calls `invalidate()` synchronously.

**Contract 5 — `POST /evaluate` is unauthenticated and uses the in-process PolicyStore.**
The simulate feature calls the live evaluation endpoint, not a separate dry-run path. The result
reflects the server's current cache at the moment of the call. This is the desired behavior
but means the simulate result can differ from what the admin expects if the server is a replica
that has not yet received the push-synced policy from `PolicySyncer`.
