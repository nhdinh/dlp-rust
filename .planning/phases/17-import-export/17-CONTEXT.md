# Phase 17: Import + Export - Context

**Gathered:** 2026-04-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Two admin-TUI capabilities to complete the policy authoring workflow (v0.4.0):

1. **Export (POLICY-07):** Read all policies via `GET /admin/policies` (existing endpoint),
   serialize with `serde_json::to_string_pretty`, and open a native file-save dialog
   with a default filename of `policies-export-{YYYY-MM-DD}.json`.

2. **Import (POLICY-08):** Open a native file-open dialog → parse JSON → call
   `GET /admin/policies` to retrieve existing IDs → compute conflict diff →
   display conflict summary → on admin confirm, POST non-conflicting and PUT
   conflicting policies → abort on any failure with which policy caused the error.
   Audit events emitted per policy via existing admin audit logging (R-09).

Both capabilities are reachable from the existing `PolicyMenu` alongside List/Create.
No server-side changes required — the `/admin/policies` CRUD endpoints already exist.

</domain>

<decisions>
## Implementation Decisions

### Import/Export UX Flow
- **D-01:** PolicyMenu gains two new entries: "Import Policies..." and "Export Policies..."
  alongside the existing List / Create items. They are top-level entries (not a
  sub-menu), matching the navigation pattern of PolicyList / PolicyCreate / PolicyEdit.
- **D-02:** Both are accessible only when authenticated (requires active session).
  Navigation to these entries fails gracefully if not authenticated (PolicyMenu
  already requires authentication — already enforced).

### Export (POLICY-07)
- **D-03:** `action_export_policies(app)` reads `GET /admin/policies` (uses
  `app.client.get::<Vec<PolicyResponse>>("admin/policies")` — same pattern as
  `action_list_policies`).
- **D-04:** Serializes the full policy set with `serde_json::to_string_pretty`
  — JSON only; TOML is blocked per STATE.md decision (serde tag incompatibility).
- **D-05:** Opens a native save dialog using a Rust dialog library. Default
  filename: `policies-export-{YYYY-MM-DD}.json`. File written in blocking task
  on `app.rt`.
- **D-06:** On success: show brief status message "Exported N policies to {filename}"
  then return to PolicyMenu. On failure: show error message and stay on PolicyMenu.

### Import (POLICY-08)
- **D-07:** `action_import_policies(app)` opens a native file-open dialog (filter: *.json).
- **D-08:** Parses the selected JSON file — expects `Vec<PolicyResponse>` matching the
  server schema (same format as export produces).
- **D-09:** Calls `GET /admin/policies` to get current IDs (conflict detection).
  Compute diff:
  - Non-conflicting: ID not in current server set → POST `/admin/policies`
  - Conflicting: ID already in server set → PUT `/admin/policies/{id}`
- **D-10:** Display a confirmation screen before committing:
  - "Import {N} policies?"
  - "{conflicting_count} will overwrite existing entries"
  - "[Confirm] / [Cancel]" row
- **D-11:** On confirm: apply POST/PUT per conflict diff. On any failure: abort,
  display which policy caused the error (e.g. "Failed on policy '{name}': {reason}"),
  do NOT commit partial results.
- **D-12:** Audit events emitted for each imported policy — handled automatically
  by existing admin audit logging infrastructure (server-side, no TUI code needed).
  The POST/PUT calls go to `/admin/policies` which triggers R-09 audit events.

### Import Conflict Screen Layout
- **D-13:** The conflict confirmation screen uses a new `Screen::ImportConfirm`
  variant holding: parsed policy list, current server IDs, selected row, and
  a validation-state enum (Pending / Confirmed / Error).
- **D-14:** Row layout:
  ```
  0: Import {N} Policies?
  1: {conflicting_count} will overwrite existing entries   (informational, bold)
  2: {non_conflicting_count} will be created as new          (informational, dim)
  3: [Confirm]    (Enter to proceed)
  4: [Cancel]     (Esc to abort)
  ```
  Section headers skip-nav pattern (same as PolicySimulate §D-15).

### File Dialog Library
- **D-15:** Use `rfd` (Rust File Dialog) crate for native file dialogs on Windows.
  `rfd` produces native OS dialogs and requires no extra permissions. Add as
  optional dependency (no-op on non-Windows builds).

### Form State
- **D-16:** No persistent state needed — each operation is stateless (read → display →
  confirm → write → return). PolicyStore cache invalidation happens server-side
  on each POST/PUT, so no explicit cache flush needed from TUI.

### Error Handling
- **D-17:** Import file parse error: display "Failed to parse JSON file: {reason}"
  and return to PolicyMenu.
- **D-18:** Network error on GET /admin/policies: display "Could not fetch current
  policies: {reason}" and return to PolicyMenu.
- **D-19:** POST/PUT failure: abort and display "Import failed on policy '{name}':
  {reason}". No policies committed if any one fails.

### Import Summary Screen (Post-Import)
- **D-20:** On successful import completion: show a summary status line
  "Imported {N} policies ({created} new, {updated} updated)" as a status
  message for 5 seconds, then return to PolicyMenu.

### Keyboard Bindings
- **D-21:** ImportConfirm: Up/Down nav (skip informational rows), Enter on
  Confirm row = proceed, Esc or Enter on Cancel row = abort.
- **D-22:** ExportConfirm: single-shot operation — no confirmation screen.
  "Export Policies..." entry → immediately executes, returns to PolicyMenu.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Server-Side Endpoints (No Changes)
- `dlp-server/src/admin_api.rs` §420–§443 — `/admin/policies` POST/GET/PUT/DELETE
  route mounts (already live)
- `dlp-server/src/admin_api.rs` §505–§536 — `list_policies` (GET /policies,
  used for conflict detection and export)
- `dlp-server/src/admin_api.rs` §568–§648 — `create_policy` (POST, generates
  audit event via R-09)
- `dlp-server/src/admin_api.rs` §650–§757 — `update_policy` (PUT, generates
  audit event via R-09)

### TUI Patterns (Copy-and-Adapt from Phase 14/15/16)
- `dlp-admin-cli/src/app.rs` §221–§240 — `Screen` enum variants (new
  `ImportConfirm` variant; existing `PolicyMenu` has "Import" and "Export" added)
- `dlp-admin-cli/src/app.rs` §153–§170 — `SimulateOutcome` enum pattern
  (can adapt for import result status)
- `dlp-admin-cli/src/screens/dispatch.rs` §450–§500 — `action_list_policies`
  (exact pattern for GET list → deserialize → process)
- `dlp-admin-cli/src/screens/dispatch.rs` — `handle_confirm` pattern (Phase 15
  §D-14, for `[Confirm]` / `[Cancel]` row nav and confirmation flow)
- `dlp-admin-cli/src/screens/dispatch.rs` — `handle_policy_simulate` (Phase 16
  §D-11: screen variant + caller enum + Esc routing; adapt for ImportConfirm)
- `dlp-admin-cli/src/screens/render.rs` §1137–§1192 — `draw_policy_list`
  (menu entry rendering pattern; adapt for PolicyMenu "Import" / "Export" rows)

### Policy Response Schema
- `dlp-server/src/admin_api.rs` §100–§140 — `PolicyResponse` struct (authoritative
  schema for import/export JSON)
- `dlp-server/src/admin_api.rs` §200–§280 — `PolicyPayload` struct (body sent
  on POST/PUT — id, name, description, priority, action, enabled, conditions)

### Requirements & Roadmap
- `.planning/REQUIREMENTS.md` § POLICY-07 — export scope
- `.planning/REQUIREMENTS.md` § POLICY-08 — import scope (conflict diff, abort-on-error)
- `.planning/ROADMAP.md` § Phase 17 — 5 success criteria

### Prior Phase Context
- `.planning/phases/16-policy-list-simulate/16-CONTEXT.md` — screen variant pattern
  (SimulateOutcome, SimulateCaller, entry points, Esc routing); section-header
  row-nav pattern for multi-row forms
- `.planning/phases/15-policy-edit-delete/15-CONTEXT.md` — handle_confirm pattern,
  delete-confirm UX for reference
- `.planning/STATE.md` § Decisions — `TOML export blocked` (JSON only);
  `Import: GET existing IDs before POST/PUT` (conflict detection strategy)

### State & Patterns
- `.planning/STATE.md` § Patterns — `TUI screens: ratatui + crossterm`;
  `generic get::<serde_json::Value> HTTP client pattern`; `generic post` used for
  typed requests
- `.planning/STATE.md` § Decisions — `chrono = "0.4" explicit dep` (admin-cli
  uses it for timestamps)

</canonical_refs>

<specifics>
## Specific Ideas

- For the file dialog: `rfd` crate is the standard Rust choice for native Windows file
  dialogs. Add to `dlp-admin-cli/Cargo.toml` as a dependency.
- The conflict diff computation is simple: for each policy in the imported file,
  check `existing_ids.contains(&policy.id)`. Collect into two vectors: `to_create`
  and `to_update`.
- Import confirm screen mirrors the `Confirm` screen pattern from Phase 15 (delete
  confirmation) but with a richer informational row showing conflict summary.
- Export uses the same `EngineClient::get` pattern as `action_list_policies`. No new
  HTTP client method needed.
- Import POST/PUT body format must match `PolicyPayload` (server-side). The JSON
  parsed from file is `Vec<PolicyResponse>` (GET response shape), but POST/PUT
  expects `PolicyPayload` (id, name, description, priority, action, enabled, conditions).
  Convert `PolicyResponse` → `PolicyPayload` before POST/PUT.
- Audit events: no TUI code needed. The server emits audit events on POST/PUT to
  `/admin/policies` (R-09 infrastructure). This is mentioned in ROADMAP §4 as a
  client requirement, but it's fulfilled by the server's existing behavior.

</specifics>

<deferred>
## Deferred Ideas

- **Batch import endpoint** (POLICY-F5): POST /admin/policies/import that accepts
  N policies in one call → single cache invalidation. Would also simplify
  conflict handling (server computes diff). Out of scope for v0.4.0; server changes
  deferred.
- **TOML export**: blocked by serde tag incompatibility — not solvable without
  changing PolicyCondition format which would break existing data.
- **Import preview screen** with full diff showing which fields would change on
  conflicting policies. Out of scope for v0.4.0 — just shows count.
- **Dry-run import**: show what would happen without making changes. Nice-to-have;
  defer to v0.5.0.

</deferred>

---

*Phase: 17-import-export*
*Context gathered: 2026-04-20*