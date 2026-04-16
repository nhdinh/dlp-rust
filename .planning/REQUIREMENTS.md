# v0.4.0 Requirements — Policy Authoring

**Milestone:** v0.4.0 Policy Authoring
**Started:** 2026-04-16

---

## Traceability

| REQ-ID | Requirement | Phase | Status |
|--------|-------------|-------|--------|
| POLICY-01 | Policy list & detail screen | TBD | — |
| POLICY-02 | Policy create form | TBD | — |
| POLICY-03 | Policy edit form | TBD | — |
| POLICY-04 | Policy delete | TBD | — |
| POLICY-05 | Conditions builder | TBD | — |
| POLICY-06 | Policy simulate | TBD | — |
| POLICY-07 | Export to JSON file | TBD | — |
| POLICY-08 | Import from JSON file | TBD | — |

---

## v0.4.0 Requirements

### Policy CRUD (TUI Screens)

- [ ] **POLICY-01**: Admin can list all policies in a scrollable table with name, priority, action, and enabled state. Table is sorted by priority ascending. Inline action keys: `n` (new), `e` (edit), `d` (delete) available from the list view without navigating to a separate menu.

- [ ] **POLICY-02**: Admin can create a new policy via a multi-field form with: name (required text), description (optional text), priority (numeric, required), action (select: ALLOW / DENY / AllowWithLog / DenyWithAlert), and one or more typed conditions added via the conditions builder (POLICY-05). Form submits via POST /admin/policies. PolicyStore cache is invalidated after successful commit.

- [ ] **POLICY-03**: Admin can edit an existing policy by loading it from GET /admin/policies/:id and modifying any field (name, description, priority, action, enabled flag, conditions). Form submits via PUT /admin/policies/{id}. PolicyStore cache is invalidated after successful commit.

- [ ] **POLICY-04**: Admin can delete a policy with a confirmation prompt ("Delete policy '{name}'? [y/n]"). The delete action is reachable directly from the policy list via the `d` keypress. Form submits via DELETE /admin/policies/{id}. PolicyStore cache is invalidated after successful commit.

### Conditions Builder

- [ ] **POLICY-05**: Admin can build policy conditions using a 3-step sequential picker (no raw JSON entry at any step):
  - **Step 1 — Select Attribute**: List of 5 options: Classification, MemberOf, DeviceTrust, NetworkLocation, AccessContext.
  - **Step 2 — Select Operator**: Dynamically filtered by attribute (e.g., Classification → `eq`; MemberOf → `eq`; DeviceTrust → `eq`). Note: the ABAC engine currently only evaluates `eq` — other operators are shown but noted as not yet enforced.
  - **Step 3 — Select Value**: Typed picker per attribute:
    - `Classification`: T1, T2, T3, T4
    - `MemberOf`: text input for AD group SID
    - `DeviceTrust`: Managed, Unmanaged, Compliant, Unknown
    - `NetworkLocation`: Corporate, CorporateVpn, Guest, Unknown
    - `AccessContext`: Local, Smb
  - After Step 3, the condition is added to the pending list. Admin can add multiple conditions. Existing conditions can be removed (delete-and-recreate, no in-place edit in v0.4.0).
  - All conditions are evaluated as implicit AND (documented in help text). NOT/OR boolean logic is deferred to v0.5.0.

### Policy Simulation

- [ ] **POLICY-06**: Admin can simulate a policy decision by filling an EvaluateRequest form with:
  - Subject fields: user_sid (text), user_name (text), groups (comma-separated AD SIDs), device_trust (select), network_location (select)
  - Resource fields: path (text), classification (select: T1/T2/T3/T4)
  - Environment fields: action (select: READ/WRITE/COPY/DELETE/MOVE/PASTE), access_context (Local/Smb)
  Form submits via POST /evaluate. Response displays: matched_policy_id (or "none"), decision, reason. Error states (network failure, server 500) are shown with descriptive text, not silently dropped.

### Import / Export

- [ ] **POLICY-07**: Admin can export the full policy set to a JSON file. Uses GET /admin/policies → serde_json::to_string_pretty → file save dialog (filename: `policies-export-{YYYY-MM-DD}.json`). Existing policies can be exported at any time; no server-side state change.

- [ ] **POLICY-08**: Admin can import policies from a JSON file. Flow: open file dialog → parse JSON → call GET /admin/policies to get existing IDs → compute conflict diff (existing IDs in file vs. current DB) → display conflict summary ("{N} policies will overwrite existing entries") → confirm → POST /admin/policies for each non-conflicting, PUT /admin/policies/{id} for each conflicting. On any failure, abort and report which policy caused the error. Audit events are emitted for each imported policy (handled by the existing admin audit logging from R-09).

---

## Future Requirements (Deferred)

These are out of scope for v0.4.0 but noted for future milestones:

- **POLICY-F1**: AND/OR/NOT boolean logic between conditions
- **POLICY-F2**: In-place condition editing (select condition from list → re-enter Step 1-3) — v0.4.0 uses delete-and-recreate
- **POLICY-F3**: Per-condition operator list (gt, lt, ne, contains) — engine does not support these yet
- **POLICY-F4**: TOML export format — blocked by `toml` crate incompatibility with `#[serde(tag = "attribute")]` PolicyCondition format
- **POLICY-F5**: Batch import endpoint (POST /admin/policies/import) — avoids N cache invalidations on bulk import
- **POLICY-F6**: Typed `Decision` action field in server (eliminates `_ => DENY` silent fallback)

---

## Open Design Decisions

| Decision | Recommendation | Phase |
|----------|----------------|-------|
| Import conflict strategy: PUT vs delete-then-insert | PUT preserves version history and audit trail | Phase E |
| In-place condition editing vs. delete-and-recreate | Delete-and-recreate for v0.4.0 | Phase B |
| Export format | JSON only (TOML blocked by serde limitation) | Phase E |
| Non-eq operator exposure in conditions builder | Show all operators but label as "not yet enforced" | Phase A |
| Action field typed vs. string | Keep String for v0.4.0 (server change deferred) | Future |

---

## Dependencies

- All POLICY requirements depend on POLICY-05 (conditions builder) because create, edit, and import all add conditions
- POLICY-06 (simulate) has no dependency on POLICY-05 — it fills an EvaluateRequest which already has a fixed schema
- POLICY-07/08 (import/export) depend on POLICY-02/03 (create/edit) being complete