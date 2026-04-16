# Roadmap: DLP-RUST

## Milestones

- ✅ **v0.2.0 Feature Completion** — Phases 0.1–12 (shipped 2026-04-13)
- ✅ **v0.3.0 Operational Hardening** — Phases 7–11 (shipped 2026-04-16)

## Progress

| Phase | Name | Milestone | Plans | Status | Completed |
|-------|------|-----------|-------|--------|----------|
| 0.1 | Fix clipboard monitoring runtime pipeline | v0.2.0 | — | Complete | 2026-04-10 |
| 1 | Fix integration tests | v0.2.0 | 1/1 | Complete | 2026-04-10 |
| 2 | Require JWT_SECRET in production | v0.2.0 | 1/1 | Complete | 2026-04-10 |
| 3 | Wire SIEM connector into server startup | v0.2.0 | 1/1 | Complete | 2026-04-10 |
| 3.1 | SIEM config in DB via dlp-admin-cli | v0.2.0 | 1/1 | Complete | 2026-04-10 |
| 4 | Wire alert router into server | v0.2.0 | 2/2 | Complete | 2026-04-11 |
| 04.1 | Full detection and intercept test suite | v0.2.0 | 3/3 | Complete | 2026-04-11 |
| 6 | Wire config push for agent config distribution | v0.2.0 | 2/2 | Complete | 2026-04-12 |
| 7 | Active Directory LDAP integration | v0.3.0 | 3/3 | Complete | 2026-04-16 |
| 8 | Rate limiting middleware | v0.3.0 | 1/1 | Complete | 2026-04-15 |
| 9 | Admin operation audit logging | v0.3.0 | 2/2 | Complete | 2026-04-14 |
| 10 | SQLite connection pool | v0.3.0 | 1/1 | Complete | 2026-04-15 |
| 11 | Policy Engine Separation | v0.3.0 | 4/4 | Complete | 2026-04-16 |
| 12 | Comprehensive DLP Test Suite | v0.2.0 | 3/3 | Complete | 2026-04-13 |
| 99 | Refactor DB Layer to Repository + Unit of Work | v0.3.0 | 3/3 | Complete | 2026-04-15 |

## v0.3.0 — Operational Hardening (Shipped)

<details>
<summary>✅ v0.3.0 — archived at <code>.planning/milestones/v0.3.0-ROADMAP.md</code></summary>

Phase details and requirement outcomes archived at `.planning/milestones/v0.3.0-ROADMAP.md` and `.planning/milestones/v0.3.0-REQUIREMENTS.md`.
</details>

_Archived milestone details: `.planning/milestones/v0.2.0-ROADMAP.md` and `.planning/milestones/v0.3.0-ROADMAP.md`_

## v0.4.0 — Policy Authoring (In Progress)

| Phase | Name | Goal | Requirements | Plans | Status |
|-------|------|------|--------------|-------|--------|
| 13 | Conditions Builder | 3-step sequential picker for building typed condition lists | POLICY-05 | 2 plans | Planning Complete |
| 14 | Policy Create | Multi-field create form with conditions attached | POLICY-02 | — | Not Started |
| 15 | Policy Edit + Delete | Load, edit, and delete existing policies from the TUI | POLICY-03, POLICY-04 | — | Not Started |
| 16 | Policy List + Simulate | Scrollable policy table and evaluate-request simulation form | POLICY-01, POLICY-06 | — | Not Started |
| 17 | Import + Export | JSON file-based batch import and full-policy-set export | POLICY-07, POLICY-08 | — | Not Started |

**Phase 13: Conditions Builder**
Goal: Provide a 3-step sequential picker for building typed PolicyCondition lists without any raw JSON entry.
Requirements: POLICY-05
Plans:
- [ ] 13-01-PLAN.md — Data model types (ConditionAttribute, CallerScreen, PolicyFormState, Screen::ConditionsBuilder) and dispatch handler with helpers and unit tests
- [ ] 13-02-PLAN.md — Render function (draw_conditions_builder modal overlay) and human visual verification
Success criteria:
1. Step 1 renders a selectable list of 5 attributes (Classification, MemberOf, DeviceTrust, NetworkLocation, AccessContext) and advances to Step 2 on Enter.
2. Step 2 renders only operators valid for the selected attribute; selecting one advances to Step 3.
3. Step 3 renders a typed value picker: T1-T4 for Classification, free-text for MemberOf, a 4-option select for DeviceTrust, a 4-option select for NetworkLocation, and a 2-option select for AccessContext.
4. After Step 3 confirmation, the completed condition appears in a pending-conditions list below the picker; the picker resets to Step 1.
5. Each condition in the pending list has a delete binding; no in-place edit is required in v0.4.0.
6. The conditions builder returns a Vec<PolicyCondition> to the caller form with no borrow-split issues (PolicyFormState struct used).

**Phase 14: Policy Create**
Goal: Multi-field form that creates a new policy with an attached condition list via the conditions builder.
Requirements: POLICY-02
Success criteria:
1. Form renders fields: name (required text), description (optional text), priority (required numeric), action (select: ALLOW / DENY / AllowWithLog / DenyWithLog).
2. A "Add Conditions" button/key opens the Phase 13 conditions builder; the resulting condition list is displayed below the button.
3. Submit validates that name is non-empty and priority is a valid integer; shows inline validation errors on failure.
4. Submit sends POST /admin/policies with a JSON body matching the server schema; on success, PolicyStore cache is invalidated and the user is returned to the policy list.
5. Network errors and server-side 4xx/5xx responses display descriptive text in the form rather than silently failing.

**Phase 15: Policy Edit + Delete**
Goal: Load an existing policy, modify any field, and delete policies - all from the policy list view.
Requirements: POLICY-03, POLICY-04
Success criteria:
1. Selecting a policy in the list and pressing `e` loads GET /admin/policies/{id}, populates all form fields (name, description, priority, action, enabled), and renders the existing conditions list with delete bindings.
2. Editing conditions uses the same conditions builder as create (delete-and-recreate pattern).
3. Submit sends PUT /admin/policies/{id}; cache is invalidated on success.
4. Pressing `d` on a list row shows "Delete policy '{name}'? [y/n]" and on `y` sends DELETE /admin/policies/{id}; cache is invalidated on success.
5. Both edit and delete require an active session; unauthenticated state redirects to login.

**Phase 16: Policy List + Simulate**
Goal: Provide a scrollable policy table and a standalone policy-simulation evaluate-request form.
Requirements: POLICY-01, POLICY-06
Success criteria:
1. The policy list renders a table with columns: Priority, Name, Action, Enabled; sorted by priority ascending; inline `n`/`e`/`d` key hints shown in a footer bar.
2. Simulate screen renders Subject fields (user_sid, user_name, groups, device_trust, network_location), Resource fields (path, classification), and Environment fields (action, access_context) with appropriate input types.
3. Submit sends POST /evaluate and renders the response: matched_policy_id (or "none"), decision, and reason.
4. Network failures and server 500 errors display descriptive text in the simulate form; no silent drops.
5. Simulate is accessible as a top-level menu item independent of the policy list.

**Phase 17: Import + Export**
Goal: Persist and restore the full policy set via JSON files with conflict detection.
Requirements: POLICY-07, POLICY-08
Success criteria:
1. Export reads GET /admin/policies, serializes with serde_json::to_string_pretty, and opens a save dialog with a default filename of `policies-export-{YYYY-MM-DD}.json`.
2. Import opens a file picker, parses the JSON, calls GET /admin/policies to retrieve current IDs, computes a conflict diff, and displays "N policies will overwrite existing entries" for admin confirmation.
3. On confirm, non-conflicting policies are POSTed and conflicting policies are PUT; on any failure the import aborts and reports which policy caused the error.
4. Audit events are emitted for each imported policy via the existing admin audit logging (R-09 infrastructure).
5. Import/export do not require a running agent; they operate purely through the admin API.
