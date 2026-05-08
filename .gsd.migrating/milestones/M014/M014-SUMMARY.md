---
id: M014
title: "v0.4.0 Policy Authoring"
status: complete
completed_at: 2026-05-08T05:53:30.354Z
key_decisions:
  - Typed import format: PolicyResponse/PolicyPayload with From conversion dropping version/updated_at
  - Skip-nav in ImportConfirm: first three rows non-selectable informational
  - Abort-on-first-failure: import stops at first error, prior successes already persisted
  - Native file dialogs via rfd = 0.14 for Windows save/open
  - Server route asymmetry: GET /policies for list, /admin/policies for POST/PUT/DELETE
key_files:
  - dlp-admin-cli/src/screens/render.rs
  - dlp-admin-cli/src/app.rs
  - dlp-server/src/admin_api.rs
lessons_learned:
  - Typed import/export format must be versioned and documented as authoritative schema
  - File dialogs require careful error handling for user cancellation
  - Import conflict diff must show clear before/after for admin decision
  - Route asymmetry (GET /policies vs /admin/policies) must be consistent across all clients
---

# M014: v0.4.0 Policy Authoring

**v0.4.0 Policy Authoring shipped with complete policy lifecycle in TUI.**

## What Happened

v0.4.0 delivered full admin policy-authoring workflow — list, create, edit, delete, simulate, import, export — all as typed forms with inline validation. No raw JSON editing required. All 8 requirements validated.

## Success Criteria Results

- Conditions builder working — PASS (S01)
- Policy create working — PASS (S02)
- Policy edit/delete working — PASS (S03)
- Policy list/simulate working — PASS (S04)
- Import/export working — PASS (S05)
- All 8 requirements validated — PASS (coverage audit)

## Definition of Done Results

All slices complete with verification evidence. All 8 requirements validated. Cross-slice integration verified. Milestone audit passed.

## Requirement Outcomes

| Requirement | Status | Evidence |
|-------------|--------|----------|
| POLICY-01 | validated | S04: Policy list with sort |
| POLICY-02 | validated | S02: Policy create form |
| POLICY-03 | validated | S03: Policy edit |
| POLICY-04 | validated | S03: Policy delete with confirmation |
| POLICY-05 | validated | S01: Conditions builder |
| POLICY-06 | validated | S04: Policy simulation |
| POLICY-07 | validated | S05: Export to JSON |
| POLICY-08 | validated | S05: Import with conflict detection |

## Deviations

TOML export deferred as POLICY-F4 due to serde tag incompatibility with toml crate.

## Follow-ups

TOML export format (POLICY-F4). Batch import endpoint (POLICY-F5). Typed Decision action field (POLICY-F6).
