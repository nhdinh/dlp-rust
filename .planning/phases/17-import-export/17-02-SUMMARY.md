---
wave: 2
status: complete
commits:
  - a5044c5 feat(phase-17): add PolicyResponse/PolicyPayload typed structs
  - 3dfb4e4 feat(phase-17): implement typed import execution with abort-on-error
---

# Phase 17 Wave 2 Summary — Import Execution

## What Shipped

- **Typed wire structs** in `dlp-admin-cli/src/app.rs`:
  - `PolicyResponse` — mirrors the server's `GET /admin/policies` shape;
    `version` and `updated_at` default via `#[serde(default)]`.
  - `PolicyPayload` — the `POST`/`PUT` body (drops `version` and
    `updated_at`); both `Serialize` and `Deserialize` for round-trip
    testing.
  - `From<PolicyResponse> for PolicyPayload` conversion.
- **`Screen::ImportConfirm.policies`** re-typed from
  `Vec<serde_json::Value>` to `Vec<PolicyResponse>`. The `existing_ids`
  field is now actively consumed (no more `#[allow(dead_code)]`).
- **`action_import_policies`** deserializes the imported JSON into
  `Vec<PolicyResponse>` and computes the conflict diff via direct
  `p.id` field access (no more string-key lookups into
  `serde_json::Value`).
- **`handle_import_confirm`** now executes the full import loop on
  Confirm:
  - Builds an O(1) `HashSet<String>` of existing server IDs.
  - Partitions imported policies into `to_create` (POST) and
    `to_update` (PUT) by set membership.
  - For each POST: convert `PolicyResponse -> PolicyPayload`, call
    `client.post::<serde_json::Value, _>("admin/policies", &payload)`.
  - For each PUT: `client.put::<..>("admin/policies/{id}", &payload)`.
  - Abort on first failure with
    `ImportState::Error("Failed on policy '{name}': {e}")`.
  - On success: `ImportState::Success { created, updated }`.
  - Enter/Esc from any terminal state returns to `PolicyMenu`.
- **4 unit tests** in `import_export_tests` module:
  - `policy_response_to_payload_drops_version_and_updated_at` — verifies
    conversion drops non-payload fields.
  - `policy_response_deserializes_from_server_json` — parses a full
    server-shaped policy.
  - `policy_response_missing_optional_fields_default` — verifies
    `version`/`updated_at` default when absent.
  - `policy_payload_roundtrip` — serializes then deserializes a payload.

## Verification

- `cargo check -p dlp-admin-cli` → clean
- `cargo build -p dlp-admin-cli` → clean
- `cargo clippy -p dlp-admin-cli -- -D warnings` → clean
- `cargo test -p dlp-admin-cli` → 26 passed; 0 failed (includes 4 new
  import/export tests)

## Deviations from 17-02-PLAN.md

- **API path correction**: plan used `"policies"` for POST/PUT; repo
  convention (Wave 1 export, existing `action_create_policy`,
  `action_update_policy`) is `"admin/policies"` and
  `"admin/policies/{id}"`. Wave 2 aligned with repo convention.
- **Borrow-checker reshuffle**: the plan's suggested `handle_import_confirm`
  body held `&mut app.screen` borrows while calling `app.rt.block_on`;
  reworked to re-enter the `if let` after each await to avoid the
  conflict.
- **Dropped `#[allow(dead_code)]`**: `ImportState::Success/Error` and
  `Screen::ImportConfirm::existing_ids` are all live in Wave 2.

## Full Phase 17 Outcome

All 5 Wave 1 tasks + 5 Wave 2 tasks shipped across 5 code commits +
2 summary docs. Milestone v0.3.0's final phase is complete. Next steps
are UAT, verification, and milestone completion — these are
orchestrated by `/gsd-verify-work` and `/gsd-complete-milestone`.
