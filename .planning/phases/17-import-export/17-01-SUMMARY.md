---
wave: 1
status: complete
commits:
  - 7ae7a2b feat(phase-17): add rfd dependency for native file dialogs
  - 0390e50 feat(phase-17): add ImportConfirm screen types
  - 7290481 feat(phase-17): wire PolicyMenu import/export actions and render ImportConfirm
---

# Phase 17 Wave 1 Summary — Export + ImportConfirm Screen

## What Shipped

- **rfd = "0.14"** added to `dlp-admin-cli/Cargo.toml` for native Windows
  file dialogs (no extra permissions required).
- **Import/Export supporting types** in `dlp-admin-cli/src/app.rs`:
  - `ImportCaller::PolicyMenu` (Esc return routing)
  - `ImportState { Pending, InProgress, Success { created, updated }, Error(String) }`
  - `Screen::ImportConfirm { policies, existing_ids, conflicting_count,
    non_conflicting_count, selected, state, caller }`
- **PolicyMenu** expanded from 7 to 9 entries. Navigation count updated,
  new match arms call `action_import_policies` (row 6) and
  `action_export_policies` (row 7); Back moved to row 8.
- **Export action** (`action_export_policies`): GET `/admin/policies` →
  `serde_json::to_string_pretty` → `rfd::FileDialog::save_file` with
  default filename `policies-export-YYYY-MM-DD.json`. Success and error
  states surface via the status bar.
- **Import action stub** (`action_import_policies`): file picker → parse
  JSON → GET existing policies → compute conflict diff → transition to
  `Screen::ImportConfirm`. The actual POST/PUT execution is deferred to
  Wave 2.
- **ImportConfirm handler** (`handle_import_confirm`): skip-nav pattern
  cycling only between rows 3 ([Confirm]) and 4 ([Cancel]). Enter on
  Confirm → `ImportState::InProgress` (Wave 2 takes over). Esc or Cancel
  → back to PolicyMenu. Terminal states (InProgress/Success/Error)
  accept only Enter/Esc to dismiss.
- **ImportConfirm rendering** (`draw_import_confirm`): 5-row list with
  a bold header, two DarkGray diff counts, Confirm (green) and Cancel
  (red) buttons, and a state block below showing Importing…, Import
  Complete, or Import Failed depending on `ImportState`.

## Verification

- `cargo check -p dlp-admin-cli` → clean
- `cargo build -p dlp-admin-cli` → clean (rfd compiled with windows_sys)
- `cargo clippy -p dlp-admin-cli -- -D warnings` → clean
- `cargo fmt --check` → our Wave 1 files clean (pre-existing fmt
  warnings in `dlp-server/policy_store.rs` are unrelated)

## Deviations from 17-01-PLAN.md

- **rfd API fix**: plan used `.title()` but rfd 0.14 renamed the builder
  method to `.set_title()`. Adjusted both call sites.
- **Dead-code allowances**: `ImportState::Success/Error` and
  `Screen::ImportConfirm::existing_ids` are gated behind
  `#[allow(dead_code)]` until Wave 2 wires them up.
- **Import error message**: plan had `Err(e) =>` without using `e` for
  the read failure; updated the format string to include the error.

## Next

Wave 2 (`17-02-PLAN.md`): typed `PolicyResponse`/`PolicyPayload`
structs, POST/PUT execution loop with abort-on-error, unit tests.
Depends on `Screen::ImportConfirm`, `ImportState`, and `existing_ids`
delivered here.
