---
phase: 15
slug: policy-edit-delete
status: complete
created: "2026-04-17"
duration: ~18 min
requirements:
  - POLICY-03  # Edit form: name, description, priority, action, enabled, conditions, PUT /admin/policies/{id}, conditions pre-pop
  - POLICY-04  # Delete: d key, confirm dialog [y/n], DELETE /policies/{id}, PolicyList reload
---

# Phase 15 Plan 1: Policy Edit + Delete Summary

**Substantive:** Policy edit form (8-row, pre-populated from GET) and delete with `e`/`d` keys and `[y/n]` confirm dialog.

## Overview

Two capabilities added to the admin TUI:

1. **Edit (POLICY-03):** `e` on a PolicyList row → GET /policies/{id} → `Screen::PolicyEdit` (8-row form) → PUT /admin/policies/{id} on `[Save]` → PolicyList reload.
2. **Delete (POLICY-04):** `d` on a PolicyList row → `Screen::Confirm` with `Delete policy '{name}'? [y/n]` → DELETE /policies/{id} on `y` → PolicyList reload.

**Phase 14 Update (D-09):** Both `Screen::PolicyCreate` and `Screen::PolicyEdit` adopt an 8-row layout with the new Enabled toggle row. `action_submit_policy` POST body gains `"enabled": form.enabled`.

## Files Modified (4 commits)

| File | Changes |
|------|---------|
| `dlp-admin-cli/src/app.rs` | Added `Screen::PolicyEdit` variant (id, form, selected, editing, buffer, validation_error); added `id: String` to `PolicyFormState`; activated `CallerScreen::PolicyEdit`; removed `#[allow(dead_code)]` from `PolicyFormState.enabled` |
| `dlp-admin-cli/src/screens/dispatch.rs` | Row constants 7→8 (`POLICY_ENABLED_ROW`, `POLICY_SAVE_ROW`, `POLICY_ROW_COUNT=8`); added `action_load_policy_for_edit`, `handle_policy_edit*`, `action_submit_policy_update`; extended `handle_policy_list` (`e`/`d`), `handle_confirm` (`y`/`Y`/`n`/`N`/`Esc`), `action_delete_policy` (reload on success, stay on failure); ConditionsBuilder Esc handlers → `PolicyEdit`; `action_submit_policy` POST body uses `form.enabled` |
| `dlp-admin-cli/src/screens/render.rs` | `POLICY_FIELD_LABELS` `[&str; 8]` with "Enabled"; `draw_policy_create` index 4 Enabled row; `draw_policy_edit` (title `" Edit Policy: {name} "`, row 7 `"[Save]"`); `draw_confirm` hints update; `draw_policy_list` hints update |

## Decisions

| ID | Decision | Rationale |
|----|----------|-----------|
| D-01 | New `Screen::PolicyEdit` variant | Separate from `PolicyCreate` per UI-SPEC D-01 |
| D-02 | Title: `" Edit Policy: {name} "` | Name from GET response, no ID in title (D-02) |
| D-03 | Submit label: `[Save]` hardcoded | Not `POLICY_FIELD_LABELS[7]` which is `"[Submit]"` for Create (D-03) |
| D-04 | Policy ID in Screen variant, not rendered | `id` field on `Screen::PolicyEdit`, `id` field on `PolicyFormState` (D-04, D-09) |
| D-05 | Both forms adopt 8-row layout | D-05 |
| D-06 | Enabled row: White when unselected, Black+Cyan+BOLD when selected | Inherits from Phase 14 highlight style (D-06) |
| D-07 | Enter on Enabled: `form.enabled = !form.enabled`, no buffer | D-07 |
| D-08 | `PolicyFormState::default().enabled = true` | Already the default in Rust bool (D-08) |
| D-09 | Phase 14 Create updated to 8 rows alongside Phase 15 | Both share `POLICY_FIELD_LABELS[8]`, both have Enabled row (D-09) |
| D-14 | `handle_confirm` extended with `Char('y')`/`Char('Y')`/`Char('n')`/`Char('N')` | D-14 |
| D-15 | Delete confirm: `"Delete policy '{name}'? [y/n]"` | Inline `[y/n]` hint per ROADMAP (D-15) |
| D-16 | Delete success: `action_list_policies(app)` | PolicyList reload on success (D-16) |
| D-17 | Delete failure: stay on PolicyList | No navigation away from PolicyList on failure (D-17) |
| D-18 | Edit success: `action_list_policies(app)` | PolicyList reload on success (D-18) |
| D-19 | Edit validation error: red Paragraph below `[Save]` | Same pattern as Create form (D-19) |
| D-21 | Esc from PolicyEdit: `action_list_policies(app)` | No confirmation on Esc (D-21) |
| D-24 | `d` key wired in `handle_policy_list` only | D-24 |
| D-25 | `e` → `action_load_policy_for_edit`; `d` → Confirm dialog | D-25 |
| D-27 | PolicyList hints: `n: new \| e: edit \| d: delete \| Enter: view \| Esc: back` | D-27 |

## Deviations from Plan

None — plan executed exactly as written.

## Quality Gates

- **Build:** PASS (zero errors)
- **Tests:** PASS (22/22 passed)
- **Clippy:** PASS (zero warnings with `-D warnings`)
- **Fmt:** PASS (`cargo fmt --check` clean)

## Acceptance Criteria (all PASS)

| # | Criterion |
|---|-----------|
| 1 | `POLICY_ROW_COUNT` is `8` in dispatch.rs |
| 2 | `POLICY_FIELD_LABELS` is `[&str; 8]` in render.rs |
| 3 | `Screen::PolicyEdit` variant exists with 6 fields in app.rs |
| 4 | `draw_policy_edit` function exists with `" Edit Policy: "` title |
| 5 | `action_load_policy_for_edit` function exists in dispatch.rs |
| 6 | `action_submit_policy_update` function exists in dispatch.rs |
| 7 | `handle_confirm` has `Char('y')` and `Char('n')` branches |
| 8 | `handle_policy_list` has `Char('e')` and `Char('d')` branches |
| 9 | `action_submit_policy` POST body has `"enabled": form.enabled` |
| 10 | `action_delete_policy` calls `action_list_policies(app)` on success |
| 11 | `PolicyFormState.enabled` has no `#[allow(dead_code)]` in app.rs |
| 12 | `CallerScreen::PolicyEdit` is activated (no `#[allow(dead_code)]`) |
| 13 | Phase 13 ConditionsBuilder Esc handlers return `Screen::PolicyEdit` |

## Commits

| Hash | Description |
|------|-------------|
| `a87ca82` | feat(phase-15): update row constants to 8 and consume PolicyFormState.enabled |
| `0935386` | feat(phase-15): add PolicyEdit handlers and extend handle_policy_list/handle_confirm |
| `9d86087` | feat(phase-15): extend draw_policy_create to 8 rows and add draw_policy_edit |

## Next Phase Readiness

Phase 15 complete. All POLICY-03 and POLICY-04 criteria satisfied. Ready for next phase.
