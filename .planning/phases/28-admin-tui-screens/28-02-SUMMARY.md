---
phase: 28
plan: "02"
subsystem: dlp-admin-cli
tags: [tui, conditions-builder, abac, app-identity, ratatui]
dependency_graph:
  requires: [28-01]
  provides: [SourceApplication-TUI, DestinationApplication-TUI]
  affects: [dlp-admin-cli/src/app.rs, dlp-admin-cli/src/screens/dispatch.rs, dlp-admin-cli/src/screens/render.rs]
tech_stack:
  added: []
  patterns:
    - AppField sub-picker step (Step 1.5) inserted between attribute selection and operator selection
    - Two-phase borrow pattern for extracting scalars before mutable state updates
    - Fail-closed field guard (field? early return) in build_condition for app-identity attrs
key_files:
  created: []
  modified:
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs
decisions:
  - SourceApplication/DestinationApplication use a 3-step sub-picker (Step 1.5) for AppField before operator selection
  - TrustTier uses a 3-item picker (trusted/untrusted/unknown); Publisher and ImagePath use free-text input
  - Step 2 Esc for app-identity returns to sub-step (clears selected_field, keeps selected_attribute) not to attribute picker
  - Edit mode pre-fills AppField from existing PolicyCondition variant directly; skip sub-step when field is known
  - fail-closed: build_condition returns None if field is None for app-identity attrs (T-28-02-01 mitigation)
metrics:
  duration: "~45 minutes"
  completed: "2026-04-23"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 3
---

# Phase 28 Plan 02: SourceApplication/DestinationApplication TUI Summary

TUI conditions builder extended with SourceApplication and DestinationApplication attribute support,
including an AppField sub-picker step and per-field operator/value routing in dlp-admin-cli.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| T-28-02-01 | Extend app.rs types | 7f78ea5 | dlp-admin-cli/src/app.rs |
| T-28-02-02 | Extend dispatch.rs and render.rs | e6beb26 | dlp-admin-cli/src/screens/dispatch.rs, dlp-admin-cli/src/screens/render.rs |

## What Was Built

**Task 1 — app.rs type extension:**
- `ConditionAttribute` extended from 5 to 7 variants: added `SourceApplication` and `DestinationApplication`
- `ATTRIBUTES` const updated from `[ConditionAttribute; 5]` to `[ConditionAttribute; 7]`
- `label()` arms added for both new variants
- `selected_field: Option<dlp_common::abac::AppField>` field added to `Screen::ConditionsBuilder`
- Both `Screen::ConditionsBuilder` construction sites in dispatch.rs updated with `selected_field: None`

**Task 2 — dispatch.rs and render.rs:**
- `operators_for(attr, field)`: SourceApplication/DestinationApplication return `eq/ne/contains` for
  Publisher/ImagePath and `eq/ne` for TrustTier; conservative `eq/ne` when field is None
- `value_count_for(attr, field)`: TrustTier returns 3 (picker); Publisher/ImagePath return 0 (free-text)
- `build_condition(attr, op, picker_selected, buffer, field)`: SourceApplication/DestinationApplication
  arms with fail-closed `field?` guard (T-28-02-01 mitigation)
- `condition_to_prefill`: replaced Phase 26 stub with real SourceApplication/DestinationApplication arms
  that decode AppField from the existing PolicyCondition and encode picker_idx/buffer accordingly
- `handle_conditions_step1`: now a router — calls `handle_conditions_app_field_sub_step` when in
  sub-step, otherwise `handle_conditions_attribute_picker`
- `handle_conditions_app_field_sub_step`: new function handling Up/Down/Enter/Esc in AppField picker
- `handle_conditions_attribute_picker`: for app-identity attrs, if `selected_field` is already Some
  (edit mode pre-fill), skips sub-step and advances to Step 2 directly
- `handle_conditions_step2`: Esc for app-identity clears `selected_field` and stays at `step=1`
  (returns to sub-step), rather than clearing `selected_attribute`
- `handle_conditions_step3`, `handle_conditions_step3_text`, `handle_conditions_step3_select`:
  all accept and thread `selected_field`; text path used for Publisher/ImagePath
- Edit mode ('e' key handler): extracts AppField directly from `PolicyCondition::SourceApplication`
  and `PolicyCondition::DestinationApplication` variants; sets `selected_field` in screen state
- `APP_FIELD_LABELS: [&str; 3]` and `app_field_from_idx(usize) -> AppField` helpers added
- render.rs `pick_operators(attr, field)`: delegates to `operators_for` with field
- render.rs `picker_items(attr, field, ...)`: SourceApplication/DestinationApplication route to
  TrustTier picker or empty vec (text input path)
- render.rs `draw_conditions_builder`: accepts `selected_field`; renders "Step 1.5: Select Application
  Field" sub-picker when in sub-step; text input hint shown for Publisher/ImagePath at Step 3
- `TRUST_TIER_VALUES: [&str; 3]` and `APP_FIELD_LABELS: [&str; 3]` constants added to render.rs
- All 42 existing tests updated for new function signatures and pass

## Deviations from Plan

None — plan executed exactly as written.

## Verification

- `cargo build -p dlp-admin-cli`: PASSED (0 errors, 0 warnings)
- `cargo clippy -p dlp-admin-cli -- -D warnings`: PASSED
- `cargo fmt -p dlp-admin-cli --check`: PASSED (rustfmt applied during task)
- `cargo test -p dlp-admin-cli`: PASSED (42/42 tests)

## Self-Check: PASSED

- Task 1 commit 7f78ea5: FOUND
- Task 2 commit e6beb26: FOUND
- app.rs modified: FOUND (ConditionAttribute 7 variants, selected_field in Screen::ConditionsBuilder)
- dispatch.rs modified: FOUND (operators_for/value_count_for/build_condition updated, sub-step routing)
- render.rs modified: FOUND (draw_conditions_builder handles sub-step, TRUST_TIER_VALUES added)
