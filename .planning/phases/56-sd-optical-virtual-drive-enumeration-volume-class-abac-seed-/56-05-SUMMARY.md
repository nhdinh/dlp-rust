---
phase: 56-sd-optical-virtual-drive-enumeration-volume-class-abac-seed
plan: "05"
subsystem: dlp-admin-cli
tags: [abac, volume-class, tui, conditions-builder, allowlist]
dependency_graph:
  requires: [56-01]
  provides: [ConditionAttribute.SourceVolumeClass, ConditionAttribute.DestinationVolumeClass, allowlist.volume_class]
  affects: [dlp-admin-cli]
tech-stack:
  added: []
  patterns:
    - "VOLUME_CLASS_VALUES constant for Step 3 picker"
    - "build_volume_class_condition helper with out-of-bounds fail-closed"
    - "volume_class_to_idx mapping for prefill round-trip"
key-files:
  created: []
  modified:
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs
    - dlp-admin-cli/src/screens/allowlist.rs
decisions:
  - "Volume class attributes use eq/ne/in for consistency with other picker-based attributes; documented that multi-select builds multiple eq conditions"
metrics:
  duration: "~20 minutes"
  completed_date: "2026-05-29"
---

# Phase 56 Plan 05: Admin TUI Volume Class Conditions and Allowlist Badges

**One-liner:** Extended the admin TUI Conditions Builder with SourceVolumeClass and DestinationVolumeClass attributes as dropdowns, and added volume class badge rendering to the allowlist screen.

---

## What Was Built

### Task 1: ConditionAttribute extension (app.rs)

- Added `SourceVolumeClass` and `DestinationVolumeClass` variants to `ConditionAttribute`
- Updated `ATTRIBUTES` array from `[ConditionAttribute; 9]` to `[ConditionAttribute; 11]`
- Added labels: "Source Volume Class" and "Destination Volume Class"
- Added doc comment explaining `in` operator semantics for volume class

### Task 2: Dispatch logic extension (dispatch.rs)

- Added `operators_for` arm: `eq`, `ne`, `in` for both volume class attributes
- Added `value_count_for` arm returning 6
- Added `build_volume_class_condition` helper with fail-closed semantics (index > 5 returns None)
- Added `volume_class_to_idx` helper for prefill round-trip
- Added `build_condition` arms calling the helper
- Added `condition_to_prefill` arms for round-trip editing
- Added `condition_display` arms rendering readable strings

### Task 3: Render and allowlist extension (render.rs, allowlist.rs)

- Added `VOLUME_CLASS_VALUES` constant with 6 volume class labels
- Added `picker_items` arm for Step 3 dropdown rendering
- Added `volume_class: Option<String>` to `AllowlistEntryUi`
- Added volume class badge rendering in `draw_allowlist_screen`

---

## Test Coverage

All dlp-admin-cli tests compile and pass. Existing tests updated for new `volume_class` field.

---

## Deviations from Plan

None — plan executed as written. Agent stall on 56-05 was recovered via inline execution.

---

## Verification Results

- `cargo check -p dlp-admin-cli`: clean
- `cargo test -p dlp-admin-cli --lib`: passes
- `cargo clippy -p dlp-admin-cli -- -D warnings`: clean
- `cargo fmt --check`: clean

---

## Commits

| Hash | Message | Files |
|------|---------|-------|
| e35df13 | feat(56-05): admin TUI volume class conditions and allowlist badges | dlp-admin-cli/src/app.rs, dispatch.rs, render.rs, allowlist.rs |

---

## Self-Check: PASSED

- [x] All created/modified files exist and compile
- [x] All commits exist in git history
- [x] Tests pass
- [x] Clippy clean
- [x] Formatting clean
