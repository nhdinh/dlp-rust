---
phase: 40
plan: "01"
subsystem: drag-and-drop
tags: [abac, ipc, ole, app-identity]
dependency_graph:
  requires: []
  provides: [40-02, 40-03, 40-04]
  affects: [dlp-common, dlp-agent]
tech-stack:
  added: []
  patterns: [serde enum variants, IPC message extension]
key-files:
  created: []
  modified:
    - dlp-common/src/abac.rs
    - dlp-agent/src/ipc/messages.rs
    - dlp-common/tests/endpoint_cross_crate_compat.rs
decisions:
  - "Action::DRAG_DROP serializes as literal variant name \"DRAG_DROP\" (no serde rename)"
  - "Pipe3UiMsg::DragDropAlert uses #[serde(default, skip_serializing_if = \"Option::is_none\")] for optional app identity and data preview fields"
  - "Win32_System_Ole windows feature already present from prior commit (21dc703)"
  - "Pre-existing test assertion in endpoint_cross_crate_compat.rs updated to match AUDIT-05 schema guarantee (destination_application always serialized as null when None)"
metrics:
  duration: "~5 minutes"
  completed_date: "2026-05-07"
---

# Phase 40 Plan 01: Drag-and-Drop Infrastructure Summary

## One-liner

Foundational ABAC Action::DRAG_DROP variant and Pipe3UiMsg::DragDropAlert IPC message already present from prior infrastructure commit; added comprehensive serde round-trip tests and fixed a stale cross-crate compatibility test assertion.

## What Was Built

### Already Present (from commit 21dc703)

The core infrastructure was already implemented in a prior commit:

1. **`Action::DRAG_DROP`** in `dlp-common/src/abac.rs` (line 39)
   - Variant serializes as literal `"DRAG_DROP"` (no serde rename attribute)
   - Doc comment: "Drag-and-drop operation (Phase 40, APP-08)."

2. **`Pipe3UiMsg::DragDropAlert`** in `dlp-agent/src/ipc/messages.rs` (lines 126-140)
   - Fields: `session_id`, `classification`, `source_application`, `destination_application`, `data_preview`
   - Optional app identity fields use `#[serde(default, skip_serializing_if = "Option::is_none")]`
   - Mirrors `ClipboardAlert` structure for consistency

3. **`Win32_System_Ole`** feature in `dlp-agent/Cargo.toml` (line 72)
   - Comment: "Phase 40: OLE drag-and-drop interception (IDropTarget, RegisterDragDrop)"

### Added in This Execution

1. **Serde tests for `Action::DRAG_DROP`** (`dlp-common/src/abac.rs`)
   - `test_drag_drop_serializes_as_variant_name` — verifies `"DRAG_DROP"` serialization
   - `test_drag_drop_deserializes_from_variant_name` — verifies round-trip deserialization
   - `test_drag_drop_is_distinct` — verifies distinctness from PASTE, COPY, READ

2. **Serde tests for `Pipe3UiMsg::DragDropAlert`** (`dlp-agent/src/ipc/messages.rs`)
   - `test_drag_drop_alert_roundtrip_with_app_identity` — full round-trip with all fields
   - `test_drag_drop_alert_skips_none_fields` — verifies optional fields omitted when None
   - `test_drag_drop_alert_deserializes_legacy_payload` — backward-compat for payloads without optional fields

3. **Fixed stale test assertion** (`dlp-common/tests/endpoint_cross_crate_compat.rs`)
   - Updated `audit_event_builder_chain_and_round_trip` to expect `"destination_application":null` instead of absence
   - Aligns with AUDIT-05 (Phase 38.3) schema guarantee that app identity fields are always serialized

## Verification Results

- `cargo check --all` — PASSED (all 6 crates compile)
- `cargo clippy --all -- -D warnings` — PASSED (no issues)
- `cargo test -p dlp-common` — PASSED (143 tests, 3 suites)
- `cargo test -p dlp-agent --lib` — PASSED (303 tests, 1 suite)
- `cargo check -p dlp-user-ui` — PASSED

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed stale cross-crate compat test assertion**
- **Found during:** Task verification (cargo test)
- **Issue:** `endpoint_cross_crate_compat.rs` test asserted `!json.contains("destination_application")` expecting None fields to be skipped, but AUDIT-05 (Phase 38.3) mandates these fields are always serialized as `null`
- **Fix:** Updated assertion to `assert!(json.contains("\"destination_application\":null"))`
- **Files modified:** `dlp-common/tests/endpoint_cross_crate_compat.rs`
- **Commit:** 244f238

### No Other Deviations

The plan's core requirements (`Action::DRAG_DROP`, `Pipe3UiMsg::DragDropAlert`, `Win32_System_Ole`) were already implemented in the base commit (21dc703). This execution focused on adding test coverage and fixing the pre-existing test regression.

## Commits

| Hash | Type | Description |
|------|------|-------------|
| 21dc703 | feat | Drag-and-Drop infrastructure (pre-existing base) |
| 244f238 | fix | Update cross-crate compat test for AUDIT-05 schema guarantee |
| 1ed8f51 | test | Add DRAG_DROP action serde round-trip tests |
| dae2172 | test | Add DragDropAlert IPC message serde tests |

## Known Stubs

None. All infrastructure is present and tested. The actual OLE drag-and-drop interception implementation (IDropTarget hooking, data object inspection) is deferred to subsequent plans (40-02 through 40-04).

## Threat Flags

None. This plan only adds enum variants and message types — no new network endpoints, auth paths, or file access patterns.

## Self-Check: PASSED

- [x] `Action::DRAG_DROP` exists and serializes to `"DRAG_DROP"`
- [x] `Pipe3UiMsg::DragDropAlert` exists with all fields
- [x] `Win32_System_Ole` feature enabled in `dlp-agent/Cargo.toml`
- [x] All match arms covering `Action` and `Pipe3UiMsg` include new variants (verified via `cargo check --all`)
- [x] `cargo check --all` passes
- [x] `cargo clippy --all -- -D warnings` passes
- [x] All created/modified files committed
- [x] No accidental file deletions
