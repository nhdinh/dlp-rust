---
phase: 59-label-service
plan: 04
type: execute
subsystem: dlp-admin-cli
wave: 3
depends_on:
  - 59-02
requirements:
  - LABEL-04
  - LABEL-07
key_files:
  created: []
  modified:
    - dlp-admin-cli/src/client.rs
    - dlp-admin-cli/src/app.rs
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs
    - dlp-admin-cli/src/screens/labels.rs
decisions:
  - "Moved PaginatedLabelsResponse out of impl EngineClient block to module scope (Rust does not allow structs inside impl blocks)"
  - "Used #[allow(clippy::too_many_arguments)] on draw_label_list and draw_label_review_queue rather than refactoring into config structs (follows existing codebase pattern for render functions)"
  - "Used total.div_ceil(page_size) instead of manual (total + page_size - 1) / page_size (clippy suggestion)"
tech_stack:
  added: []
  patterns:
    - "Paginated API client methods with limit/offset"
    - "Server-side pagination with PageUp/PageDown key handling"
    - "Confirmation dialog for destructive actions (expire) with path and tier display"
metrics:
  duration: "~8 minutes"
  completed_date: "2026-05-21"
  tasks: 3
  files_modified: 5
  commits: 3
---

# Phase 59 Plan 04: Admin TUI Label Management Gaps Summary

**One-liner:** Added expire client method, server-side pagination (PageUp/PageDown), and confirmation dialog with path/tier display to the admin TUI label management screens.

## What Was Built

### Task 1: expire_label client method and paginated list_labels
- Added `PaginatedLabelsResponse` struct with `labels`, `total`, `limit`, `offset` fields
- Updated `list_labels` signature to accept `limit: usize` and `offset: usize` parameters
- `list_labels` builds query string with required limit/offset and optional state/department filters
- Added `expire_label(id: &str)` method sending POST to `admin/labels/{id}/expire`

### Task 2: Expire action, pagination, and ConfirmPurpose variant
- Added `page`, `page_size`, `total` fields to `Screen::LabelList` and `Screen::LabelReviewQueue`
- Added `ConfirmPurpose::ExpireLabel { id, path, tier }` variant
- Added 'x' key handler in `handle_label_list` showing confirm dialog with path and tier
- Added `PageUp`/`PageDown` handlers adjusting page and reloading via `action_load_label_list_paginated`
- Added `action_expire_label` calling `client.expire_label(id)` with error handling
- Updated `action_load_label_list` to use paginated API and `action_load_label_review_queue_with_filter` similarly
- Updated all `Screen::LabelList` and `Screen::LabelReviewQueue` construction sites with default pagination values

### Task 3: Pagination display and LabelDetail verification
- Updated `LABEL_LIST_HINTS` to include `[x] Expire` and `[PgUp/PgDn] Page`
- `draw_label_list` and `draw_label_review_queue` render pagination info in footer: "Page N of M | K per page"
- Verified `Screen::LabelDetail` has no recursive enum issue (no `Screen`-typed field)
- Added `test_label_detail_non_recursive` test constructing `LabelDetail` and asserting via `matches!`

## Deviations from Plan

None - plan executed exactly as written.

## Commits

| Hash | Type | Message |
|------|------|---------|
| ef9bdea | test(59-04) | add expire_label client method and paginated list_labels |
| 0f1ebf0 | feat(59-04) | expire action, pagination, and ConfirmPurpose::ExpireLabel |
| 95bbe17 | feat(59-04) | pagination display, updated hints, non-recursive LabelDetail test |

## Verification Results

- `cargo check -p dlp-admin-cli` - PASSED (no errors, no warnings)
- `cargo test -p dlp-admin-cli` - PASSED (139 tests passed)
- `cargo clippy -p dlp-admin-cli --lib -- -D warnings` - PASSED
- `cargo build --workspace` - PASSED

## Self-Check: PASSED

- [x] All modified files exist and compile
- [x] All commits exist in git history
- [x] Tests pass
- [x] Clippy passes on lib
- [x] Workspace builds successfully
