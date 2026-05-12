# Phase 59-label-service / Plan 59-02 Summary

## Objective
Implement the admin REST API for label management: 7 endpoints following existing disk_registry/device_registry CRUD patterns, with validation, audit logging, and cache invalidation.

## Requirements Covered
- LABEL-03: Label CRUD API
- LABEL-04: Label validation (absolute path, valid enums, parent_label_id -> folder)
- LABEL-07: Audit event emission for label mutations

## Changes Made

### dlp-server/src/admin_api.rs
- **Imports**: Added `LabelRepository`, `LabelRow`, `LabelUpsertRow` from `crate::db::repositories::labels`.
- **Request/Response Types**:
  - `LabelRequest` — create/update payload with path, object_type, tier, label_state, owner_sid, parent_label_id, acl_snapshot_id, hash.
  - `LabelResponse` — full label JSON matching dlp-common `Label` struct fields.
  - `LabelFilter` — query params for `?state=`, `?tier=`, `?owner_sid=`.
  - `From<LabelRow>` impl for `LabelResponse`.
- **Canonicalization Helpers**: `canonical_tier()`, `canonical_object_type()`, `canonical_label_state()` — normalize user input to DB CHECK constraint values (e.g. `T4`, `Unclassified-Blocked`).
- **Validation**: `validate_label_request()` checks:
  - Absolute path (UNC `\\` or drive letter `X:\`)
  - object_type in {file, folder, archive}
  - tier in {T1, T2, T3, T4, Unclassified-Blocked}
  - label_state in {temporary, confirmed, rejected, expired}
  - parent_label_id points to existing folder label (returns 422 if not)
- **7 Handlers**:
  1. `list_labels` — GET /admin/labels (filters: state, tier, owner_sid)
  2. `get_label` — GET /admin/labels/:id
  3. `create_label` — POST /admin/labels (UUID v4 id, ISO-8601 timestamps)
  4. `update_label` — PUT /admin/labels/:id (preserves created_at)
  5. `confirm_label` — POST /admin/labels/:id/confirm (only from temporary)
  6. `reject_label` — POST /admin/labels/:id/reject (only from temporary)
  7. `delete_label` — DELETE /admin/labels/:id
- **Route Registration**: All 7 routes added to `admin_router()` under protected_routes (JWT required).
- **Cache Invalidation**: `state.label_service.invalidate_cache()` called after create, update, confirm, reject, delete.
- **Audit Events**: Best-effort emission via `audit_store::store_events_sync` after DB commit, using action variants `LabelCreate`, `LabelUpdate`, `LabelConfirm`, `LabelReject`, `LabelDelete`.
- **Tests**: 16 integration tests covering all endpoints, validation rules, auth requirements, and edge cases.

### dlp-common/src/abac.rs
- Added `LabelCreate`, `LabelUpdate`, `LabelConfirm`, `LabelReject`, `LabelDelete` variants to the `Action` enum.

## Verification
- `cargo build -p dlp-server`: PASS
- `cargo test -p dlp-server`: 372 passed, 4 ignored
- `cargo clippy -p dlp-server -- -D warnings`: No issues found

## Artifacts
- `dlp-server/src/admin_api.rs` — 7 label REST endpoints + types + tests
- `dlp-common/src/abac.rs` — Label action enum variants
- `.planning/phases/59-label-service/59-02-SUMMARY.md` — this file

## Threat Model Mitigations
| Threat ID | Category | Mitigation |
|-----------|----------|------------|
| T-59-04 | Tampering | Absolute path check prevents relative path traversal |
| T-59-05 | Elevation | parent_label_id validation ensures parent is a folder |
| T-59-06 | Repudiation | Every mutation emits audit event with action + details |
| T-59-07 | Denial of Service | invalidate_cache called after every mutation |
