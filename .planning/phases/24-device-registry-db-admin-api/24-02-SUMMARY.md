---
phase: 24-device-registry-db-admin-api
plan: "02"
subsystem: dlp-server/admin_api
tags: [axum, http, device-registry, jwt, tdd, usb, admin-api]
dependency_graph:
  requires: [DeviceRegistryRepository, DeviceRegistryRow, device_registry table]
  provides: [GET /admin/device-registry, POST /admin/device-registry, DELETE /admin/device-registry/{id}, AppError::UnprocessableEntity]
  affects: [dlp-server/src/admin_api.rs, dlp-server/src/lib.rs, dlp-server/src/db/repositories/device_registry.rs]
tech_stack:
  added: []
  patterns:
    - unauthenticated GET on public_routes for agent polling
    - JWT-protected POST+DELETE on protected_routes
    - spawn_blocking + UnitOfWork for write handlers
    - pool re-use within spawn_blocking (drop conn before pool read)
    - AppError::UnprocessableEntity (422) for domain-level validation
key_files:
  created: []
  modified:
    - dlp-server/src/admin_api.rs
    - dlp-server/src/lib.rs
    - dlp-server/src/db/repositories/device_registry.rs
decisions:
  - "AppError::UnprocessableEntity added to lib.rs (422) — BadRequest maps to 400 only; domain enum validation needs a distinct 422 variant"
  - "get_by_device_key added to DeviceRegistryRepository — re-read after upsert returns the persisted UUID (which may be the original on conflict)"
  - "GET placed on public_routes (unauthenticated) so agents can poll trust-tier list without credentials (T-24-06 accepted risk)"
metrics:
  duration_seconds: 900
  completed_date: "2026-04-22"
  tasks_completed: 2
  files_changed: 3
---

# Phase 24 Plan 02: Device Registry Admin API — Summary

**One-liner:** Three axum handlers (unauthenticated GET, JWT-protected POST+DELETE) wired into admin_router, with AppError::UnprocessableEntity (422) added for trust_tier domain validation.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 (RED) | Type shape tests for DeviceRegistryRequest/Response | c0f30b4 | dlp-server/src/admin_api.rs |
| 1 (GREEN) | Define types, From impl, UnprocessableEntity, get_by_device_key | c0f30b4 | dlp-server/src/admin_api.rs, lib.rs, device_registry.rs |
| 2 (RED) | 6 handler integration tests (failing — no routes yet) | embedded in c0f30b4 | dlp-server/src/admin_api.rs |
| 2 (GREEN) | Implement 3 handlers + register routes in admin_router | 0c311d0 | dlp-server/src/admin_api.rs |

## Verification Results

- `cargo test -p dlp-server`: 143 passed, 0 failed, 2 ignored (9 new tests vs 134 prior)
- `cargo build --all`: zero warnings
- `cargo clippy -p dlp-server -- -D warnings`: zero warnings
- GET /admin/device-registry: 200 + `[]` (no auth required)
- POST /admin/device-registry + valid JWT + valid body: 200 + `{id,vid,pid,serial,description,trust_tier,created_at}`
- POST with trust_tier="invalid": 422 Unprocessable Entity
- POST without JWT: 401 Unauthorized
- DELETE /admin/device-registry/{id} + valid JWT: 204 No Content
- DELETE with nonexistent UUID: 404 Not Found

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical Functionality] Added AppError::UnprocessableEntity variant**
- **Found during:** Task 1 — reading AppError definition in lib.rs
- **Issue:** The plan specifies returning 422 for invalid trust_tier values, but `AppError` had no variant that maps to `StatusCode::UNPROCESSABLE_ENTITY`. The existing `AppError::BadRequest` maps to 400 only.
- **Fix:** Added `AppError::UnprocessableEntity(String)` variant to the enum and its match arm in `IntoResponse` returning `StatusCode::UNPROCESSABLE_ENTITY`.
- **Files modified:** `dlp-server/src/lib.rs`
- **Commit:** c0f30b4

**2. [Rule 2 - Missing Critical Functionality] Added DeviceRegistryRepository::get_by_device_key**
- **Found during:** Task 2 implementation — the plan noted this requirement inline as a `todo!()`
- **Issue:** After upsert, the handler must return the persisted row including the original UUID (preserved by ON CONFLICT DO UPDATE). There was no repository method to fetch by (vid, pid, serial) key.
- **Fix:** Added `get_by_device_key(pool, vid, pid, serial) -> rusqlite::Result<DeviceRegistryRow>` to `DeviceRegistryRepository`. Called after the upsert commit, using the pool (write connection already returned) to avoid holding two connections simultaneously.
- **Files modified:** `dlp-server/src/db/repositories/device_registry.rs`
- **Commit:** c0f30b4

## Known Stubs

None — all three handlers are fully implemented with real SQL via the DeviceRegistryRepository.

## Threat Surface Scan

All mitigations from the plan's threat model are implemented:

| Threat ID | Mitigation | Status |
|-----------|------------|--------|
| T-24-04 | `admin_auth::require_auth` middleware on POST+DELETE protected_routes | Implemented — 401 test passes |
| T-24-05 | Allowlist check in upsert handler before DB write; DB CHECK constraint is second line | Implemented — 422 test passes |
| T-24-06 | GET on public_routes (unauthenticated); accepted — server is localhost-only | Accepted |
| T-24-07 | `default_config()` rate limiter already applied to all protected_routes | Inherited from existing protected_routes .route_layer |

No new threat surface introduced beyond what the plan anticipated.

## TDD Gate Compliance

- RED gate: Type shape tests written first (compile error on missing types), handler tests written before handlers (runtime 401/fail).
- GREEN gate: c0f30b4 (types + lib.rs), 0c311d0 (handlers + routes) — all tests pass.
- No REFACTOR gate needed — code is clean with no duplication.

## Self-Check: PASSED

- [x] `dlp-server/src/admin_api.rs` contains `DeviceRegistryRequest`, `DeviceRegistryResponse`, `list_device_registry_handler`, `upsert_device_registry_handler`, `delete_device_registry_handler`
- [x] `dlp-server/src/lib.rs` contains `AppError::UnprocessableEntity` and its `IntoResponse` arm
- [x] `dlp-server/src/db/repositories/device_registry.rs` contains `get_by_device_key`
- [x] Route `/admin/device-registry` GET in `public_routes`, POST in `protected_routes`
- [x] Route `/admin/device-registry/{id}` DELETE in `protected_routes`
- [x] Commits c0f30b4 and 0c311d0 present in git log
- [x] 143 dlp-server tests pass (9 new)
- [x] Zero clippy warnings, zero build warnings
