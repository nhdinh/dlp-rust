---
phase: 24-device-registry-db-admin-api
verified: 2026-04-22T12:00:00Z
status: human_needed
score: 8/9 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Run 'cargo build --release' then execute the full curl smoke-test sequence: GET /admin/device-registry -> POST with valid body -> GET (1 entry) -> DELETE -> GET (empty) -> POST with invalid tier (expect 422)"
    expected: "All six steps produce the expected HTTP responses in release-mode binary (debug profile is confirmed passing)"
    why_human: "The 24-04-SUMMARY explicitly notes the human checkpoint was approved for debug build only and flags a release-mode UAT concern. Automated integration tests (oneshot) run in debug profile; the release-mode optimization path for OnceLock initialization ordering in the USB window thread could differ."
---

# Phase 24: Device Registry DB + Admin API — Verification Report

**Phase Goal:** The server persists a trust-tier registry for USB devices and exposes a JWT-protected admin API for device management so agents can query registered device trust tiers.
**Verified:** 2026-04-22
**Status:** human_needed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths (from ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | GET /admin/device-registry returns a JSON list with VID, PID, serial, description, and trust_tier | VERIFIED | `list_device_registry_handler` at admin_api.rs:1487 returns `Vec<DeviceRegistryResponse>` (7-field struct) on public_routes; integration test `test_device_registry_get_returns_empty_list` and `test_device_registry_post_upserts_and_returns_row` confirm |
| 2 | POST creates entries and DELETE removes them; both require JWT auth | VERIFIED | Routes registered at admin_api.rs:546-551 on `protected_routes` behind `admin_auth::require_auth` middleware; `test_device_registry_post_without_jwt_returns_401` passes; `test_device_registry_delete_returns_204_and_removes_row` passes |
| 3 | Trust tier CHECK constraint rejects invalid values with 422 | VERIFIED | DB DDL at db/mod.rs:138 has `CHECK(trust_tier IN ('blocked','read_only','full_access'))`; `AppError::UnprocessableEntity` added to lib.rs:104 mapping to HTTP 422; handler allowlist check at admin_api.rs before DB write; `test_device_registry_post_invalid_tier_returns_422` passes |
| 4 | Agent caches registry in RwLock<HashMap> indexed by (vid+pid+serial) | VERIFIED | `DeviceRegistryCache` at dlp-agent/src/device_registry.rs:41 uses `parking_lot::RwLock<HashMap<(String,String,String), UsbTrustTier>>`; `trust_tier_for` returns `UsbTrustTier::Blocked` for unknown devices (fail-safe); `spawn_poll_task` wired in service.rs:396-408 |

**Plan 01 truths (must_haves):**

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 5 | device_registry table exists with correct schema (7 cols, CHECK, UNIQUE) | VERIFIED | db/mod.rs:138 CREATE TABLE confirmed; columns id, vid, pid, serial, description, trust_tier, created_at; CHECK and UNIQUE constraints present |
| 6 | DeviceRegistryRepository stateless struct with list_all, upsert, delete_by_id | VERIFIED | device_registry.rs:36-168; all three methods implemented with real SQL, no stubs |
| 7 | Duplicate (vid,pid,serial) upserts (updates tier+description, preserves UUID) | VERIFIED | ON CONFLICT DO UPDATE at device_registry.rs:93-95; `test_upsert_duplicate_updates_tier_and_description` asserts id="uuid-1" preserved after conflict |
| 8 | trust_tier outside allowed set rejected by DB CHECK | VERIFIED | DDL CHECK constraint at db/mod.rs; `test_device_registry_check_constraint` test exercises it |
| 9 | Release-mode smoke test (GET→POST→GET→DELETE→GET + invalid-422 curl sequence) | NEEDS HUMAN | 24-04-SUMMARY explicitly states human checkpoint "approved for debug build" only; release-mode concern flagged but not resolved |

**Score:** 8/9 must-haves verified (9th requires human)

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `dlp-server/src/db/mod.rs` | device_registry CREATE TABLE in init_tables | VERIFIED | Lines 135-148 contain full DDL with CHECK + UNIQUE constraints |
| `dlp-server/src/db/repositories/device_registry.rs` | DeviceRegistryRepository + DeviceRegistryRow | VERIFIED | 318 lines; list_all, upsert, get_by_device_key, delete_by_id all implemented with real SQL |
| `dlp-server/src/db/repositories/mod.rs` | pub mod device_registry + re-exports | VERIFIED | Line 12: `pub mod device_registry`; Line 24: `pub use device_registry::{DeviceRegistryRepository, DeviceRegistryRow}` |
| `dlp-server/src/admin_api.rs` | DeviceRegistryRequest, DeviceRegistryResponse, 3 handlers, route registration | VERIFIED | Types at lines 275/293; handlers at 1487/1513/1574; routes at 489, 546-551 |
| `dlp-server/src/lib.rs` | AppError::UnprocessableEntity (422) | VERIFIED | Line 104: `UnprocessableEntity(String)`; line 147: maps to `StatusCode::UNPROCESSABLE_ENTITY` |
| `dlp-agent/src/device_registry.rs` | DeviceRegistryCache + trust_tier_for + spawn_poll_task | VERIFIED | Full implementation; RwLock<HashMap>; Blocked default; 30s poll interval |
| `dlp-agent/src/service.rs` | DeviceRegistryCache spawned as background task | VERIFIED | Lines 396-408: spawn_poll_task called when server_client is Some |
| `dlp-agent/src/detection/usb.rs` | REGISTRY_CACHE static + refresh on DBT_DEVICEARRIVAL | VERIFIED | Lines 233-263: OnceLock static + set_registry_cache; lines 336-349: arrival arm triggers refresh via REGISTRY_RUNTIME_HANDLE |
| `dlp-server/tests/device_registry_integration.rs` | 8 server CRUD integration tests | VERIFIED | File exists; 8 tokio tests covering GET/POST/DELETE round-trips, 422, 401, upsert conflict |
| `dlp-agent/tests/device_registry_cache.rs` | 3 agent cache integration tests | VERIFIED | File exists; tests for empty cache, seeded lookup, wrong-serial returns Blocked |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| admin_api.rs handlers | db/repositories/device_registry.rs | `DeviceRegistryRepository::list_all`, `upsert`, `get_by_device_key`, `delete_by_id` | WIRED | All four calls confirmed in handler bodies |
| public_routes | GET /admin/device-registry handler | `.route("/admin/device-registry", get(list_device_registry_handler))` admin_api.rs:489 | WIRED | Route confirmed |
| protected_routes | POST + DELETE handlers | Lines 546-551 in admin_router | WIRED | Both routes confirmed behind require_auth middleware |
| service.rs run_loop | DeviceRegistryCache::spawn_poll_task | Arc<DeviceRegistryCache> + ServerClient clone | WIRED | Lines 396-408 confirmed |
| usb_wndproc DBT_DEVICEARRIVAL arm | DeviceRegistryCache::refresh | REGISTRY_CACHE.get() + REGISTRY_RUNTIME_HANDLE.get().spawn() | WIRED | Lines 336-349 confirmed; async refresh fires on arrival |
| dlp-agent/src/lib.rs | device_registry module | `pub mod device_registry` | WIRED | Module registered and exported |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|--------------|--------|--------------------|--------|
| `list_device_registry_handler` | `rows: Vec<DeviceRegistryRow>` | `DeviceRegistryRepository::list_all` → `SELECT ... FROM device_registry ORDER BY created_at ASC` | Yes — DB query, not static | FLOWING |
| `upsert_device_registry_handler` | `persisted: DeviceRegistryRow` | `get_by_device_key` after `upsert` → `SELECT ... WHERE vid=? AND pid=? AND serial=?` | Yes — re-reads persisted state | FLOWING |
| `DeviceRegistryCache.cache` | `RwLock<HashMap>` | `fetch_device_registry` → GET /admin/device-registry → JSON deserialization | Yes — server response | FLOWING |

---

### Behavioral Spot-Checks

Step 7b: SKIPPED for release-mode — integration tests use axum oneshot (in-process, debug profile). The release-mode concern is routed to human verification.

| Behavior | Status |
|----------|--------|
| GET returns 200 + [] (empty DB, no auth) | PASS — `test_device_registry_get_returns_empty_list` |
| POST + valid JWT returns 200 + full row JSON | PASS — `test_device_registry_post_upserts_and_returns_row` |
| POST + invalid trust_tier returns 422 | PASS — `test_device_registry_post_invalid_tier_returns_422` |
| POST without JWT returns 401 | PASS — `test_device_registry_post_without_jwt_returns_401` |
| DELETE + valid JWT returns 204, subsequent GET returns [] | PASS — `test_device_registry_delete_returns_204_and_removes_row` |
| DELETE with nonexistent UUID returns 404 | PASS — `test_device_registry_delete_nonexistent_returns_404` |
| Duplicate POST updates tier, keeps 1 row | PASS — `test_device_registry_upsert_updates_tier` |
| trust_tier_for empty cache returns Blocked | PASS — `test_empty_cache_returns_blocked` |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| USB-02 | 24-01, 24-02, 24-03, 24-04 | Device registry DB + admin API + agent cache | SATISFIED | All 4 ROADMAP success criteria verified; 8 server integration tests + 3 agent cache tests pass |

---

### Anti-Patterns Found

None detected. Spot-checks of device_registry.rs, admin_api.rs handler section, and service.rs show:
- No `todo!()`, `unimplemented!()`, or placeholder comments in production paths
- No `return null` / empty static returns in handlers — all use real DB queries
- No `unwrap()` in production paths — all use `?` or `.map_err()`
- No hardcoded empty arrays returned from API handlers

The 8 pre-existing `todo!()` panics in `dlp-agent/tests/comprehensive.rs` are documented in 24-04-SUMMARY as pre-existing stubs from Phase 6, unrelated to Phase 24.

---

### Human Verification Required

#### 1. Release-Mode Smoke Test

**Test:** Build in release mode (`cargo build --release`) then run the full curl sequence:
1. `curl -s http://127.0.0.1:9090/admin/device-registry` — expect `[]`
2. Login: `curl -s -X POST http://127.0.0.1:9090/auth/login -d '{"username":"dlp-admin","password":"<pw>"}'` — capture JWT
3. POST device: `curl -s -X POST http://127.0.0.1:9090/admin/device-registry -H "Authorization: Bearer <JWT>" -H "Content-Type: application/json" -d '{"vid":"0951","pid":"1666","serial":"ABC123","description":"Kingston","trust_tier":"read_only"}'` — expect JSON with `id`
4. `curl -s http://127.0.0.1:9090/admin/device-registry` — expect array with 1 entry
5. `curl -s -X DELETE http://127.0.0.1:9090/admin/device-registry/<id> -H "Authorization: Bearer <JWT>"` — expect HTTP 204
6. `curl -s http://127.0.0.1:9090/admin/device-registry` — expect `[]`
7. POST invalid tier: `curl -o /dev/null -w "%{http_code}" -X POST ... -d '{"vid":"x","pid":"y","serial":"z","trust_tier":"bad"}'` — expect `422`

**Expected:** All seven steps produce the documented HTTP responses in release-mode binary.

**Why human:** The 24-04-SUMMARY explicitly states the human checkpoint was approved for "debug build" only and flags a release-mode UAT concern (possible OnceLock initialization ordering differences in the USB window thread under optimization). Automated integration tests run in-process via axum oneshot in debug profile and cannot reproduce this.

---

### Gaps Summary

No blocking gaps. All four ROADMAP success criteria are satisfied at the code level. The single human verification item (release-mode smoke test) is a prudence check flagged by the implementer — it does not indicate a known failure, only an untested build configuration.

---

_Verified: 2026-04-22T12:00:00Z_
_Verifier: Claude (gsd-verifier)_
