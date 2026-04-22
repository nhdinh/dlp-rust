---
phase: 24-device-registry-db-admin-api
fixed_at: 2026-04-22T08:15:00Z
review_path: .planning/phases/24-device-registry-db-admin-api/24-REVIEW.md
iteration: 1
findings_in_scope: 5
fixed: 5
skipped: 0
status: all_fixed
---

# Phase 24: Code Review Fix Report

**Fixed at:** 2026-04-22T08:15:00Z
**Source review:** .planning/phases/24-device-registry-db-admin-api/24-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 5
- Fixed: 5
- Skipped: 0

## Fixed Issues

### CR-01: Unauthenticated GET /admin/device-registry exposes full device identity inventory

**Files modified:** `dlp-server/src/admin_api.rs`, `dlp-server/tests/device_registry_integration.rs`
**Commit:** 59067c2
**Applied fix:** Added a new `PublicDeviceEntry` struct (vid, pid, serial only) with a corresponding `From<DeviceRegistryRow>` impl. Changed `list_device_registry_handler` return type from `Vec<DeviceRegistryResponse>` to `Vec<PublicDeviceEntry>`, omitting `trust_tier`, `description`, and `created_at`. Updated the doc comment to explain the deliberate omission. Integration test assertions that previously checked `trust_tier` on the GET response were updated: test 5 now asserts absence of `trust_tier`; test 8 now verifies identity via vid/pid/serial instead.

---

### WR-01: Use-after-drop of conn inside spawn_blocking closure (upsert handler)

**Files modified:** `dlp-server/src/admin_api.rs`
**Commit:** 9eff958
**Applied fix:** Replaced the explicit `drop(conn)` call with an explicit scope block `{ ... }` wrapping the write transaction. The `conn` RAII guard is now unambiguously returned to the pool at the closing brace before the subsequent `get_by_device_key` pool re-acquire. Added a comment explaining the deadlock risk with `max_size = 1` pools.

---

### WR-02: trust_tier allowlist check can be preceded by oversized input

**Files modified:** `dlp-server/src/admin_api.rs`
**Commit:** 5f16e17
**Applied fix:** Added a length guard `if body.trust_tier.len() > 32` returning `AppError::UnprocessableEntity("trust_tier exceeds maximum length")` immediately before the `VALID_TIERS` allowlist check. Valid tiers are at most 11 characters; 32 is a generous ceiling that rejects adversarially large inputs before the string comparison.

---

### WR-03: set_jwt_secret OnceLock silently ignored in parallel test runs

**Files modified:** `dlp-server/tests/device_registry_integration.rs`
**Commit:** 3569de2
**Applied fix:** Changed `set_jwt_secret(...)` to `let _ = set_jwt_secret(...)` to make the intentional discard of the return value explicit. Added a doc comment on `build_test_app` explaining the OnceLock first-caller-wins semantics, the reason it is safe (all test files in this binary share the same `TEST_JWT_SECRET` constant that matches `DEV_JWT_SECRET`), and the risk if a second binary sets a different secret.

---

### WR-04: SQLite PRAGMA foreign_keys = ON not set per connection in the pool

**Files modified:** `dlp-server/src/db/mod.rs`
**Commit:** 2eb4d0c
**Applied fix:** Changed `SqliteConnectionManager::file(path)` to chain `.with_init(|conn| conn.execute_batch("PRAGMA foreign_keys = ON;"))`, ensuring foreign-key enforcement is enabled on every connection checked out from the pool. Added a comment explaining that this pragma is not persisted at the file level and must be set per connection.

---

## Skipped Issues

None — all findings were fixed.

---

_Fixed: 2026-04-22T08:15:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
