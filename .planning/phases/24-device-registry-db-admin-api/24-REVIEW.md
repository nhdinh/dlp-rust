---
phase: 24-device-registry-db-admin-api
reviewed: 2026-04-22T07:32:28Z
depth: standard
files_reviewed: 12
files_reviewed_list:
  - dlp-agent/src/detection/usb.rs
  - dlp-agent/src/device_registry.rs
  - dlp-agent/src/lib.rs
  - dlp-agent/src/server_client.rs
  - dlp-agent/src/service.rs
  - dlp-agent/tests/device_registry_cache.rs
  - dlp-server/src/admin_api.rs
  - dlp-server/src/db/mod.rs
  - dlp-server/src/db/repositories/device_registry.rs
  - dlp-server/src/db/repositories/mod.rs
  - dlp-server/src/lib.rs
  - dlp-server/tests/device_registry_integration.rs
findings:
  critical: 1
  warning: 4
  info: 3
  total: 8
status: issues_found
---

# Phase 24: Code Review Report

**Reviewed:** 2026-04-22T07:32:28Z
**Depth:** standard
**Files Reviewed:** 12
**Status:** issues_found

## Summary

Phase 24 delivers the device registry DB schema, the admin CRUD API (`GET`/`POST`/`DELETE /admin/device-registry`), the agent-side `DeviceRegistryCache`, and the on-arrival refresh hook wired into `usb_wndproc`. The overall implementation is solid: the fail-safe default-deny cache, the upsert-on-conflict DB semantics, the JWT-gated write endpoints, and the layered shutdown sequence are all correctly implemented.

One critical security finding stands out: `GET /admin/device-registry` is deliberately unauthenticated, which exposes the full inventory of enrolled USB device identities (VID, PID, serial number) to any network peer. The trust-tier column is also included. While the design decision is documented, the exposure of serial numbers constitutes a meaningful information disclosure risk that should be reassessed.

Four warnings cover a use-after-drop pattern that compiles correctly today but is fragile, a missing input-length guard on `trust_tier` that bypasses the allowlist check via panic-inducing input, a silent OnceLock collision in tests, and the absence of a `PRAGMA foreign_keys = ON` guard in the connection pool setup. Three informational items address dead code, a magic number, and a misleading doc comment.

---

## Critical Issues

### CR-01: Unauthenticated `GET /admin/device-registry` exposes full device identity inventory

**File:** `dlp-server/src/admin_api.rs:489` and `dlp-server/src/admin_api.rs:1481-1498`

**Issue:** The route is registered on `public_routes` (no JWT middleware) and returns the complete list of enrolled device entries including `vid`, `pid`, `serial`, `description`, and `trust_tier`. Any unauthenticated HTTP client on the network can enumerate all tracked USB devices and their trust tiers. Serial numbers, in particular, are unique device fingerprints. An attacker who can reach port 9090 can determine which devices are `full_access` and then physically present or spoof one of those exact serial numbers.

The comment at line 1482 acknowledges the decision ("T-24-06 accepted") but the accepted risk should be revisited: the agent does not carry a pre-shared secret or mutual TLS, so there is no current mechanism to restrict listing to agents only. Exposing `trust_tier` to unauthenticated callers reveals which device identities have elevated access.

**Fix:** At minimum, mask `trust_tier` in the unauthenticated response or return only device counts. Preferred: require a pre-shared agent token (can be the same bcrypt hash already stored in `agent_credentials`) so that only registered agents can list devices. A simpler near-term mitigation is to omit `trust_tier` from the unauthenticated list endpoint and keep the full data behind JWT.

```rust
// Option A: return a reduced shape for the public list endpoint
#[derive(Serialize)]
struct PublicDeviceEntry {
    vid: String,
    pid: String,
    serial: String,
}

async fn list_device_registry_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PublicDeviceEntry>>, AppError> { ... }
```

---

## Warnings

### WR-01: Use-after-drop of `conn` inside `spawn_blocking` closure (upsert handler)

**File:** `dlp-server/src/admin_api.rs:1546-1557`

**Issue:** Inside the `spawn_blocking` closure, `conn` is a `PooledConnection` (an RAII guard). After `uow.commit()`, the code calls `drop(conn)` explicitly to return the connection to the pool, then immediately calls `get_by_device_key(&pool, ...)` — which acquires a new connection from the same pool. This works correctly today because `max_size = 5`, but the `drop(conn)` call followed by use of the captured `pool` borrow inside the same closure is a fragile pattern. If the pool ever runs at `max_size = 1` (e.g., in a test fixture that shares a pool), the explicit drop must happen before the re-acquire or the closure deadlocks. The closure currently does the right thing, but the comment says "Re-read outside the transaction using the pool (write conn already returned)" which is only true because of the `drop(conn)` — if a future refactor removes it the code deadlocks silently.

**Fix:** Restructure so the write connection scope is unambiguously terminated before the read:

```rust
let persisted = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
    {   // explicit scope — conn dropped at closing brace
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        repositories::DeviceRegistryRepository::upsert(&uow, &row)
            .map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
    }   // conn returned to pool here
    repositories::DeviceRegistryRepository::get_by_device_key(&pool, &vid, &pid, &serial)
        .map_err(AppError::Database)
})
.await
.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
```

---

### WR-02: `trust_tier` allowlist check can be circumvented by a very long input causing OOM before the check

**File:** `dlp-server/src/admin_api.rs:1518-1524`

**Issue:** The `trust_tier` field in `DeviceRegistryRequest` is a plain `String` with no length constraint. axum's `Json` extractor reads the full request body before deserialization. A malicious client can send an arbitrarily large `trust_tier` value; the string is allocated on the heap in full before the allowlist check at line 1518 rejects it. While axum has a default body-size limit (2 MB for `Json`), allocating 2 MB for a field expected to hold at most 11 characters (`"full_access"`) is wasteful and constitutes a minor DoS vector on resource-constrained deployments.

**Fix:** Add a length guard immediately after the allowlist check, or use a newtype/enum for the tier that fails deserialization early:

```rust
// Lightweight guard — add before the VALID_TIERS check
if body.trust_tier.len() > 32 {
    return Err(AppError::UnprocessableEntity(
        "trust_tier exceeds maximum length".to_string()
    ));
}
```

Or, preferably, deserialize directly into a `UsbTrustTier` enum (already defined in `dlp_common`) with a `serde` `rename` attribute — this eliminates the manual string match entirely and rejects invalid values at deserialization time.

---

### WR-03: `set_jwt_secret` in integration tests is a `OnceLock` — parallel test runs silently use stale secret

**File:** `dlp-server/tests/device_registry_integration.rs:35`

**Issue:** `set_jwt_secret(TEST_JWT_SECRET.to_string())` is called inside `build_test_app()`. `set_jwt_secret` internally uses a `OnceLock` — the first caller wins and all subsequent calls are silently ignored. When the integration test binary runs tests in parallel (the default with `cargo test`), the order in which tests call `build_test_app()` is non-deterministic. If another test file in the same binary sets a different secret first, all subsequent JWT mints in this file will produce tokens that fail validation. The tests pass today because `TEST_JWT_SECRET` matches the dev default, but this is an implicit coupling to `admin_auth::DEV_JWT_SECRET` rather than an explicit contract.

**Fix:** The comment on line 26-27 correctly identifies the issue. Either:
- Move the `set_jwt_secret` call into a `#[test_log::test]` / `tokio::test` setup macro that runs once, or
- Assert the returned `Result` from `set_jwt_secret` and skip the test if the secret is already set to a different value.

The safest fix is to use the same constant in all test files and document the constraint:

```rust
// In a shared test helper crate or test utility module:
pub const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";
pub fn ensure_jwt_secret() {
    // No-op if already set to the same value (expected in CI).
    let _ = set_jwt_secret(TEST_JWT_SECRET.to_string());
}
```

---

### WR-04: SQLite `PRAGMA foreign_keys = ON` not set per connection in the pool

**File:** `dlp-server/src/db/mod.rs:47-52`

**Issue:** The pool initialization enables WAL mode (`PRAGMA journal_mode=WAL`) on the first connection, but does not enable `PRAGMA foreign_keys = ON`. The comment at line 196-198 in `init_tables` explicitly notes: "rusqlite does NOT enforce FK constraints unless PRAGMA foreign_keys = ON is set per connection." The `agent_config_overrides` table has a `REFERENCES agents(agent_id) ON DELETE CASCADE` clause that is silently ignored on all connections. Deleting an agent row leaves orphaned `agent_config_overrides` rows. While the cascade is described as "a safety net, not a correctness invariant," the orphaned rows pollute the config override table and can surface as stale data via `GET /admin/agent-config/{agent_id}`.

**Fix:** Use `r2d2_sqlite`'s `SqliteConnectionManager::with_init` to run `PRAGMA foreign_keys = ON` on every newly checked-out connection:

```rust
let mgr = SqliteConnectionManager::file(path)
    .with_init(|conn| conn.execute_batch("PRAGMA foreign_keys = ON;"));
```

This is idempotent and cheap (a single pragma per connection).

---

## Info

### IN-01: `acquire_instance_mutex` in `service.rs` creates a local mutex that is immediately dropped

**File:** `dlp-agent/src/service.rs:800-813`

**Issue:** `acquire_instance_mutex` creates a `std::sync::Mutex::new(())` on the stack and calls `try_lock()`. The lock guard (if acquired) is immediately dropped at the end of the `match` arm — the mutex itself is local to the function and dropped when the function returns. This provides no actual single-instance enforcement; a second agent process creates its own local mutex with no contention. The function logs "single-instance mutex acquired" unconditionally for every process start.

This is pre-existing dead code that predates Phase 24, but it is included in the reviewed `service.rs` file.

**Fix:** Use a named Windows mutex (`CreateMutexW` with a unique name) or a PID file for true single-instance enforcement. If single-instance enforcement is deferred, remove the misleading log line and the function.

---

### IN-02: Magic number `32_768` in `read_dbcc_name` should be a named constant

**File:** `dlp-agent/src/detection/usb.rs:391`

**Issue:** The loop bound `len < 32_768` is a magic number. The value is correct (Windows device-path maximum is 32,767 UTF-16 code units plus a null terminator), but the intent is not self-documenting to a future reader.

**Fix:**
```rust
/// Maximum length of a Windows device interface path in UTF-16 code units.
/// This bounds the null-terminator scan in `read_dbcc_name` to prevent
/// runaway reads on a malformed or adversarially crafted device path.
const MAX_DEVICE_PATH_LEN: usize = 32_768;
```

---

### IN-03: Doc comment for `fetch_device_registry` incorrectly describes JSON decode failure mapping

**File:** `dlp-agent/src/server_client.rs:374`

**Issue:** The doc comment says `ServerClientError::Http` is returned for "JSON decode failure." The implementation maps `resp.json::<Vec<DeviceRegistryEntry>>().await` errors via `.map_err(ServerClientError::Http)`, which is technically accurate (`reqwest::Error` wraps JSON errors from `resp.json()`). However, the public error type `ServerClientError::Http` carries the message "HTTP request failed" — a JSON decode error reported as `Http` will confuse operators diagnosing a mismatch between server schema and client struct. This is a minor doc/naming inconsistency.

**Fix:** Either add a separate `Deserialization` variant for JSON decode failures from response bodies, or update the doc comment to clarify that `Http` covers both network and response-body parse failures (matching `reqwest::Error`'s actual scope).

---

_Reviewed: 2026-04-22T07:32:28Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
