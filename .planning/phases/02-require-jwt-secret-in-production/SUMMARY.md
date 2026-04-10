---
phase: 02-require-jwt-secret-in-production
plan: PLAN
subsystem: auth
tags: [jwt, jsonwebtoken, env-var, dlp-server, oncelock, secrets]

# Dependency graph
requires:
  - phase: 1
    provides: Clean workspace compile — tests run without stale dlp_server references
provides:
  - JWT signing secret is required from environment in production
  - --dev CLI flag for opt-in insecure fallback during development
  - Process-wide OnceLock for JWT secret — no per-request env reads
affects: [03-wire-siem-connector, 04-wire-alert-router, 08-rate-limiting]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Secrets resolved once at startup and stored in OnceLock, not re-read per request"
    - "Production fail-fast: server refuses to start on missing required env vars"

key-files:
  created: []
  modified:
    - dlp-server/src/admin_auth.rs
    - dlp-server/src/main.rs

key-decisions:
  - "resolve_jwt_secret(dev_mode) returns Result<String, String> — caller decides how to surface the error"
  - "Store resolved secret in a process-wide OnceLock instead of threading it through axum state — simpler for the handful of JWT callsites (login, verify_jwt, change_password)"
  - "The --dev fallback still uses the known 'dlp-server-dev-secret-change-me' literal — clearly unsafe and searchable, with a prominent tracing::warn! on every startup that uses it"

patterns-established:
  - "Required-env validation pattern: resolve once in main(), map the Err to a user-readable startup error, exit before binding the listener"

requirements-completed: [R-08]

# Metrics
duration: ~23 min
completed: 2026-04-10
---

# Phase 2: Require JWT_SECRET in Production Summary

**`dlp-server` refuses to start without a `JWT_SECRET` env var — the hardcoded dev fallback is now gated behind an explicit `--dev` flag that logs a prominent warning.**

## Performance

- **Duration:** ~23 min (single commit)
- **Started:** 2026-04-10T10:23 +0700 (plan committed)
- **Completed:** 2026-04-10T10:46:44 +0700 (feature committed)
- **Tasks:** 1 feature commit
- **Files modified:** 2 (`admin_auth.rs`, `main.rs`)

## Accomplishments

- Replaced the silent `unwrap_or_else` fallback with `resolve_jwt_secret(dev_mode: bool) -> Result<String, String>` in `dlp-server/src/admin_auth.rs`.
- Added a `--dev` CLI flag to `dlp-server` (parsed in `main.rs`, surfaced in `--help`).
- Server calls `resolve_jwt_secret(config.dev_mode)` before opening the listener; any `Err` is printed to stderr and startup aborts.
- Stored the resolved secret in a process-wide `OnceLock<String>` via `set_jwt_secret()` — `login()`, `verify_jwt()`, and `require_auth()` now read through `jwt_secret()` without re-touching env vars.
- Test suite updated with `ensure_test_secret()` helper so existing JWT unit tests (`test_jwt_round_trip`, `test_expired_token_rejected`, `test_invalid_token_rejected`) initialise the OnceLock safely.

## Task Commits

1. **Feature** — `664c528` (feat: require JWT_SECRET env var in production (Phase 2, R-08))
   - `dlp-server/src/admin_auth.rs` +63 / -6 (resolve_jwt_secret, OnceLock, set_jwt_secret, test helper)
   - `dlp-server/src/main.rs` +13 / 0 (dev_mode field, --dev parse, --dev in help, resolve + set in main)

**Plan metadata:** `14c3081` (plan: phase 2 — require JWT_SECRET in production)

## Files Created/Modified

- `dlp-server/src/admin_auth.rs` — new `DEV_JWT_SECRET` const, `resolve_jwt_secret(dev_mode)`, `set_jwt_secret()`, `jwt_secret()` getter (reads OnceLock), `ensure_test_secret()` helper in `#[cfg(test)]` module.
- `dlp-server/src/main.rs` — `Config::dev_mode` field, `--dev` flag parsing, `--dev` entry in the help text, startup call `admin_auth::resolve_jwt_secret(config.dev_mode)` → `admin_auth::set_jwt_secret(secret)` before binding the listener.

## Decisions Made

- **OnceLock over router state.** The plan proposed threading the secret through axum Router state. Implementation chose a `OnceLock<String>` in `admin_auth.rs` instead — simpler, keeps the auth module self-contained, and the JWT secret is truly process-wide (no per-handler wiring churn). Justified because there are only 3 JWT callsites and they all live in `admin_auth.rs`.
- **Error returned as `Result<String, String>`, not `thiserror`.** The error is only surfaced once at startup and printed to stderr. A full error enum would be overkill for a single call site.
- **Warning log fires on every --dev startup.** Not once per process-init — every run of the server with `--dev` logs the warning so it can't be lost in scrollback across restarts.

## Deviations from Plan

**1. State storage mechanism — OnceLock instead of axum Router state**
- **Found during:** Implementation of Step 4 ("Pass the secret through server state")
- **Issue:** Threading the secret through Router state would require updating `AppState`, touching every handler's extractor, and adding a `&str` parameter to `verify_jwt()` / `require_auth()`.
- **Fix:** Used a process-wide `OnceLock<String>` — simpler wiring, same safety property (secret resolved once at startup).
- **Files modified:** `admin_auth.rs` only (no AppState change)
- **Verification:** All 4 admin_auth unit tests pass via `ensure_test_secret()` helper; 31/31 dlp-server lib tests pass at phase close.
- **Committed in:** `664c528` (feature commit)

---

**Total deviations:** 1 (implementation simplification)
**Impact on plan:** Positive — reduced change surface without weakening the security guarantee.

## Issues Encountered

- None. Existing JWT tests initially wouldn't compile because `jwt_secret()` now panics without init — fixed by adding `ensure_test_secret()` helper to the test module. All tests pass.

## Next Phase Readiness

- `dlp-server` is now production-safe against JWT_SECRET oversight.
- 31/31 dlp-server lib tests passing at phase close (verified via `cargo test --package dlp-server --lib`).
- Phase 7 (AD LDAP integration) depends on this phase per ROADMAP — ready to proceed.
- Phase 3 (Wire SIEM connector) and Phase 4 (Wire alert router) have no dependency on this change and can run in parallel.

---
*Phase: 02-require-jwt-secret-in-production*
*Completed: 2026-04-10*
