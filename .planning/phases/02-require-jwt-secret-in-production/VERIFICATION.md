---
status: passed
phase: 02-require-jwt-secret-in-production
verified: 2026-04-10
method: code inspection + cargo test --package dlp-server --lib
---

# Phase 2 Verification: Require JWT_SECRET in Production

**Phase status:** Complete (goal satisfied)
**Method:** Code inspection of the two modified files + `cargo test --package dlp-server --lib`

## Goal (from ROADMAP.md)

> Remove hardcoded dev fallback. Add `--dev` flag to allow insecure secret in development only. Fail on startup otherwise.

## UAT — all criteria met

| # | Criterion | Result | Evidence |
|---|-----------|--------|----------|
| 1 | Server refuses to start without JWT_SECRET and without `--dev` | **PASS** | `admin_auth.rs:37-55` returns `Err` when env var absent and `dev_mode=false`; `main.rs:125-128` maps that Err to an `anyhow::Error` causing `main()` to exit before the listener is bound |
| 2 | Server starts with `--dev` flag and logs a warning | **PASS** | `admin_auth.rs:40-46` logs `tracing::warn!("JWT_SECRET not set — using insecure dev secret (--dev mode)…")` and returns Ok with `DEV_JWT_SECRET` |
| 3 | Server starts normally when `JWT_SECRET` is set | **PASS** | `admin_auth.rs:38-39` returns Ok with the env value; `main.rs:129` stores it via `set_jwt_secret()` before continuing startup |
| 4 | Existing auth tests pass | **PASS** | `test_jwt_round_trip`, `test_expired_token_rejected`, `test_invalid_token_rejected`, `test_login_request_serde` all green — 31/31 dlp-server lib tests passing |

## Test results at phase close

```
cargo test --package dlp-server --lib
...
test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

Includes the 4 `admin_auth::tests` that exercise the JWT path.

## Code-level verification checklist

| Check | File | Line | Status |
|-------|------|------|--------|
| `DEV_JWT_SECRET` constant present | `admin_auth.rs` | 26 | OK |
| `resolve_jwt_secret(dev_mode)` public function | `admin_auth.rs` | 37 | OK |
| Returns Err without env var and without dev_mode | `admin_auth.rs` | 47-54 | OK |
| Warns loudly on dev fallback | `admin_auth.rs` | 40-46 | OK |
| `JWT_SECRET: OnceLock<String>` | `admin_auth.rs` | 61 | OK |
| `set_jwt_secret()` + `jwt_secret()` getter | `admin_auth.rs` | 66-77 | OK |
| `Config::dev_mode` field | `main.rs` | 53 | OK |
| `--dev` arg parsed into `dev_mode` | `main.rs` | 72 | OK |
| `--dev` documented in `--help` | `main.rs` | 98-99 | OK |
| `resolve_jwt_secret` called before binding listener | `main.rs` | 125 | OK |
| Error path prints to stderr and aborts | `main.rs` | 125-128 | OK |
| `login()` / `verify_jwt()` / `require_auth()` use `jwt_secret()` (not env) | `admin_auth.rs` | 168, 331 | OK |

## Commits

| Commit | Scope | Files |
|---|---|---|
| `14c3081 plan: phase 2 — require JWT_SECRET in production` | Plan | PLAN.md |
| `664c528 feat: require JWT_SECRET env var in production (Phase 2, R-08)` | Feature | `admin_auth.rs`, `main.rs` |

## Observations

- The OnceLock pattern used here is a good template for other singleton secrets (e.g. SIEM API tokens, webhook secrets) that Phases 3 and 4 will touch.
- `--dev` is parsed as a boolean presence flag (no value). This matches the other simple boolean flags the project uses (`--help`, `-h`).
- No integration test currently exercises the startup-refusal path (running `dlp-server` without JWT_SECRET and asserting it exits). Code inspection + unit tests cover the branches, but a startup smoke test would give full coverage if desired — not in scope for this phase.

## Re-run command

```
cargo test --package dlp-server --lib
```

Expected: `31 passed; 0 failed`.
