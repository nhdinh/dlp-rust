# Phase 8 Summary: Rate Limiting Middleware

**Date:** 2026-04-15
**Status:** Complete

---

## Changes Made

### New File

- **`dlp-server/src/rate_limiter.rs`** — `tower-governor` integration module containing:
  - `AgentIdOrIpKeyExtractor` — custom `KeyExtractor` that keys by `agent_id` for `/agents/*` routes (from URI path segment) and falls back to peer IP for all other routes.
  - `extract_agent_id_from_path()` — pure helper; parses `agent_id` from paths like `/agents/{id}/heartbeat`.
  - `rate_limit_error_handler()` — converts `GovernorError` → HTTP 429 with `Retry-After` header and JSON body `{"error":"rate_limit_exceeded","retry_after":N}`.
  - Five config constructors: `strict_config()` (5/min, IP), `moderate_config()` (30/min, agent-id), `per_agent_config()` (200/min, agent-id), `policy_config()` (60/min, IP), `default_config()` (100/min, IP).

### Modified Files

- **`dlp-server/Cargo.toml`**
  - Upgraded `axum` from `0.7` → `0.8` (required by `tower-governor 0.8`)
  - Added `axum-core` as a direct dependency
  - Added `governor = "0.10"`, `tower-governor = "0.8"`

- **`dlp-server/src/lib.rs`** — Added `pub mod rate_limiter;` to export the module.

- **`dlp-server/src/admin_api.rs`**
  - Added `use crate::rate_limiter::{self, default_config, policy_config};`
  - Applied `.route_layer(strict_config())` to `POST /auth/login`
  - Applied `.route_layer(moderate_config())` to `POST /agents/{id}/heartbeat`
  - Applied `.route_layer(per_agent_config())` to `POST /audit/events`
  - Applied `.route_layer(policy_config())` to all policy CRUD routes
  - Applied `.route_layer(default_config())` at the router level for remaining protected routes
  - Migrated all `:id` path capture syntax to axum 0.8 `{id}` syntax

- **`dlp-server/src/main.rs`**
  - Changed `axum::serve(listener, app)` → `axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())` to enable peer IP extraction for rate limiting.

- **`dlp-server/src/policy_api.rs`** — Migrated `:id` → `{id}` path syntax (axum 0.8 compatibility).

---

## Rate Limit Summary

| Route | Limit | Window | Key |
|-------|-------|--------|-----|
| `POST /auth/login` | 5 req | 60s | Peer IP (`SmartIpKeyExtractor`) |
| `POST /agents/{id}/heartbeat` | 30 req | 60s | `agent_id` path segment |
| `POST /audit/events` | 200 req | 60s | `agent_id` path segment |
| Policy CRUD (`/policies/*`, `/admin/policies/*`) | 60 req | 60s | Peer IP |
| All other protected routes | 100 req | 60s | Peer IP |

All 429 responses include:
- HTTP status `429 Too Many Requests`
- Header `Retry-After: <seconds>`
- Body `{"error":"rate_limit_exceeded","retry_after":<seconds>}`

---

## Test Results

- **78 tests passed**, 2 ignored (print spooler interception not yet implemented)
- **0 clippy warnings**
- **0 compiler warnings**

---

## Key Technical Decisions

1. **axum 0.7 → 0.8 upgrade**: `tower-governor 0.8` requires axum ≥ 0.8. The upgrade also required migrating `:id` path capture syntax to axum 0.8's `{id}` style throughout the codebase.

2. **`SmartIpKeyExtractor` for login/policy routes**: These routes don't have an `agent_id` in the path, so the extractor falls back to peer IP (via `connect_info`). The router uses `into_make_service_with_connect_info::<SocketAddr>()` to populate this.

3. **`AgentIdOrIpKeyExtractor` for agent routes**: Extracts the `{id}` path segment for `/agents/{id}/*` routes; falls back to peer IP for non-agent routes.

4. **No external state**: Governor stores rate-limit state in-memory (no Redis). Suitable for single-instance deployments; multi-instance would require shared state in a future phase.

5. **`http_body::Body` as response type**: Used in the `GovernorLayer<K, M, Body>` generic to satisfy the `From<GovernorError>` bound via tower-governor's `impl From<GovernorError> for Response<axum::body::Body>`.
