# Phase 8: Rate Limiting Middleware — Context

**Gathered:** 2026-04-15
**Status:** Ready for planning
**Source:** /gsd-discuss-phase (skipped — going with sensible defaults)

<domain>
## Phase Boundary

Add rate limiting to `dlp-server` HTTP endpoints using `tower-governor` (based on `governor` crate).
Apply per-endpoint rate classes: strict (login), moderate (heartbeat, policy CRUD), per-agent (event ingestion).
Requirement: R-07 (no rate limiting on server endpoints).

**In scope:**
- `tower-governor` middleware on `dlp-server/src/main.rs` router
- Per-endpoint rate limit classes: strict, moderate, per-agent
- Return `429 Too Many Requests` when limit exceeded
- Memory-only state (no Redis)

**Out of scope:**
- Redis-backed distributed rate limiting
- Configurable limits via DB (hardcoded for v0.3.0)
- IP-based rate limiting (agent ID based instead)

</domain>

<decisions>
## Implementation Decisions

### A — Library: tower-governor

**Decision:** Use `tower-governor` crate (wraps `governor` rate limiter) on the axum router.

Rationale: Tower-compatible, non-blocking, no async overhead. Works with in-memory state.
`governor` is the de-facto standard for in-process rate limiting in Rust.

Add to `dlp-server/Cargo.toml`: `tower-governor = "0.4"` + `governor = "0.6"`.

### B — Rate Limit Configuration

**Decision:** Hardcode limits in `main.rs` constants. Not DB-managed in this phase.

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /auth/login` | 5 req | 60s | IP address |
| `POST /agents/:id/heartbeat` | 30 req | 60s | agent_id |
| `GET/POST/PUT/DELETE /policies/*` | 60 req | 60s | IP address |
| `POST /audit/events` | 200 req | 60s | agent_id |
| All other admin endpoints | 100 req | 60s | IP address |

Rationale: Login is strictest (brute-force protection). Heartbeat is moderate (agents send every 30s).
Event ingestion is per-agent (prevent one agent from flooding the server). Admin API is IP-limited.

### C — Keying Strategy

**Decision:** IP-based for admin endpoints (login, policy CRUD), agent-ID-based for agent endpoints.

Rationale: Admins come from varied IPs. Agents always identify themselves by agent_id (from JWT or from path).
Agent-id keying on heartbeat/event ingestion prevents one misbehaving agent from affecting others.

### D — 429 Response Body

**Decision:** Return `429 Too Many Requests` with `Retry-After` header and JSON body:
```json
{"error": "rate_limit_exceeded", "retry_after": 60}
```

Rationale: Standard format, client-readable, respects the `Retry-After` header for automated clients.

### E — Burst Handling

**Decision:** Use `NotKeyed` or small burst allowance. No penalty for legitimate traffic spikes.

Rationale: Agents may batch-send events after offline period. Burst allowance of ~2-3x limit accommodates this
without requiring Redis. Excess above burst is hard-limited by the quota.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Rate limiting
- `dlp-server/src/main.rs` — where to add router middleware
- `dlp-server/src/admin_api.rs` — `admin_router()` function, route structure
- `dlp-server/Cargo.toml` — add tower-governor dependency

### Existing middleware pattern
- `admin_api.rs:400` — `.layer(middleware::from_fn(admin_auth::require_auth))` — existing layer pattern

### Config pattern (for future)
- `.planning/phases/04-wire-alert-router-into-server/04-CONTEXT.md` — hardcoded config → DB-managed pattern

</canonical_refs>

<deferred>
## Deferred Ideas

- DB-managed configurable limits (Phase 8.x or 8.1)
- Redis-backed distributed rate limiting for multi-instance deployment
- IP-based rate limiting for admin endpoints as alternative to token-based
- Per-user (admin user ID) rate limiting for admin API

</deferred>

---

*Phase: 08-rate-limiting-middleware*
*Context gathered: 2026-04-15 via /gsd-discuss-phase (skipped)*