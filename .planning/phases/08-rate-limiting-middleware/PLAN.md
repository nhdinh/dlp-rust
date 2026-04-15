---
wave: 1
depends_on: []
files_modified:
  - dlp-server/Cargo.toml
  - dlp-server/src/rate_limiter.rs (NEW)
  - dlp-server/src/admin_api.rs
  - dlp-server/src/main.rs
autonomous: true
requirements: [R-07]
---

# Phase 08: Rate Limiting Middleware — Implementation Plan

## Threat Model

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| Brute-force login attack | Medium | High | Strict limit: 5 req/60s per IP on `/auth/login` |
| Agent heartbeat flooding | Low | Medium | Moderate limit: 30 req/60s per agent on heartbeat |
| Event ingestion DoS from one agent | Medium | Medium | Per-agent limit: 200 req/60s on `/audit/events` |
| Policy enumeration/DoS via admin API | Low | Medium | Moderate limit: 60 req/60s per IP on policy routes |
| General API abuse | Medium | Low | Default: 100 req/60s per IP on remaining admin routes |

---

## Task 1 — Add Dependencies

**Action:** Add `governor` and `tower-governor` to `dlp-server/Cargo.toml`.

```toml
# Concurrency section in dlp-server/Cargo.toml
governor = "0.6"
tower-governor = "0.4"
```

No workspace-level version needed — these are server-only.

**Verification:** `cargo check -p dlp-server`

---

## Task 2 — Create `rate_limiter.rs`

Create `dlp-server/src/rate_limiter.rs` with:

- **`AgentIdKeyExtractor`** — custom `KeyExtractor` that parses `agent_id` from the URI path (e.g. `/agents/uuid/heartbeat`). Returns the full `agent_id` string as the rate-limit key.
- **`rate_limit_error_handler`** — async error handler that returns `429 Too Many Requests` with:
  - Header: `Retry-After: <seconds>`
  - Body: `{"error": "rate_limit_exceeded", "retry_after": <seconds>}`
- **`make_governor_config`** — helper to construct a `GovernorConfig` with `error_handler`.

**Agent ID extraction logic:**
```
1. Parse request.uri().path() as &str
2. If path contains "/agents/", split on that prefix
3. Take the segment up to the next '/' — this is the agent_id
4. Return agent_id as String key
5. Fallback: use "unknown" for paths that don't match
```

For path `/agents/uuid/heartbeat` → key = `"uuid"`

---

## Task 3 — Build Rate-Limited Router in `admin_api.rs`

In `admin_router()`, wrap each route group with a `GovernorLayer`:

### Strict — Login (5 req/60s, IP-based)

```rust
let public_routes = Router::new()
    .route("/health", get(health))
    .route("/ready", get(ready))
    .route("/auth/login", post(admin_auth::login)
        .layer(GovernorLayer::new(strict_config())))
    .route("/agents/register", post(agent_registry::register_agent))
    .route("/agents/:id/heartbeat", post(agent_registry::heartbeat)
        .layer(GovernorLayer::new(moderate_config())))
    .route("/audit/events", post(audit_store::ingest_events)
        .layer(GovernorLayer::new(per_agent_config())))
    .route("/agent-credentials/auth-hash", get(get_agent_auth_hash))
    .route("/agent-config/:id", get(get_agent_config_for_agent));
```

### Moderate — Policy Routes (60 req/60s, IP-based)

```rust
let protected_routes = Router::new()
    .route("/agents", get(agent_registry::list_agents))
    .route("/agents/:id", get(agent_registry::get_agent))
    .route("/audit/events", get(audit_store::query_events))
    .route("/audit/events/count", get(audit_store::get_event_count))
    .route("/policies", get(list_policies).post(create_policy)
        .layer(GovernorLayer::new(moderate_config())))
    .route("/policies/:id", get(get_policy).put(update_policy).delete(delete_policy)
        .layer(GovernorLayer::new(moderate_config())))
    // ... remaining routes with moderate/default limit
```

### Default — Remaining Protected Routes (100 req/60s, IP-based)

Wrap remaining routes with `default_config()` (100 req/60s, IP-based).

---

## Task 4 — Update `main.rs` to Use `connect_info`

**Change:**

```rust
// Before
let app = admin_api::admin_router(Arc::clone(&state));
axum::serve(listener, app)

// After
let app: Router<_, std::net::SocketAddr> = admin_api::admin_router(Arc::clone(&state))
    .into_make_service_with_connect_info::<std::net::SocketAddr>();
axum::serve(listener, app)
```

**Reason:** `SmartIpKeyExtractor` (used for admin/IP-based endpoints) reads the peer address from the connect info. Without `into_make_service_with_connect_info`, the IP is not available to the middleware.

---

## Task 5 — Background Cleanup Task

Add to `main.rs` after router build:

```rust
// Spawn governor cleanup task (runs every 60s to prune stale entries)
tokio::spawn(async {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        // governor::Registry::retain_recent() prunes tokens outside the window
        // Note: the limiter is embedded in the Router; spawn a task that holds a
        // weak reference or use a shared Arc<Governor> if cleanup is needed.
        // For tower-governor 0.4, the limiter is held inside the layer.
        tracing::debug!("rate limiter tick");
    }
});
```

> **Note:** `tower-governor` 0.4 stores the limiter inside the `GovernorLayer` and does not expose a public `retain_recent` API at the router level. The cleanup task above is a no-op placeholder. If governor proves to leak memory over long uptimes, a future task will refactor to use a shared `Arc<Governor>` with explicit cleanup.

---

## Rate Limit Constants

| Endpoint | Limit | Window | Key Extractor | Class |
|----------|-------|--------|---------------|-------|
| `POST /auth/login` | 5 req | 60s | `SmartIpKeyExtractor` | strict |
| `POST /agents/:id/heartbeat` | 30 req | 60s | `AgentIdKeyExtractor` | moderate |
| `POST /audit/events` | 200 req | 60s | `AgentIdKeyExtractor` | per-agent |
| Policy routes | 60 req | 60s | `SmartIpKeyExtractor` | moderate |
| All other routes | 100 req | 60s | `SmartIpKeyExtractor` | default |

---

## 429 Response Format

```json
HTTP/1.1 429 Too Many Requests
Retry-After: 60
Content-Type: application/json

{"error": "rate_limit_exceeded", "retry_after": 60}
```

---

## Implementation Order

1. Add dependencies to `Cargo.toml` → verify build
2. Create `rate_limiter.rs` with key extractors + error handler
3. Update `admin_api.rs` — apply `GovernorLayer` per-route
4. Update `main.rs` — `into_make_service_with_connect_info`
5. Add background cleanup task stub
6. Run `cargo build -p dlp-server` — verify no warnings
7. Run `cargo clippy -p dlp-server -- -D warnings`
8. Run `cargo fmt --check`

---

## Acceptance Criteria

- [ ] `POST /auth/login` returns `429` after 5 requests in 60s from same IP
- [ ] `POST /agents/:id/heartbeat` returns `429` after 30 requests in 60s per agent_id
- [ ] `POST /audit/events` returns `429` after 200 requests in 60s per agent_id
- [ ] Policy routes return `429` after 60 requests in 60s per IP
- [ ] All 429 responses include correct `Retry-After` header and JSON body
- [ ] `main.rs` uses `into_make_service_with_connect_info::<SocketAddr>()`
- [ ] No new compiler warnings or clippy errors
- [ ] Build passes with `cargo build -p dlp-server`