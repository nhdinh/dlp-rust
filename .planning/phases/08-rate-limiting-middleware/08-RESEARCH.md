# Phase 8: Rate Limiting Middleware — Research

**Phase:** 08 — Rate Limiting Middleware
**Researcher:** Claude Sonnet 4.6
**Date:** 2026-04-15
**Confidence:** HIGH

---

## Q1: tower-governor API for axum

**Setup pattern:**

```rust
use tower_governor::{GovernorConfigBuilder, GovernorLayer};
use std::net::SocketAddr;

// For IP extraction, must use into_make_service_with_connect_info:
let app = Router::new()
    .route("/login", post(login_handler))
    .layer(GovernorLayer::new(
        GovernorConfigBuilder::default()
            .per_second(60)        // 60-second window
            .burst_size(5)         // 5 requests max
            .key_extractor(SmartIpKeyExtractor {})
            .finish()
            .unwrap()
    ))
    .into_make_service_with_connect_info::<SocketAddr>();
```

**Key types:**
- `PeerIpKeyExtractor` — direct peer IP (no proxies)
- `SmartIpKeyExtractor` — checks `X-Forwarded-For`, `X-Real-IP`, `Forwarded` headers
- Custom: implement `KeyExtractor` trait

**Per-route layers:** Each `.route()` call can have its own `.layer(GovernorLayer::new(...))` with different limits.

**Compatibility:** Requires `axum ^0.8`, `tower ^0.5.1`. Check `dlp-server/Cargo.toml` for current axum version.

---

## Q2: Key extraction for IP vs agent_id

**IP-based (admin endpoints):** `SmartIpKeyExtractor {}` handles the proxy headers automatically.

**Custom key (agent endpoints):** Implement `KeyExtractor`:

```rust
use tower_governor::KeyExtractor;
use axum::extract::Request;
use std::convert::Infallible;

pub struct AgentIdKeyExtractor;

impl KeyExtractor for AgentIdKeyExtractor {
    type Key = String;
    type Config = ();
    type Error = Infallible;

    fn extract(&self, request: &Request) -> Result<Self::Key, Self::Error> {
        // Extract from path: /agents/:id/heartbeat
        // or from JWT claims in Authorization header
        let path = request.uri().path();
        // Parse agent_id from path
        Ok(agent_id)
    }
}
```

**Agent endpoints use path-based extraction:** Extract `agent_id` from URI path segments (`/agents/{id}/heartbeat`).

---

## Q3: 429 Response with Retry-After

**Default:** `tower-governor` returns 503 by default in older versions, 429 in newer. Check version.

**Custom response body:**
```rust
use tower_governor::GovernorError;

async fn rate_limit_error_handler(request: Request, error: GovernorError) -> impl IntoResponse {
    let retry_after = error
        .wait_time_from_now()
        .as_secs()
        .to_string();

    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after)],
        Json(json!({
            "error": "rate_limit_exceeded",
            "retry_after": retry_after
        })),
    ).into_response()
}

GovernorLayer::new(config)
    .with_error_handler(rate_limit_error_handler)
```

**Headers set automatically:** `x-ratelimit-after`, `retry-after` (when using `.use_headers()`).

---

## Q4: Known issues

1. **axum version:** `tower-governor` requires `axum >= 0.7`. If `dlp-server` uses older axum, upgrade first.
2. **SocketAddr requirement:** For IP-based limiting, must use `into_make_service_with_connect_info::<SocketAddr>()`. If currently using `into_make_service()`, this is a breaking change.
3. **Shared state:** The `Governor` limiter is created once per router. If router is rebuilt per-request (unlikely here), limits won't work correctly.
4. **Proxy awareness:** `SmartIpKeyExtractor` handles common proxy headers but requires trusting `X-Forwarded-For` (acceptable in internal network).

---

## Q5: Cargo.toml dependencies

```toml
governor = "0.6"   # rate limiter core
tower-governor = "0.4"  # tower middleware layer
```

Check for compatible axum version:
```bash
grep axum dlp-server/Cargo.toml
```

---

## Q6: Composition with existing middleware

**Layer order matters:**

```
Request
  → require_auth middleware (admin_api.rs:400)
  → GovernorLayer (rate limit)
  → Handler
```

**Implementation:** Add `GovernorLayer` inside `admin_router()`, before or after `require_auth`. Both are tower middleware — order is typically: rate limit first (reject early), then auth.

```rust
let protected_routes = Router::new()
    .route("/login", post(login))
    // rate limit before auth — reject before auth check
    .layer(GovernorLayer::new(strict_config))
    .layer(middleware::from_fn(admin_auth::require_auth));
```

---

## Q7: Agent ID extraction from JWT

**Current pattern:** `admin_auth::require_auth` extracts the JWT. We can do the same.

```rust
use axum::extract::Request;
use axum::middleware::Next;
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::sync::Arc;

// Inside a custom key extractor or a middleware:
fn extract_agent_id_from_jwt(auth_header: &str) -> Option<String> {
    let token = auth_header.strip_prefix("Bearer ")?;
    let claims: Value = decode(token, &DecodingKey::from_secret(...), &Validation::default())
        .ok()?;
    claims.get("sub").or(claims.get("agent_id"))?.as_str().map(String::from)
}
```

**Simpler approach for this phase:** Extract agent_id from the URI path directly (`/agents/{id}/heartbeat`). No JWT parsing needed.

---

## Q8: Background cleanup

Governor stores state in-memory. Periodic cleanup is recommended:
```rust
// In server startup (main.rs):
tokio::spawn(async {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        governor_limiter.retain_recent();
    }
});
```

Or use `governor::registry::Registry::retain_recent()` on the shared limiter.

---

## Open Questions

1. **axum version** — must verify `axum >= 0.7` before adding tower-governor. If not, plan must include an axum upgrade step.
2. **SocketAddr breaking change** — `into_make_service_with_connect_info::<SocketAddr>()` requires `main.rs` to change `axum::serve(listener, app)` to `axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())`. This affects the `serve` call signature.
3. **Per-route limits** — does each `.route()` need its own `GovernorLayer`, or can a single router-level layer handle different limits by path? Answer: each route that needs different limits needs its own layer.

---

## Plan Readiness

Research complete. Key findings:
- `tower-governor` with `GovernorLayer::new()` + `GovernorConfigBuilder` is the canonical API
- `SmartIpKeyExtractor` for admin endpoints (IP-based), path-based agent_id extraction for agent endpoints
- Custom error handler needed for 429 + `Retry-After` JSON body
- **Critical:** `axum` version must be `>= 0.7`; `into_make_service_with_connect_info::<SocketAddr>()` required for IP extraction
- Single-plan is sufficient for this phase
