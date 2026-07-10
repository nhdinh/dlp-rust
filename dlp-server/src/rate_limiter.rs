//! Rate limiting middleware using `tower-governor` / `governor`.
//!
//! Applies per-endpoint rate limits keyed by IP address or agent ID.
//! Returns `429 Too Many Requests` with `Retry-After` header and JSON body
//! when a limit is exceeded.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::Request;
use governor::middleware::NoOpMiddleware;
use http::{header::RETRY_AFTER, Response, StatusCode};
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::{KeyExtractor, SmartIpKeyExtractor},
    GovernorError, GovernorLayer,
};

/// Custom key extractor that derives the rate-limit key from the authenticated
/// `agent_id` in request extensions (set by `agent_auth_middleware`) when
/// present, and otherwise falls back to the peer's socket address.
///
/// It deliberately does **not** key on the `:id` path segment for agent routes:
/// on `/agents/{id}/...` the limiter runs *before* `agent_auth_middleware` has
/// populated the extension, so the only identity available at extract time is
/// the (attacker-controlled) URL. Keying on the path id let a single
/// credential-holder rotate `:id` per request to obtain a fresh bucket each
/// time, defeating per-agent isolation (WR-06). The peer IP is the only
/// pre-authentication value worth trusting here; per-agent fairness for the
/// agent routes is enforced inside the authenticated handler instead.
#[derive(Clone, Copy, Debug, Default)]
pub struct AgentIdOrIpKeyExtractor;

impl KeyExtractor for AgentIdOrIpKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        // Prefer authenticated agent identity when the limiter happens to run
        // after `agent_auth_middleware` (auth-outermost composition).
        if let Some(agent_id) = req.extensions().get::<String>() {
            return Ok(agent_id.clone());
        }

        // Fall back to peer IP (requires `connect_info` in the Router). The
        // `:id` path segment is intentionally NOT used as a key — see the
        // struct-level comment (WR-06).
        let peer = req
            .extensions()
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
            .unwrap_or_else(|| "unknown".to_owned());

        Ok(peer)
    }
}

/// Error handler: converts any `GovernorError` into HTTP 429 with a
/// `Retry-After` header and JSON body.
fn rate_limit_error_handler(err: GovernorError) -> Response<Body> {
    let wait_time = match &err {
        GovernorError::TooManyRequests { wait_time, .. } => *wait_time,
        _ => 60,
    };

    let body = serde_json::to_string(&serde_json::json!({
        "error": "rate_limit_exceeded",
        "retry_after": wait_time
    }))
    .expect("JSON serialisation must not fail");

    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(RETRY_AFTER, wait_time.to_string())
        .body(Body::from(body))
        .expect("Response builder must produce valid response")
}

// ---------------------------------------------------------------------------
// Configuration helpers
// ---------------------------------------------------------------------------

/// Strict limit: 5 requests per 60 seconds. Used for `/auth/login`.
pub fn strict_config() -> GovernorLayer<SmartIpKeyExtractor, NoOpMiddleware, Body> {
    GovernorLayer::new(
        GovernorConfigBuilder::default()
            .per_second(60)
            .burst_size(5)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("strict GovernorConfig should always be valid"),
    )
    .error_handler(rate_limit_error_handler)
}

/// Moderate limit: 30 requests per 60 seconds. Used for `/agents/:id/heartbeat`.
pub fn moderate_config() -> GovernorLayer<AgentIdOrIpKeyExtractor, NoOpMiddleware, Body> {
    GovernorLayer::new(
        GovernorConfigBuilder::default()
            .per_second(60)
            .burst_size(30)
            .key_extractor(AgentIdOrIpKeyExtractor)
            .finish()
            .expect("moderate GovernorConfig should always be valid"),
    )
    .error_handler(rate_limit_error_handler)
}

/// Per-agent limit: 200 requests per 60 seconds. Used for `/audit/events`.
pub fn per_agent_config() -> GovernorLayer<AgentIdOrIpKeyExtractor, NoOpMiddleware, Body> {
    GovernorLayer::new(
        GovernorConfigBuilder::default()
            .per_second(60)
            .burst_size(200)
            .key_extractor(AgentIdOrIpKeyExtractor)
            .finish()
            .expect("per-agent GovernorConfig should always be valid"),
    )
    .error_handler(rate_limit_error_handler)
}

/// Default limit: 100 requests per 60 seconds. Used for remaining admin routes.
pub fn default_config() -> GovernorLayer<AgentIdOrIpKeyExtractor, NoOpMiddleware, Body> {
    GovernorLayer::new(
        GovernorConfigBuilder::default()
            .per_second(60)
            .burst_size(100)
            .key_extractor(AgentIdOrIpKeyExtractor)
            .finish()
            .expect("default GovernorConfig should always be valid"),
    )
    .error_handler(rate_limit_error_handler)
}

/// Policy route limit: 60 requests per 60 seconds. Used for policy CRUD.
pub fn policy_config() -> GovernorLayer<AgentIdOrIpKeyExtractor, NoOpMiddleware, Body> {
    GovernorLayer::new(
        GovernorConfigBuilder::default()
            .per_second(60)
            .burst_size(60)
            .key_extractor(AgentIdOrIpKeyExtractor)
            .finish()
            .expect("policy GovernorConfig should always be valid"),
    )
    .error_handler(rate_limit_error_handler)
}

/// Diagnostics route limit: 30 requests per 60 seconds. Used for /admin/diagnostics.
/// Diagnostic queries can be expensive (sorting all snapshots across all DLLs),
/// so this is tighter than the default admin limit.
pub fn diagnostics_config() -> GovernorLayer<AgentIdOrIpKeyExtractor, NoOpMiddleware, Body> {
    GovernorLayer::new(
        GovernorConfigBuilder::default()
            .per_second(60)
            .burst_size(30)
            .key_extractor(AgentIdOrIpKeyExtractor)
            .finish()
            .expect("diagnostics GovernorConfig should always be valid"),
    )
    .error_handler(rate_limit_error_handler)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Authenticated identity (populated by `agent_auth_middleware`) always
    /// wins, regardless of the path. This is the auth-outermost case.
    #[test]
    fn test_extract_authenticated_agent_id_from_extensions() {
        let mut req = Request::builder()
            .uri("/agents/abc-123/health")
            .body(())
            .expect("build request");
        req.extensions_mut().insert("auth-agent-1".to_string());

        assert_eq!(
            AgentIdOrIpKeyExtractor.extract(&req).expect("extract"),
            "auth-agent-1".to_owned()
        );
    }

    /// WR-06: when the limiter runs before authentication (the agent-route
    /// composition), the `:id` path segment must NOT be used as the key — it
    /// is attacker-controlled. With no authenticated extension and no
    /// `ConnectInfo`, the extractor falls back to the `"unknown"` bucket
    /// rather than minting a per-`:id` bucket.
    #[test]
    fn test_extract_agent_route_falls_back_to_unknown_without_auth() {
        let req = Request::builder()
            .uri("/agents/abc-123/heartbeat")
            .body(())
            .expect("build request");

        assert_eq!(
            AgentIdOrIpKeyExtractor.extract(&req).expect("extract"),
            "unknown".to_owned()
        );
    }

    /// WR-06: with no authenticated extension, the peer IP from `ConnectInfo`
    /// is used as the key. This is the only pre-authentication value worth
    /// trusting.
    #[test]
    fn test_extract_uses_peer_ip_from_connect_info() {
        let mut req = Request::builder()
            .uri("/agents/abc-123/heartbeat")
            .body(())
            .expect("build request");
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::from(([10, 0, 0, 5], 4242))));

        assert_eq!(
            AgentIdOrIpKeyExtractor.extract(&req).expect("extract"),
            "10.0.0.5".to_owned()
        );
    }

    /// WR-06 regression guard: two requests that differ only in the `:id`
    /// path segment — the attack the reviewer described — must collapse to
    /// the SAME bucket so rotating `:id` cannot yield a fresh bucket per
    /// request. Both resolve to `"unknown"` here because no `ConnectInfo` is
    /// present; the important property is equality, not the literal value.
    #[test]
    fn test_distinct_path_ids_share_one_bucket() {
        let req_a = Request::builder()
            .uri("/agents/agent-a/health")
            .body(())
            .expect("build request a");
        let req_b = Request::builder()
            .uri("/agents/agent-b/health")
            .body(())
            .expect("build request b");

        let key_a = AgentIdOrIpKeyExtractor.extract(&req_a).expect("extract a");
        let key_b = AgentIdOrIpKeyExtractor.extract(&req_b).expect("extract b");
        assert_eq!(
            key_a, key_b,
            "distinct :id values must not produce distinct buckets (WR-06)"
        );
    }
}
