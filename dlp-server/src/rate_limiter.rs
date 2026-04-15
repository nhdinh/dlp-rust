//! Rate limiting middleware using `tower-governor` / `governor`.
//!
//! Applies per-endpoint rate limits keyed by IP address or agent ID.
//! Returns `429 Too Many Requests` with `Retry-After` header and JSON body
//! when a limit is exceeded.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::Request;
use http::{header::RETRY_AFTER, Response, StatusCode};
use governor::middleware::NoOpMiddleware;
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::{KeyExtractor, SmartIpKeyExtractor},
    GovernorError, GovernorLayer,
};

/// Custom key extractor that derives the rate-limit key from the `agent_id`
/// path segment for agent routes, or falls back to the peer's socket address
/// for all other routes.
///
/// This allows the heartbeat and event-ingestion endpoints to be rate-limited
/// **per agent** rather than per IP, preventing one misbehaving agent from
/// affecting others.
#[derive(Clone, Copy, Debug, Default)]
pub struct AgentIdOrIpKeyExtractor;

impl KeyExtractor for AgentIdOrIpKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let path = req.uri().path();

        // Agent-specific routes — key by the :id path segment.
        if let Some(id) = extract_agent_id_from_path(path) {
            return Ok(id);
        }

        // Fall back to peer IP (requires `connect_info` in the Router).
        let peer = req
            .extensions()
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
            .unwrap_or_else(|| "unknown".to_owned());

        Ok(peer)
    }
}

/// Parses `agent_id` from a URI path such as `/agents/{id}/heartbeat` or
/// `/agents/{id}`.
///
/// Returns `None` if the path does not match the expected pattern.
pub fn extract_agent_id_from_path(path: &str) -> Option<String> {
    let after_prefix = path.strip_prefix("/agents/")?;
    let end = after_prefix.find('/').unwrap_or(after_prefix.len());
    let id = &after_prefix[..end];
    if id.is_empty() {
        None
    } else {
        Some(id.to_owned())
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
pub fn moderate_config(
) -> GovernorLayer<AgentIdOrIpKeyExtractor, NoOpMiddleware, Body> {
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
pub fn per_agent_config(
) -> GovernorLayer<AgentIdOrIpKeyExtractor, NoOpMiddleware, Body> {
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
pub fn default_config(
) -> GovernorLayer<AgentIdOrIpKeyExtractor, NoOpMiddleware, Body> {
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
pub fn policy_config(
) -> GovernorLayer<AgentIdOrIpKeyExtractor, NoOpMiddleware, Body> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_agent_id_from_path() {
        assert_eq!(
            extract_agent_id_from_path("/agents/abc-123/heartbeat"),
            Some("abc-123".to_owned())
        );
        assert_eq!(
            extract_agent_id_from_path("/agents/my-agent-id"),
            Some("my-agent-id".to_owned())
        );
        assert_eq!(
            extract_agent_id_from_path(
                "/agents/550e8400-e29b-41d4-a716-446655440000/events"
            ),
            Some("550e8400-e29b-41d4-a716-446655440000".to_owned())
        );
        assert_eq!(extract_agent_id_from_path("/policies"), None);
        assert_eq!(extract_agent_id_from_path("/health"), None);
        assert_eq!(extract_agent_id_from_path("/agents/"), None);
    }
}
