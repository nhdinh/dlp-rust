//! Negative and edge-case tests for the DLP Agent.
//!
//! These tests verify error handling, retry exhaustion, cache eviction,
//! and graceful degradation under failure conditions.

use std::time::Duration;

use dlp_common::{Action, Classification, Decision, EvaluateRequest, EvaluateResponse};

// ─────────────────────────────────────────────────────────────────────────────
// Mock engines for error scenarios
// ─────────────────────────────────────────────────────────────────────────────

/// Starts a mock engine that always returns the given HTTP status code.
async fn start_error_engine(
    status_code: u16,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use axum::{http::StatusCode, routing::post, Router};
    use tokio::net::TcpListener;

    let app = Router::new().route(
        "/evaluate",
        post(move || async move { StatusCode::from_u16(status_code).unwrap() }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine unreachable tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_engine_unreachable_t4_denied() {
    use dlp_agent::cache::{self, Cache};

    let cache = Cache::new();
    // No engine, no cache entry → fail-closed for T4.
    let result = cache.get(r"C:\Restricted\secret.xlsx", "S-1-5-21-999");
    assert!(result.is_none());
    let fallback = cache::fail_closed_response(Classification::T4);
    assert!(fallback.decision.is_denied());
}

#[tokio::test]
async fn test_engine_unreachable_t1_allowed() {
    use dlp_agent::cache::{self, Cache};

    let cache = Cache::new();
    let result = cache.get(r"C:\Public\readme.txt", "S-1-5-21-999");
    assert!(result.is_none());
    let fallback = cache::fail_closed_response(Classification::T1);
    assert!(!fallback.decision.is_denied());
}

// ─────────────────────────────────────────────────────────────────────────────
// Retry behaviour tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_engine_500_retry_exhausted() {
    use dlp_agent::engine_client::{EngineClient, EngineClientError};

    let (addr, _h) = start_error_engine(500).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();

    let request = make_request(Classification::T3);
    let result = client.evaluate(&request).await;
    assert!(result.is_err());
    // After retries exhaust, should get an HttpError with status 500.
    match result.unwrap_err() {
        EngineClientError::HttpError { status, .. } => assert_eq!(status, 500),
        other => panic!("expected HttpError(500), got {other:?}"),
    }
}

#[tokio::test]
async fn test_engine_400_no_retry() {
    use dlp_agent::engine_client::{EngineClient, EngineClientError};

    let (addr, _h) = start_error_engine(400).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();

    let request = make_request(Classification::T2);
    let result = client.evaluate(&request).await;
    assert!(result.is_err());
    // 400 is not retryable — should get immediate error.
    match result.unwrap_err() {
        EngineClientError::HttpError { status, .. } => assert_eq!(status, 400),
        other => panic!("expected HttpError(400), got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_cache_bulk_eviction() {
    use dlp_agent::cache::Cache;

    let cache = Cache::with_ttl(Duration::from_millis(10));
    for i in 0..100 {
        cache.insert(
            &format!(r"C:\Data\file{i}.txt"),
            "S-1-5-21-BULK",
            EvaluateResponse {
                decision: Decision::ALLOW,
                matched_policy_id: None,
                reason: "bulk".into(),
            },
        );
    }
    assert_eq!(cache.len(), 100);

    // Wait for TTL expiry.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Explicit eviction.
    cache.evict_expired();
    assert_eq!(cache.len(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit emitter edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_audit_dir_creation() {
    use dlp_agent::audit_emitter::AuditEmitter;

    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("deeply").join("nested").join("dir");
    let emitter = AuditEmitter::open(&nested, "audit.jsonl", 50 * 1024 * 1024);
    assert!(emitter.is_ok());
    assert!(nested.join("audit.jsonl").exists());
}

// ─────────────────────────────────────────────────────────────────────────────
// file monitor capacity
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Clipboard edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_empty_clipboard_t1() {
    use dlp_agent::clipboard::ContentClassifier;
    assert_eq!(ContentClassifier::classify(""), Classification::T1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_request(classification: Classification) -> EvaluateRequest {
    EvaluateRequest {
        subject: dlp_common::Subject::default(),
        resource: dlp_common::Resource {
            path: r"C:\Data\test.xlsx".into(),
            classification,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: Action::WRITE,
    }
}
