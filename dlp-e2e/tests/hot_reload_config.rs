//! Hot-reload verification tests for all config subsystems.
//!
//! These tests verify that configuration changes made via the admin API
//! are immediately reflected in subsequent GET calls. This automates the
//! deferred Phase 4 UAT item for hot-reload verification.
//!
//! Each test follows the same pattern:
//! 1. GET current config (default values seeded by db::new_pool)
//! 2. PUT new config values
//! 3. GET again and assert exact value matching

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use dlp_common::{EvaluateRequest, EvaluateResponse};
use dlp_e2e::helpers;
use serde_json::json;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds a PUT request with a JSON payload and Bearer auth header.
fn build_put_request(path: &str, payload: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(Method::PUT)
        .uri(path)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", helpers::server::mint_jwt()))
        .body(Body::from(payload.to_string()))
        .expect("build PUT request")
}

/// Builds a GET request with a Bearer auth header.
fn build_get_request(path: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("Authorization", format!("Bearer {}", helpers::server::mint_jwt()))
        .body(Body::empty())
        .expect("build GET request")
}

/// Sends a PUT request and returns the response status.
async fn put_config(app: &mut Router, path: &str, payload: serde_json::Value) -> StatusCode {
    let req = build_put_request(path, payload);
    let response = app.oneshot(req).await.expect("send PUT request");
    response.status()
}

/// Sends a GET request and returns (status, parsed JSON body).
async fn get_config(app: &mut Router, path: &str) -> (StatusCode, serde_json::Value) {
    let req = build_get_request(path);
    let response = app.oneshot(req).await.expect("send GET request");
    let status = response.status();
    let body_bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("parse JSON response");
    (status, json)
}

// ---------------------------------------------------------------------------
// Test 1: SIEM config hot-reload
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_siem_config_hot_reload() {
    let (mut app, _pool) = helpers::server::build_test_app();

    // Step 1: GET default config
    let (status, default) = get_config(&mut app, "/admin/siem-config").await;
    assert_eq!(status, StatusCode::OK, "GET siem-config should return 200");
    // Default values are seeded by db::new_pool — just verify they exist
    assert!(
        default.get("splunk_url").is_some(),
        "default siem config should have splunk_url"
    );

    // Step 2: PUT new config values
    let put_payload = json!({
        "splunk_url": "https://splunk.example.com/services/collector/event",
        "splunk_token": "test-token-123",
        "splunk_enabled": true,
        "elk_url": "https://elastic.example.com:9200",
        "elk_index": "dlp_test",
        "elk_api_key": "elk-key-456",
        "elk_enabled": false
    });

    let put_status = put_config(&mut app, "/admin/siem-config", put_payload.clone()).await;
    assert_eq!(put_status, StatusCode::OK, "PUT siem-config should return 200");

    // Step 3: GET again and assert exact matching
    let (status, fetched) = get_config(&mut app, "/admin/siem-config").await;
    assert_eq!(status, StatusCode::OK, "GET siem-config after PUT should return 200");
    assert_eq!(
        fetched["splunk_url"],
        "https://splunk.example.com/services/collector/event"
    );
    assert_eq!(fetched["splunk_token"], "test-token-123");
    assert_eq!(fetched["splunk_enabled"], true);
    assert_eq!(fetched["elk_url"], "https://elastic.example.com:9200");
    assert_eq!(fetched["elk_index"], "dlp_test");
    assert_eq!(fetched["elk_api_key"], "elk-key-456");
    assert_eq!(fetched["elk_enabled"], false);
}

// ---------------------------------------------------------------------------
// Test 2: Alert config hot-reload (with password masking)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_alert_config_hot_reload() {
    let (mut app, _pool) = helpers::server::build_test_app();

    // Step 1: GET default config
    let (status, default) = get_config(&mut app, "/admin/alert-config").await;
    assert_eq!(status, StatusCode::OK, "GET alert-config should return 200");
    assert!(
        default.get("smtp_host").is_some(),
        "default alert config should have smtp_host"
    );

    // Step 2: PUT new config values (including a password)
    let put_payload = json!({
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "smtp_username": "dlp-alerts",
        "smtp_password": "secret-password-123",
        "smtp_from": "dlp@example.com",
        "smtp_to": "security@example.com",
        "smtp_enabled": true,
        "webhook_url": "https://hooks.example.com/dlp",
        "webhook_secret": "webhook-secret-456",
        "webhook_enabled": true
    });

    let put_status = put_config(&mut app, "/admin/alert-config", put_payload.clone()).await;
    assert_eq!(put_status, StatusCode::OK, "PUT alert-config should return 200");

    // Step 3: GET again and assert values match (password masked)
    let (status, fetched) = get_config(&mut app, "/admin/alert-config").await;
    assert_eq!(status, StatusCode::OK, "GET alert-config after PUT should return 200");
    assert_eq!(fetched["smtp_host"], "smtp.example.com");
    assert_eq!(fetched["smtp_port"], 587);
    assert_eq!(fetched["smtp_username"], "dlp-alerts");
    // ME-01: password must be masked on GET
    assert_eq!(fetched["smtp_password"], "***MASKED***");
    assert_eq!(fetched["smtp_from"], "dlp@example.com");
    assert_eq!(fetched["smtp_to"], "security@example.com");
    assert_eq!(fetched["smtp_enabled"], true);
    assert_eq!(fetched["webhook_url"], "https://hooks.example.com/dlp");
    // ME-01: webhook secret must also be masked on GET
    assert_eq!(fetched["webhook_secret"], "***MASKED***");
    assert_eq!(fetched["webhook_enabled"], true);
}

// ---------------------------------------------------------------------------
// Test 3: Agent config hot-reload (with validation)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_agent_config_hot_reload() {
    let (mut app, _pool) = helpers::server::build_test_app();

    // Step 1: GET default config
    let (status, default) = get_config(&mut app, "/admin/agent-config").await;
    assert_eq!(status, StatusCode::OK, "GET agent-config should return 200");
    assert!(
        default.get("heartbeat_interval_secs").is_some(),
        "default agent config should have heartbeat_interval_secs"
    );

    // Step 2: PUT valid new config values
    let put_payload = json!({
        "monitored_paths": ["C:\\\\Restricted\\\\"],
        "excluded_paths": ["C:\\\\Temp\\\\"],
        "heartbeat_interval_secs": 60,
        "offline_cache_enabled": false
    });

    let put_status = put_config(&mut app, "/admin/agent-config", put_payload.clone()).await;
    assert_eq!(put_status, StatusCode::OK, "PUT agent-config should return 200");

    // Step 3: GET again and assert exact matching
    let (status, fetched) = get_config(&mut app, "/admin/agent-config").await;
    assert_eq!(status, StatusCode::OK, "GET agent-config after PUT should return 200");
    assert_eq!(fetched["monitored_paths"], json!(["C:\\\\Restricted\\\\"]));
    assert_eq!(fetched["excluded_paths"], json!(["C:\\\\Temp\\\\"]));
    assert_eq!(fetched["heartbeat_interval_secs"], 60);
    assert_eq!(fetched["offline_cache_enabled"], false);

    // Step 4: PUT with invalid heartbeat_interval_secs (< 10) should be rejected
    let bad_payload = json!({
        "monitored_paths": [],
        "excluded_paths": [],
        "heartbeat_interval_secs": 5,
        "offline_cache_enabled": true
    });

    let bad_status = put_config(&mut app, "/admin/agent-config", bad_payload).await;
    assert_eq!(
        bad_status,
        StatusCode::BAD_REQUEST,
        "PUT agent-config with heartbeat_interval_secs < 10 should return 400"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Policy store hot-reload (cache invalidation)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_policy_store_hot_reload() {
    let (app, _pool) = helpers::server::build_test_app();

    // Step 1: Create a DENY policy for T4 resources
    let policy_payload = json!({
        "id": "hot-reload-test",
        "name": "Block T4",
        "description": "Test policy for hot-reload verification",
        "priority": 1,
        "conditions": [
            {
                "attribute": "classification",
                "op": "eq",
                "value": "T4"
            }
        ],
        "action": "DENY",
        "enabled": true,
        "mode": "ALL"
    });

    let create_req = Request::builder()
        .method(Method::POST)
        .uri("/admin/policies")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", helpers::server::mint_jwt()))
        .body(Body::from(policy_payload.to_string()))
        .expect("build POST request");

    let create_resp = app.clone().oneshot(create_req).await.expect("send POST request");
    assert_eq!(
        create_resp.status(),
        StatusCode::CREATED,
        "POST /admin/policies should return 201"
    );

    // Step 2: Evaluate a T4 request — should DENY
    let eval_req = EvaluateRequest {
        subject: dlp_common::abac::Subject {
            user_sid: "S-1-5-21-test".to_string(),
            user_name: "testuser".to_string(),
            groups: vec![],
            device_trust: dlp_common::abac::DeviceTrust::Managed,
            network_location: dlp_common::abac::NetworkLocation::Corporate,
        },
        resource: dlp_common::abac::Resource {
            path: "C:\\\\Data\\\\secret.docx".to_string(),
            classification: dlp_common::Classification::T4,
        },
        environment: dlp_common::abac::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::abac::AccessContext::Local,
        },
        action: dlp_common::abac::Action::READ,
        agent: None,
        source_application: None,
        destination_application: None,
    };

    let eval_req_http = Request::builder()
        .method(Method::POST)
        .uri("/evaluate")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&eval_req).expect("serialize eval request"),
        ))
        .expect("build eval request");

    let eval_resp = app.clone().oneshot(eval_req_http).await.expect("send eval request");
    assert_eq!(eval_resp.status(), StatusCode::OK, "POST /evaluate should return 200");
    let eval_bytes = to_bytes(eval_resp.into_body(), usize::MAX)
        .await
        .expect("read eval body");
    let eval_result: EvaluateResponse =
        serde_json::from_slice(&eval_bytes).expect("parse eval response");
    assert!(
        eval_result.decision.is_denied(),
        "T4 resource should be DENY with Block T4 policy active"
    );

    // Step 3: Update the policy to ALLOW
    let update_payload = json!({
        "id": "hot-reload-test",
        "name": "Block T4",
        "description": "Test policy for hot-reload verification",
        "priority": 1,
        "conditions": [
            {
                "attribute": "classification",
                "op": "eq",
                "value": "T4"
            }
        ],
        "action": "ALLOW",
        "enabled": true,
        "mode": "ALL"
    });

    let update_req = Request::builder()
        .method(Method::PUT)
        .uri("/admin/policies/hot-reload-test")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", helpers::server::mint_jwt()))
        .body(Body::from(update_payload.to_string()))
        .expect("build PUT request");

    let update_resp = app.clone().oneshot(update_req).await.expect("send PUT request");
    assert_eq!(
        update_resp.status(),
        StatusCode::OK,
        "PUT /admin/policies/hot-reload-test should return 200"
    );

    // Step 4: Evaluate the same T4 request again — should now ALLOW
    // (cache was invalidated by the policy update)
    let eval_req2_http = Request::builder()
        .method(Method::POST)
        .uri("/evaluate")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&eval_req).expect("serialize eval request"),
        ))
        .expect("build eval request");

    let eval_resp2 = app.clone().oneshot(eval_req2_http).await.expect("send eval request");
    assert_eq!(
        eval_resp2.status(),
        StatusCode::OK,
        "POST /evaluate (second) should return 200"
    );
    let eval_bytes2 = to_bytes(eval_resp2.into_body(), usize::MAX)
        .await
        .expect("read eval body");
    let eval_result2: EvaluateResponse =
        serde_json::from_slice(&eval_bytes2).expect("parse eval response");
    assert_eq!(
        eval_result2.decision,
        dlp_common::abac::Decision::ALLOW,
        "T4 resource should be ALLOW after policy update (cache invalidation)"
    );
}
