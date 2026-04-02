//! Integration tests for the Policy Engine HTTP API.
//!
//! Each test spawns a standalone server on an ephemeral port with a fresh
//! temporary policy store, exercises the endpoints via `reqwest`, and verifies
//! the responses.

use std::sync::Arc;

use chrono::Utc;
use dlp_common::abac::{
    AccessContext, Action, Decision, DeviceTrust, Environment, EvaluateRequest, EvaluateResponse,
    NetworkLocation, Policy, PolicyCondition, Resource, Subject,
};
use dlp_common::Classification;
use policy_engine::engine::AbacEngine;
use policy_engine::http_server;
use policy_engine::policy_store::PolicyStore;
use reqwest::Client;
use tokio::net::TcpListener;

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Spawns a policy engine server on an ephemeral port.
///
/// Returns `(base_url, tempdir, server_handle)`.  The tempdir must be kept
/// alive for the duration of the test to prevent the policy file from being
/// deleted.
async fn spawn_server() -> (String, tempfile::TempDir, tokio::task::JoinHandle<()>) {
    let tmp = tempfile::tempdir().unwrap();
    let policy_path = tmp.path().join("policies.json");
    let engine = Arc::new(AbacEngine::new());
    let store = Arc::new(PolicyStore::open(policy_path, engine).unwrap());
    let app = http_server::build_full_router(store);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), tmp, handle)
}

/// Builds a T4-deny policy for testing.
fn t4_deny_policy() -> Policy {
    Policy {
        id: "pol-t4-deny".into(),
        name: "T4 Deny All".into(),
        description: Some("Block all T4 access".into()),
        priority: 1,
        conditions: vec![PolicyCondition::Classification {
            op: "eq".into(),
            value: Classification::T4,
        }],
        action: Decision::DENY,
        enabled: true,
        version: 1,
    }
}

/// Builds a T2-allow-with-log policy for testing.
fn t2_log_policy() -> Policy {
    Policy {
        id: "pol-t2-log".into(),
        name: "T2 Allow with Log".into(),
        description: Some("Log T2 access".into()),
        priority: 3,
        conditions: vec![PolicyCondition::Classification {
            op: "eq".into(),
            value: Classification::T2,
        }],
        action: Decision::AllowWithLog,
        enabled: true,
        version: 1,
    }
}

/// Builds an evaluate request for a given classification and action.
fn make_eval_request(classification: Classification, action: Action) -> EvaluateRequest {
    EvaluateRequest {
        subject: Subject {
            user_sid: "S-1-5-21-TEST".into(),
            user_name: "testuser".into(),
            groups: vec![],
            device_trust: DeviceTrust::Managed,
            network_location: NetworkLocation::Corporate,
        },
        resource: Resource {
            path: r"C:\Data\test.xlsx".into(),
            classification,
        },
        environment: Environment {
            timestamp: Utc::now(),
            session_id: 1,
            access_context: AccessContext::Local,
        },
        action,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_health_200() {
    let (base, _tmp, _h) = spawn_server().await;
    let resp = Client::new()
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_ready_200() {
    let (base, _tmp, _h) = spawn_server().await;
    let resp = Client::new()
        .get(format!("{base}/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ─────────────────────────────────────────────────────────────────────────────
// CRUD tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_policy_201() {
    let (base, _tmp, _h) = spawn_server().await;
    let client = Client::new();

    let resp = client
        .post(format!("{base}/policies"))
        .json(&t4_deny_policy())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
    let body: Policy = resp.json().await.unwrap();
    assert_eq!(body.id, "pol-t4-deny");
    assert_eq!(body.name, "T4 Deny All");
}

#[tokio::test]
async fn test_list_policies_after_create() {
    let (base, _tmp, _h) = spawn_server().await;
    let client = Client::new();

    // Initially empty.
    let resp = client.get(format!("{base}/policies")).send().await.unwrap();
    let policies: Vec<Policy> = resp.json().await.unwrap();
    assert!(policies.is_empty());

    // Create one.
    client
        .post(format!("{base}/policies"))
        .json(&t4_deny_policy())
        .send()
        .await
        .unwrap();

    // Now one policy.
    let resp = client.get(format!("{base}/policies")).send().await.unwrap();
    let policies: Vec<Policy> = resp.json().await.unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].id, "pol-t4-deny");
}

#[tokio::test]
async fn test_get_policy_by_id() {
    let (base, _tmp, _h) = spawn_server().await;
    let client = Client::new();

    client
        .post(format!("{base}/policies"))
        .json(&t4_deny_policy())
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{base}/policies/pol-t4-deny"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let policy: Policy = resp.json().await.unwrap();
    assert_eq!(policy.id, "pol-t4-deny");
}

#[tokio::test]
async fn test_get_policy_not_found() {
    let (base, _tmp, _h) = spawn_server().await;
    let resp = Client::new()
        .get(format!("{base}/policies/nonexistent"))
        .send()
        .await
        .unwrap();
    // PolicyNotFound maps to 400 via is_client_error().
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_update_policy() {
    let (base, _tmp, _h) = spawn_server().await;
    let client = Client::new();

    // Create.
    client
        .post(format!("{base}/policies"))
        .json(&t4_deny_policy())
        .send()
        .await
        .unwrap();

    // Update: change name and priority.
    let mut updated = t4_deny_policy();
    updated.name = "T4 Updated".into();
    updated.priority = 10;

    let resp = client
        .put(format!("{base}/policies/pol-t4-deny"))
        .json(&updated)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Policy = resp.json().await.unwrap();
    assert_eq!(body.name, "T4 Updated");
    // Version should have been incremented by the store.
    assert!(body.version >= 1);
}

#[tokio::test]
async fn test_delete_policy() {
    let (base, _tmp, _h) = spawn_server().await;
    let client = Client::new();

    client
        .post(format!("{base}/policies"))
        .json(&t4_deny_policy())
        .send()
        .await
        .unwrap();

    let resp = client
        .delete(format!("{base}/policies/pol-t4-deny"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // List should be empty.
    let resp = client.get(format!("{base}/policies")).send().await.unwrap();
    let policies: Vec<Policy> = resp.json().await.unwrap();
    assert!(policies.is_empty());
}

#[tokio::test]
async fn test_delete_nonexistent() {
    let (base, _tmp, _h) = spawn_server().await;
    let resp = Client::new()
        .delete(format!("{base}/policies/nonexistent"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// ─────────────────────────────────────────────────────────────────────────────
// Evaluate tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_evaluate_deny_t4() {
    let (base, _tmp, _h) = spawn_server().await;
    let client = Client::new();

    // Load T4 deny policy.
    client
        .post(format!("{base}/policies"))
        .json(&t4_deny_policy())
        .send()
        .await
        .unwrap();

    // Evaluate a T4 request.
    let resp = client
        .post(format!("{base}/evaluate"))
        .json(&make_eval_request(Classification::T4, Action::COPY))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: EvaluateResponse = resp.json().await.unwrap();
    assert!(body.decision.is_denied());
    assert_eq!(body.matched_policy_id.as_deref(), Some("pol-t4-deny"));
}

#[tokio::test]
async fn test_evaluate_allow_t2() {
    let (base, _tmp, _h) = spawn_server().await;
    let client = Client::new();

    // Load T2 allow-with-log policy.
    client
        .post(format!("{base}/policies"))
        .json(&t2_log_policy())
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/evaluate"))
        .json(&make_eval_request(Classification::T2, Action::WRITE))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: EvaluateResponse = resp.json().await.unwrap();
    assert_eq!(body.decision, Decision::AllowWithLog);
    assert_eq!(body.matched_policy_id.as_deref(), Some("pol-t2-log"));
}

#[tokio::test]
async fn test_evaluate_default_deny() {
    let (base, _tmp, _h) = spawn_server().await;

    // Evaluate with no policies loaded — should default-deny.
    let resp = Client::new()
        .post(format!("{base}/evaluate"))
        .json(&make_eval_request(Classification::T1, Action::READ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: EvaluateResponse = resp.json().await.unwrap();
    assert!(body.decision.is_denied());
    assert!(body.matched_policy_id.is_none());
    assert!(body.reason.contains("No matching policy"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Full lifecycle test
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_full_crud_evaluate_flow() {
    let (base, _tmp, _h) = spawn_server().await;
    let client = Client::new();

    // 1. Create T4-deny policy.
    let resp = client
        .post(format!("{base}/policies"))
        .json(&t4_deny_policy())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // 2. Evaluate T4 → DENY.
    let resp = client
        .post(format!("{base}/evaluate"))
        .json(&make_eval_request(Classification::T4, Action::WRITE))
        .send()
        .await
        .unwrap();
    let body: EvaluateResponse = resp.json().await.unwrap();
    assert!(body.decision.is_denied());

    // 3. Update policy to ALLOW.
    let mut allow_policy = t4_deny_policy();
    allow_policy.action = Decision::ALLOW;
    client
        .put(format!("{base}/policies/pol-t4-deny"))
        .json(&allow_policy)
        .send()
        .await
        .unwrap();

    // 4. Evaluate T4 again → now ALLOW.
    let resp = client
        .post(format!("{base}/evaluate"))
        .json(&make_eval_request(Classification::T4, Action::WRITE))
        .send()
        .await
        .unwrap();
    let body: EvaluateResponse = resp.json().await.unwrap();
    assert_eq!(body.decision, Decision::ALLOW);

    // 5. Delete the policy.
    let resp = client
        .delete(format!("{base}/policies/pol-t4-deny"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 6. Evaluate T4 again → default-deny (no policies).
    let resp = client
        .post(format!("{base}/evaluate"))
        .json(&make_eval_request(Classification::T4, Action::WRITE))
        .send()
        .await
        .unwrap();
    let body: EvaluateResponse = resp.json().await.unwrap();
    assert!(body.decision.is_denied());
    assert!(body.matched_policy_id.is_none());
}
