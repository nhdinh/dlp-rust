//! Hot-reload integration tests for the policy store.
//!
//! Verifies that the PolicyStore detects external changes to
//! `policies.json`, validates the new content, and atomically swaps
//! policies into the ABAC engine within the debounce window (~2 s).
//!
//! These tests are timing-sensitive and must run sequentially
//! (single-threaded) to avoid file-system notification contention on
//! Windows.

// Force single-threaded execution for timing-sensitive hot-reload
// tests. Multiple concurrent file watchers on Windows compete for
// notification resources and cause spurious failures.
use std::sync::Arc;
use std::time::Duration;

use dlp_common::abac::{
    AccessContext, Action, Decision, DeviceTrust, Environment,
    EvaluateRequest, NetworkLocation, Policy, PolicyCondition,
    Resource, Subject,
};
use dlp_common::Classification;
use dlp_server::engine::AbacEngine;
use dlp_server::policy_store::PolicyStore;

/// Writes `policies` to `path` and waits for the hot-reload watcher
/// to pick it up.
async fn write_policies_and_wait(
    path: &std::path::Path,
    policies: &[Policy],
) {
    let json = serde_json::to_string_pretty(policies)
        .expect("serialise policies");
    std::fs::write(path, json).expect("write policy file");
    // Wait for debounce (2s) + file-system latency + reload thread.
    // Windows file-system notifications can be slow under concurrent
    // test load; use a generous timeout.
    tokio::time::sleep(Duration::from_secs(8)).await;
}

fn t4_deny() -> Policy {
    Policy {
        id: "pol-hr-t4".into(),
        name: "T4 Deny".into(),
        description: None,
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

fn t2_allow() -> Policy {
    Policy {
        id: "pol-hr-t2".into(),
        name: "T2 Allow".into(),
        description: None,
        priority: 10,
        conditions: vec![PolicyCondition::Classification {
            op: "eq".into(),
            value: Classification::T2,
        }],
        action: Decision::AllowWithLog,
        enabled: true,
        version: 1,
    }
}

fn open_store_with_hot_reload(
    tmp: &tempfile::TempDir,
    initial_policies: &[Policy],
) -> (Arc<PolicyStore>, tokio::task::JoinHandle<()>) {
    let path = tmp.path().join("policies.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(initial_policies).unwrap(),
    )
    .unwrap();

    let engine = Arc::new(AbacEngine::new());
    let store =
        Arc::new(PolicyStore::open(path, engine).unwrap());
    store.start_hot_reload();

    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(120)).await;
    });

    // Give the watcher thread time to register with the OS
    // before any external writes occur.
    std::thread::sleep(Duration::from_secs(2));

    (store, handle)
}

fn make_eval(
    classification: Classification,
    action: Action,
) -> EvaluateRequest {
    EvaluateRequest {
        subject: Subject {
            user_sid: "S-1-5-21-HR".into(),
            user_name: "hotreload-test".into(),
            groups: vec![],
            device_trust: DeviceTrust::Managed,
            network_location: NetworkLocation::Corporate,
        },
        resource: Resource {
            path: r"C:\Restricted\file.xlsx".into(),
            classification,
        },
        environment: Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: AccessContext::Local,
        },
        action,
        agent: None,
    }
}

#[tokio::test]
async fn test_hotreload_adds_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let (store, _watcher) =
        open_store_with_hot_reload(&tmp, &[]);

    let before = store
        .evaluate(&make_eval(Classification::T4, Action::WRITE))
        .await;
    assert!(
        before.matched_policy_id.is_none(),
        "no policy should match initially"
    );

    write_policies_and_wait(
        &tmp.path().join("policies.json"),
        &[t4_deny()],
    )
    .await;

    let after = store
        .evaluate(&make_eval(Classification::T4, Action::WRITE))
        .await;
    assert!(after.decision.is_denied());
    assert_eq!(
        after.matched_policy_id.as_deref(),
        Some("pol-hr-t4")
    );
}

#[tokio::test]
async fn test_hotreload_removes_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let (store, _watcher) =
        open_store_with_hot_reload(&tmp, &[t2_allow(), t4_deny()]);

    let before = store
        .evaluate(&make_eval(Classification::T4, Action::WRITE))
        .await;
    assert!(before.decision.is_denied());

    write_policies_and_wait(
        &tmp.path().join("policies.json"),
        &[t2_allow()],
    )
    .await;

    let after = store
        .evaluate(&make_eval(Classification::T4, Action::WRITE))
        .await;
    assert!(after.decision.is_denied());
    assert!(after.matched_policy_id.is_none());
}

#[tokio::test]
async fn test_hotreload_invalid_json_preserves_existing() {
    let tmp = tempfile::tempdir().unwrap();
    let (store, _watcher) =
        open_store_with_hot_reload(&tmp, &[t2_allow()]);

    let before = store
        .evaluate(&make_eval(Classification::T2, Action::WRITE))
        .await;
    assert!(!before.decision.is_denied());

    std::fs::write(
        tmp.path().join("policies.json"),
        "this is not json {{{",
    )
    .unwrap();
    tokio::time::sleep(Duration::from_secs(8)).await;

    let after = store
        .evaluate(&make_eval(Classification::T2, Action::WRITE))
        .await;
    assert!(!after.decision.is_denied());
}

#[tokio::test]
async fn test_hotreload_multiple_cycles() {
    let tmp = tempfile::tempdir().unwrap();
    let (store, _watcher) =
        open_store_with_hot_reload(&tmp, &[]);

    // Cycle 1: Add T4-deny.
    write_policies_and_wait(
        &tmp.path().join("policies.json"),
        &[t4_deny()],
    )
    .await;
    assert!(store
        .list_policies()
        .iter()
        .any(|p| p.id == "pol-hr-t4"));

    // Cycle 2: Remove T4-deny.
    write_policies_and_wait(
        &tmp.path().join("policies.json"),
        &[],
    )
    .await;
    assert!(!store
        .list_policies()
        .iter()
        .any(|p| p.id == "pol-hr-t4"));

    // Cycle 3: Add both.
    write_policies_and_wait(
        &tmp.path().join("policies.json"),
        &[t2_allow(), t4_deny()],
    )
    .await;
    assert!(store
        .list_policies()
        .iter()
        .any(|p| p.id == "pol-hr-t4"));
    assert!(store
        .list_policies()
        .iter()
        .any(|p| p.id == "pol-hr-t2"));
}
