//! Hot-reload integration tests for the Policy Engine.
//!
//! Verifies that the PolicyStore detects external changes to `policies.json`,
//! validates the new content, and atomically swaps policies into the ABAC engine
//! within the debounce window (~2 seconds).
//!
//! ## Coverage
//!
//! - N/A (no requirement ID — hot-reload is a NFR implied by F-ENG-06)
//! - F-ENG-06: "Engine shall load and hot-reload policies from a JSON/YAML
//!   policy store without restart"

use std::sync::Arc;
use std::time::Duration;

use dlp_common::abac::{
    AccessContext, Action, Decision, DeviceTrust, Environment, EvaluateRequest,
    NetworkLocation, Policy, PolicyCondition, Resource, Subject,
};
use dlp_common::Classification;
use policy_engine::engine::AbacEngine;
use policy_engine::policy_store::PolicyStore;

/// Writes `policies` to `path` and waits for the hot-reload watcher to pick it up.
/// The debounce window is 2 seconds, but we give extra time for file-system latency.
async fn write_policies_and_wait(path: &std::path::Path, policies: &[Policy]) {
    let json = serde_json::to_string_pretty(policies).expect("serialise policies");
    std::fs::write(path, json).expect("write policy file");
    // Wait for debounce (2s) + file-system latency + reload.
    tokio::time::sleep(Duration::from_secs(4)).await;
}

/// Builds a T4-deny policy.
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

/// Builds a T2-allow policy.
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

/// Starts a store with `initial_policies` and calls `start_hot_reload()` on it,
/// returning the store and a cancellable abort handle.
fn open_store_with_hot_reload(
    tmp: &tempfile::TempDir,
    initial_policies: &[Policy],
) -> (Arc<PolicyStore>, tokio::task::JoinHandle<()>) {
    let path = tmp.path().join("policies.json");
    std::fs::write(&path, serde_json::to_string_pretty(initial_policies).unwrap()).unwrap();

    let engine = Arc::new(AbacEngine::new());
    let store = Arc::new(PolicyStore::open(path, engine).unwrap());
    store.start_hot_reload();

    let handle = tokio::spawn(async move {
        // Keep the hot-reload watcher alive for the duration of the test.
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    (store, handle)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that an externally added policy takes effect after hot-reload.
#[tokio::test]
async fn test_hotreload_adds_policy() {
    let tmp = tempfile::tempdir().unwrap();

    // Start with an empty policy list.
    let (store, _watcher) = open_store_with_hot_reload(&tmp, &[]);

    // No policies loaded yet; T4 should hit default-deny (matched_policy_id = None).
    let before = store.evaluate(&make_eval(Classification::T4, Action::WRITE)).await;
    assert!(before.matched_policy_id.is_none(), "no policy should match initially");

    // Now add the T4-deny policy externally.
    write_policies_and_wait(&tmp.path().join("policies.json"), &[t4_deny()]).await;

    // After hot-reload, T4 should be denied by the newly loaded policy.
    let after = store.evaluate(&make_eval(Classification::T4, Action::WRITE)).await;
    assert!(
        after.decision.is_denied(),
        "T4 should be denied after hot-reload added T4 policy"
    );
    assert_eq!(
        after.matched_policy_id.as_deref(),
        Some("pol-hr-t4"),
        "T4 should be denied by the newly loaded policy"
    );
}

/// Verifies that an externally removed policy stops matching after hot-reload.
#[tokio::test]
async fn test_hotreload_removes_policy() {
    let tmp = tempfile::tempdir().unwrap();

    // Start with both T2-allow and T4-deny.
    let (store, _watcher) = open_store_with_hot_reload(&tmp, &[t2_allow(), t4_deny()]);

    // T4 should be denied.
    let before = store.evaluate(&make_eval(Classification::T4, Action::WRITE)).await;
    assert!(before.decision.is_denied(), "T4 should be denied initially");

    // Remove the T4-deny policy externally (keep only T2-allow).
    write_policies_and_wait(&tmp.path().join("policies.json"), &[t2_allow()]).await;

    // After hot-reload, T4 should still be denied (default-deny — no T4 policy matched).
    let after = store.evaluate(&make_eval(Classification::T4, Action::WRITE)).await;
    assert!(
        after.decision.is_denied(),
        "T4 should still be denied after policy removal (default-deny)"
    );
    assert!(
        after.matched_policy_id.is_none(),
        "No policy should match after T4 policy was removed"
    );
}

/// Verifies that an externally updated policy takes effect after hot-reload.
#[tokio::test]
async fn test_hotreload_updates_policy() {
    let tmp = tempfile::tempdir().unwrap();

    // Start with T2-allow policy only.
    let (store, _watcher) = open_store_with_hot_reload(&tmp, &[t2_allow()]);

    // T4 should hit default-deny (no T4 policy).
    let before = store.evaluate(&make_eval(Classification::T4, Action::WRITE)).await;
    assert!(before.matched_policy_id.is_none(), "T4: no policy should match before update");
    assert!(before.decision.is_denied(), "T4: default-deny before policy update");

    // Replace with T4-deny policy.
    write_policies_and_wait(&tmp.path().join("policies.json"), &[t4_deny()]).await;

    // Now T4 should be denied with a matched policy id.
    let after = store.evaluate(&make_eval(Classification::T4, Action::WRITE)).await;
    assert!(after.decision.is_denied());
    assert_eq!(
        after.matched_policy_id.as_deref(),
        Some("pol-hr-t4"),
        "T4 should be denied by the updated policy"
    );
}

/// Verifies that an invalid policy file does not crash the store or wipe
/// existing policies during hot-reload.
#[tokio::test]
async fn test_hotreload_invalid_json_preserves_existing() {
    let tmp = tempfile::tempdir().unwrap();

    // Start with valid T2-allow policy.
    let (store, _watcher) = open_store_with_hot_reload(&tmp, &[t2_allow()]);

    // T2 should be allowed.
    let before = store.evaluate(&make_eval(Classification::T2, Action::WRITE)).await;
    assert!(!before.decision.is_denied(), "T2 should be allowed before corruption");

    // Write garbage to the policy file.
    std::fs::write(tmp.path().join("policies.json"), "this is not json {{{").unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;

    // T2 should still be allowed (invalid file skipped, old policies kept).
    let after = store.evaluate(&make_eval(Classification::T2, Action::WRITE)).await;
    assert!(
        !after.decision.is_denied(),
        "Invalid policy file should not wipe existing policies"
    );
}

/// Verifies that invalid policy entries (bad priority) are skipped while valid
/// ones are still loaded.
#[tokio::test]
async fn test_hotreload_skips_invalid_entries() {
    let tmp = tempfile::tempdir().unwrap();

    // Write policies: a bad-priority T4-deny (exceeds max 100_000) alongside
    // a valid T2-allow.
    let bad_policy = Policy {
        id: "bad".into(),
        name: "Bad Priority".into(),
        description: None,
        priority: 200_000, // exceeds max 100_000
        conditions: vec![PolicyCondition::Classification {
            op: "eq".into(),
            value: Classification::T4,
        }],
        action: Decision::DENY,
        enabled: true,
        version: 1,
    };

    let (store, _watcher) = open_store_with_hot_reload(&tmp, &[t2_allow(), bad_policy]);

    // The bad-policy T4-deny is silently skipped during load.
    // T2 should be allowed by the valid policy.
    let t2_result = store.evaluate(&make_eval(Classification::T2, Action::WRITE)).await;
    assert!(!t2_result.decision.is_denied(), "T2 should be allowed by valid policy");

    // T4 should hit default-deny (bad policy skipped), NOT DENY from the bad policy.
    // We verify the bad policy was not loaded by checking list_policies.
    let policies = store.list_policies();
    let bad_found = policies.iter().any(|p| p.id == "bad");
    assert!(!bad_found, "bad-priority policy should not have been loaded");
}

/// Verifies that the hot-reload debounce coalesces rapid file changes — only
/// the final state is loaded, not intermediate states.
#[tokio::test]
async fn test_hotreload_debounce_coalesces_rapid_changes() {
    let tmp = tempfile::tempdir().unwrap();

    let (store, _watcher) = open_store_with_hot_reload(&tmp, &[t2_allow()]);

    // Rapidly write three different policy sets in 100ms intervals.
    std::fs::write(
        tmp.path().join("policies.json"),
        serde_json::to_string(&[t2_allow()]).unwrap(),
    )
    .unwrap();

    // Wait for debounce start.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Write T4-deny.
    std::fs::write(
        tmp.path().join("policies.json"),
        serde_json::to_string(&[t4_deny()]).unwrap(),
    )
    .unwrap();

    // Wait for debounce start again.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Write both policies.
    std::fs::write(
        tmp.path().join("policies.json"),
        serde_json::to_string(&[t2_allow(), t4_deny()]).unwrap(),
    )
    .unwrap();

    // Wait for debounce to fire.
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Final state should be both policies (not just one of the intermediate states).
    let t4_result = store.evaluate(&make_eval(Classification::T4, Action::WRITE)).await;
    assert!(t4_result.decision.is_denied(), "Final state should have T4 deny policy");

    let t2_result = store.evaluate(&make_eval(Classification::T2, Action::WRITE)).await;
    assert!(!t2_result.decision.is_denied(), "T2 should still be allowed");
}

/// Verifies that multiple hot-reload cycles work correctly in sequence.
#[tokio::test]
async fn test_hotreload_multiple_cycles() {
    let tmp = tempfile::tempdir().unwrap();

    // Start with empty policy list.
    let (store, _watcher) = open_store_with_hot_reload(&tmp, &[]);

    // Cycle 1: Add T4-deny.
    write_policies_and_wait(&tmp.path().join("policies.json"), &[t4_deny()]).await;
    let policies1 = store.list_policies();
    assert!(
        policies1.iter().any(|p| p.id == "pol-hr-t4"),
        "Cycle 1: T4-deny policy should be loaded"
    );

    // Cycle 2: Remove T4-deny (write empty list).
    write_policies_and_wait(&tmp.path().join("policies.json"), &[]).await;
    let policies2 = store.list_policies();
    assert!(
        !policies2.iter().any(|p| p.id == "pol-hr-t4"),
        "Cycle 2: T4-deny should be removed"
    );

    // Cycle 3: Add both policies.
    write_policies_and_wait(&tmp.path().join("policies.json"), &[t2_allow(), t4_deny()]).await;
    let policies3 = store.list_policies();
    assert!(
        policies3.iter().any(|p| p.id == "pol-hr-t4"),
        "Cycle 3: T4-deny should be re-loaded"
    );
    assert!(
        policies3.iter().any(|p| p.id == "pol-hr-t2"),
        "Cycle 3: T2-allow should be loaded"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn make_eval(classification: Classification, action: Action) -> EvaluateRequest {
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
