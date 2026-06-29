//! Integration tests for Phase 56 volume-class ABAC policy enforcement.
//!
//! Proves that:
//!   - A policy "DENY COPY where classification=T4 AND source_volume_class=LocalNTFS
//!     AND destination_volume_class=Optical" correctly evaluates to DENY.
//!   - Negative control: same policy with destination_volume_class=LocalNTFS
//!     evaluates to ALLOW (no match, falls through to default-allow for T4
//!     when no other policy matches).
//!   - Hardware-dependent test exists (marked #[ignore]) for environments with
//!     real optical drives.
//!
//! These tests mock volume classes directly via AbacContext fields — no WMI
//! queries or physical hardware required. Addresses review concern:
//! "Integration test requires physical hardware / non-hermetic".

use std::sync::Arc;

use dlp_common::abac::{
    AbacContext, Action, Decision, Environment, PolicyCondition, Resource, Subject, VolumeClass,
};
use dlp_common::Classification;
use dlp_server::db::repositories::policies::{PolicyRepository, PolicyRow};
use dlp_server::db::UnitOfWork;

/// Helper to build an AbacContext for a COPY operation with configurable
/// source and destination volume classes.
fn make_copy_context(
    classification: Classification,
    source_vc: Option<VolumeClass>,
    dest_vc: Option<VolumeClass>,
) -> AbacContext {
    AbacContext {
        subject: Subject {
            user_sid: "S-1-5-21-test".to_string(),
            user_name: "testuser".to_string(),
            groups: vec![],
            ..Default::default()
        },
        resource: Resource {
            path: r"C:\test\secret.doc".to_string(),
            classification,
        },
        environment: Environment::default(),
        action: Action::COPY,
        source_volume_class: source_vc,
        destination_volume_class: dest_vc,
        ..Default::default()
    }
}

/// Inserts a policy into the DB and invalidates the store cache.
#[allow(clippy::too_many_arguments)]
fn seed_policy(
    pool: &dlp_server::db::Pool,
    store: &dlp_server::policy_store::PolicyStore,
    id: &str,
    name: &str,
    priority: i64,
    conditions: &str,
    action: &str,
    enabled: i64,
    mode: &str,
    enforcement_mode: &str,
) {
    let conn = pool.get().expect("acquire connection");
    let mut conn_ref = conn;
    let uow = UnitOfWork::new(&mut conn_ref).expect("begin transaction");
    let row = PolicyRow {
        id: id.to_string(),
        name: name.to_string(),
        description: None,
        priority,
        conditions: conditions.to_string(),
        action: action.to_string(),
        enabled,
        mode: mode.to_string(),
        enforcement_mode: enforcement_mode.to_string(),
        version: 1,
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    PolicyRepository::insert(&uow, &row).expect("insert policy");
    uow.commit().expect("commit transaction");
    store.invalidate();
}

/// JSON conditions for the optical deny policy.
fn optical_deny_conditions() -> String {
    serde_json::to_string(&vec![
        PolicyCondition::Classification {
            op: "eq".to_string(),
            value: Classification::T4,
        },
        PolicyCondition::SourceVolumeClass {
            op: "eq".to_string(),
            value: VolumeClass::LocalNTFS,
        },
        PolicyCondition::DestinationVolumeClass {
            op: "eq".to_string(),
            value: VolumeClass::Optical,
        },
    ])
    .unwrap()
}

// ---------------------------------------------------------------------------
// Main integration test (mock-based, no hardware required)
// ---------------------------------------------------------------------------

#[test]
fn test_deny_local_ntfs_t4_to_optical() {
    let tmp = tempfile::NamedTempFile::new().expect("create temp db");
    let pool =
        Arc::new(dlp_server::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let store =
        dlp_server::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store");

    seed_policy(
        &pool,
        &store,
        "test-optical-deny",
        "Deny T4 to Optical",
        1,
        &optical_deny_conditions(),
        "Deny",
        1,
        "ALL",
        "Block",
    );

    let ctx = make_copy_context(
        Classification::T4,
        Some(VolumeClass::LocalNTFS),
        Some(VolumeClass::Optical),
    );

    let resp = store.evaluate(&ctx, None, false);

    assert_eq!(
        resp.decision,
        Decision::DENY,
        "Expected DENY for T4 COPY from LocalNTFS to Optical"
    );
    assert_eq!(
        resp.matched_policy_id,
        Some("test-optical-deny".to_string())
    );
    assert!(
        resp.reason.contains("Deny T4 to Optical"),
        "Reason should mention the policy name: {}",
        resp.reason
    );
}

/// Negative control: same source and classification, but destination is
/// LocalNTFS (not Optical). We add a second ALLOW policy with lower
/// priority number (evaluated first) to prove the volume-class condition
/// is what causes the difference.
#[test]
fn test_allow_local_ntfs_t4_to_local_ntfs() {
    let tmp = tempfile::NamedTempFile::new().expect("create temp db");
    let pool =
        Arc::new(dlp_server::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let store =
        dlp_server::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store");

    // ALLOW policy for same-volume copies — evaluated first (priority 1).
    let allow_conditions = serde_json::to_string(&vec![
        PolicyCondition::Classification {
            op: "eq".to_string(),
            value: Classification::T4,
        },
        PolicyCondition::SourceVolumeClass {
            op: "eq".to_string(),
            value: VolumeClass::LocalNTFS,
        },
        PolicyCondition::DestinationVolumeClass {
            op: "eq".to_string(),
            value: VolumeClass::LocalNTFS,
        },
    ])
    .unwrap();

    seed_policy(
        &pool,
        &store,
        "test-allow-same-volume",
        "Allow T4 on same volume",
        1,
        &allow_conditions,
        "Allow",
        1,
        "ALL",
        "Block",
    );

    // DENY policy for optical destination — evaluated second (priority 2).
    seed_policy(
        &pool,
        &store,
        "test-optical-deny",
        "Deny T4 to Optical",
        2,
        &optical_deny_conditions(),
        "Deny",
        1,
        "ALL",
        "Block",
    );

    let ctx = make_copy_context(
        Classification::T4,
        Some(VolumeClass::LocalNTFS),
        Some(VolumeClass::LocalNTFS),
    );

    let resp = store.evaluate(&ctx, None, false);

    assert_eq!(
        resp.decision,
        Decision::ALLOW,
        "Expected ALLOW for T4 COPY from LocalNTFS to LocalNTFS \
         (optical policy should not match)"
    );
    assert_eq!(
        resp.matched_policy_id,
        Some("test-allow-same-volume".to_string())
    );
}

/// Volume class fail-closed: when source_volume_class is None, the
/// SourceVolumeClass condition should NOT match (fails closed), so the
/// policy does not trigger.
#[test]
fn test_fail_closed_when_source_volume_class_missing() {
    let tmp = tempfile::NamedTempFile::new().expect("create temp db");
    let pool =
        Arc::new(dlp_server::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let store =
        dlp_server::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store");

    seed_policy(
        &pool,
        &store,
        "test-optical-deny",
        "Deny T4 to Optical",
        1,
        &optical_deny_conditions(),
        "Deny",
        1,
        "ALL",
        "Block",
    );

    let ctx = make_copy_context(
        Classification::T4,
        None, // missing source volume class
        Some(VolumeClass::Optical),
    );

    let resp = store.evaluate(&ctx, None, false);

    // Policy does not match because source_volume_class is None.
    // Default-deny for T4 kicks in (no matching policy).
    assert_eq!(
        resp.decision,
        Decision::DENY,
        "Default deny for T4 when no policy matches"
    );
    assert_eq!(
        resp.matched_policy_id, None,
        "No policy should match when source volume class is missing"
    );
    assert!(
        resp.reason.contains("default deny"),
        "Should be default deny, not policy match: {}",
        resp.reason
    );
}

/// Volume class fail-closed: when destination_volume_class is None, the
/// DestinationVolumeClass condition should NOT match.
#[test]
fn test_fail_closed_when_destination_volume_class_missing() {
    let tmp = tempfile::NamedTempFile::new().expect("create temp db");
    let pool =
        Arc::new(dlp_server::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let store =
        dlp_server::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store");

    seed_policy(
        &pool,
        &store,
        "test-optical-deny",
        "Deny T4 to Optical",
        1,
        &optical_deny_conditions(),
        "Deny",
        1,
        "ALL",
        "Block",
    );

    let ctx = make_copy_context(
        Classification::T4,
        Some(VolumeClass::LocalNTFS),
        None, // missing destination volume class
    );

    let resp = store.evaluate(&ctx, None, false);

    assert_eq!(
        resp.decision,
        Decision::DENY,
        "Default deny for T4 when no policy matches"
    );
    assert_eq!(
        resp.matched_policy_id, None,
        "No policy should match when destination volume class is missing"
    );
}

/// "ne" operator on volume class: denies when source is NOT LocalNTFS.
#[test]
fn test_volume_class_ne_operator() {
    let tmp = tempfile::NamedTempFile::new().expect("create temp db");
    let pool =
        Arc::new(dlp_server::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let store =
        dlp_server::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store");

    let conditions = serde_json::to_string(&vec![
        PolicyCondition::Classification {
            op: "eq".to_string(),
            value: Classification::T4,
        },
        PolicyCondition::SourceVolumeClass {
            op: "ne".to_string(),
            value: VolumeClass::LocalNTFS,
        },
    ])
    .unwrap();

    seed_policy(
        &pool,
        &store,
        "test-ne-policy",
        "Deny non-LocalNTFS source",
        1,
        &conditions,
        "Deny",
        1,
        "ALL",
        "Block",
    );

    // USBRemovable source -> condition matches (ne LocalNTFS).
    let ctx_usb = make_copy_context(
        Classification::T4,
        Some(VolumeClass::USBRemovable),
        Some(VolumeClass::LocalNTFS),
    );
    let resp = store.evaluate(&ctx_usb, None, false);
    assert_eq!(resp.decision, Decision::DENY);

    // LocalNTFS source -> condition does NOT match.
    let ctx_local = make_copy_context(
        Classification::T4,
        Some(VolumeClass::LocalNTFS),
        Some(VolumeClass::LocalNTFS),
    );
    let resp = store.evaluate(&ctx_local, None, false);
    assert_eq!(resp.decision, Decision::DENY); // default deny for T4
    assert_eq!(resp.matched_policy_id, None);
}

// ---------------------------------------------------------------------------
// Hardware-dependent test (requires physical optical drive or mounted ISO)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "Requires physical optical drive or mounted ISO on test endpoint"]
fn test_deny_with_real_optical_drive() {
    // This test performs an actual CopyFileExW to a real optical drive.
    // Run with: cargo test -p dlp-server --test volume_class_integration -- --ignored
    //
    // Prerequisites:
    // - Optical drive present on test endpoint
    // - Writable optical media inserted (CD-RW, DVD-RW)
    // - Or: ISO mounted via Windows Explorer with drive letter assigned
    //
    // Steps:
    // 1. Mount an ISO or insert optical media (get drive letter, e.g., D:)
    // 2. Create a T4-classified file on C: (LocalNTFS)
    // 3. Attempt CopyFileExW from C:\file.txt to D:\file.txt
    // 4. Assert ERROR_ACCESS_DENIED is returned
    // 5. Check audit log for VolumeClass=Optical in the deny event
    //
    // Note: This test is platform-specific (Windows only) and requires
    // elevation to install the hook DLL.
    panic!("Hardware-dependent test not implemented — run manually with optical drive");
}
