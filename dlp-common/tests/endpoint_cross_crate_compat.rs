//! Integration test: cross-type serde compatibility for the Phase 22 endpoint types.
//!
//! This test binary runs as an external consumer of `dlp-common`, exercising
//! every public re-export path that downstream crates will use in Phases 23+.
//! Any breakage here indicates a public-API regression in `dlp-common` that
//! would cascade across the workspace.

use dlp_common::{
    AbacContext, Action, AppIdentity, AppTrustTier, AuditEvent, Classification, Decision,
    DeviceIdentity, EvaluateRequest, EventType, SignatureState, UsbTrustTier,
};

fn sample_app() -> AppIdentity {
    AppIdentity {
        image_path: r"C:\Program Files\Contoso\app.exe".to_string(),
        publisher: "Contoso Corporation".to_string(),
        trust_tier: AppTrustTier::Trusted,
        signature_state: SignatureState::Valid,
    }
}

fn sample_device() -> DeviceIdentity {
    DeviceIdentity {
        vid: "0951".to_string(),
        pid: "1666".to_string(),
        serial: "ABCDEF".to_string(),
        description: "Kingston DataTraveler 3.0".to_string(),
    }
}

#[test]
fn crate_root_reexports_are_reachable() {
    // All five Phase 22 types reachable from crate root (Plan 01 D-01 named re-export).
    let _tier: UsbTrustTier = UsbTrustTier::default();
    let _trust: AppTrustTier = AppTrustTier::default();
    let _sig: SignatureState = SignatureState::default();
    let _app: AppIdentity = AppIdentity::default();
    let _dev: DeviceIdentity = DeviceIdentity::default();
}

#[test]
fn usb_trust_tier_wire_values_match_db_check_constraint() {
    // Phase 24 DB CHECK constraint (REQUIREMENTS.md USB-02) requires exactly
    // these three strings. If this test ever fails, Phase 24's CHECK will
    // reject valid Rust payloads at insert time.
    assert_eq!(
        serde_json::to_string(&UsbTrustTier::Blocked).unwrap(),
        "\"blocked\""
    );
    assert_eq!(
        serde_json::to_string(&UsbTrustTier::ReadOnly).unwrap(),
        "\"read_only\""
    );
    assert_eq!(
        serde_json::to_string(&UsbTrustTier::FullAccess).unwrap(),
        "\"full_access\""
    );
}

#[test]
fn evaluate_request_round_trip_with_both_app_fields() {
    let req = EvaluateRequest {
        source_application: Some(sample_app()),
        destination_application: Some(AppIdentity {
            image_path: r"C:\dst.exe".to_string(),
            publisher: "Unknown".to_string(),
            trust_tier: AppTrustTier::Untrusted,
            signature_state: SignatureState::NotSigned,
        }),
        ..Default::default()
    };
    let json = serde_json::to_string(&req).unwrap();
    let rt: EvaluateRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(
        rt.source_application.as_ref().map(|a| a.publisher.as_str()),
        Some("Contoso Corporation"),
    );
    assert_eq!(
        rt.destination_application.as_ref().map(|a| a.trust_tier),
        Some(AppTrustTier::Untrusted),
    );
}

#[test]
fn abac_context_has_no_agent_field_and_round_trips() {
    // D-10: AbacContext has no `agent` field -- only EvaluateRequest does.
    let ctx = AbacContext {
        source_application: Some(sample_app()),
        ..Default::default()
    };
    let json = serde_json::to_string(&ctx).unwrap();
    // No "agent" key -- structural guarantee from D-10.
    assert!(!json.contains("\"agent\""), "json was: {json}");
    let rt: AbacContext = serde_json::from_str(&json).unwrap();
    assert!(rt.source_application.is_some());
    assert!(rt.destination_application.is_none());
}

#[test]
fn audit_event_builder_chain_and_round_trip() {
    let event = AuditEvent::new(
        EventType::Block,
        "S-1-5-21-100".to_string(),
        "jsmith".to_string(),
        r"E:\secret.docx".to_string(),
        Classification::T3,
        Action::WRITE,
        Decision::DENY,
        "AGENT-CROSS-01".to_string(),
        7,
    )
    .with_source_application(Some(sample_app()))
    .with_device_identity(Some(sample_device()));

    let json = serde_json::to_string(&event).unwrap();
    // D-11/D-12: populated fields present.
    assert!(json.contains("source_application"));
    assert!(json.contains("device_identity"));
    // D-13: the None destination_application is skipped from JSON output.
    assert!(!json.contains("destination_application"));

    let rt: AuditEvent = serde_json::from_str(&json).unwrap();
    assert!(rt.source_application.is_some());
    assert!(rt.destination_application.is_none());
    assert_eq!(
        rt.device_identity.as_ref().map(|d| d.vid.as_str()),
        Some("0951")
    );
}

#[test]
fn audit_event_legacy_payload_deserializes_unchanged() {
    // D-13 explicit backward-compat: every AuditEvent JSON written before
    // Phase 22 must still parse. Any regression here would corrupt the
    // audit JSONL store replay path on dlp-server startup.
    let legacy = r#"{
        "timestamp": "2025-01-01T00:00:00Z",
        "event_type": "BLOCK",
        "user_sid": "S-1-5-21-1",
        "user_name": "jsmith",
        "resource_path": "C:\\x.txt",
        "classification": "T3",
        "action_attempted": "READ",
        "decision": "DENY",
        "agent_id": "AGENT-1",
        "session_id": 1,
        "override_granted": false,
        "access_context": "local"
    }"#;
    let event: AuditEvent = serde_json::from_str(legacy).unwrap();
    assert!(event.source_application.is_none());
    assert!(event.destination_application.is_none());
    assert!(event.device_identity.is_none());
}
