//! Contract tests for agent-ui heartbeat lifecycle messages.
//!
//! These tests verify that the Ping/Pong wire format agreed upon by
//! `dlp-agent` and `dlp-user-ui` is stable and consistent.  A mismatch
//! here would silently break the heartbeat watchdog.

use dlp_agent::ipc::messages::{Pipe1AgentMsg, Pipe1UiMsg};

// ---------------------------------------------------------------------------
// Heartbeat wire-format contract
// ---------------------------------------------------------------------------

/// The exact JSON payload the agent sends for a heartbeat Ping.
const PING_JSON: &str = r#"{"type":"Ping"}"#;

/// The exact JSON payload the UI sends for a heartbeat Pong.
const PONG_JSON: &str = r#"{"type":"Pong"}"#;

#[test]
fn agent_ping_serializes_to_expected_wire_format() {
    let msg = Pipe1AgentMsg::Ping;
    let json = serde_json::to_string(&msg).expect("serialize Ping");
    assert_eq!(json, PING_JSON, "Ping wire format changed — UI may not recognise it");
}

#[test]
fn ui_pong_serializes_to_expected_wire_format() {
    let msg = Pipe1UiMsg::Pong;
    let json = serde_json::to_string(&msg).expect("serialize Pong");
    assert_eq!(json, PONG_JSON, "Pong wire format changed — agent may not recognise it");
}

#[test]
fn agent_ping_deserializes_from_wire_format() {
    let decoded: Pipe1AgentMsg = serde_json::from_str(PING_JSON).expect("parse Ping");
    assert!(
        matches!(decoded, Pipe1AgentMsg::Ping),
        "expected Ping variant, got something else"
    );
}

#[test]
fn ui_pong_deserializes_from_wire_format() {
    let decoded: Pipe1UiMsg = serde_json::from_str(PONG_JSON).expect("parse Pong");
    assert!(
        matches!(decoded, Pipe1UiMsg::Pong),
        "expected Pong variant, got something else"
    );
}

#[test]
fn ping_does_not_carry_unexpected_fields() {
    // If someone adds fields to Pipe1AgentMsg::Ping, this test fails
    // and forces an explicit decision about wire-format compatibility.
    let msg = Pipe1AgentMsg::Ping;
    let json = serde_json::to_string(&msg).expect("serialize Ping");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse as Value");
    let obj = value.as_object().expect("Ping must be a JSON object");
    assert_eq!(
        obj.len(),
        1,
        "Ping must contain exactly one field (type); got {json}"
    );
    assert_eq!(
        obj.get("type"),
        Some(&serde_json::Value::String("Ping".to_string())),
        "Ping type field mismatch"
    );
}

#[test]
fn pong_does_not_carry_unexpected_fields() {
    let msg = Pipe1UiMsg::Pong;
    let json = serde_json::to_string(&msg).expect("serialize Pong");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse as Value");
    let obj = value.as_object().expect("Pong must be a JSON object");
    assert_eq!(
        obj.len(),
        1,
        "Pong must contain exactly one field (type); got {json}"
    );
    assert_eq!(
        obj.get("type"),
        Some(&serde_json::Value::String("Pong".to_string())),
        "Pong type field mismatch"
    );
}

// ---------------------------------------------------------------------------
// RegisterSession first-message contract
// ---------------------------------------------------------------------------

#[test]
fn register_session_serializes_with_session_id() {
    let msg = Pipe1UiMsg::RegisterSession { session_id: 42 };
    let json = serde_json::to_string(&msg).expect("serialize RegisterSession");
    assert!(json.contains("\"type\":\"RegisterSession\""));
    assert!(json.contains("\"session_id\":42"));
}
