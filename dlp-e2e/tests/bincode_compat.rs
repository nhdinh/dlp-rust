//! Bincode backward-compatibility integration tests for the IPC protocol.
//!
//! These tests verify that the wire format between hook DLL and agent is stable
//! across protocol versions. Golden fixtures are committed to version control
//! so any accidental format change is caught in CI.
//!
//! # Test Strategy
//!
//! - **Round-trip tests**: Serialize + deserialize must produce identical values.
//! - **Default-field tests**: Old peers without new fields deserialize correctly.
//! - **Golden fixture tests**: Pre-serialized bytes must match current code.
//! - **Unknown-version tests**: Future/unknown versions degrade gracefully.

use dlp_common::hook_ipc::{
    CacheHint, HookOp, HookRequest, HookResponse, IpcEnvelope, IpcMessageV1, IpcPayloadV1,
};
use dlp_common::{Classification, Decision};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// 1. Old request deserializes with defaults
// ---------------------------------------------------------------------------

/// An old HookRequest (without cache_version, protocol_version, op fields)
/// serialized as JSON must deserialize with serde(default) values.
#[test]
fn old_request_deserializes_with_defaults() {
    let old_json = r#"{"path":"C:\\old.txt","action":"READ"}"#;
    let deserialized: HookRequest = serde_json::from_str(old_json).unwrap();

    assert_eq!(deserialized.path, r"C:\old.txt");
    assert_eq!(deserialized.action, "READ");
    assert_eq!(
        deserialized.cache_version, 0,
        "cache_version should default to 0"
    );
    assert_eq!(
        deserialized.protocol_version, 1,
        "protocol_version should default to 1"
    );
    assert_eq!(deserialized.op, HookOp::Read, "op should default to Read");
}

// ---------------------------------------------------------------------------
// 2. New request round-trips via bincode
// ---------------------------------------------------------------------------

/// A fully-populated HookRequest must round-trip through bincode without loss.
#[test]
fn new_request_roundtrips() {
    let req = HookRequest {
        path: r"C:\new.txt".to_string(),
        action: "WRITE".to_string(),
        cache_version: 7,
        protocol_version: 1,
        op: HookOp::Write,
        source_volume_class: None,
        destination_volume_class: None,
        pid: 0,
    handle_value: 0,
    };

    let bytes = bincode::serialize(&req).unwrap();
    let round_trip: HookRequest = bincode::deserialize(&bytes).unwrap();

    assert_eq!(req, round_trip);
}

// ---------------------------------------------------------------------------
// 3. Old response deserializes with defaults
// ---------------------------------------------------------------------------

/// An old HookResponse (without cache_hint, cache_version fields)
/// serialized as JSON must deserialize with serde(default) values.
#[test]
fn old_response_deserializes_with_defaults() {
    let old_json = r#"{"decision":"ALLOW","reason":"ok"}"#;
    let deserialized: HookResponse = serde_json::from_str(old_json).unwrap();

    assert_eq!(deserialized.decision, Decision::ALLOW);
    assert_eq!(deserialized.reason, "ok");
    assert!(
        deserialized.cache_hint.is_none(),
        "cache_hint should default to None"
    );
    assert_eq!(
        deserialized.cache_version, 0,
        "cache_version should default to 0"
    );
}

// ---------------------------------------------------------------------------
// 4. New response round-trips via bincode
// ---------------------------------------------------------------------------

/// A fully-populated HookResponse (with CacheHint) must round-trip through
/// bincode without loss.
#[test]
fn new_response_roundtrips() {
    let resp = HookResponse {
        decision: Decision::DENY,
        reason: "T4 write".to_string(),
        cache_hint: Some(CacheHint {
            path: PathBuf::from(r"C:\secret.txt"),
            tier: Classification::T4,
            ttl_secs: 30,
        }),
        cache_version: 99,
        approval_override: None,
    };

    let bytes = bincode::serialize(&resp).unwrap();
    let round_trip: HookResponse = bincode::deserialize(&bytes).unwrap();

    assert_eq!(resp, round_trip);
}

// ---------------------------------------------------------------------------
// 5. Protocol version defaults to one
// ---------------------------------------------------------------------------

/// When deserializing JSON without an explicit protocol_version, the default
/// function must return 1 (CURRENT_PROTOCOL_VERSION).
#[test]
fn protocol_version_defaults_to_one() {
    let json = r#"{"path":"C:\\test.txt","action":"READ"}"#;
    let req: HookRequest = serde_json::from_str(json).unwrap();

    assert_eq!(req.protocol_version, 1);
}

// ---------------------------------------------------------------------------
// 6. Envelope V1 round-trip
// ---------------------------------------------------------------------------

/// The full IpcEnvelope::V1 wrapping must round-trip through bincode,
/// including both Request and Response payloads.
#[test]
fn envelope_v1_roundtrip() {
    let req = HookRequest {
        path: r"C:\test.txt".to_string(),
        action: "WRITE".to_string(),
        cache_version: 42,
        protocol_version: 1,
        op: HookOp::Write,
        source_volume_class: None,
        destination_volume_class: None,
        pid: 0,
    handle_value: 0,
    };

    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::Request(req),
    });

    let bytes = bincode::serialize(&envelope).unwrap();
    let round_trip: IpcEnvelope = bincode::deserialize(&bytes).unwrap();

    assert_eq!(envelope, round_trip);
}

// ---------------------------------------------------------------------------
// 7. Golden fixture stability
// ---------------------------------------------------------------------------

/// Pre-serialized bincode bytes must remain stable. If this test fails,
/// the wire format has changed and old peers will break.
#[test]
fn golden_fixture_stability() {
    // Golden fixture: HookRequest { path="C:\\fixture.txt", action="READ",
    // cache_version=0, protocol_version=1, op=HookOp::Read,
    // source_volume_class=None, destination_volume_class=None, pid=0,
    // handle_value=0 }
    //
    // Generated with: bincode::serialize(&req).unwrap()
    // Total: 61 bytes
    const GOLDEN_REQUEST: &[u8] = &[
        14, 0, 0, 0, 0, 0, 0, 0, // path: len=14 (u64 little-endian)
        67, 58, 92, 102, 105, 120, 116, 117, 114, 101, 46, 116, 120, 116, // "C:\fixture.txt"
        4, 0, 0, 0, 0, 0, 0, 0, // action: len=4 (u64 little-endian)
        82, 69, 65, 68, // "READ"
        0, 0, 0, 0, 0, 0, 0, 0, // cache_version: 0 (u64)
        1, 0, 0, 0, 0, // protocol_version (u8=1) + op (u32=0 for Read)
        0, // source_volume_class: None (Option u8 discriminant=0)
        0, // destination_volume_class: None (Option u8 discriminant=0)
        0, 0, 0, 0, // pid: 0 (u32 little-endian)
        0, 0, 0, 0, 0, 0, 0, 0, // handle_value: 0 (u64 little-endian)
    ];

    let deserialized: HookRequest = bincode::deserialize(GOLDEN_REQUEST).unwrap();
    assert_eq!(deserialized.path, r"C:\fixture.txt");
    assert_eq!(deserialized.action, "READ");
    assert_eq!(deserialized.cache_version, 0);
    assert_eq!(deserialized.protocol_version, 1);
    assert_eq!(deserialized.op, HookOp::Read);
    assert_eq!(deserialized.source_volume_class, None);
    assert_eq!(deserialized.destination_volume_class, None);
    assert_eq!(deserialized.pid, 0);
    assert_eq!(deserialized.handle_value, 0);

    // Re-serialize and verify byte-for-byte stability
    let re_serialized = bincode::serialize(&deserialized).unwrap();
    assert_eq!(
        re_serialized, GOLDEN_REQUEST,
        "re-serialized bytes differ from golden fixture — wire format changed"
    );
}

// ---------------------------------------------------------------------------
// 8. Unknown version fallback
// ---------------------------------------------------------------------------

/// When an unknown protocol version is encountered, deserialization should
/// fail gracefully (not panic), allowing the caller to fall back to
/// pipe-only authoritative classification.
#[test]
fn unknown_version_fallback() {
    // A minimal invalid/unknown envelope byte sequence.
    // Bincode enum discriminant: u32 for variant index.
    // Variant 99 does not exist in IpcEnvelope.
    let unknown: &[u8] = &[99, 0, 0, 0]; // discriminant = 99

    let result: Result<IpcEnvelope, _> = bincode::deserialize(unknown);
    assert!(
        result.is_err(),
        "unknown envelope variant should deserialize as an error"
    );
}
