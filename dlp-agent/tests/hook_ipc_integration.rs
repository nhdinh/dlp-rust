//! Integration tests for the consolidated HookIpcServer routing all four
//! IpcPayloadV1 frame types through the builder chain.
//!
//! These tests exercise `HookIpcServer` directly (public API) with mock
//! handlers and verify that:
//! - `Request` frames route to the hook handler
//! - `PullDiagnostics` frames route to the diagnostics handler
//! - `PullHealth` frames route to the health handler
//! - `RequestOverride` frames route to the override handler (fire-and-forget)
//!
//! This is distinct from `volume_class_integration.rs`, which focuses on
//! volume-class policy enforcement via `start_mock_server` with raw handlers.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dlp_agent::hook_ipc::HookIpcServer;
use dlp_common::{
    hook_ipc::{
        ControlResponse, HookRequest, HookResponse, IpcEnvelope, IpcMessageV1, IpcPayloadV1,
        OverrideRequest, PollControl, PullDiagnosticsRequest, PullHealthRequest, UnhookAck,
        UnhookReason,
    },
    Decision, VolumeClass,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sends an IpcEnvelope over a pipe and reads the response envelope.
fn send_envelope(pipe: windows::Win32::Foundation::HANDLE, envelope: &IpcEnvelope) -> IpcEnvelope {
    let payload = bincode::serialize(envelope).expect("serialize envelope");
    dlp_agent::ipc::frame::write_frame(pipe, &payload).expect("write frame");
    let frame = dlp_agent::ipc::frame::read_frame(pipe).expect("read frame");
    bincode::deserialize(&frame).expect("deserialize envelope")
}

/// Gracefully shuts down a spawned `HookIpcServer` thread.
///
/// Sets the global shutdown flag, connects a dummy client to unblock the
/// server's `ConnectNamedPipe`, and joins the thread with a 2-second timeout.
/// This prevents pipe/thread exhaustion when many serial tests run back-to-back.
fn shutdown_and_join(handle: std::thread::JoinHandle<()>, pipe_name: &str) {
    dlp_agent::service::request_shutdown();
    // Connect a dummy client to unblock ConnectNamedPipe so the server
    // can see the shutdown flag and exit its accept loop.
    if let Ok(client) = dlp_agent::hook_ipc::connect_client(pipe_name) {
        dlp_agent::hook_ipc::close_pipe(client);
    }
    // Give the server a moment to clean up, then join.
    std::thread::sleep(std::time::Duration::from_millis(50));
    if handle.join().is_err() {
        eprintln!("WARN: server thread did not join cleanly");
    }
    dlp_agent::service::reset_shutdown_signal();
}

// ---------------------------------------------------------------------------
// Test: consolidated server routes all four frame types
// ---------------------------------------------------------------------------

/// Test that `HookIpcServer` with builder chain starts a named thread and can
/// accept `Request` frames.
#[test]
#[serial_test::serial]
fn test_consolidated_server_routes_request_frame() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestConsolidatedRequest";

    let handler = Arc::new(move |req: HookRequest| {
        let decision = if req.action == "COPY" {
            Decision::ALLOW
        } else {
            Decision::DENY
        };
        HookResponse {
            decision,
            reason: format!("mock handler: {}", req.action),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        }
    });

    let server = HookIpcServer::new(pipe_name, handler);

    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    assert_eq!(handle.thread().name(), Some("hook-ipc-server"));

    // Give the server time to create the pipe.
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Connect a client and send a Request frame.
    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    let req = HookRequest {
        path: r"C:\test\file.txt".to_string(),
        action: "COPY".to_string(),
        cache_version: 0,
        protocol_version: 1,
        op: dlp_common::hook_ipc::HookOp::Read,
        source_volume_class: Some(VolumeClass::LocalNTFS),
        destination_volume_class: Some(VolumeClass::LocalNTFS),
        pid: 1234,
    };

    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::Request(req),
    });

    let response_envelope = send_envelope(client, &envelope);

    match response_envelope {
        IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::Response(resp),
        }) => {
            assert_eq!(resp.decision, Decision::ALLOW);
            assert!(resp.reason.contains("mock handler"));
        }
        other => panic!("Expected Response frame, got {:?}", other),
    }

    dlp_agent::hook_ipc::close_pipe(client);

    shutdown_and_join(handle, pipe_name);
}

/// Test that `HookIpcServer` routes `PullDiagnostics` to the diagnostics handler
/// and returns non-empty snapshots when the diagnostic ring has been populated.
#[test]
#[serial_test::serial]
fn test_consolidated_server_routes_diagnostics_frame_with_snapshots() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestConsolidatedDiagSnapshots";

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: "default mock".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let diag_handler =
        Arc::new(
            move |_req: PullDiagnosticsRequest| dlp_common::hook_ipc::DiagnosticsResponse {
                snapshots: vec![dlp_common::hook_ipc::DiagnosticSnapshot {
                    hook_function: "WriteFile".to_string(),
                    classification_source: dlp_common::hook_ipc::ClassificationSource::Pipe,
                    classification_age_ms: 0,
                    abac_resource: r"C:\test\secret.doc".to_string(),
                    abac_action: "WRITE".to_string(),
                    abac_environment: "LocalNTFS".to_string(),
                    matched_policy_id: Some("POL-001".to_string()),
                    enforcement_mode: Some("DENY".to_string()),
                    decision_latency_us: 1234,
                    timestamp_qpc: 5678,
                    user_sid: "S-1-5-21-123".to_string(),
                }],
            },
        );

    let server = HookIpcServer::new(pipe_name, handler).with_diagnostics_handler(diag_handler);

    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::PullDiagnostics(PullDiagnosticsRequest { max_entries: 10 }),
    });

    let response_envelope = send_envelope(client, &envelope);

    match response_envelope {
        IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::DiagnosticsResponse(resp),
        }) => {
            // DIFF-02: Verify non-empty snapshots with expected fields.
            assert!(
                !resp.snapshots.is_empty(),
                "Diagnostics must return non-empty snapshots"
            );
            let snap = &resp.snapshots[0];
            assert_eq!(snap.hook_function, "WriteFile");
            assert_eq!(snap.abac_action, "WRITE");
            assert_eq!(snap.abac_resource, r"C:\test\secret.doc");
            assert_eq!(snap.user_sid, "S-1-5-21-123");
            assert_eq!(snap.decision_latency_us, 1234);
        }
        other => panic!("Expected DiagnosticsResponse frame, got {:?}", other),
    }

    dlp_agent::hook_ipc::close_pipe(client);

    shutdown_and_join(handle, pipe_name);
}

/// Test that `HookIpcServer` routes `PullHealth` to the health handler.
#[test]
#[serial_test::serial]
fn test_consolidated_server_routes_health_frame() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestConsolidatedHealth";

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: "default mock".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let health_handler =
        Arc::new(
            move |_req: PullHealthRequest| dlp_common::hook_ipc::HealthResponse {
                snapshot: dlp_common::hook_ipc::HookHealthSnapshot {
                    injected_pids: 1,
                    patched_modules: 2,
                    pipe_round_trips_60s: 3,
                    cache_hit_rate_60s: 0.5,
                    current_fail_state: 0,
                    timestamp_secs: 1_700_000_000,
                },
            },
        );

    let server = HookIpcServer::new(pipe_name, handler).with_health_handler(health_handler);

    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::PullHealth(PullHealthRequest {}),
    });

    let response_envelope = send_envelope(client, &envelope);

    match response_envelope {
        IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::HealthResponse(resp),
        }) => {
            assert_eq!(resp.snapshot.injected_pids, 1);
            assert_eq!(resp.snapshot.patched_modules, 2);
        }
        other => panic!("Expected HealthResponse frame, got {:?}", other),
    }

    dlp_agent::hook_ipc::close_pipe(client);

    shutdown_and_join(handle, pipe_name);
}

/// Test that `HookIpcServer` routes `RequestOverride` to the override
/// handler (fire-and-forget; response is ACK).
#[test]
#[serial_test::serial]
fn test_consolidated_server_routes_override_frame() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestConsolidatedOverride";

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: "default mock".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let override_count = Arc::new(AtomicUsize::new(0));
    let override_count_clone = Arc::clone(&override_count);

    let override_handler = Arc::new(move |req: OverrideRequest| {
        assert_eq!(req.requester_sid, "S-1-5-21-1");
        assert_eq!(req.data_object_id, "doc-123");
        assert_eq!(req.action, "WRITE");
        override_count_clone.fetch_add(1, Ordering::SeqCst);
    });

    let server = HookIpcServer::new(pipe_name, handler).with_override_handler(override_handler);

    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::RequestOverride(OverrideRequest {
            requester_sid: "S-1-5-21-1".to_string(),
            data_object_id: "doc-123".to_string(),
            action: "WRITE".to_string(),
            destination_scope: None,
            justification: "test".to_string(),
            resource_path: r"C:\test\file.txt".to_string(),
        }),
    });

    let payload = bincode::serialize(&envelope).expect("serialize envelope");
    dlp_agent::ipc::frame::write_frame(client, &payload).expect("write frame");

    // Override is fire-and-forget; server responds with ACK.
    let frame = dlp_agent::ipc::frame::read_frame(client).expect("read ack frame");
    let ack_envelope: IpcEnvelope = bincode::deserialize(&frame).expect("deserialize ack");
    match ack_envelope {
        IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::Response(resp),
        }) => {
            assert_eq!(resp.decision, Decision::ALLOW);
            assert!(resp.reason.contains("override"));
        }
        other => panic!("Expected Response ACK frame, got {:?}", other),
    }

    std::thread::sleep(std::time::Duration::from_millis(50));

    dlp_agent::hook_ipc::close_pipe(client);

    assert_eq!(override_count.load(Ordering::SeqCst), 1);

    shutdown_and_join(handle, pipe_name);
}

/// Test that the consolidated server returns ALLOW for COPY and DENY for DELETE
/// via the hook handler.
#[test]
#[serial_test::serial]
fn test_consolidated_server_volume_class_allow_deny() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestConsolidatedVolClass";

    let handler = Arc::new(move |req: HookRequest| {
        let decision = if req.action == "COPY" {
            Decision::ALLOW
        } else {
            Decision::DENY
        };
        HookResponse {
            decision,
            reason: format!("mock: {} with vol classes", req.action),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        }
    });

    let server = HookIpcServer::new(pipe_name, handler);

    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    // 1. COPY should ALLOW.
    {
        let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");
        let req = HookRequest {
            path: r"C:\test\file.txt".to_string(),
            action: "COPY".to_string(),
            cache_version: 0,
            protocol_version: 1,
            op: dlp_common::hook_ipc::HookOp::Read,
            source_volume_class: Some(VolumeClass::LocalNTFS),
            destination_volume_class: Some(VolumeClass::LocalNTFS),
            pid: 1234,
        };
        let envelope = IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::Request(req),
        });
        let response_envelope = send_envelope(client, &envelope);
        match response_envelope {
            IpcEnvelope::V1(IpcMessageV1 {
                payload: IpcPayloadV1::Response(resp),
            }) => {
                assert_eq!(resp.decision, Decision::ALLOW, "COPY should ALLOW");
            }
            other => panic!("Expected Response frame, got {:?}", other),
        }
        dlp_agent::hook_ipc::close_pipe(client);
    }

    // Give the server time to recycle the pipe instance.
    std::thread::sleep(std::time::Duration::from_millis(100));

    // 2. DELETE should DENY.
    {
        let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");
        let req = HookRequest {
            path: r"C:\test\file.txt".to_string(),
            action: "DELETE".to_string(),
            cache_version: 0,
            protocol_version: 1,
            op: dlp_common::hook_ipc::HookOp::Write,
            source_volume_class: Some(VolumeClass::LocalNTFS),
            destination_volume_class: None,
            pid: 1234,
        };
        let envelope = IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::Request(req),
        });
        let response_envelope = send_envelope(client, &envelope);
        match response_envelope {
            IpcEnvelope::V1(IpcMessageV1 {
                payload: IpcPayloadV1::Response(resp),
            }) => {
                assert_eq!(resp.decision, Decision::DENY, "DELETE should DENY");
                assert!(resp.reason.contains("mock"));
            }
            other => panic!("Expected Response frame, got {:?}", other),
        }
        dlp_agent::hook_ipc::close_pipe(client);
    }

    shutdown_and_join(handle, pipe_name);
}

// ---------------------------------------------------------------------------
// DIFF-04: HealthResponse one-way ingestion tests
// ---------------------------------------------------------------------------

/// Test that `HookIpcServer` ingests one-way `HealthResponse` frames into the
/// `HealthAggregator` (DIFF-04).
#[test]
#[serial_test::serial]
fn test_consolidated_server_ingests_health_response() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestHealthResponseIngest";

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: "default mock".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let health_aggregator = Arc::new(dlp_agent::health_aggregator::HealthAggregator::new());
    let health_aggregator_clone = Arc::clone(&health_aggregator);

    let server = dlp_agent::hook_ipc::HookIpcServer::new(pipe_name, handler)
        .with_health_aggregator(health_aggregator_clone);

    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    // Send a one-way HealthResponse frame (as the hook DLL would).
    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::HealthResponse(dlp_common::hook_ipc::HealthResponse {
            snapshot: dlp_common::hook_ipc::HookHealthSnapshot {
                injected_pids: 42,
                patched_modules: 7,
                pipe_round_trips_60s: 200,
                cache_hit_rate_60s: 0.85,
                current_fail_state: 0,
                timestamp_secs: 1_700_000_000,
            },
        }),
    });

    let payload = bincode::serialize(&envelope).expect("serialize envelope");
    dlp_agent::ipc::frame::write_frame(client, &payload).expect("write frame");

    // Read the ACK response (server always responds, even for one-way frames).
    let frame = dlp_agent::ipc::frame::read_frame(client).expect("read ack frame");
    let ack_envelope: IpcEnvelope = bincode::deserialize(&frame).expect("deserialize ack");
    match ack_envelope {
        IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::Response(resp),
        }) => {
            assert_eq!(resp.decision, Decision::ALLOW);
            assert!(resp.reason.contains("health snapshot ingested"));
        }
        other => panic!("Expected Response ACK frame, got {:?}", other),
    }

    dlp_agent::hook_ipc::close_pipe(client);

    // Verify the aggregator ingested the snapshot.
    let (status, snap) = health_aggregator
        .get_current_status()
        .expect("aggregator should have a snapshot");
    assert_eq!(status, dlp_agent::health_aggregator::HealthStatus::Healthy);
    assert_eq!(snap.injected_pids, 42);
    assert_eq!(snap.patched_modules, 7);
    assert_eq!(snap.pipe_round_trips_60s, 200);
    assert!((snap.cache_hit_rate_60s - 0.85).abs() < f64::EPSILON);
    assert_eq!(snap.current_fail_state, 0);

    shutdown_and_join(handle, pipe_name);
}

/// Test that `HealthResponse` frames without an aggregator configured are
/// handled gracefully (warn but do not panic).
#[test]
#[serial_test::serial]
fn test_consolidated_server_health_response_without_aggregator() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestHealthResponseNoAgg";

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: "default mock".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    // No health aggregator configured.
    let server = dlp_agent::hook_ipc::HookIpcServer::new(pipe_name, handler);

    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::HealthResponse(dlp_common::hook_ipc::HealthResponse {
            snapshot: dlp_common::hook_ipc::HookHealthSnapshot {
                injected_pids: 1,
                patched_modules: 1,
                pipe_round_trips_60s: 1,
                cache_hit_rate_60s: 0.5,
                current_fail_state: 1,
                timestamp_secs: 1_700_000_001,
            },
        }),
    });

    let payload = bincode::serialize(&envelope).expect("serialize envelope");
    dlp_agent::ipc::frame::write_frame(client, &payload).expect("write frame");

    let frame = dlp_agent::ipc::frame::read_frame(client).expect("read ack frame");
    let ack_envelope: IpcEnvelope = bincode::deserialize(&frame).expect("deserialize ack");
    match ack_envelope {
        IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::Response(resp),
        }) => {
            assert_eq!(resp.decision, Decision::ALLOW);
            assert!(resp.reason.contains("health snapshot ingested"));
        }
        other => panic!("Expected Response ACK frame, got {:?}", other),
    }

    dlp_agent::hook_ipc::close_pipe(client);

    shutdown_and_join(handle, pipe_name);
}

/// Test that multiple consecutive HealthResponse frames build up history in the
/// HealthAggregator.
#[test]
#[serial_test::serial]
fn test_health_response_builds_aggregator_history() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestHealthResponseHistory";

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: "default mock".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let health_aggregator = Arc::new(dlp_agent::health_aggregator::HealthAggregator::new());
    let health_aggregator_clone = Arc::clone(&health_aggregator);

    let server = dlp_agent::hook_ipc::HookIpcServer::new(pipe_name, handler)
        .with_health_aggregator(health_aggregator_clone);

    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    // Send 5 health snapshots with different hit rates to trigger status transitions.
    for i in 0..5 {
        let hit_rate = if i % 2 == 0 { 0.85 } else { 0.70 };
        let envelope = IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::HealthResponse(dlp_common::hook_ipc::HealthResponse {
                snapshot: dlp_common::hook_ipc::HookHealthSnapshot {
                    injected_pids: 5,
                    patched_modules: 10,
                    pipe_round_trips_60s: 100 + i as u64,
                    cache_hit_rate_60s: hit_rate,
                    current_fail_state: 0,
                    timestamp_secs: 1_700_000_000 + i as u64,
                },
            }),
        });
        let payload = bincode::serialize(&envelope).expect("serialize envelope");
        dlp_agent::ipc::frame::write_frame(client, &payload).expect("write frame");

        // Read ACK for each frame.
        let frame = dlp_agent::ipc::frame::read_frame(client).expect("read ack frame");
        let ack: IpcEnvelope = bincode::deserialize(&frame).expect("deserialize ack");
        match ack {
            IpcEnvelope::V1(IpcMessageV1 {
                payload: IpcPayloadV1::Response(resp),
            }) => {
                assert_eq!(resp.decision, Decision::ALLOW);
            }
            other => panic!("Expected Response ACK frame, got {:?}", other),
        }
    }

    dlp_agent::hook_ipc::close_pipe(client);

    shutdown_and_join(handle, pipe_name);
}

// ---------------------------------------------------------------------------
// DIFF-02/03/04: Plan 05 integration tests for diagnostic, health, and hash
// ---------------------------------------------------------------------------

/// Test that `PullDiagnostics` returns non-empty snapshots after a DENY.
///
/// This test starts a mock HookIpcServer with a diagnostics handler that
/// returns a `DiagnosticsResponse` containing one `DiagnosticSnapshot`.
/// It then connects a mock client, sends a `PullDiagnosticsRequest`, and
/// asserts the response contains at least one snapshot with
/// `hook_function == "WriteFile"`.
#[test]
#[serial_test::serial]
fn test_pull_diagnostics_after_deny() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestPullDiagnosticsAfterDeny";

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: "default mock".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let diag_handler =
        Arc::new(
            move |_req: PullDiagnosticsRequest| dlp_common::hook_ipc::DiagnosticsResponse {
                snapshots: vec![dlp_common::hook_ipc::DiagnosticSnapshot {
                    hook_function: "WriteFile".to_string(),
                    classification_source: dlp_common::hook_ipc::ClassificationSource::Pipe,
                    classification_age_ms: 0,
                    abac_resource: r"C:\test\secret.doc".to_string(),
                    abac_action: "WRITE".to_string(),
                    abac_environment: "LocalNTFS".to_string(),
                    matched_policy_id: Some("POL-001".to_string()),
                    enforcement_mode: Some("DENY".to_string()),
                    decision_latency_us: 1234,
                    timestamp_qpc: 5678,
                    user_sid: "S-1-5-21-123".to_string(),
                }],
            },
        );

    let server = HookIpcServer::new(pipe_name, handler).with_diagnostics_handler(diag_handler);

    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::PullDiagnostics(PullDiagnosticsRequest { max_entries: 10 }),
    });

    let response_envelope = send_envelope(client, &envelope);

    match response_envelope {
        IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::DiagnosticsResponse(resp),
        }) => {
            assert!(
                !resp.snapshots.is_empty(),
                "PullDiagnostics must return non-empty snapshots after a DENY"
            );
            let snap = &resp.snapshots[0];
            assert_eq!(snap.hook_function, "WriteFile");
            assert_eq!(snap.abac_action, "WRITE");
            assert_eq!(snap.abac_resource, r"C:\test\secret.doc");
            assert_eq!(snap.user_sid, "S-1-5-21-123");
            assert_eq!(snap.decision_latency_us, 1234);
        }
        other => panic!("Expected DiagnosticsResponse frame, got {:?}", other),
    }

    dlp_agent::hook_ipc::close_pipe(client);

    shutdown_and_join(handle, pipe_name);
}

/// Test that `PullHealth` returns a valid snapshot.
///
/// This test starts a mock HookIpcServer with a health handler that returns a
/// `HealthResponse` containing a `HookHealthSnapshot` with
/// `current_fail_state == 0` (Healthy).
#[test]
#[serial_test::serial]
fn test_pull_health_returns_snapshot() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestPullHealthReturnsSnapshot";

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: "default mock".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let health_handler =
        Arc::new(
            move |_req: PullHealthRequest| dlp_common::hook_ipc::HealthResponse {
                snapshot: dlp_common::hook_ipc::HookHealthSnapshot {
                    injected_pids: 1,
                    patched_modules: 2,
                    pipe_round_trips_60s: 3,
                    cache_hit_rate_60s: 0.5,
                    current_fail_state: 0,
                    timestamp_secs: 1_700_000_000,
                },
            },
        );

    let server = HookIpcServer::new(pipe_name, handler).with_health_handler(health_handler);

    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::PullHealth(PullHealthRequest {}),
    });

    let response_envelope = send_envelope(client, &envelope);

    match response_envelope {
        IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::HealthResponse(resp),
        }) => {
            assert_eq!(resp.snapshot.current_fail_state, 0);
            assert!(resp.snapshot.timestamp_secs > 0);
            assert_eq!(resp.snapshot.injected_pids, 1);
            assert_eq!(resp.snapshot.patched_modules, 2);
            assert_eq!(resp.snapshot.pipe_round_trips_60s, 3);
            assert!((resp.snapshot.cache_hit_rate_60s - 0.5).abs() < f64::EPSILON);
        }
        other => panic!("Expected HealthResponse frame, got {:?}", other),
    }

    dlp_agent::hook_ipc::close_pipe(client);

    shutdown_and_join(handle, pipe_name);
}

/// Test that `HealthResponse` frames from the hook DLL are ingested into the
/// `HealthAggregator`.
///
/// This test starts a mock HookIpcServer with a `HealthAggregator`, sends a
/// one-way `HealthResponse` frame from a mock client, and asserts the
/// aggregator's history length is 1.
#[test]
#[serial_test::serial]
fn test_health_response_ingestion() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestHealthResponseIngestion";

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: "default mock".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let health_aggregator = Arc::new(dlp_agent::health_aggregator::HealthAggregator::new());
    let health_aggregator_clone = Arc::clone(&health_aggregator);

    let server = dlp_agent::hook_ipc::HookIpcServer::new(pipe_name, handler)
        .with_health_aggregator(health_aggregator_clone);

    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    // Send a one-way HealthResponse frame (as the hook DLL would).
    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::HealthResponse(dlp_common::hook_ipc::HealthResponse {
            snapshot: dlp_common::hook_ipc::HookHealthSnapshot {
                injected_pids: 42,
                patched_modules: 7,
                pipe_round_trips_60s: 200,
                cache_hit_rate_60s: 0.85,
                current_fail_state: 0,
                timestamp_secs: 1_700_000_000,
            },
        }),
    });

    let payload = bincode::serialize(&envelope).expect("serialize envelope");
    dlp_agent::ipc::frame::write_frame(client, &payload).expect("write frame");

    // Read the ACK response (server always responds, even for one-way frames).
    let frame = dlp_agent::ipc::frame::read_frame(client).expect("read ack frame");
    let ack_envelope: IpcEnvelope = bincode::deserialize(&frame).expect("deserialize ack");
    match ack_envelope {
        IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::Response(resp),
        }) => {
            assert_eq!(resp.decision, Decision::ALLOW);
            assert!(resp.reason.contains("health snapshot ingested"));
        }
        other => panic!("Expected Response ACK frame, got {:?}", other),
    }

    dlp_agent::hook_ipc::close_pipe(client);

    // Verify the aggregator ingested the snapshot.
    assert_eq!(
        health_aggregator.history_len(),
        1,
        "HealthAggregator should have exactly 1 snapshot after ingestion"
    );

    shutdown_and_join(handle, pipe_name);
}

/// Test that a blocked write audit event contains `content_sha256` via mocked
/// `HashEvidence` frame ingestion.
///
/// This test starts a mock HookIpcServer with a `HashCache`, sends a
/// `HashEvidence` frame with a known `content_sha256`, and then verifies that
/// the agent's `HashCache` contains the expected hash when looked up by
/// `(pid, handle_value)`.
#[test]
#[serial_test::serial]
fn test_blocked_write_audit_contains_hash() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestBlockedWriteAuditContainsHash";

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: "default mock".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let hash_cache = dlp_agent::hash_cache::create_hash_cache();
    let hash_cache_clone = Arc::clone(&hash_cache);

    let server = dlp_agent::hook_ipc::HookIpcServer::new(pipe_name, handler)
        .with_hash_cache(hash_cache_clone);

    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    // Send a HashEvidence frame with a known content_sha256.
    let known_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();
    let evidence = dlp_common::hook_ipc::HashEvidenceFrame {
        pid: 1234,
        handle_value: 0xABCD,
        content_sha256: Some(known_hash.clone()),
        hash_truncated: false,
        hash_skipped: false,
        timestamp_secs: 1_700_000_000,
    };

    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::HashEvidence(evidence),
    });

    let payload = bincode::serialize(&envelope).expect("serialize envelope");
    dlp_agent::ipc::frame::write_frame(client, &payload).expect("write frame");

    // Read the ACK response (server always responds, even for one-way frames).
    let frame = dlp_agent::ipc::frame::read_frame(client).expect("read ack frame");
    let ack_envelope: IpcEnvelope = bincode::deserialize(&frame).expect("deserialize ack");
    match ack_envelope {
        IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::Response(resp),
        }) => {
            assert_eq!(resp.decision, Decision::ALLOW);
            assert!(resp.reason.contains("hash evidence received"));
        }
        other => panic!("Expected Response ACK frame, got {:?}", other),
    }

    dlp_agent::hook_ipc::close_pipe(client);

    // Verify the HashCache contains the expected hash.
    let found = dlp_agent::hash_cache::lookup_hash(&hash_cache, 1234, 0xABCD);
    assert!(
        found.is_some(),
        "HashCache should contain the hash evidence for (pid=1234, handle=0xABCD)"
    );
    let found = found.unwrap();
    assert_eq!(
        found.content_sha256,
        Some(known_hash),
        "HashCache should contain the expected content_sha256"
    );
    assert!(!found.hash_truncated);
    assert!(!found.hash_skipped);

    shutdown_and_join(handle, pipe_name);
}

// ---------------------------------------------------------------------------
// Phase 58.5: Unhook polling protocol integration tests
// ---------------------------------------------------------------------------

/// Seeds a registry with one Injected process and returns it.
fn registry_with_injected(
    pid: u32,
    creation_time: u64,
) -> Arc<dlp_agent::process_registry::ProcessRegistry> {
    let registry = Arc::new(dlp_agent::process_registry::ProcessRegistry::new());
    let key = dlp_agent::process_registry::ProcessKey { pid, creation_time };
    registry.try_claim(key);
    registry.record_injected(key, "x64".to_string());
    registry
}

/// Sends a `PollControl` frame and returns the `ControlResponse`.
fn send_poll_control(
    pipe: windows::Win32::Foundation::HANDLE,
    poll: &PollControl,
) -> ControlResponse {
    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::PollControl(poll.clone()),
    });
    let response_envelope = send_envelope(pipe, &envelope);
    match response_envelope {
        IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::ControlResponse(resp),
        }) => resp,
        other => panic!("Expected ControlResponse frame, got {:?}", other),
    }
}

/// Sends an `UnhookAck` frame and returns the server's ACK response.
fn send_unhook_ack(pipe: windows::Win32::Foundation::HANDLE, ack: UnhookAck) -> HookResponse {
    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::UnhookAck(ack),
    });
    let response_envelope = send_envelope(pipe, &envelope);
    match response_envelope {
        IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::Response(resp),
        }) => resp,
        other => panic!("Expected Response ACK frame, got {:?}", other),
    }
}

/// Integration test: full unhook polling protocol round-trip.
///
/// 1. Seed registry with one Injected entry.
/// 2. Send `PollControl` while unhook is NOT requested -> `command: None`.
/// 3. Set `UNHOOK_ALL_REQUESTED`.
/// 4. Send `PollControl` for the known entry -> `UnhookCommand`.
/// 5. Send `UnhookAck { success: true }` -> registry entry becomes `Exited`.
#[test]
#[serial_test::serial]
fn unhook_polling_protocol_roundtrip() {
    dlp_agent::service::reset_unhook_signal();
    let pipe_name = r"\\.\pipe\DlpHookPipeTestUnhookRoundtrip";

    let registry = registry_with_injected(1234, 1000);
    let registry_for_server = Arc::clone(&registry);

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::ALLOW,
        reason: "ok".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let server = HookIpcServer::new(pipe_name, handler).with_registry(registry_for_server);
    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    // Step 1: no unhook requested -> no command.
    let poll = PollControl {
        pid: 1234,
        creation_time: 1000,
    };
    let response = send_poll_control(client, &poll);
    assert!(
        response.command.is_none(),
        "no command expected before unhook request"
    );

    // Step 2: request unhook -> UnhookCommand for known injected entry.
    dlp_agent::service::UNHOOK_ALL_REQUESTED.store(true, Ordering::Release);
    let response = send_poll_control(client, &poll);
    let command = response
        .command
        .expect("UnhookCommand expected for known injected entry");
    assert_eq!(command.reason, UnhookReason::AgentShutdown);
    assert!(command.timestamp_secs > 0);

    // Step 3: successful ack -> registry entry Exited.
    let ack = UnhookAck {
        pid: 1234,
        creation_time: 1000,
        success: true,
        error: None,
    };
    let ack_response = send_unhook_ack(client, ack);
    assert_eq!(ack_response.decision, Decision::ALLOW);

    dlp_agent::hook_ipc::close_pipe(client);

    let state = registry
        .get(&dlp_agent::process_registry::ProcessKey {
            pid: 1234,
            creation_time: 1000,
        })
        .expect("key should exist");
    assert_eq!(*state, dlp_agent::process_registry::ProcessState::Exited);

    dlp_agent::service::reset_unhook_signal();
    shutdown_and_join(handle, pipe_name);
}

/// Integration test: failed `UnhookAck` preserves Injected state and emits
/// `UnhookFailure`.
#[test]
#[serial_test::serial]
fn unhook_polling_protocol_failed_ack() {
    dlp_agent::service::reset_unhook_signal();
    let pipe_name = r"\\.\pipe\DlpHookPipeTestUnhookFailedAck";

    let registry = registry_with_injected(1234, 1000);
    let registry_for_server = Arc::clone(&registry);

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::ALLOW,
        reason: "ok".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let server = HookIpcServer::new(pipe_name, handler).with_registry(registry_for_server);

    let token = dlp_agent::audit_emitter::enable_test_capture();
    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            dlp_agent::audit_emitter::set_current_capture_token(token);
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    dlp_agent::service::UNHOOK_ALL_REQUESTED.store(true, Ordering::Release);
    let poll = PollControl {
        pid: 1234,
        creation_time: 1000,
    };
    let response = send_poll_control(client, &poll);
    assert!(response.command.is_some(), "UnhookCommand expected");

    let ack = UnhookAck {
        pid: 1234,
        creation_time: 1000,
        success: false,
        error: Some("unload failed".to_string()),
    };
    let ack_response = send_unhook_ack(client, ack);
    assert_eq!(ack_response.decision, Decision::ALLOW);

    dlp_agent::hook_ipc::close_pipe(client);

    // Registry must remain Injected.
    let state = registry
        .get(&dlp_agent::process_registry::ProcessKey {
            pid: 1234,
            creation_time: 1000,
        })
        .expect("key should exist");
    assert!(matches!(
        *state,
        dlp_agent::process_registry::ProcessState::Injected { .. }
    ));

    // UnhookFailure audit should be captured.
    let events = dlp_agent::audit_emitter::drain_test_events();
    let failure_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == dlp_common::EventType::UnhookFailure)
        .collect();
    assert_eq!(failure_events.len(), 1);
    assert_eq!(failure_events[0].resource_path, "pid=1234");
    assert!(
        failure_events[0]
            .justification
            .as_deref()
            .unwrap_or("")
            .contains("unload failed"),
        "error metadata should be in justification"
    );

    dlp_agent::service::reset_unhook_signal();
    shutdown_and_join(handle, pipe_name);
}

/// Integration test: `PollControl` for an unknown/stale caller receives
/// `command: None` even when `UNHOOK_ALL_REQUESTED` is true.
#[test]
#[serial_test::serial]
fn unhook_polling_protocol_unknown_caller() {
    dlp_agent::service::reset_unhook_signal();
    let pipe_name = r"\\.\pipe\DlpHookPipeTestUnhookUnknownCaller";

    let registry = registry_with_injected(1234, 1000);
    let registry_for_server = Arc::clone(&registry);

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::ALLOW,
        reason: "ok".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let server = HookIpcServer::new(pipe_name, handler).with_registry(registry_for_server);
    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    std::thread::sleep(std::time::Duration::from_millis(100));

    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");

    dlp_agent::service::UNHOOK_ALL_REQUESTED.store(true, Ordering::Release);
    // Same PID but different creation_time -> not in registry as Injected.
    let poll = PollControl {
        pid: 1234,
        creation_time: 9999,
    };
    let response = send_poll_control(client, &poll);
    assert!(
        response.command.is_none(),
        "no command expected for unknown/stale caller"
    );

    dlp_agent::hook_ipc::close_pipe(client);

    dlp_agent::service::reset_unhook_signal();
    shutdown_and_join(handle, pipe_name);
}

/// Integration test: watchdog evidence reconciliation round-trip.
///
/// Writes evidence files to a temporary directory, invokes the test-exposed
/// `reconcile_watchdog_evidence_in_dir` helper, and verifies that matched
/// entries transition to `Exited` and emit `WatchdogSelfUnload`, while
/// unmatched entries are retained and emit an untracked event.
#[test]
#[serial_test::serial]
fn watchdog_evidence_reconciliation_roundtrip() {
    let _guard = dlp_agent::audit_emitter::audit_test_lock();
    dlp_agent::audit_emitter::enable_test_capture();

    let dir = tempfile::tempdir()
        .unwrap()
        .as_ref()
        .join("WatchdogSelfUnload");
    std::fs::create_dir_all(&dir).unwrap();

    // Matched evidence file.
    let matched_path = dir.join("1234.evidence.json");
    let matched_evidence = serde_json::json!({
        "pid": 1234,
        "creation_time": 1000,
        "reason": "watchdog_timeout",
        "timestamp_secs": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });
    std::fs::write(
        &matched_path,
        serde_json::to_string(&matched_evidence).unwrap(),
    )
    .unwrap();

    // Unmatched evidence file.
    let unmatched_path = dir.join("9999.evidence.json");
    let unmatched_evidence = serde_json::json!({
        "pid": 9999,
        "creation_time": 1000,
        "reason": "watchdog_timeout",
        "timestamp_secs": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });
    std::fs::write(
        &unmatched_path,
        serde_json::to_string(&unmatched_evidence).unwrap(),
    )
    .unwrap();

    // Seed registry with a matching Injected entry.
    let registry = Arc::new(dlp_agent::process_registry::ProcessRegistry::new());
    let matched_key = dlp_agent::process_registry::ProcessKey {
        pid: 1234,
        creation_time: 1000,
    };
    registry.try_claim(matched_key);
    registry.record_injected(matched_key, "x64".to_string());

    let audit_ctx = dlp_agent::audit_emitter::EmitContext {
        agent_id: "AGENT-TEST".to_string(),
        session_id: 1,
        user_sid: "S-1-5-18".to_string(),
        user_name: "SYSTEM".to_string(),
        machine_name: None,
    };

    dlp_agent::service::reconcile_watchdog_evidence_in_dir(
        &audit_ctx,
        Some(Arc::clone(&registry)),
        dir.clone(),
    );

    // Matched entry should be Exited and the file removed.
    let state = registry.get(&matched_key).expect("key should exist");
    assert_eq!(*state, dlp_agent::process_registry::ProcessState::Exited);
    assert!(
        !matched_path.exists(),
        "matched evidence file should be removed"
    );

    // Unmatched file should be retained.
    assert!(
        unmatched_path.exists(),
        "unmatched evidence file should be retained"
    );

    // Both events should be captured.
    let events = dlp_agent::audit_emitter::drain_test_events();
    let watchdog_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == dlp_common::EventType::WatchdogSelfUnload)
        .collect();
    assert_eq!(watchdog_events.len(), 2);

    let matched_event = watchdog_events
        .iter()
        .find(|e| e.resource_path == "process://1234/watchdog_self_unload")
        .expect("matched event should exist");
    assert!(matched_event
        .justification
        .as_deref()
        .unwrap_or("")
        .contains("reason=watchdog_timeout"));

    let unmatched_event = watchdog_events
        .iter()
        .find(|e| e.resource_path == "process://9999/watchdog_self_unload")
        .expect("unmatched event should exist");
    assert!(
        unmatched_event
            .justification
            .as_deref()
            .unwrap_or("")
            .contains("untracked=true"),
        "expected untracked flag in justification"
    );
}
