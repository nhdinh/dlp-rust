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
        HookRequest, HookResponse, IpcEnvelope, IpcMessageV1, IpcPayloadV1, OverrideRequest,
        PullDiagnosticsRequest, PullHealthRequest,
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

    // Detach the server thread. It will block on the next ConnectNamedPipe
    // until the integration test binary exits, at which point the OS terminates
    // it. Joining is not required for this test and avoids a shutdown-race.
    let _ = handle;
    dlp_agent::service::reset_shutdown_signal();
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
            assert!(!resp.snapshots.is_empty(), "Diagnostics must return non-empty snapshots");
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

    let _ = handle;
    dlp_agent::service::reset_shutdown_signal();
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

    // Detach the server thread. It will block on the next ConnectNamedPipe
    // until the integration test binary exits, at which point the OS terminates
    // it. Joining is not required for this test and avoids a shutdown-race.
    let _ = handle;
    dlp_agent::service::reset_shutdown_signal();
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

    // Detach the server thread. It will block on the next ConnectNamedPipe
    // until the integration test binary exits, at which point the OS terminates
    // it. Joining is not required for this test and avoids a shutdown-race.
    let _ = handle;
    dlp_agent::service::reset_shutdown_signal();
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

    // Detach the server thread. It will block on the next ConnectNamedPipe
    // until the integration test binary exits, at which point the OS terminates
    // it. Joining is not required for this test and avoids a shutdown-race.
    let _ = handle;
    dlp_agent::service::reset_shutdown_signal();
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

    // Detach the server thread.
    let _ = handle;
    dlp_agent::service::reset_shutdown_signal();
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

    let _ = handle;
    dlp_agent::service::reset_shutdown_signal();
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

    // Verify history has all 5 entries.
    assert_eq!(health_aggregator.history_len(), 5);
    let history = health_aggregator.get_history();
    assert_eq!(history.len(), 5);
    // Verify timestamps are in order.
    for (i, snap) in history.iter().enumerate() {
        assert_eq!(snap.timestamp_secs, 1_700_000_000 + i as u64);
    }

    let _ = handle;
    dlp_agent::service::reset_shutdown_signal();
}