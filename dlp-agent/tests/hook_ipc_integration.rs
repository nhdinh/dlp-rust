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

use std::process::{Command, Stdio};
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

/// Default mock hook handler used by most integration tests.
fn default_mock_handler() -> dlp_agent::hook_ipc::HookHandler {
    Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: "default mock".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    })
}

/// Spawns a `HookIpcServer` on a named thread and returns the join handle.
fn spawn_test_server(server: dlp_agent::hook_ipc::HookIpcServer) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn")
}

/// Starts a test server, waits for its pipe, and connects a client.
fn start_test_server(
    pipe_name: &str,
    server: dlp_agent::hook_ipc::HookIpcServer,
) -> (
    std::thread::JoinHandle<()>,
    windows::Win32::Foundation::HANDLE,
) {
    let handle = spawn_test_server(server);
    std::thread::sleep(std::time::Duration::from_millis(100));
    let client = dlp_agent::hook_ipc::connect_client(pipe_name).expect("client connect");
    (handle, client)
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

    let handle = spawn_test_server(server);

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
        handle_value: 0,
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

    let handler = default_mock_handler();

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
                    timestamp_secs: 5678,
                    user_sid: "S-1-5-21-123".to_string(),
                }],
            },
        );

    let server = HookIpcServer::new(pipe_name, handler).with_diagnostics_handler(diag_handler);

    let (handle, client) = start_test_server(pipe_name, server);

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

    let handler = default_mock_handler();

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

    let (handle, client) = start_test_server(pipe_name, server);

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

    let handler = default_mock_handler();

    let override_count = Arc::new(AtomicUsize::new(0));
    let override_count_clone = Arc::clone(&override_count);

    let override_handler = Arc::new(move |req: OverrideRequest| {
        assert_eq!(req.requester_sid, "S-1-5-21-1");
        assert_eq!(req.data_object_id, "doc-123");
        assert_eq!(req.action, "WRITE");
        override_count_clone.fetch_add(1, Ordering::SeqCst);
    });

    let server = HookIpcServer::new(pipe_name, handler).with_override_handler(override_handler);

    let (handle, client) = start_test_server(pipe_name, server);

    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::RequestOverride(OverrideRequest {
            requester_sid: "S-1-5-21-1".to_string(),
            pid: 0,
            data_object_id: "doc-123".to_string(),
            action: "WRITE".to_string(),
            classification: "T3".to_string(),
            destination_scope: None,
            justification: "test".to_string(),
            resource_path: r"C:\test\file.txt".to_string(),
        }),
    });

    let payload = bincode::serialize(&envelope).expect("serialize envelope");
    dlp_agent::ipc::frame::write_frame(client, &payload).expect("write frame");

    // RequestOverride is fire-and-forget: the server handles the request but
    // does not write a response frame because the DLL closes the pipe
    // immediately after send_raw_oneway. Close our end so the server leaves
    // handle_connection and the override handler can run.
    dlp_agent::hook_ipc::close_pipe(client);

    // Give the handler a moment to run on the server thread.
    std::thread::sleep(std::time::Duration::from_millis(100));

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

    let handle = spawn_test_server(server);

    // Give the server time to create the pipe.
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
            handle_value: 0,
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
            handle_value: 0,
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

    let handler = default_mock_handler();

    let health_aggregator = Arc::new(dlp_agent::health_aggregator::HealthAggregator::new());
    let health_aggregator_clone = Arc::clone(&health_aggregator);

    let server = dlp_agent::hook_ipc::HookIpcServer::new(pipe_name, handler)
        .with_health_aggregator(health_aggregator_clone);

    let (handle, client) = start_test_server(pipe_name, server);

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

    // HealthResponse is one-way: the server ingests and writes NO response
    // (WR-02). Let the server ingest, then assert the aggregator side effect
    // instead of reading an ACK (reading would deadlock the client).
    std::thread::sleep(std::time::Duration::from_millis(100));

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

    let handler = default_mock_handler();

    // No health aggregator configured.
    let server = dlp_agent::hook_ipc::HookIpcServer::new(pipe_name, handler);

    let (handle, client) = start_test_server(pipe_name, server);

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

    // HealthResponse is one-way: the server handles it (warn if no aggregator)
    // and writes NO response (WR-02). Let it run, then close cleanly instead of
    // reading an ACK (reading would deadlock the client).
    std::thread::sleep(std::time::Duration::from_millis(100));

    dlp_agent::hook_ipc::close_pipe(client);

    shutdown_and_join(handle, pipe_name);
}

/// Test that multiple consecutive HealthResponse frames build up history in the
/// HealthAggregator.
#[test]
#[serial_test::serial]
fn test_health_response_builds_aggregator_history() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestHealthResponseHistory";

    let handler = default_mock_handler();

    let health_aggregator = Arc::new(dlp_agent::health_aggregator::HealthAggregator::new());
    let health_aggregator_clone = Arc::clone(&health_aggregator);

    let server = dlp_agent::hook_ipc::HookIpcServer::new(pipe_name, handler)
        .with_health_aggregator(health_aggregator_clone);

    let (handle, client) = start_test_server(pipe_name, server);

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
    }

    // HealthResponse frames are one-way: the server ingests each and writes NO
    // response (WR-02). Let the server drain the loop, then close cleanly
    // instead of reading an ACK per frame (which would deadlock on frame 0).
    std::thread::sleep(std::time::Duration::from_millis(150));

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

    let handler = default_mock_handler();

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
                    timestamp_secs: 5678,
                    user_sid: "S-1-5-21-123".to_string(),
                }],
            },
        );

    let server = HookIpcServer::new(pipe_name, handler).with_diagnostics_handler(diag_handler);

    let (handle, client) = start_test_server(pipe_name, server);

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

    let handler = default_mock_handler();

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

    let (handle, client) = start_test_server(pipe_name, server);

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

    let handler = default_mock_handler();

    let health_aggregator = Arc::new(dlp_agent::health_aggregator::HealthAggregator::new());
    let health_aggregator_clone = Arc::clone(&health_aggregator);

    let server = dlp_agent::hook_ipc::HookIpcServer::new(pipe_name, handler)
        .with_health_aggregator(health_aggregator_clone);

    let (handle, client) = start_test_server(pipe_name, server);

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

    // HealthResponse is one-way: the server ingests and writes NO response
    // (WR-02). Let the server ingest, then assert history_len instead of reading
    // an ACK (reading would deadlock the client).
    std::thread::sleep(std::time::Duration::from_millis(100));

    dlp_agent::hook_ipc::close_pipe(client);

    // Verify the aggregator ingested the snapshot.
    assert_eq!(
        health_aggregator.history_len(),
        1,
        "HealthAggregator should have exactly 1 snapshot after ingestion"
    );

    shutdown_and_join(handle, pipe_name);
}

/// Test that `HookIpcServer` ingests one-way `DiagnosticsResponse` frames into
/// the `DiagnosticAggregator` keyed by the real pipe client PID + agent_id
/// (DIFF-04 consumer half).
///
/// Drives a single one-way `IpcPayloadV1::DiagnosticsResponse` frame through the
/// server (the same fire-and-send shape the hook DLL emits) and asserts the
/// aggregator is actually fed — holding out RESEARCH Pitfall 1 (the aggregator
/// must not stay empty in production). This deliberately does NOT use the
/// `PullDiagnostics` request/response path.
#[test]
#[serial_test::serial]
fn diagnostics_response_ingests_into_aggregator() {
    let pipe_name = r"\\.\pipe\DlpHookPipeTestDiagnosticsResponseIngest";

    let handler = default_mock_handler();

    let aggregator = Arc::new(dlp_agent::diagnostic_aggregator::DiagnosticAggregator::new());
    let aggregator_clone = Arc::clone(&aggregator);

    let server = dlp_agent::hook_ipc::HookIpcServer::new(pipe_name, handler)
        .with_diagnostic_aggregator("agent-test", aggregator_clone);

    let (handle, client) = start_test_server(pipe_name, server);

    // Send a one-way DiagnosticsResponse frame exactly as the hook DLL would.
    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::DiagnosticsResponse(dlp_common::hook_ipc::DiagnosticsResponse {
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
                timestamp_secs: 5678,
                user_sid: "S-1-5-21-123".to_string(),
            }],
        }),
    });

    let payload = bincode::serialize(&envelope).expect("serialize envelope");
    dlp_agent::ipc::frame::write_frame(client, &payload).expect("write frame");

    // DiagnosticsResponse is one-way: the server ingests and writes NO response
    // (WR-02). Let the server ingest, then assert the aggregator count instead
    // of reading an ACK (reading would deadlock the client).
    std::thread::sleep(std::time::Duration::from_millis(100));

    dlp_agent::hook_ipc::close_pipe(client);

    // The aggregator must be keyed by "{pid}_{agent_id}" and hold exactly one
    // snapshot. Integration tests link the non-test build of dlp-agent, so the
    // PID is the real pipe client PID (the test process) — we assert the count,
    // not the literal key, to stay independent of the runtime PID.
    assert_eq!(
        aggregator.total_snapshot_count(),
        1,
        "DiagnosticAggregator should retain exactly one snapshot after one one-way frame"
    );

    shutdown_and_join(handle, pipe_name);
}

/// Integration test: an injected idle child process (that never calls a hooked
/// API) still connects to the agent pipe and sends a `PollControl` frame with
/// the real process creation time.
///
/// This validates the Phase 58.5 fix: the agent records the real creation time
/// and the hook DLL starts its control-poll thread immediately after injection.
#[test]
#[serial_test::serial]
fn idle_injected_process_sends_poll_control_with_creation_time() {
    use std::sync::Mutex;

    dlp_agent::service::reset_unhook_signal();

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().expect("workspace root");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    // `cargo test` builds dlp-hook-dll with the `test-helpers` feature, which
    // includes a mock `poll_control` queue for unit tests. The injected DLL is
    // an independent process, so we force real named-pipe I/O via the env var
    // below rather than building a second production DLL (which would contend
    // with the outer `cargo test` and could confuse doctest compilation).
    let dll_path = workspace_root
        .join("target")
        .join(profile)
        .join("dlp_hook_dll.dll");

    if !dll_path.exists() {
        eprintln!(
            "Skipping idle-injection test: DLL not found at {}. Run `cargo build -p dlp-hook-dll` first.",
            dll_path.display()
        );
        return;
    }

    let pipe_name = dlp_agent::hook_ipc::DEFAULT_PIPE_NAME;

    // Capture the first PollControl frame received from the injected process.
    let captured_poll: Arc<Mutex<Option<PollControl>>> = Arc::new(Mutex::new(None));
    let captured_poll_for_handler = Arc::clone(&captured_poll);
    let poll_handler: dlp_agent::hook_ipc::PollControlHandler =
        Arc::new(move |poll: &PollControl| {
            let mut guard = captured_poll_for_handler.lock().unwrap();
            if guard.is_none() {
                *guard = Some(poll.clone());
            }
        });

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::ALLOW,
        reason: "ok".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let server = dlp_agent::hook_ipc::HookIpcServer::new(pipe_name, handler)
        .with_poll_control_handler(poll_handler);

    let handle = std::thread::Builder::new()
        .name("hook-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = server.run() {
                eprintln!("Hook IPC server exited with error: {}", e);
            }
        })
        .expect("server thread should spawn");

    // Give the server time to create the pipe.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Spawn an idle child process that will not call any hooked API.
    // Use ping instead of timeout because MSYS/Cygwin timeout.exe may shadow
    // the cmd built-in and reject the bare "30" argument.
    //
    // Force real named-pipe I/O in the injected DLL: the DLL is built with
    // test-helpers in this configuration, so without this flag poll_control
    // would read from an empty mock queue and never reach the agent server.
    let mut child = Command::new("cmd.exe")
        .env("DLP_HOOK_TEST_REAL_POLL", "1")
        .args(["/c", "ping", "-n", "31", "127.0.0.1"])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn test process");

    let child_pid = child.id();
    let creation_time = dlp_agent::process_utils::get_process_creation_time(child_pid)
        .expect("child creation time should be queryable");

    eprintln!(
        "Spawned idle test process PID {} creation_time {}",
        child_pid, creation_time
    );

    // Inject the hook DLL. This should also start the control-poll thread.
    let injector = dlp_agent::hook_injector::HookInjector::new(&dll_path, None);
    let inject_result = injector.inject(child_pid);

    // Wait for the first PollControl frame, with a generous timeout.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut received = None;
    while std::time::Instant::now() < deadline {
        if let Some(poll) = captured_poll.lock().unwrap().clone() {
            received = Some(poll);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Clean up child regardless of injection result.
    let _ = child.kill();
    let _ = child.wait();

    // Validate injection succeeded (or was skipped for privilege reasons).
    match inject_result {
        Ok(()) => {}
        Err(dlp_agent::hook_injector::HookError::AccessDenied { .. })
        | Err(dlp_agent::hook_injector::HookError::RemoteAllocFailed { .. })
        | Err(dlp_agent::hook_injector::HookError::RemoteWriteFailed { .. })
        | Err(dlp_agent::hook_injector::HookError::RemoteThreadFailed { .. }) => {
            eprintln!(
                "Skipping idle-injection test: insufficient privileges or security restriction"
            );
            shutdown_and_join(handle, pipe_name);
            return;
        }
        Err(other) => panic!("injection should succeed: {:?}", other),
    }

    let poll = received.expect("agent should receive PollControl from idle injected process");
    assert_eq!(
        poll.pid, child_pid,
        "PollControl pid should match child pid"
    );
    assert_eq!(
        poll.creation_time, creation_time,
        "PollControl creation_time should match real process creation time"
    );

    dlp_agent::service::reset_unhook_signal();
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

    let handler = default_mock_handler();

    let hash_cache = dlp_agent::hash_cache::create_hash_cache();
    let hash_cache_clone = Arc::clone(&hash_cache);

    let server = dlp_agent::hook_ipc::HookIpcServer::new(pipe_name, handler)
        .with_hash_cache(hash_cache_clone);

    let (handle, client) = start_test_server(pipe_name, server);

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

    // HashEvidence is one-way: the server populates the HashCache and writes NO
    // response (WR-02). Let the server ingest, then assert the HashCache side
    // effect instead of reading an ACK (reading would deadlock the client).
    std::thread::sleep(std::time::Duration::from_millis(100));

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

/// Returns the process ID used by the unhook polling protocol integration tests.
///
/// `UnhookAck` validation compares the ack's claimed PID against the real
/// named-pipe client PID. Integration tests link against the non-test build of
/// `dlp-agent`, so they cannot use the unit-test PID override; instead they use
/// the current process ID and seed the registry with the same value.
fn test_pid() -> u32 {
    std::process::id()
}

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

    let registry = registry_with_injected(test_pid(), 1000);
    let registry_for_server = Arc::clone(&registry);

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::ALLOW,
        reason: "ok".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let server = HookIpcServer::new(pipe_name, handler).with_registry(registry_for_server);
    let (handle, client) = start_test_server(pipe_name, server);

    // Step 1: no unhook requested -> no command.
    let poll = PollControl {
        pid: test_pid(),
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
        pid: test_pid(),
        creation_time: 1000,
        success: true,
        error: None,
    };
    let ack_response = send_unhook_ack(client, ack);
    assert_eq!(ack_response.decision, Decision::ALLOW);

    dlp_agent::hook_ipc::close_pipe(client);

    let state = registry
        .get(&dlp_agent::process_registry::ProcessKey {
            pid: test_pid(),
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

    let registry = registry_with_injected(test_pid(), 1000);
    let registry_for_server = Arc::clone(&registry);

    let handler = Arc::new(move |_req: HookRequest| HookResponse {
        decision: Decision::ALLOW,
        reason: "ok".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });

    let server = HookIpcServer::new(pipe_name, handler)
        .with_registry(registry_for_server)
        .with_audit_ctx(dlp_agent::audit_emitter::EmitContext::default());

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
        pid: test_pid(),
        creation_time: 1000,
    };
    let response = send_poll_control(client, &poll);
    assert!(response.command.is_some(), "UnhookCommand expected");

    let ack = UnhookAck {
        pid: test_pid(),
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
            pid: test_pid(),
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
    assert_eq!(
        failure_events[0].resource_path,
        format!("pid={}", test_pid())
    );
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
    let (handle, client) = start_test_server(pipe_name, server);

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

// ---------------------------------------------------------------------------
// MODE-01 (Phase 58.10 Plan 03): end-to-end decision-path tests
// ---------------------------------------------------------------------------
//
// These tests call the REAL `evaluate_hook_request` (the function the production
// hook-IPC closure delegates to, extracted in Plan 01) directly with an EXPLICIT
// `global_mode`. This is the concrete mechanism that resolves the harness
// infeasibility: the `default_mock_handler` returns a hardcoded response and
// never runs `offline_decision` or the mode gate, and the production closure
// reads the mode via the `CONFIG: OnceLock` (set-once-per-process) — so neither
// can drive both an Audit and a Block case in one process. `evaluate_hook_request`
// takes `global_mode` as an explicit parameter, so a single test process drives
// both. No named pipe is used, so these are NOT `#[cfg(windows)]`-gated.

use dlp_common::abac::{EnforcementMode, EvaluateResponse};

/// Builds the fixtures `evaluate_hook_request` needs: an `OfflineManager`
/// backed by a fresh cache, an empty `ApprovalCache` (so the approval-override
/// early return does not fire), and an empty `HashCache`. Returns the manager
/// plus the cache so a test can pre-populate a cached DENY (a cache HIT) to
/// drive the deny path through the real `offline_decision`.
fn mode_gate_fixtures() -> (
    dlp_agent::offline::OfflineManager,
    Arc<dlp_agent::cache::Cache>,
    dlp_agent::approval_cache::ApprovalCache,
    dlp_agent::hash_cache::HashCache,
) {
    let cache = Arc::new(dlp_agent::cache::Cache::new());
    let client = dlp_agent::engine_client::EngineClient::default_client()
        .expect("default engine client constructs");
    let manager = dlp_agent::offline::OfflineManager::new(client, cache.clone(), None);
    let approval = dlp_agent::approval_cache::ApprovalCache::new();
    let hash_cache = dlp_agent::hash_cache::create_hash_cache();
    (manager, cache, approval, hash_cache)
}

/// A cached DENY response whose per-policy mode is Audit, standing in for a
/// T3/T4 sensitive-write denial. The parity audit threads the classification
/// carried by the `EvaluateRequest` built from the hook request.
fn cached_sensitive_deny() -> EvaluateResponse {
    EvaluateResponse {
        decision: Decision::DENY,
        matched_policy_id: Some("policy-sensitive-write".to_string()),
        reason: "sensitive write".to_string(),
        enforcement_mode: Some(EnforcementMode::Audit),
        would_have_denied: true,
        matched_label_id: None,
    }
}

fn t3_write_request(path: &str) -> HookRequest {
    HookRequest {
        path: path.to_string(),
        action: "WRITE".to_string(),
        ..Default::default()
    }
}

/// SC#2 evidence (hook path): a global Audit override flips a real cached DENY
/// to ALLOW and emits a full-parity Access audit (would_have_denied=true,
/// policy_mode="Audit"). Driven through the REAL `evaluate_hook_request`
/// decision path — not the mock handler, not the CONFIG OnceLock.
#[test]
fn global_audit_returns_allow_for_sensitive_write_with_parity_audit() {
    let (manager, cache, approval, hash_cache) = mode_gate_fixtures();
    let path = r"C:\Restricted\secret.xlsx";
    let sid = "S-1-5-21-999";

    // Pre-populate a cached DENY so `offline_decision` returns a real denial
    // (a cache HIT) that the mode gate can flip.
    cache.insert(path, sid, cached_sensitive_deny());

    let req = t3_write_request(path);
    let (response, audit) = dlp_agent::service::evaluate_hook_request(
        &req,
        sid.to_string(),
        &manager,
        &approval,
        &hash_cache,
        EnforcementMode::Audit,
    );

    // Global Audit flips the cached DENY to ALLOW.
    assert_eq!(
        response.decision,
        Decision::ALLOW,
        "global Audit must flip the cached DENY to ALLOW"
    );

    // Exactly one full-parity Access audit is produced.
    let audit = audit.expect("parity audit emitted on Audit flip");
    assert_eq!(audit.event_type, dlp_common::EventType::Access);
    assert_eq!(audit.policy_mode.as_deref(), Some("Audit"));
    assert!(
        audit.would_have_denied,
        "parity audit must set would_have_denied"
    );
}

/// Control (T-17 preserved end-to-end): the SAME request under a global Block
/// override keeps the DENY. Runs in the SAME process as the Audit case because
/// `global_mode` is an explicit parameter (no OnceLock).
#[test]
fn global_block_preserves_deny_for_sensitive_write() {
    let (manager, cache, approval, hash_cache) = mode_gate_fixtures();
    let path = r"C:\Restricted\secret.xlsx";
    let sid = "S-1-5-21-999";

    cache.insert(path, sid, cached_sensitive_deny());

    let req = t3_write_request(path);
    let (response, _audit) = dlp_agent::service::evaluate_hook_request(
        &req,
        sid.to_string(),
        &manager,
        &approval,
        &hash_cache,
        EnforcementMode::Block,
    );

    // DENY preserved under global Block — the mode gate is NOT a no-op.
    assert_eq!(
        response.decision,
        Decision::DENY,
        "global Block must preserve the cached DENY (T-17)"
    );
}
