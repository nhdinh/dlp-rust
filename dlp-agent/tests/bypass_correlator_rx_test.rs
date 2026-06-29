//! Integration tests for bypass_rx routing to BypassCorrelator.
//!
//! Tests verify that bypass alerts sent by the hook DLL over the named pipe
//! (via `bypass_tx`) are consumed by the `BypassCorrelator` bypass_rx task
//! and routed to the alert batch (and eventually to the repository via flush).

use std::sync::Arc;

use dlp_common::abac::EnforcementMode;
use dlp_common::hook_ipc::{BypassAlert, BypassReason};

use dlp_agent::bypass_correlator::{BypassCorrelator, CorrelatorConfig};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates a default `BypassAlert` for testing.
fn test_bypass_alert(pid: u32, stub_name: &str, reason: BypassReason) -> BypassAlert {
    BypassAlert {
        reason,
        stub_name: stub_name.to_string(),
        pid,
        timestamp_secs: 1_700_000_000,
        version: 2,
        agent_id: "".to_string(),
        image_path: "".to_string(),
        image_sha256: None,
        file_path: r"C:\Data\file.txt".to_string(),
        operation: "Create".to_string(),
        file_object: 0xDEADBEEF,
        qpc_timestamp: 0,
        severity: "".to_string(),
        correlation_reason: "".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Test 1: bypass_rx routes alert to repository (via batch)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_bypass_rx_routes_to_repo() {
    // Arrange: Create correlator with default config (EnforcementMode::PerPolicy).
    let config = CorrelatorConfig::default();
    let correlator = Arc::new(BypassCorrelator::new(config));

    let (bypass_tx, bypass_rx) = crossbeam_channel::bounded::<BypassAlert>(100);

    let alert = test_bypass_alert(1234, "NtCreateFile", BypassReason::HookOverwritten);

    // Act: Send alert via bypass_tx (simulating hook DLL IPC).
    bypass_tx.send(alert.clone()).expect("send should succeed");

    // Simulate what the bypass_rx task in run() does: recv + submit_bypass_alert.
    let received = bypass_rx.recv().expect("recv should succeed");
    let corr_clone = Arc::clone(&correlator);
    corr_clone.submit_bypass_alert(received).await;

    // Assert: Alert is in the batch (awaiting flush to repository).
    assert_eq!(
        correlator.batch_len().await,
        1,
        "alert should be batched after submit_bypass_alert"
    );
    let batched_alert = correlator.batch_alert(0).await.expect("alert at index 0");
    assert_eq!(batched_alert.pid, 1234);
    assert_eq!(batched_alert.reason, BypassReason::HookOverwritten);
    assert_eq!(batched_alert.stub_name, "NtCreateFile");
    // Verify agent-side enrichment was applied.
    assert!(
        !batched_alert.agent_id.is_empty(),
        "agent_id should be enriched"
    );
    assert!(
        !batched_alert.severity.is_empty(),
        "severity should be mapped"
    );
    assert!(
        batched_alert
            .correlation_reason
            .contains("Hook self-reported"),
        "correlation_reason should be set"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Audit mode suppresses bypass_rx alerts
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_bypass_rx_audit_mode_suppresses() {
    // Arrange: Create correlator in Audit mode.
    let config = dlp_agent::bypass_correlator::CorrelatorConfig {
        enforcement_mode: EnforcementMode::Audit,
        ..Default::default()
    };
    let correlator = Arc::new(BypassCorrelator::new(config));

    let (bypass_tx, bypass_rx) = crossbeam_channel::bounded::<BypassAlert>(100);

    let alert = test_bypass_alert(5678, "NtWriteFile", BypassReason::PatchRaced);

    // Act: Send alert via bypass_tx.
    bypass_tx.send(alert).expect("send should succeed");

    // Simulate bypass_rx task.
    let received = bypass_rx.recv().expect("recv should succeed");
    let corr_clone = Arc::clone(&correlator);
    corr_clone.submit_bypass_alert(received).await;

    // Assert: Batch should be empty because Audit mode suppresses.
    assert_eq!(
        correlator.batch_len().await,
        0,
        "audit mode should suppress bypass_rx alerts"
    );
}

// ---------------------------------------------------------------------------
// Test 3: 100-alert batch boundary
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_bypass_rx_batch_of_100() {
    // Arrange: Create correlator with batch_size = 100 (default).
    let config = CorrelatorConfig::default();
    let correlator = Arc::new(BypassCorrelator::new(config));

    let (bypass_tx, bypass_rx) = crossbeam_channel::bounded::<BypassAlert>(1000);

    // Act: Send 100 alerts rapidly.
    for i in 0..100 {
        let alert = test_bypass_alert(1000 + i, "NtCreateFile", BypassReason::HookOverwritten);
        bypass_tx.send(alert).expect("send should succeed");
    }

    // Simulate bypass_rx task: drain all 100 alerts.
    let corr_clone = Arc::clone(&correlator);
    let bypass_rx_handle = tokio::task::spawn_blocking(move || {
        while let Ok(alert) = bypass_rx.recv() {
            let corr = Arc::clone(&corr_clone);
            // Bridge sync to async.
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.block_on(corr.submit_bypass_alert(alert));
            }
        }
    });

    // Wait for the task to complete (channel closes when tx dropped).
    // Give it a moment to process, then drop tx to signal completion.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(bypass_tx);
    bypass_rx_handle
        .await
        .expect("spawn_blocking should succeed");

    // Assert: All 100 alerts should be in the batch.
    assert_eq!(
        correlator.batch_len().await,
        100,
        "all 100 bypass alerts should be batched"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Graceful channel close handling
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_bypass_rx_drop_on_channel_close() {
    // Arrange: Create correlator and channel.
    let config = CorrelatorConfig::default();
    let correlator = Arc::new(BypassCorrelator::new(config));

    let (bypass_tx, bypass_rx) = crossbeam_channel::bounded::<BypassAlert>(10);

    let alert = test_bypass_alert(9999, "NtCreateFile", BypassReason::HookOverwritten);

    // Send one alert before closing.
    bypass_tx.send(alert).expect("send should succeed");

    // Act: Drop the sender (simulates hook DLL disconnect / channel close).
    drop(bypass_tx);

    // Simulate bypass_rx task: recv the one alert, then exit gracefully.
    let corr_clone = Arc::clone(&correlator);
    let handle = tokio::task::spawn_blocking(move || {
        let mut received_count = 0;
        while let Ok(alert) = bypass_rx.recv() {
            let corr = Arc::clone(&corr_clone);
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.block_on(corr.submit_bypass_alert(alert));
            }
            received_count += 1;
        }
        // Channel closed — exit gracefully.
        received_count
    });

    let received_count = handle.await.expect("task should complete gracefully");

    // Assert: One alert received, then channel closed gracefully.
    assert_eq!(received_count, 1, "should receive exactly one alert");
    assert_eq!(
        correlator.batch_len().await,
        1,
        "one alert should be batched"
    );
}
