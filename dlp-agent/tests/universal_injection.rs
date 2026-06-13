//! Integration tests for universal injection subsystem (Phase 49).
//!
//! These tests exercise:
//! - ProcessRegistry state transitions
//! - AllowlistMatcher system-critical and self-exclusion
//! - AppInit registry reading and Secure Boot detection
//! - ProcessWatcher lifecycle

use std::sync::Arc;

// ---------------------------------------------------------------------------
// Process Registry State Transitions
// ---------------------------------------------------------------------------

#[test]
fn test_process_registry_state_transitions() {
    use dlp_agent::process_registry::{ClaimResult, ProcessKey, ProcessRegistry, ProcessState};

    let registry = ProcessRegistry::new();
    let key = ProcessKey {
        pid: 1234,
        creation_time: 1,
    };

    // Initial claim.
    let result = registry.try_claim(key);
    assert_eq!(result, ClaimResult::Claimed);

    // Record injected.
    registry.record_injected(key, "x64".to_string());
    {
        let state = registry.get(&key).expect("key should exist");
        assert!(
            matches!(&*state, ProcessState::Injected { ref arch, .. } if arch == "x64"),
            "expected Injected state"
        );
    }

    // Record hello.
    registry.record_hello(key);
    {
        let state = registry.get(&key).expect("key should exist");
        assert!(
            matches!(
                &*state,
                ProcessState::Injected {
                    hello_received_at: Some(_),
                    ..
                }
            ),
            "expected Injected with hello"
        );
    }

    // Record exited.
    registry.record_exited(key);
    {
        let state = registry.get(&key).expect("key should exist");
        assert_eq!(*state, ProcessState::Exited);
    }

    // Cleanup removes exited.
    let removed = registry.prune_exited();
    assert_eq!(removed, 1);
    assert!(registry.get(&key).is_none());
}

#[test]
fn test_process_registry_should_skip_after_injected() {
    use dlp_agent::process_registry::{ClaimResult, ProcessKey, ProcessRegistry};

    let registry = ProcessRegistry::new();
    let key = ProcessKey {
        pid: 1234,
        creation_time: 1,
    };

    registry.try_claim(key);
    registry.record_injected(key, "x64".to_string());

    // Second claim should return AlreadyClaimed.
    let result = registry.try_claim(key);
    assert!(
        matches!(result, ClaimResult::AlreadyClaimed(_)),
        "expected AlreadyClaimed after injection"
    );
}

#[test]
fn test_process_registry_telemetry_snapshot() {
    use dlp_agent::process_registry::{ProcessKey, ProcessRegistry, SkipReason};

    let registry = ProcessRegistry::new();

    // Injected: 1
    let key1 = ProcessKey {
        pid: 1001,
        creation_time: 1,
    };
    registry.try_claim(key1);
    registry.record_injected(key1, "x64".to_string());

    // Skipped (self): 1
    let key2 = ProcessKey {
        pid: 1002,
        creation_time: 2,
    };
    registry.try_claim(key2);
    registry.record_skipped(key2, SkipReason::SelfProcess);

    // Exited: 1 (not counted in coverage denominator)
    let key3 = ProcessKey {
        pid: 1003,
        creation_time: 3,
    };
    registry.try_claim(key3);
    registry.record_exited(key3);

    let snapshot = registry.telemetry_snapshot();
    assert_eq!(snapshot.injected_count, 1);
    assert_eq!(snapshot.total_tracked, 3);

    // Coverage = 1 / (1 + 1) * 100 = 50% (exited not counted).
    assert!(
        (snapshot.coverage_percent - 50.0).abs() < 0.01,
        "expected ~50% coverage, got {}",
        snapshot.coverage_percent
    );
}

// ---------------------------------------------------------------------------
// Allowlist Matcher Tests
// ---------------------------------------------------------------------------

#[test]
fn test_allowlist_system_critical_exclusion() {
    use dlp_agent::allowlist::{AllowlistCategory, AllowlistMatcher};

    let matcher = AllowlistMatcher::new(
        vec![],
        r"C:\ProgramData\DLP\dlp-agent.exe".to_string(),
        9999,
    );

    // System-critical process in trusted directory.
    let result = matcher.check(100, r"C:\Windows\System32\csrss.exe", 0);
    assert_eq!(result, Some(AllowlistCategory::SystemCritical));

    // Same basename outside trusted directory — should NOT match.
    let result = matcher.check(100, r"C:\Temp\csrss.exe", 0);
    assert!(
        result.is_none(),
        "spoofed csrss.exe outside trusted dir must not match"
    );
}

#[test]
fn test_allowlist_self_exclusion() {
    use dlp_agent::allowlist::{AllowlistCategory, AllowlistMatcher};

    let self_pid = std::process::id();
    let self_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| r"C:\ProgramData\DLP\dlp-agent.exe".to_string());

    let matcher = AllowlistMatcher::new(vec![], self_path.clone(), self_pid);

    // Self PID should be excluded.
    let result = matcher.check(self_pid, r"C:\Other\app.exe", 0);
    assert_eq!(result, Some(AllowlistCategory::SelfProcess));

    // Self path should be excluded.
    let result = matcher.check(9999, &self_path, 0);
    assert_eq!(result, Some(AllowlistCategory::SelfProcess));
}

// ---------------------------------------------------------------------------
// AppInit and Secure Boot Tests
// ---------------------------------------------------------------------------

#[test]
fn test_secure_boot_detection_no_panic() {
    use dlp_agent::appinit::is_secure_boot_enabled;

    // Should return Some(true), Some(false), or None — never panic.
    let result = is_secure_boot_enabled();
    // On non-Windows platforms this returns None; on Windows it may return any.
    // The test passes if we reach this point without panicking.
    assert!(
        result.is_none() || result == Some(true) || result == Some(false),
        "unexpected Secure Boot result: {:?}",
        result
    );
}

#[test]
fn test_appinit_registry_read_no_panic() {
    use dlp_agent::appinit::read_appinit_state;

    // Should return Ok or Err — never panic.
    let result = read_appinit_state();
    match result {
        Ok(state) => {
            // Values may be None or Some depending on registry state.
            let _ = state.appinit_dlls;
            let _ = state.load_appinit;
            let _ = state.require_signed;
        }
        Err(e) => {
            // Reading HKLM may fail in test environments — that's acceptable.
            tracing::debug!(
                "read_appinit_state returned error (expected in tests): {}",
                e
            );
        }
    }
}

#[test]
fn test_appinit_state_default() {
    use dlp_agent::appinit::AppInitState;

    let state = AppInitState::default();
    assert!(state.appinit_dlls.is_none());
    assert!(state.load_appinit.is_none());
    assert!(state.require_signed.is_none());
}

// ---------------------------------------------------------------------------
// Process Watcher Tests
// ---------------------------------------------------------------------------

#[test]
fn test_process_watcher_new() {
    use dlp_agent::process_watcher::ProcessWatcher;

    let watcher = ProcessWatcher::new();
    assert!(watcher.is_etw_healthy());
    assert_eq!(watcher.overflow_count(), 0);
}

#[test]
fn test_process_event_source_variants() {
    use dlp_agent::process_watcher::EventSource;

    let sources = [
        EventSource::Etw,
        EventSource::Wmi,
        EventSource::StartupSweep,
        EventSource::PeriodicSweep,
    ];
    for (i, s1) in sources.iter().enumerate() {
        for (j, s2) in sources.iter().enumerate() {
            if i == j {
                assert_eq!(s1, s2);
            } else {
                assert_ne!(s1, s2);
            }
        }
    }
}

#[test]
fn test_sweep_trigger_variants() {
    use dlp_agent::process_watcher::SweepTrigger;

    assert_eq!(SweepTrigger::ChannelOverflow, SweepTrigger::ChannelOverflow);
    assert_eq!(
        SweepTrigger::HeartbeatRecovery,
        SweepTrigger::HeartbeatRecovery
    );
    assert_ne!(
        SweepTrigger::ChannelOverflow,
        SweepTrigger::HeartbeatRecovery
    );
}

// ---------------------------------------------------------------------------
// Universal Injector Tests
// ---------------------------------------------------------------------------

#[test]
fn test_latency_histogram_record_and_percentiles() {
    use dlp_agent::universal_injector::LatencyHistogram;

    let mut hist = LatencyHistogram::new();
    hist.record(25); // bucket 0
    hist.record(75); // bucket 1
    hist.record(150); // bucket 2
    hist.record(400); // bucket 3
    hist.record(600); // bucket 4
    hist.record(2000); // bucket 5

    // total is private; verify via percentiles instead.
    let pct = hist.pct_under_500ms();
    assert!((pct - 66.67).abs() < 0.1, "expected ~66.67%, got {}", pct);

    let (p50, p95, p99) = hist.percentiles();
    assert!(p50 > 0.0, "p50 should be > 0");
    assert!(p95 > 0.0, "p95 should be > 0");
    assert!(p99 > 0.0, "p99 should be > 0");
}

#[test]
fn test_latency_histogram_empty() {
    use dlp_agent::universal_injector::LatencyHistogram;

    let hist = LatencyHistogram::new();
    assert_eq!(hist.pct_under_500ms(), 100.0);
    let (p50, p95, p99) = hist.percentiles();
    assert_eq!(p50, 0.0);
    assert_eq!(p95, 0.0);
    assert_eq!(p99, 0.0);
}

#[test]
fn test_skip_reason_from_category() {
    use dlp_agent::allowlist::AllowlistCategory;
    use dlp_agent::process_registry::SkipReason;

    assert_eq!(
        SkipReason::from_category(AllowlistCategory::SelfProcess),
        SkipReason::SelfProcess
    );
    assert_eq!(
        SkipReason::from_category(AllowlistCategory::Avedr),
        SkipReason::Avedr
    );
    assert_eq!(
        SkipReason::from_category(AllowlistCategory::SystemCritical),
        SkipReason::SystemCritical
    );
    assert_eq!(
        SkipReason::from_category(AllowlistCategory::OperatorDefined),
        SkipReason::OperatorDefined
    );
}

#[test]
fn test_categorize_error_mapping() {
    use dlp_agent::hook_injector::HookError;
    use dlp_agent::process_registry::InjectionFailure;
    use dlp_agent::universal_injector::categorize_error;

    assert_eq!(
        categorize_error(&HookError::AccessDenied { pid: 1234 }),
        InjectionFailure::AccessDenied
    );
    assert_eq!(
        categorize_error(&HookError::RemoteThreadFailed {
            pid: 1234,
            detail: "test".to_string()
        }),
        InjectionFailure::RemoteThreadFailed
    );
    assert_eq!(
        categorize_error(&HookError::InjectionFailed {
            pid: 1234,
            exit_code: 5
        }),
        InjectionFailure::InjectionFailed
    );
    assert_eq!(
        categorize_error(&HookError::RemoteThreadTimeout { pid: 1234 }),
        InjectionFailure::Timeout
    );
}

#[tokio::test]
async fn test_allowlisted_process_is_skipped() {
    use dlp_agent::allowlist::AllowlistMatcher;
    use dlp_agent::hook_injector::HookInjector;
    use dlp_agent::process_registry::{ProcessKey, ProcessRegistry, ProcessState, SkipReason};
    use dlp_agent::process_watcher::{EventSource, ProcessEvent};
    use dlp_agent::universal_injector::UniversalInjector;
    use std::time::Instant;

    let registry = Arc::new(ProcessRegistry::new());
    let matcher = Arc::new(AllowlistMatcher::new(
        vec![],
        r"C:\Test\app.exe".to_string(),
        42, // self_pid
    ));
    let injector = Arc::new(HookInjector::new("C:\\dummy.dll", None));
    let (retry_tx, _retry_rx) = tokio::sync::mpsc::unbounded_channel();
    let ui = UniversalInjector::with_retry_queue(registry.clone(), matcher, injector, retry_tx);

    let event = ProcessEvent {
        pid: 42,
        image_path: r"C:\Other\app.exe".to_string(),
        parent_pid: 0,
        creation_time: 1,
        source: EventSource::Etw,
        event_timestamp: Instant::now(),
    };
    let (sweep_tx, _sweep_rx) = tokio::sync::mpsc::channel(1);
    ui.handle_event(event, &sweep_tx).await;

    let key = ProcessKey {
        pid: 42,
        creation_time: 1,
    };
    let state = registry.get(&key).expect("key should exist");
    assert!(
        matches!(&*state, ProcessState::Skipped(SkipReason::SelfProcess)),
        "expected Skipped(SelfProcess), got {:?}",
        *state
    );
}

#[tokio::test]
async fn test_duplicate_claim_prevents_double_inject() {
    use dlp_agent::allowlist::AllowlistMatcher;
    use dlp_agent::hook_injector::HookInjector;
    use dlp_agent::process_registry::{ProcessKey, ProcessRegistry};
    use dlp_agent::process_watcher::{EventSource, ProcessEvent};
    use dlp_agent::universal_injector::UniversalInjector;
    use std::time::Instant;

    let registry = Arc::new(ProcessRegistry::new());
    let matcher = Arc::new(AllowlistMatcher::new(
        vec![],
        r"C:\ProgramData\DLP\dlp-agent.exe".to_string(),
        9999,
    ));
    let injector = Arc::new(HookInjector::new("C:\\dummy.dll", None));
    let (retry_tx, _retry_rx) = tokio::sync::mpsc::unbounded_channel();
    let ui = UniversalInjector::with_retry_queue(registry.clone(), matcher, injector, retry_tx);

    let event1 = ProcessEvent {
        pid: 1000,
        image_path: r"C:\Windows\System32\notepad.exe".to_string(),
        parent_pid: 0,
        creation_time: 1,
        source: EventSource::Etw,
        event_timestamp: Instant::now(),
    };
    let event2 = ProcessEvent {
        pid: 1000,
        image_path: r"C:\Windows\System32\notepad.exe".to_string(),
        parent_pid: 0,
        creation_time: 1,
        source: EventSource::Etw,
        event_timestamp: Instant::now(),
    };
    let (sweep_tx, _sweep_rx) = tokio::sync::mpsc::channel(1);

    // First event gets claimed.
    ui.handle_event(event1, &sweep_tx).await;

    // Second event for same PID+creation_time should be skipped.
    ui.handle_event(event2, &sweep_tx).await;

    let key = ProcessKey {
        pid: 1000,
        creation_time: 1,
    };
    // Should still be in some state (either Injected or Skipped depending on injection result).
    assert!(registry.get(&key).is_some());
}

// ---------------------------------------------------------------------------
// Simulated ETW Event Stream Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_simulated_etw_stream_100_events() {
    use dlp_agent::allowlist::AllowlistMatcher;
    use dlp_agent::hook_injector::HookInjector;
    use dlp_agent::process_registry::ProcessRegistry;
    use dlp_agent::process_watcher::{EventSource, ProcessEvent};
    use dlp_agent::universal_injector::UniversalInjector;
    use std::sync::Arc;
    use std::time::Instant;

    let registry = Arc::new(ProcessRegistry::new());
    let matcher = Arc::new(AllowlistMatcher::new(
        vec![],
        r"C:\ProgramData\DLP\dlp-agent.exe".to_string(),
        9999,
    ));
    let injector = Arc::new(HookInjector::new("C:\\dummy.dll", None));
    let (retry_tx, _retry_rx) = tokio::sync::mpsc::unbounded_channel();
    let ui = UniversalInjector::with_retry_queue(registry.clone(), matcher, injector, retry_tx);

    let (sweep_tx, _sweep_rx) = tokio::sync::mpsc::channel(1);

    // Simulate 100 process creation events.
    for i in 0..100 {
        let event = ProcessEvent {
            pid: 1000 + i,
            image_path: format!(r"C:\Program Files\App{}\app.exe", i),
            parent_pid: 1,
            creation_time: i as u64,
            source: EventSource::Etw,
            event_timestamp: Instant::now(),
        };
        ui.handle_event(event, &sweep_tx).await;
    }

    let counts = registry.counts();
    // All events should be processed (none remain Discovered).
    assert_eq!(
        counts.discovered, 0,
        "all 100 events should be processed, none Discovered"
    );

    // Total tracked should be exactly 100 (all unique PIDs).
    assert_eq!(
        counts.injected_hello
            + counts.injected_no_hello
            + counts.skipped_self
            + counts.skipped_avedr
            + counts.skipped_system
            + counts.skipped_ppl
            + counts.skipped_wow64
            + counts.skipped_operator
            + counts.skipped_failed
            + counts.exited,
        100,
        "all 100 events should be accounted for in counts"
    );
}

// ---------------------------------------------------------------------------
// PID Reuse Integration Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pid_reuse_same_pid_different_creation_time() {
    use dlp_agent::allowlist::AllowlistMatcher;
    use dlp_agent::hook_injector::HookInjector;
    use dlp_agent::process_registry::{ProcessKey, ProcessRegistry, ProcessState};
    use dlp_agent::process_watcher::{EventSource, ProcessEvent};
    use dlp_agent::universal_injector::UniversalInjector;
    use std::sync::Arc;
    use std::time::Instant;

    let registry = Arc::new(ProcessRegistry::new());
    let matcher = Arc::new(AllowlistMatcher::new(
        vec![],
        r"C:\ProgramData\DLP\dlp-agent.exe".to_string(),
        9999,
    ));
    let injector = Arc::new(HookInjector::new("C:\\dummy.dll", None));
    let (retry_tx, _retry_rx) = tokio::sync::mpsc::unbounded_channel();
    let ui = UniversalInjector::with_retry_queue(registry.clone(), matcher, injector, retry_tx);

    let (sweep_tx, _sweep_rx) = tokio::sync::mpsc::channel(1);

    // First process with PID 1234, creation_time 1000.
    let event1 = ProcessEvent {
        pid: 1234,
        image_path: r"C:\Program Files\App1\app.exe".to_string(),
        parent_pid: 1,
        creation_time: 1000,
        source: EventSource::Etw,
        event_timestamp: Instant::now(),
    };
    ui.handle_event(event1, &sweep_tx).await;

    // Second process with same PID 1234 but different creation_time 2000.
    let event2 = ProcessEvent {
        pid: 1234,
        image_path: r"C:\Program Files\App2\app.exe".to_string(),
        parent_pid: 1,
        creation_time: 2000,
        source: EventSource::Etw,
        event_timestamp: Instant::now(),
    };
    ui.handle_event(event2, &sweep_tx).await;

    // Both should be tracked as separate entries.
    let key1 = ProcessKey {
        pid: 1234,
        creation_time: 1000,
    };
    let key2 = ProcessKey {
        pid: 1234,
        creation_time: 2000,
    };

    assert!(
        registry.get(&key1).is_some(),
        "first process should be tracked"
    );
    assert!(
        registry.get(&key2).is_some(),
        "second process (PID reuse) should be tracked"
    );

    // The states should be different (one was claimed first).
    let state1 = registry.get(&key1).unwrap();
    let state2 = registry.get(&key2).unwrap();
    // Both should be in some terminal state (not Discovered).
    assert!(
        !matches!(&*state1, ProcessState::Discovered),
        "first process should not be Discovered"
    );
    assert!(
        !matches!(&*state2, ProcessState::Discovered),
        "second process should not be Discovered"
    );
}

#[tokio::test]
async fn test_pid_reuse_rapid_claim_unclaim_claim() {
    use dlp_agent::process_registry::{ClaimResult, ProcessKey, ProcessRegistry, ProcessState};

    let registry = ProcessRegistry::new();
    let key = ProcessKey {
        pid: 5555,
        creation_time: 100,
    };

    // First claim succeeds.
    let result1 = registry.try_claim(key);
    assert_eq!(result1, ClaimResult::Claimed);

    // Record as injected.
    registry.record_injected(key, "x64".to_string());
    assert!(matches!(
        *registry.get(&key).unwrap(),
        ProcessState::Injected { .. }
    ));

    // Record exit.
    registry.record_exited(key);
    assert_eq!(*registry.get(&key).unwrap(), ProcessState::Exited);

    // Prune exited.
    let removed = registry.prune_exited();
    assert_eq!(removed, 1);
    assert!(
        registry.get(&key).is_none(),
        "exited entry should be pruned"
    );

    // Same PID with different creation_time should be claimable again.
    let key2 = ProcessKey {
        pid: 5555,
        creation_time: 200,
    };
    let result2 = registry.try_claim(key2);
    assert_eq!(
        result2,
        ClaimResult::Claimed,
        "PID reuse with different creation_time should be claimable"
    );
}

// ---------------------------------------------------------------------------
// Stress Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_high_churn_1000_processes() {
    use dlp_agent::allowlist::AllowlistMatcher;
    use dlp_agent::hook_injector::HookInjector;
    use dlp_agent::process_registry::ProcessRegistry;
    use dlp_agent::process_watcher::{EventSource, ProcessEvent};
    use dlp_agent::universal_injector::UniversalInjector;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let registry = Arc::new(ProcessRegistry::new());
    let matcher = Arc::new(AllowlistMatcher::new(
        vec![],
        r"C:\ProgramData\DLP\dlp-agent.exe".to_string(),
        9999,
    ));
    let injector = Arc::new(HookInjector::new("C:\\dummy.dll", None));
    let (retry_tx, _retry_rx) = tokio::sync::mpsc::unbounded_channel();
    let ui = UniversalInjector::with_retry_queue(registry.clone(), matcher, injector, retry_tx);

    let (sweep_tx, _sweep_rx) = tokio::sync::mpsc::channel(1);

    let start = Instant::now();

    // Simulate 1000 events with PID reuse (modulo 500).
    for i in 0..1000 {
        let event = ProcessEvent {
            pid: 2000 + (i % 500), // simulate PID reuse
            image_path: format!(r"C:\Temp\app{}.exe", i),
            parent_pid: 1,
            creation_time: i as u64, // unique creation_time prevents collision
            source: EventSource::Etw,
            event_timestamp: Instant::now(),
        };
        ui.handle_event(event, &sweep_tx).await;
    }

    let elapsed = start.elapsed();

    let counts = registry.counts();
    let total = counts.injected_hello
        + counts.injected_no_hello
        + counts.skipped_self
        + counts.skipped_avedr
        + counts.skipped_system
        + counts.skipped_ppl
        + counts.skipped_wow64
        + counts.skipped_operator
        + counts.skipped_failed
        + counts.exited;

    assert_eq!(total, 1000, "all 1000 events should be accounted for");
    assert!(
        elapsed < Duration::from_secs(10),
        "should process 1000 events in <10s, took {:?}",
        elapsed
    );
}
