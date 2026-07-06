//! Integration test: ISOLATED -> RESYNC -> HEALTHY recovery cycle.
//!
//! Exercises the real agent-side `ClassificationCache` writer and hook-DLL-side
//! `CacheLookup` reader together, driving the full fail-mode state machine
//! recovery cycle end-to-end.
//!
//! # Test Architecture
//!
//! 1. Create a real `ClassificationCache` via `dlp-agent` (dev-dependency).
//! 2. Map it read-only via hook-dll's `CacheLookup::from_raw_pointer()`.
//! 3. Drive `FailModeState` into ISOLATED with simulated pipe failures.
//! 4. Start the hook-dll background thread with the mapped header.
//! 5. Publish a new cache version via `ClassificationCache::rebuild()`.
//! 6. Assert the background thread detects the fresh version and triggers
//!    ISOLATED -> RESYNC within 2000ms.
//! 7. Assert 5 consecutive `record_pipe_success` calls transition RESYNC -> HEALTHY.
//!
//! # Serialization
//!
//! All tests use a static `Mutex` to serialize mapping creation/destruction,
//! since all tests share the same mapping name. Tests run with `--test-threads=1`
//! to prevent collisions.
//!
//! # Non-Windows
//!
//! All tests gracefully skip on non-Windows platforms via early return.

use std::sync::{Arc, Mutex};

use dlp_agent::classification_cache::ClassificationCache;
use dlp_common::hook_ipc::HookOp;
use dlp_common::Classification;
use dlp_hook_dll::lru;
use dlp_hook_dll::CacheHeader;
use dlp_hook_dll::CacheLookup;
use dlp_hook_dll::{decide_isolated, is_cache_stale, FailModeState, FailState};
use dlp_hook_dll::{
    reset_background_thread_for_test, shutdown_background_thread, start_background_thread,
};

/// Test-specific shared-memory mapping name.
/// Uses Local\ prefix (not Global\) to avoid requiring administrator privileges.
const TEST_CACHE_NAME: &str = "Local\\DlpClassificationCache_TestPhase50_1";

/// Global mutex for serializing tests that create/destroy the shared mapping.
static TEST_SERIALIZER: Mutex<()> = Mutex::new(());

/// Test setup helper: create a ClassificationCache, populate it, and return
/// the cache instance, header pointer, and mapping handle.
///
/// The cache instance must be kept alive for the test lifetime.
fn create_test_cache(
    entries: Vec<(String, Classification, u32)>,
) -> (
    ClassificationCache,
    *const CacheHeader,
    windows::Win32::Foundation::HANDLE,
) {
    let cache =
        ClassificationCache::new_with_name(TEST_CACHE_NAME).expect("failed to create test cache");
    cache
        .rebuild(entries)
        .expect("failed to rebuild test cache");

    let header_ptr = cache.header_for_test();
    let handle = cache.mapping_handle_for_test();

    (cache, header_ptr, handle)
}

/// Verify FAIL-01: Background thread detects fresh version and transitions
/// ISOLATED -> RESYNC within 2000ms.
///
/// This is the core recovery test: when the agent publishes a new cache
/// version after being unreachable, the hook DLL's background thread must
/// detect it and trigger automatic recovery.
#[test]
#[serial_test::serial]
fn isolated_to_resync_via_background_thread() {
    #[cfg(not(windows))]
    {
        eprintln!("Skipping Windows-only integration test on non-Windows platform");
        return;
    }

    let _guard = TEST_SERIALIZER.lock().unwrap();

    // Arrange: Create cache with a T4 path. Drive state to ISOLATED.
    let entries = vec![(r"C:\Sensitive\".to_string(), Classification::T4, 3600)];
    let (cache, header_ptr, handle) = create_test_cache(entries);
    let fail_state = Arc::new(FailModeState::new());

    for _ in 0..10 {
        fail_state.record_pipe_failure();
    }
    assert_eq!(fail_state.current_state(), FailState::Isolated);

    // Reset background thread to ensure clean state.
    reset_background_thread_for_test();

    // Create CacheLookup from raw pointer.
    let lookup = unsafe {
        CacheLookup::from_raw_pointer(header_ptr, handle, true)
            .expect("failed to create CacheLookup from raw pointer")
    };
    let _lookup = lookup; // Keep alive for test lifetime.

    // Start background thread with the mapped header.
    start_background_thread(header_ptr, Arc::clone(&fail_state), None, None);

    // Act: Publish a new cache version via rebuild.
    let entries2 = vec![
        (r"C:\Sensitive\".to_string(), Classification::T4, 3600),
        (r"C:\Other\".to_string(), Classification::T3, 3600),
    ];
    let new_version = cache.rebuild(entries2).expect("rebuild failed");
    assert!(new_version > 0, "new version should be > 0");

    // Assert: Poll state with 2000ms timeout.
    // 2000ms accounts for 100ms polling interval + CI scheduling jitter.
    let start = std::time::Instant::now();
    let mut became_resync = false;
    while start.elapsed().as_millis() < 2000 {
        if fail_state.current_state() == FailState::Resync {
            became_resync = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        became_resync,
        "state should become RESYNC within 2000ms after fresh version published"
    );

    // Cleanup.
    shutdown_background_thread();
    reset_background_thread_for_test();
    drop(cache);
}

/// Verify FAIL-01: RESYNC -> HEALTHY after 5 consecutive successes.
///
/// Hysteresis requires 5 successes to exit RESYNC and return to HEALTHY.
#[test]
fn resync_to_healthy_hysteresis() {
    #[cfg(not(windows))]
    {
        eprintln!("Skipping Windows-only integration test on non-Windows platform");
        return;
    }

    let fail_state = FailModeState::new();

    // Enter Isolated.
    for _ in 0..10 {
        fail_state.record_pipe_failure();
    }
    assert_eq!(fail_state.current_state(), FailState::Isolated);

    // Set up for RESYNC: cache_version_seen_at = 1, success with version 2.
    fail_state.set_cache_version_seen_at(1);
    fail_state.record_pipe_success(2);
    assert_eq!(fail_state.current_state(), FailState::Resync);

    // 4 more successes (total 5) -> HEALTHY.
    for i in 0..4 {
        let state = fail_state.record_pipe_success(2);
        if i < 3 {
            assert_eq!(
                state,
                FailState::Resync,
                "should stay RESYNC at success {i}"
            );
        }
    }
    assert_eq!(
        fail_state.current_state(),
        FailState::Healthy,
        "should become HEALTHY after 5 total successes"
    );
}

/// Verify FAIL-01: Full cycle HEALTHY -> DEGRADED -> ISOLATED -> RESYNC -> HEALTHY.
#[test]
#[serial_test::serial]
fn full_cycle_end_to_end() {
    #[cfg(not(windows))]
    {
        eprintln!("Skipping Windows-only integration test on non-Windows platform");
        return;
    }

    let _guard = TEST_SERIALIZER.lock().unwrap();

    let entries = vec![(r"C:\Sensitive\".to_string(), Classification::T4, 3600)];
    let (cache, header_ptr, handle) = create_test_cache(entries);
    let fail_state = Arc::new(FailModeState::new());

    // 3 failures -> DEGRADED.
    for _ in 0..3 {
        fail_state.record_pipe_failure();
    }
    assert_eq!(fail_state.current_state(), FailState::Degraded);

    // 7 more failures -> ISOLATED.
    for _ in 0..7 {
        fail_state.record_pipe_failure();
    }
    assert_eq!(fail_state.current_state(), FailState::Isolated);

    // Reset and start background thread.
    reset_background_thread_for_test();
    let lookup = unsafe {
        CacheLookup::from_raw_pointer(header_ptr, handle, true)
            .expect("failed to create CacheLookup")
    };
    let _lookup = lookup;
    start_background_thread(header_ptr, Arc::clone(&fail_state), None, None);

    // Rebuild -> RESYNC.
    let entries2 = vec![(r"C:\Sensitive\".to_string(), Classification::T4, 3600)];
    cache.rebuild(entries2).expect("rebuild failed");

    let start = std::time::Instant::now();
    let mut became_resync = false;
    while start.elapsed().as_millis() < 2000 {
        if fail_state.current_state() == FailState::Resync {
            became_resync = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(became_resync, "should become RESYNC within 2000ms");

    // 5 successes -> HEALTHY.
    for _ in 0..5 {
        fail_state.record_pipe_success(999);
    }
    assert_eq!(fail_state.current_state(), FailState::Healthy);

    // Cleanup.
    shutdown_background_thread();
    reset_background_thread_for_test();
    drop(cache);
}

/// Verify cross-crate checksum alignment: agent-written header passes
/// hook-dll validation.
///
/// This test proves that after Task 1's ABI alignment, the agent's
/// compute_checksum and the hook-dll's compute_checksum produce identical
/// results for the same header content.
#[test]
#[serial_test::serial]
fn cross_crate_checksum_validation() {
    #[cfg(not(windows))]
    {
        eprintln!("Skipping Windows-only integration test on non-Windows platform");
        return;
    }

    let _guard = TEST_SERIALIZER.lock().unwrap();

    let entries = vec![(r"C:\Sensitive\".to_string(), Classification::T4, 3600)];
    let (cache, header_ptr, handle) = create_test_cache(entries);

    // Create CacheLookup with validate=true.
    let lookup = unsafe {
        CacheLookup::from_raw_pointer(header_ptr, handle, true)
            .expect("hook-dll checksum validation should pass on agent-written header")
    };
    let _lookup = lookup;

    drop(cache);
}

/// Verify FAIL-01 in-flight guarantee: decisions started before RESYNC
/// complete using the old cache snapshot.
///
/// The guarantee is about LRU version pinning, not shared-memory read
/// isolation (the mapping flips atomically).
#[test]
#[serial_test::serial]
fn in_flight_decision_uses_old_cache() {
    #[cfg(not(windows))]
    {
        eprintln!("Skipping Windows-only integration test on non-Windows platform");
        return;
    }

    let _guard = TEST_SERIALIZER.lock().unwrap();

    let entries = vec![(
        r"C:\Sensitive\file.txt".to_string(),
        Classification::T4,
        3600,
    )];
    let (cache, _header_ptr, _handle) = create_test_cache(entries);

    // Populate LRU with version 1 entry.
    lru::insert(r"C:\SENSITIVE\FILE.TXT", Classification::T4, 1);

    // Enter ISOLATED first, then transition to RESYNC.
    let fail_state = FailModeState::new();
    for _ in 0..10 {
        fail_state.record_pipe_failure();
    }
    assert_eq!(fail_state.current_state(), FailState::Isolated);

    // Now simulate RESYNC: version 1 was seen, now success with version 2.
    fail_state.set_cache_version_seen_at(1);
    fail_state.record_pipe_success(2);
    assert_eq!(fail_state.current_state(), FailState::Resync);

    // Old version lookup should still return the cached classification.
    assert_eq!(
        lru::get(r"C:\SENSITIVE\FILE.TXT", 1),
        Some(Classification::T4),
        "old version entry should still be in LRU during RESYNC"
    );

    // New version lookup should miss (not inserted yet).
    assert_eq!(
        lru::get(r"C:\SENSITIVE\FILE.TXT", 2),
        None,
        "new version entry should not exist until inserted"
    );

    drop(cache);
}

/// Verify FAIL-01 writer-in-progress guard: odd version_word during rebuild
/// is ignored by the background thread.
///
/// The background thread skips odd versions because they indicate the writer
/// is still building the inactive buffer.
#[test]
#[serial_test::serial]
fn odd_version_during_rebuild_ignored() {
    #[cfg(not(windows))]
    {
        eprintln!("Skipping Windows-only integration test on non-Windows platform");
        return;
    }

    let _guard = TEST_SERIALIZER.lock().unwrap();

    let entries = vec![(r"C:\Sensitive\".to_string(), Classification::T4, 3600)];
    let (cache, header_ptr, handle) = create_test_cache(entries);
    let fail_state = Arc::new(FailModeState::new());

    // Enter ISOLATED.
    for _ in 0..10 {
        fail_state.record_pipe_failure();
    }
    assert_eq!(fail_state.current_state(), FailState::Isolated);

    // Reset and start background thread.
    reset_background_thread_for_test();
    let lookup = unsafe {
        CacheLookup::from_raw_pointer(header_ptr, handle, false)
            .expect("failed to create CacheLookup")
    };
    let _lookup = lookup;
    start_background_thread(header_ptr, Arc::clone(&fail_state), None, None);

    // Set version_word to odd (simulating writer in progress).
    use std::sync::atomic::Ordering;
    unsafe {
        (*header_ptr)
            .version_word
            .store((3u64 << 1) | 1, Ordering::Release);
    }

    // Wait 200ms — state should still be ISOLATED (background thread skips odd).
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(
        fail_state.current_state(),
        FailState::Isolated,
        "background thread should skip odd version_word"
    );

    // Now publish a valid even version and verify recovery works.
    let entries2 = vec![(r"C:\Sensitive\".to_string(), Classification::T4, 3600)];
    cache.rebuild(entries2).expect("rebuild failed");

    let start = std::time::Instant::now();
    let mut became_resync = false;
    while start.elapsed().as_millis() < 2000 {
        if fail_state.current_state() == FailState::Resync {
            became_resync = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        became_resync,
        "should recover to RESYNC after even version published"
    );

    // Cleanup.
    shutdown_background_thread();
    reset_background_thread_for_test();
    drop(cache);
}

/// Verify FAIL-03 staleness budget: T4 cache older than 30s is stale.
///
/// This validates the `is_cache_stale` helper function. The full pipe-client-
/// driven staleness transition (where the pipe client checks staleness before
/// each operation and calls `record_pipe_failure`) is NOT tested here — it
/// requires production-code changes to the pipe client hot path and is deferred
/// to a follow-up phase.
#[test]
fn stale_cache_triggers_isolated_helper() {
    #[cfg(not(windows))]
    {
        eprintln!("Skipping Windows-only integration test on non-Windows platform");
        return;
    }

    let now_secs = 2000u64;
    let old_created_at = 1969u64; // 31 seconds ago

    // cache_version=5, header_version=6 (newer), age=31s > T4=30s budget.
    assert!(
        is_cache_stale(5, 6, old_created_at, now_secs, Classification::T4),
        "cache older than T4 budget (30s) should be stale"
    );

    // Within budget: not stale.
    let recent_created_at = 1975u64; // 25 seconds ago
    assert!(
        !is_cache_stale(5, 6, recent_created_at, now_secs, Classification::T4),
        "cache within T4 budget should not be stale"
    );
}

/// Verify FAIL-01 recovery robustness: pipe failure during RESYNC returns to ISOLATED.
#[test]
fn resync_pipe_failure_returns_isolated() {
    #[cfg(not(windows))]
    {
        eprintln!("Skipping Windows-only integration test on non-Windows platform");
        return;
    }

    let fail_state = FailModeState::new();

    // Enter Isolated.
    for _ in 0..10 {
        fail_state.record_pipe_failure();
    }
    assert_eq!(fail_state.current_state(), FailState::Isolated);

    // Enter Resync.
    fail_state.set_cache_version_seen_at(1);
    fail_state.record_pipe_success(2);
    assert_eq!(fail_state.current_state(), FailState::Resync);

    // Pipe failure -> ISOLATED (not Healthy).
    fail_state.record_pipe_failure();
    assert_eq!(
        fail_state.current_state(),
        FailState::Isolated,
        "any failure during RESYNC should abort recovery and return to ISOLATED"
    );
}

/// Verify FAIL-01 LRU flush guarantee: clear_all removes all old-version entries.
#[test]
fn lru_flush_on_resync() {
    #[cfg(not(windows))]
    {
        eprintln!("Skipping Windows-only integration test on non-Windows platform");
        return;
    }

    // Populate LRU with entries at version 1.
    lru::insert(r"C:\file1.txt", Classification::T4, 1);
    lru::insert(r"C:\file2.txt", Classification::T3, 1);

    assert_eq!(lru::get(r"C:\file1.txt", 1), Some(Classification::T4));
    assert_eq!(lru::get(r"C:\file2.txt", 1), Some(Classification::T3));

    // Flush.
    lru::clear_all();

    // All entries should be gone.
    assert_eq!(lru::get(r"C:\file1.txt", 1), None);
    assert_eq!(lru::get(r"C:\file2.txt", 1), None);
}

/// Verify FAIL-02 asymmetric tier-gated decisions in ISOLATED state.
///
/// - T3/T4 + Write -> deny (fail-closed for sensitive data)
/// - T3/T4 + Read -> allow
/// - T1/T2 (any op) -> allow (fail-open for non-sensitive)
/// - Unknown + Write -> deny
/// - Unknown + Read -> allow
#[test]
fn asymmetric_decisions_in_isolated() {
    #[cfg(not(windows))]
    {
        eprintln!("Skipping Windows-only integration test on non-Windows platform");
        return;
    }

    // T4 write -> deny.
    assert!(
        decide_isolated(Some(Classification::T4), HookOp::Write).is_some(),
        "T4 write should deny"
    );

    // T3 write -> deny.
    assert!(
        decide_isolated(Some(Classification::T3), HookOp::Write).is_some(),
        "T3 write should deny"
    );

    // T1 write -> allow.
    assert!(
        decide_isolated(Some(Classification::T1), HookOp::Write).is_none(),
        "T1 write should allow"
    );

    // Unknown write -> deny.
    assert!(
        decide_isolated(None, HookOp::Write).is_some(),
        "unknown write should deny"
    );

    // T4 read -> allow.
    assert!(
        decide_isolated(Some(Classification::T4), HookOp::Read).is_none(),
        "T4 read should allow"
    );
}
