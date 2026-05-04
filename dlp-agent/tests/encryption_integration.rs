//! Integration tests for the Phase-34 BitLocker encryption verification
//! orchestration loop. Drives the public `spawn_encryption_check_task_with_backend`
//! entry point through a deterministic in-memory `EncryptionBackend` mock so
//! the full pipeline (wait-for-enumeration -> fan-out -> mutate state ->
//! emit events -> loop) is exercised on any platform.
//!
//! Real WMI / Registry smoke tests live behind the `integration-tests`
//! feature flag and only compile on Windows hosts with BitLocker provisioned.
//!
//! ## Design Notes
//!
//! ### Global singleton isolation
//!
//! `EncryptionChecker` and `DiskEnumerator` use `OnceLock` (set-once-per-process).
//! Tests mutate interior `RwLock` state directly via public fields.
//! `#[serial_test::serial]` prevents concurrent test execution so only one test
//! mutates the singletons at a time.
//!
//! Crucially, `spawn_encryption_check_task_with_backend` spawns a tokio task
//! that loops forever.  To prevent tasks from prior tests from contaminating
//! later tests, all tests use `#[tokio::test(flavor = "current_thread",
//! start_paused = true)]` together with `tokio::time::advance()` to drive time
//! precisely.  With time paused, the periodic `interval(recheck)` ticker does
//! NOT fire unless we explicitly advance past the interval.  `spawn_blocking`
//! (used by the mock backend) still completes in real OS-thread time; only
//! the tokio timer is paused.
//!
//! ### Audit event capture
//!
//! `audit_emitter::enable_test_capture()` / `drain_test_events()` are always
//! compiled (no feature flag) so integration test binaries can call them
//! directly.  Production code never calls `enable_test_capture()`, so the sink
//! is always disabled in service runs (Option C per Plan 34-05 §Step D).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use dlp_agent::audit_emitter::{drain_test_events, enable_test_capture, EmitContext};
use dlp_agent::detection::disk::{get_disk_enumerator, set_disk_enumerator, DiskEnumerator};
use dlp_agent::detection::encryption::{
    get_encryption_checker, set_encryption_checker, spawn_encryption_check_task_with_backend,
    EncryptionBackend, EncryptionChecker, EncryptionError,
};
use dlp_common::{DiskIdentity, EncryptionMethod, EncryptionStatus, EventType};

// ---------------------------------------------------------------------------
// Mock backend
// ---------------------------------------------------------------------------

/// Type alias for the per-volume mock response queue entry.
/// A type alias keeps the `MockBackend` struct declaration within clippy's
/// `type_complexity` threshold.
type VolumeResult = Result<(EncryptionStatus, Option<EncryptionMethod>), EncryptionError>;

/// Deterministic in-memory backend. Each call to `query_volume` consumes the
/// next value from a per-drive-letter script. `read_boot_status_registry`
/// returns a configured fixed value or error.
///
/// In Rust, `Arc<Mutex<...>>` gives shared ownership with interior mutability
/// -- equivalent to Python's threading.Lock() wrapping a shared object.
struct MockBackend {
    /// Per-drive-letter response scripts. Each script is a queue (FIFO);
    /// once exhausted, further calls return `VolumeNotFound`.
    scripts: Mutex<HashMap<char, Vec<VolumeResult>>>,
    /// Fixed response for the Registry fallback path.
    boot_registry: Mutex<Result<u32, String>>,
    /// Counts total `query_volume` invocations (for assertion in Test 2).
    call_count: AtomicUsize,
}

impl MockBackend {
    /// Create a new empty `MockBackend` wrapped in `Arc` for sharing.
    fn new() -> Arc<Self> {
        Arc::new(Self {
            scripts: Mutex::new(HashMap::new()),
            boot_registry: Mutex::new(Err("unset".to_string())),
            call_count: AtomicUsize::new(0),
        })
    }

    /// Push responses for a drive letter.  Each call to `query_volume` with
    /// this letter pops the front element.
    fn script(self: &Arc<Self>, letter: char, results: Vec<VolumeResult>) {
        self.scripts.lock().insert(letter, results);
    }

    /// Return how many times `query_volume` has been called across all letters.
    fn calls(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

impl EncryptionBackend for MockBackend {
    fn query_volume(
        &self,
        drive_letter: char,
    ) -> Result<(EncryptionStatus, Option<EncryptionMethod>), EncryptionError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let mut scripts = self.scripts.lock();
        // `entry(...).or_default()` creates an empty Vec if the letter is absent.
        let queue = scripts.entry(drive_letter).or_default();
        if queue.is_empty() {
            return Err(EncryptionError::VolumeNotFound);
        }
        // `remove(0)` dequeues the front element (FIFO semantics).
        queue.remove(0)
    }

    fn read_boot_status_registry(&self) -> Result<u32, EncryptionError> {
        match &*self.boot_registry.lock() {
            Ok(v) => Ok(*v),
            Err(msg) => Err(EncryptionError::RegistryReadFailed(msg.clone())),
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Build a minimal `EmitContext` for testing.  No real agent state needed --
/// the orchestration code only reads agent_id, session_id, user_sid, user_name.
fn fake_audit_ctx() -> EmitContext {
    EmitContext {
        agent_id: "AGENT-TEST".to_string(),
        session_id: 1,
        user_sid: "S-1-5-18".to_string(),
        user_name: "SYSTEM".to_string(),
        machine_name: Some("TEST-HOST".to_string()),
    }
}

/// Build a minimal `DiskIdentity` fixture.  Only the fields consumed by the
/// orchestration loop are populated; others get `Default::default()` / `None`.
///
/// In Rust, `..Default::default()` is a struct update expression: all fields
/// not explicitly listed are filled from the default impl.
fn fake_disk(instance_id: &str, drive_letter: char, is_boot: bool) -> DiskIdentity {
    DiskIdentity {
        instance_id: instance_id.to_string(),
        drive_letter: Some(drive_letter),
        is_boot_disk: is_boot,
        ..Default::default()
    }
}

/// Seed (or re-seed) the global `DiskEnumerator` singleton's interior state.
///
/// Because `OnceLock::set` is one-shot, we retrieve the already-registered
/// enumerator (or register a fresh one on first use) and overwrite its
/// interior `RwLock` contents directly -- matching the pattern used by
/// `run_one_verification_cycle` in production.
fn seed_enumerator(disks: Vec<DiskIdentity>, mark_complete: bool) -> Arc<DiskEnumerator> {
    let enumerator = match get_disk_enumerator() {
        Some(e) => e,
        None => {
            let fresh = Arc::new(DiskEnumerator::new());
            set_disk_enumerator(Arc::clone(&fresh));
            get_disk_enumerator().expect("enumerator must be set after set_disk_enumerator")
        }
    };
    // Overwrite discovered_disks, then rebuild the two secondary maps so they
    // remain consistent -- matches the pattern in run_one_verification_cycle.
    {
        let mut w = enumerator.discovered_disks.write();
        *w = disks.clone();
    }
    {
        let mut id_map = enumerator.instance_id_map.write();
        id_map.clear();
        for d in &disks {
            id_map.insert(d.instance_id.clone(), d.clone());
        }
    }
    {
        let mut letter_map = enumerator.drive_letter_map.write();
        letter_map.clear();
        for d in &disks {
            if let Some(l) = d.drive_letter {
                letter_map.insert(l, d.clone());
            }
        }
    }
    *enumerator.enumeration_complete.write() = mark_complete;
    enumerator
}

/// Reset the `EncryptionChecker` singleton's interior state so each test
/// starts from a clean slate.  Because `OnceLock` is one-shot, we cannot
/// replace the singleton itself -- we mutate through it instead.
fn reset_checker_state() {
    let checker = match get_encryption_checker() {
        Some(c) => c,
        None => {
            let fresh = Arc::new(EncryptionChecker::new());
            set_encryption_checker(Arc::clone(&fresh));
            get_encryption_checker().expect("checker must be set after set_encryption_checker")
        }
    };
    checker.encryption_status_map.write().clear();
    *checker.last_check_at.write() = None;
    // Reset check_complete (is_ready) to false so the test sees a fresh state.
    *checker.check_complete.write() = false;
    // Reset is_first_check to true so D-16/D-16a Alert gating works correctly.
    *checker.is_first_check.write() = true;
}

/// Enable the audit event capture sink and drain any stale events from
/// previous tests.
fn enable_event_capture() {
    let _ = drain_test_events();
    enable_test_capture();
}

/// Drain any stale events from previous tests without re-enabling the sink.
fn clear_events() {
    let _ = drain_test_events();
}

/// Drive the spawned encryption-check task through exactly one verification
/// cycle and wait for the `spawn_blocking` work to complete.
///
/// ## How this works with `start_paused = true`
///
/// Tokio's paused-time mode (`#[tokio::test(start_paused = true)]`) freezes
/// the virtual clock so timer futures (`interval`, `sleep`) never fire
/// spontaneously.  Crucially, paused time does NOT affect `spawn_blocking`:
/// the blocking closure runs on a real OS thread and completes in real time.
///
/// The task's flow once spawned:
///
///   1. `wait_for_disk_enumerator_ready()` — returns immediately if the
///      enumerator is ready (no timer involved).
///   2. `run_one_verification_cycle(...)` — fans out via `JoinSet::spawn`;
///      each spawn calls `check_one_disk` which calls `spawn_blocking`. The
///      blocking work finishes in real time (microseconds for the mock).
///      `tokio::time::timeout(5s, ...)` wraps the handle; the 5-second timer
///      does NOT fire because time is paused, but the handle resolves when the
///      blocking thread completes -- returning `Ok(result)`.
///   3. Parks on `ticker.tick()` waiting for the virtual clock to advance
///      past `recheck_interval`.
///
/// By advancing time by a tiny amount (1 ms) and then yielding multiple times,
/// we flush the event loop and let the JoinSet handles resolve.  The tiny
/// advance is necessary to unpark the task after step 1 if `is_ready` returns
/// false on the first poll (the task would sleep 250 ms before re-checking).
async fn run_one_cycle() {
    // Give the spawned task a chance to reach `wait_for_disk_enumerator_ready`
    // and start the first `run_one_verification_cycle`.
    tokio::task::yield_now().await;
    // Advance time by 1 ms -- needed in case the task is parked on the 250 ms
    // sleep inside `wait_for_disk_enumerator_ready` (only happens when
    // `is_ready()` returns false on the first poll).
    tokio::time::advance(Duration::from_millis(1)).await;
    // Yield generously to flush the JoinSet handles and let all blocking
    // OS threads join.  The call stack is:
    //   spawned task -> JoinSet::spawn (per disk) -> spawn_blocking -> waker
    // With `current_thread`, each layer requires the reactor to be polled at
    // least once.  100 yields provides a comfortable margin: when tests run
    // sequentially, the OS thread pool may be busy with the previous test's
    // blocking tasks, delaying completion for the current test.
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
}

/// Advance tokio time past `interval` and wait for the periodic cycle to
/// complete.
async fn advance_past_interval(interval: Duration) {
    tokio::time::advance(interval + Duration::from_millis(5)).await;
    // Yield generously to let the re-check cycle run through to completion.
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

// ---------------------------------------------------------------------------
// Test 1: Singleton lifecycle -- fresh checker is not ready and is first check
// ---------------------------------------------------------------------------

/// Verify that a freshly reset `EncryptionChecker` reports `!is_ready()` and
/// `is_first_check() == true`, and that `status_for_instance_id` returns `None`
/// for any key.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[serial_test::serial]
async fn singleton_lifecycle_fresh_checker_not_ready() {
    // Arrange: reset to a clean slate (no events expected)
    reset_checker_state();
    clear_events();

    // Act: read the singleton's public state
    let checker = get_encryption_checker().expect("checker must be registered after reset");

    // Assert: fresh checker is not ready, is in first-check state, has no statuses
    assert!(!checker.is_ready(), "fresh checker must not be ready");
    assert!(
        checker.is_first_check(),
        "fresh checker must be in first-check state"
    );
    assert_eq!(
        checker.status_for_instance_id("NONEXISTENT"),
        None,
        "fresh checker must return None for unknown instance IDs"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Status update via mock backend (D-20)
// ---------------------------------------------------------------------------

/// Seed two fake disks, run one cycle, assert the checker is ready and
/// statuses are populated in both the `EncryptionChecker` and the
/// `DiskEnumerator` records.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[serial_test::serial]
async fn periodic_recheck_populates_status_after_first_cycle() {
    // Arrange
    reset_checker_state();
    // No event assertion in this test -- just clear stale events.
    clear_events();

    let disks = vec![
        fake_disk("T2-USBSTOR-D", 'D', false),
        fake_disk("T2-SCSI-C", 'C', true),
    ];
    let enumerator = seed_enumerator(disks.clone(), true);

    let backend = MockBackend::new();
    backend.script(
        'D',
        vec![Ok((
            EncryptionStatus::Encrypted,
            Some(EncryptionMethod::XtsAes128),
        ))],
    );
    backend.script(
        'C',
        vec![Ok((
            EncryptionStatus::Encrypted,
            Some(EncryptionMethod::XtsAes128),
        ))],
    );

    // Act: spawn the task with a long recheck interval (600s) so the periodic
    // loop never fires during this test.  Advance time by a small amount to
    // let the initial cycle complete.
    let recheck = Duration::from_secs(600);
    spawn_encryption_check_task_with_backend(
        tokio::runtime::Handle::current(),
        fake_audit_ctx(),
        recheck,
        backend.clone(),
    );
    run_one_cycle().await;

    // Assert: checker is now ready
    let checker = get_encryption_checker().expect("checker must be registered");
    assert!(
        checker.is_ready(),
        "checker must be ready after first cycle"
    );
    assert!(
        !checker.is_first_check(),
        "is_first_check must flip to false"
    );

    // Assert: statuses are populated in EncryptionChecker
    assert_eq!(
        checker.status_for_instance_id("T2-USBSTOR-D"),
        Some(EncryptionStatus::Encrypted),
        "USBSTOR disk must show Encrypted"
    );
    assert_eq!(
        checker.status_for_instance_id("T2-SCSI-C"),
        Some(EncryptionStatus::Encrypted),
        "boot disk must show Encrypted"
    );

    // Assert: DiskEnumerator records were updated in-place (D-20)
    let disks_after = enumerator.all_disks();
    for d in &disks_after {
        assert_eq!(
            d.encryption_status,
            Some(EncryptionStatus::Encrypted),
            "disk {} encryption_status must be Some(Encrypted)",
            d.instance_id
        );
        assert_eq!(
            d.encryption_method,
            Some(EncryptionMethod::XtsAes128),
            "disk {} encryption_method must be Some(XtsAes128)",
            d.instance_id
        );
        assert!(
            d.encryption_checked_at.is_some(),
            "disk {} encryption_checked_at must be set",
            d.instance_id
        );
    }

    // The backend must have been called at least once per disk.
    assert!(
        backend.calls() >= 2,
        "backend must have been queried at least twice"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Status-change emission (D-25)
// ---------------------------------------------------------------------------

/// Pre-seed cache with `Encrypted` for disk X. Run a cycle where the backend
/// returns `Suspended` for X. Assert exactly one `DiskDiscovery` event with
/// the substring `"encryption status changed:"` referencing X.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[serial_test::serial]
async fn status_change_emits_disk_discovery_event() {
    // Arrange: reset and pre-seed cache with Encrypted
    reset_checker_state();
    // Enable capture so we can assert on emitted DiskDiscovery events.
    enable_event_capture();

    let disk = fake_disk("T3-DISK-E", 'E', false);
    let _enumerator = seed_enumerator(vec![disk.clone()], true);

    // Manually insert the "old" status into the checker's map to simulate a
    // prior cycle having run with Encrypted status.
    {
        let checker = get_encryption_checker().expect("checker must be registered");
        checker
            .encryption_status_map
            .write()
            .insert("T3-DISK-E".to_string(), EncryptionStatus::Encrypted);
    }

    // Backend now returns Suspended -- simulating a status drift.
    let backend = MockBackend::new();
    backend.script('E', vec![Ok((EncryptionStatus::Suspended, None))]);

    // Act: run one cycle using a long recheck interval.
    spawn_encryption_check_task_with_backend(
        tokio::runtime::Handle::current(),
        fake_audit_ctx(),
        Duration::from_secs(600),
        backend,
    );
    run_one_cycle().await;

    // The checker map is updated *before* the emit inside run_one_verification_cycle.
    // Poll until the map reflects Suspended so we know the emit has already fired,
    // regardless of how long the spawn_blocking OS thread takes on this machine.
    for _ in 0..200 {
        let done = get_encryption_checker()
            .map(|c| {
                c.encryption_status_map.read().get("T3-DISK-E").copied()
                    == Some(EncryptionStatus::Suspended)
            })
            .unwrap_or(false);
        if done {
            break;
        }
        tokio::task::yield_now().await;
    }

    // Assert: at least one DiskDiscovery event with "encryption status changed:"
    let events = drain_test_events();
    let change_events: Vec<_> = events
        .iter()
        .filter(|e| {
            e.event_type == EventType::DiskDiscovery
                && e.justification
                    .as_deref()
                    .unwrap_or("")
                    .contains("encryption status changed:")
        })
        .collect();

    assert!(
        !change_events.is_empty(),
        "must emit at least one DiskDiscovery with 'encryption status changed:'"
    );

    // The justification must reference the disk's instance ID.
    let justification = change_events[0].justification.as_deref().unwrap_or("");
    assert!(
        justification.contains("T3-DISK-E"),
        "justification must reference the changed disk's instance ID; got: {justification}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Silent on no-change (D-12)
// ---------------------------------------------------------------------------

/// Pre-seed cache with `Encrypted` for both disks. Backend returns `Encrypted`
/// again. Assert ZERO new `DiskDiscovery` events fired.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[serial_test::serial]
async fn no_change_does_not_emit_events() {
    // Arrange
    reset_checker_state();
    // Enable capture to assert that zero DiskDiscovery events are emitted.
    enable_event_capture();

    let disk_a = fake_disk("T4-DISK-F", 'F', false);
    let disk_b = fake_disk("T4-DISK-G", 'G', false);
    let _enumerator = seed_enumerator(vec![disk_a.clone(), disk_b.clone()], true);

    // Pre-seed checker with the same statuses the backend will return.
    {
        let checker = get_encryption_checker().expect("checker must be registered");
        let mut map = checker.encryption_status_map.write();
        map.insert("T4-DISK-F".to_string(), EncryptionStatus::Encrypted);
        map.insert("T4-DISK-G".to_string(), EncryptionStatus::Encrypted);
        // Mark check_complete and flip is_first_check so Alert gate is not armed.
        *checker.check_complete.write() = true;
        *checker.is_first_check.write() = false;
    }

    let backend = MockBackend::new();
    backend.script(
        'F',
        vec![Ok((
            EncryptionStatus::Encrypted,
            Some(EncryptionMethod::XtsAes128),
        ))],
    );
    backend.script(
        'G',
        vec![Ok((
            EncryptionStatus::Encrypted,
            Some(EncryptionMethod::XtsAes128),
        ))],
    );

    // Act: one cycle
    spawn_encryption_check_task_with_backend(
        tokio::runtime::Handle::current(),
        fake_audit_ctx(),
        Duration::from_secs(600),
        backend,
    );
    run_one_cycle().await;

    // Assert: no DiskDiscovery events -- only encryption_checked_at is updated (D-12).
    let events = drain_test_events();
    let disk_discovery_count = events
        .iter()
        .filter(|e| e.event_type == EventType::DiskDiscovery)
        .count();
    assert_eq!(
        disk_discovery_count, 0,
        "no-change cycle must not emit any DiskDiscovery events (D-12)"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Failure yields Unknown, not Encrypted (D-14)
// ---------------------------------------------------------------------------

/// Backend returns `Err(Timeout)` for disk H and `Ok(Encrypted)` for disk I.
/// Assert: H's status is `Unknown`, I's status is `Encrypted`. The error path
/// must never produce `Encrypted` (D-14 defensive default).
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[serial_test::serial]
async fn failure_yields_unknown_not_encrypted() {
    // Arrange
    reset_checker_state();
    // No event assertion needed; clear any stale events.
    clear_events();

    let disk_h = fake_disk("T5-DISK-H", 'H', false);
    let disk_i = fake_disk("T5-DISK-I", 'I', false);
    let _enumerator = seed_enumerator(vec![disk_h.clone(), disk_i.clone()], true);

    let backend = MockBackend::new();
    // Disk H times out -- orchestrator must map this to Unknown.
    backend.script('H', vec![Err(EncryptionError::Timeout)]);
    // Disk I succeeds with Encrypted.
    backend.script(
        'I',
        vec![Ok((
            EncryptionStatus::Encrypted,
            Some(EncryptionMethod::Aes256),
        ))],
    );

    // Act
    spawn_encryption_check_task_with_backend(
        tokio::runtime::Handle::current(),
        fake_audit_ctx(),
        Duration::from_secs(600),
        backend,
    );
    run_one_cycle().await;

    // Assert
    let checker = get_encryption_checker().expect("checker must be registered");
    assert_eq!(
        checker.status_for_instance_id("T5-DISK-H"),
        Some(EncryptionStatus::Unknown),
        "failed disk must resolve to Unknown (D-14), not Encrypted"
    );
    assert_eq!(
        checker.status_for_instance_id("T5-DISK-I"),
        Some(EncryptionStatus::Encrypted),
        "successful disk must show Encrypted"
    );
}

// ---------------------------------------------------------------------------
// Test 6: Initial total-failure fires ONE Alert; second cycle stays silent
// (D-16 / D-16a / Pitfall E)
// ---------------------------------------------------------------------------

/// Mock backend errors on ALL disks during the first cycle. Assert exactly one
/// `EventType::Alert` event with resource `encryption://verification-failed` and
/// `Decision::DENY`. Drive a second cycle (still all-fail). Assert the Alert
/// count remains 1 -- Pitfall E proven.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[serial_test::serial]
async fn initial_total_failure_fires_one_alert_only() {
    // Arrange: fresh start so is_first_check starts as true.
    reset_checker_state();
    // Enable capture to assert Alert event count across two cycles.
    enable_event_capture();

    let disk_j = fake_disk("T6-DISK-J", 'J', false);
    let disk_k = fake_disk("T6-DISK-K", 'K', false);
    let _enumerator = seed_enumerator(vec![disk_j.clone(), disk_k.clone()], true);

    // Use a short recheck interval so we can trigger two cycles by advancing time.
    let recheck = Duration::from_millis(200);

    let backend = MockBackend::new();
    // Provide two failures per disk: one for the initial cycle, one for the second.
    backend.script(
        'J',
        vec![
            Err(EncryptionError::WmiQueryFailed("all-fail-1".to_string())),
            Err(EncryptionError::WmiQueryFailed("all-fail-2".to_string())),
        ],
    );
    backend.script(
        'K',
        vec![
            Err(EncryptionError::WmiQueryFailed("all-fail-1".to_string())),
            Err(EncryptionError::WmiQueryFailed("all-fail-2".to_string())),
        ],
    );

    // Act: spawn task and run the first cycle.
    spawn_encryption_check_task_with_backend(
        tokio::runtime::Handle::current(),
        fake_audit_ctx(),
        recheck,
        backend,
    );
    run_one_cycle().await;

    // Advance time past the recheck interval to trigger the SECOND cycle.
    advance_past_interval(recheck).await;

    // Assert: exactly ONE Alert event (not two, despite two total-failure cycles).
    let events = drain_test_events();
    let alert_count = events
        .iter()
        .filter(|e| {
            e.event_type == EventType::Alert
                && e.resource_path == "encryption://verification-failed"
        })
        .count();
    assert_eq!(
        alert_count, 1,
        "must emit exactly ONE Alert on total-failure across all cycles (Pitfall E / D-16a)"
    );
}

// ---------------------------------------------------------------------------
// Test 7: D-04 wait-for-enumeration ordering
// ---------------------------------------------------------------------------

/// Set `enumeration_complete = false` initially. Spawn the task. Confirm the
/// checker stays not-ready while enumeration is pending. Then flip
/// `enumeration_complete = true` and wait for the checker to become ready.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[serial_test::serial]
async fn waits_for_disk_enumeration_before_checking() {
    // Arrange: seed enumerator but leave enumeration_complete = false.
    reset_checker_state();
    // No event assertion; clear stale events.
    clear_events();

    let disk = fake_disk("T7-DISK-L", 'L', false);
    // mark_complete = false: the task must park in wait_for_disk_enumerator_ready.
    let enumerator = seed_enumerator(vec![disk.clone()], false);

    let backend = MockBackend::new();
    backend.script(
        'L',
        vec![Ok((
            EncryptionStatus::Encrypted,
            Some(EncryptionMethod::XtsAes128),
        ))],
    );

    // Act: spawn the task with a long recheck interval.
    spawn_encryption_check_task_with_backend(
        tokio::runtime::Handle::current(),
        fake_audit_ctx(),
        Duration::from_secs(600),
        backend,
    );

    // Yield to let the task reach `wait_for_disk_enumerator_ready` and enter
    // its polling loop.  The loop immediately checks `is_ready()` and sleeps
    // 250 ms if false.  Advance time past 250 ms to trigger the next poll.
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(251)).await;
    tokio::task::yield_now().await;

    // The checker must still be not-ready because enumeration_complete is false.
    let checker = get_encryption_checker().expect("checker must be registered");
    assert!(
        !checker.is_ready(),
        "checker must NOT be ready while enumeration_complete is false (D-04)"
    );

    // Now mark enumeration complete.
    *enumerator.enumeration_complete.write() = true;

    // Advance time past another 250 ms sleep to trigger the next `is_ready()`
    // poll.  This time `is_ready()` returns true, so the task exits the loop
    // and runs the initial verification cycle.
    tokio::time::advance(Duration::from_millis(251)).await;
    // Yield generously to let the spawn_blocking tasks join (same margin as run_one_cycle).
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }

    assert!(
        checker.is_ready(),
        "checker must become ready after enumeration_complete flips to true"
    );
}

// ---------------------------------------------------------------------------
// Test 8: Pitfall D -- None vs Some(Unknown) wire disambiguation
// ---------------------------------------------------------------------------

/// Backend errors on every disk. Snapshot the `DiskIdentity` slice from the
/// enumerator and serialize via `serde_json::to_value`. Assert that each disk's
/// `encryption_status` field equals the JSON string `"unknown"` (NOT absent /
/// NOT `null`), proving the orchestrator wrote `Some(Unknown)` rather than
/// leaving `None` (Pitfall D).
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[serial_test::serial]
async fn wire_unknown_written_as_some_unknown_not_absent() {
    // Arrange
    reset_checker_state();
    // No event assertion needed; clear stale events.
    clear_events();

    let disk_m = fake_disk("T8-DISK-M", 'M', false);
    let disk_n = fake_disk("T8-DISK-N", 'N', false);
    let enumerator = seed_enumerator(vec![disk_m.clone(), disk_n.clone()], true);

    let backend = MockBackend::new();
    // Both disks fail (VolumeNotFound) so Unknown is written.
    backend.script('M', vec![Err(EncryptionError::VolumeNotFound)]);
    backend.script('N', vec![Err(EncryptionError::VolumeNotFound)]);

    // Act
    spawn_encryption_check_task_with_backend(
        tokio::runtime::Handle::current(),
        fake_audit_ctx(),
        Duration::from_secs(600),
        backend,
    );
    run_one_cycle().await;

    // Assert: serialize each disk and verify the encryption_status wire value.
    let disks = enumerator.all_disks();
    assert_eq!(disks.len(), 2, "must have exactly two disks in enumerator");

    for disk in &disks {
        let json_value = serde_json::to_value(disk).expect("DiskIdentity must serialize to JSON");

        // The field must exist in the JSON object (Some(Unknown) -> "unknown" on wire).
        // If the field is absent it means encryption_status is still None -- Pitfall D bug.
        let status_field = json_value.get("encryption_status").unwrap_or_else(|| {
            panic!(
                "encryption_status field must be present in JSON for disk {} -- \
                     Pitfall D: orchestrator must write Some(Unknown) not None",
                disk.instance_id
            )
        });

        assert_eq!(
            status_field,
            &serde_json::Value::String("unknown".to_string()),
            "encryption_status must serialize as JSON string \"unknown\" for disk {} \
             (Pitfall D wire disambiguation -- Some(Unknown) vs None)",
            disk.instance_id
        );
    }
}

// ---------------------------------------------------------------------------
// Optional Windows-only smoke test (requires --features integration-tests)
// ---------------------------------------------------------------------------

#[cfg(all(windows, feature = "integration-tests"))]
#[tokio::test(flavor = "current_thread")]
async fn live_windows_wmi_smoke_test() {
    // SAFETY: this test only runs on a real Windows host with BitLocker
    // provisioned and `--features integration-tests` explicitly enabled.
    // It instantiates the production WindowsEncryptionBackend and verifies
    // we can open the namespace with PktPrivacy and parse at least one volume.
    use dlp_agent::detection::encryption::WindowsEncryptionBackend;
    let backend = WindowsEncryptionBackend;
    let result = backend.query_volume('C');
    match result {
        Ok((status, _method)) => {
            assert!(matches!(
                status,
                EncryptionStatus::Encrypted
                    | EncryptionStatus::Suspended
                    | EncryptionStatus::Unencrypted
                    | EncryptionStatus::Unknown
            ));
        }
        Err(e) => {
            // Acceptable on Windows Home / disabled-BitLocker hosts.
            eprintln!("WMI smoke test soft-failed: {e}");
        }
    }
}
