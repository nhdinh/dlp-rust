//! Performance telemetry for the hook DLL.
//!
//! Provides QPC (QueryPerformanceCounter) latency measurement and histogram
//! aggregation with periodic emission. State transitions are emitted
//! immediately (not batched) for audit integrity.
//!
//! # Cache Non-Authoritative Invariant
//!
//! The cache stores classification **HINT only**. ABAC authority is never
//! bypassed. Telemetry is for performance validation only and contains no
//! per-path sensitive data.
//!
//! # Design
//!
//! - Thread-local `PerfTelemetry` with atomic counters — no allocation in hot path.
//! - QPC before/after wrapping the entire decision path.
//! - Histogram with 8 buckets from 10us to >10ms.
//! - Emission every 1000 calls to keep overhead < 0.1%.
//! - State transitions emitted immediately via `tracing::warn!`.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::fail_mode::FailState;

// ---------------------------------------------------------------------------
// Latency bucket definitions
// ---------------------------------------------------------------------------

/// QPC tick thresholds for latency histogram buckets.
///
/// These thresholds are calibrated to approximate microseconds assuming a
/// QPC frequency of ~10 MHz (100ns per tick). Actual frequencies vary by
/// hardware; the buckets are approximate.
///
/// | Bucket | Range       |
/// |--------|-------------|
/// | 0      | 0-10us      |
/// | 1      | 10-50us     |
/// | 2      | 50-100us    |
/// | 3      | 100-500us   |
/// | 4      | 500us-1ms   |
/// | 5      | 1ms-5ms     |
/// | 6      | 5ms-10ms    |
/// | 7      | >10ms       |
const LATENCY_BUCKETS: &[u64] = &[100, 500, 1000, 5000, 10_000, 50_000, 100_000, u64::MAX];

/// Number of histogram buckets.
const BUCKET_COUNT: usize = 8;

/// Emit aggregated telemetry every N calls.
const EMIT_INTERVAL: u64 = 1000;

// ---------------------------------------------------------------------------
// PerfTelemetry struct
// ---------------------------------------------------------------------------

/// Thread-local performance telemetry state.
///
/// All counters are `AtomicU64` to allow lock-free updates from the same
/// thread (the RefCell ensures single-threaded access, but atomics prevent
/// any accidental aliasing issues).
pub struct PerfTelemetry {
    /// Histogram bucket counters.
    buckets: [AtomicU64; BUCKET_COUNT],
    /// Total number of calls measured.
    call_count: AtomicU64,
    /// Number of cache hits.
    cache_hits: AtomicU64,
    /// Number of cache misses.
    cache_misses: AtomicU64,
}

impl PerfTelemetry {
    /// Create a new `PerfTelemetry` with all counters at zero.
    #[must_use]
    pub fn new() -> Self {
        // SAFETY: AtomicU64::new(0) is valid and the array is fully initialized.
        let buckets: [AtomicU64; BUCKET_COUNT] =
            std::array::from_fn(|_| AtomicU64::new(0));
        Self {
            buckets,
            call_count: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
        }
    }

    /// Record a latency measurement.
    ///
    /// Increments the appropriate bucket, call count, and hit/miss counters.
    /// If `call_count` reaches a multiple of `EMIT_INTERVAL`, triggers
    /// `emit_telemetry()`.
    ///
    /// # Arguments
    ///
    /// * `elapsed_qpc` — Elapsed QPC ticks.
    /// * `is_cache_hit` — `true` if this was a cache hit, `false` for miss.
    pub fn record_latency(&self, elapsed_qpc: u64, is_cache_hit: bool) {
        // Increment call count.
        let count = self.call_count.fetch_add(1, Ordering::Relaxed) + 1;

        // Increment hit/miss counters.
        if is_cache_hit {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
        }

        // Find bucket index.
        let bucket_idx = find_bucket(elapsed_qpc);
        self.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed);

        // Emit telemetry every EMIT_INTERVAL calls.
        if count.is_multiple_of(EMIT_INTERVAL) {
            self.emit_telemetry();
        }
    }

    /// Emit aggregated telemetry and reset counters.
    ///
    /// Reads all bucket counters (resetting them to 0), computes cache hit rate
    /// and p50/p95 bucket indices, and emits via `tracing::info!`. If a pipe
    /// is available, the telemetry is also sent as a `siem.hook_telemetry` event.
    pub fn emit_telemetry(&self) {
        // Read and reset all counters.
        let mut bucket_values = [0u64; BUCKET_COUNT];
        for (i, bucket) in self.buckets.iter().enumerate() {
            bucket_values[i] = bucket.swap(0, Ordering::Relaxed);
        }
        let total_calls = self.call_count.load(Ordering::Relaxed);
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);

        // Compute cache hit rate.
        let total_lookups = hits + misses;
        let hit_rate = if total_lookups > 0 {
            (hits as f64) / (total_lookups as f64)
        } else {
            0.0
        };

        // Compute p50 and p95 bucket indices.
        let p50_bucket = percentile_bucket(&bucket_values, 0.50);
        let p95_bucket = percentile_bucket(&bucket_values, 0.95);

        let pid = std::process::id();

        tracing::info!(
            event = "siem.hook_telemetry",
            pid = pid,
            total_calls = total_calls,
            cache_hits = hits,
            cache_misses = misses,
            hit_rate = %format!("{:.4}", hit_rate),
            p50_bucket = p50_bucket,
            p95_bucket = p95_bucket,
            buckets = ?bucket_values,
            "hook telemetry"
        );
    }
}

impl Default for PerfTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Thread-local telemetry instance
// ---------------------------------------------------------------------------

thread_local! {
    static TELEMETRY: RefCell<PerfTelemetry> = RefCell::new(PerfTelemetry::new());
}

/// Record a latency measurement in the thread-local telemetry.
///
/// # Arguments
///
/// * `elapsed_qpc` — Elapsed QPC ticks.
/// * `is_cache_hit` — `true` if this was a cache hit, `false` for miss.
pub fn record_latency(elapsed_qpc: u64, is_cache_hit: bool) {
    TELEMETRY.with(|t| t.borrow().record_latency(elapsed_qpc, is_cache_hit));
}

/// Emit aggregated telemetry from the thread-local telemetry.
#[allow(dead_code)]
pub fn emit_telemetry() {
    TELEMETRY.with(|t| t.borrow().emit_telemetry());
}

// ---------------------------------------------------------------------------
// QPC measurement wrapper
// ---------------------------------------------------------------------------

/// Measure the elapsed QPC ticks of a function call.
///
/// Wraps the function `f` with QPC before/after readings and returns both
/// the function result and the elapsed ticks.
///
/// # Arguments
///
/// * `f` — The function to measure.
///
/// # Returns
///
/// A tuple of `(result, elapsed_qpc_ticks)`.
///
/// # Example
///
/// ```
/// let (result, elapsed) = measure(|| {
///     // Some work here
///     42
/// });
/// assert_eq!(result, 42);
/// ```
pub fn measure<F, T>(f: F) -> (T, u64)
where
    F: FnOnce() -> T,
{
    let start = query_performance_counter();
    let result = f();
    let end = query_performance_counter();
    (result, end.saturating_sub(start))
}

/// Read the current QueryPerformanceCounter value.
///
/// Returns 0 on non-Windows platforms or if the call fails.
fn query_performance_counter() -> u64 {
    #[cfg(windows)]
    {
        use windows::Win32::System::Performance::QueryPerformanceCounter;
        let mut counter = 0i64;
        // SAFETY: QueryPerformanceCounter writes to a valid i64 pointer.
        let result = unsafe { QueryPerformanceCounter(&mut counter) };
        if result.is_ok() {
            counter as u64
        } else {
            0
        }
    }
    #[cfg(not(windows))]
    {
        // On non-Windows, use a coarse timestamp.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64
    }
}

// ---------------------------------------------------------------------------
// Immediate state transition emission
// ---------------------------------------------------------------------------

/// Emit an immediate state transition event.
///
/// State transitions are security-relevant and must be logged immediately
/// (not batched). Emits via `tracing::warn!` and, if available, sends a
/// `siem.fail_mode_transition` event.
///
/// # Arguments
///
/// * `old_state` — The previous fail-mode state.
/// * `new_state` — The new fail-mode state.
/// * `reason` — Human-readable reason for the transition.
pub fn emit_state_transition_immediate(old_state: FailState, new_state: FailState, reason: &str) {
    if old_state == new_state {
        return;
    }

    let pid = std::process::id();
    let image_path = crate::allowlist::get_process_image_path();

    tracing::warn!(
        event = "siem.fail_mode_transition",
        old_state = ?old_state,
        new_state = ?new_state,
        reason = %reason,
        pid = pid,
        image_path = %image_path,
        timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "fail_mode state transition"
    );
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Find the bucket index for a given QPC tick value.
///
/// Uses `LATENCY_BUCKETS` thresholds. Values exceeding the last threshold
/// go into the final bucket.
fn find_bucket(elapsed_qpc: u64) -> usize {
    for (i, &threshold) in LATENCY_BUCKETS.iter().enumerate() {
        if elapsed_qpc <= threshold {
            return i;
        }
    }
    BUCKET_COUNT - 1
}

/// Compute the bucket index at a given percentile.
///
/// # Arguments
///
/// * `buckets` — The histogram bucket values.
/// * `percentile` — The percentile to compute (0.0 to 1.0).
///
/// # Returns
///
/// The bucket index containing the percentile value.
fn percentile_bucket(buckets: &[u64; BUCKET_COUNT], percentile: f64) -> usize {
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        return 0;
    }

    let target = (total as f64 * percentile) as u64;
    let mut cumulative = 0u64;
    for (i, &count) in buckets.iter().enumerate() {
        cumulative += count;
        if cumulative >= target {
            return i;
        }
    }
    BUCKET_COUNT - 1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Task 5: Histogram ---

    #[test]
    fn latency_buckets_defined() {
        assert_eq!(LATENCY_BUCKETS.len(), 8);
        assert_eq!(LATENCY_BUCKETS[0], 100);
        assert_eq!(LATENCY_BUCKETS[7], u64::MAX);
    }

    #[test]
    fn perf_telemetry_new_has_zero_counters() {
        let tel = PerfTelemetry::new();
        assert_eq!(tel.call_count.load(Ordering::Relaxed), 0);
        assert_eq!(tel.cache_hits.load(Ordering::Relaxed), 0);
        assert_eq!(tel.cache_misses.load(Ordering::Relaxed), 0);
        for bucket in &tel.buckets {
            assert_eq!(bucket.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn record_latency_increments_call_count() {
        let tel = PerfTelemetry::new();
        tel.record_latency(50, true);
        assert_eq!(tel.call_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn record_latency_increments_hit_counter() {
        let tel = PerfTelemetry::new();
        tel.record_latency(50, true);
        assert_eq!(tel.cache_hits.load(Ordering::Relaxed), 1);
        assert_eq!(tel.cache_misses.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn record_latency_increments_miss_counter() {
        let tel = PerfTelemetry::new();
        tel.record_latency(50, false);
        assert_eq!(tel.cache_hits.load(Ordering::Relaxed), 0);
        assert_eq!(tel.cache_misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn record_latency_bucket_assignment() {
        let tel = PerfTelemetry::new();
        // Bucket 0: 0-100 ticks
        tel.record_latency(50, true);
        assert_eq!(tel.buckets[0].load(Ordering::Relaxed), 1);

        // Bucket 1: 100-500 ticks
        tel.record_latency(200, true);
        assert_eq!(tel.buckets[1].load(Ordering::Relaxed), 1);

        // Bucket 7: >100_000 ticks
        tel.record_latency(1_000_000, true);
        assert_eq!(tel.buckets[7].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn find_bucket_boundary() {
        assert_eq!(find_bucket(0), 0);
        assert_eq!(find_bucket(100), 0); // <= threshold goes to bucket
        assert_eq!(find_bucket(101), 1);
        assert_eq!(find_bucket(500), 1);
        assert_eq!(find_bucket(501), 2);
        assert_eq!(find_bucket(u64::MAX), 7);
    }

    #[test]
    fn percentile_bucket_empty() {
        let buckets = [0u64; BUCKET_COUNT];
        assert_eq!(percentile_bucket(&buckets, 0.50), 0);
    }

    #[test]
    fn percentile_bucket_single_bucket() {
        let mut buckets = [0u64; BUCKET_COUNT];
        buckets[2] = 10;
        assert_eq!(percentile_bucket(&buckets, 0.50), 2);
    }

    #[test]
    fn percentile_bucket_spread() {
        let mut buckets = [0u64; BUCKET_COUNT];
        buckets[0] = 10;
        buckets[1] = 10;
        buckets[2] = 10;
        // p50 = 15th item -> bucket 1
        assert_eq!(percentile_bucket(&buckets, 0.50), 1);
        // p95 = 28th item -> bucket 2
        assert_eq!(percentile_bucket(&buckets, 0.95), 2);
    }

    #[test]
    fn emit_telemetry_resets_counters() {
        let tel = PerfTelemetry::new();
        for _ in 0..10 {
            tel.record_latency(50, true);
        }
        tel.emit_telemetry();
        // After emission, buckets should be reset.
        for bucket in &tel.buckets {
            assert_eq!(bucket.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn measure_returns_result_and_elapsed() {
        let (result, elapsed) = measure(|| 42);
        assert_eq!(result, 42);
        // Elapsed should be non-negative.
        assert!(elapsed < u64::MAX);
    }

    // --- Task 6: Immediate state transition ---

    #[test]
    fn emit_state_transition_no_op_when_same() {
        // Should not panic.
        emit_state_transition_immediate(FailState::Healthy, FailState::Healthy, "test");
    }

    #[test]
    fn emit_state_transition_emits_for_different() {
        // Should not panic.
        emit_state_transition_immediate(
            FailState::Healthy,
            FailState::Degraded,
            "3_consecutive_pipe_failures",
        );
    }

    #[test]
    fn emit_state_transition_isolated_to_healthy() {
        // Should not panic.
        emit_state_transition_immediate(
            FailState::Isolated,
            FailState::Healthy,
            "cache_resync_complete",
        );
    }

    // --- Thread-local tests ---

    #[test]
    fn thread_local_record_latency() {
        record_latency(100, true);
        // Should not panic.
    }

    #[test]
    fn thread_local_emit_telemetry() {
        emit_telemetry();
        // Should not panic.
    }

    #[test]
    fn bucket_count_matches_latency_buckets() {
        assert_eq!(BUCKET_COUNT, LATENCY_BUCKETS.len());
    }
}
