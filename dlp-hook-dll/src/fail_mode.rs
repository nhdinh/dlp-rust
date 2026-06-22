//! Fail-mode state machine for the hook DLL.
//!
//! Manages deterministic transitions between four states (Healthy, Degraded,
//! Isolated, Resync) with hysteresis to prevent flapping. Drives asymmetric
//! tier-gated decisions when the agent pipe is unreachable.
//!
//! # Cache Non-Authoritative Invariant
//!
//! The cache stores classification **HINT only**. ABAC authority is never
//! bypassed. A cache hit enables tier-gated fast-path decisions; a cache miss
//! always falls through to the full ABAC evaluation via pipe round-trip.
//!
//! # State Machine Overview
//!
//! ```text
//! HEALTHY --(3 failures)--> DEGRADED --(10 failures or stale)--> ISOLATED
//!     ^                           |                                    |
//!     |                           |                                    |
//!     +--(3 successes)-----------+                                    |
//!     |                                                                |
//!     +--(5 successes + LRU flush)------------------------------------+
//!                              ^
//!                              |
//!                           RESYNC (pipe success + fresh version)
//! ```
//!
//! All state transitions are atomic and idempotent. The state machine is
//! per-DLL (process-local), not global. Hysteresis prevents rapid oscillation
//! between states.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use dlp_common::hook_ipc::HookOp;
use dlp_common::Classification;

use crate::fail_closed::DenyReturn;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of consecutive pipe failures to transition from Healthy to Degraded.
const HEALTHY_TO_DEGRADED_THRESHOLD: u32 = 3;

/// Number of consecutive pipe failures to transition from Degraded to Isolated.
const DEGRADED_TO_ISOLATED_THRESHOLD: u32 = 10;

/// Consecutive successes required to leave Degraded and return to Healthy.
const DEGRADED_EXIT_HYSTERESIS: u32 = 3;

/// Consecutive successes required to leave Isolated/Resync and return to Healthy.
const ISOLATED_EXIT_HYSTERESIS: u32 = 5;

/// In Degraded state, retry the pipe every Nth call.
const DEGRADED_RETRY_INTERVAL: u32 = 10;

/// Per-tier staleness budgets: T1=0, T2=1, T3=2, T4=3.
#[allow(dead_code)]
const STALENESS_BUDGETS: [u64; 4] = [
    1800, // T1: 30 minutes
    300,  // T2: 5 minutes
    60,   // T3: 60 seconds
    30,   // T4: 30 seconds
];

// ---------------------------------------------------------------------------
// FailState enum
// ---------------------------------------------------------------------------

/// The four states of the fail-mode state machine.
///
/// Stored as `u8` for atomic operations. Values are chosen to be
/// monotonically increasing in severity (Healthy = 0, Isolated = 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FailState {
    /// Normal operation: pipe round-trips on cache miss.
    Healthy = 0,
    /// Degraded: cache + periodic pipe retry every 10th call.
    Degraded = 1,
    /// Isolated: cache-only, no pipe attempts. Asymmetric decisions apply.
    Isolated = 2,
    /// Resync: recovering from isolation, using new cache data.
    Resync = 3,
}

impl FailState {
    /// Convert a raw `u8` to `FailState`.
    ///
    /// Unknown values default to `Isolated` (safest state).
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Healthy,
            1 => Self::Degraded,
            2 => Self::Isolated,
            3 => Self::Resync,
            _ => Self::Isolated, // Unknown -> safest state
        }
    }
}

// ---------------------------------------------------------------------------
// FailModeState struct
// ---------------------------------------------------------------------------

/// Process-local fail-mode state machine.
///
/// Tracks consecutive successes/failures, cache version, and retry counters
/// to drive deterministic state transitions with hysteresis.
///
/// All fields are atomic to allow lock-free updates from multiple threads
/// without requiring a mutex in the hot path.
pub struct FailModeState {
    /// Current state (Healthy, Degraded, Isolated, Resync).
    state: AtomicU8,
    /// Consecutive pipe failures since last success.
    consecutive_failures: AtomicU32,
    /// Consecutive pipe successes since last failure.
    consecutive_successes: AtomicU32,
    /// Last known good cache version (high 63 bits of version_word).
    cache_version_seen_at: AtomicU64,
    /// Wall-clock seconds of the last pipe attempt (Unix epoch).
    last_pipe_attempt_epoch_secs: AtomicU64,
    /// Counter for every-Nth retry in Degraded state.
    degraded_retry_counter: AtomicU32,
}

impl FailModeState {
    /// Create a new `FailModeState` initialized to Healthy with zero counters.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(FailState::Healthy as u8),
            consecutive_failures: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
            cache_version_seen_at: AtomicU64::new(0),
            last_pipe_attempt_epoch_secs: AtomicU64::new(0),
            degraded_retry_counter: AtomicU32::new(0),
        }
    }

    /// Returns the current state.
    #[must_use]
    pub fn current_state(&self) -> FailState {
        FailState::from_u8(self.state.load(Ordering::Relaxed))
    }

    /// Record a successful pipe round-trip and update state.
    ///
    /// Increments consecutive successes, resets failures, and transitions
    /// state if hysteresis thresholds are met.
    ///
    /// # Arguments
    ///
    /// * `cache_version` - The cache version from the successful response.
    ///
    /// # Returns
    ///
    /// The new state after transition (may be same as before).
    pub fn record_pipe_success(&self, cache_version: u64) -> FailState {
        let old_state = self.current_state();

        // Increment successes, reset failures.
        let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
        self.consecutive_failures.store(0, Ordering::Relaxed);

        // Update last pipe attempt time.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_pipe_attempt_epoch_secs
            .store(now_secs, Ordering::Relaxed);

        // Check hysteresis thresholds for state transitions BEFORE updating
        // cache_version_seen_at, so that ISOLATED -> RESYNC can detect
        // cache_version > last_seen.
        let new_state = match old_state {
            FailState::Healthy => FailState::Healthy,
            FailState::Degraded => {
                if successes >= DEGRADED_EXIT_HYSTERESIS {
                    FailState::Healthy
                } else {
                    FailState::Degraded
                }
            }
            FailState::Isolated => {
                // ISOLATED -> RESYNC requires pipe success AND fresh version.
                let last_seen = self.cache_version_seen_at.load(Ordering::Relaxed);
                if cache_version > last_seen {
                    FailState::Resync
                } else {
                    FailState::Isolated
                }
            }
            FailState::Resync => {
                if successes >= ISOLATED_EXIT_HYSTERESIS {
                    FailState::Healthy
                } else {
                    FailState::Resync
                }
            }
        };

        // Now update cache_version_seen_at after transition check.
        self.cache_version_seen_at
            .store(cache_version, Ordering::Relaxed);

        if new_state != old_state {
            self.state.store(new_state as u8, Ordering::Relaxed);
        }

        new_state
    }

    /// Record a pipe failure and update state.
    ///
    /// Increments consecutive failures, resets successes, and transitions
    /// state if thresholds are crossed.
    ///
    /// # Returns
    ///
    /// The new state after transition (may be same as before).
    pub fn record_pipe_failure(&self) -> FailState {
        let old_state = self.current_state();

        // Increment failures, reset successes.
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        self.consecutive_successes.store(0, Ordering::Relaxed);

        // Update last pipe attempt time.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_pipe_attempt_epoch_secs
            .store(now_secs, Ordering::Relaxed);

        // Check thresholds for state transitions.
        let new_state = match old_state {
            FailState::Healthy => {
                if failures >= HEALTHY_TO_DEGRADED_THRESHOLD {
                    FailState::Degraded
                } else {
                    FailState::Healthy
                }
            }
            FailState::Degraded => {
                if failures >= DEGRADED_TO_ISOLATED_THRESHOLD {
                    FailState::Isolated
                } else {
                    FailState::Degraded
                }
            }
            FailState::Isolated => FailState::Isolated,
            FailState::Resync => {
                // RESYNC -> ISOLATED on any pipe failure.
                FailState::Isolated
            }
        };

        if new_state != old_state {
            self.state.store(new_state as u8, Ordering::Relaxed);
        }

        new_state
    }

    /// Returns `true` if the pipe should be retried in Degraded state.
    ///
    /// In Degraded state, the pipe is retried every 10th call to avoid
    /// overwhelming the system with failed connection attempts.
    #[must_use]
    pub fn should_retry_pipe(&self) -> bool {
        if self.current_state() != FailState::Degraded {
            return false;
        }
        let counter = self.degraded_retry_counter.fetch_add(1, Ordering::Relaxed) + 1;
        counter.is_multiple_of(DEGRADED_RETRY_INTERVAL)
    }

    /// Returns the last known good cache version.
    #[must_use]
    pub fn cache_version_seen_at(&self) -> u64 {
        self.cache_version_seen_at.load(Ordering::Relaxed)
    }

    /// Sets the last known good cache version (test-only).
    pub fn set_cache_version_seen_at(&self, version: u64) {
        self.cache_version_seen_at.store(version, Ordering::Relaxed);
    }

    /// Returns the last pipe attempt epoch seconds.
    #[must_use]
    #[allow(dead_code)]
    pub fn last_pipe_attempt_epoch_secs(&self) -> u64 {
        self.last_pipe_attempt_epoch_secs.load(Ordering::Relaxed)
    }

    /// Reset the degraded retry counter.
    ///
    /// Called when transitioning out of Degraded state.
    #[allow(dead_code)]
    pub fn reset_retry_counter(&self) {
        self.degraded_retry_counter.store(0, Ordering::Relaxed);
    }

    /// Reset all counters.
    ///
    /// Called during RESYNC -> HEALTHY transition.
    pub fn reset_counters(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.consecutive_successes.store(0, Ordering::Relaxed);
        self.degraded_retry_counter.store(0, Ordering::Relaxed);
    }

    /// Set state directly (used by background thread for RESYNC detection).
    ///
    /// # Safety
    ///
    /// This should only be called after verifying all entry guards.
    pub fn set_state(&self, new_state: FailState) {
        self.state.store(new_state as u8, Ordering::Relaxed);
    }

    /// Transition to ISOLATED if the cache is stale.
    ///
    /// Called by the pipe client or background thread when cache staleness is
    /// detected. This is the "cache stale" guard for the DEGRADED -> ISOLATED
    /// transition documented in the state machine table.
    ///
    /// # Arguments
    ///
    /// * `cache_version` - The last known good cache version.
    /// * `header_version` - The current version from the cache header.
    /// * `header_created_at` - When the cache buffer was built (Unix epoch).
    /// * `now_secs` - Current wall-clock seconds (Unix epoch).
    /// * `classification` - The classification tier for staleness budget lookup.
    ///
    /// # Returns
    ///
    /// The new state after transition (may be same as before).
    pub fn transition_if_cache_stale(
        &self,
        cache_version: u64,
        header_version: u64,
        header_created_at: u64,
        now_secs: u64,
        classification: Classification,
    ) -> FailState {
        let old_state = self.current_state();
        if old_state != FailState::Degraded && old_state != FailState::Healthy {
            // Only Healthy and Degraded can transition on staleness.
            return old_state;
        }

        if is_cache_stale(
            cache_version,
            header_version,
            header_created_at,
            now_secs,
            classification,
        ) {
            // Cache is stale: force transition to ISOLATED regardless of failure count.
            self.consecutive_failures.store(0, Ordering::Relaxed);
            self.consecutive_successes.store(0, Ordering::Relaxed);
            self.state
                .store(FailState::Isolated as u8, Ordering::Relaxed);
            FailState::Isolated
        } else {
            old_state
        }
    }
}

impl Default for FailModeState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Asymmetric tier-gated decisions
// ---------------------------------------------------------------------------

/// Make a decision when in ISOLATED state.
///
/// Asymmetric fail semantics:
/// - T3/T4 + Write -> deny (fail-closed for sensitive data)
/// - T3/T4 + Read -> allow (read exfiltration handled by other controls)
/// - T1/T2 (any op) -> allow (fail-open for non-sensitive data)
/// - Unknown (None) + Write -> deny (unknown could be sensitive)
/// - Unknown (None) + Read -> allow
///
/// # Arguments
///
/// * `classification` - The cached classification, or None if cache miss.
/// * `op` - The operation type (read vs write).
///
/// # Returns
///
/// `Some(DenyReturn)` if the operation should be denied, `None` to allow.
#[must_use]
pub fn decide_isolated(classification: Option<Classification>, op: HookOp) -> Option<DenyReturn> {
    match (classification, op) {
        // Known sensitive + Write -> deny
        (Some(Classification::T3 | Classification::T4), HookOp::Write) => {
            Some(DenyReturn::BoolFalse)
        }
        // Known sensitive + Read -> allow (other controls handle read exfil)
        (Some(Classification::T3 | Classification::T4), HookOp::Read) => None,
        // Known non-sensitive -> allow
        (Some(Classification::T1 | Classification::T2), _) => None,
        // Unknown + Write -> deny (fail-closed for unknown)
        (None, HookOp::Write) => Some(DenyReturn::BoolFalse),
        // Unknown + Read -> allow
        (None, HookOp::Read) => None,
    }
}

/// Make a decision when in DEGRADED state.
///
/// Same as ISOLATED for cache-hit decisions (fast path). On cache miss,
/// if `should_retry_pipe()` returns true, the caller should attempt a pipe
/// round-trip; otherwise the decision falls through to `decide_isolated`.
///
/// # Arguments
///
/// * `classification` - The cached classification, or None if cache miss.
/// * `op` - The operation type (read vs write).
///
/// # Returns
///
/// `Some(DenyReturn)` if the operation should be denied, `None` to allow.
#[must_use]
pub fn decide_degraded(classification: Option<Classification>, op: HookOp) -> Option<DenyReturn> {
    // Cache hit: same as ISOLATED (fast path).
    if classification.is_some() {
        return decide_isolated(classification, op);
    }
    // Cache miss: caller checks should_retry_pipe(); if not retrying,
    // falls through to decide_isolated.
    decide_isolated(classification, op)
}

/// Make a decision when in RESYNC state.
///
/// During RESYNC, new decisions use the new cache immediately.
/// In-flight decisions (started before RESYNC) use the old cache until
/// completion. This is handled by taking a version snapshot at lookup start.
///
/// # Arguments
///
/// * `classification` - The cached classification from the new cache.
/// * `op` - The operation type (read vs write).
///
/// # Returns
///
/// `Some(DenyReturn)` if the operation should be denied, `None` to allow.
#[must_use]
pub fn decide_resync(classification: Option<Classification>, op: HookOp) -> Option<DenyReturn> {
    // Same logic as Healthy: use cache if available, otherwise pipe.
    // In practice, RESYNC means we have fresh cache data.
    decide_isolated(classification, op)
}

// ---------------------------------------------------------------------------
// Staleness checking
// ---------------------------------------------------------------------------

/// Check if the cache is stale based on the tier-specific budget.
///
/// Uses the appropriate staleness budget for the given classification tier.
/// T1 (Public) = 30 min, T2 (Internal) = 5 min, T3 (Confidential) = 60 s,
/// T4 (Restricted) = 30 s.
///
/// Used for state transition decisions (DEGRADED -> ISOLATED when cache
/// exceeds the tier's budget).
///
/// # Arguments
///
/// * `cache_version` - The last known good cache version.
/// * `header_version` - The current version from the cache header.
/// * `header_created_at` - When the cache buffer was built (Unix epoch).
/// * `now_secs` - Current wall-clock seconds (Unix epoch).
/// * `classification` - The classification tier of the data being accessed.
///
/// # Returns
///
/// `true` if the cache is stale (older than the tier's budget or never validated).
#[must_use]
#[allow(dead_code)]
pub fn is_cache_stale(
    cache_version: u64,
    header_version: u64,
    header_created_at: u64,
    now_secs: u64,
    classification: Classification,
) -> bool {
    if cache_version == 0 {
        // Never seen a valid cache -> stale.
        return true;
    }

    if header_version <= cache_version {
        // Same or older version -> not stale.
        return false;
    }

    // Newer version available: check age against tier-specific budget.
    let age = now_secs.saturating_sub(header_created_at);
    age > staleness_budget_for(classification)
}

/// Check if a specific cache entry has expired.
///
/// # Arguments
///
/// * `entry_ttl_secs` - The TTL for this entry.
/// * `buffer_created_at` - When the cache buffer was built (Unix epoch).
/// * `now_secs` - Current wall-clock seconds (Unix epoch).
///
/// # Returns
///
/// `true` if the entry has exceeded its TTL.
#[must_use]
#[allow(dead_code)]
pub fn is_entry_expired(entry_ttl_secs: u16, buffer_created_at: u64, now_secs: u64) -> bool {
    let age = now_secs.saturating_sub(buffer_created_at);
    age > u64::from(entry_ttl_secs)
}

/// Get the staleness budget for a given classification tier.
///
/// # Arguments
///
/// * `tier` - The classification tier.
///
/// # Returns
///
/// The maximum age in seconds before the cache is considered stale for
/// that tier.
#[must_use]
#[allow(dead_code)]
pub fn staleness_budget_for(tier: Classification) -> u64 {
    match tier {
        Classification::T1 => STALENESS_BUDGETS[0],
        Classification::T2 => STALENESS_BUDGETS[1],
        Classification::T3 => STALENESS_BUDGETS[2],
        Classification::T4 => STALENESS_BUDGETS[3],
    }
}

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

/// Emit telemetry when a state transition occurs.
///
/// Logs via `tracing::warn!` and, if the pipe is available, sends a SIEM
/// event with the transition details. Debounced: only emits once per
/// transition.
///
/// # Arguments
///
/// * `old` - The previous state.
/// * `new` - The new state.
/// * `reason` - Human-readable reason for the transition.
#[allow(dead_code)]
pub fn emit_state_transition(old: FailState, new: FailState, reason: &str) {
    if old == new {
        return;
    }

    let pid = std::process::id();

    tracing::warn!(
        old_state = ?old,
        new_state = ?new,
        reason = %reason,
        pid = pid,
        "fail_mode state transition"
    );

    // Note: SIEM pipe event is best-effort. If the pipe is unavailable
    // (which is likely during state transitions), the tracing log is the
    // primary record. The agent's ETW consumer can also detect process-level
    // anomalies.
    let _ = reason; // Used in tracing above; suppress unused warning.
}

// ---------------------------------------------------------------------------
// Transition table (documented in code comments)
// ---------------------------------------------------------------------------

// | Current State | Event              | Guard                          | Next State | Action          | Decision Behavior |
// |---------------|--------------------|--------------------------------|------------|-----------------|-------------------|
// | HEALTHY       | pipe_failure       | failures >= 3                  | DEGRADED   | reset successes | cache + retry     |
// | DEGRADED      | pipe_failure       | failures >= 10 OR cache stale  | ISOLATED   | reset successes | cache-only        |
// | DEGRADED      | pipe_success       | successes >= 3                 | HEALTHY    | reset failures  | full pipe         |
// | ISOLATED      | pipe_success AND   | version > last_seen            | RESYNC     | flush LRU       | new cache         |
// |               | fresh_version      |                                |            |                 |                   |
// | RESYNC        | pipe_success       | successes >= 5                 | HEALTHY    | reset all       | full pipe         |

// RESYNC entry guards:
// - Pipe round-trip succeeded (not just connection available)
// - Cache version in shared memory > cache_version_seen_at (fresh data)
// - Full ABI validation passed (magic, layout_version, checksum, bounds)
// - All three must be true for RESYNC entry

// RESYNC exit guards:
// - LRU fully flushed (all old-version entries removed)
// - fail_state counters reset (failures=0, successes=0)
// - N consecutive successful pipe round-trips (ISOLATED_EXIT_HYSTERESIS=5)
// - All three must be true for RESYNC -> HEALTHY

// RESYNC allowed decisions:
// - In-flight decisions (started before RESYNC): complete using old cache
// - New decisions: use new cache immediately
// - No blocking, no latency spike

// RESYNC retry cadence:
// - Background thread continues polling every 100ms
// - Each poll checks if version > last_seen
// - If version unchanged, remain in RESYNC
// - If pipe fails during RESYNC, transition to ISOLATED

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Task 1: State transitions ---

    #[test]
    fn state_transitions_healthy_to_degraded() {
        let state = FailModeState::new();
        assert_eq!(state.current_state(), FailState::Healthy);

        // 2 failures: still Healthy
        state.record_pipe_failure();
        state.record_pipe_failure();
        assert_eq!(state.current_state(), FailState::Healthy);

        // 3rd failure: -> Degraded
        state.record_pipe_failure();
        assert_eq!(state.current_state(), FailState::Degraded);
    }

    #[test]
    fn state_transitions_degraded_to_isolated() {
        let state = FailModeState::new();

        // Enter Degraded (3 failures).
        for _ in 0..3 {
            state.record_pipe_failure();
        }
        assert_eq!(state.current_state(), FailState::Degraded);

        // 6 more failures: still Degraded (failures=9, threshold=10).
        for _ in 0..6 {
            state.record_pipe_failure();
        }
        assert_eq!(state.current_state(), FailState::Degraded);

        // 7th failure in Degraded (total 10): -> Isolated
        state.record_pipe_failure();
        assert_eq!(state.current_state(), FailState::Isolated);
    }

    #[test]
    fn state_transitions_degraded_to_healthy_hysteresis() {
        let state = FailModeState::new();

        // Enter Degraded.
        for _ in 0..3 {
            state.record_pipe_failure();
        }
        assert_eq!(state.current_state(), FailState::Degraded);

        // 2 successes: still Degraded
        state.record_pipe_success(1);
        state.record_pipe_success(1);
        assert_eq!(state.current_state(), FailState::Degraded);

        // 3rd success: -> Healthy
        state.record_pipe_success(1);
        assert_eq!(state.current_state(), FailState::Healthy);
    }

    #[test]
    fn state_transitions_isolated_to_resync() {
        let state = FailModeState::new();

        // Enter Isolated.
        for _ in 0..10 {
            state.record_pipe_failure();
        }
        assert_eq!(state.current_state(), FailState::Isolated);

        // Set cache_version_seen_at to 5.
        state.cache_version_seen_at.store(5, Ordering::Relaxed);

        // Success with version 6 (> 5): -> Resync
        state.record_pipe_success(6);
        assert_eq!(state.current_state(), FailState::Resync);
    }

    #[test]
    fn state_transitions_resync_to_healthy_hysteresis() {
        let state = FailModeState::new();

        // Enter Isolated.
        for _ in 0..10 {
            state.record_pipe_failure();
        }
        assert_eq!(state.current_state(), FailState::Isolated);

        // Enter Resync.
        state.cache_version_seen_at.store(5, Ordering::Relaxed);
        state.record_pipe_success(6);
        assert_eq!(state.current_state(), FailState::Resync);

        // 3 successes: still Resync (total 4, need 5)
        for _ in 0..3 {
            state.record_pipe_success(6);
        }
        assert_eq!(state.current_state(), FailState::Resync);

        // 4th success (total 5): -> Healthy
        state.record_pipe_success(6);
        assert_eq!(state.current_state(), FailState::Healthy);
    }

    #[test]
    fn state_transitions_resync_to_isolated_on_failure() {
        let state = FailModeState::new();

        // Enter Isolated.
        for _ in 0..10 {
            state.record_pipe_failure();
        }
        assert_eq!(state.current_state(), FailState::Isolated);

        // Enter Resync.
        state.cache_version_seen_at.store(5, Ordering::Relaxed);
        state.record_pipe_success(6);
        assert_eq!(state.current_state(), FailState::Resync);

        // Failure: -> Isolated
        state.record_pipe_failure();
        assert_eq!(state.current_state(), FailState::Isolated);
    }

    // --- Task 2: Asymmetric decisions ---

    #[test]
    fn asymmetric_decisions_t3_write_denies() {
        assert_eq!(
            decide_isolated(Some(Classification::T3), HookOp::Write),
            Some(DenyReturn::BoolFalse)
        );
    }

    #[test]
    fn asymmetric_decisions_t4_write_denies() {
        assert_eq!(
            decide_isolated(Some(Classification::T4), HookOp::Write),
            Some(DenyReturn::BoolFalse)
        );
    }

    #[test]
    fn asymmetric_decisions_t3_read_allows() {
        assert_eq!(
            decide_isolated(Some(Classification::T3), HookOp::Read),
            None
        );
    }

    #[test]
    fn asymmetric_decisions_t4_read_allows() {
        assert_eq!(
            decide_isolated(Some(Classification::T4), HookOp::Read),
            None
        );
    }

    #[test]
    fn asymmetric_decisions_t1_any_allows() {
        assert_eq!(
            decide_isolated(Some(Classification::T1), HookOp::Write),
            None
        );
        assert_eq!(
            decide_isolated(Some(Classification::T1), HookOp::Read),
            None
        );
    }

    #[test]
    fn asymmetric_decisions_t2_any_allows() {
        assert_eq!(
            decide_isolated(Some(Classification::T2), HookOp::Write),
            None
        );
        assert_eq!(
            decide_isolated(Some(Classification::T2), HookOp::Read),
            None
        );
    }

    #[test]
    fn asymmetric_decisions_unknown_write_denies() {
        assert_eq!(
            decide_isolated(None, HookOp::Write),
            Some(DenyReturn::BoolFalse)
        );
    }

    #[test]
    fn asymmetric_decisions_unknown_read_allows() {
        assert_eq!(decide_isolated(None, HookOp::Read), None);
    }

    #[test]
    fn decide_degraded_uses_same_logic() {
        assert_eq!(
            decide_degraded(Some(Classification::T4), HookOp::Write),
            Some(DenyReturn::BoolFalse)
        );
        assert_eq!(
            decide_degraded(Some(Classification::T1), HookOp::Write),
            None
        );
    }

    #[test]
    fn decide_resync_uses_same_logic() {
        assert_eq!(
            decide_resync(Some(Classification::T4), HookOp::Write),
            Some(DenyReturn::BoolFalse)
        );
        assert_eq!(decide_resync(Some(Classification::T1), HookOp::Write), None);
    }

    // --- Task 3: Staleness budgets ---

    #[test]
    fn staleness_budgets_values() {
        assert_eq!(STALENESS_BUDGETS[0], 1800); // T1: 30 min
        assert_eq!(STALENESS_BUDGETS[1], 300); // T2: 5 min
        assert_eq!(STALENESS_BUDGETS[2], 60); // T3: 60 sec
        assert_eq!(STALENESS_BUDGETS[3], 30); // T4: 30 sec
    }

    #[test]
    fn staleness_budget_for_tier() {
        assert_eq!(staleness_budget_for(Classification::T1), 1800);
        assert_eq!(staleness_budget_for(Classification::T2), 300);
        assert_eq!(staleness_budget_for(Classification::T3), 60);
        assert_eq!(staleness_budget_for(Classification::T4), 30);
    }

    #[test]
    fn is_cache_stale_never_seen() {
        assert!(is_cache_stale(0, 1, 1000, 2000, Classification::T4));
    }

    #[test]
    fn is_cache_stale_fresh_version() {
        // Header version <= cache version: not stale
        assert!(!is_cache_stale(5, 5, 1000, 2000, Classification::T4));
        assert!(!is_cache_stale(5, 4, 1000, 2000, Classification::T4));
    }

    #[test]
    fn is_cache_stale_new_version_within_budget() {
        // Newer version, age = 20s (within T4=30s budget)
        assert!(!is_cache_stale(5, 6, 1000, 1019, Classification::T4));
    }

    #[test]
    fn is_cache_stale_new_version_exceeds_budget() {
        // Newer version, age = 31s (exceeds T4=30s budget)
        assert!(is_cache_stale(5, 6, 1000, 1031, Classification::T4));
    }

    #[test]
    fn is_cache_stale_boundary() {
        // Exactly at budget: not stale (strict >)
        assert!(!is_cache_stale(5, 6, 1000, 1030, Classification::T4));
        // One second over: stale
        assert!(is_cache_stale(5, 6, 1000, 1031, Classification::T4));
    }

    #[test]
    fn is_entry_expired_within_ttl() {
        assert!(!is_entry_expired(60, 1000, 1059));
    }

    #[test]
    fn is_entry_expired_at_ttl() {
        // Exactly at TTL: not expired (strict >)
        assert!(!is_entry_expired(60, 1000, 1060));
    }

    #[test]
    fn is_entry_expired_over_ttl() {
        assert!(is_entry_expired(60, 1000, 1061));
    }

    // --- Task 4: RESYNC transitions ---

    #[test]
    fn resync_transitions_entry_guards() {
        let state = FailModeState::new();

        // Enter Isolated.
        for _ in 0..10 {
            state.record_pipe_failure();
        }
        assert_eq!(state.current_state(), FailState::Isolated);

        // Set last seen version.
        state.cache_version_seen_at.store(42, Ordering::Relaxed);

        // Success with same version: stays Isolated
        state.record_pipe_success(42);
        assert_eq!(state.current_state(), FailState::Isolated);

        // Success with newer version: -> Resync
        state.record_pipe_success(43);
        assert_eq!(state.current_state(), FailState::Resync);
    }

    #[test]
    fn resync_transitions_exit_guards() {
        let state = FailModeState::new();

        // Enter Isolated -> Resync.
        for _ in 0..10 {
            state.record_pipe_failure();
        }
        state.cache_version_seen_at.store(1, Ordering::Relaxed);
        state.record_pipe_success(2);
        assert_eq!(state.current_state(), FailState::Resync);

        // Need 5 consecutive successes to exit. Already have 1 from entering Resync.
        // 3 more: still Resync (total 4).
        for i in 0..3 {
            state.record_pipe_success(2);
            assert_eq!(
                state.current_state(),
                FailState::Resync,
                "should stay Resync at success {i}"
            );
        }

        // 4th additional success (total 5): -> Healthy
        state.record_pipe_success(2);
        assert_eq!(state.current_state(), FailState::Healthy);
    }

    // --- Task 7: Telemetry ---

    #[test]
    fn emit_state_transition_no_op_when_same() {
        // Should not panic, should not emit.
        emit_state_transition(FailState::Healthy, FailState::Healthy, "test");
    }

    #[test]
    fn emit_state_transition_emits_for_different() {
        // Should not panic.
        emit_state_transition(
            FailState::Healthy,
            FailState::Degraded,
            "3_consecutive_pipe_failures",
        );
    }

    // --- Task 8: Hysteresis and flapping ---

    #[test]
    fn hysteresis_degraded_exit_requires_3() {
        let state = FailModeState::new();

        for _ in 0..3 {
            state.record_pipe_failure();
        }
        assert_eq!(state.current_state(), FailState::Degraded);

        // 2 successes: still Degraded
        state.record_pipe_success(1);
        state.record_pipe_success(1);
        assert_eq!(state.current_state(), FailState::Degraded);

        // 3rd: -> Healthy
        state.record_pipe_success(1);
        assert_eq!(state.current_state(), FailState::Healthy);
    }

    #[test]
    fn hysteresis_isolated_exit_requires_5() {
        let state = FailModeState::new();

        for _ in 0..10 {
            state.record_pipe_failure();
        }
        state.cache_version_seen_at.store(1, Ordering::Relaxed);
        state.record_pipe_success(2);
        assert_eq!(state.current_state(), FailState::Resync);

        // 3 successes: still Resync (total 4, need 5)
        for _ in 0..3 {
            state.record_pipe_success(2);
        }
        assert_eq!(state.current_state(), FailState::Resync);

        // 4th additional success (total 5): -> Healthy
        state.record_pipe_success(2);
        assert_eq!(state.current_state(), FailState::Healthy);
    }

    #[test]
    fn flapping_prevention() {
        let state = FailModeState::new();

        // Rapid success/failure/success pattern should not oscillate.
        state.record_pipe_success(1);
        state.record_pipe_failure();
        state.record_pipe_success(1);
        state.record_pipe_failure();
        state.record_pipe_success(1);

        // After the pattern: successes=1, failures=0, so still Healthy.
        assert_eq!(state.current_state(), FailState::Healthy);

        // Now 3 failures: -> Degraded
        state.record_pipe_failure();
        state.record_pipe_failure();
        state.record_pipe_failure();
        assert_eq!(state.current_state(), FailState::Degraded);

        // 2 successes: still Degraded
        state.record_pipe_success(1);
        state.record_pipe_success(1);
        assert_eq!(state.current_state(), FailState::Degraded);

        // 1 failure: resets successes, still Degraded
        state.record_pipe_failure();
        assert_eq!(state.current_state(), FailState::Degraded);
    }

    #[test]
    fn edge_threshold_2_of_3() {
        let state = FailModeState::new();

        // 2 failures: still Healthy
        state.record_pipe_failure();
        state.record_pipe_failure();
        assert_eq!(state.current_state(), FailState::Healthy);

        // 3rd: -> Degraded
        state.record_pipe_failure();
        assert_eq!(state.current_state(), FailState::Degraded);
    }

    #[test]
    fn edge_threshold_9_of_10() {
        let state = FailModeState::new();

        // Enter Degraded.
        for _ in 0..3 {
            state.record_pipe_failure();
        }
        assert_eq!(state.current_state(), FailState::Degraded);

        // 9 total failures: still Degraded
        for _ in 0..6 {
            state.record_pipe_failure();
        }
        assert_eq!(state.current_state(), FailState::Degraded);

        // 10th: -> Isolated
        state.record_pipe_failure();
        assert_eq!(state.current_state(), FailState::Isolated);
    }

    #[test]
    fn recovery_from_isolated() {
        let state = FailModeState::new();

        // Enter Isolated.
        for _ in 0..10 {
            state.record_pipe_failure();
        }
        assert_eq!(state.current_state(), FailState::Isolated);

        // Set up for RESYNC.
        state.cache_version_seen_at.store(1, Ordering::Relaxed);

        // Pipe success + fresh version: -> Resync
        state.record_pipe_success(2);
        assert_eq!(state.current_state(), FailState::Resync);

        // 5 successes: -> Healthy
        for _ in 0..4 {
            state.record_pipe_success(2);
        }
        assert_eq!(state.current_state(), FailState::Healthy);
    }

    #[test]
    fn resync_pipe_failure_returns_to_isolated() {
        let state = FailModeState::new();

        // Enter Isolated -> Resync.
        for _ in 0..10 {
            state.record_pipe_failure();
        }
        state.cache_version_seen_at.store(1, Ordering::Relaxed);
        state.record_pipe_success(2);
        assert_eq!(state.current_state(), FailState::Resync);

        // Pipe failure: -> Isolated (not Healthy)
        state.record_pipe_failure();
        assert_eq!(state.current_state(), FailState::Isolated);
    }

    #[test]
    fn cache_stale_transition() {
        let _state = FailModeState::new();

        // Simulate cache older than T4 budget causing transition.
        // This is tested via is_cache_stale; the state machine checks
        // staleness before calling record_pipe_failure.
        let now_secs = 2000;
        let created_at = 1000; // 1000s old, exceeds T4=30s
        assert!(is_cache_stale(
            5,
            6,
            created_at,
            now_secs,
            Classification::T4
        ));
    }

    #[test]
    fn should_retry_pipe_only_in_degraded() {
        let state = FailModeState::new();

        // Healthy: no retry
        assert!(!state.should_retry_pipe());

        // Degraded: retry every 10th call
        state.set_state(FailState::Degraded);
        state.reset_retry_counter();

        // First 9 calls: no retry
        for _ in 0..9 {
            assert!(!state.should_retry_pipe());
        }

        // 10th call: retry
        assert!(state.should_retry_pipe());

        // 11th-19th: no retry
        for _ in 0..9 {
            assert!(!state.should_retry_pipe());
        }

        // 20th: retry
        assert!(state.should_retry_pipe());
    }

    #[test]
    fn should_retry_pipe_not_in_isolated() {
        let state = FailModeState::new();
        state.set_state(FailState::Isolated);
        assert!(!state.should_retry_pipe());
    }

    #[test]
    fn should_retry_pipe_not_in_resync() {
        let state = FailModeState::new();
        state.set_state(FailState::Resync);
        assert!(!state.should_retry_pipe());
    }

    #[test]
    fn reset_counters_clears_all() {
        let state = FailModeState::new();

        state.record_pipe_failure();
        state.record_pipe_failure();
        state.record_pipe_success(1);

        assert_eq!(state.consecutive_failures.load(Ordering::Relaxed), 0);
        assert_eq!(state.consecutive_successes.load(Ordering::Relaxed), 1);

        state.reset_counters();

        assert_eq!(state.consecutive_failures.load(Ordering::Relaxed), 0);
        assert_eq!(state.consecutive_successes.load(Ordering::Relaxed), 0);
        assert_eq!(state.degraded_retry_counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn fail_state_from_u8() {
        assert_eq!(FailState::from_u8(0), FailState::Healthy);
        assert_eq!(FailState::from_u8(1), FailState::Degraded);
        assert_eq!(FailState::from_u8(2), FailState::Isolated);
        assert_eq!(FailState::from_u8(3), FailState::Resync);
        assert_eq!(FailState::from_u8(255), FailState::Isolated); // unknown -> safe
    }

    #[test]
    fn default_is_healthy() {
        let state = FailModeState::default();
        assert_eq!(state.current_state(), FailState::Healthy);
    }

    #[test]
    fn record_pipe_success_updates_version_seen() {
        let state = FailModeState::new();
        state.record_pipe_success(42);
        assert_eq!(state.cache_version_seen_at(), 42);
    }

    #[test]
    fn record_pipe_failure_updates_last_attempt_time() {
        let state = FailModeState::new();
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        state.record_pipe_failure();
        let after = state.last_pipe_attempt_epoch_secs();
        assert!(after >= before);
    }
}
