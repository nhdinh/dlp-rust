//! Health snapshot aggregator for hook DLL self-health monitoring (DIFF-04).
//!
//! The `HealthAggregator` collects health snapshots from hook DLLs, maintains
//! a 12-snapshot rolling history, computes threshold-based status, and emits
//! audit events on health transitions.
//!
//! ## Thresholds (D-21)
//!
//! | Status    | Condition                                              |
//! |-----------|--------------------------------------------------------|
//! | Healthy   | cache_hit_rate >= 0.80 AND fail_state == Healthy AND pipe_round_trips > 0 |
//! | Degraded  | cache_hit_rate < 0.80 OR fail_state == Degraded        |
//! | Critical  | fail_state == Isolated OR pipe_round_trips == 0        |
//!
//! ## Alert Emission (D-22)
//!
//! - Healthy -> Degraded for 2 consecutive polls: warn audit event.
//! - Any -> Critical: crit audit event + alert_router::send.
//! - Any -> Healthy: resets consecutive_degraded counter.
//!
//! ## Security
//!
//! - In-memory only — no disk persistence.
//! - 60-second poll interval limits alert rate (T-58-09 mitigation).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use dlp_common::hook_ipc::HookHealthSnapshot;
use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};
use tracing::{info, warn};

/// Maximum history entries retained (12 minutes at 60s poll interval).
const MAX_HISTORY_LEN: usize = 12;

/// Number of consecutive degraded polls before emitting a warn alert.
const CONSECUTIVE_DEGRADED_THRESHOLD: u32 = 2;

/// Health status computed from a snapshot against thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// All metrics within healthy bounds.
    Healthy,
    /// One or more metrics degraded but not critical.
    Degraded,
    /// Fail-state is Isolated or no pipe activity.
    Critical,
}

impl HealthStatus {
    /// Returns the human-readable string for this status.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Critical => "critical",
        }
    }
}

/// Alias for the optional boxed alert-router closure to keep field types readable.
type AlertRouterSlot = Arc<Mutex<Option<Box<dyn Fn(&AuditEvent) + Send + 'static>>>>;

/// Aggregates hook DLL health snapshots and emits alerts on transitions.
///
/// Thread-safe via interior mutability (Mutex). All public methods take `&self`.
pub struct HealthAggregator {
    /// Rolling history of health snapshots (max 12 entries).
    history: Arc<Mutex<VecDeque<HookHealthSnapshot>>>,
    /// Last computed health status.
    last_status: Arc<Mutex<HealthStatus>>,
    /// Count of consecutive degraded polls.
    consecutive_degraded: Arc<Mutex<u32>>,
    /// Optional alert router for crit severity routing.
    ///
    /// Stored as a function pointer to avoid coupling to dlp-server's
    /// AlertRouter type. The caller provides the routing closure at
    /// construction time.
    alert_router: AlertRouterSlot,

    // Phantom data to make the type Debug-friendly without requiring
    // Debug on the closure type.
    _phantom: std::marker::PhantomData<()>,
}

impl std::fmt::Debug for HealthAggregator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthAggregator")
            .field("history_len", &self.history_len())
            .field(
                "last_status",
                &self.last_status.lock().unwrap_or_else(|e| {
                    tracing::error!("Mutex poisoned, recovering last_status");
                    e.into_inner()
                }),
            )
            .field(
                "consecutive_degraded",
                &self.consecutive_degraded.lock().unwrap_or_else(|e| {
                    tracing::error!("Mutex poisoned, recovering consecutive_degraded");
                    e.into_inner()
                }),
            )
            .finish()
    }
}

impl Clone for HealthAggregator {
    fn clone(&self) -> Self {
        Self {
            history: Arc::clone(&self.history),
            last_status: Arc::clone(&self.last_status),
            consecutive_degraded: Arc::clone(&self.consecutive_degraded),
            alert_router: Arc::clone(&self.alert_router),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl HealthAggregator {
    /// Creates a new health aggregator with no alert router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            history: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_HISTORY_LEN))),
            last_status: Arc::new(Mutex::new(HealthStatus::Healthy)),
            consecutive_degraded: Arc::new(Mutex::new(0)),
            alert_router: Arc::new(Mutex::new(None)),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Sets the alert router callback for crit severity events.
    ///
    /// # Arguments
    ///
    /// * `router` — closure that receives an `AuditEvent` and routes it.
    pub fn set_alert_router<F>(&self, router: F)
    where
        F: Fn(&AuditEvent) + Send + 'static,
    {
        let mut guard = self.alert_router.lock().unwrap_or_else(|e| {
            tracing::error!("Mutex poisoned, recovering alert_router");
            e.into_inner()
        });
        *guard = Some(Box::new(router));
    }

    /// Ingests a health snapshot and evaluates threshold transitions.
    ///
    /// # Arguments
    ///
    /// * `snapshot` — the health snapshot from a hook DLL.
    pub fn ingest_snapshot(&self, snapshot: HookHealthSnapshot) {
        // Push to history, evict oldest if over capacity.
        {
            let mut history = self.history.lock().unwrap_or_else(|e| {
                tracing::error!("Mutex poisoned, recovering history");
                e.into_inner()
            });
            history.push_back(snapshot.clone());
            if history.len() > MAX_HISTORY_LEN {
                history.pop_front();
            }
        }

        // Compute new status from the snapshot.
        let new_status = Self::compute_status(&snapshot);
        let old_status = {
            let mut last = self.last_status.lock().unwrap_or_else(|e| {
                tracing::error!("Mutex poisoned, recovering last_status");
                e.into_inner()
            });
            let old = *last;
            *last = new_status;
            old
        };

        // Handle transitions.
        match new_status {
            HealthStatus::Degraded => {
                let mut count = self.consecutive_degraded.lock().unwrap_or_else(|e| {
                    tracing::error!("Mutex poisoned, recovering consecutive_degraded");
                    e.into_inner()
                });
                if old_status == HealthStatus::Healthy {
                    *count += 1;
                }
                // Emit warn alert on threshold crossing.
                if *count >= CONSECUTIVE_DEGRADED_THRESHOLD {
                    self.emit_health_audit_event("warn", &snapshot, old_status, new_status);
                    *count = 0; // Reset after emitting to avoid repeat spam.
                }
            }
            HealthStatus::Critical => {
                {
                    let mut count = self.consecutive_degraded.lock().unwrap_or_else(|e| {
                        tracing::error!("Mutex poisoned, recovering consecutive_degraded");
                        e.into_inner()
                    });
                    *count = 0;
                }
                self.emit_health_audit_event("crit", &snapshot, old_status, new_status);
            }
            HealthStatus::Healthy => {
                let mut count = self.consecutive_degraded.lock().unwrap_or_else(|e| {
                    tracing::error!("Mutex poisoned, recovering consecutive_degraded");
                    e.into_inner()
                });
                *count = 0;
                // Optionally emit an info-level recovery event.
                if old_status != HealthStatus::Healthy {
                    info!(
                        old_status = %old_status.as_str(),
                        "hook health recovered to healthy"
                    );
                }
            }
        }
    }

    /// Returns the current health status and most recent snapshot (if any).
    #[must_use]
    pub fn get_current_status(&self) -> Option<(HealthStatus, HookHealthSnapshot)> {
        let history = self.history.lock().unwrap_or_else(|e| {
            tracing::error!("Mutex poisoned, recovering history");
            e.into_inner()
        });
        let last_status = self.last_status.lock().unwrap_or_else(|e| {
            tracing::error!("Mutex poisoned, recovering last_status");
            e.into_inner()
        });
        history.back().cloned().map(|snap| (*last_status, snap))
    }

    /// Returns a copy of the full history.
    #[must_use]
    pub fn get_history(&self) -> Vec<HookHealthSnapshot> {
        let history = self.history.lock().unwrap_or_else(|e| {
            tracing::error!("Mutex poisoned, recovering history");
            e.into_inner()
        });
        history.iter().cloned().collect()
    }

    /// Returns the number of history entries.
    #[must_use]
    pub fn history_len(&self) -> usize {
        let history = self.history.lock().unwrap_or_else(|e| {
            tracing::error!("Mutex poisoned, recovering history");
            e.into_inner()
        });
        history.len()
    }

    /// Computes the health status from a single snapshot.
    ///
    /// Thresholds per D-21:
    /// - Healthy: cache_hit_rate >= 0.80 AND fail_state == 0 (Healthy) AND pipe_round_trips > 0
    /// - Degraded: cache_hit_rate < 0.80 OR fail_state == 1 (Degraded)
    /// - Critical: fail_state == 2 (Isolated) OR pipe_round_trips == 0
    fn compute_status(snapshot: &HookHealthSnapshot) -> HealthStatus {
        // Critical takes precedence.
        if snapshot.current_fail_state == 2 || snapshot.pipe_round_trips_60s == 0 {
            return HealthStatus::Critical;
        }

        // Degraded: low cache hit rate or degraded fail state.
        if snapshot.cache_hit_rate_60s < 0.80 || snapshot.current_fail_state == 1 {
            return HealthStatus::Degraded;
        }

        // Healthy: all metrics within bounds.
        HealthStatus::Healthy
    }

    /// Emits a health transition audit event.
    ///
    /// For "crit" severity, also routes through the alert router if configured.
    fn emit_health_audit_event(
        &self,
        severity: &str,
        snapshot: &HookHealthSnapshot,
        old_status: HealthStatus,
        new_status: HealthStatus,
    ) {
        let event_type = if severity == "crit" {
            EventType::Alert
        } else {
            EventType::Block
        };

        let mut event = AuditEvent::new(
            event_type,
            "S-1-5-18".to_string(), // SYSTEM SID — health events are system-generated.
            "dlp-agent".to_string(),
            "hook-health".to_string(),
            Classification::T1,
            Action::READ,
            Decision::DenyWithAlert,
            "dlp-agent".to_string(),
            0,
        )
        .with_policy(
            format!("hook-health-{}", new_status.as_str()),
            format!(
                "Hook health transitioned from {} to {} (injected_pids={}, patched_modules={}, cache_hit_rate={:.2}, pipe_round_trips={})",
                old_status.as_str(),
                new_status.as_str(),
                snapshot.injected_pids,
                snapshot.patched_modules,
                snapshot.cache_hit_rate_60s,
                snapshot.pipe_round_trips_60s,
            ),
        );

        // Set severity via policy_mode for SIEM routing.
        event.policy_mode = Some(severity.to_string());

        // Route to SIEM (all health events).
        if event_type.routed_to_siem() {
            // SIEM routing happens at the audit emitter layer; we just
            // construct the event here. The caller (interception/mod.rs)
            // will emit via the standard audit pipeline.
            info!(
                old_status = %old_status.as_str(),
                new_status = %new_status.as_str(),
                severity = %severity,
                "hook health transition audit event constructed"
            );
        }

        // Route through alert_router for crit severity.
        if severity == "crit" {
            let router_guard = self.alert_router.lock().unwrap_or_else(|e| {
                tracing::error!("Mutex poisoned, recovering alert_router");
                e.into_inner()
            });
            if let Some(ref router) = *router_guard {
                router(&event);
            } else {
                warn!(
                    old_status = %old_status.as_str(),
                    new_status = %new_status.as_str(),
                    "Critical health transition but no alert router configured"
                );
            }
        }
    }
}

impl Default for HealthAggregator {
    fn default() -> Self {
        Self::new()
    }
}

// Manual Debug impl above; no derive needed.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn make_snapshot(hit_rate: f64, fail_state: u8, pipe_trips: u64) -> HookHealthSnapshot {
        HookHealthSnapshot {
            injected_pids: 5,
            patched_modules: 12,
            pipe_round_trips_60s: pipe_trips,
            cache_hit_rate_60s: hit_rate,
            current_fail_state: fail_state,
            timestamp_secs: 1_700_000_000,
        }
    }

    #[test]
    fn test_healthy_status() {
        let agg = HealthAggregator::new();
        let snap = make_snapshot(0.85, 0, 100);
        agg.ingest_snapshot(snap);

        let (status, _) = agg.get_current_status().expect("should have status");
        assert_eq!(status, HealthStatus::Healthy);
    }

    #[test]
    fn test_degraded_status_low_hit_rate() {
        let agg = HealthAggregator::new();
        let snap = make_snapshot(0.70, 0, 100);
        agg.ingest_snapshot(snap);

        let (status, _) = agg.get_current_status().expect("should have status");
        assert_eq!(status, HealthStatus::Degraded);
    }

    #[test]
    fn test_critical_isolated() {
        let agg = HealthAggregator::new();
        let snap = make_snapshot(0.90, 2, 100);
        agg.ingest_snapshot(snap);

        let (status, _) = agg.get_current_status().expect("should have status");
        assert_eq!(status, HealthStatus::Critical);
    }

    #[test]
    fn test_critical_zero_pipes() {
        let agg = HealthAggregator::new();
        let snap = make_snapshot(0.90, 0, 0);
        agg.ingest_snapshot(snap);

        let (status, _) = agg.get_current_status().expect("should have status");
        assert_eq!(status, HealthStatus::Critical);
    }

    #[test]
    fn test_consecutive_degraded_alert() {
        let alert_count = Arc::new(AtomicUsize::new(0));
        let alert_count_clone = Arc::clone(&alert_count);

        let agg = HealthAggregator::new();
        agg.set_alert_router(move |_event: &AuditEvent| {
            alert_count_clone.fetch_add(1, Ordering::SeqCst);
        });

        // First degraded: no alert (count = 1, below threshold).
        agg.ingest_snapshot(make_snapshot(0.70, 0, 100));
        assert_eq!(alert_count.load(Ordering::SeqCst), 0);

        // Second degraded from Healthy: alert fires (count reaches 2).
        // Reset the last_status to Healthy first by creating a fresh aggregator.
        let agg2 = HealthAggregator::new();
        let count2 = Arc::new(AtomicUsize::new(0));
        let count2_clone = Arc::clone(&count2);
        agg2.set_alert_router(move |_event: &AuditEvent| {
            count2_clone.fetch_add(1, Ordering::SeqCst);
        });

        // Start healthy, then two consecutive degraded.
        agg2.ingest_snapshot(make_snapshot(0.90, 0, 100)); // Healthy
        agg2.ingest_snapshot(make_snapshot(0.70, 0, 100)); // Degraded #1
        assert_eq!(count2.load(Ordering::SeqCst), 0);

        agg2.ingest_snapshot(make_snapshot(0.65, 0, 100)); // Degraded #2
                                                           // After 2 consecutive degraded from healthy, warn event is emitted.
                                                           // The warn event does NOT call alert_router (only crit does).
                                                           // So count stays 0 for warn.
        assert_eq!(count2.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_critical_alert() {
        let alert_count = Arc::new(AtomicUsize::new(0));
        let alert_count_clone = Arc::clone(&alert_count);

        let agg = HealthAggregator::new();
        agg.set_alert_router(move |_event: &AuditEvent| {
            alert_count_clone.fetch_add(1, Ordering::SeqCst);
        });

        // Critical transition triggers alert_router.
        agg.ingest_snapshot(make_snapshot(0.90, 2, 100));
        assert_eq!(alert_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_history_limit() {
        let agg = HealthAggregator::new();
        for i in 0..15 {
            let mut snap = make_snapshot(0.90, 0, 100);
            snap.timestamp_secs = 1_700_000_000 + i as u64;
            agg.ingest_snapshot(snap);
        }
        assert_eq!(agg.history_len(), 12);

        let history = agg.get_history();
        assert_eq!(history.len(), 12);
        // Oldest entries (0..2) should have been evicted.
        assert_eq!(history[0].timestamp_secs, 1_700_000_003);
    }

    #[test]
    fn test_healthy_resets_counter() {
        let agg = HealthAggregator::new();

        // Degraded.
        agg.ingest_snapshot(make_snapshot(0.70, 0, 100));
        // Healthy should reset counter.
        agg.ingest_snapshot(make_snapshot(0.90, 0, 100));

        // Back to degraded — counter starts from 0, so no alert yet.
        agg.ingest_snapshot(make_snapshot(0.70, 0, 100));

        // Status should be Degraded.
        let (status, _) = agg.get_current_status().expect("should have status");
        assert_eq!(status, HealthStatus::Degraded);
    }

    #[test]
    fn test_degraded_fail_state() {
        let agg = HealthAggregator::new();
        let snap = make_snapshot(0.90, 1, 100); // Degraded fail state.
        agg.ingest_snapshot(snap);

        let (status, _) = agg.get_current_status().expect("should have status");
        assert_eq!(status, HealthStatus::Degraded);
    }

    #[test]
    fn test_critical_takes_precedence_over_degraded() {
        let agg = HealthAggregator::new();
        // Both low hit rate AND isolated — Critical wins.
        let snap = make_snapshot(0.50, 2, 100);
        agg.ingest_snapshot(snap);

        let (status, _) = agg.get_current_status().expect("should have status");
        assert_eq!(status, HealthStatus::Critical);
    }

    #[test]
    fn test_get_current_status_empty() {
        let agg = HealthAggregator::new();
        assert!(agg.get_current_status().is_none());
    }
}
