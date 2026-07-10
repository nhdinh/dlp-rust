//! In-memory health snapshot store for the admin self-health dashboard (DIFF-04).
//!
//! The `HealthSnapshotStore` collects per-agent hook DLL health snapshots,
//! retains the latest snapshot and a bounded rolling history per agent, and
//! aggregates them into a dashboard snapshot for the admin TUI.
//!
//! ## Security
//!
//! - In-memory only — no disk persistence (T-58.8-07 mitigation).
//! - Per-agent history cap prevents unbounded memory growth.
//! - Global key cap with LRU eviction prevents unbounded agent keys.

use std::collections::VecDeque;
use std::sync::Arc;

use dashmap::DashMap;
use dlp_common::hook_ipc::HookHealthSnapshot;
use serde::{Deserialize, Serialize};

/// Default maximum number of snapshots retained per agent.
const DEFAULT_MAX_HISTORY: usize = 12;

/// Default maximum number of agent keys retained globally.
const DEFAULT_MAX_KEYS: usize = 10_000;

/// Dashboard-facing aggregation of hook DLL health across all agents.
///
/// This is the shape consumed by `dlp-admin-cli/src/screens/render.rs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DashboardHealthSnapshot {
    /// Overall health status: "healthy", "degraded", or "critical".
    pub overall_status: String,
    /// Total number of injected processes across all agents.
    pub injected_pids: u64,
    /// Total number of patched modules across all agents.
    pub patched_modules: u64,
    /// Total pipe round-trips in the last 60 seconds across all agents.
    pub pipe_round_trips_60s: u64,
    /// Weighted-average cache hit rate over the last 60 seconds.
    pub cache_hit_rate_60s: f64,
    /// Maximum current fail state across all agents (0=Healthy, 1=Degraded, 2=Isolated).
    pub fail_state: u8,
    /// Latest snapshot timestamp (Unix seconds).
    pub timestamp_secs: u64,
}

/// Per-agent record retaining the latest snapshot and rolling history.
#[derive(Debug, Clone)]
struct AgentHealthRecord {
    /// Most recent snapshot (also the newest entry in `history`).
    latest: HookHealthSnapshot,
    /// Rolling history, oldest at the front, newest at the back.
    history: VecDeque<HookHealthSnapshot>,
}

/// In-memory store for hook DLL health snapshots.
///
/// Thread-safe via `DashMap`. All public methods take `&self`.
#[derive(Debug, Clone)]
pub struct HealthSnapshotStore {
    /// Lock-free map from `agent_id` to per-agent record.
    snapshots: Arc<DashMap<String, AgentHealthRecord>>,
    /// Maximum snapshots to retain per agent.
    max_history: usize,
    /// Maximum number of agent keys to retain globally.
    max_keys: usize,
    /// Ordered queue of keys for LRU eviction when `max_keys` is exceeded.
    key_queue: Arc<std::sync::Mutex<VecDeque<String>>>,
}

impl HealthSnapshotStore {
    /// Creates a new store with the default per-agent history cap.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_HISTORY)
    }

    /// Creates a new store with a custom per-agent history cap.
    ///
    /// # Arguments
    ///
    /// * `max_history` — maximum snapshots retained per agent.
    #[must_use]
    pub fn with_capacity(max_history: usize) -> Self {
        Self::with_caps(max_history, DEFAULT_MAX_KEYS)
    }

    /// Creates a new store with custom per-agent and global key caps.
    ///
    /// # Arguments
    ///
    /// * `max_history` — maximum snapshots retained per agent.
    /// * `max_keys` — maximum agent keys retained globally.
    #[must_use]
    pub fn with_caps(max_history: usize, max_keys: usize) -> Self {
        Self {
            snapshots: Arc::new(DashMap::new()),
            max_history,
            max_keys,
            key_queue: Arc::new(std::sync::Mutex::new(VecDeque::new())),
        }
    }

    /// Ingests a health snapshot for the given agent.
    ///
    /// Updates the agent's latest snapshot and appends to its rolling history,
    /// evicting the oldest entry when the per-agent cap is exceeded.
    ///
    /// # Arguments
    ///
    /// * `agent_id` — unique identifier of the agent endpoint.
    /// * `snapshot` — health snapshot to ingest.
    pub fn ingest(&self, agent_id: &str, snapshot: HookHealthSnapshot) {
        let key = agent_id.to_owned();
        let is_new_key = !self.snapshots.contains_key(&key);

        {
            let mut entry = self.snapshots.entry(key.clone()).or_insert_with(|| AgentHealthRecord {
                latest: snapshot.clone(),
                history: VecDeque::with_capacity(self.max_history),
            });
            entry.latest = snapshot.clone();
            entry.history.push_back(snapshot);
            while entry.history.len() > self.max_history {
                entry.history.pop_front();
            }
        }

        if is_new_key {
            let mut queue = self.key_queue.lock().expect("key_queue lock poisoned");
            queue.push_back(key);
            while queue.len() > self.max_keys {
                if let Some(oldest_key) = queue.pop_front() {
                    self.snapshots.remove(&oldest_key);
                }
            }
        }
    }

    /// Computes a dashboard snapshot aggregating across all agents.
    ///
    /// Returns `None` when no snapshots have been ingested.
    #[must_use]
    pub fn get_dashboard_snapshot(&self) -> Option<DashboardHealthSnapshot> {
        let mut total_injected_pids: u64 = 0;
        let mut total_patched_modules: u64 = 0;
        let mut total_pipe_round_trips: u64 = 0;
        let mut weighted_cache_hits: f64 = 0.0;
        let mut max_fail_state: u8 = 0;
        let mut latest_timestamp: u64 = 0;
        let mut count: usize = 0;

        for entry in self.snapshots.iter() {
            let snap = &entry.value().latest;
            total_injected_pids += snap.injected_pids;
            total_patched_modules += snap.patched_modules;
            total_pipe_round_trips += snap.pipe_round_trips_60s;
            weighted_cache_hits += snap.cache_hit_rate_60s * snap.pipe_round_trips_60s as f64;
            max_fail_state = max_fail_state.max(snap.current_fail_state);
            latest_timestamp = latest_timestamp.max(snap.timestamp_secs);
            count += 1;
        }

        if count == 0 {
            return None;
        }

        let avg_cache_hit_rate = if total_pipe_round_trips > 0 {
            weighted_cache_hits / total_pipe_round_trips as f64
        } else {
            0.0
        };

        let overall_status = if max_fail_state == 2 || total_pipe_round_trips == 0 {
            "critical"
        } else if max_fail_state == 1 || avg_cache_hit_rate < 0.80 {
            "degraded"
        } else {
            "healthy"
        };

        Some(DashboardHealthSnapshot {
            overall_status: overall_status.to_string(),
            injected_pids: total_injected_pids,
            patched_modules: total_patched_modules,
            pipe_round_trips_60s: total_pipe_round_trips,
            cache_hit_rate_60s: avg_cache_hit_rate,
            fail_state: max_fail_state,
            timestamp_secs: latest_timestamp,
        })
    }

    /// Returns the combined rolling history for all agents.
    ///
    /// Results are sorted by `timestamp_secs` descending (most recent first)
    /// and capped at `limit`.
    ///
    /// # Arguments
    ///
    /// * `limit` — maximum number of history entries to return.
    #[must_use]
    pub fn get_history(&self, limit: usize) -> Vec<HookHealthSnapshot> {
        let mut all: Vec<HookHealthSnapshot> = self
            .snapshots
            .iter()
            .flat_map(|entry| {
                let record = entry.value();
                record.history.iter().cloned().collect::<Vec<_>>()
            })
            .collect();
        all.sort_by(|a, b| b.timestamp_secs.cmp(&a.timestamp_secs));
        all.into_iter().take(limit).collect()
    }

    /// Returns the number of agent keys currently tracked.
    #[must_use]
    pub fn agent_count(&self) -> usize {
        self.snapshots.len()
    }
}

impl Default for HealthSnapshotStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snapshot(
        injected_pids: u64,
        patched_modules: u64,
        pipe_trips: u64,
        hit_rate: f64,
        fail_state: u8,
        timestamp_secs: u64,
    ) -> HookHealthSnapshot {
        HookHealthSnapshot {
            injected_pids,
            patched_modules,
            pipe_round_trips_60s: pipe_trips,
            cache_hit_rate_60s: hit_rate,
            current_fail_state: fail_state,
            timestamp_secs,
        }
    }

    #[test]
    fn test_ingest_and_latest() {
        let store = HealthSnapshotStore::new();
        let snap = make_snapshot(1, 2, 10, 0.85, 0, 100);
        store.ingest("agent-1", snap.clone());

        let dashboard = store.get_dashboard_snapshot().expect("should have snapshot");
        assert_eq!(dashboard.overall_status, "healthy");
        assert_eq!(dashboard.injected_pids, 1);
        assert_eq!(dashboard.patched_modules, 2);
        assert_eq!(dashboard.pipe_round_trips_60s, 10);
        assert!((dashboard.cache_hit_rate_60s - 0.85).abs() < f64::EPSILON);
        assert_eq!(dashboard.fail_state, 0);
        assert_eq!(dashboard.timestamp_secs, 100);
    }

    #[test]
    fn test_history_eviction() {
        let store = HealthSnapshotStore::with_capacity(3);
        for i in 0..5 {
            store.ingest("agent-1", make_snapshot(1, 1, 1, 0.9, 0, 100 + i));
        }

        let history = store.get_history(100);
        assert_eq!(history.len(), 3);
        // Newest entries retained.
        assert_eq!(history[0].timestamp_secs, 104);
        assert_eq!(history[2].timestamp_secs, 102);
    }

    #[test]
    fn test_empty_store_returns_none() {
        let store = HealthSnapshotStore::new();
        assert!(store.get_dashboard_snapshot().is_none());
        assert!(store.get_history(10).is_empty());
    }

    #[test]
    fn test_multi_agent_aggregation() {
        let store = HealthSnapshotStore::new();
        store.ingest("agent-1", make_snapshot(2, 4, 100, 0.9, 0, 100));
        store.ingest("agent-2", make_snapshot(3, 6, 200, 0.7, 0, 200));

        let dashboard = store.get_dashboard_snapshot().expect("should aggregate");
        assert_eq!(dashboard.injected_pids, 5);
        assert_eq!(dashboard.patched_modules, 10);
        assert_eq!(dashboard.pipe_round_trips_60s, 300);
        // Weighted average: (0.9*100 + 0.7*200) / 300 = 230/300 = 0.7666...
        assert!((dashboard.cache_hit_rate_60s - (230.0 / 300.0)).abs() < 0.0001);
        assert_eq!(dashboard.fail_state, 0);
        assert_eq!(dashboard.overall_status, "degraded");
        assert_eq!(dashboard.timestamp_secs, 200);
    }

    #[test]
    fn test_fail_state_critical() {
        let store = HealthSnapshotStore::new();
        store.ingest("agent-1", make_snapshot(1, 1, 100, 0.9, 2, 100));

        let dashboard = store.get_dashboard_snapshot().expect("should have snapshot");
        assert_eq!(dashboard.fail_state, 2);
        assert_eq!(dashboard.overall_status, "critical");
    }

    #[test]
    fn test_zero_pipe_trips_critical() {
        let store = HealthSnapshotStore::new();
        store.ingest("agent-1", make_snapshot(1, 1, 0, 0.95, 0, 100));

        let dashboard = store.get_dashboard_snapshot().expect("should have snapshot");
        assert_eq!(dashboard.overall_status, "critical");
    }

    #[test]
    fn test_degraded_by_fail_state() {
        let store = HealthSnapshotStore::new();
        store.ingest("agent-1", make_snapshot(1, 1, 100, 0.95, 1, 100));

        let dashboard = store.get_dashboard_snapshot().expect("should have snapshot");
        assert_eq!(dashboard.fail_state, 1);
        assert_eq!(dashboard.overall_status, "degraded");
    }

    #[test]
    fn test_history_sorted_descending_and_limited() {
        let store = HealthSnapshotStore::new();
        store.ingest("agent-1", make_snapshot(1, 1, 1, 0.9, 0, 300));
        store.ingest("agent-1", make_snapshot(1, 1, 1, 0.9, 0, 100));
        store.ingest("agent-2", make_snapshot(1, 1, 1, 0.9, 0, 200));

        let history = store.get_history(2);
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].timestamp_secs, 300);
        assert_eq!(history[1].timestamp_secs, 200);
    }

    #[test]
    fn test_max_keys_eviction() {
        let store = HealthSnapshotStore::with_caps(10, 2);
        store.ingest("agent-1", make_snapshot(1, 1, 1, 0.9, 0, 100));
        store.ingest("agent-2", make_snapshot(1, 1, 1, 0.9, 0, 200));
        store.ingest("agent-3", make_snapshot(1, 1, 1, 0.9, 0, 300));

        assert_eq!(store.agent_count(), 2);
        // Oldest agent evicted.
        assert!(store.get_dashboard_snapshot().expect("snapshot").timestamp_secs != 100);
    }
}
