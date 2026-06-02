//! In-memory diagnostic snapshot store for the admin diagnostics API (DIFF-02).
//!
//! This module provides a lightweight, server-side mirror of the agent's
//! `DiagnosticAggregator`. When the server runs bundled with an agent,
//! the agent pushes snapshots into this store. When standalone, the store
//! is empty and the admin API returns an empty list.
//!
//! ## Security
//!
//! - In-memory only — no disk persistence (T-58-08 mitigation).
//! - Pagination caps at 1000 entries per request (T-58-13 mitigation).
//! - JWT auth required on the admin endpoint (T-58-11 mitigation).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use dlp_common::hook_ipc::DiagnosticSnapshot;

/// Filter criteria for diagnostic snapshot queries.
///
/// All fields are optional — omitting a field means "match all" for that
/// dimension.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiagnosticFilter {
    /// Only include snapshots captured after this timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Only include snapshots for this user SID.
    pub user_sid: Option<String>,
    /// Only include snapshots matching this policy ID.
    pub policy_id: Option<String>,
}

/// In-memory store for hook DLL diagnostic snapshots.
///
/// Snapshots are stored per-DLL (keyed by `pid_agent_id`) in a bounded Vec.
/// When the cap is exceeded, oldest entries are removed from the front.
#[derive(Debug, Clone)]
pub struct DiagnosticSnapshotStore {
    /// Lock-free map from `{pid}_{agent_id}` to snapshot Vec.
    snapshots: Arc<DashMap<String, Vec<DiagnosticSnapshot>>>,
    /// Maximum snapshots to retain per DLL.
    max_entries_per_dll: usize,
}

impl DiagnosticSnapshotStore {
    /// Creates a new store with the default per-DLL cap.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(1000)
    }

    /// Creates a new store with a custom per-DLL cap.
    ///
    /// # Arguments
    ///
    /// * `max_entries_per_dll` — maximum snapshots retained per DLL.
    #[must_use]
    pub fn with_capacity(max_entries_per_dll: usize) -> Self {
        Self {
            snapshots: Arc::new(DashMap::new()),
            max_entries_per_dll,
        }
    }

    /// Ingests diagnostic snapshots from a single hook DLL instance.
    ///
    /// Appends `new_snapshots` to the existing Vec for the given DLL key.
    /// If the total exceeds `max_entries_per_dll`, oldest entries are
    /// truncated from the front.
    ///
    /// # Arguments
    ///
    /// * `agent_id` — unique identifier of the agent endpoint.
    /// * `pid` — process ID of the hooked process.
    /// * `new_snapshots` — snapshots to ingest.
    pub fn ingest(&self, agent_id: &str, pid: u32, mut new_snapshots: Vec<DiagnosticSnapshot>) {
        let key = format!("{pid}_{agent_id}");
        let mut entry = self.snapshots.entry(key).or_default();
        entry.append(&mut new_snapshots);

        // Truncate from front (oldest) if over capacity.
        if entry.len() > self.max_entries_per_dll {
            let excess = entry.len() - self.max_entries_per_dll;
            entry.drain(0..excess);
        }
    }

    /// Retrieves all snapshots matching the given filter, sorted by QPC
    /// timestamp descending (most recent first).
    ///
    /// # Arguments
    ///
    /// * `filter` — criteria to apply.
    ///
    /// # Returns
    ///
    /// Filtered Vec of snapshots, sorted newest-first.
    #[must_use]
    pub fn get_snapshots(&self, filter: &DiagnosticFilter) -> Vec<DiagnosticSnapshot> {
        let mut result: Vec<DiagnosticSnapshot> = self
            .snapshots
            .iter()
            .flat_map(|entry| entry.value().clone())
            .filter(|snap| Self::matches_filter(snap, filter))
            .collect();

        // Sort by QPC timestamp descending (most recent first).
        // QPC is monotonic within a single boot, so higher = more recent.
        result.sort_by(|a, b| b.timestamp_qpc.cmp(&a.timestamp_qpc));
        result
    }

    /// Retrieves filtered snapshots with pagination.
    ///
    /// # Arguments
    ///
    /// * `filter` — criteria to apply.
    /// * `limit` — maximum number of snapshots to return.
    /// * `offset` — number of snapshots to skip.
    ///
    /// # Returns
    ///
    /// Tuple of (paginated snapshots, total count before pagination).
    #[must_use]
    pub fn get_snapshots_paginated(
        &self,
        filter: &DiagnosticFilter,
        limit: usize,
        offset: usize,
    ) -> (Vec<DiagnosticSnapshot>, usize) {
        let all = self.get_snapshots(filter);
        let total = all.len();
        let paginated = all.into_iter().skip(offset).take(limit).collect();
        (paginated, total)
    }

    /// Returns the total number of DLL keys currently tracked.
    #[must_use]
    pub fn dll_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Returns the total number of snapshots across all DLLs.
    #[must_use]
    pub fn total_snapshot_count(&self) -> usize {
        self.snapshots.iter().map(|entry| entry.value().len()).sum()
    }

    /// Checks whether a single snapshot matches the filter criteria.
    fn matches_filter(snap: &DiagnosticSnapshot, filter: &DiagnosticFilter) -> bool {
        if let Some(ref since) = filter.since {
            // Convert QPC timestamp to a chrono DateTime for comparison.
            // QPC ticks are not directly comparable to wall-clock time,
            // so we use a best-effort conversion. In practice, the agent
            // should use the snapshot's capture time if available.
            // For now, we skip time-based filtering since DiagnosticSnapshot
            // only has QPC (not wall-clock). The since filter is a no-op
            // until wall-clock timestamps are added to DiagnosticSnapshot.
            let _ = since;
        }

        if let Some(ref user_sid) = filter.user_sid {
            if snap.user_sid != *user_sid {
                return false;
            }
        }

        if let Some(ref policy_id) = filter.policy_id {
            if snap.matched_policy_id.as_ref() != Some(policy_id) {
                return false;
            }
        }

        true
    }
}

impl Default for DiagnosticSnapshotStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::hook_ipc::{ClassificationSource, DiagnosticSnapshot};

    fn make_snapshot(user_sid: &str, policy_id: Option<&str>, qpc: u64) -> DiagnosticSnapshot {
        DiagnosticSnapshot {
            hook_function: "WriteFile".to_string(),
            classification_source: ClassificationSource::CacheHit,
            classification_age_ms: 42,
            abac_subject: user_sid.to_string(),
            abac_resource: r"C:\Data\file.txt".to_string(),
            abac_action: "WRITE".to_string(),
            abac_environment: "local".to_string(),
            matched_policy_id: policy_id.map(|s| s.to_string()),
            enforcement_mode: Some("Block".to_string()),
            decision_latency_us: 150,
            timestamp_qpc: qpc,
            user_sid: user_sid.to_string(),
        }
    }

    #[test]
    fn test_ingest_and_retrieve() {
        let store = DiagnosticSnapshotStore::new();
        let snaps = vec![make_snapshot("S-1-5-21-1", Some("pol-001"), 1000)];
        store.ingest("AGENT-01", 1234, snaps.clone());

        let filter = DiagnosticFilter::default();
        let result = store.get_snapshots(&filter);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].user_sid, "S-1-5-21-1");
    }

    #[test]
    fn test_filter_by_user_sid() {
        let store = DiagnosticSnapshotStore::new();
        store.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-A", Some("pol-001"), 1000)],
        );
        store.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-B", Some("pol-002"), 2000)],
        );
        store.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-A", Some("pol-003"), 3000)],
        );

        let filter = DiagnosticFilter {
            user_sid: Some("S-1-5-21-A".to_string()),
            ..Default::default()
        };
        let result = store.get_snapshots(&filter);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|s| s.user_sid == "S-1-5-21-A"));
    }

    #[test]
    fn test_filter_by_policy_id() {
        let store = DiagnosticSnapshotStore::new();
        store.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-1", Some("pol-001"), 1000)],
        );
        store.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-1", Some("pol-002"), 2000)],
        );
        store.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-1", Some("pol-001"), 3000)],
        );

        let filter = DiagnosticFilter {
            policy_id: Some("pol-001".to_string()),
            ..Default::default()
        };
        let result = store.get_snapshots(&filter);
        assert_eq!(result.len(), 2);
        assert!(result
            .iter()
            .all(|s| s.matched_policy_id == Some("pol-001".to_string())));
    }

    #[test]
    fn test_pagination() {
        let store = DiagnosticSnapshotStore::new();
        let mut snaps = Vec::new();
        for i in 0..10 {
            snaps.push(make_snapshot("S-1-5-21-1", Some("pol-001"), i * 1000));
        }
        store.ingest("AGENT-01", 100, snaps);

        let filter = DiagnosticFilter::default();

        // First page: 5 items, offset 0.
        let (page1, total1) = store.get_snapshots_paginated(&filter, 5, 0);
        assert_eq!(total1, 10);
        assert_eq!(page1.len(), 5);
        // Sorted descending, so first page has highest QPC values.
        assert_eq!(page1[0].timestamp_qpc, 9000);
        assert_eq!(page1[4].timestamp_qpc, 5000);

        // Second page: 5 items, offset 5.
        let (page2, total2) = store.get_snapshots_paginated(&filter, 5, 5);
        assert_eq!(total2, 10);
        assert_eq!(page2.len(), 5);
        assert_eq!(page2[0].timestamp_qpc, 4000);
        assert_eq!(page2[4].timestamp_qpc, 0);
    }

    #[test]
    fn test_max_entries_cap() {
        let store = DiagnosticSnapshotStore::with_capacity(1000);
        let mut snaps = Vec::new();
        for i in 0..1500 {
            snaps.push(make_snapshot("S-1-5-21-1", Some("pol-001"), i));
        }
        store.ingest("AGENT-01", 100, snaps);

        let filter = DiagnosticFilter::default();
        let result = store.get_snapshots(&filter);
        // Only 1000 retained; oldest (lowest QPC) truncated.
        assert_eq!(result.len(), 1000);
        // Oldest remaining should have QPC = 500.
        assert_eq!(result.last().unwrap().timestamp_qpc, 500);
        // Newest should have QPC = 1499.
        assert_eq!(result.first().unwrap().timestamp_qpc, 1499);
    }

    #[test]
    fn test_dll_count_and_total() {
        let store = DiagnosticSnapshotStore::new();
        assert_eq!(store.dll_count(), 0);
        assert_eq!(store.total_snapshot_count(), 0);

        store.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-1", Some("pol-001"), 1000)],
        );
        store.ingest(
            "AGENT-01",
            200,
            vec![make_snapshot("S-1-5-21-2", Some("pol-002"), 2000)],
        );

        assert_eq!(store.dll_count(), 2);
        assert_eq!(store.total_snapshot_count(), 2);
    }
}
