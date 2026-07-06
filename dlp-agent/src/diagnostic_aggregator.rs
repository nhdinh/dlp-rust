//! Diagnostic snapshot aggregator for hook DLL diagnostics (DIFF-02).
//!
//! The `DiagnosticAggregator` collects diagnostic snapshots from hook DLLs
//! via named pipe polling, stores them in-memory per-DLL, and provides
//! filtered, paginated retrieval for the admin API.
//!
//! ## Design
//!
//! - Uses `DashMap` for lock-free concurrent snapshot storage.
//! - Key format: `{pid}_{agent_id}` — per-DLL isolation.
//! - Oldest entries truncated when per-DLL cap exceeded.
//! - Filters support `since`, `user_sid`, and `policy_id` per D-11.
//!
//! ## Security
//!
//! - In-memory only — no disk persistence (D-07, T-58-08 mitigation).
//! - Admin API filtering prevents information disclosure.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use dlp_common::hook_ipc::DiagnosticSnapshot;

/// Default maximum snapshots retained per DLL.
const DEFAULT_MAX_ENTRIES_PER_DLL: usize = 1000;

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

/// In-memory aggregator for hook DLL diagnostic snapshots.
///
/// Snapshots are stored per-DLL (keyed by `pid_agent_id`) in a bounded Vec.
/// When the cap is exceeded, oldest entries are removed from the front.
#[derive(Debug, Clone)]
pub struct DiagnosticAggregator {
    /// Lock-free map from `{pid}_{agent_id}` to snapshot Vec.
    snapshots: Arc<DashMap<String, Vec<DiagnosticSnapshot>>>,
    /// Maximum snapshots to retain per DLL.
    max_entries_per_dll: usize,
}

impl DiagnosticAggregator {
    /// Creates a new aggregator with the default per-DLL cap.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_ENTRIES_PER_DLL)
    }

    /// Creates a new aggregator with a custom per-DLL cap.
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
            // `timestamp_secs` is a wall-clock Unix timestamp captured by the
            // hook DLL when the snapshot is created. Snapshots captured before
            // the requested window are excluded.
            let since_secs = since.timestamp().max(0) as u64;
            if snap.timestamp_secs < since_secs {
                return false;
            }
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

impl Default for DiagnosticAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::hook_ipc::{ClassificationSource, DiagnosticSnapshot};

    fn make_snapshot(user_sid: &str, policy_id: Option<&str>, qpc: u64) -> DiagnosticSnapshot {
        make_snapshot_with_secs(user_sid, policy_id, qpc, qpc)
    }

    fn make_snapshot_with_secs(
        user_sid: &str,
        policy_id: Option<&str>,
        qpc: u64,
        secs: u64,
    ) -> DiagnosticSnapshot {
        DiagnosticSnapshot {
            hook_function: "WriteFile".to_string(),
            classification_source: ClassificationSource::CacheHit,
            classification_age_ms: 42,
            abac_resource: r"C:\Data\file.txt".to_string(),
            abac_action: "WRITE".to_string(),
            abac_environment: "local".to_string(),
            matched_policy_id: policy_id.map(|s| s.to_string()),
            enforcement_mode: Some("Block".to_string()),
            decision_latency_us: 150,
            timestamp_qpc: qpc,
            timestamp_secs: secs,
            user_sid: user_sid.to_string(),
        }
    }

    #[test]
    fn test_ingest_and_retrieve() {
        let agg = DiagnosticAggregator::new();
        let snaps = vec![make_snapshot("S-1-5-21-1", Some("pol-001"), 1000)];
        agg.ingest("AGENT-01", 1234, snaps.clone());

        let filter = DiagnosticFilter::default();
        let result = agg.get_snapshots(&filter);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].user_sid, "S-1-5-21-1");
    }

    #[test]
    fn test_ingest_multiple_dlls() {
        let agg = DiagnosticAggregator::new();
        agg.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-1", Some("pol-001"), 1000)],
        );
        agg.ingest(
            "AGENT-01",
            200,
            vec![make_snapshot("S-1-5-21-2", Some("pol-002"), 2000)],
        );
        agg.ingest(
            "AGENT-01",
            300,
            vec![make_snapshot("S-1-5-21-3", Some("pol-003"), 3000)],
        );

        let filter = DiagnosticFilter::default();
        let result = agg.get_snapshots(&filter);
        assert_eq!(result.len(), 3);
        // Should be sorted by QPC descending.
        assert_eq!(result[0].timestamp_qpc, 3000);
        assert_eq!(result[1].timestamp_qpc, 2000);
        assert_eq!(result[2].timestamp_qpc, 1000);
    }

    #[test]
    fn test_filter_by_user_sid() {
        let agg = DiagnosticAggregator::new();
        agg.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-A", Some("pol-001"), 1000)],
        );
        agg.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-B", Some("pol-002"), 2000)],
        );
        agg.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-A", Some("pol-003"), 3000)],
        );

        let filter = DiagnosticFilter {
            user_sid: Some("S-1-5-21-A".to_string()),
            ..Default::default()
        };
        let result = agg.get_snapshots(&filter);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|s| s.user_sid == "S-1-5-21-A"));
    }

    #[test]
    fn test_filter_by_policy_id() {
        let agg = DiagnosticAggregator::new();
        agg.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-1", Some("pol-001"), 1000)],
        );
        agg.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-1", Some("pol-002"), 2000)],
        );
        agg.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-1", Some("pol-001"), 3000)],
        );

        let filter = DiagnosticFilter {
            policy_id: Some("pol-001".to_string()),
            ..Default::default()
        };
        let result = agg.get_snapshots(&filter);
        assert_eq!(result.len(), 2);
        assert!(result
            .iter()
            .all(|s| s.matched_policy_id == Some("pol-001".to_string())));
    }

    #[test]
    fn test_filter_by_since() {
        let agg = DiagnosticAggregator::new();
        agg.ingest(
            "AGENT-01",
            100,
            vec![
                make_snapshot_with_secs("S-1-5-21-1", Some("pol-001"), 1000, 100),
                make_snapshot_with_secs("S-1-5-21-1", Some("pol-001"), 2000, 200),
                make_snapshot_with_secs("S-1-5-21-1", Some("pol-001"), 3000, 300),
            ],
        );

        let since = DateTime::from_timestamp(150, 0).expect("valid timestamp");
        let filter = DiagnosticFilter {
            since: Some(since),
            ..Default::default()
        };
        let result = agg.get_snapshots(&filter);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|s| s.timestamp_secs >= 150));
    }

    #[test]
    fn test_pagination() {
        let agg = DiagnosticAggregator::new();
        let mut snaps = Vec::new();
        for i in 0..10 {
            snaps.push(make_snapshot("S-1-5-21-1", Some("pol-001"), i * 1000));
        }
        agg.ingest("AGENT-01", 100, snaps);

        let filter = DiagnosticFilter::default();

        // First page: 5 items, offset 0.
        let (page1, total1) = agg.get_snapshots_paginated(&filter, 5, 0);
        assert_eq!(total1, 10);
        assert_eq!(page1.len(), 5);
        // Sorted descending, so first page has highest QPC values.
        assert_eq!(page1[0].timestamp_qpc, 9000);
        assert_eq!(page1[4].timestamp_qpc, 5000);

        // Second page: 5 items, offset 5.
        let (page2, total2) = agg.get_snapshots_paginated(&filter, 5, 5);
        assert_eq!(total2, 10);
        assert_eq!(page2.len(), 5);
        assert_eq!(page2[0].timestamp_qpc, 4000);
        assert_eq!(page2[4].timestamp_qpc, 0);
    }

    #[test]
    fn test_max_entries_cap() {
        let agg = DiagnosticAggregator::with_capacity(1000);
        let mut snaps = Vec::new();
        for i in 0..1500 {
            snaps.push(make_snapshot("S-1-5-21-1", Some("pol-001"), i));
        }
        agg.ingest("AGENT-01", 100, snaps);

        let filter = DiagnosticFilter::default();
        let result = agg.get_snapshots(&filter);
        // Only 1000 retained; oldest (lowest QPC) truncated.
        assert_eq!(result.len(), 1000);
        // Oldest remaining should have QPC = 500.
        assert_eq!(result.last().unwrap().timestamp_qpc, 500);
        // Newest should have QPC = 1499.
        assert_eq!(result.first().unwrap().timestamp_qpc, 1499);
    }

    #[test]
    fn test_dll_count_and_total() {
        let agg = DiagnosticAggregator::new();
        assert_eq!(agg.dll_count(), 0);
        assert_eq!(agg.total_snapshot_count(), 0);

        agg.ingest(
            "AGENT-01",
            100,
            vec![make_snapshot("S-1-5-21-1", Some("pol-001"), 1000)],
        );
        agg.ingest(
            "AGENT-01",
            200,
            vec![make_snapshot("S-1-5-21-2", Some("pol-002"), 2000)],
        );

        assert_eq!(agg.dll_count(), 2);
        assert_eq!(agg.total_snapshot_count(), 2);
    }
}
