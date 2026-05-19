//! Process lifecycle registry with PID-reuse-safe composite keys.
//!
//! The registry uses `(PID, creation_time)` as the composite key to prevent
//! false "already injected" states when Windows recycles PIDs rapidly.
//! All state transitions are atomic via DashMap entry API.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;

/// Unique identifier for a process instance: PID + creation time (from ETW or OpenProcess).
/// The creation_time (u64, FILETIME) distinguishes PID reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    pub pid: u32,
    pub creation_time: u64,
}

/// Reason a process was skipped (allowlisted or failed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    SelfProcess,
    Avedr,
    SystemCritical,
    Ppl(PplOutcome),
    WoW64,
    OperatorDefined,
    Failed(InjectionFailure),
}

/// Explicit PPL classification outcomes (review fix: no catch-all AccessDenied -> PPL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PplOutcome {
    /// Confirmed protected via GetProcessMitigationPolicy.
    Protected,
    /// OpenProcess succeeded but GetProcessMitigationPolicy returned non-zero.
    LikelyProtectedAccessDenied,
    /// Could not query policy (API failure, not necessarily protected).
    QueryFailed,
    /// Confirmed not protected.
    NotProtected,
}

/// Injection failure categories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionFailure {
    AccessDenied,
    RemoteThreadFailed,
    InjectionFailed,
    Timeout,
}

/// Process lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessState {
    /// Discovered but not yet processed.
    Discovered,
    /// Explicitly skipped (allowlisted or failed).
    Skipped(SkipReason),
    /// Successfully injected with architecture and timestamps.
    Injected {
        arch: String,
        injected_at: Instant,
        hello_received_at: Option<Instant>,
    },
    /// Process exited.
    Exited,
}

/// Result of an atomic claim attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimResult {
    /// This caller won the race and should proceed with injection.
    Claimed,
    /// Another thread already claimed or processed this PID.
    AlreadyClaimed(ProcessState),
}

/// Lock-free process lifecycle registry.
///
/// Uses `DashMap` for concurrent access across ETW callback threads,
/// tokio injection tasks, and cleanup sweeps.
#[derive(Debug, Clone)]
pub struct ProcessRegistry {
    states: Arc<DashMap<ProcessKey, ProcessState>>,
}

impl ProcessRegistry {
    /// Creates a new empty process registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            states: Arc::new(DashMap::new()),
        }
    }

    /// Atomically attempt to claim a PID for injection.
    ///
    /// Returns `Claimed` if this caller should proceed; `AlreadyClaimed` if not.
    /// This prevents the race between ETW, WMI, startup sweep, and periodic sweep.
    ///
    /// # Arguments
    ///
    /// * `key` — The `(pid, creation_time)` composite key identifying the process.
    pub fn try_claim(&self, key: ProcessKey) -> ClaimResult {
        use dashmap::mapref::entry::Entry;
        match self.states.entry(key) {
            Entry::Vacant(e) => {
                e.insert(ProcessState::Discovered);
                ClaimResult::Claimed
            }
            Entry::Occupied(e) => ClaimResult::AlreadyClaimed(e.get().clone()),
        }
    }

    /// Transition a claimed PID to Injected state.
    ///
    /// # Arguments
    ///
    /// * `key` — The process key.
    /// * `arch` — Architecture string (e.g., "x64" or "x86").
    pub fn record_injected(&self, key: ProcessKey, arch: String) {
        self.states.insert(
            key,
            ProcessState::Injected {
                arch,
                injected_at: Instant::now(),
                hello_received_at: None,
            },
        );
    }

    /// Record that a hello message was received from the injected DLL.
    ///
    /// # Arguments
    ///
    /// * `key` — The process key.
    pub fn record_hello(&self, key: ProcessKey) {
        if let Some(mut entry) = self.states.get_mut(&key) {
            if let ProcessState::Injected {
                ref mut hello_received_at,
                ..
            } = *entry.value_mut()
            {
                *hello_received_at = Some(Instant::now());
            }
        }
    }

    /// Record skip reason.
    ///
    /// # Arguments
    ///
    /// * `key` — The process key.
    /// * `reason` — Why the process was skipped.
    pub fn record_skipped(&self, key: ProcessKey, reason: SkipReason) {
        self.states.insert(key, ProcessState::Skipped(reason));
    }

    /// Record process exit.
    ///
    /// # Arguments
    ///
    /// * `key` — The process key.
    pub fn record_exited(&self, key: ProcessKey) {
        self.states.insert(key, ProcessState::Exited);
    }

    /// Get state for a key.
    ///
    /// # Arguments
    ///
    /// * `key` — The process key to look up.
    pub fn get(
        &self,
        key: &ProcessKey,
    ) -> Option<dashmap::mapref::one::Ref<'_, ProcessKey, ProcessState>> {
        self.states.get(key)
    }

    /// Remove exited PIDs (called by cleanup sweep).
    ///
    /// Returns the number of entries removed.
    pub fn prune_exited(&self) -> usize {
        let to_remove: Vec<ProcessKey> = self
            .states
            .iter()
            .filter(|entry| matches!(entry.value(), ProcessState::Exited))
            .map(|entry| *entry.key())
            .collect();
        let count = to_remove.len();
        for key in to_remove {
            self.states.remove(&key);
        }
        count
    }

    /// Count processes in each state for telemetry.
    #[must_use]
    pub fn counts(&self) -> ProcessCounts {
        let mut counts = ProcessCounts::default();
        for entry in self.states.iter() {
            match entry.value() {
                ProcessState::Discovered => counts.discovered += 1,
                ProcessState::Skipped(ref r) => match r {
                    SkipReason::SelfProcess => counts.skipped_self += 1,
                    SkipReason::Avedr => counts.skipped_avedr += 1,
                    SkipReason::SystemCritical => counts.skipped_system += 1,
                    SkipReason::Ppl(_) => counts.skipped_ppl += 1,
                    SkipReason::WoW64 => counts.skipped_wow64 += 1,
                    SkipReason::OperatorDefined => counts.skipped_operator += 1,
                    SkipReason::Failed(_) => counts.skipped_failed += 1,
                },
                ProcessState::Injected {
                    hello_received_at: Some(_),
                    ..
                } => counts.injected_hello += 1,
                ProcessState::Injected {
                    hello_received_at: None,
                    ..
                } => counts.injected_no_hello += 1,
                ProcessState::Exited => counts.exited += 1,
            }
        }
        counts
    }

    /// Returns a telemetry snapshot with coverage metrics.
    ///
    /// Coverage percent = injected / (injected + skipped_non_ppl + failed) * 100.0.
    /// PPL skips are expected and not counted as coverage gaps.
    #[must_use]
    pub fn telemetry_snapshot(&self) -> InjectionTelemetry {
        let counts = self.counts();
        let injected = counts.injected_hello + counts.injected_no_hello;
        let skipped_non_ppl = counts.skipped_self
            + counts.skipped_avedr
            + counts.skipped_system
            + counts.skipped_wow64
            + counts.skipped_operator;
        let failed = counts.skipped_failed;
        let denominator = injected + skipped_non_ppl + failed;
        let coverage_percent = if denominator == 0 {
            0.0
        } else {
            (injected as f64 / denominator as f64) * 100.0
        };
        let total_tracked = self.states.len();
        InjectionTelemetry {
            injected_count: injected as usize,
            skipped_by_reason: counts.skipped_by_reason(),
            total_tracked,
            coverage_percent,
        }
    }
}

impl Default for ProcessRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregated counts of processes in each state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessCounts {
    pub discovered: u64,
    pub skipped_self: u64,
    pub skipped_avedr: u64,
    pub skipped_system: u64,
    pub skipped_ppl: u64,
    pub skipped_wow64: u64,
    pub skipped_operator: u64,
    pub skipped_failed: u64,
    pub injected_hello: u64,
    pub injected_no_hello: u64,
    pub exited: u64,
}

impl ProcessCounts {
    /// Returns a HashMap of skip reasons to their counts.
    #[must_use]
    pub fn skipped_by_reason(&self) -> std::collections::HashMap<SkipReasonCategory, usize> {
        let mut map = std::collections::HashMap::new();
        map.insert(SkipReasonCategory::SelfProcess, self.skipped_self as usize);
        map.insert(SkipReasonCategory::Avedr, self.skipped_avedr as usize);
        map.insert(
            SkipReasonCategory::SystemCritical,
            self.skipped_system as usize,
        );
        map.insert(SkipReasonCategory::Ppl, self.skipped_ppl as usize);
        map.insert(SkipReasonCategory::WoW64, self.skipped_wow64 as usize);
        map.insert(
            SkipReasonCategory::OperatorDefined,
            self.skipped_operator as usize,
        );
        map.insert(SkipReasonCategory::Failed, self.skipped_failed as usize);
        map
    }
}

/// Categorised skip reason for telemetry aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkipReasonCategory {
    SelfProcess,
    Avedr,
    SystemCritical,
    Ppl,
    WoW64,
    OperatorDefined,
    Failed,
}

/// Telemetry snapshot with coverage metrics.
#[derive(Debug, Clone)]
pub struct InjectionTelemetry {
    /// Number of successfully injected processes.
    pub injected_count: usize,
    /// Skip counts by reason category.
    pub skipped_by_reason: std::collections::HashMap<SkipReasonCategory, usize>,
    /// Total number of tracked processes.
    pub total_tracked: usize,
    /// Coverage percentage (injected / (injected + non-PPL skipped + failed) * 100).
    pub coverage_percent: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_claim_first_call_returns_claimed() {
        let registry = ProcessRegistry::new();
        let key = ProcessKey {
            pid: 1234,
            creation_time: 1,
        };
        let result = registry.try_claim(key);
        assert_eq!(result, ClaimResult::Claimed);
    }

    #[test]
    fn test_try_claim_second_call_returns_already_claimed() {
        let registry = ProcessRegistry::new();
        let key = ProcessKey {
            pid: 1234,
            creation_time: 1,
        };
        let first = registry.try_claim(key);
        assert_eq!(first, ClaimResult::Claimed);

        let second = registry.try_claim(key);
        assert!(
            matches!(
                second,
                ClaimResult::AlreadyClaimed(ProcessState::Discovered)
            ),
            "expected AlreadyClaimed(Discovered), got {:?}",
            second
        );
    }

    #[test]
    fn test_record_injected_and_record_hello() {
        let registry = ProcessRegistry::new();
        let key = ProcessKey {
            pid: 1234,
            creation_time: 1,
        };
        registry.try_claim(key);
        registry.record_injected(key, "x64".to_string());

        // Verify injected state without hello.
        {
            let state = registry.get(&key).expect("key should exist");
            let is_injected_no_hello = matches!(
                &*state,
                ProcessState::Injected {
                    ref arch,
                    hello_received_at: None,
                    ..
                } if arch == "x64"
            );
            assert!(is_injected_no_hello, "expected Injected with no hello");
        }

        registry.record_hello(key);

        // Verify injected state with hello.
        {
            let state = registry.get(&key).expect("key should exist");
            let is_injected_with_hello = matches!(
                &*state,
                ProcessState::Injected {
                    ref arch,
                    hello_received_at: Some(_),
                    ..
                } if arch == "x64"
            );
            assert!(is_injected_with_hello, "expected Injected with hello");
        }
    }

    #[test]
    fn test_record_skipped_all_variants() {
        let registry = ProcessRegistry::new();

        let variants = vec![
            (SkipReason::SelfProcess, "self"),
            (SkipReason::Avedr, "avedr"),
            (SkipReason::SystemCritical, "system"),
            (SkipReason::Ppl(PplOutcome::Protected), "ppl"),
            (SkipReason::WoW64, "wow64"),
            (SkipReason::OperatorDefined, "operator"),
            (SkipReason::Failed(InjectionFailure::AccessDenied), "failed"),
        ];

        for (i, (reason, _label)) in variants.into_iter().enumerate() {
            let key = ProcessKey {
                pid: 1000 + i as u32,
                creation_time: i as u64,
            };
            registry.try_claim(key);
            registry.record_skipped(key, reason.clone());

            let state = registry.get(&key).expect("key should exist");
            assert!(
                matches!(&*state, ProcessState::Skipped(r) if std::mem::discriminant(r) == std::mem::discriminant(&reason)),
                "expected Skipped variant at index {}",
                i
            );
        }
    }

    #[test]
    fn test_record_exited() {
        let registry = ProcessRegistry::new();
        let key = ProcessKey {
            pid: 1234,
            creation_time: 1,
        };
        registry.try_claim(key);
        registry.record_exited(key);

        let state = registry.get(&key).expect("key should exist");
        assert_eq!(*state, ProcessState::Exited);
    }

    #[test]
    fn test_counts_are_correct() {
        let registry = ProcessRegistry::new();

        // Discovered: 1
        let key_discovered = ProcessKey {
            pid: 1000,
            creation_time: 1,
        };
        registry.try_claim(key_discovered);

        // Injected with hello: 1
        let key_injected_hello = ProcessKey {
            pid: 1001,
            creation_time: 2,
        };
        registry.try_claim(key_injected_hello);
        registry.record_injected(key_injected_hello, "x64".to_string());
        registry.record_hello(key_injected_hello);

        // Injected without hello: 1
        let key_injected_no_hello = ProcessKey {
            pid: 1002,
            creation_time: 3,
        };
        registry.try_claim(key_injected_no_hello);
        registry.record_injected(key_injected_no_hello, "x86".to_string());

        // Skipped (self): 1
        let key_skipped_self = ProcessKey {
            pid: 1003,
            creation_time: 4,
        };
        registry.try_claim(key_skipped_self);
        registry.record_skipped(key_skipped_self, SkipReason::SelfProcess);

        // Exited: 1
        let key_exited = ProcessKey {
            pid: 1004,
            creation_time: 5,
        };
        registry.try_claim(key_exited);
        registry.record_exited(key_exited);

        let counts = registry.counts();
        assert_eq!(counts.discovered, 1);
        assert_eq!(counts.injected_hello, 1);
        assert_eq!(counts.injected_no_hello, 1);
        assert_eq!(counts.skipped_self, 1);
        assert_eq!(counts.exited, 1);
        assert_eq!(counts.skipped_avedr, 0);
        assert_eq!(counts.skipped_system, 0);
        assert_eq!(counts.skipped_ppl, 0);
        assert_eq!(counts.skipped_wow64, 0);
        assert_eq!(counts.skipped_operator, 0);
        assert_eq!(counts.skipped_failed, 0);
    }

    #[test]
    fn test_pid_reuse_simulation() {
        // Same PID, different creation_time -> treated as separate entries.
        let registry = ProcessRegistry::new();
        let key1 = ProcessKey {
            pid: 1234,
            creation_time: 1000,
        };
        let key2 = ProcessKey {
            pid: 1234,
            creation_time: 2000,
        };

        registry.try_claim(key1);
        registry.record_injected(key1, "x64".to_string());

        // key2 with different creation_time should be treated as a new process.
        let result = registry.try_claim(key2);
        assert_eq!(result, ClaimResult::Claimed);

        // key1 should still be Injected; key2 should be Discovered.
        assert!(matches!(
            *registry.get(&key1).unwrap(),
            ProcessState::Injected { .. }
        ));
        assert_eq!(*registry.get(&key2).unwrap(), ProcessState::Discovered);
    }

    #[test]
    fn test_prune_exited_removes_exited_entries() {
        let registry = ProcessRegistry::new();

        let key_exited = ProcessKey {
            pid: 1000,
            creation_time: 1,
        };
        let key_injected = ProcessKey {
            pid: 1001,
            creation_time: 2,
        };

        registry.try_claim(key_exited);
        registry.record_exited(key_exited);

        registry.try_claim(key_injected);
        registry.record_injected(key_injected, "x64".to_string());

        assert_eq!(registry.states.len(), 2);
        let removed = registry.prune_exited();
        assert_eq!(removed, 1);
        assert_eq!(registry.states.len(), 1);
        assert!(registry.get(&key_injected).is_some());
        assert!(registry.get(&key_exited).is_none());
    }

    #[test]
    fn test_ppl_outcome_variants() {
        // Verify all four PplOutcome variants exist and are distinct.
        let outcomes = vec![
            PplOutcome::Protected,
            PplOutcome::LikelyProtectedAccessDenied,
            PplOutcome::QueryFailed,
            PplOutcome::NotProtected,
        ];

        for (i, outcome) in outcomes.iter().enumerate() {
            let registry = ProcessRegistry::new();
            let key = ProcessKey {
                pid: 2000 + i as u32,
                creation_time: i as u64,
            };
            registry.try_claim(key);
            registry.record_skipped(key, SkipReason::Ppl(outcome.clone()));

            let state = registry.get(&key).unwrap();
            assert!(
                matches!(&*state, ProcessState::Skipped(SkipReason::Ppl(o)) if std::mem::discriminant(o) == std::mem::discriminant(outcome)),
                "PplOutcome variant mismatch at index {}",
                i
            );
        }
    }
}
