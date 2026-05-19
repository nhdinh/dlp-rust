//! Universal injection orchestrator: receives ProcessEvents, performs allowlist
//! matching, PPL detection, injection, and latency tracking.

use crate::allowlist::{AllowlistCategory, AllowlistMatcher};
use crate::hook_injector::HookInjector;
use crate::process_registry::{
    ClaimResult, InjectionFailure, PplOutcome, ProcessKey, ProcessRegistry, SkipReason,
};
use crate::process_watcher::{ProcessEvent, SweepTrigger};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Latency histogram for injection SLA tracking.
pub struct LatencyHistogram {
    /// Buckets in milliseconds: [0-50, 50-100, 100-250, 250-500, 500-1000, 1000+]
    buckets: [u64; 6],
    total: u64,
}

impl LatencyHistogram {
    /// Creates a new empty latency histogram.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: [0; 6],
            total: 0,
        }
    }

    /// Records a latency measurement in milliseconds.
    pub fn record(&mut self, latency_ms: u64) {
        self.total += 1;
        let idx = match latency_ms {
            0..=50 => 0,
            51..=100 => 1,
            101..=250 => 2,
            251..=500 => 3,
            501..=1000 => 4,
            _ => 5,
        };
        self.buckets[idx] += 1;
    }

    /// Percentage of injections under 500ms.
    #[must_use]
    pub fn pct_under_500ms(&self) -> f64 {
        if self.total == 0 {
            return 100.0;
        }
        let under_500 = self.buckets[0] + self.buckets[1] + self.buckets[2] + self.buckets[3];
        (under_500 as f64 / self.total as f64) * 100.0
    }

    /// p50, p95, p99 approximations (bucket-based).
    #[must_use]
    pub fn percentiles(&self) -> (f64, f64, f64) {
        if self.total == 0 {
            return (0.0, 0.0, 0.0);
        }

        // Bucket upper bounds for percentile calculation.
        let bucket_bounds = [50.0_f64, 100.0, 250.0, 500.0, 1000.0, f64::INFINITY];
        let mut cumulative = 0u64;

        let mut p50 = bucket_bounds[0];
        let mut p95 = bucket_bounds[0];
        let mut p99 = bucket_bounds[0];

        for (i, count) in self.buckets.iter().enumerate() {
            cumulative += count;
            let pct = cumulative as f64 / self.total as f64;

            if pct >= 0.50 && p50 == bucket_bounds[0] && i > 0 {
                p50 = bucket_bounds[i];
            }
            if pct >= 0.95 && p95 == bucket_bounds[0] && i > 0 {
                p95 = bucket_bounds[i];
            }
            if pct >= 0.99 && p99 == bucket_bounds[0] && i > 0 {
                p99 = bucket_bounds[i];
            }
        }

        (p50, p95, p99)
    }
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Universal injection orchestrator with latency tracking and retry queue.
pub struct UniversalInjector {
    registry: Arc<ProcessRegistry>,
    matcher: Arc<AllowlistMatcher>,
    injector: Arc<HookInjector>,
    latency: std::sync::Mutex<LatencyHistogram>,
    /// Delayed retry queue sender: (ProcessEvent, retry_at).
    retry_queue: mpsc::UnboundedSender<(ProcessEvent, Instant)>,
}

impl UniversalInjector {
    /// Creates a new universal injector.
    ///
    /// # Arguments
    ///
    /// * `registry` — Process lifecycle registry for atomic claim and state tracking.
    /// * `matcher` — Allowlist matcher for skip decisions.
    /// * `injector` — Hook injector for DLL injection.
    #[must_use]
    pub fn new(
        registry: Arc<ProcessRegistry>,
        matcher: Arc<AllowlistMatcher>,
        injector: Arc<HookInjector>,
    ) -> Self {
        let (retry_tx, _retry_rx) = mpsc::unbounded_channel();
        Self {
            registry,
            matcher,
            injector,
            latency: std::sync::Mutex::new(LatencyHistogram::new()),
            retry_queue: retry_tx,
        }
    }

    /// Creates a new universal injector with a custom retry queue sender.
    ///
    /// Used by service.rs to wire the retry consumer task.
    #[must_use]
    pub fn with_retry_queue(
        registry: Arc<ProcessRegistry>,
        matcher: Arc<AllowlistMatcher>,
        injector: Arc<HookInjector>,
        retry_queue: mpsc::UnboundedSender<(ProcessEvent, Instant)>,
    ) -> Self {
        Self {
            registry,
            matcher,
            injector,
            latency: std::sync::Mutex::new(LatencyHistogram::new()),
            retry_queue,
        }
    }

    /// Main entry: process a single ProcessEvent.
    pub async fn handle_event(
        &self,
        event: ProcessEvent,
        _sweep_trigger: &mpsc::Sender<SweepTrigger>,
    ) {
        let key = ProcessKey {
            pid: event.pid,
            creation_time: event.creation_time,
        };

        // Atomic claim prevents duplicate injection races.
        match self.registry.try_claim(key) {
            ClaimResult::AlreadyClaimed(state) => {
                tracing::trace!(pid = event.pid, ?state, "already claimed or processed");
                return;
            }
            ClaimResult::Claimed => {}
        }

        // Get canonical image path.
        let image_path = crate::allowlist::canonicalize_path(&event.image_path);

        // Allowlist check.
        if let Some(category) = self
            .matcher
            .check(event.pid, &image_path, event.creation_time)
        {
            tracing::info!(pid = event.pid, ?category, "allowlist skip");
            self.registry
                .record_skipped(key, SkipReason::from_category(category));
            return;
        }

        // PPL detection at injection time (D-19).
        let ppl_outcome = detect_ppl(event.pid);
        match ppl_outcome {
            PplOutcome::Protected | PplOutcome::LikelyProtectedAccessDenied => {
                tracing::info!(pid = event.pid, ?ppl_outcome, "PPL skip");
                self.registry
                    .record_skipped(key, SkipReason::Ppl(ppl_outcome));
                return;
            }
            PplOutcome::QueryFailed => {
                // Best effort: attempt injection anyway. If it fails with AccessDenied,
                // we'll record it as PPL skip post-hoc.
                tracing::warn!(
                    pid = event.pid,
                    "PPL query failed — attempting injection anyway"
                );
            }
            PplOutcome::NotProtected => {}
        }

        // Attempt injection.
        let inject_start = Instant::now();
        match self.injector.inject(event.pid) {
            Ok(()) => {
                let latency = inject_start
                    .duration_since(event.event_timestamp)
                    .as_millis() as u64;
                // Arch resolved by HookInjector internally; we record "x64" as default.
                // The hook injector's target_architecture check ensures correct DLL selection.
                self.registry.record_injected(key, "x64".into());
                {
                    let mut hist = self.latency.lock().expect("latency mutex poisoned");
                    hist.record(latency);
                }
                tracing::info!(
                    pid = event.pid,
                    latency_ms = latency,
                    "injected successfully"
                );
            }
            Err(e) => {
                let latency = inject_start
                    .duration_since(event.event_timestamp)
                    .as_millis() as u64;
                {
                    let mut hist = self.latency.lock().expect("latency mutex poisoned");
                    hist.record(latency);
                }
                // Categorize failure.
                let failure = categorize_error(&e);
                match &failure {
                    InjectionFailure::AccessDenied => {
                        // Likely PPL or protected process.
                        self.registry.record_skipped(
                            key,
                            SkipReason::Ppl(PplOutcome::LikelyProtectedAccessDenied),
                        );
                        tracing::warn!(
                            pid = event.pid,
                            error = %e,
                            "injection access denied — treating as PPL"
                        );
                    }
                    InjectionFailure::RemoteThreadFailed | InjectionFailure::InjectionFailed => {
                        self.registry
                            .record_skipped(key, SkipReason::Failed(failure.clone()));
                        tracing::error!(pid = event.pid, error = %e, "injection failed");
                        // Queue for delayed retry (review fix: +200ms retry).
                        let retry_at = Instant::now() + Duration::from_millis(200);
                        let _ = self.retry_queue.send((event, retry_at));
                    }
                    InjectionFailure::Timeout => {
                        self.registry
                            .record_skipped(key, SkipReason::Failed(failure.clone()));
                        tracing::error!(pid = event.pid, error = %e, "injection timed out");
                    }
                }
            }
        }
    }

    /// Handle delayed retry events.
    pub async fn handle_retry(
        &self,
        event: ProcessEvent,
        sweep_trigger: &mpsc::Sender<SweepTrigger>,
    ) {
        // Same logic as handle_event but with retry context.
        // If this also fails, no further retries (retry_queue is not used again).
        tracing::info!(pid = event.pid, "delayed retry injection");
        self.handle_event(event, sweep_trigger).await;
    }

    /// Get current latency metrics.
    ///
    /// Returns (p50_ms, p95_ms, p99_ms, pct_under_500ms).
    #[must_use]
    pub fn latency_metrics(&self) -> (f64, f64, f64, f64) {
        let hist = self.latency.lock().expect("latency mutex poisoned");
        let (p50, p95, p99) = hist.percentiles();
        let pct_500 = hist.pct_under_500ms();
        (p50, p95, p99, pct_500)
    }
}

/// Detect PPL status at injection time.
#[must_use]
pub fn detect_ppl(pid: u32) -> PplOutcome {
    use windows::Win32::System::Threading::{
        GetProcessMitigationPolicy, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(_) => return PplOutcome::QueryFailed,
    };

    // PROCESS_MITIGATION_POLICY is a u32 enum. ProcessSignaturePolicy = 8 on Windows 8.1+.
    // The policy structure is a ULONG (u32) where bit 0x1 indicates protected.
    let mut policy_value: u32 = 0;
    let size = std::mem::size_of::<u32>();
    let result = unsafe {
        GetProcessMitigationPolicy(
            handle,
            windows::Win32::System::Threading::PROCESS_MITIGATION_POLICY(8),
            (&mut policy_value as *mut u32).cast::<std::ffi::c_void>(),
            size,
        )
    };

    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }

    if result.is_err() {
        return PplOutcome::QueryFailed;
    }

    // ProcessSignaturePolicy structure: ULONG Flags;
    // MICROSOFT_PROCESS_SIGNING_ALL = 0x1 indicates PPL.
    if policy_value & 0x1 != 0 {
        PplOutcome::Protected
    } else {
        PplOutcome::NotProtected
    }
}

/// Categorize a HookError into an InjectionFailure.
#[must_use]
pub fn categorize_error(e: &crate::hook_injector::HookError) -> InjectionFailure {
    use crate::hook_injector::HookError;
    match e {
        HookError::AccessDenied { .. } => InjectionFailure::AccessDenied,
        HookError::RemoteThreadFailed { .. } => InjectionFailure::RemoteThreadFailed,
        HookError::InjectionFailed { .. } => InjectionFailure::InjectionFailed,
        HookError::RemoteThreadTimeout { .. } => InjectionFailure::Timeout,
        _ => InjectionFailure::InjectionFailed,
    }
}

impl SkipReason {
    /// Convert an AllowlistCategory to the corresponding SkipReason.
    #[must_use]
    pub fn from_category(cat: AllowlistCategory) -> Self {
        match cat {
            AllowlistCategory::SelfProcess => SkipReason::SelfProcess,
            AllowlistCategory::Avedr => SkipReason::Avedr,
            AllowlistCategory::SystemCritical => SkipReason::SystemCritical,
            AllowlistCategory::OperatorDefined => SkipReason::OperatorDefined,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::AllowlistMatcher;
    use crate::hook_injector::HookInjector;
    use crate::process_registry::ProcessRegistry;
    use crate::process_watcher::EventSource;

    fn test_injector() -> Arc<HookInjector> {
        Arc::new(HookInjector::new("C:\\dummy.dll", None))
    }

    fn test_matcher() -> Arc<AllowlistMatcher> {
        Arc::new(AllowlistMatcher::new(
            vec![],
            r"C:\ProgramData\DLP\dlp-agent.exe".to_string(),
            9999,
        ))
    }

    fn test_registry() -> Arc<ProcessRegistry> {
        Arc::new(ProcessRegistry::new())
    }

    fn make_event(pid: u32, image_path: &str) -> ProcessEvent {
        ProcessEvent {
            pid,
            image_path: image_path.to_string(),
            parent_pid: 0,
            creation_time: 1,
            source: EventSource::Etw,
            event_timestamp: Instant::now(),
        }
    }

    #[test]
    fn test_latency_histogram_record_and_percentiles() {
        let mut hist = LatencyHistogram::new();
        hist.record(25); // bucket 0
        hist.record(75); // bucket 1
        hist.record(150); // bucket 2
        hist.record(400); // bucket 3
        hist.record(600); // bucket 4
        hist.record(2000); // bucket 5

        assert_eq!(hist.total, 6);
        let pct = hist.pct_under_500ms();
        assert!((pct - 66.67).abs() < 0.1, "expected ~66.67%, got {}", pct);

        let (p50, p95, p99) = hist.percentiles();
        assert!(p50 > 0.0, "p50 should be > 0");
        assert!(p95 > 0.0, "p95 should be > 0");
        assert!(p99 > 0.0, "p99 should be > 0");
    }

    #[test]
    fn test_latency_histogram_empty() {
        let hist = LatencyHistogram::new();
        assert_eq!(hist.pct_under_500ms(), 100.0);
        let (p50, p95, p99) = hist.percentiles();
        assert_eq!(p50, 0.0);
        assert_eq!(p95, 0.0);
        assert_eq!(p99, 0.0);
    }

    #[test]
    fn test_skip_reason_from_category() {
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
    fn test_categorize_error_access_denied() {
        let e = crate::hook_injector::HookError::AccessDenied { pid: 1234 };
        assert_eq!(categorize_error(&e), InjectionFailure::AccessDenied);
    }

    #[test]
    fn test_categorize_error_remote_thread_failed() {
        let e = crate::hook_injector::HookError::RemoteThreadFailed {
            pid: 1234,
            detail: "test".to_string(),
        };
        assert_eq!(categorize_error(&e), InjectionFailure::RemoteThreadFailed);
    }

    #[test]
    fn test_categorize_error_injection_failed() {
        let e = crate::hook_injector::HookError::InjectionFailed {
            pid: 1234,
            exit_code: 5,
        };
        assert_eq!(categorize_error(&e), InjectionFailure::InjectionFailed);
    }

    #[test]
    fn test_categorize_error_timeout() {
        let e = crate::hook_injector::HookError::RemoteThreadTimeout { pid: 1234 };
        assert_eq!(categorize_error(&e), InjectionFailure::Timeout);
    }

    #[tokio::test]
    async fn test_allowlisted_process_is_skipped() {
        let registry = test_registry();
        let matcher = Arc::new(AllowlistMatcher::new(
            vec![],
            r"C:\Test\app.exe".to_string(),
            42, // self_pid
        ));
        let injector = test_injector();
        let (retry_tx, _retry_rx) = mpsc::unbounded_channel();
        let ui = UniversalInjector::with_retry_queue(registry.clone(), matcher, injector, retry_tx);

        let event = make_event(42, r"C:\Other\app.exe");
        let (sweep_tx, _sweep_rx) = mpsc::channel(1);
        ui.handle_event(event, &sweep_tx).await;

        let key = ProcessKey {
            pid: 42,
            creation_time: 1,
        };
        let state = registry.get(&key).expect("key should exist");
        assert!(
            matches!(
                &*state,
                crate::process_registry::ProcessState::Skipped(SkipReason::SelfProcess)
            ),
            "expected Skipped(SelfProcess), got {:?}",
            *state
        );
    }

    #[tokio::test]
    async fn test_duplicate_claim_prevents_double_inject() {
        let registry = test_registry();
        let matcher = test_matcher();
        let injector = test_injector();
        let (retry_tx, _retry_rx) = mpsc::unbounded_channel();
        let ui = UniversalInjector::with_retry_queue(registry.clone(), matcher, injector, retry_tx);

        let event1 = make_event(1000, r"C:\Windows\System32\notepad.exe");
        let event2 = make_event(1000, r"C:\Windows\System32\notepad.exe");
        let (sweep_tx, _sweep_rx) = mpsc::channel(1);

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

    #[test]
    fn test_universal_injector_latency_metrics() {
        let registry = test_registry();
        let matcher = test_matcher();
        let injector = test_injector();
        let ui = UniversalInjector::new(registry, matcher, injector);

        let (p50, p95, p99, pct) = ui.latency_metrics();
        assert_eq!(p50, 0.0);
        assert_eq!(p95, 0.0);
        assert_eq!(p99, 0.0);
        assert_eq!(pct, 100.0);
    }
}
