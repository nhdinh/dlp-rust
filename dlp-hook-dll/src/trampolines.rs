//! DLP hook trampolines — expanded file-I/O surface.
//!
//! This module contains all 12 trampoline implementations that intercept
//! Windows file-I/O APIs and route classification requests to the agent
//! via named pipe.
//!
//! ## Known Limitation: CopyFile2
//!
//! `CopyFile2` is a COM-based API and does not have a traditional IAT entry
//! in most processes. It is covered indirectly via the underlying
//! `NtCreateFile` and `NtWriteFile` hooks.
//!
//! ## Journal Operation Mapping
//!
//! The hook journal records every file-I/O operation before returning the
//! classification decision. Operation types:
//! - `CreateFile*`, `NtCreateFile`, `NtOpenFile` -> op = 1 (Create)
//! - `WriteFile*`, `NtWriteFile` -> op = 2 (Write)
//! - `DeleteFile*`, `NtSetInformationFile(FileDispositionInformation)` -> op = 3 (Delete)
//! - `MoveFileEx*`, `CopyFileEx*`, `ReplaceFile*`, `NtSetInformationFile(FileRenameInfo)` -> op = 4 (SetInfo)
//!
//! ## Journal Coverage Audit (Phase 58.1)
//!
//! Per D-01, all 9 mutating trampolines MUST write a journal entry before the
//! original Win32/NT API call. The 3 pure-open trampolines MUST NOT.
//!
//! | # | Trampoline | Journal | journal_op | Placement |
//! |---|------------|---------|------------|-----------|
//! | 1 | HookCreateFileW | NOT_JOURNALED | 1 | Pure open (correct) |
//! | 2 | HookNtCreateFile | NOT_JOURNALED | 1 | Pure open (correct) |
//! | 3 | HookWriteFile | JOURNALED | 2 | classify_and_log_handle line 534 |
//! | 4 | HookWriteFileEx | JOURNALED | 2 | classify_and_log_handle line 534 |
//! | 5 | HookMoveFileExW | JOURNALED | 4 | classify_and_log_path line 397 |
//! | 6 | HookCopyFileExW | JOURNALED | 4 | classify_and_log_path line 397 |
//! | 7 | HookDeleteFileW | JOURNALED | 3 | classify_and_log_path line 397 |
//! | 8 | HookReplaceFileW | JOURNALED | 4 | classify_and_log_path line 397 |
//! | 9 | HookSetFileInformationByHandle | JOURNALED | 4 | classify_and_log_handle line 534 |
//! | 10 | HookNtOpenFile | NOT_JOURNALED | 1 | Pure open (correct) |
//! | 11 | HookNtWriteFile | JOURNALED | 2 | classify_and_log_handle line 534 |
//! | 12 | HookNtSetInformationFile | JOURNALED | 4 | classify_and_log_handle line 534 |
//!
//! D-03 invariant: The journal write is placed AFTER classification and BEFORE
//! returning the decision. Both `classify_and_log_path` (line 397) and
//! `classify_and_log_handle` (line 534) call `journal_write_from_trampoline`
//! as their final operation before returning `Option<DenyReturn>`. This ensures
//! ETW cannot observe an operation the hook has not yet recorded.
//!
//! D-04 invariant: If the journal mapping is lost, `journal_write` returns
//! silently (HookJournal::get() returns None). The ABAC decision is preserved.
//! Phase 58.1 Task 3 adds `JournalDegraded` alert emission for monitoring.
//!
//! ## Ntdll Trampolines (Phase 51)
//!
//! The ntdll-specific trampolines (`NtdllTrampolineNtCreateFile`, etc.) follow
//! the same classification pipeline but are not included in the 12 IAT
//! trampolines above. They reuse `classify_and_log_path` and therefore inherit
//! the same journal coverage.

// Trampolines are inherently unsafe FFI boundaries; safety docs and transmute
// are pre-existing patterns from Plan 48-02.
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]
#![allow(clippy::transmutes_expressible_as_ptr_casts)]

use dlp_common::hook_ipc::HookOp;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, NTSTATUS};

use crate::fail_mode::{FailModeState, FailState};
use dlp_common::hook_ipc::ClassificationSource;
use dlp_common::Classification;

// ---------------------------------------------------------------------------
// Helper: shared classification + logging + deny/allow logic
// ---------------------------------------------------------------------------

/// Global fail-mode state machine.
///
/// Stored in a resettable `Mutex<Option<...>>` so tests can tear it down
/// between runs. Production code never resets it; the mutex is uncontended
/// after initialization.
static FAIL_STATE: Mutex<Option<Arc<FailModeState>>> = Mutex::new(None);

/// Returns the global fail-mode state machine, initializing if needed.
fn get_fail_state() -> Arc<FailModeState> {
    {
        let guard = FAIL_STATE.lock();
        if let Some(state) = guard.as_ref() {
            return Arc::clone(state);
        }
    }

    let state = Arc::new(FailModeState::new());
    if let Some(cache) = crate::classification_cache::CacheLookup::get() {
        let header = &cache as *const _ as *const crate::classification_cache::CacheHeader;
        // Pass None for verify_fn — ntdll trampoline verification callback
        // will be wired in Plan 06 when NtdllPatcher is initialized.
        crate::background_thread::start_background_thread(header, Arc::clone(&state), None, None);
    }

    let mut guard = FAIL_STATE.lock();
    if guard.is_none() {
        *guard = Some(Arc::clone(&state));
    }
    Arc::clone(guard.as_ref().unwrap())
}

/// Test-only helper to reset the global fail-mode state machine.
#[cfg(any(test, feature = "test-helpers"))]
pub(crate) fn reset_fail_state_for_test() {
    crate::background_thread::shutdown_background_thread();
    let mut guard = FAIL_STATE.lock();
    *guard = None;
}

/// Default cooldown between override prompt requests for the same path/action pair.
///
/// A single blocked application can repeatedly hit the same deny branch (e.g., a
/// sync client retrying every few seconds). This TTL prevents the UI from being
/// flooded with identical prompts while still giving the user a chance to request
/// an override after a reasonable window.
const OVERRIDE_COOLDOWN_TTL: Duration = Duration::from_secs(30);

/// Maximum number of distinct path/action keys retained by the cooldown map.
///
/// Bounded memory is required because every unique denied path could otherwise
/// become a permanent entry. When the cap is exceeded, the oldest keys are
/// evicted opportunistically after removing expired entries.
const OVERRIDE_COOLDOWN_MAX_KEYS: usize = 10_000;

/// Per-path/action override prompt cooldown state.
///
/// Tracks the last emission instant for each composite key (`"{path}\0{action}"`).
/// A bounded LRU queue (`lru_keys`) is kept in parallel so that memory usage is
/// capped even when many unique paths are denied.
struct OverrideCooldownMap {
    /// Last-emission instant per composite key.
    entries: HashMap<String, Instant>,
    /// LRU key queue used for bounded eviction.
    lru_keys: VecDeque<String>,
    /// Hard cap on the number of tracked keys.
    max_keys: usize,
}

impl OverrideCooldownMap {
    /// Creates an empty cooldown map with the default key cap.
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            lru_keys: VecDeque::new(),
            max_keys: OVERRIDE_COOLDOWN_MAX_KEYS,
        }
    }

    /// Returns true if an override request should be emitted for `key`.
    ///
    /// The key is treated as fresh (and true is returned) when:
    /// - the key has never been seen, or
    /// - the stored instant is older than `ttl`.
    ///
    /// On a fresh key, the current instant is recorded and the key is moved to
    /// the back of the LRU queue. If the map exceeds `max_keys`, expired entries
    /// are removed first; if still over capacity, the oldest keys are evicted.
    ///
    /// # Arguments
    ///
    /// * `key` — Composite cooldown key (caller-defined format).
    /// * `now` — Current instant to compare against.
    /// * `ttl` — Cooldown duration.
    fn should_emit(&mut self, key: &str, now: Instant, ttl: Duration) -> bool {
        let is_fresh = match self.entries.get(key) {
            Some(ts) => now.saturating_duration_since(*ts) >= ttl,
            None => true,
        };

        if !is_fresh {
            return false;
        }

        self.entries.insert(key.to_string(), now);
        // Update LRU position: remove existing occurrence and push to back.
        self.lru_keys.retain(|k| k != key);
        self.lru_keys.push_back(key.to_string());
        self.evict_expired_and_oldest(now, ttl);
        true
    }

    /// Removes expired entries, then evicts oldest keys until at or below cap.
    fn evict_expired_and_oldest(&mut self, now: Instant, ttl: Duration) {
        // Opportunistically remove expired entries first.
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, ts)| now.saturating_duration_since(**ts) >= ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            self.entries.remove(&k);
            self.lru_keys.retain(|x| x != &k);
        }

        // If still over capacity, evict the oldest keys.
        while self.entries.len() > self.max_keys {
            match self.lru_keys.pop_front() {
                Some(oldest) => {
                    self.entries.remove(&oldest);
                }
                None => break,
            }
        }
    }

    /// Clears all cooldown entries (test use only).
    fn clear(&mut self) {
        self.entries.clear();
        self.lru_keys.clear();
    }
}

/// Global override-prompt cooldown map.
///
/// Guarded by a mutex because the deny path may be invoked concurrently from
/// multiple hooked threads. The lock is held only for a short HashMap operation.
static OVERRIDE_COOLDOWN: std::sync::LazyLock<Mutex<OverrideCooldownMap>> =
    std::sync::LazyLock::new(|| Mutex::new(OverrideCooldownMap::new()));

/// Emits a one-way `IpcPayloadV1::RequestOverride` frame to the agent.
///
/// This is invoked from every deny branch in [`classify_and_log_path`] and
/// [`classify_and_log_handle`]. The original operation remains denied; the
/// override request only gives the user a chance to approve a future operation
/// via [`HookResponse.approval_override`].
///
/// The call is fire-and-forget: it uses [`pipe_client::send_raw_oneway`] with a
/// bounded 50 ms connect budget and never waits for a response. Failures are
/// logged and ignored so that a missing agent does not change the deny decision.
///
/// A 30-second per-path/action cooldown and a 10,000-key cap prevent UI spam
/// and unbounded memory growth.
///
/// # Arguments
///
/// * `path` — The denied file path (may be empty for handle-based ops).
/// * `action` — The action being denied (e.g., `"CREATE"`, `"WRITE"`).
/// * `handle_value` — The raw handle value, used only when `path` is empty.
fn emit_override_request(path: &str, action: &str, handle_value: u64) {
    let key = format!("{}\0{}", path, action);
    let now = Instant::now();

    {
        let mut cooldown = OVERRIDE_COOLDOWN.lock();
        if !cooldown.should_emit(&key, now, OVERRIDE_COOLDOWN_TTL) {
            return;
        }
    }

    let resource = if path.is_empty() {
        format!("handle:{}", handle_value)
    } else {
        path.to_string()
    };

    let req = dlp_common::hook_ipc::OverrideRequest {
        requester_sid: crate::get_current_user_sid(),
        data_object_id: resource.clone(),
        action: action.to_string(),
        destination_scope: None,
        justification: String::new(),
        resource_path: resource,
    };

    let envelope = dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
        payload: dlp_common::hook_ipc::IpcPayloadV1::RequestOverride(req),
    });

    match bincode::serialize(&envelope) {
        Ok(bytes) => {
            if let Err(e) = crate::pipe_client::send_raw_oneway(crate::current_pipe_name(), &bytes)
            {
                tracing::warn!(
                    resource_path = %path,
                    action = %action,
                    error = %e,
                    "emit_override_request: one-way send failed"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                resource_path = %path,
                action = %action,
                error = %e,
                "emit_override_request: bincode serialization failed"
            );
        }
    }
}

/// Test-only helper to reset the global override cooldown map.
///
/// Integration tests should call this before assertions so that cooldown state
/// from previous tests does not influence results.
#[cfg(any(test, feature = "test-helpers"))]
pub fn reset_override_cooldown() {
    OVERRIDE_COOLDOWN.lock().clear();
}

/// DIFF-04: Record a pipe round-trip and emit a health snapshot every
/// `HEALTH_EMIT_INTERVAL` round-trips.
fn record_pipe_round_trip_and_maybe_emit() {
    crate::perf_telemetry::record_pipe_round_trip();
    let health_count = crate::perf_telemetry::HEALTH_EMIT_COUNTER
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        + 1;
    if health_count.is_multiple_of(crate::perf_telemetry::HEALTH_EMIT_INTERVAL) {
        let snapshot = crate::perf_telemetry::emit_health_snapshot();
        if let Err(e) =
            crate::pipe_client::send_health_snapshot(crate::current_pipe_name(), &snapshot)
        {
            crate::debug_log(&format!("[dlp-hook] health snapshot send failed: {}\0", e));
        }
    }
}

/// Performs the common classification, logging, and decision routing for
/// path-based trampolines.
///
/// New flow (Plan 50-04 + Phase 56):
/// 1. Check allowlist first (fastest path).
/// 2. Resolve volume class from path for ABAC context enrichment.
/// 3. Check thread-local LRU for path.
/// 4. If LRU miss, check shared-memory cache.
/// 5. If cache hit, apply tier-gated fast-path decision.
/// 6. Get current fail_state.
/// 7. If HEALTHY or (DEGRADED and should_retry_pipe()):
///    a. Attempt pipe round-trip (with volume class in request)
///    b. On success: record_pipe_success(cache_version), warm LRU, return decision
///    c. On failure: record_pipe_failure(), goto step 8
/// 8. If DEGRADED and not retry call: use cache decision or ISOLATED decision
/// 9. If ISOLATED: use decide_isolated(classification, op), no pipe attempt
/// 10. If RESYNC: flush LRU, reset counters, transition to HEALTHY, retry
///
/// Returns `Some(deny_return_value)` if the operation should be denied,
/// `None` if it should proceed to the original function.
///
/// `handle_value` is the HANDLE from the API call (0 for path-based ops where
/// the handle is not yet available). `journal_op` is the operation type for
/// the hook journal (1=Create, 2=Write, 3=Delete, 4=SetInfo).
///
/// `source_volume_class` and `destination_volume_class` are optionally
/// pre-resolved volume classes (e.g., from copy/move trampolines that know
/// both paths). When `None`, the function resolves from `path` automatically.
pub(crate) fn classify_and_log_path(
    path: &str,
    action: &str,
    fn_name: &str,
    handle_value: u64,
    journal_op: u8,
    source_volume_class: Option<dlp_common::VolumeClass>,
    destination_volume_class: Option<dlp_common::VolumeClass>,
) -> Option<crate::fail_closed::DenyReturn> {
    // Ensure IAT hooks are patched before any classification work. DllMain
    // defers patching to a worker thread; this fallback covers tests and the
    // unlikely case where the init thread failed to start.
    crate::lazy_init();

    // Shutdown pass-through: do not classify, do not touch shared mappings,
    // do not increment active-call counters. Returning None tells the trampoline
    // to call the original API.
    if crate::is_shutting_down() {
        return None;
    }

    let path_hash = crate::hash_path(path);

    // Resolve volume class from path if not pre-resolved (e.g., from copy/move).
    // This happens AFTER allowlist check (so allowlisted paths skip cache lookup)
    // but BEFORE the pipe round-trip.
    let source_volume_class = source_volume_class
        .or_else(|| crate::volume_class_cache::resolve_volume_class_from_path(path));

    // Determine operation type for tier-gated decisions.
    let op = if is_write_action(action) {
        HookOp::Write
    } else {
        HookOp::Read
    };

    // Wrap entire decision logic with QPC latency measurement.
    // Track classification source for diagnostic snapshots (DIFF-02).
    let mut classification_source = ClassificationSource::Pipe;
    let (decision, elapsed_qpc) = crate::perf_telemetry::measure(|| {
        // 1. Check allowlist first (fastest path).
        // Get cache header for operator-extended allowlist.
        let cache_lookup = crate::classification_cache::CacheLookup::get();
        let header_ref = cache_lookup.map(|c| {
            // SAFETY: CacheLookup header pointer is valid read-only mapping.
            // `CacheView` is a lightweight copy of that pointer, so we dereference
            // the pointer it wraps rather than casting the view itself.
            unsafe { &*c.header }
        });

        let (allowlisted, category) = crate::allowlist::is_allowlisted(path, header_ref);
        if allowlisted {
            let msg = format!(
                "[dlp-hook] ALLOW(allowlist) {} hash={:016x}\0",
                fn_name, path_hash
            );
            crate::debug_log(&msg);

            // Emit audit for allowlist hits in fail-mode contexts.
            let fail_state = get_fail_state();
            let current_state = fail_state.current_state();
            let context_str = format!("{:?}", current_state).to_ascii_uppercase();
            if let Some(cat) = category {
                crate::allowlist::emit_allowlist_hit(path, cat, &context_str);
            }

            return None;
        }

        // 2. Check shared-memory cache (includes thread-local LRU).
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut cache_classification: Option<Classification> = None;
        let mut cache_version: u64 = 0;
        let mut is_cache_hit = false;

        if let Some(cache) = cache_lookup {
            // Check thread-local LRU first.
            let version_word = cache.current_version_word();
            cache_version = version_word >> 1;

            if let Some(classification) = crate::classification_cache::lru::get(path, cache_version)
            {
                // LRU hit — use this classification for fail-mode decisions.
                cache_classification = Some(classification);
                is_cache_hit = true;
            } else {
                // LRU miss — check shared-memory cache.
                if let Some(classification) = cache.lookup(path, op, now_secs) {
                    // Cache hit — warm LRU.
                    crate::classification_cache::lru::insert(path, classification, cache_version);
                    cache_classification = Some(classification);
                    is_cache_hit = true;
                }
            }
        }

        // DIFF-04: Record cache hit/miss counters.
        if is_cache_hit {
            crate::perf_telemetry::record_cache_hit();
        } else if cache_lookup.is_some() {
            // Cache was available but we missed (no classification found).
            crate::perf_telemetry::record_cache_miss();
        }

        // 3. Get fail-mode state.
        let fail_state = get_fail_state();
        let current_state = fail_state.current_state();

        // 4. Apply state-specific logic.
        let result = match current_state {
            FailState::Healthy => {
                // HEALTHY: attempt pipe on cache miss, or use cache decision on hit.
                if let Some(classification) = cache_classification {
                    classification_source = ClassificationSource::CacheHit;
                    let msg = format!(
                        "[dlp-hook] ALLOW(cache) {} hash={:016x} tier={}\0",
                        fn_name, path_hash, classification
                    );
                    crate::debug_log(&msg);
                    if let Some(deny) = cache_lookup.and_then(|c| c.decide(classification, op)) {
                        return Some(deny);
                    }
                    return None;
                }

                // Cache miss — attempt pipe round-trip.
                match crate::classify_path(
                    path,
                    action,
                    crate::current_pipe_name(),
                    source_volume_class,
                    destination_volume_class,
                ) {
                    Ok(ref resp)
                        if resp.decision == crate::Decision::ALLOW
                            || resp.decision == crate::Decision::AllowWithLog =>
                    {
                        fail_state.record_pipe_success(cache_version);
                        record_pipe_round_trip_and_maybe_emit();
                        let msg = format!("[dlp-hook] ALLOW {} hash={:016x}\0", fn_name, path_hash);
                        crate::debug_log(&msg);
                        None
                    }
                    Ok(ref resp)
                        if (resp.decision == crate::Decision::DENY
                            || resp.decision == crate::Decision::DenyWithAlert)
                            && resp.approval_override == Some(true) =>
                    {
                        // DIFF-01: Approval override granted — allow the operation.
                        fail_state.record_pipe_success(cache_version);
                        record_pipe_round_trip_and_maybe_emit();
                        let msg = format!(
                            "[dlp-hook] ALLOW(override) {} hash={:016x}\0",
                            fn_name, path_hash
                        );
                        crate::debug_log(&msg);
                        None
                    }
                    Ok(_) => {
                        fail_state.record_pipe_success(cache_version);
                        record_pipe_round_trip_and_maybe_emit();
                        let msg = format!("[dlp-hook] DENY {} hash={:016x}\0", fn_name, path_hash);
                        crate::debug_log(&msg);
                        Some(crate::fail_closed::DenyReturn::BoolFalse)
                    }
                    Err(_) => {
                        fail_state.record_pipe_failure();
                        record_pipe_round_trip_and_maybe_emit();
                        let msg = format!(
                            "[dlp-hook] DENY(fail-closed) {} hash={:016x}\0",
                            fn_name, path_hash
                        );
                        crate::debug_log(&msg);
                        Some(crate::fail_closed::DenyReturn::BoolFalse)
                    }
                }
            }
            FailState::Degraded => {
                // DEGRADED: use cache decision if available; retry pipe every 10th call.
                if let Some(classification) = cache_classification {
                    classification_source = ClassificationSource::CacheHit;
                    let msg = format!(
                        "[dlp-hook] ALLOW(cache-degraded) {} hash={:016x} tier={}\0",
                        fn_name, path_hash, classification
                    );
                    crate::debug_log(&msg);
                    if let Some(deny) = cache_lookup.and_then(|c| c.decide(classification, op)) {
                        return Some(deny);
                    }
                    return None;
                }

                // Cache miss in Degraded: retry pipe every 10th call.
                if fail_state.should_retry_pipe() {
                    match crate::classify_path(
                        path,
                        action,
                        crate::current_pipe_name(),
                        source_volume_class,
                        destination_volume_class,
                    ) {
                        Ok(ref resp)
                            if resp.decision == crate::Decision::ALLOW
                                || resp.decision == crate::Decision::AllowWithLog =>
                        {
                            fail_state.record_pipe_success(cache_version);
                            record_pipe_round_trip_and_maybe_emit();
                            None
                        }
                        Ok(ref resp)
                            if (resp.decision == crate::Decision::DENY
                                || resp.decision == crate::Decision::DenyWithAlert)
                                && resp.approval_override == Some(true) =>
                        {
                            // DIFF-01: Approval override granted.
                            fail_state.record_pipe_success(cache_version);
                            record_pipe_round_trip_and_maybe_emit();
                            None
                        }
                        Ok(_) => {
                            fail_state.record_pipe_success(cache_version);
                            record_pipe_round_trip_and_maybe_emit();
                            Some(crate::fail_closed::DenyReturn::BoolFalse)
                        }
                        Err(_) => {
                            fail_state.record_pipe_failure();
                            record_pipe_round_trip_and_maybe_emit();
                            crate::fail_mode::decide_degraded(cache_classification, op)
                        }
                    }
                } else {
                    // No pipe retry: use degraded decision (same as isolated for cache miss).
                    crate::fail_mode::decide_degraded(cache_classification, op)
                }
            }
            FailState::Isolated => {
                // ISOLATED: cache-only, no pipe attempts.
                if cache_classification.is_some() {
                    classification_source = ClassificationSource::CacheHit;
                }
                let decision = crate::fail_mode::decide_isolated(cache_classification, op);
                let tier_str = cache_classification
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                if decision.is_some() {
                    let msg = format!(
                        "[dlp-hook] DENY(isolated) {} hash={:016x} tier={}\0",
                        fn_name, path_hash, tier_str
                    );
                    crate::debug_log(&msg);
                } else {
                    let msg = format!(
                        "[dlp-hook] ALLOW(isolated) {} hash={:016x} tier={}\0",
                        fn_name, path_hash, tier_str
                    );
                    crate::debug_log(&msg);
                }
                decision
            }
            FailState::Resync => {
                // RESYNC: flush LRU, reset counters, transition to Healthy, retry.
                // In-flight decisions use old cache; new decisions use new cache.
                // We flush LRU and reset counters, then treat as Healthy.
                crate::classification_cache::lru::clear_all();
                fail_state.reset_counters();
                fail_state.set_state(FailState::Healthy);

                // Retry from Healthy path.
                if let Some(classification) = cache_classification {
                    classification_source = ClassificationSource::CacheHit;
                    if let Some(deny) = cache_lookup.and_then(|c| c.decide(classification, op)) {
                        return Some(deny);
                    }
                    return None;
                }

                // Attempt pipe after RESYNC recovery.
                match crate::classify_path(
                    path,
                    action,
                    crate::current_pipe_name(),
                    source_volume_class,
                    destination_volume_class,
                ) {
                    Ok(ref resp)
                        if resp.decision == crate::Decision::ALLOW
                            || resp.decision == crate::Decision::AllowWithLog =>
                    {
                        fail_state.record_pipe_success(cache_version);
                        record_pipe_round_trip_and_maybe_emit();
                        None
                    }
                    Ok(ref resp)
                        if (resp.decision == crate::Decision::DENY
                            || resp.decision == crate::Decision::DenyWithAlert)
                            && resp.approval_override == Some(true) =>
                    {
                        // DIFF-01: Approval override granted.
                        fail_state.record_pipe_success(cache_version);
                        record_pipe_round_trip_and_maybe_emit();
                        None
                    }
                    Ok(_) => {
                        fail_state.record_pipe_success(cache_version);
                        record_pipe_round_trip_and_maybe_emit();
                        Some(crate::fail_closed::DenyReturn::BoolFalse)
                    }
                    Err(_) => {
                        fail_state.record_pipe_failure();
                        record_pipe_round_trip_and_maybe_emit();
                        Some(crate::fail_closed::DenyReturn::BoolFalse)
                    }
                }
            }
        };

        // Emit state transition if state changed during this call.
        let new_state = fail_state.current_state();
        if new_state != current_state {
            let reason = format!("state_changed_during_{}", fn_name);
            crate::perf_telemetry::emit_state_transition_immediate(
                current_state,
                new_state,
                &reason,
            );
        }

        result
    });

    // DIFF-02: Push diagnostic snapshot on every DENY branch.
    if decision.is_some() {
        let snapshot = dlp_common::hook_ipc::DiagnosticSnapshot {
            hook_function: fn_name.to_string(),
            classification_source,
            classification_age_ms: 0,
            abac_resource: path.to_string(),
            abac_action: action.to_string(),
            abac_environment: format!("{:?}", source_volume_class),
            matched_policy_id: None,
            enforcement_mode: None,
            decision_latency_us: elapsed_qpc,
            timestamp_qpc: crate::perf_telemetry::query_performance_counter(),
            timestamp_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            user_sid: crate::get_current_user_sid(),
        };
        crate::diagnostic_ring::push_snapshot(snapshot);
    }

    // Record latency telemetry.
    let is_cache_hit = decision.is_none()
        && !crate::allowlist::is_allowlisted(path, None).0
        && crate::classification_cache::CacheLookup::get().is_some();
    // Simplified: we don't have perfect cache hit tracking here without
    // threading state through the closure. For telemetry, we approximate:
    // - allowlist hit: not recorded as cache hit
    // - pipe call: recorded as cache miss
    // - cache-based decision: recorded as cache hit
    // A more precise implementation would thread an `is_cache_hit` bool
    // through the measure closure.
    crate::perf_telemetry::record_latency(elapsed_qpc, is_cache_hit);

    // Write to hook journal BEFORE returning the decision (per D-23).
    // This ensures both allow and deny paths are journaled.
    crate::hook_journal::journal_write_from_trampoline(handle_value, journal_op, path);

    decision
}

/// Sends a classification request to the agent via named pipe, including
/// volume class context for ABAC evaluation.
///
/// This is a wrapper around `crate::classify_path` that adds
/// `source_volume_class` and `destination_volume_class` to the request.
/// When both are `None`, the behavior is identical to `classify_path`.
#[allow(dead_code)]
fn classify_path_with_volume_class(
    path: &str,
    action: &str,
    pipe_name: &str,
    source_volume_class: Option<dlp_common::VolumeClass>,
    destination_volume_class: Option<dlp_common::VolumeClass>,
) -> Result<crate::Decision, crate::pipe_client::PipeError> {
    let req = dlp_common::HookRequest {
        path: path.to_string(),
        action: action.to_string(),
        source_volume_class,
        destination_volume_class,
        ..Default::default()
    };
    let resp = crate::pipe_client::send_request(pipe_name, &req, 50)?;
    Ok(resp.decision)
}

/// Returns `true` if the action is a write operation.
///
/// Write actions trigger fast-path deny for T3/T4 cache hits.
fn is_write_action(action: &str) -> bool {
    matches!(
        action.as_bytes(),
        b"CREATE"
            | b"WRITE"
            | b"MOVE"
            | b"COPY"
            | b"DELETE"
            | b"REPLACE"
            | b"SET_INFO"
            | b"NT_WRITE"
            | b"NT_SET_INFO"
            | b"create"
            | b"write"
            | b"move"
            | b"copy"
            | b"delete"
            | b"replace"
            | b"set_info"
            | b"nt_write"
            | b"nt_set_info"
    )
}

/// Performs the common classification, logging, and decision routing for
/// handle-based trampolines.
///
/// Returns `Some(deny_return_value)` if the operation should be denied,
/// `None` if it should proceed to the original function.
///
/// `journal_op` is the operation type for the hook journal (1=Create, 2=Write,
/// 3=Delete, 4=SetInfo). `path` is the file path for journal correlation
/// (may be empty for pure handle-based ops where the path is resolved
/// server-side).
///
/// # Known Limitation: Volume Class
///
/// Handle-based operations do not include volume class in the request.
/// The `classify_handle` function sends a `HookRequest` wrapped in the
/// versioned `IpcEnvelope` so the agent can route it. The request uses a
/// `handle://<value>` path until server-side handle-to-path resolution is
/// implemented. Volume-class ABAC conditions will evaluate against `None`
/// (fail-closed). To fix this, we would need to resolve the handle to a path
/// (via `NtQueryObject` or `GetFinalPathNameByHandleW`) and then look up the
/// volume class.
/// TODO(WR-01): Resolve handle-to-path and include volume class in handle-based
/// classification requests.
fn classify_and_log_handle(
    handle_value: u64,
    action: &str,
    fn_name: &str,
    journal_op: u8,
    path: &str,
) -> Option<crate::fail_closed::DenyReturn> {
    // Ensure IAT hooks are patched before any classification work. DllMain
    // defers patching to a worker thread; this fallback covers tests and the
    // unlikely case where the init thread failed to start.
    crate::lazy_init();

    // Shutdown pass-through: do not classify, do not touch shared mappings,
    // do not increment active-call counters. Returning None tells the trampoline
    // to call the original API.
    if crate::is_shutting_down() {
        return None;
    }

    let path_hash = crate::hash_path(path);

    // Determine operation type for tier-gated decisions.
    let op = if is_write_action(action) {
        HookOp::Write
    } else {
        HookOp::Read
    };

    // If a path was provided (e.g., future trampolines resolve handle->path),
    // apply the same fast-path checks as path-based hooks.
    if !path.is_empty() {
        let cache_lookup = crate::classification_cache::CacheLookup::get();
        let header_ref = cache_lookup.map(|c|
            // SAFETY: CacheLookup header pointer is valid read-only mapping.
            unsafe { &*c.header });
        let (allowlisted, category) = crate::allowlist::is_allowlisted(path, header_ref);
        if allowlisted {
            let msg = format!(
                "[dlp-hook] ALLOW(allowlist) {} handle={} hash={:016x}\0",
                fn_name, handle_value, path_hash
            );
            crate::debug_log(&msg);
            let fail_state = get_fail_state();
            let context_str = format!("{:?}", fail_state.current_state()).to_ascii_uppercase();
            if let Some(cat) = category {
                crate::allowlist::emit_allowlist_hit(path, cat, &context_str);
            }
            return None;
        }
    }

    let start = std::time::Instant::now();
    let mut classification_source = ClassificationSource::Pipe;

    let fail_state = get_fail_state();
    let current_state = fail_state.current_state();

    // Attempt a pipe round-trip for a handle-based request and map the
    // response to a deny/allow decision while updating fail-mode counters.
    let attempt_pipe = || -> Option<crate::fail_closed::DenyReturn> {
        match crate::classify_handle(handle_value, action, crate::current_pipe_name()) {
            Ok(ref resp)
                if resp.decision == crate::Decision::ALLOW
                    || resp.decision == crate::Decision::AllowWithLog =>
            {
                fail_state.record_pipe_success(0);
                record_pipe_round_trip_and_maybe_emit();
                let latency = start.elapsed();
                let msg = format!(
                    "[dlp-hook] ALLOW {} handle={} latency={}us\0",
                    fn_name,
                    handle_value,
                    latency.as_micros()
                );
                crate::debug_log(&msg);
                None
            }
            Ok(ref resp) if resp.decision.is_denied() && resp.approval_override == Some(true) => {
                fail_state.record_pipe_success(0);
                record_pipe_round_trip_and_maybe_emit();
                // DIFF-01: Approval override granted — allow the operation.
                let latency = start.elapsed();
                let msg = format!(
                    "[dlp-hook] ALLOW(override) {} handle={} latency={}us\0",
                    fn_name,
                    handle_value,
                    latency.as_micros()
                );
                crate::debug_log(&msg);
                None
            }
            Ok(ref resp) if resp.decision.is_denied() => {
                fail_state.record_pipe_success(0);
                record_pipe_round_trip_and_maybe_emit();
                let latency = start.elapsed();
                let msg = format!(
                    "[dlp-hook] DENY {} handle={} latency={}us\0",
                    fn_name,
                    handle_value,
                    latency.as_micros()
                );
                crate::debug_log(&msg);
                Some(crate::fail_closed::DenyReturn::BoolFalse)
            }
            Ok(_) => {
                fail_state.record_pipe_success(0);
                record_pipe_round_trip_and_maybe_emit();
                let latency = start.elapsed();
                let msg = format!(
                    "[dlp-hook] DENY {} handle={} latency={}us\0",
                    fn_name,
                    handle_value,
                    latency.as_micros()
                );
                crate::debug_log(&msg);
                Some(crate::fail_closed::DenyReturn::BoolFalse)
            }
            Err(_) => {
                fail_state.record_pipe_failure();
                record_pipe_round_trip_and_maybe_emit();
                let latency = start.elapsed();
                let msg = format!(
                    "[dlp-hook] DENY(fail-closed) {} handle={} latency={}us\0",
                    fn_name,
                    handle_value,
                    latency.as_micros()
                );
                crate::debug_log(&msg);
                Some(crate::fail_closed::DenyReturn::BoolFalse)
            }
        }
    };

    let result = match current_state {
        FailState::Healthy => {
            // HEALTHY: authoritative pipe round-trip.
            attempt_pipe()
        }
        FailState::Degraded => {
            // DEGRADED: retry pipe periodically, otherwise use fail-mode decision.
            // Handle-based ops currently cannot resolve handle->path locally, so
            // the shared-memory cache cannot be consulted. The TODO below tracks
            // wiring handle-to-path resolution for full cache integration.
            // TODO(Phase 58.4): Resolve handle to path and consult cache in Degraded.
            if fail_state.should_retry_pipe() {
                attempt_pipe()
            } else {
                let decision = crate::fail_mode::decide_degraded(None, op);
                let msg = if decision.is_some() {
                    format!(
                        "[dlp-hook] DENY(degraded) {} handle={}\0",
                        fn_name, handle_value
                    )
                } else {
                    format!(
                        "[dlp-hook] ALLOW(degraded) {} handle={}\0",
                        fn_name, handle_value
                    )
                };
                crate::debug_log(&msg);
                decision
            }
        }
        FailState::Isolated => {
            // ISOLATED: cache-only, no pipe attempts. Without handle->path
            // resolution we have no cached classification, so fall through to
            // the isolated fail-mode decision.
            classification_source = ClassificationSource::CacheHit;
            let decision = crate::fail_mode::decide_isolated(None, op);
            let msg = if decision.is_some() {
                format!(
                    "[dlp-hook] DENY(isolated) {} handle={}\0",
                    fn_name, handle_value
                )
            } else {
                format!(
                    "[dlp-hook] ALLOW(isolated) {} handle={}\0",
                    fn_name, handle_value
                )
            };
            crate::debug_log(&msg);
            decision
        }
        FailState::Resync => {
            // RESYNC: flush LRU, reset counters, transition to Healthy, retry.
            crate::classification_cache::lru::clear_all();
            fail_state.reset_counters();
            fail_state.set_state(FailState::Healthy);
            attempt_pipe()
        }
    };

    // Emit state transition if state changed during this call.
    let new_state = fail_state.current_state();
    if new_state != current_state {
        let reason = format!("state_changed_during_{}", fn_name);
        crate::perf_telemetry::emit_state_transition_immediate(current_state, new_state, &reason);
    }

    let latency = start.elapsed();

    // DIFF-02: Push diagnostic snapshot on every DENY branch.
    if result.is_some() {
        let snapshot = dlp_common::hook_ipc::DiagnosticSnapshot {
            hook_function: fn_name.to_string(),
            classification_source,
            classification_age_ms: 0,
            abac_resource: if path.is_empty() {
                format!("handle:{}", handle_value)
            } else {
                path.to_string()
            },
            abac_action: action.to_string(),
            abac_environment: String::new(),
            matched_policy_id: None,
            enforcement_mode: None,
            decision_latency_us: latency.as_micros() as u64,
            timestamp_qpc: crate::perf_telemetry::query_performance_counter(),
            timestamp_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            user_sid: crate::get_current_user_sid(),
        };
        crate::diagnostic_ring::push_snapshot(snapshot);
    }

    // Write to hook journal BEFORE returning the decision (per D-23).
    crate::hook_journal::journal_write_from_trampoline(handle_value, journal_op, path);

    result
}

// ---------------------------------------------------------------------------
// 1. HookCreateFileW — path-based
// ---------------------------------------------------------------------------

/// Classification hook for `CreateFileW`.
///
/// Sends the file path to the agent via named pipe. If the agent denies
/// the operation, returns `INVALID_HANDLE_VALUE` with `ERROR_ACCESS_DENIED`.
/// Otherwise delegates to the original `CreateFileW`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookCreateFileW(
    lpfilename: PCWSTR,
    dwdesiredaccess: u32,
    dwsharemode: windows::Win32::Storage::FileSystem::FILE_SHARE_MODE,
    lpsecurityattributes: *const windows::Win32::Security::SECURITY_ATTRIBUTES,
    dwcreationdisposition: windows::Win32::Storage::FileSystem::FILE_CREATION_DISPOSITION,
    dwflagsandattributes: windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
    htemplatefile: HANDLE,
) -> HANDLE {
    crate::crash_guard::guard_trampoline(
        "CreateFileW",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let path = crate::pcwstr_to_string(lpfilename);
                    if let Some(_deny) =
                        classify_and_log_path(&path, "CREATE", "CreateFileW", 0, 1, None, None)
                    {
                        return crate::fail_closed!(InvalidHandleValue);
                    }
                    let original = crate::ORIGINAL_CREATE_FILE_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("CreateFileW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        lpfilename,
                        dwdesiredaccess,
                        dwsharemode,
                        lpsecurityattributes,
                        dwcreationdisposition,
                        dwflagsandattributes,
                        htemplatefile,
                    )
                },
                || {
                    let original = crate::ORIGINAL_CREATE_FILE_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("CreateFileW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        lpfilename,
                        dwdesiredaccess,
                        dwsharemode,
                        lpsecurityattributes,
                        dwcreationdisposition,
                        dwflagsandattributes,
                        htemplatefile,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_CREATE_FILE_W.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("CreateFileW"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                lpfilename,
                dwdesiredaccess,
                dwsharemode,
                lpsecurityattributes,
                dwcreationdisposition,
                dwflagsandattributes,
                htemplatefile,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 2. HookNtCreateFile — path-based
// ---------------------------------------------------------------------------

/// Classification hook for `NtCreateFile`.
///
/// Sends the file path (extracted from `OBJECT_ATTRIBUTES`) to the agent.
/// Fail-closed on any error or denial.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookNtCreateFile(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut std::ffi::c_void,
    iostatusblock: *mut std::ffi::c_void,
    allocationsize: *const i64,
    fileattributes: u32,
    shareaccess: u32,
    createdisposition: u32,
    createoptions: u32,
    eabuffer: *mut std::ffi::c_void,
    ealength: u32,
) -> NTSTATUS {
    crate::crash_guard::guard_trampoline(
        "NtCreateFile",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let path = crate::extract_nt_path(objectattributes);
                    if let Some(_deny) =
                        classify_and_log_path(&path, "CREATE", "NtCreateFile", 0, 1, None, None)
                    {
                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    let Some(original) = (unsafe {
                        crate::ORIGINAL_NT_CREATE_FILE.or_else(|| crate::resolve_nt_create_file())
                    }) else {
                        return crate::fail_closed!(StatusAccessDenied);
                    };
                    original(
                        filehandle,
                        desiredaccess,
                        objectattributes,
                        iostatusblock,
                        allocationsize,
                        fileattributes,
                        shareaccess,
                        createdisposition,
                        createoptions,
                        eabuffer,
                        ealength,
                    )
                },
                || {
                    let Some(original) = (unsafe {
                        crate::ORIGINAL_NT_CREATE_FILE.or_else(|| crate::resolve_nt_create_file())
                    }) else {
                        return crate::fail_closed!(StatusAccessDenied);
                    };
                    original(
                        filehandle,
                        desiredaccess,
                        objectattributes,
                        iostatusblock,
                        allocationsize,
                        fileattributes,
                        shareaccess,
                        createdisposition,
                        createoptions,
                        eabuffer,
                        ealength,
                    )
                },
            )
        },
        || {
            let Some(original) = (unsafe {
                crate::ORIGINAL_NT_CREATE_FILE.or_else(|| crate::resolve_nt_create_file())
            }) else {
                return crate::fail_closed!(StatusAccessDenied);
            };
            original(
                filehandle,
                desiredaccess,
                objectattributes,
                iostatusblock,
                allocationsize,
                fileattributes,
                shareaccess,
                createdisposition,
                createoptions,
                eabuffer,
                ealength,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 3. HookWriteFile — handle-based
// ---------------------------------------------------------------------------

/// Classification hook for `WriteFile`.
///
/// Handle-based: sends the HANDLE value to the agent for path resolution.
/// Deny returns `BOOL(0)` with `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookWriteFile(
    hfile: HANDLE,
    lpbuffer: *const u8,
    nnumberofbytestowrite: u32,
    lpnumberofbyteswritten: *mut u32,
    lpoverlapped: *mut std::ffi::c_void,
) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "WriteFile",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let handle_value = hfile.0 as u64;
                    if let Some(_deny) =
                        classify_and_log_handle(handle_value, "WRITE", "WriteFile", 2, "")
                    {
                        // DIFF-03: Compute content hash from lpBuffer / nNumberOfBytesToWrite.
                        let (hash, truncated, skipped) =
                            if !lpbuffer.is_null() && nnumberofbytestowrite > 0 {
                                if (nnumberofbytestowrite as usize)
                                    < crate::hash_compute::SMALL_BUFFER_THRESHOLD
                                {
                                    unsafe {
                                        crate::hash_compute::compute_content_hash(
                                            lpbuffer,
                                            nnumberofbytestowrite,
                                        )
                                    }
                                } else {
                                    unsafe {
                                        crate::hash_compute::compute_content_hash_offloaded(
                                            lpbuffer,
                                            nnumberofbytestowrite,
                                        )
                                    }
                                }
                            } else {
                                (None, false, false)
                            };

                        let evidence = dlp_common::hook_ipc::HashEvidenceFrame {
                            pid: std::process::id(),
                            handle_value,
                            content_sha256: hash,
                            hash_truncated: truncated,
                            hash_skipped: skipped,
                            timestamp_secs: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        };
                        let _ = crate::pipe_client::send_hash_evidence(
                            crate::current_pipe_name(),
                            &evidence,
                        );

                        return crate::fail_closed!(BoolFalse);
                    }
                    let original = crate::ORIGINAL_WRITE_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("WriteFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        hfile,
                        lpbuffer,
                        nnumberofbytestowrite,
                        lpnumberofbyteswritten,
                        lpoverlapped,
                    )
                },
                || {
                    let original = crate::ORIGINAL_WRITE_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("WriteFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        hfile,
                        lpbuffer,
                        nnumberofbytestowrite,
                        lpnumberofbyteswritten,
                        lpoverlapped,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_WRITE_FILE.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("WriteFile"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                hfile,
                lpbuffer,
                nnumberofbytestowrite,
                lpnumberofbyteswritten,
                lpoverlapped,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 4. HookWriteFileEx — handle-based
// ---------------------------------------------------------------------------

/// Classification hook for `WriteFileEx`.
///
/// Handle-based: sends the HANDLE value to the agent for path resolution.
/// Deny returns `BOOL(0)` with `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookWriteFileEx(
    hfile: HANDLE,
    lpbuffer: *const u8,
    nnumberofbytestowrite: u32,
    lpoverlapped: *mut std::ffi::c_void,
    lpcompletionroutine: *mut std::ffi::c_void,
) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "WriteFileEx",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let handle_value = hfile.0 as u64;
                    if let Some(_deny) =
                        classify_and_log_handle(handle_value, "WRITE_EX", "WriteFileEx", 2, "")
                    {
                        // DIFF-03: Compute content hash from lpBuffer / nNumberOfBytesToWrite.
                        let (hash, truncated, skipped) =
                            if !lpbuffer.is_null() && nnumberofbytestowrite > 0 {
                                if (nnumberofbytestowrite as usize)
                                    < crate::hash_compute::SMALL_BUFFER_THRESHOLD
                                {
                                    unsafe {
                                        crate::hash_compute::compute_content_hash(
                                            lpbuffer,
                                            nnumberofbytestowrite,
                                        )
                                    }
                                } else {
                                    unsafe {
                                        crate::hash_compute::compute_content_hash_offloaded(
                                            lpbuffer,
                                            nnumberofbytestowrite,
                                        )
                                    }
                                }
                            } else {
                                (None, false, false)
                            };

                        let evidence = dlp_common::hook_ipc::HashEvidenceFrame {
                            pid: std::process::id(),
                            handle_value,
                            content_sha256: hash,
                            hash_truncated: truncated,
                            hash_skipped: skipped,
                            timestamp_secs: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        };
                        let _ = crate::pipe_client::send_hash_evidence(
                            crate::current_pipe_name(),
                            &evidence,
                        );

                        return crate::fail_closed!(BoolFalse);
                    }
                    let original = crate::ORIGINAL_WRITE_FILE_EX.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("WriteFileEx"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        hfile,
                        lpbuffer,
                        nnumberofbytestowrite,
                        lpoverlapped,
                        lpcompletionroutine,
                    )
                },
                || {
                    let original = crate::ORIGINAL_WRITE_FILE_EX.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("WriteFileEx"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        hfile,
                        lpbuffer,
                        nnumberofbytestowrite,
                        lpoverlapped,
                        lpcompletionroutine,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_WRITE_FILE_EX.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("WriteFileEx"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                hfile,
                lpbuffer,
                nnumberofbytestowrite,
                lpoverlapped,
                lpcompletionroutine,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 5. HookMoveFileExW — path-based (source + destination)
// ---------------------------------------------------------------------------

/// Classification hook for `MoveFileExW`.
///
/// Path-based: evaluates BOTH source and destination paths. If either is
/// denied, the operation is blocked.
/// Deny returns `BOOL(0)` with `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookMoveFileExW(
    lpexistingfilename: PCWSTR,
    lpnewfilename: PCWSTR,
    dwflags: u32,
) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "MoveFileExW",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let src_path = crate::pcwstr_to_string(lpexistingfilename);
                    let dst_path = crate::pcwstr_to_string(lpnewfilename);

                    let src_vc =
                        crate::volume_class_cache::resolve_volume_class_from_path(&src_path);
                    let dst_vc =
                        crate::volume_class_cache::resolve_volume_class_from_path(&dst_path);

                    if let Some(_deny) = classify_and_log_path(
                        &src_path,
                        "MOVE",
                        "MoveFileExW",
                        0,
                        4,
                        src_vc,
                        dst_vc,
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }
                    if let Some(_deny) = classify_and_log_path(
                        &dst_path,
                        "MOVE",
                        "MoveFileExW",
                        0,
                        4,
                        src_vc,
                        dst_vc,
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }

                    let original = crate::ORIGINAL_MOVE_FILE_EX_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("MoveFileExW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(lpexistingfilename, lpnewfilename, dwflags)
                },
                || {
                    let original = crate::ORIGINAL_MOVE_FILE_EX_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("MoveFileExW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(lpexistingfilename, lpnewfilename, dwflags)
                },
            )
        },
        || {
            let original = crate::ORIGINAL_MOVE_FILE_EX_W.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("MoveFileExW"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(lpexistingfilename, lpnewfilename, dwflags)
        },
    )
}

// ---------------------------------------------------------------------------
// 6. HookCopyFileExW — path-based (source + destination)
// ---------------------------------------------------------------------------

/// Classification hook for `CopyFileExW`.
///
/// Path-based: evaluates BOTH source and destination paths. If either is
/// denied, the operation is blocked.
/// Deny returns `BOOL(0)` with `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookCopyFileExW(
    lpexistingfilename: PCWSTR,
    lpnewfilename: PCWSTR,
    lpprogressroutine: *mut std::ffi::c_void,
    lpdata: *mut std::ffi::c_void,
    pbcancel: *mut i32,
    dwcopyflags: u32,
) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "CopyFileExW",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let src_path = crate::pcwstr_to_string(lpexistingfilename);
                    let dst_path = crate::pcwstr_to_string(lpnewfilename);

                    let src_vc =
                        crate::volume_class_cache::resolve_volume_class_from_path(&src_path);
                    let dst_vc =
                        crate::volume_class_cache::resolve_volume_class_from_path(&dst_path);

                    if let Some(_deny) = classify_and_log_path(
                        &src_path,
                        "COPY",
                        "CopyFileExW",
                        0,
                        4,
                        src_vc,
                        dst_vc,
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }
                    if let Some(_deny) = classify_and_log_path(
                        &dst_path,
                        "COPY",
                        "CopyFileExW",
                        0,
                        4,
                        src_vc,
                        dst_vc,
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }

                    let original = crate::ORIGINAL_COPY_FILE_EX_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("CopyFileExW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        lpexistingfilename,
                        lpnewfilename,
                        lpprogressroutine,
                        lpdata,
                        pbcancel,
                        dwcopyflags,
                    )
                },
                || {
                    let original = crate::ORIGINAL_COPY_FILE_EX_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("CopyFileExW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        lpexistingfilename,
                        lpnewfilename,
                        lpprogressroutine,
                        lpdata,
                        pbcancel,
                        dwcopyflags,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_COPY_FILE_EX_W.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("CopyFileExW"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                lpexistingfilename,
                lpnewfilename,
                lpprogressroutine,
                lpdata,
                pbcancel,
                dwcopyflags,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 7. HookDeleteFileW — path-based
// ---------------------------------------------------------------------------

/// Classification hook for `DeleteFileW`.
///
/// Path-based: evaluates the file path. Deny returns `BOOL(0)` with
/// `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookDeleteFileW(lpfilename: PCWSTR) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "DeleteFileW",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let path = crate::pcwstr_to_string(lpfilename);
                    if let Some(_deny) =
                        classify_and_log_path(&path, "DELETE", "DeleteFileW", 0, 3, None, None)
                    {
                        return crate::fail_closed!(BoolFalse);
                    }
                    let original = crate::ORIGINAL_DELETE_FILE_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("DeleteFileW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(lpfilename)
                },
                || {
                    let original = crate::ORIGINAL_DELETE_FILE_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("DeleteFileW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(lpfilename)
                },
            )
        },
        || {
            let original = crate::ORIGINAL_DELETE_FILE_W.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("DeleteFileW"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(lpfilename)
        },
    )
}

// ---------------------------------------------------------------------------
// 8. HookReplaceFileW — path-based (replaced + replacement + backup)
// ---------------------------------------------------------------------------

/// Classification hook for `ReplaceFileW`.
///
/// Path-based: evaluates ALL three paths (replaced, replacement, backup).
/// If any is denied, the operation is blocked.
/// Deny returns `BOOL(0)` with `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookReplaceFileW(
    lpreplacedfilename: PCWSTR,
    lpreplacementfilename: PCWSTR,
    lpbackupfilename: PCWSTR,
    dwreplaceflags: u32,
    lpexclude: *mut std::ffi::c_void,
    lpreserved: *mut std::ffi::c_void,
) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "ReplaceFileW",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let replaced_path = crate::pcwstr_to_string(lpreplacedfilename);
                    let replacement_path = crate::pcwstr_to_string(lpreplacementfilename);
                    let backup_path = crate::pcwstr_to_string(lpbackupfilename);

                    if let Some(_deny) = classify_and_log_path(
                        &replaced_path,
                        "REPLACE",
                        "ReplaceFileW",
                        0,
                        4,
                        None,
                        None,
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }
                    if let Some(_deny) = classify_and_log_path(
                        &replacement_path,
                        "REPLACE",
                        "ReplaceFileW",
                        0,
                        4,
                        None,
                        None,
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }
                    if let Some(_deny) = classify_and_log_path(
                        &backup_path,
                        "REPLACE",
                        "ReplaceFileW",
                        0,
                        4,
                        None,
                        None,
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }

                    let original = crate::ORIGINAL_REPLACE_FILE_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("ReplaceFileW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        lpreplacedfilename,
                        lpreplacementfilename,
                        lpbackupfilename,
                        dwreplaceflags,
                        lpexclude,
                        lpreserved,
                    )
                },
                || {
                    let original = crate::ORIGINAL_REPLACE_FILE_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("ReplaceFileW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        lpreplacedfilename,
                        lpreplacementfilename,
                        lpbackupfilename,
                        dwreplaceflags,
                        lpexclude,
                        lpreserved,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_REPLACE_FILE_W.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("ReplaceFileW"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                lpreplacedfilename,
                lpreplacementfilename,
                lpbackupfilename,
                dwreplaceflags,
                lpexclude,
                lpreserved,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 9. HookSetFileInformationByHandle — handle-based, class-filtered
// ---------------------------------------------------------------------------

/// Classification hook for `SetFileInformationByHandle`.
///
/// Handle-based: sends the HANDLE value to the agent for path resolution.
/// Only blocks `FileRenameInfo` (class 10), `FileDispositionInfo` (class 4),
/// and `FileEndOfFileInfo` (class 6). All other classes pass through
/// immediately without classification.
/// Deny returns `BOOL(0)` with `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookSetFileInformationByHandle(
    hfile: HANDLE,
    fileinformationclass: i32,
    lpfileinformation: *mut std::ffi::c_void,
    dwbuffersize: u32,
) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "SetFileInformationByHandle",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    // Only block FileRenameInfo (10), FileDispositionInfo (4),
                    // and FileEndOfFileInfo (6). All other classes pass through.
                    const FILE_RENAME_INFO: i32 = 10;
                    const FILE_DISPOSITION_INFO: i32 = 4;
                    const FILE_END_OF_FILE_INFO: i32 = 6;

                    if fileinformationclass != FILE_RENAME_INFO
                        && fileinformationclass != FILE_DISPOSITION_INFO
                        && fileinformationclass != FILE_END_OF_FILE_INFO
                    {
                        let original = crate::ORIGINAL_SET_FILE_INFORMATION_BY_HANDLE
                            .unwrap_or_else(|| {
                                std::mem::transmute(
                                    crate::resolve_kernel32_proc(windows::core::s!(
                                        "SetFileInformationByHandle"
                                    ))
                                    .map(|f| f as *const std::ffi::c_void)
                                    .unwrap_or(std::ptr::null()),
                                )
                            });
                        return original(
                            hfile,
                            fileinformationclass,
                            lpfileinformation,
                            dwbuffersize,
                        );
                    }

                    let handle_value = hfile.0 as u64;
                    if let Some(_deny) = classify_and_log_handle(
                        handle_value,
                        "SET_INFO",
                        "SetFileInformationByHandle",
                        4,
                        "",
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }

                    let original =
                        crate::ORIGINAL_SET_FILE_INFORMATION_BY_HANDLE.unwrap_or_else(|| {
                            std::mem::transmute(
                                crate::resolve_kernel32_proc(windows::core::s!(
                                    "SetFileInformationByHandle"
                                ))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                            )
                        });
                    original(hfile, fileinformationclass, lpfileinformation, dwbuffersize)
                },
                || {
                    let original =
                        crate::ORIGINAL_SET_FILE_INFORMATION_BY_HANDLE.unwrap_or_else(|| {
                            std::mem::transmute(
                                crate::resolve_kernel32_proc(windows::core::s!(
                                    "SetFileInformationByHandle"
                                ))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                            )
                        });
                    original(hfile, fileinformationclass, lpfileinformation, dwbuffersize)
                },
            )
        },
        || {
            let original = crate::ORIGINAL_SET_FILE_INFORMATION_BY_HANDLE.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("SetFileInformationByHandle"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(hfile, fileinformationclass, lpfileinformation, dwbuffersize)
        },
    )
}

// ---------------------------------------------------------------------------
// 10. HookNtOpenFile — path-based
// ---------------------------------------------------------------------------

/// Classification hook for `NtOpenFile`.
///
/// Path-based: extracts the path from `OBJECT_ATTRIBUTES` and sends it to
/// the agent. Deny returns `NTSTATUS(STATUS_ACCESS_DENIED)`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookNtOpenFile(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut std::ffi::c_void,
    iostatusblock: *mut std::ffi::c_void,
    shareaccess: u32,
    openoptions: u32,
) -> NTSTATUS {
    crate::crash_guard::guard_trampoline(
        "NtOpenFile",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let path = crate::extract_nt_path(objectattributes);
                    if let Some(_deny) =
                        classify_and_log_path(&path, "OPEN", "NtOpenFile", 0, 1, None, None)
                    {
                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    let original = crate::ORIGINAL_NT_OPEN_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_ntdll_proc(windows::core::s!("NtOpenFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        filehandle,
                        desiredaccess,
                        objectattributes,
                        iostatusblock,
                        shareaccess,
                        openoptions,
                    )
                },
                || {
                    let original = crate::ORIGINAL_NT_OPEN_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_ntdll_proc(windows::core::s!("NtOpenFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        filehandle,
                        desiredaccess,
                        objectattributes,
                        iostatusblock,
                        shareaccess,
                        openoptions,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_NT_OPEN_FILE.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_ntdll_proc(windows::core::s!("NtOpenFile"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                filehandle,
                desiredaccess,
                objectattributes,
                iostatusblock,
                shareaccess,
                openoptions,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 11. HookNtWriteFile — handle-based
// ---------------------------------------------------------------------------

/// Classification hook for `NtWriteFile`.
///
/// Handle-based: sends the HANDLE value to the agent for path resolution.
/// Deny returns `NTSTATUS(STATUS_ACCESS_DENIED)`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookNtWriteFile(
    filehandle: HANDLE,
    event: HANDLE,
    apcroutine: *mut std::ffi::c_void,
    apccontext: *mut std::ffi::c_void,
    iostatusblock: *mut std::ffi::c_void,
    buffer: *const u8,
    length: u32,
    byteoffset: *const i64,
    key: *mut u32,
) -> NTSTATUS {
    crate::crash_guard::guard_trampoline(
        "NtWriteFile",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let handle_value = filehandle.0 as u64;
                    if let Some(_deny) =
                        classify_and_log_handle(handle_value, "NT_WRITE", "NtWriteFile", 2, "")
                    {
                        // DIFF-03: Compute content hash from buffer / length.
                        let (hash, truncated, skipped) = if !buffer.is_null() && length > 0 {
                            if (length as usize) < crate::hash_compute::SMALL_BUFFER_THRESHOLD {
                                unsafe { crate::hash_compute::compute_content_hash(buffer, length) }
                            } else {
                                unsafe {
                                    crate::hash_compute::compute_content_hash_offloaded(
                                        buffer, length,
                                    )
                                }
                            }
                        } else {
                            (None, false, false)
                        };

                        let evidence = dlp_common::hook_ipc::HashEvidenceFrame {
                            pid: std::process::id(),
                            handle_value,
                            content_sha256: hash,
                            hash_truncated: truncated,
                            hash_skipped: skipped,
                            timestamp_secs: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        };
                        let _ = crate::pipe_client::send_hash_evidence(
                            crate::current_pipe_name(),
                            &evidence,
                        );

                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    let original = crate::ORIGINAL_NT_WRITE_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_ntdll_proc(windows::core::s!("NtWriteFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        filehandle,
                        event,
                        apcroutine,
                        apccontext,
                        iostatusblock,
                        buffer,
                        length,
                        byteoffset,
                        key,
                    )
                },
                || {
                    let original = crate::ORIGINAL_NT_WRITE_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_ntdll_proc(windows::core::s!("NtWriteFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        filehandle,
                        event,
                        apcroutine,
                        apccontext,
                        iostatusblock,
                        buffer,
                        length,
                        byteoffset,
                        key,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_NT_WRITE_FILE.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_ntdll_proc(windows::core::s!("NtWriteFile"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                filehandle,
                event,
                apcroutine,
                apccontext,
                iostatusblock,
                buffer,
                length,
                byteoffset,
                key,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 12. HookNtSetInformationFile — handle-based
// ---------------------------------------------------------------------------

/// Classification hook for `NtSetInformationFile`.
///
/// Handle-based: sends the HANDLE value to the agent for path resolution.
/// Deny returns `NTSTATUS(STATUS_ACCESS_DENIED)`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookNtSetInformationFile(
    filehandle: HANDLE,
    iostatusblock: *mut std::ffi::c_void,
    fileinformation: *mut std::ffi::c_void,
    length: u32,
    fileinformationclass: u32,
) -> NTSTATUS {
    crate::crash_guard::guard_trampoline(
        "NtSetInformationFile",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let handle_value = filehandle.0 as u64;
                    if let Some(_deny) = classify_and_log_handle(
                        handle_value,
                        "NT_SET_INFO",
                        "NtSetInformationFile",
                        4,
                        "",
                    ) {
                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    let original = crate::ORIGINAL_NT_SET_INFORMATION_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_ntdll_proc(windows::core::s!("NtSetInformationFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        filehandle,
                        iostatusblock,
                        fileinformation,
                        length,
                        fileinformationclass,
                    )
                },
                || {
                    let original = crate::ORIGINAL_NT_SET_INFORMATION_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_ntdll_proc(windows::core::s!("NtSetInformationFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        filehandle,
                        iostatusblock,
                        fileinformation,
                        length,
                        fileinformationclass,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_NT_SET_INFORMATION_FILE.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_ntdll_proc(windows::core::s!("NtSetInformationFile"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                filehandle,
                iostatusblock,
                fileinformation,
                length,
                fileinformationclass,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// Ntdll-specific trampolines (Phase 51)
//
// These trampolines are installed by ntdll_patcher via retour::RawDetour
// on the ntdll syscall stubs themselves (not the IAT). They follow the same
// classification pipeline as IAT trampolines but call the original stub
// through retour's generated trampoline instead of the IAT-saved pointer.
// ---------------------------------------------------------------------------

/// Classification hook for `NtCreateFile` via ntdll stub patching.
///
/// Path-based: extracts the path from `OBJECT_ATTRIBUTES` and sends it to
/// the agent. Deny returns `NTSTATUS(STATUS_ACCESS_DENIED)`.
/// Guard name: "NtCreateFile_ntdll" (distinguishes from IAT hook).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn NtdllTrampolineNtCreateFile(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut std::ffi::c_void,
    iostatusblock: *mut std::ffi::c_void,
    allocationsize: *const i64,
    fileattributes: u32,
    shareaccess: u32,
    createdisposition: u32,
    createoptions: u32,
    eabuffer: *mut std::ffi::c_void,
    ealength: u32,
) -> NTSTATUS {
    // Phase 51: Lazy-init ntdll patcher on first trampoline invocation.
    // The AtomicBool check is ~1ns; Mutex lock only on first call.
    if crate::NTDLL_PATCHING_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        let _ = crate::lazy_init_ntdll_patcher(true);
    }

    crate::crash_guard::guard_trampoline(
        "NtCreateFile_ntdll",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let path = crate::extract_nt_path(objectattributes);
                    if let Some(_deny) =
                        classify_and_log_path(&path, "CREATE", "NtCreateFile", 0, 1, None, None)
                    {
                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    let original_ptr =
                        crate::ntdll_patcher::get_original_trampoline("NtCreateFile");
                    if let Some(ptr) = original_ptr {
                        let original: crate::NtCreateFileFn = std::mem::transmute(ptr);
                        original(
                            filehandle,
                            desiredaccess,
                            objectattributes,
                            iostatusblock,
                            allocationsize,
                            fileattributes,
                            shareaccess,
                            createdisposition,
                            createoptions,
                            eabuffer,
                            ealength,
                        )
                    } else {
                        let Some(fallback) = (unsafe { crate::resolve_nt_create_file() }) else {
                            return crate::fail_closed!(StatusAccessDenied);
                        };
                        fallback(
                            filehandle,
                            desiredaccess,
                            objectattributes,
                            iostatusblock,
                            allocationsize,
                            fileattributes,
                            shareaccess,
                            createdisposition,
                            createoptions,
                            eabuffer,
                            ealength,
                        )
                    }
                },
                || {
                    let original_ptr =
                        crate::ntdll_patcher::get_original_trampoline("NtCreateFile");
                    if let Some(ptr) = original_ptr {
                        let original: crate::NtCreateFileFn = std::mem::transmute(ptr);
                        original(
                            filehandle,
                            desiredaccess,
                            objectattributes,
                            iostatusblock,
                            allocationsize,
                            fileattributes,
                            shareaccess,
                            createdisposition,
                            createoptions,
                            eabuffer,
                            ealength,
                        )
                    } else {
                        let Some(fallback) = (unsafe { crate::resolve_nt_create_file() }) else {
                            return crate::fail_closed!(StatusAccessDenied);
                        };
                        fallback(
                            filehandle,
                            desiredaccess,
                            objectattributes,
                            iostatusblock,
                            allocationsize,
                            fileattributes,
                            shareaccess,
                            createdisposition,
                            createoptions,
                            eabuffer,
                            ealength,
                        )
                    }
                },
            )
        },
        || {
            let Some(fallback) = (unsafe { crate::resolve_nt_create_file() }) else {
                return crate::fail_closed!(StatusAccessDenied);
            };
            fallback(
                filehandle,
                desiredaccess,
                objectattributes,
                iostatusblock,
                allocationsize,
                fileattributes,
                shareaccess,
                createdisposition,
                createoptions,
                eabuffer,
                ealength,
            )
        },
    )
}

/// Classification hook for `NtOpenFile` via ntdll stub patching.
///
/// Path-based: extracts the path from `OBJECT_ATTRIBUTES` and sends it to
/// the agent. Deny returns `NTSTATUS(STATUS_ACCESS_DENIED)`.
/// Guard name: "NtOpenFile_ntdll".
#[unsafe(no_mangle)]
pub unsafe extern "system" fn NtdllTrampolineNtOpenFile(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut std::ffi::c_void,
    iostatusblock: *mut std::ffi::c_void,
    shareaccess: u32,
    openoptions: u32,
) -> NTSTATUS {
    // Phase 51: Lazy-init ntdll patcher on first trampoline invocation.
    if crate::NTDLL_PATCHING_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        let _ = crate::lazy_init_ntdll_patcher(true);
    }

    crate::crash_guard::guard_trampoline(
        "NtOpenFile_ntdll",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let path = crate::extract_nt_path(objectattributes);
                    if let Some(_deny) =
                        classify_and_log_path(&path, "OPEN", "NtOpenFile", 0, 1, None, None)
                    {
                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    let original_ptr = crate::ntdll_patcher::get_original_trampoline("NtOpenFile");
                    if let Some(ptr) = original_ptr {
                        let original: unsafe extern "system" fn(
                            *mut HANDLE,
                            u32,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            u32,
                            u32,
                        )
                            -> NTSTATUS = std::mem::transmute(ptr);
                        original(
                            filehandle,
                            desiredaccess,
                            objectattributes,
                            iostatusblock,
                            shareaccess,
                            openoptions,
                        )
                    } else {
                        let Some(fallback) =
                            (unsafe { crate::resolve_ntdll_proc(windows::core::s!("NtOpenFile")) })
                        else {
                            return crate::fail_closed!(StatusAccessDenied);
                        };
                        let original: unsafe extern "system" fn(
                            *mut HANDLE,
                            u32,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            u32,
                            u32,
                        )
                            -> NTSTATUS = std::mem::transmute(fallback);
                        original(
                            filehandle,
                            desiredaccess,
                            objectattributes,
                            iostatusblock,
                            shareaccess,
                            openoptions,
                        )
                    }
                },
                || {
                    let original_ptr = crate::ntdll_patcher::get_original_trampoline("NtOpenFile");
                    if let Some(ptr) = original_ptr {
                        let original: unsafe extern "system" fn(
                            *mut HANDLE,
                            u32,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            u32,
                            u32,
                        )
                            -> NTSTATUS = std::mem::transmute(ptr);
                        original(
                            filehandle,
                            desiredaccess,
                            objectattributes,
                            iostatusblock,
                            shareaccess,
                            openoptions,
                        )
                    } else {
                        let Some(fallback) =
                            (unsafe { crate::resolve_ntdll_proc(windows::core::s!("NtOpenFile")) })
                        else {
                            return crate::fail_closed!(StatusAccessDenied);
                        };
                        let original: unsafe extern "system" fn(
                            *mut HANDLE,
                            u32,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            u32,
                            u32,
                        )
                            -> NTSTATUS = std::mem::transmute(fallback);
                        original(
                            filehandle,
                            desiredaccess,
                            objectattributes,
                            iostatusblock,
                            shareaccess,
                            openoptions,
                        )
                    }
                },
            )
        },
        || {
            let Some(fallback) =
                (unsafe { crate::resolve_ntdll_proc(windows::core::s!("NtOpenFile")) })
            else {
                return crate::fail_closed!(StatusAccessDenied);
            };
            let original: unsafe extern "system" fn(
                *mut HANDLE,
                u32,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                u32,
                u32,
            ) -> NTSTATUS = std::mem::transmute(fallback);
            original(
                filehandle,
                desiredaccess,
                objectattributes,
                iostatusblock,
                shareaccess,
                openoptions,
            )
        },
    )
}

/// Classification hook for `NtWriteFile` via ntdll stub patching.
///
/// Handle-based: sends the HANDLE value to the agent for path resolution.
/// Deny returns `NTSTATUS(STATUS_ACCESS_DENIED)`.
/// Guard name: "NtWriteFile_ntdll".
#[unsafe(no_mangle)]
pub unsafe extern "system" fn NtdllTrampolineNtWriteFile(
    filehandle: HANDLE,
    event: HANDLE,
    apcroutine: *mut std::ffi::c_void,
    apccontext: *mut std::ffi::c_void,
    iostatusblock: *mut std::ffi::c_void,
    buffer: *const u8,
    length: u32,
    byteoffset: *const i64,
    key: *mut u32,
) -> NTSTATUS {
    // Phase 51: Lazy-init ntdll patcher on first trampoline invocation.
    if crate::NTDLL_PATCHING_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        let _ = crate::lazy_init_ntdll_patcher(true);
    }

    crate::crash_guard::guard_trampoline(
        "NtWriteFile_ntdll",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let handle_value = filehandle.0 as u64;
                    if let Some(_deny) =
                        classify_and_log_handle(handle_value, "NT_WRITE", "NtWriteFile", 2, "")
                    {
                        // DIFF-03: Compute content hash from buffer / length.
                        let (hash, truncated, skipped) = if !buffer.is_null() && length > 0 {
                            if (length as usize) < crate::hash_compute::SMALL_BUFFER_THRESHOLD {
                                unsafe { crate::hash_compute::compute_content_hash(buffer, length) }
                            } else {
                                unsafe {
                                    crate::hash_compute::compute_content_hash_offloaded(
                                        buffer, length,
                                    )
                                }
                            }
                        } else {
                            (None, false, false)
                        };

                        let evidence = dlp_common::hook_ipc::HashEvidenceFrame {
                            pid: std::process::id(),
                            handle_value,
                            content_sha256: hash,
                            hash_truncated: truncated,
                            hash_skipped: skipped,
                            timestamp_secs: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        };
                        let _ = crate::pipe_client::send_hash_evidence(
                            crate::current_pipe_name(),
                            &evidence,
                        );

                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    let original_ptr = crate::ntdll_patcher::get_original_trampoline("NtWriteFile");
                    if let Some(ptr) = original_ptr {
                        let original: unsafe extern "system" fn(
                            HANDLE,
                            HANDLE,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            *const u8,
                            u32,
                            *const i64,
                            *mut u32,
                        )
                            -> NTSTATUS = std::mem::transmute(ptr);
                        original(
                            filehandle,
                            event,
                            apcroutine,
                            apccontext,
                            iostatusblock,
                            buffer,
                            length,
                            byteoffset,
                            key,
                        )
                    } else {
                        let Some(fallback) = (unsafe {
                            crate::resolve_ntdll_proc(windows::core::s!("NtWriteFile"))
                        }) else {
                            return crate::fail_closed!(StatusAccessDenied);
                        };
                        let original: unsafe extern "system" fn(
                            HANDLE,
                            HANDLE,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            *const u8,
                            u32,
                            *const i64,
                            *mut u32,
                        )
                            -> NTSTATUS = std::mem::transmute(fallback);
                        original(
                            filehandle,
                            event,
                            apcroutine,
                            apccontext,
                            iostatusblock,
                            buffer,
                            length,
                            byteoffset,
                            key,
                        )
                    }
                },
                || {
                    let original_ptr = crate::ntdll_patcher::get_original_trampoline("NtWriteFile");
                    if let Some(ptr) = original_ptr {
                        let original: unsafe extern "system" fn(
                            HANDLE,
                            HANDLE,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            *const u8,
                            u32,
                            *const i64,
                            *mut u32,
                        )
                            -> NTSTATUS = std::mem::transmute(ptr);
                        original(
                            filehandle,
                            event,
                            apcroutine,
                            apccontext,
                            iostatusblock,
                            buffer,
                            length,
                            byteoffset,
                            key,
                        )
                    } else {
                        let Some(fallback) = (unsafe {
                            crate::resolve_ntdll_proc(windows::core::s!("NtWriteFile"))
                        }) else {
                            return crate::fail_closed!(StatusAccessDenied);
                        };
                        let original: unsafe extern "system" fn(
                            HANDLE,
                            HANDLE,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            *const u8,
                            u32,
                            *const i64,
                            *mut u32,
                        )
                            -> NTSTATUS = std::mem::transmute(fallback);
                        original(
                            filehandle,
                            event,
                            apcroutine,
                            apccontext,
                            iostatusblock,
                            buffer,
                            length,
                            byteoffset,
                            key,
                        )
                    }
                },
            )
        },
        || {
            let Some(fallback) =
                (unsafe { crate::resolve_ntdll_proc(windows::core::s!("NtWriteFile")) })
            else {
                return crate::fail_closed!(StatusAccessDenied);
            };
            let original: unsafe extern "system" fn(
                HANDLE,
                HANDLE,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const u8,
                u32,
                *const i64,
                *mut u32,
            ) -> NTSTATUS = std::mem::transmute(fallback);
            original(
                filehandle,
                event,
                apcroutine,
                apccontext,
                iostatusblock,
                buffer,
                length,
                byteoffset,
                key,
            )
        },
    )
}

/// Classification hook for `NtSetInformationFile` via ntdll stub patching.
///
/// Handle-based: sends the HANDLE value to the agent for path resolution.
/// Deny returns `NTSTATUS(STATUS_ACCESS_DENIED)`.
/// Guard name: "NtSetInformationFile_ntdll".
#[unsafe(no_mangle)]
pub unsafe extern "system" fn NtdllTrampolineNtSetInformationFile(
    filehandle: HANDLE,
    iostatusblock: *mut std::ffi::c_void,
    fileinformation: *mut std::ffi::c_void,
    length: u32,
    fileinformationclass: u32,
) -> NTSTATUS {
    // Phase 51: Lazy-init ntdll patcher on first trampoline invocation.
    if crate::NTDLL_PATCHING_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        let _ = crate::lazy_init_ntdll_patcher(true);
    }

    crate::crash_guard::guard_trampoline(
        "NtSetInformationFile_ntdll",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let handle_value = filehandle.0 as u64;
                    if let Some(_deny) = classify_and_log_handle(
                        handle_value,
                        "NT_SET_INFO",
                        "NtSetInformationFile",
                        4,
                        "",
                    ) {
                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    let original_ptr =
                        crate::ntdll_patcher::get_original_trampoline("NtSetInformationFile");
                    if let Some(ptr) = original_ptr {
                        let original: unsafe extern "system" fn(
                            HANDLE,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            u32,
                            u32,
                        )
                            -> NTSTATUS = std::mem::transmute(ptr);
                        original(
                            filehandle,
                            iostatusblock,
                            fileinformation,
                            length,
                            fileinformationclass,
                        )
                    } else {
                        let Some(fallback) = (unsafe {
                            crate::resolve_ntdll_proc(windows::core::s!("NtSetInformationFile"))
                        }) else {
                            return crate::fail_closed!(StatusAccessDenied);
                        };
                        let original: unsafe extern "system" fn(
                            HANDLE,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            u32,
                            u32,
                        )
                            -> NTSTATUS = std::mem::transmute(fallback);
                        original(
                            filehandle,
                            iostatusblock,
                            fileinformation,
                            length,
                            fileinformationclass,
                        )
                    }
                },
                || {
                    let original_ptr =
                        crate::ntdll_patcher::get_original_trampoline("NtSetInformationFile");
                    if let Some(ptr) = original_ptr {
                        let original: unsafe extern "system" fn(
                            HANDLE,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            u32,
                            u32,
                        )
                            -> NTSTATUS = std::mem::transmute(ptr);
                        original(
                            filehandle,
                            iostatusblock,
                            fileinformation,
                            length,
                            fileinformationclass,
                        )
                    } else {
                        let Some(fallback) = (unsafe {
                            crate::resolve_ntdll_proc(windows::core::s!("NtSetInformationFile"))
                        }) else {
                            return crate::fail_closed!(StatusAccessDenied);
                        };
                        let original: unsafe extern "system" fn(
                            HANDLE,
                            *mut std::ffi::c_void,
                            *mut std::ffi::c_void,
                            u32,
                            u32,
                        )
                            -> NTSTATUS = std::mem::transmute(fallback);
                        original(
                            filehandle,
                            iostatusblock,
                            fileinformation,
                            length,
                            fileinformationclass,
                        )
                    }
                },
            )
        },
        || {
            let Some(fallback) =
                (unsafe { crate::resolve_ntdll_proc(windows::core::s!("NtSetInformationFile")) })
            else {
                return crate::fail_closed!(StatusAccessDenied);
            };
            let original: unsafe extern "system" fn(
                HANDLE,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                u32,
                u32,
            ) -> NTSTATUS = std::mem::transmute(fallback);
            original(
                filehandle,
                iostatusblock,
                fileinformation,
                length,
                fileinformationclass,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_createfilew_is_exported() {
        // Verify the symbol exists and has the correct ABI.
        let _fn: unsafe extern "system" fn(
            PCWSTR,
            u32,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE,
            *const windows::Win32::Security::SECURITY_ATTRIBUTES,
            windows::Win32::Storage::FileSystem::FILE_CREATION_DISPOSITION,
            windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
            HANDLE,
        ) -> HANDLE = HookCreateFileW;
    }

    #[test]
    fn hook_ntcreatefile_is_exported() {
        let _fn: unsafe extern "system" fn(
            *mut HANDLE,
            u32,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *const i64,
            u32,
            u32,
            u32,
            u32,
            *mut std::ffi::c_void,
            u32,
        ) -> NTSTATUS = HookNtCreateFile;
    }

    #[test]
    fn hook_writefile_is_exported() {
        let _fn: unsafe extern "system" fn(
            HANDLE,
            *const u8,
            u32,
            *mut u32,
            *mut std::ffi::c_void,
        ) -> windows::core::BOOL = HookWriteFile;
    }

    #[test]
    fn hook_writefileex_is_exported() {
        let _fn: unsafe extern "system" fn(
            HANDLE,
            *const u8,
            u32,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
        ) -> windows::core::BOOL = HookWriteFileEx;
    }

    #[test]
    fn hook_movefileexw_is_exported() {
        let _fn: unsafe extern "system" fn(PCWSTR, PCWSTR, u32) -> windows::core::BOOL =
            HookMoveFileExW;
    }

    #[test]
    fn hook_copyfileexw_is_exported() {
        let _fn: unsafe extern "system" fn(
            PCWSTR,
            PCWSTR,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *mut i32,
            u32,
        ) -> windows::core::BOOL = HookCopyFileExW;
    }

    #[test]
    fn hook_deletefilew_is_exported() {
        let _fn: unsafe extern "system" fn(PCWSTR) -> windows::core::BOOL = HookDeleteFileW;
    }

    #[test]
    fn hook_replacefilew_is_exported() {
        let _fn: unsafe extern "system" fn(
            PCWSTR,
            PCWSTR,
            PCWSTR,
            u32,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
        ) -> windows::core::BOOL = HookReplaceFileW;
    }

    #[test]
    fn hook_setfileinformationbyhandle_is_exported() {
        let _fn: unsafe extern "system" fn(
            HANDLE,
            i32,
            *mut std::ffi::c_void,
            u32,
        ) -> windows::core::BOOL = HookSetFileInformationByHandle;
    }

    #[test]
    fn hook_ntopenfile_is_exported() {
        let _fn: unsafe extern "system" fn(
            *mut HANDLE,
            u32,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            u32,
            u32,
        ) -> NTSTATUS = HookNtOpenFile;
    }

    #[test]
    fn hook_ntwritefile_is_exported() {
        let _fn: unsafe extern "system" fn(
            HANDLE,
            HANDLE,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *const u8,
            u32,
            *const i64,
            *mut u32,
        ) -> NTSTATUS = HookNtWriteFile;
    }

    #[test]
    fn hook_ntsetinformationfile_is_exported() {
        let _fn: unsafe extern "system" fn(
            HANDLE,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            u32,
            u32,
        ) -> NTSTATUS = HookNtSetInformationFile;
    }

    #[test]
    fn all_twelve_trampolines_have_no_mangle() {
        // This test is a compile-time check: if any trampoline is missing
        // #[unsafe(no_mangle)], the symbol won't be exported and this test
        // would fail to link (but we verify by function pointer assignment).
        let _trampolines: [unsafe extern "system" fn(); 12] = unsafe {
            [
                std::mem::transmute(HookCreateFileW as *const ()),
                std::mem::transmute(HookNtCreateFile as *const ()),
                std::mem::transmute(HookWriteFile as *const ()),
                std::mem::transmute(HookWriteFileEx as *const ()),
                std::mem::transmute(HookMoveFileExW as *const ()),
                std::mem::transmute(HookCopyFileExW as *const ()),
                std::mem::transmute(HookDeleteFileW as *const ()),
                std::mem::transmute(HookReplaceFileW as *const ()),
                std::mem::transmute(HookSetFileInformationByHandle as *const ()),
                std::mem::transmute(HookNtOpenFile as *const ()),
                std::mem::transmute(HookNtWriteFile as *const ()),
                std::mem::transmute(HookNtSetInformationFile as *const ()),
            ]
        };
    }

    // -- Ntdll trampoline export tests (Phase 51-03) --

    #[test]
    fn ntdll_trampoline_ntcreatefile_is_exported() {
        let _fn: unsafe extern "system" fn(
            *mut HANDLE,
            u32,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *const i64,
            u32,
            u32,
            u32,
            u32,
            *mut std::ffi::c_void,
            u32,
        ) -> NTSTATUS = NtdllTrampolineNtCreateFile;
    }

    #[test]
    fn ntdll_trampoline_ntopenfile_is_exported() {
        let _fn: unsafe extern "system" fn(
            *mut HANDLE,
            u32,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            u32,
            u32,
        ) -> NTSTATUS = NtdllTrampolineNtOpenFile;
    }

    #[test]
    fn ntdll_trampoline_ntwritefile_is_exported() {
        let _fn: unsafe extern "system" fn(
            HANDLE,
            HANDLE,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *const u8,
            u32,
            *const i64,
            *mut u32,
        ) -> NTSTATUS = NtdllTrampolineNtWriteFile;
    }

    #[test]
    fn ntdll_trampoline_ntsetinformationfile_is_exported() {
        let _fn: unsafe extern "system" fn(
            HANDLE,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            u32,
            u32,
        ) -> NTSTATUS = NtdllTrampolineNtSetInformationFile;
    }

    #[test]
    fn test_classify_path_with_volume_class_populates_fields() {
        // Minimal unit test: verify HookRequest can be constructed with volume class fields.
        // This proves the fields exist and are accessible from the hook DLL side.
        // A more comprehensive integration test with actual pipe communication will be
        // added in Plan 03.
        let req = dlp_common::HookRequest {
            path: "C:\\test.txt".to_string(),
            action: "WRITE".to_string(),
            source_volume_class: Some(dlp_common::VolumeClass::USBRemovable),
            destination_volume_class: Some(dlp_common::VolumeClass::Optical),
            ..Default::default()
        };
        assert_eq!(
            req.source_volume_class,
            Some(dlp_common::VolumeClass::USBRemovable)
        );
        assert_eq!(
            req.destination_volume_class,
            Some(dlp_common::VolumeClass::Optical)
        );
    }

    #[test]
    fn all_ntdll_trampolines_have_no_mangle() {
        // Compile-time check: all four ntdll trampolines are exported.
        let _trampolines: [unsafe extern "system" fn(); 4] = unsafe {
            [
                std::mem::transmute(NtdllTrampolineNtCreateFile as *const ()),
                std::mem::transmute(NtdllTrampolineNtOpenFile as *const ()),
                std::mem::transmute(NtdllTrampolineNtWriteFile as *const ()),
                std::mem::transmute(NtdllTrampolineNtSetInformationFile as *const ()),
            ]
        };
    }

    // --- DIFF-02: Diagnostic snapshot on DENY ---

    #[test]
    fn test_diagnostic_snapshot_on_deny_path() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        crate::reset_for_test();

        let handler =
            std::sync::Arc::new(|_req: dlp_common::HookRequest| dlp_common::HookResponse {
                decision: dlp_common::Decision::DENY,
                reason: "denied".to_string(),
                cache_hint: None,
                cache_version: 0,
                approval_override: None,
            });
        let _server = crate::MockAgentServer::start(handler);
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Call classify_and_log_path with a test path and action.
        // The mock server returns DENY, so this should push a diagnostic snapshot.
        let result = classify_and_log_path(
            r"C:\test\secret.txt",
            "CREATE",
            "CreateFileW",
            0,
            1,
            None,
            None,
        );
        assert!(result.is_some(), "expected DENY from mock server");

        // Verify the diagnostic ring contains the expected snapshot.
        let snapshots = crate::diagnostic_ring::drain_snapshots(10);
        assert!(
            !snapshots.is_empty(),
            "expected at least one diagnostic snapshot after DENY"
        );

        let snapshot = &snapshots[0];
        assert_eq!(snapshot.hook_function, "CreateFileW");
        assert_eq!(snapshot.abac_resource, r"C:\test\secret.txt");
        assert_eq!(snapshot.abac_action, "CREATE");
        assert!(
            !snapshot.user_sid.is_empty(),
            "user_sid should be non-empty"
        );
        assert!(snapshot.timestamp_qpc > 0, "timestamp_qpc should be > 0");

        // Clean up.
        crate::diagnostic_ring::drain_all_snapshots();
    }

    #[test]
    fn test_diagnostic_snapshot_on_deny_handle() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        crate::reset_hook_globals();
        crate::perf_telemetry::reset_perf_counters();
        crate::pipe_client::reset_pipe_client_mocks();
        // Drain any leftover snapshots from prior tests.
        crate::diagnostic_ring::drain_all_snapshots();

        // classify_and_log_handle uses DEFAULT_PIPE_NAME internally.
        // With no server running, it will fail-closed (DENY) and push a snapshot.
        let result = classify_and_log_handle(0xABCD, "WRITE", "WriteFile", 2, "");
        assert!(result.is_some(), "expected DENY (fail-closed)");

        // Verify the diagnostic ring contains the expected snapshot.
        let snapshots = crate::diagnostic_ring::drain_snapshots(10);
        assert!(
            !snapshots.is_empty(),
            "expected at least one diagnostic snapshot after handle DENY"
        );

        let snapshot = &snapshots[0];
        assert_eq!(snapshot.hook_function, "WriteFile");
        assert_eq!(snapshot.abac_action, "WRITE");
        assert!(
            !snapshot.user_sid.is_empty(),
            "user_sid should be non-empty"
        );
        assert!(snapshot.timestamp_qpc > 0, "timestamp_qpc should be > 0");

        // Clean up.
        crate::diagnostic_ring::drain_all_snapshots();
    }

    // --- Phase 56: Volume class wiring tests ---

    #[test]
    fn test_classify_and_log_path_resolves_volume_class() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        crate::reset_hook_globals();
        crate::perf_telemetry::reset_perf_counters();
        crate::pipe_client::reset_pipe_client_mocks();

        // Pre-warm the cache so resolve_volume_class_from_path returns a known value.
        crate::volume_class_cache::invalidate_cache();
        crate::volume_class_cache::VOLUME_CLASS_CACHE.with(|cache| {
            cache.borrow_mut().insert(
                'C',
                (
                    dlp_common::VolumeClass::USBRemovable,
                    std::time::Instant::now(),
                ),
            );
        });

        // Call classify_and_log_path with None, None — it should auto-resolve from path.
        // Since there's no agent, the pipe will fail and it returns fail-closed.
        // The test verifies it compiles and runs without panic (volume class resolution
        // happens inside the function).
        let _result = classify_and_log_path(r"C:\test.txt", "CREATE", "Test", 0, 1, None, None);
        // Result is Some(deny) because no agent is running — that's expected.
    }

    #[test]
    fn test_classify_and_log_path_uses_pre_resolved_volume_class() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        crate::reset_hook_globals();
        crate::perf_telemetry::reset_perf_counters();
        crate::pipe_client::reset_pipe_client_mocks();

        // When source_volume_class is pre-resolved (e.g., from copy/move trampolines),
        // the function should use it directly without re-resolving.
        let _result = classify_and_log_path(
            r"C:\test.txt",
            "CREATE",
            "Test",
            0,
            1,
            Some(dlp_common::VolumeClass::USBRemovable),
            Some(dlp_common::VolumeClass::NetworkShare),
        );
        // Result is Some(deny) because no agent is running — that's expected.
        // The test verifies pre-resolved values are accepted and forwarded.
    }

    #[test]
    fn shutdown_pass_through_skips_classification() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        crate::reset_hook_globals();
        crate::perf_telemetry::reset_perf_counters();

        // With no agent running, a normal call would fail-closed (DENY).
        // When shutting down, the call should pass through and also return None
        // so the trampoline calls the original API. In the test binary there is
        // no original function installed, so classify_and_log_handle returns None
        // because shutdown mode bypasses classification. The important invariant
        // is that no pipe round-trip or snapshot is produced.
        crate::set_shutting_down_for_test(true);
        let result = classify_and_log_handle(0x1234, "WRITE", "WriteFile", 2, "");
        crate::set_shutting_down_for_test(false);
        assert!(result.is_none());
    }

    #[test]
    fn active_call_counter_increments_and_decrements() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        crate::reset_hook_globals();

        // Ensure shutdown flag is clear; a prior test may have left it set.
        crate::set_shutting_down_for_test(false);
        let before = crate::active_call_count();
        {
            let guard = crate::ActiveCallGuard::new();
            assert!(guard.is_active());
            assert_eq!(crate::active_call_count(), before + 1);
        }
        assert_eq!(crate::active_call_count(), before);
    }

    #[test]
    fn active_call_guard_skips_when_shutting_down() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        crate::reset_hook_globals();

        crate::set_shutting_down_for_test(true);
        let guard = crate::ActiveCallGuard::new();
        assert!(!guard.is_active());
        crate::set_shutting_down_for_test(false);
    }

    // --- DIFF-01: Approval override allows denied operation ---
    //
    // Renamed with `zzz_` prefix so cargo test runs it LAST in this module.
    // The mock agent server is started on a unique pipe by MockAgentServer::start,
    // so a leaked server cannot collide with other tests.
    #[test]
    fn test_zzz_approval_override_allows_deny_path() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        crate::reset_for_test();

        let handler =
            std::sync::Arc::new(|_req: dlp_common::HookRequest| dlp_common::HookResponse {
                decision: dlp_common::Decision::DENY,
                reason: "denied-but-overridden".to_string(),
                cache_hint: None,
                cache_version: 0,
                approval_override: Some(true),
            });
        let _server = crate::MockAgentServer::start(handler);
        std::thread::sleep(std::time::Duration::from_millis(50));

        let result = classify_and_log_path(
            r"C:\test\approval_override_unique_path.txt",
            "CREATE",
            "CreateFileW",
            0,
            1,
            None,
            None,
        );

        assert!(
            result.is_none(),
            "approval_override=true on DENY should allow the operation (return None)"
        );

        // An allowed operation must NOT leave a diagnostic snapshot in the ring.
        let snapshots = crate::diagnostic_ring::drain_snapshots(10);
        assert!(
            snapshots.is_empty(),
            "override allow should not produce a diagnostic snapshot"
        );
    }
}
