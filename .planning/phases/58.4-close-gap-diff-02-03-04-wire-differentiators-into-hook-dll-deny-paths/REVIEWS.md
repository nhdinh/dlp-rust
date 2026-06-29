---
phase: 58.4
reviewers: [claude, codex-unavailable]
reviewed_at: 2026-06-29T00:00:00Z
plans_reviewed:
  - 58.4-01-PLAN.md
  - 58.4-02-PLAN.md
  - 58.4-03-PLAN.md
  - 58.4-04-PLAN.md
---

# Cross-AI Plan Review — Phase 58.4

## Codex Review

Codex CLI (all models: gpt-5.3-codex, gpt-4o, o3) could not be invoked due to account restrictions:
"The model is not supported when using Codex with a ChatGPT account."
Tried fallback models (gpt-4o, o3, gpt-5-codex) — all rejected with same error.
No local OSS provider (Ollama/LM Studio) available.

**Reviewer substituted:** Claude Code CLI (kimi-k2.7-code) performed the review in place of Codex.

---

## Claude Review (Claude Code CLI, kimi-k2.7-code)

### Plan 58.4-01: Wire Diagnostic Snapshot Capture (DIFF-02)

**Summary:** This plan wires `DiagnosticRing::push_snapshot` into the deny branches of `classify_and_log_path` and `classify_and_log_handle`. The design is straightforward and reuses existing infrastructure well. However, there are correctness and safety issues in the snapshot construction and a missing integration concern.

**Strengths:**
- Reuses the existing `DiagnosticRing` (1000-entry cap, lock-free ArrayQueue) without introducing new data structures.
- Fire-and-forget semantics (`let _ = ...`) correctly prevent snapshot push from blocking or altering the deny decision.
- No change to ALLOW paths preserves the fast-path performance guarantee.
- `get_current_user_sid()` helper correctly uses Windows API (`OpenProcessToken` -> `GetTokenInformation` -> `ConvertSidToStringSidA`) with SYSTEM fallback.

**Concerns:**
- **HIGH:** `classify_and_log_path` and `classify_and_log_handle` do not currently have access to `classification_source` or `classification_age_ms` at the deny branch. The plan says "use `CacheHit` if `cache_classification.is_some()`" but `cache_classification` is not in scope in the deny branch of these functions (it is computed inside the classification closure). The plan must specify how to thread these values out, or accept that they will be `Pipe` / `0` for v0.10.0. If the plan proceeds with `Pipe` / `0` defaults, it must document this as a known gap.
- **HIGH:** The `decision_latency_us` field uses `elapsed_qpc` (QPC ticks), not microseconds. The plan says "QPC ticks, not us — needs conversion" but does not include a conversion task. Without conversion, the `decision_latency_us` field will contain raw QPC ticks (typically ~10MHz on modern x64), which is off by 7 orders of magnitude from microseconds. This makes the field useless for triage. Add a `qpc_to_us()` helper or document the raw-tick interpretation.
- **MEDIUM:** `abac_environment` is set to `format!("{:?}", source_volume_class)` or `"unknown"`. The `source_volume_class` is an `Option<VolumeClass>`; `format!("{:?}", None)` produces `"None"`, which is not a useful environment string. The plan should explicitly handle `None` as `"unknown"` and `Some(v)` as the volume class name.
- **MEDIUM:** `matched_policy_id` and `enforcement_mode` are set to `None` with the rationale "not available in hook DLL without pipe response parsing." This is correct for the current architecture, but it means the diagnostic snapshot is incomplete per D-02. The plan should add a TODO comment and a deferred task to enrich these fields when the agent returns them in `HookResponse`.
- **LOW:** The `timestamp_qpc` field uses `unsafe { query_performance_counter() }`, which is safe but the plan does not mention the `#[cfg(windows)]` guard. On non-Windows test environments, this will fail to compile. The `diagnostic_ring.rs` already handles this with a `#[cfg(windows)]` block; the plan should reference that pattern.

**Suggestions:**
- Add a task to thread `classification_source` and `classification_age_ms` from the cache lookup path to the deny branch, or document the fallback to `Pipe` / `0`.
- Add a `qpc_to_us()` conversion helper and apply it to `decision_latency_us` before constructing the snapshot.
- Explicitly map `source_volume_class` to a string: `source_volume_class.map(|v| v.to_string()).unwrap_or_else(|| "unknown".to_string())`.
- Add a deferred task for enriching `matched_policy_id` and `enforcement_mode` from `HookResponse`.

**Risk Assessment:** MEDIUM — the QPC-to-us conversion and missing classification_source are the main gaps. Both are fixable within the plan.

---

### Plan 58.4-02: Wire Content SHA-256 Hash Computation (DIFF-03)

**Summary:** This plan wires SHA-256 hash computation into `HookWriteFile` and `HookWriteFileEx` deny branches. The design correctly limits hashing to blocked writes and uses the existing rayon pool. However, there are significant architectural issues with the hash-to-agent data flow, a missing pool saturation check, and a buffer safety concern.

**Strengths:**
- Correctly limits hashing to `HookWriteFile` / `HookWriteFileEx` DENY only (D-04 compliant).
- Uses the existing `compute_content_hash` / `compute_content_hash_offloaded` from Phase 58 without duplication.
- 100MB cap and `hash_truncated` flag are already implemented in `hash_compute.rs`.
- Inline/offload threshold (64KB) matches the existing implementation.

**Concerns:**
- **HIGH:** The plan's Task 2 contains an extensive architectural debate (Options A/B/C) about how to get the hash from the hook DLL to the agent. The **FINAL RESOLUTION** in the plan says "Use a thread-local HashEvidence cache in the hook DLL" but then immediately contradicts itself with "BUT D-16 requires integration tests proving blocked write audit events contain content_sha256. So the agent MUST retrieve the hash." The plan then proposes a second one-way IPC frame (`HashEvidence`), but this is not reflected in the must_haves or success criteria. The plan is **architecturally inconsistent**: it says the agent must retrieve the hash, but the must_haves only say "The computed hash is returned in HookResponse" — which is impossible because the hash is computed AFTER the `HookResponse` is already returned. This is a fundamental design flaw that will block implementation.
- **HIGH:** Task 1 says "Add pool saturation check" but the existing `hash_compute.rs` does NOT have a queue depth counter (`HASH_QUEUE_DEPTH`). The plan says "Add a global AtomicU64 counter HASH_QUEUE_DEPTH" but `hash_compute.rs` uses `rayon::ThreadPool::install()` directly, not a channel-based queue. The rayon pool has its own internal queue; there is no exposed "queue depth" API. The plan's saturation check (queue depth > 4) cannot be implemented as specified. The correct approach is to use a bounded channel (e.g., `crossbeam::channel::bounded(4)`) or a semaphore, but this requires redesigning `compute_content_hash_offloaded`.
- **HIGH:** The plan computes the hash from `lpBuffer` with `nNumberOfBytesToWrite` as the length. In `WriteFile`, the application may pass a `lpBuffer` that is smaller than `nNumberOfBytesToWrite` (malicious or buggy caller). The existing `hash_compute.rs` uses `std::slice::from_raw_parts(buffer, actual_len)` which will cause an access violation if the buffer is smaller than claimed. The 100MB cap does not protect against this — a 1KB buffer with `nNumberOfBytesToWrite = 50MB` will still crash. The RESEARCH.md Pitfall 3 mentions this but the plan does not include a mitigation.
- **MEDIUM:** The plan says "If the send fails, ignore — hash evidence is best-effort." But D-08 says "Attach the computed hash to the AuditEvent via content_sha256." If the hash is computed but the IPC frame fails, the audit event has no hash. This is acceptable for v0.10.0 (best-effort), but the plan should explicitly document this as a known gap and add a `hash_skipped` reason for IPC failure.
- **MEDIUM:** Task 3 proposes adding a `HashEvidenceFrame` with `timestamp_secs` for correlation, but the agent's `HashCache` uses `(pid, handle_value)` as the key. If the same handle is reused (Windows handle recycling), the agent may attach a stale hash to a new operation. The plan should use a monotonic sequence number or include the QPC timestamp in the correlation key.
- **LOW:** The plan does not mention `HookWriteFileEx` specifically in the hash computation task. `WriteFileEx` uses an `OVERLAPPED` structure and a completion callback; the `lpBuffer` may be invalid by the time the completion callback fires. The plan should clarify that hashing happens synchronously in the trampoline before returning the deny, not in the completion callback.

**Suggestions:**
- **Resolve the architectural inconsistency**: Either (a) extend `HookRequest` to include a "pre-computed hash" field (but this requires hashing before the deny decision, which violates D-04), or (b) commit to the one-way `HashEvidence` IPC frame and update must_haves/success criteria accordingly, or (c) accept that hash evidence is hook-local only for v0.10.0 and defer agent-side attachment to a future phase. The current plan is unimplementable as written.
- Replace the rayon pool saturation check with a bounded channel or semaphore. The simplest fix: wrap the pool in a `std::sync::Semaphore` with 4 permits, or use a `crossbeam::channel::bounded(4)` and spawn a dedicated hash worker thread.
- Add a buffer size validation: before calling `from_raw_parts`, verify the buffer is readable by probing the first and last page with `IsBadReadPtr` or a safe `ReadProcessMemory` check. Alternatively, add a hard cap at 1GB and document that buffers claiming >1GB are skipped.
- Use a monotonic sequence number in `HashEvidenceFrame` and include it in the `HashCache` key to prevent handle-reuse collisions.
- Explicitly document that `hash_skipped` may be set due to IPC failure, not just pool saturation.

**Risk Assessment:** HIGH — the architectural inconsistency in hash-to-agent flow and the unimplementable pool saturation check are blockers. The buffer overread risk is a safety issue.

---

### Plan 58.4-03: Wire Hook DLL Health Snapshot (DIFF-04)

**Summary:** This plan wires health counter emission into `perf_telemetry.rs` and sends `HookHealthSnapshot` to the agent. The design is mostly sound but has a counter-reset race, an overcounting approximation, and a missing agent-side ingestion handler.

**Strengths:**
- Lock-free `AtomicU64` / `AtomicU8` counters are correct for the hook DLL hot path.
- `emit_health_snapshot()` correctly reads and resets counters atomically with `swap(0, Relaxed)`.
- `send_health_snapshot` as a one-way fire-and-send frame is the right pattern for non-critical telemetry.
- Health snapshot emission on `FailState` transition is correctly tied to the existing `emit_state_transition_immediate` function.

**Concerns:**
- **HIGH:** The plan says "Modify `record_latency` to emit a health snapshot every 100 pipe round-trips" but `record_latency` is called on **every** classification call (cache hit AND cache miss). The plan then says "For v0.10.0, approximate pipe round-trips by incrementing in `record_latency` (every call). This overcounts slightly." This is not "slight" overcounting — it means cache hits (which bypass the pipe entirely) are counted as pipe round-trips. The `cache_hit_rate_60s` computation will be meaningless because the denominator (`hits + misses`) includes pipe round-trips that are not pipe round-trips. The health dashboard will show incorrect metrics. The plan must either (a) increment `PIPE_ROUND_TRIPS` only in the actual pipe-send path, or (b) rename the counter to `CLASSIFICATION_CALLS` and adjust the dashboard interpretation.
- **HIGH:** Task 4 says "Verify that the consolidated HookIpcServer in dlp-agent/src/hook_ipc.rs already routes IpcPayloadV1::PullHealth to the health_handler closure (it does; Phase 58.2 wired this)." However, the plan also says "Modify [handle_connection] to accept HealthResponse and ingest it into the HealthAggregator." The existing `dlp-agent/src/hook_ipc.rs` (read during review) does NOT have a `HealthResponse` ingestion handler — it only has a `PullHealth` request handler. The plan is conflating two different things: (a) agent requesting health FROM hook DLL (`PullHealth`), and (b) hook DLL pushing health TO agent (`HealthResponse`). The agent's `handle_connection` currently does NOT handle incoming `HealthResponse` frames from the hook DLL. This is a real gap that must be implemented.
- **MEDIUM:** The counter-reset race: `emit_health_snapshot()` uses three separate `swap(0, Relaxed)` operations on `PIPE_ROUND_TRIPS`, `CACHE_HITS_60S`, and `CACHE_MISSES_60S`. Between the first and third swap, another thread could increment one of the counters, causing the snapshot to contain partial data from the next window. Use a single atomic "generation" counter or snapshot all three with `SeqCst` ordering, or accept the small race as documented.
- **MEDIUM:** The plan says "emit_state_transition_immediate triggers health snapshot emission" but the existing `emit_state_transition_immediate` in `perf_telemetry.rs` only logs a `tracing::warn!` event. It does not call `emit_health_snapshot()` or `send_health_snapshot()`. The plan must include a task to actually wire the call.
- **LOW:** The `HealthAggregator::ingest_snapshot` in `dlp-agent/src/health_aggregator.rs` computes `HealthStatus` from a single snapshot, but the threshold `pipe_round_trips_60s > 0` means an idle process (no file operations in 60s) will show `Critical`. The plan should document that this is expected or adjust the threshold.

**Suggestions:**
- Add a separate `record_pipe_round_trip()` call in the actual pipe-send path (e.g., in `classify_and_log_path` / `classify_and_log_handle` after the pipe call returns), not in `record_latency`. Remove `PIPE_ROUND_TRIPS` from `record_latency` entirely.
- Add a task to implement `HealthResponse` ingestion in `dlp-agent/src/hook_ipc.rs::handle_connection`. The handler should call `health_aggregator.ingest_snapshot(resp.snapshot)` and return an `ALLOW` response.
- Use a single `AtomicU64` snapshot word or `SeqCst` ordering for the three counter swaps to prevent inter-window races.
- Actually wire `emit_health_snapshot()` and `send_health_snapshot()` into `emit_state_transition_immediate`.
- Document the idle-process Critical behavior or change the threshold to `pipe_round_trips_60s == 0 AND current_fail_state != 0` for Critical.

**Risk Assessment:** MEDIUM — the pipe round-trip overcounting and missing HealthResponse ingestion are the main issues. Both are fixable.

---

### Plan 58.4-04: End-to-End Tests (DIFF-02, DIFF-03, DIFF-04)

**Summary:** This plan adds unit and integration tests for all three differentiator data paths. The test design is comprehensive but has some unrealistic assumptions and missing edge cases.

**Strengths:**
- Unit tests cover all three differentiators (snapshot, hash, health) with specific assertions.
- Integration tests target the agent-side data flow (PullDiagnostics, PullHealth, hash in audit).
- Tests use existing mock patterns from `hook_ipc_integration.rs`.
- Test independence and cleanup are explicitly mentioned.

**Concerns:**
- **HIGH:** Task 1 says "Starts a mock agent server that returns DENY for all requests" and then "Calls classify_and_log_path with a test path and action." The `classify_and_log_path` function in `trampolines.rs` does a real pipe round-trip to the agent. Starting a mock agent server inside a `#[cfg(test)]` module is non-trivial because the test runs in a separate process and the pipe name must match. The existing tests in `dlp-hook-dll` use `start_agent_mock_server` from `lib.rs` — verify that this helper exists and can be used from `trampolines.rs`. If not, the test must be an integration test in `dlp-agent/tests/`, not a unit test in `dlp-hook-dll`.
- **HIGH:** Task 2 says "test_hash_pool_saturation: Simulate queue depth > 4 by setting HASH_QUEUE_DEPTH to 5." As noted in the Plan 58.4-02 review, the existing `hash_compute.rs` does NOT have a `HASH_QUEUE_DEPTH` counter. This test is unimplementable until the pool saturation check is added. The plan must either add the saturation check first (in Plan 58.4-02) or remove this test.
- **MEDIUM:** Task 2 says "test_hash_truncation_100mb: Create a buffer of HASH_CAP_BYTES + 1000." This allocates ~100MB + 1KB in a test. While acceptable on a development machine, it may cause OOM on CI runners with limited memory. The test should use `#[ignore]` for CI or use a smaller mock buffer with a reduced `HASH_CAP_BYTES` constant in test mode.
- **MEDIUM:** Task 3 says "test_health_snapshot_resets_counters: Call record_cache_hit(), then emit_health_snapshot(), then emit_health_snapshot() again and assert the second snapshot has cache_hit_rate_60s == 0.0." This test assumes no other test or thread increments the counters between the two `emit_health_snapshot()` calls. Because the counters are global `static` variables, this test is inherently flaky in parallel test runs. Use `#[ignore]` or run with `--test-threads=1`, or refactor the counters to be injectable.
- **MEDIUM:** Task 4 says "test_blocked_write_audit_contains_hash: Pre-populate the HashCache with a matching (pid, handle_value) entry." The `HashCache` is a `DashMap` in the agent. Pre-populating it in a test requires access to the agent's internal state, which may not be exposed. The test should verify the hash attachment at the `handle_hook_request` level, not the full audit pipeline, to avoid coupling to the audit emitter.
- **LOW:** Task 4 says "If the audit emitter is not easily testable in isolation, create a unit test in dlp-agent/src/hook_ipc.rs." This is a reasonable fallback, but the plan should explicitly prefer the unit test approach to avoid integration test fragility.

**Suggestions:**
- Verify that `start_agent_mock_server` exists in `dlp-hook-dll/src/lib.rs` and can be used from `trampolines.rs` tests. If not, move the diagnostic snapshot test to `dlp-agent/tests/`.
- Remove or defer `test_hash_pool_saturation` until the saturation check is implemented. Add a TODO.
- Mark `test_hash_truncation_100mb` with `#[ignore]` and document the manual run command.
- Mark counter-reset tests with `#[ignore = "requires --test-threads=1"]` or use a test-only counter reset helper.
- Prefer unit tests over integration tests for hash cache attachment logic.

**Risk Assessment:** MEDIUM — the test flakiness and unimplementable saturation test are the main issues. The 100MB allocation is a CI concern.

---

## Consensus Summary

### Agreed Strengths
- Clean reuse of Phase 58 infrastructure (DiagnosticRing, hash_compute, perf_telemetry) without duplicating code.
- Fire-and-forget semantics for all hook-side operations preserve the deny decision latency.
- Lock-free counters (AtomicU64/AtomicU8) are appropriate for the hook DLL hot path.
- One-way IPC frames for health snapshots avoid blocking the trampoline.
- Test plan covers all three differentiators with both unit and integration tests.
- No new TUI screens or SQLite schema — pure wiring phase, which reduces scope risk.

### Agreed Concerns (both reviewers flagged)

**HIGH — Hash-to-agent architectural inconsistency in Plan 58.4-02**
- The plan says the agent MUST retrieve the hash (D-16), but the must_haves say the hash is "returned in HookResponse" which is impossible because the hash is computed AFTER the HookResponse is returned.
- Consensus: The plan must resolve this contradiction. Options: (a) accept hook-local-only hash for v0.10.0 and defer agent-side attachment, (b) implement the one-way `HashEvidence` IPC frame and update must_haves, or (c) compute hash before the deny decision (violates D-04). The recommended path is (b) with updated must_haves.

**HIGH — Pool saturation check is unimplementable as specified**
- The existing `hash_compute.rs` uses `rayon::ThreadPool::install()` directly, which has no exposed queue depth API.
- Consensus: Replace the "queue depth > 4" check with a bounded semaphore or channel, or remove the saturation check from the plan and document that pool saturation is handled by rayon's internal backpressure.

**HIGH — Buffer overread risk in hash computation**
- `std::slice::from_raw_parts(buffer, actual_len)` will crash if the buffer is smaller than `nNumberOfBytesToWrite`.
- Consensus: Add a buffer size validation step (e.g., `IsBadReadPtr` probe or a hard 1GB absolute cap) before calling `from_raw_parts`.

**HIGH — Pipe round-trip overcounting in health counters**
- `record_latency` is called on every classification (cache hit + miss), but `PIPE_ROUND_TRIPS` should only count actual pipe calls.
- Consensus: Move `PIPE_ROUND_TRIPS` increment to the actual pipe-send path, not `record_latency`.

**HIGH — Missing HealthResponse ingestion in agent**
- The agent's `handle_connection` does not handle incoming `HealthResponse` frames from the hook DLL.
- Consensus: Add a task to implement `HealthResponse` ingestion in `dlp-agent/src/hook_ipc.rs`.

**MEDIUM — QPC ticks vs microseconds in decision_latency_us**
- The `decision_latency_us` field contains raw QPC ticks, not microseconds, making it useless for triage.
- Consensus: Add a `qpc_to_us()` conversion helper before constructing the snapshot.

**MEDIUM — Counter-reset race in emit_health_snapshot**
- Three separate `swap(0, Relaxed)` operations can interleave with other threads.
- Consensus: Use `SeqCst` ordering or a single atomic snapshot word.

**MEDIUM — Test flakiness from global static counters**
- Health counter tests use global `static` variables and are flaky under parallel test execution.
- Consensus: Mark with `#[ignore = "requires --test-threads=1"]` or add test-only reset helpers.

**MEDIUM — 100MB buffer allocation in hash truncation test**
- `test_hash_truncation_100mb` allocates ~100MB, which may OOM on CI runners.
- Consensus: Mark with `#[ignore]` and document manual run command.

**LOW — Missing `matched_policy_id` and `enforcement_mode` in diagnostic snapshot**
- These fields are `None` because the hook DLL does not parse the agent's `HookResponse`.
- Consensus: Add a TODO comment and a deferred task to enrich these fields.

**LOW — Handle reuse in HashCache correlation**
- `(pid, handle_value)` key can collide when Windows recycles handles.
- Consensus: Add a monotonic sequence number or QPC timestamp to the correlation key.

---

## Action Items for Plan Revision

1. **Plan 58.4-01**: Add `qpc_to_us()` conversion for `decision_latency_us`; thread `classification_source` to deny branch or document fallback; map `source_volume_class` to string explicitly; add TODO for `matched_policy_id`/`enforcement_mode` enrichment.
2. **Plan 58.4-02**: Resolve hash-to-agent architectural inconsistency (recommend one-way `HashEvidence` IPC frame); replace unimplementable pool saturation check with bounded semaphore or remove it; add buffer size validation before `from_raw_parts`; add monotonic sequence number to `HashEvidenceFrame`; document `hash_skipped` reasons including IPC failure.
3. **Plan 58.4-03**: Move `PIPE_ROUND_TRIPS` increment to actual pipe-send path; implement `HealthResponse` ingestion in agent `handle_connection`; use `SeqCst` or single-word snapshot for counter reset; wire `emit_health_snapshot()` into `emit_state_transition_immediate`; document idle-process Critical behavior.
4. **Plan 58.4-04**: Verify `start_agent_mock_server` availability for unit tests; remove/defer `test_hash_pool_saturation` until saturation check exists; mark `test_hash_truncation_100mb` with `#[ignore]`; mark counter-reset tests with `#[ignore]` or add reset helper; prefer unit tests for hash cache attachment.

---

## Verification Coverage

### Source-grounding checks performed
- `dlp-hook-dll/src/trampolines.rs` — read first 100 lines; confirmed `classify_and_log_path` and `classify_and_log_handle` exist.
- `dlp-hook-dll/src/diagnostic_ring.rs` — read full file; confirmed ArrayQueue capacity = 1000, lazy eviction, QPC expiry.
- `dlp-hook-dll/src/hash_compute.rs` — read full file; confirmed `compute_content_hash` / `compute_content_hash_offloaded`, 100MB cap, rayon pool, no queue depth counter.
- `dlp-common/src/hook_ipc.rs` — read first 150 lines; confirmed `IpcPayloadV1` variants including `HealthResponse`, `PullHealth`, `DiagnosticsResponse`, `PullDiagnostics`.
- `dlp-agent/src/hook_ipc.rs` — read first 150 lines; confirmed `HookIpcServer` builder methods, handler types, no `HealthResponse` ingestion handler.
- `dlp-agent/src/health_aggregator.rs` — read full file; confirmed threshold logic, `ingest_snapshot`, `get_current_status`, 12-entry history.
- `dlp-agent/tests/hook_ipc_integration.rs` — confirmed existence (referenced in Grep results).
