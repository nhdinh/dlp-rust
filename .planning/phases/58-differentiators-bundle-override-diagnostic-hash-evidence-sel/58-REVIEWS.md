---
phase: 58
reviewers: [claude, opencode]
reviewed_at: 2026-06-02T20:00:00Z
plans_reviewed:
  - 58-01-PLAN.md
  - 58-02-PLAN.md
  - 58-03-PLAN.md
  - 58-04-PLAN.md
  - 58-05-PLAN.md
  - 58-06-PLAN.md
---

# Cross-AI Plan Review — Phase 58

## Codex Review

Codex CLI (gpt-5.3-codex) could not be invoked due to account restrictions:
"The 'gpt-5.3-codex' model is not supported when using Codex with a ChatGPT account."
Tried fallback models (o4-mini, gpt-4o, gpt-4o-mini, gpt-4.1) — all rejected with same error.

---

## Claude Review (Claude Code CLI, v2.1.143)

### Plan 58-01: Foundational Hook DLL Modules

**Summary:** This plan establishes the core infrastructure for versioned IPC, lock-free diagnostic capture, and async content hashing in the hook DLL. The versioned envelope pattern (IpcPayloadV2/HookResponseV2) is correctly designed for backward compatibility, and the choice of crossbeam::queue::ArrayQueue aligns with the lock-free requirement. However, there are critical discrepancies between the plan and locked decisions in CONTEXT.md, and the ArrayQueue semantics don't match the stated "best-effort overwrite" behavior.

**Strengths:**
- Versioned envelope with fallback deserialization prevents cross-architecture IPC breakage (addresses Pitfall 2).
- `OnceLock` lazy initialization from trampoline avoids DllMain deadlock (addresses Pitfall 1).
- Bounded channel (16) for hash queue with skip-on-full provides backpressure.
- Separate sync path for small buffers (<=64KB) avoids thread-pool overhead for trivial cases.
- Wall-clock timestamps enable cross-process sorting.

**Concerns:**
- **HIGH:** ArrayQueue capacity is 64, but D-07 mandates **1000 entries per DLL**. At 18 fields per snapshot, 64 entries is far too small for high-frequency operations and contradicts the locked decision. Either switch to `crossbeam::queue::SegQueue` (unbounded, but D-07 wants bounded) or increase ArrayQueue to 1000. The plan also says "best-effort overwrite" — ArrayQueue::push returns Err when full; it does NOT overwrite. To overwrite oldest, you'd need a custom ring buffer or pop+push loop.
- **HIGH:** 100MB cap is stated as safety boundary, but Pitfall 3 mentions "1GB absolute maximum" as a defense against buffer overread. The plan only mentions the 100MB cap with no fallback for the 100MB–1GB range. Clarify: skip hash entirely above 100MB, or stream-hash up to 1GB?
- **MEDIUM:** `clear_expired_snapshots` with SystemTime on ArrayQueue is problematic — ArrayQueue doesn't support arbitrary removal. The plan says "1-hour lazy eviction" in D-07 but doesn't explain how to evict from a ring buffer. A ring buffer naturally overwrites old entries; explicit eviction may not be needed if capacity is 1000 and overwrite is the policy. Reconcile this design.
- **MEDIUM:** `compute_hash_async` waits up to 50ms oneshot — what happens if the background thread panics? The OnceLock makes recovery impossible without DLL reload. Add a watchdog or `std::thread::JoinHandle` health check.
- **LOW:** No mention of `bincode` config (e.g., `bincode::DefaultOptions` vs legacy) for IpcPayloadV2 serialization. Ensure both sides use the same config.

**Suggestions:**
- Increase ArrayQueue capacity to 1000 to match D-07, and use a pop-then-push loop for overwrite semantics (or document that ArrayQueue::push failure = drop).
- Clarify the 100MB vs 1GB boundary: skip if >100MB, stream-hash if <=1GB, reject/abort if >1GB.
- Use `std::sync::atomic::AtomicU64` for monotonic sequence numbers in DiagnosticSnapshot to make ordering deterministic even with identical timestamps.
- Add a `IpcPayloadV2::len()` sanity check before deserialization to detect pipe corruption.

**Risk Assessment:** MEDIUM — the ArrayQueue capacity and overwrite semantics are fundamental errors that will cause diagnostic loss. Fixing these is straightforward but must happen before 58-02.

---

### Plan 58-02: Trampoline Integration

**Summary:** This plan wires the diagnostic and hash infrastructure into all 12 trampolines and refactors the decision path to return a rich DecisionContext. Removing the approval cache from the hook DLL and making the agent authoritative simplifies consistency but adds IPC latency on every DENY. The plan correctly limits hash computation to WriteFile/WriteFileEx on DENY.

**Strengths:**
- Refactoring `classify_and_log_handle` to return DecisionContext consolidates 9 fields into one struct, reducing parameter bloat.
- Hash computation strictly limited to DENY on WriteFile/WriteFileEx per D-12 (avoids Pitfall 1).
- Counter placement (injected_pids at injection, patched_modules at patch) is logically correct.
- Documenting WriteFileEx hash latency tradeoff shows awareness of the async boundary.

**Concerns:**
- **HIGH:** Removing approval cache from hook DLL means **every DENY incurs a full IPC round-trip** even when no override is pending. If the agent is down or slow, this adds latency to every blocked operation. The original architecture likely had the cache in-hook to fast-path DENY. The plan should quantify acceptable latency (D-01 mentions TTL-bounded approval but doesn't discuss hot-path performance). Consider keeping a negative-cache in hook DLL: "no override pending" cached for 5-10s.
- **HIGH:** The plan says "Push DiagnosticSnapshot on DENY for all 12 trampolines" — but what about ABAC AUDIT mode (not DENY)? D-07 says severity derived from enforcement_mode: `deny->critical, audit->warning, allow->info`. If we only push on DENY, we lose audit->warning and allow->info snapshots. D-02 requires "full decision tree per blocked event" — blocked implies DENY, but diagnostic value exists for audit events too. Clarify whether snapshots are DENY-only or all modes.
- **MEDIUM:** DecisionContext includes `pipe_round_trips_60s` and `cache_hit_rate_60s` — where do these values come from? The hook DLL doesn't have a 60-second window unless there's a counter aggregator. These should be computed by the agent (Plan 58-03), not returned by `classify_and_log_handle`. This creates a dependency on health counter state that may not exist at the decision point.
- **MEDIUM:** If `compute_hash_async` times out or channel is full, the DiagnosticSnapshot should still be pushed with `hash_skipped=true`. The plan says "Other 10 trampolines: content_hash=None, hash_skipped=false" — for WriteFile/WriteFileEx that fail to hash, what are the field values? Be explicit.
- **LOW:** `injected_pids` as AtomicU32 will overflow after 4 billion injections. Use saturating increment.

**Suggestions:**
- Add a "fast DENY" path: hook DLL sends request, agent returns immediately with approval_override=false if no override exists, minimizing latency for the common case.
- Clarify whether DiagnosticSnapshot pushes on AUDIT/ALLOW modes too, or if the severity field is only populated for DENY. If DENY-only, document that decision.
- Move `pipe_round_trips_60s` and `cache_hit_rate_60s` out of DecisionContext — these are agent-computed aggregates, not per-decision fields. The snapshot can store the instantaneous counters and let the agent compute rates.
- Add `hash_error: Option<String>` field to DiagnosticSnapshot for forensic traceability when hashing fails.

**Risk Assessment:** MEDIUM — removing the in-hook approval cache changes the hot-path latency profile significantly. This needs benchmarking or a negative-cache fallback.

---

### Plan 58-03: Agent-Side Aggregation

**Summary:** This plan builds the agent's DiagnosticAggregator with PID-reuse-safe keying, health threshold scanning, and connected pipe registry for polling DLLs. It bridges hook DLL diagnostics to server-push. The design is mostly sound but has timing discrepancies with locked decisions and underspecified health transition logic.

**Strengths:**
- PID + process_start_time keying correctly addresses PID reuse (a real problem on Windows).
- DashMap for concurrent per-DLL state is appropriate.
- AuditEvent emission on health transitions integrates with existing audit infrastructure instead of creating a parallel alert path.
- Batched diagnostic_ingest (every 60s or 100 entries) is efficient.

**Concerns:**
- **HIGH:** Polling frequency mismatch. D-07 says "polled every 30s via named pipe" for diagnostics. Plan says `poll_all_diagnostics every 60s` and `poll_all_health every 60s (staggered 30s)`. This means diagnostics are polled at 60s, not 30s. The locked decision says 30s — which takes precedence? Similarly, D-18 says health counters polled every 60s, which matches for health but not diagnostics.
- **HIGH:** Health threshold logic "scanning last 5 entries: cache_hit_rate >= 0.80, fail_state == 'healthy', pipe_round_trips_60s > 0 across all 5" is brittle. If a process just started and has 1 entry, the scan fails the "all 5" check and marks Critical? The plan should specify minimum sample size (e.g., require 3+ entries). Also, `pipe_round_trips_60s > 0` means "had at least one IPC call in the last 60s" — but if the process is idle (no file operations), this will falsely show Degraded.
- **MEDIUM:** `GetNamedPipeClientProcessId` requires Windows Vista+ and specific handle rights. The plan doesn't mention error handling if this call fails (e.g., pipe already closed). What happens to the connected_pipes registry entry?
- **MEDIUM:** `poll_all_diagnostics` and `poll_all_health` are both every 60s. With many injected processes (e.g., 500 PIDs), sequential polling could take significant time. The plan doesn't mention concurrency for polling. Use `tokio::task::spawn` or `rayon` for parallel pipe I/O.
- **LOW:** The plan says "Emit AuditEvent on health transitions instead of calling alert_router" — but the success criteria says "auto-alert on degradation". If alert_router is the alerting path and audit events are just logging, alerts may be missed. Verify that alert_router consumes audit events, or add an explicit alert emission path.

**Suggestions:**
- Change `poll_all_diagnostics` to 30s to match D-07, or update CONTEXT.md if 60s is intentional.
- Define health thresholds with minimum sample size: require N>=3 entries, and `pipe_round_trips_60s > 0` should be `>= 0` (idle processes are healthy, not degraded). Use "no pipe_round_trips in 300s" for disconnected detection.
- Use `tokio::task::JoinSet` for concurrent pipe polling to avoid head-of-line blocking.
- Add a "last_seen" timestamp per pipe and evict pipes not seen in 5 minutes to prevent registry bloat from crashed processes.

**Risk Assessment:** MEDIUM — timing mismatch and brittle health logic could cause false-positive degradation alerts or missed diagnostics.

---

### Plan 58-04: Server API and Schema

**Summary:** This plan adds server-side caching for diagnostics and health with agent-push ingestion and admin read endpoints. The in-memory cache design respects D-07's no-disk-persistence rule for diagnostics. However, the plan is underspecified on authentication, data retention boundaries, and the audit event integration.

**Strengths:**
- In-memory DashMap cache avoids disk persistence for raw diagnostic snapshots (compliant with D-07).
- Background pruning task prevents unbounded memory growth.
- Filtering by agent_id, pid, limit is practical for operators.
- Agent-push model reduces server complexity (no need for server to poll agents).

**Concerns:**
- **HIGH:** "Identify and document AuditEvent INSERT location in audit_repository.rs" is a research/documentation task, not implementation. If Plan 58-03 emits AuditEvent for health transitions, the server needs to actually INSERT them. This task should be "Add AuditEvent INSERT in audit_repository.rs for health_transition and diagnostic_ingest events" with the actual SQL/bindings.
- **HIGH:** No mention of authentication/authorization on POST /agent/diagnostics. Agent-to-server push must be authenticated (mTLS, JWT, or API key). Without this, any process can flood the server with fake diagnostics.
- **MEDIUM:** Cache max_age is 300s (5 minutes), but agent push frequency is 60s (or 30s per D-07). This means cache always has fresh data, but what about agents that go offline? The 300s stale threshold seems fine, but admin TUI should show "agent offline" when last_updated > 300s.
- **MEDIUM:** No rate limiting on POST /agent/diagnostics. A misbehaving agent (or compromised one) could push thousands of snapshots per second and exhaust server memory before the 60s prune task runs. Add per-agent rate limiting.
- **LOW:** GET /admin/diagnostics filtering by policy_id is mentioned in "Claude's discretion" but not in the plan's endpoint spec. Add it or remove the discretion note.

**Suggestions:**
- Replace the documentation task with actual implementation: add `insert_health_transition_event()` and `insert_diagnostic_ingest_event()` methods to audit_repository.rs.
- Require Bearer token or mTLS on POST /agent/diagnostics. Reuse existing agent auth mechanism.
- Add per-agent rate limiting: max 1000 snapshots per push, max 1 push per 30s.
- Include `agent_hostname` in the cached key alongside `agent_id` for multi-host clarity.
- Add `GET /admin/diagnostics/{snapshot_id}` for fetching a single snapshot's full decision tree (needed for D-02 detail view).

**Risk Assessment:** MEDIUM — missing auth on agent push is a security gap. The documentation-only task for audit events is insufficient.

---

### Plan 58-05: Admin TUI Screens

**Summary:** This plan builds the operator-facing Diagnostic List and Self-Health Dashboard screens in the admin TUI. The designs use ratatui idiomatically (tables, sparklines, color-coding) and include a unit test for menu order. However, the Diagnostic List screen may not fully satisfy D-02's requirement for a "full decision tree."

**Strengths:**
- SeverityFilter with cycle method follows existing TUI interaction patterns.
- Relative time display from timestamp_utc is operator-friendly.
- Sparkline widget for 12-reading health history is a nice visual differentiator.
- Color-coding by severity/status leverages ratatui well.
- Unit test for menu order prevents regression.

**Concerns:**
- **HIGH:** D-02 requires "full decision tree per blocked event — hook fired, classification source + age, ABAC subject/resource/action/environment, matched policy ID + mode, decision latency in microseconds." The plan's Diagnostic List table only shows: Time, PID, Source, Policy, Mode, Severity, Latency. It omits: hook name, classification age, ABAC subject, ABAC resource, ABAC action, ABAC environment. This is a **partial implementation of D-02**. Either add these columns, make them toggleable, or add a detail popup (press Enter to expand).
- **MEDIUM:** The plan doesn't mention how the TUI handles empty states (no diagnostics, no agents). A blank screen is poor UX. Add empty-state messages.
- **MEDIUM:** Self-Health Dashboard shows "Sparkline" but doesn't define the metric being sparklined. Is it cache_hit_rate? pipe_round_trips? fail_state transitions? The plan should specify.
- **LOW:** SystemMenu positions 13/14 — what if the menu exceeds screen height? Does ratatui scroll? Verify the existing menu widget handles this.

**Suggestions:**
- Add a detail view modal (activated by Enter on a diagnostic row) showing all 18 DiagnosticSnapshot fields. This satisfies D-02 without cluttering the list view.
- Add "classification age" and "ABAC subject (user_sid)" to the main table if space permits.
- Define sparkline metric: use `cache_hit_rate` as primary trend, with color indicating threshold breaches.
- Add empty-state widgets: "No diagnostic snapshots received. Ensure agents are running and policies are active."

**Risk Assessment:** LOW — the missing detail view is the main gap. Easy to fix.

---

### Plan 58-06: Override Flow Integration

**Summary:** This plan wires the end-to-end override flow from hook DLL DENY through agent, user UI, server, and back. The versioned HookResponseV2 is consistent with IpcPayloadV2, and the 30-second deduplication prevents dialog spam. However, the plan is vague on the admin approval side and contradicts the requirements endpoint path.

**Strengths:**
- HookResponseV2 versioned envelope mirrors IpcPayloadV2 pattern — consistent design.
- 30-second deduplication by (resource_path, action) prevents user UI spam.
- Agent-side ApprovalCache check means hook DLL stays simple (no cache logic).
- User UI modal with min 10 char justification enforces meaningful requests.

**Concerns:**
- **HIGH:** Requirements say "justification round-trips through POST /admin/overrides" but the plan says "POST /admin/approvals". If Phase 61 already has `/admin/approvals`, this is fine — but verify which endpoint exists. If it's `/admin/approvals`, update the requirements doc. If it's `/admin/overrides`, fix the plan. Inconsistency here will break integration.
- **HIGH:** The plan says "admin grants TTL-bounded approval via admin TUI" but the plan itself doesn't include any admin TUI changes for granting approvals. D-01 says "reuses Phase 61 approval infrastructure entirely (no new SQLite schema, no new JWT signing, no new TUI screen)" — but if Phase 61's approval UI doesn't have a screen for this specific flow, where does the admin grant approval? The plan is completely missing the admin TUI side. Is there an existing approval screen that handles this? If yes, document it. If no, this is a gap.
- **HIGH:** What happens when the override JWT/token expires while the user is mid-operation? The plan mentions `override_expiry` in HookResponseV2 but doesn't describe the TTL enforcement. Does the hook DLL check expiry on every subsequent call? The agent? Clarify the enforcement boundary.
- **MEDIUM:** `Pipe2AgentMsg::ShowOverrideDialog` and `UserUiToAgentMsg::OverrideJustification` — these cross-process IPC messages need serialization. Are they using the existing named pipe protocol? The plan doesn't mention the wire format. Use the same versioned envelope as IpcPayloadV2.
- **MEDIUM:** The deduplication DashMap keyed by (resource_path, action) with String keys will allocate on every DENY even when dedup is cold. Use `(Arc<str>, Action)` or a hash of the path to avoid allocation.
- **LOW:** What if the user clicks "Cancel" on the override dialog? The plan mentions `OverrideCancelled` and `OverrideDialogClosed` but doesn't say what the agent does with these messages. Presumably nothing (user must retry), but document it.

**Suggestions:**
- Verify and document the exact server endpoint: `/admin/overrides` or `/admin/approvals`. Add to the plan.
- Document the existing Phase 61 admin TUI screen used for approval, or add a task to 58-05 for the approval grant UI if it doesn't exist.
- Add TTL enforcement: hook DLL checks `override_expiry > now()` before honoring. If expired, re-query agent.
- Use a hashed key for deduplication (e.g., `FxHash64(resource_path) ^ action.as_u64()`) to avoid String allocation.
- Define the full state machine: DENY -> ShowDialog -> JustificationSent -> Waiting -> ApprovalReceived/Expired/Denied.

**Risk Assessment:** HIGH — the missing admin approval UI and endpoint ambiguity are blockers. The TTL enforcement is underspecified.

---

## OpenCode Review (gpt-5.3-chat-latest)

### Plan 58-01: Foundational Hook DLL Modules

**Summary:** Strong foundational plan with correct attention to IPC versioning, lock-free structures, and avoiding DllMain hazards. The design aligns well with constraints, but there are a few correctness and backpressure edge cases around the ring buffer and hashing pipeline that could cause silent data loss or inconsistent behavior under load.

**Strengths:**
- Correct use of versioned IPC (`IpcPayloadV2`) without breaking V1 compatibility
- Avoids DllMain initialization pitfalls via `OnceLock`
- Lock-free `ArrayQueue` aligns with high-frequency hook context
- Bounded async hashing with fallback avoids unbounded resource usage
- Explicit cap (100MB) and async offload prevent hook thread blocking
- Wall-clock timestamps enable cross-process ordering

**Concerns:**
- **HIGH:** `ArrayQueue` "best-effort overwrite" is not natively supported; naive implementation risks dropping newest or oldest inconsistently
- **HIGH:** Hash channel saturation silently drops hashes -> forensic gap (no signal that hash was skipped due to pressure)
- **MEDIUM:** 50ms wait on oneshot could still stall hook thread under contention
- **MEDIUM:** Sorting snapshots on read may become expensive if called frequently (N log N per poll)
- **MEDIUM:** `SystemTime` for expiry is not monotonic; clock skew can break eviction logic
- **LOW:** No explicit schema/version field inside `DiagnosticSnapshot` itself (future evolution risk)

**Suggestions:**
- Implement explicit overwrite policy: `pop()` oldest before `push()` when full
- Add `hash_skipped_reason` enum (TooLarge, ChannelFull, Timeout) to preserve forensic integrity
- Reduce blocking wait to near-zero or make fully fire-and-forget for large buffers
- Maintain insertion order and avoid full sort; use monotonic sequence ID instead
- Use `Instant` for TTL tracking, keep `SystemTime` only for display
- Add `version: u8` inside `DiagnosticSnapshot`

**Risk Assessment:** MEDIUM — Core design is sound, but silent data loss (hash skipping, ring buffer overwrite ambiguity) directly impacts forensic guarantees.

---

### Plan 58-02: Trampoline Integration

**Summary:** Good integration plan that cleanly centralizes decision context and limits hashing to DENY paths. However, it introduces coupling and a potentially risky removal of approval logic from the hook layer without fully validating latency and fallback behavior.

**Strengths:**
- Clear separation via `DecisionContext`
- Correctly restricts hashing to DENY for performance
- Consistent diagnostic capture across all trampolines
- Atomic counters for health metrics are lightweight and safe
- Avoids UI reentrancy issues by not embedding override logic in hook

**Concerns:**
- **HIGH:** Removing approval cache check from hook may introduce latency regressions (extra IPC roundtrip on every DENY)
- **HIGH:** No fallback if agent is unreachable -> DENY always, even if override exists
- **MEDIUM:** DecisionContext includes rolling metrics (60s rates) — unclear if hook can compute accurately without shared state
- **MEDIUM:** WriteFileEx async semantics vs hash timing not fully resolved (possible mismatch between event and hash)
- **LOW:** No explicit handling for partial writes or multiple WriteFile calls per logical operation

**Suggestions:**
- Keep a minimal fast-path override cache in hook (read-only, TTL-based) to avoid IPC latency
- Define behavior when agent pipe is unavailable (fail-open vs fail-closed — likely fail-closed but must be explicit)
- Clarify how rolling metrics are computed (shared atomic window vs snapshot)
- For WriteFileEx, document whether hash reflects buffer at call time or completion
- Consider correlating multi-chunk writes via handle/file ID

**Risk Assessment:** MEDIUM-HIGH — The override flow dependency shift to agent introduces latency and availability risks that could impact core enforcement UX.

---

### Plan 58-03: Agent-Side Aggregation

**Summary:** Well-structured aggregation layer with good attention to PID reuse and health computation. The design is mostly solid, but some logic around health evaluation and polling scalability could lead to misleading signals or performance issues at scale.

**Strengths:**
- PID + start_time key is correct for reuse protection
- Bounded history (VecDeque) prevents memory growth
- Health evaluation rules are explicit and deterministic
- Agent-initiated polling avoids DLL push complexity
- AuditEvent-based emission aligns with existing pipeline

**Concerns:**
- **HIGH:** Health rule "pipe_round_trips_60s > 0 across all 5" may mark idle systems as degraded incorrectly
- **MEDIUM:** Polling every 60s for all pipes may not scale with many injected processes
- **MEDIUM:** No backpressure handling if agent cannot ingest fast enough
- **MEDIUM:** Diagnostic batching (100 entries / 60s) may delay visibility for critical events
- **LOW:** DashMap<(pid, start_time)> growth not explicitly bounded if processes churn rapidly

**Suggestions:**
- Adjust health rules to distinguish "idle healthy" vs "degraded"
- Add jitter or adaptive polling (skip inactive pipes)
- Introduce max entries per PID with eviction policy
- Allow immediate flush for critical severity events
- Track ingestion lag metric to detect backlog buildup

**Risk Assessment:** MEDIUM — Mostly correct, but health semantics and scaling behavior could produce noisy or misleading operational signals.

---

### Plan 58-04: Server API and Schema

**Summary:** Clean, minimal server-side design that avoids persistence and keeps diagnostics ephemeral as intended. The main risks are around memory pressure, multi-agent scaling, and lack of pagination/limits.

**Strengths:**
- In-memory cache aligns with "no persistence" requirement
- Clear separation of ingestion (`POST /agent/diagnostics`) and query APIs
- TTL-based pruning prevents unbounded growth
- DashMap provides concurrency safety

**Concerns:**
- **HIGH:** No hard cap on stored diagnostics per agent -> potential memory blowup under high event rate
- **MEDIUM:** GET endpoints lack pagination/limit enforcement -> large responses possible
- **MEDIUM:** No authentication/authorization detail for admin endpoints (assumed but not specified)
- **LOW:** Prune interval (60s) may allow short bursts to exceed memory expectations

**Suggestions:**
- Add per-agent cap (e.g., max 5k snapshots) with FIFO eviction
- Enforce query limits (default + max)
- Ensure admin endpoints require proper RBAC scope
- Track memory usage metrics for cache

**Risk Assessment:** MEDIUM — Functionally correct but needs bounding mechanisms to avoid memory and response-size issues.

---

### Plan 58-05: Admin TUI Screens

**Summary:** Straightforward UI plan with good alignment to backend APIs. Low technical risk, but some usability and performance considerations are under-specified.

**Strengths:**
- Clear mapping of backend data to UI tables
- Severity filtering and color coding improve usability
- Sparkline visualization adds value for health trends
- Menu synchronization test prevents navigation drift

**Concerns:**
- **MEDIUM:** No pagination or virtualized rendering -> large datasets may degrade TUI performance
- **LOW:** Relative time display depends on clock sync across systems
- **LOW:** No mention of refresh cadence or manual vs auto-refresh

**Suggestions:**
- Add pagination or limit (e.g., top N entries)
- Implement periodic refresh with configurable interval
- Allow drill-down into full decision tree (not just summary row)
- Cache last response to avoid flicker

**Risk Assessment:** LOW — Mostly presentation layer; risks are UX/performance, not correctness.

---

### Plan 58-06: Override Flow Integration

**Summary:** Complex but well-structured flow that correctly reuses existing approval infrastructure. The main risks are around race conditions, deduplication correctness, and security boundaries for override tokens.

**Strengths:**
- Reuses existing approval system (avoids duplication)
- Versioned HookResponse maintains backward compatibility
- Clear separation: hook -> agent -> UI -> server
- Deduplication reduces spam
- TTL-bound override aligns with security model

**Concerns:**
- **HIGH:** Race condition between DENY event and override approval (user retries before cache updated)
- **HIGH:** Dedup key (resource_path, action) may be too coarse — collisions across users/processes
- **MEDIUM:** No explicit validation of justification content beyond length
- **MEDIUM:** Override token propagation path not fully specified (how bound to subject/resource?)
- **MEDIUM:** 30s dedup window may suppress legitimate rapid retries
- **LOW:** No explicit audit trail linkage between request and approval

**Suggestions:**
- Include user_sid and process_id in dedup key
- Define retry semantics clearly (UI prompt vs silent retry)
- Bind override token to (user, resource, action, TTL) cryptographically
- Add correlation_id for full audit chain (deny -> request -> approval -> allow)
- Consider exponential backoff instead of fixed dedup window

**Risk Assessment:** MEDIUM-HIGH — Core flow is correct, but race conditions and token binding are critical to both UX and security.

---

## Consensus Summary

### Agreed Strengths
- Clean dependency ordering (foundation -> hook DLL -> agent -> server -> TUI -> override)
- Strong reuse of existing Phase 48-61 infrastructure
- Good separation of concerns across the six plans
- Health counter emission reuses existing telemetry cadence
- Override flow correctly reuses Phase 61 approval infrastructure
- TUI screens follow established four-file pattern consistently
- Versioned IPC envelope pattern (IpcPayloadV2, HookResponseV2) prevents bincode breakage
- Lock-free ArrayQueue and DashMap choices align with performance requirements
- Wall-clock timestamps (timestamp_utc) correctly address cross-process sorting

### Agreed Concerns (both reviewers flagged)

**HIGH — ArrayQueue capacity mismatch (64 vs 1000 per D-07)**
- Both reviewers identified that the plan specifies capacity 64 but D-07 mandates 1000 entries per DLL.
- Consensus: Increase to 1000 and implement pop-then-push overwrite semantics explicitly.

**HIGH — Hash channel saturation silently drops forensic evidence**
- Both reviewers flagged that when the bounded channel (16) is full, hashes are skipped with no audit trail of why.
- Consensus: Add `hash_skipped_reason` enum (TooLarge, ChannelFull, Timeout) to DiagnosticSnapshot.

**HIGH — Polling frequency mismatch (30s vs 60s)**
- D-07 says diagnostics polled every 30s; Plan 58-03 says 60s.
- Consensus: Standardize on 30s for diagnostics or revise the locked decision in CONTEXT.md.

**HIGH — Health threshold logic marks idle processes as degraded**
- `pipe_round_trips_60s > 0 across all 5` entries means idle processes (no file operations) show Degraded.
- Consensus: Distinguish "idle healthy" from "degraded"; use minimum sample size (N>=3); consider "no round trips in 300s" for disconnected detection.

**HIGH — Unauthenticated POST /agent/diagnostics endpoint**
- Plan 58-04 lacks authentication on the agent push endpoint.
- Consensus: Require existing agent JWT auth or mTLS.

**HIGH — Override endpoint ambiguity (/admin/overrides vs /admin/approvals)**
- Requirements say POST /admin/overrides; Plan 58-06 says POST /admin/approvals (Phase 61 endpoint).
- Consensus: Verify which endpoint exists and document the correct path.

**HIGH — Missing admin approval UI for override flow**
- Plan 58-06 does not specify which admin TUI screen grants approvals.
- Consensus: Document the existing Phase 61 ApprovalList screen or add UI task if missing.

**MEDIUM — DecisionContext includes agent-computed rolling metrics**
- `pipe_round_trips_60s` and `cache_hit_rate_60s` in DecisionContext are aggregates the hook DLL cannot compute.
- Consensus: Move these out of DecisionContext; store instantaneous counters and let agent compute rates.

**MEDIUM — Diagnostic List table omits full decision tree fields**
- D-02 requires hook name, classification age, ABAC subject/resource/action/environment; the table only shows summary columns.
- Consensus: Add detail popup (Enter key) showing all 18 DiagnosticSnapshot fields.

**MEDIUM — Deduplication key too coarse**
- (resource_path, action) dedup key collides across users and processes.
- Consensus: Include user_sid and process_id in dedup key.

**MEDIUM — No rate limiting on agent push**
- A compromised agent could exhaust server memory.
- Consensus: Add per-agent rate limiting (max snapshots per push, max push frequency).

**LOW — Missing empty states in TUI screens**
- Both reviewers noted lack of empty-state handling.
- Consensus: Add empty-state messages for no diagnostics / no agents.

### Divergent Views
- **ArrayQueue overwrite semantics**: OpenCode suggests explicit pop-before-push; Claude notes ArrayQueue::len() is approximate in MPMC and recommends documenting best-effort semantics rather than claiming exact behavior.
- **Hash wait timeout**: OpenCode suggests reducing to near-zero or fire-and-forget; Claude accepts 50ms as bounded but asks about background thread panic recovery.
- **Approval cache in hook DLL**: OpenCode suggests keeping a minimal fast-path negative cache in hook; Claude focuses on quantifying latency impact of removing it entirely.
- **Health idle detection**: OpenCode suggests adaptive polling; Claude suggests changing the threshold from `> 0` to `>= 0` for idle processes.

---

## Action Items for Plan Revision

1. **Plan 58-01**: Increase ArrayQueue capacity to 1000; add `hash_skipped_reason` enum; fix QPC expiry constant; add `version: u8` to DiagnosticSnapshot; document best-effort overwrite semantics.
2. **Plan 58-02**: Refactor `classify_and_log_handle` return type to DecisionContext; move rolling metrics out of DecisionContext; add negative-cache consideration for hook DLL; document WriteFileEx buffer validity.
3. **Plan 58-03**: Fix polling frequency to 30s for diagnostics; adjust health thresholds for idle processes; add concurrent pipe polling; add per-pipe last_seen eviction.
4. **Plan 58-04**: Add auth to POST /agent/diagnostics; implement actual AuditEvent INSERT functions; add per-agent rate limiting; add GET /admin/health endpoint.
5. **Plan 58-05**: Add detail popup for full decision tree; add empty-state widgets; define sparkline metric; ensure both dispatch.rs and render.rs SystemMenu lists stay synchronized.
6. **Plan 58-06**: Verify and document correct server endpoint; document existing admin approval UI; add TTL enforcement in hook/agent; strengthen dedup key; define full override state machine.
