---
phase: 58
reviewers: [claude, opencode]
reviewed_at: 2026-06-02T16:20:00Z
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

---

## Claude Review

Now I have a comprehensive understanding of both the plans and the actual codebase. Let me provide my review.

---

# Phase 58 Execution Plans — Cross-Plan Review

## Summary

The six plans present a logically ordered build sequence from hook DLL foundation (58-01) through trampoline integration (58-02), agent aggregation (58-03), server API (58-04), TUI screens (58-05), and override flow (58-06). The internal module design within each plan is sound and follows established patterns. However, **critical architectural gaps exist at system boundaries**: bincode IPC compatibility is unaddressed across all plans that extend `IpcPayloadV1` or `HookResponse`, the server cannot access the agent's in-memory `DiagnosticAggregator` in production, no IPC mechanism exists to trigger a modal dialog in `dlp-user-ui` from the agent, and the health threshold computation in 58-03 violates D-21 by using a single snapshot instead of history. These are not implementation details—they are design flaws that will block integration.

---

## Plan 58-01: Foundational Hook DLL Modules

### Strengths
- Correct dependency ordering (pure hook DLL internals first, no cross-crate churn).
- `OnceLock` lazy initialization from trampoline call (not `DllMain`) follows established patterns and avoids Pitfall 1 from RESEARCH.md.
- `#[serde(default)]` on all new IPC struct fields for JSON backward compatibility.
- Small/large buffer split (64KB threshold) for SHA-256 computation is pragmatic.
- Comprehensive unit test coverage for both modules.

### Concerns
- **HIGH — Bincode IPC compatibility:** Adding 5 new variants to `IpcPayloadV1` breaks bincode deserialization when an old agent talks to a new hook DLL (or vice versa). RESEARCH.md Pitfall 2 explicitly warns: "Bincode requires exact layout match." `#[serde(default)]` only helps JSON. The plan mentions versioned envelopes but does not actually use one—the new variants are appended directly to the existing enum.
- **MEDIUM — ArrayQueue overwrite semantics:** The plan says "if ring.is_full(), pop one entry first, then push" but `ArrayQueue::len()` is approximate in MPMC and there's a race between `pop()` and `push()`. For a best-effort diagnostic ring this is acceptable, but the plan should acknowledge the relaxed semantics rather than claiming exact oldest-overwrite behavior.
- **MEDIUM — QPC-based expiry:** `ENTRY_EXPIRY_QPC_TICKS = 36_000_000_000_000` assumes a fixed QPC frequency (~10MHz). QPC frequency varies by hardware (typically 10MHz on modern systems but can differ). Using raw QPC ticks for 1-hour expiry is fragile; wall-clock time (`Instant` or `SystemTime`) would be more robust.
- **LOW — `hash_skipped` semantics:** The plan says return `(None, false, true)` if pool creation fails, but `OnceLock::get_or_init` panics on failure. The `hash_skipped` flag can only trigger on pool saturation (rayon `install` blocking), not initialization failure.

### Suggestions
- Use a new protocol version (`IpcPayloadV2`) or wrap new variants in a versioned envelope. Do not append to `IpcPayloadV1` without a version bump.
- Replace QPC expiry with `SystemTime::now()` stored in `DiagnosticSnapshot` and compare against `Duration::from_secs(3600)`.
- Document that `ArrayQueue` overwrite is best-effort under contention.

---

## Plan 58-02: Trampoline Integration

### Strengths
- Health counter emission reuses existing `EMIT_INTERVAL` (1000 calls) per R-02—no new hot-path emission path.
- Correctly limits SHA-256 computation to `WriteFile`/`WriteFileEx` DENY paths per D-12.
- Diagnostic snapshot push on DENY for all trampolines (not just WriteFile) follows D-07.

### Concerns
- **HIGH — `classify_and_log_handle` return type:** The current signature returns `Option<DenyReturn>`. The plan requires populating `DiagnosticSnapshot` with `classification_source`, `classification_age_ms`, `matched_policy_id`, `enforcement_mode`, and `decision_latency_us`—none of which are available from the current return value. The plan says "populate from classification context" but does not specify **how** to extract this context. Changing the return type is a breaking change across all 12 trampolines and the plan does not account for this refactor scope.
- **HIGH — `RequestOverride` pipe send:** The plan calls `crate::pipe_client::send_message(...)` and `crate::pipe_client::send_override_request(...)`. The codebase exploration shows `pipe_client.rs` exists but these specific functions may not. The plan does not verify the pipe client API or describe how `send_message` handles fire-and-forget semantics without blocking the hooked thread.
- **MEDIUM — `injected_pids` and `patched_modules` counters:** These are required by D-18 but the plan states they should be incremented "at injection time" and "when ntdll stubs are patched"—neither of which is in this plan's `files_modified`. This is scope leakage; these increments need explicit tasks in this plan or a prerequisite plan.
- **MEDIUM — WriteFileEx OVERLAPPED hash timing:** D-17 says "compute hash synchronously in the trampoline before returning." For async I/O, the application may reuse the buffer after `WriteFileEx` returns. Computing the hash before calling the original `WriteFileEx` is safe but adds latency to the async path. The plan should note this tradeoff.

### Suggestions
- Refactor `classify_and_log_handle` to return a `DecisionContext` struct (or use a thread-local context) containing all fields needed for the diagnostic snapshot. This is a significant refactor that should be its own sub-task.
- Verify the `pipe_client` API before implementation; add a `send_fire_and_forget` helper if needed.
- Add explicit sub-tasks for incrementing `injected_pids` in `lib.rs` (or injection entry point) and `patched_modules` in the ntdll patcher module.

---

## Plan 58-03: Agent-Side Aggregation

### Strengths
- `DashMap` for lock-free per-DLL storage follows the `ApprovalCache` pattern exactly.
- Health status enum maps cleanly to D-21 thresholds.
- Alert emission on transitions follows D-22 with consecutive-degraded counting.

### Concerns
- **HIGH — Health threshold uses single snapshot, not history:** D-21 defines `Healthy` as "cache_hit_rate >= 80% AND fail_state == Healthy AND pipe_round_trips > 0 in last 5 min." The `ingest_snapshot` method computes status from the **current snapshot only**—it never checks whether `pipe_round_trips_60s > 0` has held for the last 5 minutes. The `history` field stores 12 snapshots (12 minutes) but is never scanned for the 5-minute trend. This is a direct violation of D-21.
- **HIGH — Agent cannot call `alert_router::send`:** The `alert_router` lives in `dlp-server`. The agent crate does not (and should not) depend on the server crate. The plan's `emit_health_audit_event` calls `alert_router::send` directly, which is architecturally impossible. The agent should emit an `AuditEvent` (via the existing audit pipeline) and let the server route alerts.
- **HIGH — PullDiagnostics/PullHealth directionality is backwards:** D-09 says "The agent polls each connected hook DLL... via the existing named pipe (`HookMessage::PullDiagnostics`)." This means the **agent sends** `PullDiagnostics` **to** the hook DLL, and the hook DLL responds with `DiagnosticsResponse`. The plan's `interception/mod.rs` task describes these as if the hook DLL sends them to the agent: "Add arm for HookMessage::PullDiagnostics(request)... respond with aggregated data." This is backwards—the agent initiates the poll.
- **MEDIUM — Diagnostic key collision on PID reuse:** The key format `"{pid}_{agent_id}"` will collide when a process restarts and gets the same PID. Old diagnostic entries from the previous process will be mixed with new ones. Use a process start timestamp or GUID.
- **MEDIUM — Sorting by QPC across agents:** `get_snapshots` sorts by `timestamp_qpc` descending, but QPC is machine-specific and not comparable across different endpoints. Sorting should use wall-clock time.

### Suggestions
- Compute the `pipe_round_trips > 0 in last 5 min` condition by scanning the last 5 entries in `history` (or a separate 5-minute rolling window).
- Replace `alert_router::send` with audit event emission through the existing agent audit pipeline.
- Clarify that `PullDiagnostics` and `PullHealth` are **agent-initiated** polls sent TO hook DLLs; the interception handler needs a registry of active pipes to poll, not match arms for receiving these messages.
- Use `(pid, process_start_time)` as the diagnostic key, or evict entries when a PID disconnects.

---

## Plan 58-04: Server API and Schema

### Strengths
- Handler pattern (`Query<T>` + `spawn_blocking`) follows `list_bypass_alerts_handler` exactly.
- Route registration under `protected_routes` ensures JWT auth.
- Agent service startup wiring is clear.

### Concerns
- **HIGH — Server cannot read agent's in-memory `DiagnosticAggregator`:** The plan adds `AppState.diagnostic_aggregator` as an `Option<Arc<DiagnosticAggregator>>`. This only works when server and agent run in the same process (test mode). In production, they are separate processes. The plan includes a "KNOWN LIMITATION" note but **no actual solution**. Plan 58-05's TUI screen depends on this endpoint working in production.
- **MEDIUM — Missing health endpoint:** Plan 58-05 calls `GET /admin/health` (or `admin/health`) via `client.get_self_health()`, but this plan does not define such an endpoint. Only `/admin/diagnostics` is defined.
- **MEDIUM — No connected-pipe registry for polling:** The agent needs to track which hook DLL pipes are currently connected to send `PullDiagnostics` and `PullHealth` messages. The existing event loop processes messages as they arrive but does not maintain a `HashMap<pid, PipeHandle>` for outbound polling. The plan does not address this.
- **LOW — Missing specific INSERT/SELECT locations:** The plan says "update the audit event insertion code" but does not identify the specific repository function or file where `AuditEvent` is persisted to SQLite.

### Suggestions
- Add an `POST /agent/diagnostics` endpoint (or reuse the audit ingest channel) for the agent to **push** aggregated diagnostic snapshots to the server periodically. The server stores them in-memory or in a short-lived cache. This supports standalone server deployments.
- Add `GET /admin/health` to serve the current health snapshot from the server's cached data.
- Add a `connected_pipes: Arc<DashMap<u32, PipeHandle>>` to the agent's event loop state for outbound polling.

---

## Plan 58-05: Admin TUI Screens

### Strengths
- Follows the established four-file pattern (constants, dispatch, render, client) rigorously.
- `DiagnosticSeverityFilter` clones `BypassAlertSeverityFilter` exactly.
- UI-SPEC.md is well-referenced and detailed.

### Concerns
- **MEDIUM — `severity` field does not exist on `DiagnosticSnapshot`:** The `draw_diagnostic_list` function extracts `event["severity"]` and the filter cycles through Crit/Warn/Info, but `DiagnosticSnapshot` (defined in 58-01) has no `severity` field. This data must be derived from `matched_policy_id`/`enforcement_mode` or added to the struct. The UI spec invents this field without updating the data model.
- **MEDIUM — Health endpoint mismatch:** The `get_self_health` client method calls `"admin/health"` but Plan 58-04 does not define this endpoint.
- **MEDIUM — QPC timestamp can't show relative time:** The table time column shows "2m ago" but `DiagnosticSnapshot` only has `timestamp_qpc` (QPC ticks). Converting QPC to relative time requires the QPC frequency and a baseline, which the TUI doesn't have. Need a wall-clock timestamp field.
- **LOW — SystemMenu render list not explicitly updated:** The plan says "Shift Syslog Config from 12 to 14, Back from 13 to 15" but the render.rs SystemMenu list is a separate concern from dispatch.rs. Both must be updated and kept in sync.

### Suggestions
- Add `severity: String` to `DiagnosticSnapshot` (derive from enforcement_mode or matched policy tier) or remove severity filtering from the TUI.
- Add `timestamp: DateTime<Utc>` to `DiagnosticSnapshot` for wall-clock display.
- Ensure both `dispatch.rs` AND `render.rs` SystemMenu lists are updated and verified by a unit test.

---

## Plan 58-06: Override Flow Integration

### Strengths
- Extensive reuse of Phase 61 infrastructure (`ApprovalCache`, `ApprovalCacheKey`, JWT verification).
- Correct fire-and-forget semantics: hook DLL returns DENY immediately, user retries after approval.
- `approval_override` field in `HookResponse` is the right integration point (avoids a second pipe round-trip).

### Concerns
- **HIGH — Bincode compatibility for `HookResponse` extension:** Adding `approval_override: Option<bool>` to `HookResponse` has the same bincode compatibility problem as 58-01. Old hook DLLs deserializing a response from a new agent will fail with `UnexpectedEof`. This breaks the existing installed base.
- **HIGH — No IPC mechanism to trigger modal dialog in `dlp-user-ui`:** The plan says "forward to dlp-user-ui via existing IPC mechanism." The existing agent->UI IPC (`Pipe1AgentMsg::BlockNotify`, `Pipe2AgentMsg::Toast`) sends notifications/toasts. A modal dialog requiring text input (`show_override_dialog()`) needs a new IPC message type. The plan does not design this message.
- **HIGH — `dlp-user-ui` may not have server network access:** The plan says dlp-user-ui submits to `POST /admin/approvals`, but the user UI process runs in the user session and may not have the server's TLS certificates or network route. The agent (SYSTEM service) is the natural proxy. The flow should be: user UI submits justification back to agent -> agent POSTs to server.
- **MEDIUM — Approval override check should be in agent's evaluate path, not hook DLL:** The plan in 58-02 describes `check_approval_cache` in the hook DLL, but the hook DLL cannot access the agent's `ApprovalCache` (it's in a different process). The correct flow is: hook DLL sends normal classify request -> agent evaluates ABAC -> if DENY, agent checks `ApprovalCache` -> if valid override, agent returns `HookResponse` with `approval_override=true`. Plan 58-06 gets this right, but 58-02 contradicts it.

### Suggestions
- Bump the IPC protocol version for `HookResponse` changes, or add `approval_override` to a new response variant.
- Design a new `Pipe2AgentMsg::ShowOverrideDialog { requester_sid, resource_path, action }` message from agent to user UI.
- Have dlp-user-ui submit the justification back to the agent via a new user-ui -> agent IPC message, then agent forwards to the server.

---

## Cross-Cutting Issues

| Issue | Affected Plans | Severity | Mitigation |
|-------|-------------|----------|------------|
| Bincode IPC compatibility | 58-01, 58-06 | HIGH | Bump protocol version or use versioned envelope for all new fields/variants |
| Server can't read agent memory | 58-04, 58-05 | HIGH | Agent pushes diagnostics to server; server caches them |
| No UI modal IPC mechanism | 58-06 | HIGH | Design new agent->UI IPC message for modal dialog trigger |
| Health threshold uses wrong data | 58-03 | HIGH | Scan 5-minute history window, not single snapshot |
| `classify_and_log_handle` return type | 58-02 | HIGH | Refactor to return `DecisionContext` struct |
| Missing health endpoint | 58-04, 58-05 | MEDIUM | Add `GET /admin/health` to server API |
| `severity` field missing from snapshot | 58-01, 58-05 | MEDIUM | Add to `DiagnosticSnapshot` or remove from TUI |
| PID reuse in diagnostic keys | 58-03 | MEDIUM | Include process start time in key |

---

## Risk Assessment: **HIGH**

The plans are well-structured at the module level and follow established patterns, but four **blocking architectural issues** prevent confident execution:

1. **Bincode compatibility** breaks across process boundaries for all new IPC types. Without a protocol version strategy, deploying these changes will cause pipe deserialization failures between old and new components.
2. **Cross-process data access** (server reading agent's `DiagnosticAggregator`) is impossible in the current architecture. The TUI screens depend on an endpoint that cannot exist as designed.
3. **Missing UI IPC** for modal dialog triggering means DIFF-01 cannot be implemented without designing a new message channel, which is not scoped in any plan.
4. **Health threshold bug** (58-03) means the Self-Health Dashboard will show incorrect status and miss degradation transitions.

**Recommendation:** Revise 58-01 to use a new IPC protocol version, revise 58-03 to scan history for thresholds and emit audit events instead of calling alert_router, revise 58-04 to define an agent-push model for diagnostics and add the health endpoint, and revise 58-06 to design the agent->UI modal IPC message. Only then should execution begin.

---

## OpenCode Review

[0m
> build · gpt-5.3-chat-latest
[0m

---

## Consensus Summary

### Agreed Strengths
- Clean dependency ordering (foundation → hook DLL → agent → server → TUI → override)
- Strong reuse of existing Phase 48-61 infrastructure
- Good separation of concerns across the six plans
- Health counter emission reuses existing telemetry cadence
- Override flow correctly reuses Phase 61 approval infrastructure
- TUI screens follow established four-file pattern consistently

### Agreed Concerns (both reviewers flagged)

**HIGH — Bincode IPC compatibility when adding new enum variants**
- Both reviewers identified that adding variants to `IpcPayloadV1` without a versioned envelope risks breaking bincode deserialization with old agents.
- Consensus: Bump to `IpcPayloadV2` or introduce a versioned envelope before adding variants.

**HIGH — Blocking hash computation on hooked thread**
- Both reviewers noted that `rayon::ThreadPool::install()` blocks the calling thread until a worker is available.
- The research specifies non-blocking fallback on saturation (`hash_skipped: true`), but the current design cannot achieve this with `install()`.
- Consensus: Replace with a bounded channel + timeout or `ThreadPool::spawn` + timeout mechanism.

**HIGH — Server/agent memory-sharing assumption for diagnostics**
- Both reviewers identified that `DiagnosticAggregator` in `AppState` is architecturally broken for production (server and agent are separate processes).
- Consensus: Implement agent-side HTTP endpoint (`GET /agent/diagnostics`) and have TUI or server proxy call it.

**HIGH — Approval override incompatible with shared-memory cache fast path**
- Both reviewers flagged that `HookResponse.approval_override` cannot be checked when the hook DLL uses the shared-memory cache (Phase 50) without a pipe round-trip.
- Consensus: Either always do a lightweight pipe check on DENY, or scope override check to pipe-based decisions only, or mirror approval cache to shared memory.

**HIGH — Classification context plumbing underspecified**
- Both reviewers noted that `classify_and_log_handle()` returns `Option<DenyReturn>` which does not expose classification source, cache age, or ABAC context needed for diagnostic snapshots.
- Consensus: Refactor return type to a richer struct before Plan 58-02 executes.

**MEDIUM — Override request sent on every DENY without throttling**
- Both reviewers flagged that repeated blocked operations will spam the pipe and create multiple pending approval requests.
- Consensus: Add per-operation deduplication window (e.g., 30-second cooldown per `(path, action)` tuple).

**MEDIUM — Agent-to-user-session IPC mechanism unspecified**
- Both reviewers noted that crossing the SYSTEM → user session boundary requires explicit mechanism verification.
- Consensus: Verify existing IPC supports cross-session communication or document the mechanism.

**MEDIUM — `alert_router::send` called from `dlp-agent` (cross-crate violation)**
- Both reviewers identified that `alert_router` lives in `dlp-server`, not `dlp-agent`.
- Consensus: Emit audit event from agent and let server's ingestion pipeline trigger alerts.

**MEDIUM — QPC tick constant for expiry is machine-dependent**
- Both reviewers flagged that `36_000_000_000_000` assumes 10 MHz QPC frequency, which varies by hardware.
- Consensus: Use `QueryPerformanceFrequency` at runtime or switch to `GetTickCount64` / `std::time::Instant`.

### Divergent Views
- **Hash latency tolerance**: OpenCode suggests reducing cap to 8MB for synchronous path; Claude accepts 100MB cap with documented latency expectation (~3-8ms on modern hardware).
- **Diagnostic sorting**: OpenCode suggests maintaining insertion order; Claude recommends adding wall-clock `timestamp_utc` field for cross-process sorting.
- **Override flow authority**: OpenCode suggests hook DLL should NOT independently check approval cache (agent is authoritative); Claude focuses on the shared-memory cache incompatibility rather than authority.

---

## Action Items for Plan Revision

1. **Plan 58-01**: Add `IpcPayloadV2` or versioned envelope; replace `rayon::install` with non-blocking hash submit; fix QPC expiry constant; verify `hex` crate dependency.
2. **Plan 58-02**: Refactor `classify_and_log_handle` return type; add `RequestOverride` throttling; document `WriteFileEx` buffer validity.
3. **Plan 58-03**: Fix `DiagnosticAggregator` DashMap race; remove `alert_router::send` from agent; make override flow fully async.
4. **Plan 58-04**: Replace shared `AppState` with agent HTTP endpoint for diagnostics; clarify health endpoint ownership.
5. **Plan 58-05**: Pre-parse API responses; clarify history population for sparklines; define severity filter mapping.
6. **Plan 58-06**: Resolve `HookResponse.approval_override` vs shared-memory cache incompatibility; verify cross-session IPC; fix empty justification flow.

