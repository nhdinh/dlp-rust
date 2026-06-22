# Phase 58: Differentiators Bundle (Override + Diagnostic + Hash Evidence + Self-Health) - Context

**Gathered:** 2026-06-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 58 delivers four high-value differentiators that materially improve operator deployability and forensic posture. The phase is **cuttable as a unit to v0.10.1** if scope pressure hits.

**What Phase 58 builds:**
1. **User override flow (DIFF-01)** — On DENY, `dlp-user-ui` shows the existing override dialog; justification round-trips through the existing Phase 61 approval API; admin grants TTL-bounded approval via the existing ApprovalList TUI screen; agent caches the JWT token via existing `approval_cache.rs`; user completes the originally-denied operation within the TTL window.
2. **Diagnostic-mode admin TUI screen (DIFF-02)** — Displays the full decision tree per blocked event: hook function fired, classification source + age, ABAC subject/resource/action/environment values, matched policy ID + mode, decision latency in microseconds. Sufficient to triage a real false-positive without leaving the TUI.
3. **Content hash evidence (DIFF-03)** — Block events on `WriteFile`/`WriteFileEx` carry a `content_sha256` hash of the would-be-written content, computed from the write buffer (`lpBuffer`) directly with no second file open. Hash is forwarded unchanged through audit events and SIEM relay for forensic chain-of-custody.
4. **Self-health dashboard (DIFF-04)** — Hook DLL emits per-host counters (injected_pids, patched_modules, pipe_round_trips, cache_hit_rate, fail_state) polled by agent every 60s. Admin TUI surfaces a coexistence dashboard with current snapshot + 5-min trend, plus auto-alert on degraded health.

**What Phase 58 does NOT build:**
- New approval server schema or JWT signing infrastructure (reuses Phase 61)
- New override UI dialog (reuses existing `override_request.rs`)
- Kernel-mode or driver-based diagnostics
- File content hashing for ALLOW decisions (only blocked writes)
- Multi-GB file full-content hashing (capped at 100MB)
- User-facing diagnostic screen (admin TUI only)
- Cross-endpoint health aggregation (per-host only)

**Depends on:** Phases 48-57 (every differentiator depends on prior shipped capabilities). Specifically:
- DIFF-01: hook DLL (48), universal injection (49), user UI (25), approval workflow (61)
- DIFF-02: hook DLL tracing (48), ABAC engine (26), perf telemetry (50)
- DIFF-03: hook DLL WriteFile trampoline (48), audit event pipeline (v0.2.0+)
- DIFF-04: shared-memory cache (50), injection registry (49), perf telemetry (50)

**Requirements:** DIFF-01, DIFF-02, DIFF-03, DIFF-04

</domain>

<decisions>
## Implementation Decisions

### Override Flow (DIFF-01)
- **D-01:** Reuse the existing Phase 61 approval workflow infrastructure. No new SQLite schema, no new JWT signing code, no new approval TUI screen. The `approvals` table, `Approval` types, `approval_cache.rs`, and `ApprovalList` TUI screen from Phase 61 are leveraged directly.
- **D-02:** On DENY, the hook DLL sends `HookMessage::RequestOverride` via the existing named pipe to the agent. The agent forwards to `dlp-user-ui` which shows the existing `show_override_dialog()` from `dialogs/override_request.rs`. This is a modal Win32 dialog (not a toast) because it requires user text input.
- **D-03:** The justification + blocked operation metadata are submitted to the existing `POST /admin/approvals` endpoint (reused from Phase 61), not a new `/admin/overrides` endpoint. The override is an approval request with `status = Pending`.
- **D-04:** Admin grants the approval via the existing ApprovalList TUI screen (Phase 61). The TTL is controlled by the existing `valid_until` field on the `Approval` record. Default TTL is 1 hour; maximum TTL is 24 hours enforced at the API boundary.
- **D-05:** The approved JWT token is delivered to the agent via the existing `GET /agent/approvals` endpoint (Phase 61). The agent stores it in the existing `ApprovalCache` (`approval_cache.rs`). On the next blocked operation, the hook DLL checks the cache via the existing three-stage pipeline (NTFS -> ABAC -> approval override).
- **D-06:** Override scope is per `(requester_sid, data_object_id, action, destination_scope)` — the existing `ApprovalCacheKey` structure. This is the same granularity as Phase 61 approvals.

### Diagnostic Mode (DIFF-02)
- **D-07:** Diagnostic data is captured in an in-memory ring buffer in the hook DLL, not persisted to disk or SQLite. Each entry is a `DiagnosticSnapshot` struct containing: hook_function, classification_source (CacheHit/CacheMiss/Pipe), classification_age_ms, abac_context (subject/resource/action/environment), matched_policy_id, enforcement_mode, decision_latency_us, timestamp_qpc.
- **D-08:** Ring buffer capacity is 1000 entries per hook DLL instance. Oldest entries are overwritten when full. Entries expire after 1 hour (lazy eviction on write). This bounds memory to ~1MB per process.
- **D-09:** The agent polls each connected hook DLL for diagnostic snapshots every 30 seconds via the existing named pipe (`HookMessage::PullDiagnostics`). The agent aggregates snapshots in memory and exposes them via a new `GET /admin/diagnostics` paginated endpoint.
- **D-10:** The admin TUI diagnostic screen reads from `GET /admin/diagnostics` and displays a scrollable list of blocked events. Each row shows: time, user, path, tier, policy, latency, classification source. Enter opens a detail popup with the full ABAC context and decision tree.
- **D-11:** Diagnostic mode is admin-only. No user-facing diagnostic screen. The diagnostic screen follows the existing `BypassAlertList` pattern (Phase 54) for dispatch/render/client wiring.

### Content Hash Evidence (DIFF-03)
- **D-12:** SHA-256 is computed only for blocked (`DENY`) `WriteFile` and `WriteFileEx` operations. ALLOW operations do not hash content. This minimizes hot-path overhead.
- **D-13:** The hash is computed from the write buffer (`lpBuffer` parameter) directly in the trampoline, before calling the original `WriteFile`. No second file open is performed. The buffer length is `nNumberOfBytesToWrite`.
- **D-14:** A 100MB size cap applies: if `nNumberOfBytesToWrite > 100MB`, only the first 100MB is hashed. This prevents multi-GB writes from causing latency spikes. The audit event records `content_sha256: "<hash>"` with an optional `hash_truncated: true` field when the cap is hit.
- **D-15:** SHA-256 only (not SHA-512). Use the `sha2` crate's `Sha256` hasher in streaming mode. The hash computation happens in a `tokio::task::spawn_blocking` equivalent inside the hook DLL (a dedicated thread pool or rayon) to avoid blocking the hooked thread. If the compute thread pool is saturated, the hash field is omitted and a `hash_skipped: true` flag is set.
- **D-16:** The computed hash is attached to the `AuditEvent` as `content_sha256: Option<String>` and forwarded unchanged through the SIEM relay. The hash is also stored in the server-side `audit_events` table for forensic retrieval.
- **D-17:** For `WriteFileEx` with an OVERLAPPED structure (asynchronous I/O), the hash is computed synchronously in the trampoline before returning, using the same buffer pointer. The completion callback is not intercepted.

### Self-Health Dashboard (DIFF-04)
- **D-18:** Hook DLL emits per-host counters as an extension to `perf_telemetry.rs`. New counters added: `injected_pids` (count of processes reporting in), `patched_modules` (count of ntdll stubs successfully patched), `pipe_round_trips_60s` (count of pipe requests in last 60s), `cache_hit_rate_60s` (ratio of cache hits in last 60s), `current_fail_state` (Healthy/Degraded/Isolated/Resync).
- **D-19:** The agent polls connected hook DLLs every 60 seconds for health counters via the existing named pipe (`HookMessage::PullHealth`). The agent aggregates counters per-host and stores the last 12 snapshots (12 minutes of history) in an in-memory `VecDeque`.
- **D-20:** The admin TUI self-health dashboard shows: (a) current snapshot with color-coded status (green=healthy, yellow=degraded, red=isolated), (b) 5-minute sparkline trend for cache_hit_rate and pipe_round_trips. Screen follows the existing `BypassAlertList` / `ProtectedPaths` pattern.
- **D-21:** Health thresholds: `Healthy` = cache_hit_rate >= 80% AND fail_state == Healthy AND pipe_round_trips > 0 in last 5 min. `Degraded` = cache_hit_rate < 80% OR fail_state == Degraded. `Critical` = fail_state == Isolated OR 0 pipe_round_trips in last 5 min.
- **D-22:** Auto-alert generation: when health transitions from Healthy to Degraded for 2 consecutive polls (2 minutes), the agent emits a `siem.hook_health_degraded` audit event at `warn` severity. When transitioning to Critical, it emits at `crit` severity and routes through the alert router (existing `alert_router::send`).
- **D-23:** The self-health dashboard is read-only. No operator actions (restart, re-inject) from the TUI — those remain manual operational procedures documented in Phase 57's deployment guide.

### Claude's Discretion
- The diagnostic ring buffer should use a `crossbeam::queue::ArrayQueue` for lock-free writes from multiple threads.
- Hash computation should use a small thread pool (2 threads) inside the hook DLL dedicated to SHA-256 computation, initialized lazily via `OnceLock`.
- Health counter aggregation in the agent should reuse the existing `PerfTelemetry` emission cadence (every 1000 calls) rather than adding a new emission path.
- The diagnostic admin API should support filtering by `since`, `user_sid`, and `policy_id` to help operators triage specific false-positive patterns.
</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Architecture
- `.planning/ROADMAP.md` — Phase 58 goal, 4 success criteria, requirements DIFF-01..04
- `.planning/PROJECT.md` — v0.10.0 milestone context, architecture constraints
- `.planning/STATE.md` — Phase completion status, prior decisions

### Prior Phase Context (Capabilities to Reuse)
- `.planning/phases/55-monitor-only-audit-only-per-policy-enforcement-mode/55-CONTEXT.md` — Enforcement modes, effective mode computation
- `.planning/phases/56-sd-optical-virtual-drive-enumeration-volume-class-abac-seed-/56-CONTEXT.md` — Volume-class ABAC, hook DLL context extension
- `.planning/phases/57-operational-deployment-guide-av-edr-allowlist-uat/57-CONTEXT.md` — Deployment guide patterns, UAT methodology

### Approval Workflow (Phase 61 — Reused for DIFF-01)
- `.planning/phases/61-approval-workflow-engine-t3-data-owner-t4-board-digital-signature/61-CONTEXT.md` — Approval workflow design, JWT tokens, Ed25519 signing
- `dlp-common/src/approval.rs` — `Approval`, `ApprovalClaims`, `ApprovalCacheKey`, `CachedApproval`, `ApprovalToken`, `ApprovalRequest` types
- `dlp-agent/src/approval_cache.rs` — Agent-side `ApprovalCache` with JWT re-verification and destination scope matching
- `dlp-server/src/db/repositories/approvals.rs` — Server-side approval repository
- `dlp-user-ui/src/dialogs/override_request.rs` — Existing Win32 override justification dialog (`show_override_dialog`)

### Hook DLL Infrastructure (Phases 48-51)
- `.planning/phases/48-hook-dll-surface-expansion-crash-hardening-build-harness/48-CONTEXT.md` — Hook DLL architecture, trampoline patterns
- `.planning/phases/50-shared-memory-classification-cache-fail-mode-state-machine/50-CONTEXT.md` — Shared-memory cache, fail-mode state machine
- `.planning/phases/51-ntdll-syscall-stub-trampolines-edr-coexistence/51-CONTEXT.md` — ntdll patching, EDR detection, background verification thread
- `dlp-hook-dll/src/perf_telemetry.rs` — QPC latency measurement, histogram, thread-local telemetry
- `dlp-hook-dll/src/trampolines.rs` — File-I/O trampoline bodies (WriteFile, WriteFileEx, etc.)
- `dlp-hook-dll/src/fail_mode.rs` — Fail-state machine (Healthy/Degraded/Isolated/Resync)
- `dlp-hook-dll/src/pipe_client.rs` — Named pipe communication with agent
- `dlp-hook-dll/src/hook_journal.rs` — Per-process journal ring buffer (pattern to follow for diagnostic ring)

### Audit & SIEM Pipeline
- `dlp-common/src/audit.rs` — `AuditEvent` types, SIEM routing
- `dlp-server/src/siem_connector.rs` — SIEM relay
- `dlp-server/src/alert_router.rs` — Alert router (email/webhook)

### Admin TUI Patterns
- `.planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-CONTEXT.md` — Admin TUI screen patterns
- `dlp-admin-cli/src/screens/bypass_alerts.rs` — `BypassAlertList` screen (dispatch/render/client pattern to follow)
- `dlp-admin-cli/src/app.rs` — `Screen` enum, navigation, `AppState`

### Code Conventions
- `.planning/codebase/CONVENTIONS.md` — Rust coding standards, naming, error handling
- `.planning/codebase/STRUCTURE.md` — Workspace module organization

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`ApprovalCache`** (`dlp-agent/src/approval_cache.rs`): Lock-free DashMap with JWT re-verification and scope matching. Reuse entirely for DIFF-01 — just wire the hook DLL deny path to trigger the user UI dialog and approval API submission.
- **`show_override_dialog`** (`dlp-user-ui/src/dialogs/override_request.rs`): Existing Win32 modal dialog for override justification. Reuse without modification for DIFF-01.
- **`PerfTelemetry`** (`dlp-hook-dll/src/perf_telemetry.rs`): Thread-local QPC telemetry with histogram buckets and periodic emission. Extend with health counters for DIFF-04.
- **`HookJournal`** (`dlp-hook-dll/src/hook_journal.rs`): Per-process ring buffer in shared memory (64 KiB, 56-byte entries). Follow the same pattern for the diagnostic ring buffer (DIFF-02).
- **`BypassAlertList`** (`dlp-admin-cli/src/screens/bypass_alerts.rs`): Complete TUI screen with list, pagination, filter, ack, detail popup. Clone and adapt for both the Diagnostic screen (DIFF-02) and Self-Health dashboard (DIFF-04).
- **`AuditEvent`** (`dlp-common/src/audit.rs`): Builder pattern with optional fields. Add `content_sha256` and `hash_truncated` fields for DIFF-03.

### Established Patterns
- **Hook DLL -> Agent named pipe**: `HookMessage` enum in `dlp-common/src/hook_ipc.rs`. Extend with `RequestOverride`, `PullDiagnostics`, `PullHealth` variants.
- **Agent -> User UI IPC**: `ipc/messages.rs` in `dlp-user-ui`. Reuse for forwarding override requests.
- **Thread-local + periodic emission**: `perf_telemetry.rs` emits every 1000 calls. Health counters should follow the same cadence.
- **TUI screen pattern**: `dispatch.rs` (event handling) + `render.rs` (ratatui widgets) + `client.rs` (HTTP calls) + `app.rs` (Screen enum variant). Every new TUI screen follows this four-file pattern.
- **SIEM event routing**: `routed_to_siem()` predicate + `triggers_alert()` predicate. Health degraded events route to SIEM; crit severity routes to alert router.

### Integration Points
- `dlp-common/src/hook_ipc.rs` — Add `HookMessage::RequestOverride`, `HookMessage::PullDiagnostics`, `HookMessage::PullHealth`, `HookMessage::DiagnosticsResponse`, `HookMessage::HealthResponse`.
- `dlp-common/src/audit.rs` — Add `content_sha256: Option<String>`, `hash_truncated: Option<bool>`, `hash_skipped: Option<bool>` to `AuditEvent`.
- `dlp-hook-dll/src/trampolines.rs` — On DENY: (1) trigger override request flow, (2) compute content hash for WriteFile/WriteFileEx, (3) emit diagnostic snapshot, (4) update health counters.
- `dlp-hook-dll/src/perf_telemetry.rs` — Extend with health counter aggregation and emission.
- `dlp-agent/src/interception/mod.rs` — Handle `RequestOverride` pipe message: forward to user UI; handle `PullDiagnostics`/`PullHealth`: respond with aggregated data.
- `dlp-agent/src/approval_cache.rs` — No changes needed; already supports the override token caching.
- `dlp-server/src/admin_api.rs` — Add `GET /admin/diagnostics` endpoint (paginated, filtered); extend audit event ingestion to store `content_sha256`.
- `dlp-server/src/db/mod.rs` — Migration: add `content_sha256` column to `audit_events` table.
- `dlp-admin-cli/src/app.rs` — Add `Screen::DiagnosticList` and `Screen::SelfHealthDashboard` variants.
- `dlp-admin-cli/src/screens/` — Create `diagnostic_list.rs` and `self_health_dashboard.rs` following `bypass_alerts.rs` pattern.
</code_context>

<specifics>
## Specific Ideas

- Override dialog reuse: The existing `show_override_dialog()` uses `DialogBoxIndirectParamW` with an in-memory template. It already captures multi-line justification text. The only change needed is wiring it to the hook DLL deny path via agent IPC.
- Approval API reuse: `POST /admin/approvals` already accepts `requester_sid`, `data_object_id`, `allowed_action`, `destination_scope`, `justification`. The hook DLL deny path can populate these from the ABAC context. `data_object_id` maps to the label/classification ID; if no label exists, use the file path hash as fallback.
- Hash computation thread pool: Use `rayon` inside the hook DLL (already a workspace dependency via `dlp-common`) with a custom `ThreadPool` of 2 threads initialized lazily via `OnceLock`. This keeps SHA-256 computation off the hot path thread.
- Diagnostic snapshot detail popup: Show the ABAC decision tree as nested key-value pairs in a scrollable text block within the popup. Use the existing `render_detail_popup` pattern from `bypass_alerts.rs`.
- Self-health dashboard sparklines: Use `ratatui`'s `Sparkline` widget for the 5-minute cache_hit_rate trend. Color the sparkline green above 80%, yellow 60-80%, red below 60%.
- Health counter wire format: A small `HookHealthSnapshot` struct with 5 u64 fields + 1 enum, serialized via `bincode` for minimal pipe overhead. Total size ~64 bytes.
</specifics>

<deferred>
## Deferred Ideas

- User-facing diagnostic screen (self-service false-positive triage) — deferred to operational efficiency phase
- Cross-endpoint health aggregation (fleet-wide hook health view) — deferred to v0.11.0+ fleet management phase
- Automated agent restart/re-injection from TUI on degraded health — deferred; manual per deployment guide
- Content hashing for ALLOW decisions (audit trail completeness) — deferred; only blocked writes are hashed for v0.10.0
- SHA-512 hash option for higher assurance environments — deferred; SHA-256 is sufficient for v0.10.0 forensic needs
- Diagnostic data persistence to SQLite or SIEM long-term storage — deferred; in-memory only for v0.10.0
- Machine-learning-based false-positive prediction from diagnostic patterns — deferred to post-v1.0

</deferred>

---

*Phase: 58-Differentiators Bundle (Override + Diagnostic + Hash Evidence + Self-Health)*
*Context gathered: 2026-06-02*
