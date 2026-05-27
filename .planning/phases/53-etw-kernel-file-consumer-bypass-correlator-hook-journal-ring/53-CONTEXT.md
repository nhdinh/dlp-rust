# Phase 53: ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring - Context

**Gathered:** 2026-05-27
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 53 turns hook-vs-ETW divergence into auditable `BypassAlert` events routed through SIEM and the alert router. It delivers:

1. **ETW Kernel-File consumer** (`etw_kernel_file.rs`) — real-time `Microsoft-Windows-Kernel-File` subscription via `ferrisetw` 1.2.0; 256 KB x 200 buffers; CREATE/WRITE/DELETE_PATH/OP_END keywords; consumer-side System32/WinSxS filter.
2. **Hook-DLL journal ring buffer** — per-process `Global\DlpHookJournal_<pid>` shared memory (64 KiB); single-producer (hook DLL), single-consumer (agent correlator); entry written BEFORE returning decision so denials are also journaled.
3. **Bypass correlator** (`bypass_correlator.rs`) — for each ETW event, looks up matching journal entry within +/-5 ms QPC tolerance; absence produces `BypassAlert`; allowlisted PIDs dropped pre-correlation.
4. **Server-side bypass alert storage** — `bypass_alerts` SQLite table, repository, `POST /audit/bypass` (agent -> server), `GET /admin/bypass-alerts` (admin TUI feed), `POST /admin/bypass-alerts/:id/ack`.
5. **SIEM + alert router wiring** — bypass alerts route through existing `siem_connector::relay` and `alert_router::send` (when severity >= ALERT); no new outbound transport.

**What Phase 53 does NOT build:**
- Admin TUI Bypass Alerts screen (Phase 54 — UX-02)
- Admin TUI Protected Paths screen (Phase 54 — UX-01)
- Monitor-only / audit-only mode awareness in bypass alerts (Phase 55)
- SD/optical/virtual drive volume-class filtering (Phase 56)
- Automatic remediation of bypassed operations (out of scope — detection and alerting only)
- Kernel-mode driver or minifilter (architecturally banned per PROJECT.md)

**Depends on:** Phase 50 (shared-memory cache, fail-mode state machine, background thread pattern), Phase 51 (ntdll patching produces operations worth correlating, BypassAlert types exist), Phase 49 (ProcessWatcher provides process creation events for journal discovery), Phase 52 (protected paths define what is worth monitoring)
**Requirements:** ETW-01, ETW-02, ETW-03, ETW-04, ETW-05

</domain>

<decisions>
## Implementation Decisions

### Journal Ring Lifecycle and Discovery
- **D-01:** The hook DLL creates its journal shared memory lazily on first hook invocation (not in `DllMain`). Uses the same `CreateFileMapping` + `MapViewOfFile` pattern as the classification cache (`Global\DlpClassificationCache`). Name: `Global\DlpHookJournal_<pid>` where `<pid>` is the decimal process ID.
- **D-02:** The agent discovers new journals via the existing `ProcessWatcher` (Phase 49) process creation events. When a `ProcessEvent` with `source = Etw` arrives, the correlator attempts to open `Global\DlpHookJournal_<pid>` with a 5-second retry loop (journal may not exist yet if the process hasn't made its first hooked I/O call).
- **D-03:** On process exit (detected via `ProcessWatcher` heartbeat timeout or `NtQuerySystemInformation` periodic sweep), the agent unmaps the journal handle after a 5-second grace period. This grace period captures any trailing ETW events for that process. The shared memory object itself is freed when the last handle closes (Windows semantics).
- **D-04:** Journal ring buffer layout: 64 KiB total, 48 bytes per entry, ~1365 entries. Header (8 bytes): `version: u32` + `write_index: u32` (monotonic, wraps via modulo). Entries are `JournalEntry { seq: u64, handle_value: u64, op: u8, path_hash: u64, ts_qpc: u64 }` (40 bytes with 7 bytes padding = 48 bytes total). Single-producer writes header+entry atomically via `write_index` bump; single-consumer reads behind write_index.

### Correlation Key and Matching Strategy
- **D-05:** Correlation uses `(pid, path_hash, op, ts_qpc)` as the composite key, NOT `file_object`. The hook DLL operates in user mode and receives `HANDLE` values, not kernel `FILE_OBJECT` pointers. `FILE_OBJECT` is stored in the bypass alert for forensics but is not used for correlation.
- **D-06:** `path_hash` is FNV-1a 64-bit of the normalized path. The hook DLL uses the same normalization as the classification cache (NT/DOS/UNC normalization, 8.3 short-name rejection, ADS stripping, case-insensitive). The correlator applies identical normalization to the ETW `FileName` field before hashing for comparison.
- **D-07:** `op` is a compact enum (`Create = 1`, `Write = 2`, `Delete = 3`, `SetInfo = 4`) derived from the ETW keyword/opcode and the hook's trampoline type. The correlator maps ETW `Opcode` + `Keyword` to this enum and looks for an exact match in the journal.
- **D-08:** +/-5 ms QPC tolerance: the correlator reads `QueryPerformanceCounter` at startup to establish QPC frequency. On each ETW event, it computes `ts_qpc = event_timestamp * (qpc_freq / 1_000_000)` (ETW timestamps are in 100ns units). It searches journal entries where `|entry.ts_qpc - event_ts_qpc| <= 5ms_in_qpc_units`.
- **D-09:** Correlation is a best-effort lookup, not a guarantee. False positives (journal entry present but ETW event still flagged) are acceptable at low rates; false negatives (bypassed operation missed) are the primary concern. The 5ms tolerance and path-hash match are tuned for low false-negative rate.

### Severity Mapping
- **D-10:** Fixed severity mapping by correlation reason and path sensitivity:
  - `NoHookJournal` on a registered Protected Path (T3/T4) -> `crit`
  - `NoHookJournal` on non-protected path -> `warn` (still interesting for threat hunting)
  - `OpMismatch` (journal has different op for same path/timestamp) -> `warn`
  - `HookOverwritten` (from Phase 51 re-verification thread) -> `crit`
  - `PatchRaced` (from Phase 51 patch attempt) -> `info`
- **D-11:** `crit` severity bypass alerts trigger the alert router (`alert_router::send`) in addition to SIEM relay. `warn` and `info` go to SIEM only. This matches the existing alert router behavior for `DENY_WITH_ALERT` policy actions.

### Agent-Side Allowlist for Pre-Correlation Filtering
- **D-12:** The agent reads the same `Global\DlpAllowlistCache` shared-memory region that the hook DLL uses. This avoids duplicating allowlist logic or config surface. The agent re-reads the allowlist every 30 seconds (same cadence as `policy_sync` config polling).
- **D-13:** Pre-correlation filtering drops ETW events where the originating PID's image path matches an allowlist entry (System32, WinSxS, build tools, AV/EDR). The filter is applied BEFORE the correlator runs, reducing noise and CPU load. Allowlisted PIDs are tracked in a `HashSet<u32>` with 60-second TTL (process may restart with same PID).
- **D-14:** In addition to shared-memory allowlist, the agent maintains a hardcoded emergency filter for known system processes (`System`, `Registry`, `smss.exe`, `csrss.exe`, `lsass.exe`) that is always applied regardless of shared-memory state. This prevents system-critical processes from flooding the bypass alert table.

### ETW Consumer Architecture
- **D-15:** The ETW Kernel-File consumer follows the same architecture as `ProcessWatcher` (Phase 49): dedicated OS thread running `ferrisetw` blocking trace loop, events pushed through `crossbeam::bounded` channel to a tokio task. Buffer config: 256 KB x 200 buffers (52 MB total), matching ProcessWatcher and ROADMAP spec.
- **D-16:** Consumer-side keyword filter: subscribe to `Microsoft-Windows-Kernel-File` with keywords `CREATE | WRITE | DELETE_PATH | OP_END` and `TRACE_LEVEL_INFORMATION`. Additional System32/WinSxS path filter applied in the tokio task (not at ETW layer — ETW filtering is too coarse for path-based exclusion).
- **D-17:** Lost-event monitoring: the agent subscribes to `Microsoft-Windows-Kernel-EventTracing/Admin` for Event ID 2 (lost events). If any lost-event entry appears during a stress test, the buffer size or count is increased. This is a test-time verification, not a runtime alert.
- **D-18:** The ETW consumer is gated by the same `enable_ntdll_patching` policy flag (default off). When the flag is off, the correlator still runs but operates in a reduced mode: it journals hook events and correlates, but only emits `info`-severity alerts (no `crit` triggers to alert router). This provides baseline telemetry without alarming operators during phased rollout.

### Server Endpoint Design
- **D-19:** `POST /audit/bypass` accepts a batch of bypass alerts (max 100 per request) from the agent. Uses the same JWT authentication as existing agent endpoints. The agent batches alerts and flushes every 5 seconds or when the batch reaches 100 entries.
- **D-20:** `GET /admin/bypass-alerts` supports query parameters: `since` (ISO-8601 timestamp), `severity` (comma-separated: `info,warn,crit`), `acknowledged` (bool), `limit` (default 50, max 500), `offset`. Returns paginated JSON with total count.
- **D-21:** `POST /admin/bypass-alerts/:id/ack` requires admin JWT. Sets `ack_by` and `ack_at` on the row. Idempotent — acking an already-acked alert returns 200. Returns 404 if alert ID does not exist.
- **D-22:** The `bypass_alerts` table schema matches the research/ARCHITECTURE.md specification exactly (see canonical refs). No additional columns. `image_sha256` is nullable and populated lazily on first alert from a given image path (cached in-memory to avoid repeated hashing).

### Hook DLL Journal Integration
- **D-23:** Journal write happens in every file-I/O trampoline BEFORE the classification decision returns. This includes both allowlisted paths (journal then early return) and denied operations (journal then deny). The sequence guarantees that a denial does not skip journaling.
- **D-24:** Journal write is a single non-atomic write of the entry followed by an `Release` store of `write_index`. The consumer reads `write_index` with `Acquire`, then reads the entry. This is safe because the ring is single-producer single-consumer and the write_index bump is the synchronization point.
- **D-25:** If journal shared memory creation fails (e.g., low memory, name collision), the hook DLL silently continues without journaling. The correlator will see ETW events with no matching journal and emit `NoHookJournal` alerts. This is the correct fail-safe: degraded detection is better than crashing the host process.

### Claude's Discretion
- Lazy journal creation chosen over agent pre-creation to avoid races (agent doesn't know when DLL is loaded).
- HANDLE value stored instead of FILE_OBJECT because user-mode code cannot access kernel FILE_OBJECT directly without expensive `NtQuerySystemInformation(SystemHandleInformation)` lookup.
- Path-hash correlation chosen over FILE_OBJECT correlation because path is the stable semantic identifier across user/kernel boundary.
- Shared-memory allowlist reuse chosen over separate agent allowlist to minimize config drift.
- Batch ingest (100 alerts) chosen over per-alert POST to reduce server load and network overhead.
- `enable_ntdll_patching` flag reused as ETW consumer gate to simplify operator rollout (one flag controls both ntdll patching and bypass detection).
- 5-second grace period on process exit chosen to capture trailing ETW events without being so long that it leaks handles.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Architecture
- `.planning/ROADMAP.md` — Phase 53 goal and 5 success criteria
- `.planning/PROJECT.md` — v0.10.0 milestone context, minifilter ban, asymmetric fail semantics
- `.planning/STATE.md` — Decision 4: "retour-based Detours-style 5-byte JMP trampoline"; Decision 6: DACL tripwire design
- `.planning/milestones/v0.11.0-REQUIREMENTS.md` — ETW-01..ETW-05 requirement definitions
- `.planning/research/ARCHITECTURE.md` — Bypass correlator architecture, bypass_alerts table schema, ETW consumer design

### Existing Code Patterns
- `dlp-agent/src/process_watcher.rs` — `ferrisetw` 1.2.0 ETW consumer pattern with crossbeam channel. **MUST mirror** for Kernel-File consumer.
- `dlp-common/src/hook_ipc.rs` — `BypassAlert` struct, `BypassReason` enum (Phase 51). **Extend** with new reason variants for ETW correlation.
- `dlp-server/src/alert_router.rs` — `send_alert` pattern with SMTP + webhook. **Reuse** for crit-severity bypass alerts.
- `dlp-server/src/admin_api.rs` — Admin API CRUD route pattern. **Add** `/admin/bypass-alerts` routes.
- `dlp-server/src/db/mod.rs` — `init_tables()` and `run_migrations()` patterns. **Add** `bypass_alerts` table.
- `dlp-agent/src/service.rs` — Agent service startup; where `EtwKernelFileConsumer` and `BypassCorrelator` are initialized.
- `dlp-agent/src/engine_client.rs` — Agent config polling (30s TOML hot-reload). **Extend** with ETW consumer enable flag.
- `dlp-agent/src/wfp_manager.rs` — `WfpManager` lifecycle pattern (`new`/`register`/`unregister`). **MUST mirror** for ETW consumer.
- `dlp-hook-dll/src/classification_cache.rs` — Shared-memory creation pattern. **Reuse** for journal ring buffer.
- `dlp-hook-dll/src/trampolines.rs` — File-I/O trampoline bodies. **Extend** with journal write call before returning.

### Related Phase Context
- `.planning/phases/50-shared-memory-classification-cache-fail-mode-state-machine/50-CONTEXT.md` — Shared-memory cache, atomic version flip, background thread, allowlist cache
- `.planning/phases/51-ntdll-syscall-stub-trampolines-edr-coexistence/51-CONTEXT.md` — Ntdll patching, BypassAlert types, background thread extension, re-verification thread
- `.planning/phases/52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-/52-CONTEXT.md` — Protected paths registry, repair watcher pattern, staging table
- `.planning/phases/49-universal-injection-etw-process-watcher-allowlist-appinit-fa/49-CONTEXT.md` — Universal injection, process registry, ProcessWatcher architecture
</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`ProcessWatcher`** (`dlp-agent/src/process_watcher.rs`): Complete `ferrisetw` consumer with crossbeam channel, bounded queue, overflow handling, heartbeat health. Model `EtwKernelFileConsumer` after this — same thread + channel + tokio task pattern.
- **`BypassAlert`** (`dlp-common/src/hook_ipc.rs`): Existing struct with `reason`, `stub_name`, `pid`, `timestamp_secs`. Extend `BypassReason` with `NoHookJournal`, `OpMismatch` variants for ETW correlation.
- **`AppState { pool, crypto, policy_store, siem, alert, ad }`** (`dlp-server/src/lib.rs`): Shared state pattern. Add `bypass_alerts: Arc<BypassAlertsRepository>`.
- **`crossbeam::bounded`** (Phase 49): Bounded channel pattern between blocking OS thread and tokio task. Reuse for ETW event flow.
- **`AllowlistCategory::Avedr`** (`dlp-agent/src/allowlist.rs`): Known AV/EDR module names. Reuse for pre-correlation PID filtering.
- **`build_deny_everyone_dacl`** (`dlp-agent/src/protection.rs`): Raw ACL buffer construction. Not directly reused but pattern reference for shared-memory ACL setup.

### Established Patterns
- **Repository pattern**: Stateless struct with `pool` parameter (like `AllowlistRepository`). Use for `BypassAlertsRepository`.
- **Admin API CRUD**: `list` (GET), `get_by_id` (GET), `create` (POST), `update` (PUT), `delete` (DELETE). Bypass alerts are read-only except for ack.
- **Agent config TOML poll**: 30s cadence, hash-based reload. New `[etw_consumer]` section with `enabled` boolean.
- **SIEM audit events**: `siem_connector::relay(audit_event)` for structured audit logging.
- **Alert router**: `alert_router::send_alert(event)` for email/webhook alerts when severity threshold met.
- **Shared-memory naming**: `Global\Dlp{Purpose}` prefix for all shared objects.
- **FNV-1a 64-bit hashing**: Used in classification cache. Reuse for journal path_hash.

### Integration Points
- `dlp-agent/src/lib.rs` — add `etw_kernel_file.rs` and `bypass_correlator.rs` modules.
- `dlp-agent/src/service.rs` — initialize `EtwKernelFileConsumer` and `BypassCorrelator` after `ProcessWatcher` startup.
- `dlp-agent/src/process_watcher.rs` — `ProcessEvent` channel is consumed by both injection task AND correlator journal discovery task.
- `dlp-hook-dll/src/trampolines.rs` — add `journal_write()` call in each file-I/O trampoline before returning.
- `dlp-hook-dll/src/lib.rs` — add `hook_journal.rs` module with shared-memory creation and write functions.
- `dlp-server/src/db/mod.rs` — add `bypass_alerts` table to `init_tables()`.
- `dlp-server/src/admin_api.rs` — add `/admin/bypass-alerts` routes.
- `dlp-server/src/lib.rs` — add `bypass_alerts_repository` to `AppState`.
- `dlp-common/src/hook_ipc.rs` — extend `BypassReason` with ETW correlation variants.
- `dlp-common/src/audit.rs` — add ETW consumer start/stop and bypass alert event types for SIEM.
</code_context>

<specifics>
## Specific Ideas

- The hook journal should be created with `PAGE_READWRITE` protection and no ACL (default security descriptor). The agent opens it with `FILE_MAP_READ` only. This follows the principle that the producer (hook DLL) has write access, the consumer (agent) has read access.
- ETW Kernel-File event parsing: Event ID 12 (Create), 13 (Cleanup), 14 (Close), 15 (Read), 16 (Write), 17 (SetInformation), 18 (Delete), 30 (Rename). We care about 12, 16, 18, 30 and their corresponding `FileName` field.
- The `file_object` field in the bypass_alerts table stores the raw `u64` value of the kernel FILE_OBJECT pointer (from ETW). This is for forensics only — operators can correlate with other ETW traces or kernel debugger sessions.
- Batch alert flush: use a `tokio::time::interval(Duration::from_secs(5))` combined with a `crossbeam_channel::bounded(100)` alert queue. The flush task drains the queue every 5 seconds or when full.
- Image SHA-256 computation: cache in a `DashMap<String, String>` (image_path -> sha256) to avoid re-hashing the same executable repeatedly. Use `windows` crate `GetFileVersionInfo` or manual `CreateFile` + `ReadFile` + SHA-256 for the hash.
- QPC frequency calibration: read `QueryPerformanceFrequency` once at correlator startup. Store as `qpc_freq: i64`. Convert ETW 100ns timestamps to QPC units: `etw_ts_qpc = etw_timestamp * qpc_freq / 10_000_000`.
- The correlator should maintain a per-process `JournalReader` struct that tracks the last read index and a small in-memory ring buffer copy for fast searching.
- For the `POST /audit/bypass` endpoint, validate that `agent_id` matches the JWT's claimed agent ID to prevent one agent from injecting alerts for another agent.
</specifics>

<deferred>
## Deferred Ideas

- Admin TUI Bypass Alerts screen (Phase 54 — UX-02)
- Admin TUI Protected Paths screen (Phase 54 — UX-01)
- Monitor-only / audit-only mode awareness in bypass alerts (Phase 55 — MODE-01)
- SD/optical/virtual drive volume-class filtering in ETW consumer (Phase 56 — DRIVE-01..04)
- Automatic remediation of bypassed operations (post-v0.10.0 — would require handle injection or process termination, high risk)
- Machine-learning-based false-positive suppression for bypass alerts (post-v0.10.0 — needs production data)
- Real-time bypass alert streaming via WebSocket (post-v0.10.0 — current polling model is sufficient)

</deferred>

---

*Phase: 53-ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring*
*Context gathered: 2026-05-27*
