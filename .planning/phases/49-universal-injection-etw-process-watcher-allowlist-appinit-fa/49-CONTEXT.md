# Phase 49: Universal Injection — ETW Process Watcher + Allowlist + AppInit Fallback - Context

**Gathered:** 2026-05-19
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 49 drives the unified hook DLL (built in Phase 48) into every non-allowlisted user-mode process — both already-running and newly-spawned — within 500 ms of process start. It adds:

1. **ETW-based process creation detection** — primary trigger via `Microsoft-Windows-Kernel-Process` Event ID 1
2. **WMI `Win32_ProcessStartTrace` backstop** — secondary when ETW is unhealthy
3. **Per-process allowlist** — self (DLP binaries), AV/EDR (signer-cert match), system-critical (PIDs 0/4, csrss, etc.), PPL-detected, WoW64-dispatched
4. **AppInit_DLLs fallback** — tertiary for non-Secure-Boot endpoints, set by installer
5. **Startup `EnumProcesses` sweep** — injects into all already-running non-allowlisted processes within 5 s
6. **Process lifecycle tracking** — `DashMap<u32, ProcessState>` with telemetry for coverage metrics

**Phase 49 does NOT build:**
- ntdll syscall-stub patching (Phase 51)
- Shared-memory classification cache (Phase 50)
- DACL tripwire (Phase 52)
- Deployment guide (Phase 57)

**Depends on:** Phase 48 (unified hook DLL must exist)
**Requirements:** BLOCK-05, BLOCK-06, BLOCK-07

</domain>

<decisions>
## Implementation Decisions

### Allowlist Hot-Reload
- **D-01:** Allowlist delivery extends the existing agent-config TOML poll (30 s cadence). Add `[universal_injection.allowlist]` section to the agent config. Agent reloads on hash-change without restart — reuses v0.2.0+ infrastructure.
- **D-02:** Allowlist matching uses **both** path prefix and signer certificate subject. System-critical processes (PIDs 0/4, csrss, smss, wininit, services, lsass, fontdrvhost, dwm) match by process name / path prefix. AV/EDR processes match by Authenticode signer cert subject (e.g., "O=CrowdStrike, Inc."). This satisfies BLOCK-06's signer-cert requirement and handles the system-critical category that lacks meaningful certs.
- **D-03:** Operator extension flows: Admin TUI writes to server DB → server includes in agent-config TOML response → agent polls and reloads. No dedicated API endpoint or SQLite table needed.

### ETW Consumer Architecture
- **D-04:** ETW consumer runs on a **dedicated OS thread** (`std::thread`) that calls `ProcessTrace` in a blocking loop. ETW callbacks push `(pid, image_path, parent_pid)` structs through a bounded `crossbeam::channel` to a tokio task that performs injection. This keeps the blocking ETW API off the tokio runtime entirely.
- **D-05:** Buffer sizing: 256 KB × 200 buffers = 50 MB total (matches ETW-01 spec). Consumer-side filter drops System32/WinSxS processes at the ETW layer before the callback fires, keeping volume manageable.
- **D-06:** Event loss: If ETW reports dropped events, log `warn!` with dropped count. Do NOT emit a SIEM alert — event loss under load is expected; the WMI backstop and the 5-minute `EnumProcesses` periodic sweep cover gaps.
- **D-07:** WMI backstop: A separate lightweight WMI subscription (`Win32_ProcessStartTrace`) runs as secondary. Higher latency (~50–100 ms) but fires even if ETW session is disrupted. Only used when ETW primary is unhealthy (detected via heartbeat).

### Process Lifecycle Tracking
- **D-08:** State model: `DashMap<u32, ProcessState>` with states: `Discovered` → `Skipped(Reason)` → `Injected(arch, timestamp)` → `Exited`. This gives the telemetry needed for the 99 % coverage metric and the "visibly skipped" requirement from BLOCK-06.
- **D-09:** Cleanup: Two-phase. (a) ETW `Microsoft-Windows-Kernel-Process` Event ID 2 (process exit) removes the PID immediately. (b) A 60-second background sweep catches any missed exits (OpenProcess check) as a safety backstop.
- **D-10:** Duplicate injection guard: Before injecting, check if PID is already in `Injected` state. If yes, skip. This prevents double-injection on ETW + WMI backstop overlap.
- **D-11:** Startup sweep: On agent startup, `EnumProcesses` enumerates all running PIDs. For each PID not already in the map, run the allowlist check and inject if allowed. Target: complete within 5 seconds (success criterion #5).

### Injection Failure Handling
- **D-12:** Retry strategy: One immediate retry after 50 ms. Handles the common case where the process is still initializing its PEB when ETW fires. No further retries — if it fails twice, the process is likely short-lived or protected.
- **D-13:** Failure categorization: `AccessDenied` (PPL, protected process, or insufficient privileges — expected) logged at `warn!`, no alert. `RemoteThreadFailed` / `InjectionFailed` (unexpected) logged at `error!` and emit a `siem.injection_failure` audit event with PID, image path, and error code.
- **D-14:** Periodic backstop: Every 5 minutes, a lightweight `EnumProcesses` sweep checks all running PIDs not in `Injected` or `Skipped` state. Catches processes launched during ETW outage and retries past failures.
- **D-15:** Telemetry aggregation: Per-minute counters (`injected_count`, `skipped_count_by_reason`, `failed_count`) emitted as `siem.injection_telemetry` events. Feed coverage dashboard and help operators spot trends.

### AppInit_DLLs Registration
- **D-16:** Installer sets `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` + `LoadAppInit_DLLs=1` + `RequireSignedAppInit_DLLs=1` at install time. Agent does NOT modify these at runtime. On uninstall, installer restores original values from a backup reg key saved during install.
- **D-17:** Agent only READS the registry at boot to verify AppInit is set correctly. If not, log a warning and rely on ETW-driven injection exclusively.

### Secure Boot Detection
- **D-18:** Agent calls `GetFirmwareEnvironmentVariable("SecureBoot", "{8be4df61-93ca-11d2-aa0d-00e098032b8c}")` at boot. If Secure Boot is enabled, emit exactly one `siem.appinit_dlls_disabled` audit event and skip AppInit registration entirely. If the API is unavailable (pre-UEFI system), treat as Secure Boot = unknown and proceed with AppInit.

### PPL Detection Timing
- **D-19:** PPL status is checked at injection time, not at process creation. ETW Event ID 1 gives PID and image path; the injection task calls `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `GetProcessMitigationPolicy(ProcessSignaturePolicy)` to detect PPL before injecting. This avoids caching stale PPL state (a process may elevate to PPL after launch). The `Skipped(PPL)` state is recorded in the `DashMap`.

### Agent Restart State
- **D-20:** The process map is NOT persisted across restarts. On restart, agent clears the `DashMap` and runs a full `EnumProcesses` sweep. This is simpler and handles the case where processes exited while the agent was down. The 5-second sweep target covers all already-running processes.

### Claude's Discretion
- `ProcessState` enum should derive `Debug`, `Clone`, `PartialEq` for telemetry serialization.
- The `crossbeam::channel` between ETW thread and tokio injection task should be bounded (capacity 1024) with `try_send` — if full, drop the oldest event rather than block the ETW callback (event loss is acceptable per D-06).
- `EnumProcesses` sweep should use `rayon` or manual thread-pool for parallel injection if >100 processes are running. Batch size of 16 processes per thread keeps the sweep under 5 s.
- The allowlist TOML section should support both exact paths and glob patterns: `path = "C:\\Program Files\\CrowdStrike\\*"` and `cert_subject = "O=CrowdStrike, Inc."`.
- Installer backup reg key: `HKLM\SOFTWARE\DLP\Backup\AppInit_DLLs` stores the original value before modification.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Architecture
- `.planning/REQUIREMENTS.md` §"Universal hook DLL + expanded surface (BLOCK)" — BLOCK-05, BLOCK-06, BLOCK-07 requirements
- `.planning/ROADMAP.md` §"Phase 49: Universal Injection — ETW Process Watcher + Allowlist + AppInit Fallback" — phase goal and success criteria
- `.planning/PROJECT.md` §"Current Milestone: v0.10.0 Real-Time File Access Prevention" — milestone context

### Existing Code Patterns
- `dlp-agent/src/hook_injector.rs` — `HookInjector` with `CreateRemoteThread + LoadLibraryW`. **MUST reuse** for universal injection.
- `dlp-agent/src/service.rs` — Agent service lifecycle; startup sweep hooks in here.
- `dlp-agent/src/engine_client.rs` — Agent config polling from server (TOML hot-reload pattern).
- `dlp-server/src/policy_sync.rs` — Server-side config generation and sync cadence.
- `dlp-server/src/admin_api.rs` — Admin API router pattern for new `/admin/allowlist` endpoints.
- `dlp-common/src/classification.rs` — Shared types for cross-crate contracts.
- `dlp-admin-cli/src/screens/dispatch.rs` — TUI screen dispatch pattern.

### Related Docs
- `docs/architecture.md` §"Windows split-session pattern" — explains SYSTEM service vs user-session UI separation relevant to injection targets.
- `.planning/codebase/ARCHITECTURE.md` — overall architecture and crate boundaries.
- `.planning/codebase/STRUCTURE.md` — file organization and integration points.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`HookInjector`** (`dlp-agent/src/hook_injector.rs`): `CreateRemoteThread + LoadLibraryW` injection with architecture detection (`IsWow64Process`), x64/x86 DLL dispatch, and comprehensive error types. Reuse directly; no rewrite needed.
- **Agent config polling** (`dlp-agent/src/engine_client.rs`): TOML config fetched from server every 30 s, persisted locally, hash-based reload detection. Extend with `[universal_injection.allowlist]` section.
- **`AppState { pool, policy_store, siem, alert, ad }`** (`dlp-server/src/lib.rs`): Shared state pattern. Add `process_registry: Arc<DashMap<u32, ProcessState>>` to agent-side `AppState` equivalent.

### Established Patterns
- **Repository pattern**: Stateless struct with `pool` parameter for DB access.
- **Admin API CRUD**: `list` (GET), `get_by_id` (GET), `create` (POST), `update` (PUT), `delete` (DELETE) for config tables.
- **TOML config section**: Hierarchical TOML sections with serde derive (existing pattern for agent config).
- **SIEM audit events**: `siem_connector::relay(audit_event)` for structured audit logging.

### Integration Points
- `dlp-agent/src/service.rs` — add `ProcessWatcher` initialization and startup `EnumProcesses` sweep.
- `dlp-agent/src/lib.rs` — add `process_watcher.rs`, `universal_injector.rs`, `process_registry.rs` modules.
- `dlp-server/src/admin_api.rs` — add `/admin/allowlist` routes for CRUD.
- `dlp-server/src/db/mod.rs` — add `allowlist_entries` table to `init_tables()`.
- `dlp-admin-cli/src/app.rs` — add `Screen::AllowlistConfig` following existing screen patterns.
- `installer/build.ps1` or WiX — add AppInit_DLLs registry key setup and backup.

</code_context>

<specifics>
## Specific Ideas

- The `ProcessState` enum should include `Skipped(AllowlistReason)` where `AllowlistReason` is `Self | AVEDR | SystemCritical | PPL | WoW64 | OperatorDefined` so telemetry shows exact skip counts per category.
- The `siem.injection_telemetry` event should include a `coverage_percent` field computed as `injected / (injected + skipped_non_ppl + failed)` to give operators a real-time coverage metric.
- The installer should write the original AppInit_DLLs value to `HKLM\SOFTWARE\DLP\Backup\AppInit_DLLs` before modifying it, and restore from this key on uninstall.
- The `EnumProcesses` startup sweep should skip processes with `SESSIONID=0` that are not the DLP agent itself — SYSTEM services generally don't need hooking (they don't access user files).
</specifics>

<deferred>
## Deferred Ideas

- ntdll syscall-stub patching (Phase 51 — BLOCK-08, BLOCK-09)
- Shared-memory classification cache (Phase 50 — CACHE-01..06, FAIL-01..03)
- Deployment guide with per-vendor AV/EDR allowlist procedures (Phase 57 — OPS-01..04)
- Monitor-only / audit-only per-policy mode (Phase 55 — MODE-01)
- Admin TUI Protected Paths screen (Phase 54 — UX-01)
- Admin TUI Bypass Alerts screen (Phase 54 — UX-02)
- SD/optical/virtual drive enumeration (Phase 56 — DRIVE-01..04)
- DACL tripwire (Phase 52 — DACL-01..05)
- ETW Kernel-File consumer for bypass detection (Phase 53 — ETW-01..05)

</deferred>

---

*Phase: 49-universal-injection-etw-process-watcher-allowlist-appinit-fa*
*Context gathered: 2026-05-19*
