# Phase 49: Universal Injection — ETW Process Watcher + Allowlist + AppInit Fallback - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-19
**Phase:** 49-universal-injection-etw-process-watcher-allowlist-appinit-fa
**Areas discussed:** Allowlist hot-reload, ETW consumer architecture, Process lifecycle tracking, Injection failure handling, AppInit registration, Secure Boot detection, PPL detection timing, Agent restart state

---

## Allowlist hot-reload

| Option | Description | Selected |
|--------|-------------|----------|
| Extend existing policy sync | Add allowlist to agent-config TOML that agent polls every 30s. Reuses v0.2.0+ infrastructure. | ✓ |
| Dedicated API endpoint + push | Agent exposes local HTTP API; server pushes updates immediately. Lower latency but new code path. | |
| SQLite table + pull | Agent stores allowlist in local SQLite; server writes to shared DB. Overkill for this data. | |

**User's choice:** "your recommendations" (deferred to Claude)
**Notes:** User deferred on both questions in this area. Claude recommended extending the existing TOML poll and using both path-prefix + cert-subject matching.

---

## ETW consumer architecture

| Option | Description | Selected |
|--------|-------------|----------|
| Dedicated OS thread | Spawn std::thread for ProcessTrace; push via crossbeam channel to tokio task. Keeps blocking ETW off tokio runtime. | ✓ |
| tokio::task::spawn_blocking | Wrap blocking ProcessTrace in spawn_blocking. Simpler but risks saturating blocking pool. | |
| You decide | Claude decides based on codebase patterns | |

**User's choice:** "You decide" (deferred to Claude)
**Notes:** User deferred. Claude recommended dedicated OS thread + crossbeam channel, 256KB×200 buffers, event loss logged as warn! only, WMI Win32_ProcessStartTrace as secondary backstop.

---

## Process lifecycle tracking

| Option | Description | Selected |
|--------|-------------|----------|
| Injected-PID DashMap only | Simple DashMap<u32, InjectionRecord>; periodic sweep cleanup. Minimal state. | |
| Full state machine | DashMap<u32, ProcessState> with states: Discovered → Skipped → Injected → Exited. More telemetry-friendly. | ✓ |
| You decide | Claude decides based on success criteria | |

**User's choice:** "You decide" (deferred to Claude)
**Notes:** User deferred. Claude recommended full state machine for coverage telemetry, ETW Event ID 2 for exit cleanup, 60s sweep backstop, duplicate injection guard, and startup EnumProcesses sweep targeting 5s.

---

## Injection failure handling

| Option | Description | Selected |
|--------|-------------|----------|
| One-shot with logging | Try once; log error and move on. 5-minute periodic sweep retries naturally. | |
| Immediate retry (1x) | Retry once with 50ms delay. Handles transient initialization races. | ✓ |
| You decide | Claude decides based on codebase patterns | |

**User's choice:** "You decide" (deferred to Claude)
**Notes:** User deferred. Claude recommended one immediate retry after 50ms, categorized logging (warn! for expected AccessDenied, error!+SIEM for unexpected), 5-minute periodic backstop sweep, and per-minute telemetry counters.

---

## AppInit registration

**User's choice:** "Yes, lock all four" (batch confirmation of all remaining areas)
**Notes:** Installer sets AppInit_DLLs registry keys at install time. Agent reads-only at boot. Uninstaller restores from backup reg key. Agent does not modify AppInit at runtime.

---

## Secure Boot detection

**User's choice:** "Yes, lock all four" (batch confirmation)
**Notes:** Agent calls `GetFirmwareEnvironmentVariable("SecureBoot", ...)` at boot. If enabled, emit one `siem.appinit_dlls_disabled` audit event and skip AppInit. If API unavailable (pre-UEFI), treat as unknown and proceed with AppInit.

---

## PPL detection timing

**User's choice:** "Yes, lock all four" (batch confirmation)
**Notes:** PPL detected at injection time via `OpenProcess` + `GetProcessMitigationPolicy(ProcessSignaturePolicy)`, not at process creation. Avoids stale PPL state. `Skipped(PPL)` recorded in DashMap.

---

## Agent restart state

**User's choice:** "Yes, lock all four" (batch confirmation)
**Notes:** Process map is NOT persisted across restarts. Agent clears DashMap and runs full EnumProcesses sweep on startup. Simpler and handles processes that exited while agent was down.

---

## Claude's Discretion

All eight gray areas were discussed. The user deferred to Claude's judgment on every decision ("your recommendations", "You decide", "Yes, lock all four"). Claude exercised discretion on:

- Allowlist delivery mechanism (TOML poll vs. API vs. SQLite)
- Allowlist matching strategy (path prefix vs. cert subject vs. both)
- ETW threading model (dedicated thread vs. spawn_blocking)
- Buffer sizing, event loss handling, WMI backstop
- Process tracking granularity (DashMap only vs. full state machine)
- Cleanup strategy (ETW exit event + periodic sweep)
- Injection retry policy (one-shot vs. immediate retry)
- Failure categorization and telemetry
- AppInit registration ownership (installer vs. agent)
- Secure Boot detection API
- PPL detection timing (creation vs. injection time)
- Agent restart persistence model

## Deferred Ideas

- ntdll syscall-stub patching (Phase 51)
- Shared-memory classification cache (Phase 50)
- Deployment guide with per-vendor AV/EDR procedures (Phase 57)
- Monitor-only / audit-only per-policy mode (Phase 55)
- Admin TUI Protected Paths and Bypass Alerts screens (Phase 54)
- SD/optical/virtual drive enumeration (Phase 56)
- DACL tripwire (Phase 52)
- ETW Kernel-File consumer for bypass detection (Phase 53)
