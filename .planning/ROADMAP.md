---
milestone: v0.11.0
milestone_name: Label Service + Workflow + Audit
last_updated: 2026-06-09
total_phases: 6
v1_requirements: 26
coverage: 26/26
granularity: standard
prerequisite_phases:

  - 59   # Label Service foundation — shipped 2026-05-12

---

# Roadmap: DLP-RUST

Phase numbering is continuous across milestones — it never restarts. Phases 0.1–46 cover v0.2.0 through v0.9.0; Phase 47 (Secrets Encryption at Rest, HARD-01) shipped 2026-05-11. **The v1.0.0 Enterprise Hardening milestone was abandoned 2026-05-12; HARD-02..08 were dropped (see PROJECT.md).** v0.10.0 Real-Time File Access Prevention is the new active milestone and starts at **Phase 48** with no gaps.

## Milestones

- v0.2.0 Feature Completion — Phases 0.1–12 (shipped 2026-04-13)
- v0.3.0 Operational Hardening — Phases 7–11 (shipped 2026-04-16)
- v0.4.0 Policy Authoring — Phases 13–17 (shipped 2026-04-20)
- v0.5.0 Boolean Logic — Phases 18–21 (shipped 2026-04-21)
- v0.6.0 Endpoint Hardening — Phases 22–30 (shipped 2026-04-29)
- v0.7.0 Disk Exfiltration Prevention — Phases 33–38.2 (shipped 2026-05-06)
- v0.7.1 Operational Hardening — Phases 38.3–38.6 (shipped 2026-05-06)
- v0.8.0 Application-Aware DLP — Phases 39–42 (shipped 2026-05-07)
- v0.8.1 Deferred Items & Issue Debt — Phases 43–46 (shipped 2026-05-08)
- v0.9.0 Cloud & Print Exfiltration Prevention — M017 / pre-Phase 47 (shipped 2026-05-09)
- ~~v1.0.0 Enterprise Hardening & Scale — abandoned 2026-05-12; only Phase 47 (HARD-01) shipped~~
- **v0.10.0 Real-Time File Access Prevention — Phases 47 (prerequisite) + 48–56 (complete) + 57–58 (active)**
- ✅ **v0.11.0 Label Service + Workflow + Syslog + Hash + Device — Phases 59–64 (shipped 2026-06-09)**

---

## Active Milestone — v0.10.0 Real-Time File Access Prevention

### Milestone Goal

Convert general file I/O from a passive audit-trail-after-the-fact into active real-time blocking at the moment of access. The architecture stacks four user-mode enforcement layers on the v0.9.0 baseline:

1. **Universal hook DLL** — extends the proven v0.9.0 `dlp-hook-dll` cloud-sync IAT pattern to every user process.
2. **ntdll syscall-stub trampoline** — closes the direct-syscall bypass that v0.9.0's IAT-only hooks leave open.
3. **NTFS DACL deny-ACE tripwire** — kernel-enforced backstop on T3/T4 root paths that holds even when the hook is unloaded or crashes.
4. **ETW Kernel-File consumer** — bypass detection feeding a new admin TUI Bypass Alerts screen, SIEM, and the alert router.

**Architecture commitments (reaffirmed):** NO kernel driver, NO minifilter, NO EV cert.

### Prerequisite — Phase 47 (carried forward, already shipped)

Phase 47 (Secrets Encryption at Rest, HARD-01) shipped 2026-05-11 under the abandoned v1.0.0 milestone. v1.0.0 was dropped 2026-05-12 and v0.10.0 became active; HARD-01 carries forward as a validated prerequisite. **No re-planning of Phase 47** — it is referenced here only so the requirement-to-phase trace remains intact and so v0.10.0's continuous numbering starts cleanly at Phase 48.

| Phase | Goal | Requirements | Status |
|-------|------|--------------|--------|
| 47 | 1/1 | Complete    | 2026-06-21 |

The DPAPI master-key recovery handoff originally slated for v1.0.0 Phase 52 is folded into v0.10.0 **Phase 52** (DACL-05) as `docs/operations/dpapi-recovery.md`.

## Phases (v0.10.0 active phases)

- [x] **Phase 48: Hook DLL Surface Expansion + Crash Hardening + Build Harness** — extend and harden the v0.9.0 hook into a single unified DLL with the full file-I/O surface, x86 sibling, and Authenticode signing pipeline. (completed 2026-05-15)
- [x] **Phase 49: Universal Injection — ETW Process Watcher + Allowlist + AppInit Fallback** — drive the wider hook surface into every non-allowlisted user process via ETW Kernel-Process and `CreateRemoteThread`. (completed 2026-05-19)
- [x] **Phase 50: Shared-Memory Classification Cache + Fail-Mode State Machine** — give the hook DLL a survivable sub-50µs hot path and a tier-gated asymmetric fail policy. (completed 2026-05-20)
- [x] **Phase 51: ntdll Syscall-Stub Trampolines + EDR Coexistence** — close the direct-syscall bypass behind a default-off feature flag with detect-before-patch EDR safety. (completed 2026-05-22)
- [x] **Phase 52: DACL Tripwire + Repair Watcher + Protected Paths + DPAPI Recovery Doc** — kernel-enforced NTFS backstop for T3/T4 roots, plus the carried-forward DPAPI recovery runbook. (completed 2026-05-27)
- [x] **Phase 53: ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring** — turn hook-vs-ETW divergence into auditable BypassAlert events routed through SIEM and the alert router. (completed 2026-05-28)
- [x] **Phase 54: Admin TUI Protected Paths + Bypass Alerts Screens** — operator UX for the two new server surfaces. (completed 2026-05-28)
- [x] **Phase 55: Monitor-Only / Audit-Only Per-Policy Enforcement Mode** — safe-rollout mode every industry DLP requires before production deployment. (completed 2026-05-29)
- [x] **Phase 55.1: Close gap MODE-01 — read global_enforcement_mode in BypassCorrelator (INSERTED)** — urgent gap closure. (completed 2026-06-20)
- [x] **Phase 56: SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004)** — fold SEED-004 in: device enumeration, two new ABAC attributes, admin TUI extension. (completed 2026-06-06)
- [x] **Phase 57: Operational Deployment Guide + AV/EDR Allowlist + UAT** — the milestone ship gate; per-vendor allowlist procedures, hash publishing, and real-Windows UAT (folds in former HARD-05). (completed 2026-06-10)
- [x] **Phase 58: Differentiators Bundle (cuttable to v0.10.1 if scope pressure hits)** — cuttable as a unit to v0.10.1 if scope pressure hits; otherwise materially improves deployability. (completed 2026-06-09)
- [x] **Phase 58.1: Close v0.10.0 ship-gap verification items (INSERTED)** — fix ETW journal writes in hook DLL trampolines, verify BypassCorrelator::run() consumes bypass_rx, execute OPS-04 UAT on physical Windows 11 hardware, and create missing VERIFICATION.md files. (completed 2026-06-23)
- [x] **Phase 58.2: Fix double HookIpcServer and wire volume classes (INSERTED)** — eliminate duplicate hook IPC server initialization and complete volume-class attribute wiring through the ABAC enforcement path. (Plan 01 complete 2026-06-24; Plans 02-03 pending)
- [ ] **Phase 58.3: Close gap: OPS-04 — execute physical Windows 11 UAT (INSERTED)** — execute the v0.10.0 UAT plan on physical Windows 11 hardware and record actual results in `.planning/milestones/v0.10.0-UAT.md`.
- [x] **Phase 58.4: Close gap: DIFF-02/03/04 — wire differentiators into hook DLL deny paths (INSERTED)** — invoke diagnostic snapshot capture, content SHA-256 hashing, and health snapshot ingestion from the hook DLL deny paths. (completed 2026-06-29)
- [x] **Phase 58.5: Unhook dlp_hook_dll.dll when dlp-agent is killed/exited (INSERTED)** — TBD. (not started) (completed 2026-07-02)
- [ ] **Phase 58.6: Targeted hook injection — only processes that perform file operations (INSERTED)** — investigate and implement selective hook injection based on process file-operation behavior instead of universal injection.

---

## Phase Details

### Phase 48: Hook DLL Surface Expansion + Crash Hardening + Build Harness

**Goal**: A unified, crash-hardened, dual-arch hook DLL exposes the full file-I/O API surface and ships through a signed release pipeline, ready for universal injection in Phase 49.
**Depends on**: Phase 47 (prerequisite — secrets at rest; agent reads encrypted SMTP/SIEM/JWT/LDAP creds in any new admin endpoint added here)
**Requirements**: BLOCK-01, BLOCK-02, BLOCK-03, BLOCK-04, BLOCK-10
**Success Criteria** (what must be TRUE):

  1. A user process loaded with the unified hook DLL can no longer rename, copy, move, delete, or replace a T3/T4-classified file out of policy via any of `WriteFile`/`WriteFileEx`/`MoveFileExW`/`CopyFileExW`/`CopyFile2`/`DeleteFileW`/`ReplaceFileW`/`SetFileInformationByHandle`/`NtOpenFile`/`NtWriteFile`/`NtSetInformationFile`, and the original-call fail-closed return value (`BOOL(0)` / `INVALID_HANDLE_VALUE` / `STATUS_ACCESS_DENIED`) is visible to the host.
  2. A panic or access-violation injected inside any patched stub leaves the host process running (`catch_unwind` + SEH translation routes through to the original API as fail-OPEN); no `WerFault` event log entry naming `dlp_hook_dll.dll` appears under the chaos-test fixture.
  3. All v0.9.0 cloud-sync regression tests in `dlp-e2e/` pass green-bar against the unified DLL — there is no second `dlp-cloud-hook.dll` shipped or loaded.
  4. The CI matrix produces both `dlp_hook_dll.dll` (x64) and `dlp_hook_dll_x86.dll` (i686-pc-windows-msvc) on every release tag; the injector dispatches to the matching DLL based on `IsWow64Process`.
  5. Every shipped binary (`dlp-agent.exe`, `dlp-user-ui.exe`, `dlp-admin-cli.exe`, `dlp-server.exe`, both hook DLLs) is Authenticode-signed with RFC-3161 timestamping; `signtool verify /pa` returns clean.

**Plans:** 5/5 plans complete

- [ ] `48-01-PLAN.md` — Crash Hardening: catch_unwind, SEH wrappers, fail-closed macro, thread-local buffers
- [ ] `48-02-PLAN.md` — Expanded Hook Surface: 12 trampolines, PE utils with cfg(target_arch), HandleHookRequest
- [ ] `48-03-PLAN.md` — Unified DLL Integration: HookDescriptor table, 32K cap, classify_handle, lib.rs refactor
- [ ] `48-04-PLAN.md` — x86 Sibling + CI Matrix: service.rs x86 path, i686 target build, x86 offset verification
- [ ] `48-05-PLAN.md` — Authenticode Signing Pipeline: release.yml with signtool, WiX installer update

### Phase 49: Universal Injection — ETW Process Watcher + Allowlist + AppInit Fallback

**Goal**: Every non-allowlisted user-mode process — both already-running and newly-spawned — receives the unified hook DLL within 500 ms of process start, with documented coverage gaps for PPL and Secure Boot.
**Depends on**: Phase 48
**Requirements**: BLOCK-05, BLOCK-06, BLOCK-07
**Success Criteria** (what must be TRUE):

  1. A new user process spawned on the test endpoint emits a hook-DLL "hello" pipe message to the agent within 500 ms of `ProcessStart`; coverage telemetry shows >= 99% of non-allowlisted PIDs report in within that window.
  2. AV/EDR processes (signer-cert match against the top-10 vendor list — CrowdStrike, SentinelOne, Defender, Carbon Black, Sophos, Trend Micro, Cylance, ESET, Bitdefender, McAfee), system-critical processes (PIDs 0/4, csrss/smss/wininit/services/lsass/fontdrvhost/dwm), self processes (DLP binaries), and PPL-detected processes are visibly skipped in the injection log; the operator can extend the AV/EDR list via admin TUI without an agent restart.
  3. On a Secure Boot endpoint, the agent emits exactly one `siem.appinit_dlls_disabled` audit event at boot, and the deployment guide is wired to surface AppInit_DLLs as inert under Secure Boot.
  4. WoW64 32-bit processes are injected with `dlp_hook_dll_x86.dll` (verified via `Process Hacker` module list); pure-x64 processes are injected with the x64 DLL.
  5. On agent restart, the startup `EnumProcesses` sweep injects into all already-running non-allowlisted processes within 5 s; no process requires a logout/reboot to gain coverage.

**Plans:** 5/5 plans complete

Plans:

- [ ] `49-01-PLAN.md` — Agent Core Modules: process_registry.rs + allowlist.rs + appinit.rs + lib.rs mods + Cargo.toml deps
- [ ] `49-02-PLAN.md` — Server-Side Allowlist: SQLite table + AllowlistRepository + /admin/allowlist CRUD API
- [ ] `49-03-PLAN.md` — ETW Watcher + Universal Injector: process_watcher.rs + universal_injector.rs + service.rs integration
- [ ] `49-04-PLAN.md` — Config Wiring + Admin TUI: AgentConfig extension + server_client payload + allowlist screen
- [ ] `49-05-PLAN.md` — Telemetry + Installer + Tests: periodic tasks + AppInit_DLLs setup + full workspace test suite

### Phase 50: Shared-Memory Classification Cache + Fail-Mode State Machine

**Goal**: The hook DLL completes a per-file decision in <= 50 us p95 on cache hit and gracefully degrades through HEALTHY → DEGRADED → ISOLATED → RESYNC when the agent pipe is unreachable, with tier-gated fail-closed/fail-open behaviour.
**Depends on**: Phase 49
**Requirements**: CACHE-01, CACHE-02, CACHE-03, CACHE-04, CACHE-05, CACHE-06, FAIL-01, FAIL-02, FAIL-03
**Success Criteria** (what must be TRUE):

  1. A `cargo build --workspace --release` workload on the test endpoint completes within 25% wall-clock overhead of the same build with hooks disabled (CRIT-04 benchmark gate); hot-path p95 latency on cache hit measures <= 50 us via in-DLL `QueryPerformanceCounter` telemetry.
  2. Every hooked process maps `Global\DlpClassificationCache` read-only after self-allowlist clears; a server-side classification policy edit produces a `HookMessage::CacheDelta` push that flips the global atomic version word and is observable in the next DLL round-trip's `cache_version` field.
  3. With the agent service stopped, the hook denies (`ERROR_ACCESS_DENIED` / `STATUS_ACCESS_DENIED`) every write attempt against a T3 or T4 path and allows every write against a T1 or T2 path; the fail-state telemetry shows the DLL transitioning HEALTHY → DEGRADED → ISOLATED.
  4. Build-tool processes (devenv.exe, cargo.exe, msbuild.exe, rustc.exe, link.exe, gcc.exe) and trusted system paths (System32, WinSxS, WindowsApps, Program Files\Common Files) bypass the pipe entirely on the operator-extendable allowlist; the per-tier staleness budgets (T4=30s, T3=60s, T2=5min, T1=30min) are observable in audit events.
  5. After agent restart with a higher `cache_version`, every connected hook DLL transitions ISOLATED → RESYNC → HEALTHY within 1 s without losing any in-flight decision.

**Plans:** 6/6 plans complete

Plans:

- [ ] `50-01-PLAN.md` — IPC Protocol Extension: HookRequest/HookResponse with cache_version, cache_hint, HookOp
- [ ] `50-02-PLAN.md` — Agent Classification Cache Manager: shared-memory creation, double-buffered atomic flip, CachePusher
- [ ] `50-03-PLAN.md` — Hook DLL Cache Lookup Module: shared-memory reader, two-tier lookup, thread-local LRU, trampoline integration
- [ ] `50-04-PLAN.md` — Hook DLL Fail-Mode State Machine: HEALTHY/DEGRADED/ISOLATED/RESYNC transitions, background thread
- [ ] `50-05-PLAN.md` — Hook DLL Allowlist + Telemetry: trusted paths, build tools, operator extensions, QPC histogram
- [ ] `50-06-PLAN.md` — IPC Integration + Benchmarks: agent handler cache_version awareness, cache hint warming, p95 benchmark

### Phase 50.1: Close gap FAIL-01/02/03 — verify ISOLATED->RESYNC->HEALTHY recovery at runtime (INSERTED)

**Goal:** [Urgent work - to be planned]
**Requirements**: TBD
**Depends on:** Phase 50
**Plans:** 1/1 plans complete

Plans:

- [x] 50.1-01-PLAN.md

- [ ] TBD (run `/gsd-plan-phase 50.1` to break down)

### Phase 51: ntdll Syscall-Stub Trampolines + EDR Coexistence

**Goal**: Direct-syscall bypass of the IAT hook layer is closed for `NtCreateFile`/`NtOpenFile`/`NtWriteFile`/`NtSetInformationFile`, behind a feature flag that is safe to enable per-customer because EDR coexistence is detected before patching and never falsely "cleaned."
**Depends on**: Phase 50
**Requirements**: BLOCK-08, BLOCK-09
**Success Criteria** (what must be TRUE):

  1. With `enable_ntdll_patching = true`, a Go binary or hand-rolled direct-syscall test (e.g. `syswhispers`-style) attempting to write a T4 file is denied with `STATUS_ACCESS_DENIED` and audit-logged with `hook_function = NtWriteFile`.
  2. On an endpoint where any supported EDR (CrowdStrike, SentinelOne, Defender for Endpoint, Carbon Black) is detected, the patcher reads the syscall-stub prologue, detects `0xE9` jump bytes, walks the JMP target into the EDR module range, and skips patching for that stub — never restoring "clean" ntdll bytes from disk (DoppelGate evasion-malware classifier risk).
  3. The 30-second re-verification thread emits `BypassAlert(reason=HookOverwritten)` within one verification cycle when an EDR re-patches over our trampoline; the alert reaches the admin TUI Bypass Alerts feed (Phase 53/54).
  4. The patcher's suspend-all-other-threads protocol blocks if any thread RIP lands in `[stub, stub+5]`; under the chaos-test fixture (1000 threads spinning on `NtCreateFile`), no torn-instruction crash is observed across 100 patch cycles.
  5. The `enable_ntdll_patching` policy flag defaults off; per-customer rollout is auditable via SIEM (`siem.ntdll_patching_enabled` event at boot).

**Plans:** 6/6 plans complete

Plans:

- [x] `51-01-PLAN.md` — EDR Detection + Thread Safety: edr_detector.rs + thread_suspender.rs + lib.rs mods
- [x] `51-02-PLAN.md` — Ntdll Patcher Core: retour dependency + HookDescriptor extension + ntdll_patcher.rs with per-stub state machine
- [x] `51-03-PLAN.md` — Ntdll Trampoline Bodies: NtdllTrampolineNtCreateFile/NtOpenFile/NtWriteFile/NtSetInformationFile with guard_trampoline pattern
- [x] `51-04-PLAN.md` — Background Thread Extension: 30-second trampoline re-verification + StubIntegrity checks + BypassAlert emission
- [x] `51-05-PLAN.md` — Agent Config + SIEM Events: enable_ntdll_patching flag + BypassAlert/BypassReason types + NtdllPatchingEnabled audit events
- [ ] `51-06-PLAN.md` — Integration + Chaos Test: lazy OnceLock init (NOT from DllMain) + global patcher wiring + 1000-thread chaos fixture

### Phase 52: DACL Tripwire + Repair Watcher + Protected Paths + DPAPI Recovery Doc

**Goal**: T3/T4 root paths carry an explicit, canonically-ordered NTFS Deny ACE that survives operator and adversary tampering, with a repair watcher that distinguishes operator-staged removals from out-of-band tampering. The DPAPI master-key recovery runbook (carried forward from v1.0.0) ships alongside.
**Depends on**: Phase 47 (DPAPI envelope from HARD-01); independent of the BLOCK chain — can land in parallel from Phase 50 onwards
**Requirements**: DACL-01, DACL-02, DACL-03, DACL-04, DACL-05
**Success Criteria** (what must be TRUE):

  1. With the agent stopped and the hook DLL absent, an Authenticated Users-context process attempting to write, append, delete, or chmod a T3 or T4 path under a registered Protected Path receives `ERROR_ACCESS_DENIED` from the NTFS kernel itself; SYSTEM and the DLP-Admin AD group remain unaffected.
  2. An out-of-band `icacls /reset` against a Protected Path triggers a tamper-event audit within 60 s (combination of `ReadDirectoryChangesW(FILE_NOTIFY_CHANGE_SECURITY)` and the 60-s polling backstop) and the watcher restores the canonical ACE order via subtree-walk replace-not-append.
  3. Operator-initiated removal via the Phase 54 admin TUI flows through the two-phase staged update (server `protected_paths_pending_change` → agent stages diff → ACE event arrives) and produces NO spurious tamper alert.
  4. The admin API exposes `GET`/`POST`/`PUT`/`DELETE /admin/protected-paths/:id`; the agent pulls protected-path config via `policy_sync` cadence and stores it in the new `protected_paths` + `protected_path_aces` SQLite tables (with foreign keys); 60 KB ACL size guard rejects oversize ACL writes with a clear operator error.
  5. `docs/operations/dpapi-recovery.md` exists and documents both the `re-init-from-env-vars` and `restore-from-backup` flows when DPAPI unprotect fails on agent restart, with a UAT verification that an operator can recover a corrupted DPAPI master key without manual SQL.

**Plans:** 7/7 plans planned (revised 2026-05-27 incorporating cross-AI review feedback)

**Wave 1** *(no dependencies)*

- [x] `52-01-PLAN.md` — DACL Tripwire Writer: raw ACL construction, explicit canonical algorithm (DLP Deny first, SYSTEM/DLP-Admin Allows, preserved non-DLP ACEs, inherited), SDDL snapshot, 60 KB guard on ALL write paths, access-control proof matrix, fail-closed 10K limit *(completed 2026-05-27)*
- [x] `52-03-PLAN.md` — Protected Paths Server-Side Schema: SQLite schema with UNIQUE path, repository with conflict-aware sync_from_labels (manual entries preserved, tier-upgraded on conflict) *(completed 2026-05-27)*

**Wave 2** *(blocked on Wave 1 completion)*

- [x] `52-02-PLAN.md` — DACL Repair Watcher: ReadDirectoryChangesW per-path with bWatchSubtree=true, crossbeam channel, debounced repair (500ms-2s), 60s polling backstop with FULL subtree walk, DaclTamperDetected audit with triggers_alert=true *(completed 2026-05-27)*
- [x] `52-04-PLAN.md` — Two-Phase Staged Updates Data Layer: agent SQLite staging table, explicit StagingState enum (STAGED -> WATCHER_SUPPRESSED -> ACL_REMOVED -> APPLIED -> GC), per-path locking via DashMap<PathBuf, Mutex<()>>, adaptive GC *(completed 2026-05-27)*
- [x] `52-06-PLAN.md` — Protected Paths Admin API + Config Sync: CRUD routes with Windows API path validation (GetFullPathNameW, rejects UNC/extended-length/volume GUID/8.3), AgentConfigPayload extension, AppState wiring *(completed 2026-05-27)*

**Wave 3** *(blocked on Waves 1-2 completion)*

- [x] `52-07-PLAN.md` — Staged Update Integration: config diff in apply_payload_to_config with per-path lock coordination, staging-aware tamper suppression with state machine crash recovery, removal application task, expired-staging tamper alert negative case *(completed 2026-05-27)*
- [x] `52-05-PLAN.md` — DPAPI Recovery Doc + Final Integration: runbook verified against Phase 47 env vars/service names, negative UAT cases (expired staging alert, partial apply rejection, junction skip), full audit wiring verification, workspace test suite *(completed 2026-05-27)*

**Cross-cutting constraints:**

- All audit events (`DaclTripwireTooLarge`, `DaclTamperDetected`) wired through `routed_to_siem()` with correct `triggers_alert()` semantics in Plans 01 and 02 (not deferred)
- Per-path locking (`DashMap<PathBuf, Mutex<()>>`) serializes all concurrent operations on the same path across Plans 04 and 07
- Windows API canonicalization (`GetFullPathNameW`) replaces regex validation in Plans 01 and 06

### Phase 53: ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring

**Goal**: Every file operation that ETW Kernel-File records but the hook DLL never journaled is correlated within +/-5 ms QPC and surfaced as a BypassAlert through SIEM, the alert router, and a server endpoint feeding the Phase 54 admin TUI.
**Depends on**: Phases 50 (journal must exist) and 51 (ntdll patching must produce operations to correlate)
**Requirements**: ETW-01, ETW-02, ETW-03, ETW-04, ETW-05
**Success Criteria** (what must be TRUE):

  1. With the hook DLL deliberately uninstalled from a test process, every CREATE/WRITE/DELETE_PATH against a registered Protected Path produces a `BypassAlert{correlation_reason=NoHookJournal}` row in the `bypass_alerts` table within 5 s of the operation.
  2. The ETW consumer runs with 256 KB x 200 buffers and the consumer-side System32/WinSxS filter; under a 10 000-events/sec stress fixture, the agent reports zero `Microsoft-Windows-Kernel-EventTracing/Admin` Event ID 2 (lost-events) entries.
  3. Each hook DLL writes a ring entry `(seq, file_object, op, path_hash, ts_qpc)` to its per-process `Global\DlpHookJournal_<pid>` BEFORE returning a decision, so denials are also journaled and not falsely flagged as bypasses.
  4. Allowlisted PIDs (AV/EDR, self, system-critical, PPL) are dropped pre-correlation; the bypass-alerts feed contains zero entries from Defender/CrowdStrike/SentinelOne in the soak-test fixture.
  5. `POST /audit/bypass` ingests agent-emitted bypass alerts; alerts route through `siem_connector::relay` and (when `severity >= ALERT`) `alert_router::send` with no new outbound transport added; `GET /admin/bypass-alerts?since=&severity=` and `POST /admin/bypass-alerts/:id/ack` round-trip cleanly.

**Plans:** 7/7 plans planned (revised 2026-05-28)

**Wave 1** *(no dependencies)*

- [ ] `53-01-PLAN.md` — ETW Kernel-File Consumer: ferrisetw 1.2.0 integration, 256KB x 200 buffers, CREATE/WRITE/DELETE_PATH parsing, System32/WinSxS filter, `EventType::EtwConsumerGatedOff` distinct from Stopped (CR-09), `EtwFileEvent.nt_path_converted` flag (WR-11), 19 unit tests
- [ ] `53-02-PLAN.md` — Hook DLL Journal Ring Buffer: per-process `GlobalDlpHookJournal_<pid>` shared memory (64 KiB), 56-byte `JournalEntry` with seq/file_object/op/path_hash/ts_qpc, Release fence (CR-03), ERROR_ALREADY_EXISTS handling (CR-04)
- [ ] `53-03-PLAN.md` — Shared Path Normalization in dlp-common: extracted `normalize_path` + `fnv1a_64` from classification_cache.rs, `nt_path_to_dos_path()` for ETW FileName conversion (WR-09), 21 unit tests, zero hash-mismatch risk between DLL and correlator

**Wave 2** *(blocked on Wave 1 completion)*

- [ ] `53-04-PLAN.md` — Bypass Correlator: on-demand journal discovery + exponential backoff, +/-5ms QPC tolerance, path-hash exact match, allowlist pre-filter (Defender/CrowdStrike), explicit `file_object` wiring from ETW event (CR-08), NEW `batch_id` per retry (WR-10), skip unconverted NT paths (WR-11), `#[serde(default)]` on all new fields (WR-12), 26 unit tests

**Wave 3** *(blocked on Wave 2 completion)*

- [x] `53-05-PLAN.md` — Server-Side Bypass Alert Storage: `bypass_alerts` SQLite schema with `file_object INTEGER NOT NULL DEFAULT 0` (WR-12), `POST /audit/bypass` batch ingest (max 100, JWT-validated agent_id), v1+v2 deserialization with `#[serde(default)]`, `GET /admin/bypass-alerts` paginated filtered, `POST /admin/bypass-alerts/:id/ack` idempotent, 14 integration tests *(completed 2026-05-28)*

**Wave 4** *(blocked on Wave 3 completion)*

- [ ] `53-06-PLAN.md` — SIEM + Alert Router Wiring: `BypassAlertDetected` routes through `routed_to_siem()` and `triggers_alert()`, `EtwConsumerGatedOff` routes to SIEM only (CR-09), crit severity triggers alert_router::send, warn/info routes to SIEM only, 8 end-to-end integration tests including file_object E2E (CR-08) and v1 backward compat (WR-12)

**Cross-cutting constraints:**

- CR-08: `file_object` explicitly wired from ETW event through correlator to DB to SIEM payload — verified by dedicated test with 0xDEADBEEF mock value
- CR-09: `EtwConsumerGatedOff` is a distinct event type from `EtwConsumerStopped`; gated-off path emits GatedOff (not Stopped); re-enable emits Started (no backwards Stopped)
- WR-10: Failed batch retry generates NEW `batch_id` (UUID v4) per attempt; server dedup never blocks legitimate retries
- WR-11: `EtwFileEvent.nt_path_converted: bool` field; correlator skips events where conversion failed with `tracing::warn!`
- WR-12: ALL new `BypassAlert` fields have `#[serde(default)]`; DB schema has `DEFAULT 0` for `file_object`; v1 alerts deserialize without error

### Phase 53.1: Close gap ETW-03 — add BypassAlert to IpcPayloadV1 and route in agent hook_ipc (INSERTED)

**Goal:** Close integration blocker INT-BLOCK-01: the hook DLL emits BypassAlert frames over the named pipe, but the agent deserializes every frame as HookRequest and IpcPayloadV1 has no BypassAlert variant. Add the variant, route BypassAlert to the bypass correlator, and wrap the hook DLL emission in the versioned envelope.
**Requirements**: ETW-03
**Depends on:** Phase 53
**Plans:** 4/4 plans complete

**Wave 1** *(no dependencies)*

- [x] `53.1-01-PLAN.md` — Extend IpcPayloadV1 with BypassAlert(BypassAlert) variant in dlp-common; add round-trip bincode unit test *(completed 2026-06-17)*

**Wave 2** *(blocked on Wave 1 completion)*

- [ ] `53.1-02-PLAN.md` — Agent IPC routing: deserialize IpcEnvelope in handle_connection, route BypassAlert to bypass_correlator via crossbeam_channel; add submit_bypass_alert entry point and wiring tests
- [ ] `53.1-03-PLAN.md` — Hook DLL emission: wrap BypassAlert in IpcEnvelope::V1 before bincode::serialize in emit_bypass_alert; add envelope wrapping unit test

**Cross-cutting constraints:**

- All new BypassAlert fields have #[serde(default)] for backward compat (WR-12 from Phase 53)
- Sync->async handoff uses crossbeam_channel::Sender<BypassAlert> without blocking the pipe loop (Pitfall 3 from RESEARCH.md)

### Phase 54: Admin TUI Protected Paths + Bypass Alerts Screens

**Goal**: An operator can fully manage Protected Paths and triage Bypass Alerts from the admin TUI without touching SQLite, the registry, or any raw config file.
**Depends on**: Phases 52 (Protected Paths server endpoints) and 53 (Bypass Alerts server endpoints)
**Requirements**: UX-01, UX-02
**Success Criteria** (what must be TRUE):

  1. The Protected Paths screen lists every T3/T4 root with a visible diff between policy-derived defaults and operator overrides; add/remove actions round-trip through the admin API and reflect on the agent within one `policy_sync` cycle.
  2. The Bypass Alerts screen shows a paginated event feed with per-event detail (image path + SHA-256, file path, operation, QPC timestamp, correlation reason); the operator can ack/dismiss with a single keypress and filter by severity.
  3. Both screens follow the existing `screens/usb_enforcement.rs` and `screens/print_config.rs` pattern (mod/dispatch/render/client/app.rs extensions); navigation, focus, and Esc-back semantics match every other admin TUI screen.
  4. Eight new client methods (`list_protected_paths`, `create_protected_path`, `update_protected_path`, `delete_protected_path`, `list_bypass_alerts`, `ack_bypass_alert`, plus the two screens' navigation entry points) exist, are unit-tested, and surface server errors as user-readable toasts.

**Plans:** 6/6 plans complete
**UI hint**: yes

### Phase 55: Monitor-Only / Audit-Only Per-Policy Enforcement Mode

**Goal**: Every policy can be deployed in `Audit`, `Block`, or `AuditAndBlock` mode so an operator can roll out v0.10.0 in monitor-first mode, tune false positives, and only then enable blocking.
**Depends on**: Phases 48-50 (hook DLL must exist and observe `policy_mode`); independent of 51-54
**Requirements**: MODE-01
**Success Criteria** (what must be TRUE):

  1. The policy schema carries an `enforcement_mode: Audit | Block | AuditAndBlock` field, with the existing Conditions Builder TUI exposing it as a dropdown; absent value defaults to `Block` for backward compatibility with v0.9.0 policies.
  2. A policy in `Audit` mode produces a full audit event (`policy_mode = Audit`, `would_have_denied = true`) on a violation but the hook returns ALLOW; the file operation succeeds and the SIEM relay forwards the would-have-blocked event.
  3. A policy in `AuditAndBlock` mode produces both an audit event and a DENY return; the audit event records `policy_mode = AuditAndBlock` so post-deployment review can distinguish it from pure-`Block`.
  4. The Conditions Builder dropdown is exercised by an integration test that round-trips Audit → Block → AuditAndBlock through `PUT /admin/policies/:id` and verifies the agent sees each mode within one `policy_sync` cycle.

**Plans:** 7/7 plans complete

Plans:
**Wave 1**

- [x] 55-01-PLAN.md — Core types: EnforcementMode enum, AuditEvent extension, SQLite migration, PolicyRepository CRUD
- [x] 55-02-PLAN.md — PolicyStore effective mode computation, admin API payload extension, alert router severity downgrade

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 55-03-PLAN.md — Agent config parsing, IPC handler effective mode, enriched audit event emission
- [x] 55-04-PLAN.md — DACL tripwire mode awareness: skip Deny ACE for Audit-mode policies
- [x] 55-05-PLAN.md — Alert router + SIEM mode awareness: downgrade Audit-mode alerts, SIEM unchanged

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 55-06-PLAN.md — Admin TUI Conditions Builder: enforcement_mode dropdown, form wiring, global override banner

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 55-07-PLAN.md — Integration tests: round-trip Audit/Block/AuditAndBlock through admin API

### Phase 55.1: Close gap MODE-01 — read global_enforcement_mode in BypassCorrelator (INSERTED)

**Goal:** Close gap MODE-01 — make the agent's BypassCorrelator read global_enforcement_mode so that Audit-mode bypass events do not trigger false-positive alerts.
**Requirements**: MODE-01, ETW-01, ETW-02
**Depends on:** Phase 55
**Plans:** 2/2 plans complete

**Wave 1** *(no dependencies)*

- [ ] `55.1-01-PLAN.md` — CorrelatorConfig + service wiring: add `enforcement_mode` field, default to Block, pass `global_mode` from service.rs
- [ ] `55.1-02-PLAN.md` — Audit-mode suppression + tests: guard handle_etw_event, submit_bypass_alert, emit_alert; add unit tests for Audit/Block/AuditAndBlock behavior

### Phase 56: SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004)

**Goal**: SD cards, optical (CD/DVD/Blu-ray), and virtual (Daemon Tools / VHD / VHDX / Explorer-mounted ISO) drives are first-class citizens in device enumeration and the ABAC engine, with policy expressible as `source_volume_class → destination_volume_class`.
**Depends on**: Phases 48-50 (hook DLL covers I/O for free regardless of volume class); independent of 51-54
**Requirements**: DRIVE-01, DRIVE-02, DRIVE-03, DRIVE-04
**Success Criteria** (what must be TRUE):

  1. On the test endpoint, an operator inserting an SD card, mounting a VHDX, and mounting an ISO via Explorer each produces a single distinct device-arrival audit event with the correct `volume_class` in {`LocalNTFS`, `USBRemovable`, `SDCard`, `Optical`, `Virtual`, `NetworkShare`} (disambiguated via `Win32_DiskDrive` + `Win32_LogicalDisk` WMI; `GetDriveTypeW` alone is insufficient).
  2. The ABAC attribute set grows from 5 to 7 with `source_volume_class` and `destination_volume_class`; an integration test proves a policy "DENY copy from LocalNTFS T4 to Optical" blocks an actual `CopyFileExW` to a registered optical drive on the test endpoint.
  3. The admin TUI Conditions Builder exposes `source_volume_class` and `destination_volume_class` as dropdowns with the six enum values; the existing USB/disk allowlist screens render SD/Optical/Virtual rows alongside USB without UI breakage.
  4. `WM_DEVICECHANGE` handlers cover virtual mounts (Daemon Tools, ISO mounting via Windows Explorer, VHD/VHDX mount) by registering `GUID_DEVINTERFACE_VOLUME` notification handlers for non-USB volume classes; the 500 ms deferred-processing pattern from v0.7.0 is preserved.

**Plans:** 5/6 plans executed
**UI hint**: yes

Plans:

- [x] 55.1-01-PLAN.md
- [x] 55.1-02-PLAN.md

**Wave 1** *(no dependencies)*

- [x] `56-01-PLAN.md` — VolumeClass enum + AbacContext extension + PolicyCondition variants + VolumeArrival audit event in dlp-common *(completed 2026-05-29)*
- [x] `56-02-PLAN.md` — Agent-side volume classification (GetDriveTypeW + WMI hybrid) + VolumeArrival emission + volume_class_map *(completed 2026-05-29)*

**Wave 2** *(blocked on Wave 1 completion)*

- [x] `56-03-PLAN.md` — Hook DLL thread-local volume-class cache (10s TTL) + trampoline integration for path-based and copy/move ops *(completed 2026-06-06)*
- [x] `56-04-PLAN.md` — Server-side ABAC evaluation: PolicyStore match arms for SourceVolumeClass/DestinationVolumeClass + integration test *(completed 2026-05-29)*
- [x] `56-05-PLAN.md` — Admin TUI Conditions Builder: SourceVolumeClass/DestinationVolumeClass dropdowns + allowlist volume class badges *(completed 2026-05-29)*

**Wave 3** *(blocked on Waves 1-2 completion)*

- [x] `56-06-PLAN.md` — End-to-end integration test: DENY LocalNTFS T4 to Optical policy + full workspace verification *(completed 2026-06-06)*

### Phase 56.1: Close gap DRIVE-03/04 — add volume class fields to HookRequest and ABAC path (INSERTED)

**Goal:** Carry volume class from hook DLL through IPC to ABAC evaluation so volume-class policies (e.g., "deny T4 copy to Optical") fire for hook-intercepted operations.
**Requirements**: DRIVE-03, DRIVE-04
**Depends on:** Phase 56
**Plans:** 3/3 plans complete

**Wave 1** *(no dependencies)*

- [ ] `56.1-01-PLAN.md` — Add source_volume_class and destination_volume_class to HookRequest (dlp-common) and EvaluateRequest (dlp-common/abac.rs), update From<EvaluateRequest> for AbacContext to forward fields, add backward-compat tests
- [ ] `56.1-02-PLAN.md` — Hook DLL populate volume class fields in classify_path_with_volume_class instead of discarding, update classify_and_log_path to forward parameters, add tests

**Wave 2** *(blocked on Wave 1 completion)*

- [ ] `56.1-03-PLAN.md` — Agent hook IPC handler: convert HookRequest to EvaluateRequest with real ABAC evaluation via OfflineManager, wire volume class fields through, add integration tests

### Phase 57: Operational Deployment Guide + AV/EDR Allowlist + UAT

**Goal**: An operator can deploy v0.10.0 to a real Windows fleet alongside any of the top 6 EDRs without false-positive quarantine, and the milestone passes a UAT smoke test on a real Windows 11 host with real cloud clients, real printers, and real removable media. **This phase is the milestone ship gate.**
**Depends on**: Phases 48-56 (deployment guide must reflect every shipped capability; UAT exercises every shipped feature)
**Requirements**: OPS-01, OPS-02, OPS-03, OPS-04
**Success Criteria** (what must be TRUE):

  1. `docs/operations/deployment-guide.md` exists and documents per-vendor AV/EDR allowlist procedures (with screenshots + console steps + IOC/hash exclusion examples) for Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Carbon Black, Sophos, and Trend Micro Apex One; an operator following the guide can deploy v0.10.0 alongside each EDR without quarantine.
  2. Every shipped binary has SHA-256 + SHA-512 hashes published in `RELEASE_NOTES.md`; the Microsoft binary submission flow (`wdsi/filesubmission`) is documented; a `signtool verify` command for Authenticode timestamp verification is included; reproducible by an operator from the documented commands alone.
  3. The deployment guide explicitly addresses Secure Boot reality (AppInit_DLLs is inert; `siem.appinit_dlls_disabled` will fire), the PPL coverage gap (lsass/MsMpEng/EDR-self) and the DACL-tripwire backstop, `SeSystemProfilePrivilege` preservation across upgrades, and the post-install reboot requirement for hook activation.
  4. UAT executes on a real Windows 11 host with real OneDrive/Google Drive/Dropbox/Box clients, real printers, and real USB/SD/optical/virtual drives; every v0.9.0 cloud-sync regression test plus every v0.10.0 active-blocking scenario passes; the CRIT-04 benchmark gate (<= 25% wall-clock overhead on representative `cargo build` + `Office app launch` workloads) holds; results are captured in `.planning/milestones/v0.10.0-UAT.md`.

**Plans:** 2/6 plans executed

### Phase 58: Differentiators Bundle (Override + Diagnostic + Hash Evidence + Self-Health)

**Goal**: The four highest-value differentiators ship as a bundle that materially improves operator deployability and forensic posture; cuttable as a unit to v0.10.1 if scope pressure hits.
**Depends on**: Phases 48-57 (every differentiator depends on a prior shipped capability — override needs the hook + UI + audit enrichment, diagnostic mode needs the audit fields, hash evidence needs the file-handle plumbing, self-health needs the cache + injector)
**Requirements**: DIFF-01, DIFF-02, DIFF-03, DIFF-04
**Success Criteria** (what must be TRUE):

  1. On a DENY decision, the user sees a `dlp-user-ui` toast offering "Request override"; submitting a justification round-trips through `POST /admin/overrides`; an admin can grant a TTL-bounded approval (default 1 hour) via the new admin TUI screen, and the user can complete the originally-denied operation within the TTL window.
  2. The diagnostic-mode admin TUI screen displays the full decision tree per blocked event — which hook fired, classification source + age, ABAC subject/resource/action/environment values, matched policy ID + mode, decision latency in microseconds — sufficient to triage a real false-positive without leaving the TUI.
  3. Block events on `WriteFile`/`WriteFileEx` carry a `content_sha256` hash of the would-be-written content (computed via the OS file handle, NOT a second open); audit-event consumers and SIEM relay forward the hash unchanged for forensic chain-of-custody.
  4. The hook DLL emits per-host self-health counters (injected_pids, patched_modules, pipe_round_trips, cache_hit_rate, fail_state) that the admin TUI surfaces on a coexistence dashboard, letting an operator see at a glance which endpoints have healthy hooks and which are degraded by AV/EDR interaction.

**Plans:** 6/6 plans planned (revised 2026-05-27 incorporating cross-AI review feedback)

### Phase 58.1: Close v0.10.0 ship-gap verification items (INSERTED)

**Goal**: Close the remaining verification and integration gaps that block v0.10.0 ship readiness: hook DLL ETW journal writes, bypass correlator routing, physical Windows 11 UAT execution, and missing VERIFICATION.md artifacts.
**Depends on**: Phase 58
**Requirements**: TBD
**Success Criteria** (what must be TRUE):

  1. The hook DLL writes a ring journal entry for every ETW-correlated trampoline operation so bypass correlation is accurate.
  2. `BypassCorrelator::run()` consumes `bypass_rx` events and routes them to alert storage without dropping agent-submitted bypass alerts.
  3. OPS-04 UAT executes on physical Windows 11 hardware and results are recorded in `.planning/milestones/v0.10.0-UAT.md`.
  4. Missing `VERIFICATION.md` files are created for the relevant completed phases.

**Plans:** 4/4 plans complete

Plans:

- [x] 58.1-01-PLAN.md — Hook DLL journal writes verification: audit trampoline coverage, add JournalDegraded alert, 10 unit tests *(completed 2026-06-23)*
- [x] 58.1-02-PLAN.md — BypassCorrelator bypass_rx routing: verify bypass_tx/bypass_rx wiring, metric logging, batch semantics integration tests *(completed 2026-06-23)*
- [x] 58.1-03-PLAN.md — Missing VERIFICATION.md artifacts: discovery matrix + 8 verification documents (50, 50.1, 52, 53, 53.1, 56, 58, 57) *(completed 2026-06-23)*
- [x] 58.1-04-PLAN.md — OPS-04 UAT execution handoff: PowerShell script (36 scenarios + CRIT-04 benchmark) + markdown companion guide *(completed 2026-06-23)*

### Phase 58.2: Fix double HookIpcServer and wire volume classes (INSERTED)

**Goal**: Eliminate duplicate `HookIpcServer` initialization in the agent and complete the wiring of `source_volume_class` / `destination_volume_class` attributes through the ABAC evaluation path so volume-class policies enforce correctly for hook-intercepted operations.
**Depends on**: Phase 58.1
**Requirements**: TBD
**Success Criteria** (what must be TRUE):

  1. Only one `HookIpcServer` instance is created and torn down per agent lifecycle; no duplicate named-pipe listeners or conflicting hook IPC endpoints exist.
  2. `HookRequest` / `EvaluateRequest` carry populated volume-class fields from the hook DLL through the agent to `PolicyStore::evaluate`.
  3. ABAC policies expressed in terms of `source_volume_class` and `destination_volume_class` produce the expected ALLOW/DENY decision for hook-intercepted file operations.
  4. Existing unit and integration tests continue to pass; new tests cover the duplicate-initialization guard and the volume-class wiring path.

**Plans:** 3/3 plans complete

Plans:

- [x] 58.2-01-PLAN.md
- [x] 58.2-02-PLAN.md
- [x] 58.2-03-PLAN.md

- [ ] `58.2-01-PLAN.md` — Consolidate HookIpcServer: introduce HookIpcServerConfig, rewrite spawn_hook_ipc_server, remove inline block from run_loop_init, remove BlockingThreads::hook_ipc, wire all DIFF handlers
- [ ] `58.2-02-PLAN.md` — Wire volume classes and identity resolution: add hook_request_to_evaluate_request, map_hook_action_to_abac, get_caller_sid, warn! for missing volume classes on COPY/MOVE
- [ ] `58.2-03-PLAN.md` — Tests: unit tests for helpers, integration test for consolidated server routing all four frame types, end-to-end volume-class ALLOW/DENY decisions

### Phase 58.3: Close gap: OPS-04 — execute physical Windows 11 UAT (INSERTED)

**Goal**: Execute the v0.10.0 UAT plan on physical Windows 11 hardware and record actual results in `.planning/milestones/v0.10.0-UAT.md`.
**Depends on**: Phase 58.2
**Requirements**: OPS-04
**Success Criteria** (what must be TRUE):

  1. Every UAT scenario in `.planning/milestones/v0.10.0-UAT.md` has an actual result, pass/fail status, tester notes, and captured artifacts.
  2. The CRIT-04 benchmark gate (<= 25% wall-clock overhead on `cargo build` and Office app launch) is measured and recorded.
  3. The tester sign-off section is completed with engineering lead and QA lead approval.
  4. Any blocking failures are documented with defect IDs and remediation plans before ship decision.

**Plans:** 3/3 plans planned

Plans:

- [ ] `58.3-01-PLAN.md` — Prepare physical Windows 11 host, peripherals, and cloud clients.
- [ ] `58.3-02-PLAN.md` — Execute UAT scenarios A–J and capture artifacts.
- [ ] `58.3-03-PLAN.md` — Record results, compute CRIT-04 overhead, and complete sign-off.

### Phase 58.5: Unhook dlp_hook_dll.dll when dlp-agent is killed/exited (INSERTED)

**Goal**: Ensure the DLP agent cleanly unhooks `dlp_hook_dll.dll` from all injected processes when the agent service is killed, exits, or restarts, restoring original IAT/ntdll trampolines and releasing shared-memory resources without crashing host processes.
**Depends on**: Phase 58.4
**Requirements**: SC-58.5-01, SC-58.5-02, SC-58.5-03, SC-58.5-04, SC-58.5-05
**Success Criteria** (what must be TRUE):

  1. On agent graceful shutdown, every process injected with `dlp_hook_dll.dll` receives an unhook command and the DLL is unloaded or trampolines are restored to original bytes.
  2. On agent crash or unexpected termination, a watchdog mechanism detects agent absence and triggers self-unload in hooked processes within a bounded timeout.
  3. No host process crashes or hangs during unhook; original file I/O behavior is fully restored.
  4. Shared-memory sections (`Global\\DlpClassificationCache`, per-process journal sections) are closed and released.
  5. Audit events are emitted for unhook lifecycle (`agent_shutdown_unhook`, `watchdog_self_unload`, `unhook_failure`).

**Plans:** 7/7 plans complete

Plans:

- [x] 58.5-07-PLAN.md

- [x] 58.5-05-PLAN.md
- [x] 58.5-06-PLAN.md

- [x] 58.5-01-PLAN.md
- [x] 58.5-02-PLAN.md
- [x] 58.5-03-PLAN.md
- [x] 58.5-04-PLAN.md

- [ ] `58.5-01-PLAN.md` — Add cooperative unhook IPC types and audit event types.
- [ ] `58.5-02-PLAN.md` — Implement hook DLL self-unhook (UnhookAll, watchdog, UnhookCommand handler).
- [ ] `58.5-03-PLAN.md` — Implement agent-side unhook dispatch and registry transitions.
- [ ] `58.5-04-PLAN.md` — Write tests and run quality gates across all three crates.

### Phase 58.6: Targeted hook injection — only processes that perform file operations (INSERTED)

**Goal**: Reduce hook-DLL footprint and host-process risk by injecting only into processes that actually perform file operations, instead of injecting into every non-allowlisted user process.
**Depends on**: Phase 58.5
**Requirements**: TGT-01, TGT-02, TGT-03, TGT-04, TGT-05, TGT-06
**Success Criteria** (what must be TRUE):

  1. The agent can identify processes that are likely to perform file operations (e.g., by executable image imports, command-line heuristics, known application categories, or runtime observation) with low false-negative rate for T3/T4 data handlers.
  2. Processes that are not expected to touch the file system (e.g., pure rendering services, some background utility processes) are skipped by the injector unless runtime observation later indicates file I/O.
  3. Coverage telemetry shows a measurable reduction in injected process count compared to universal injection, while maintaining >= 99% coverage of actual file-operation events that touch T3/T4 paths.
  4. The change is backward-compatible with the existing allowlist and does not reintroduce bypass paths closed by Phases 48–58.5.
  5. New or updated tests cover the targeting heuristic and fallback to universal injection when targeting data is insufficient.

**Plans:** 9/9 plans planned

Plans:

- [ ] `58.6-01-PLAN.md` — Config, mode enum, ProcessRegistry state extensions, and InjectProcess trait seam for targeted injection.
- [ ] `58.6-02-PLAN.md` — PE import scanner with file-IO scoring, ScoreUnavailable semantics, and TTL cache.
- [ ] `58.6-03-PLAN.md` — Remote PEB command-line reader with WoW64 guard and basename/command-line heuristic classifier.
- [ ] `58.6-04-PLAN.md` — Hybrid ProcessClassifier combining allowlist/PPL, PE score, basename, and command-line signals with allowlist-version-aware cache.
- [ ] `58.6-05-PLAN.md` — LazyInjector with TierResolver seam and honest first-event-missed coverage metrics.
- [ ] `58.6-06-PLAN.md` — Integrate classifier and lazy injector into UniversalInjector and service.rs; decouple enablement, fix retry semantics, ETW fanout.
- [ ] `58.6-07-PLAN.md` — Targeted injection telemetry counters, path-hashed SIEM audit events, and agent-side details emission.
- [ ] `58.6-08-PLAN.md` — Server-side persistence of AuditEvent.details in SQLite, queries, SIEM relay, and alert router.
- [ ] `58.6-09-PLAN.md` — Integration tests using InjectProcess/TierResolver seams, telemetry audit verification, and workspace quality gates.

### Phase 58.4: Close gap: DIFF-02/03/04 — wire differentiators into hook DLL deny paths (INSERTED)

**Goal**: Invoke diagnostic snapshot capture, content SHA-256 hashing, and health snapshot ingestion from the hook DLL deny paths so the differentiator infrastructure built in Phase 58 produces real data.
**Depends on**: Phase 58.2
**Requirements**: DIFF-02, DIFF-03, DIFF-04
**Success Criteria** (what must be TRUE):

  1. `dlp-hook-dll/src/trampolines.rs` deny branches call `DiagnosticRing::push_snapshot` with the full decision context; `PullDiagnostics` returns non-empty snapshots.
  2. `HookWriteFile` / `HookWriteFileEx` deny branches call `hash_compute::compute_content_hash` and attach the resulting SHA-256 to the audit event / `HookResponse`.
  3. The hook DLL populates and sends `HookHealthSnapshot` to the agent health handler at regular intervals and on state transitions; the Self-Health Dashboard shows live counters.
  4. Existing unit and integration tests continue to pass; new tests prove each differentiator data path end-to-end.

**Plans:** 5/5 plans complete

Plans:

- [x] 58.4-01-PLAN.md
- [x] 58.4-02-PLAN.md
- [x] 58.4-03-PLAN.md
- [x] 58.4-04-PLAN.md
- [x] 58.4-05-PLAN.md

- [ ] `58.4-01-PLAN.md` — Wire diagnostic snapshot capture into `classify_and_log_path` / `classify_and_log_handle` deny branches.
- [ ] `58.4-02-PLAN.md` — Wire content SHA-256 hash computation into `HookWriteFile` / `HookWriteFileEx` deny branches.
- [ ] `58.4-03-PLAN.md` — Wire hook DLL health snapshot population and emission to the agent health handler.
- [ ] `58.4-04-PLAN.md` — Add end-to-end tests for diagnostic, hash, and health data paths.

### Phase 59: Label Service — DB Schema + API + Folder Inheritance + Manual Assignment

**Goal**: A label service provides persistent data classification labels with folder inheritance, manual assignment, and admin API/TUI management.
**Depends on**: None (new capability)
**Requirements**: LABEL-01, LABEL-02, LABEL-03, LABEL-04, LABEL-05, LABEL-06, LABEL-07
**Success Criteria** (what must be TRUE):

  1. Labels are stored in SQLite with `labels`, `label_paths`, and `label_inheritance` tables; foreign keys enforce referential integrity.
  2. The admin API exposes CRUD endpoints for labels with path-based lookup, folder inheritance resolution, and validation.
  3. The ABAC PolicyStore evaluates labels as a resource attribute (`resource_label_tier`) with automatic path-to-label resolution.
  4. The admin TUI provides full label management (list, create, edit, delete, review queue) with keyboard navigation matching existing screens.

**Plans**: 4 plans (59-01 through 59-04) — under review
**UI hint**: yes

### Phase 60: Data Owner Review Queue + Admin TUI Screen

**Goal**: Data Owners can review pending label assignments through a dedicated admin TUI screen, with approval/reject actions that update label state and emit audit events.
**Depends on**: Phase 59 (label service must exist)
**Requirements**: LABEL-04
**Success Criteria** (what must be TRUE):

  1. Confirming/rejecting a label emits a SIEM-ready audit event with before/after state.
  2. Data Owners see only labels they own; admins see all.
  3. Scanner confidence is displayed in the review queue.
  4. Department filter scopes the review queue.
  5. Confirm invalidates the ABAC label resolution cache.

**Plans:** 1/1 plans planned
**UI hint**: yes

### Phase 61: Approval Workflow Engine — T3 Data Owner + T4 Board Digital Signature

**Goal**: Users can request time-bounded approvals for blocked operations. T3 requests route to Data Owners; T4 requests require Board-level digital signature. Approved operations carry a signed token validated by the agent before allowing the blocked action.
**Depends on**: Phase 60 (Data Owner review queue must exist for T3 routing)
**Requirements**: WORKFLOW-01, WORKFLOW-02, WORKFLOW-03, WORKFLOW-04, WORKFLOW-05, WORKFLOW-06
**Success Criteria** (what must be TRUE):

  1. `approvals` SQLite table exists with all required fields and foreign keys (WORKFLOW-01)
  2. T3 approval flow works end-to-end: user request → server → Data Owner grants via admin TUI → signed token delivered to agent (WORKFLOW-02)
  3. T4 approval flow requires Board digital signature (Ed25519) verified server-side before grant (WORKFLOW-03)
  4. Agent validates approval tokens during ABAC evaluation, checking scope, expiry, and signature (WORKFLOW-04)
  5. Admin TUI ApprovalList screen supports list, grant, revoke, filter with keyboard navigation (WORKFLOW-05)
  6. Every approval request, grant, and use emits a SIEM-ready audit event (WORKFLOW-06)

**Plans**: 4 plans (61-01 through 61-04)
**UI hint**: yes

### Phase 62: Syslog Forwarder — RFC 5424 + Encrypted Offline Queue

**Goal**: A syslog forwarder ships audit events in RFC 5424 format with TLS transport and an encrypted offline queue for resilience during network outages.
**Depends on**: Phase 59 (label service audit events must exist to forward)
**Requirements**: SYSLOG-01, SYSLOG-02, SYSLOG-03, SYSLOG-04
**Success Criteria** (what must be TRUE):

  1. RFC 5424 structured data with correct PRI, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, and structured-data elements.
  2. TLS 1.3 transport with certificate pinning.
  3. Encrypted offline queue (AES-256-GCM with DPAPI-wrapped key) survives agent restart.
  4. Configurable batch size and flush interval with backpressure handling.

**Plans**: 4 plans (62-01 through 62-04) — Complete 2026-05-21

### Phase 63: Tamper-Evident Audit — SHA-256 Hash Chain

**Goal**: Every audit event is cryptographically linked to its predecessor via a SHA-256 hash chain, making undetected tampering computationally infeasible.
**Depends on**: Phase 62 (syslog forwarder must exist to relay tamper-evident events)
**Requirements**: TAMPER-01, TAMPER-02, TAMPER-03, TAMPER-04
**Success Criteria** (what must be TRUE):

  1. Every audit event carries `prev_hash` and `chain_hash` fields linking it to the previous event in the chain.
  2. The hash chain is verified on every server startup; a break triggers `EventType::HashChainBreak` with `triggers_alert = true`.
  3. The chain root is anchored to a hardware-backed key (DPAPI) or external timestamp service.
  4. A verification API allows operators to query chain integrity for any time range.

**Plans**: 4 plans (63-01 through 63-04) — Complete 2026-06-06

### Phase 64: Device Identity Expansion — Fingerprint + MAC + VPN + Health

**Goal**: The agent collects and reports machine-level device identity (fingerprint, MAC addresses, VPN state, domain join) and health status, enabling ABAC policies that enforce based on endpoint posture and detect tamper or connectivity degradation.
**Depends on**: None (new capability, orthogonal to prior phases)
**Requirements**: DEVICE-01, DEVICE-02, DEVICE-03, DEVICE-04, DEVICE-05
**Success Criteria** (what must be TRUE):

  1. A stable device fingerprint (SHA-256 of hostname + sorted MACs + OS version + install date) is computed at agent install, persisted in `HKLM\SOFTWARE\DLP\Agent`, and reported with every heartbeat.
  2. All active NIC MAC addresses are collected via `GetAdaptersAddresses`, sorted lexicographically, and sent in the heartbeat payload; the server stores them in the agents table.
  3. VPN state is detected at runtime via `GetAdaptersAddresses` (IF_TYPE_TUNNEL + description keywords) and reflected in ABAC policy evaluation through the `DeviceHealth` condition.
  4. Domain join state is included in the agent heartbeat via `NetGetJoinInformation`; the server stores and exposes it in agent info responses.
  5. Health status transitions atomically on tamper detection (Tampered), connectivity loss (3 failures = Degraded, 10 = Offline), and recovery (successful heartbeat = Healthy); every transition emits a `DeviceHealthChange` audit event.

**Plans:** 4/4 plans complete (2026-06-09)

**Wave 1** *(no dependencies)*

- [x] `64-01-PLAN.md` — Core data types: EndpointIdentity struct, DeviceHealthStatus enum, DeviceHealth PolicyCondition variant, lib.rs re-exports, 9 unit tests
- [x] `64-02-PLAN.md` — Agent device collection: MAC addresses, VPN detection, domain join, fingerprint computation, registry persistence, 8 unit tests

**Wave 2** *(blocked on Wave 1 completion)*

- [x] `64-03-PLAN.md` — Heartbeat integration + server storage: extended heartbeat payload, HeartbeatRequest/AgentInfoResponse, DB migrations (5 columns), AgentRepository updates, offline sweeper

**Wave 3** *(blocked on Wave 2 completion)*

- [x] `64-04-PLAN.md` — ABAC integration + health state machine: EventType::DeviceHealthChange, PolicyStore DeviceHealth match arm, AtomicU8 transitions, heartbeat failure tracking, tamper detection, audit emission

### Phase 66.1: Close gap: WORKFLOW-04 — wire ApprovalCache into enforcement

**Goal**: Wire the fully-implemented but never-consulted `ApprovalCache` into both agent enforcement paths (file monitor event loop and hook DLL IPC handler) so that approved operations carrying a valid JWT token override an ABAC DENY decision.
**Depends on**: Phase 61 (ApprovalCache must exist with JWT verification, TTL expiry, background polling)
**Requirements**: WORKFLOW-04
**Success Criteria** (what must be TRUE):

  1. When a user has a valid approval token for (sid, data_object_id, action, destination_scope), an ABAC DENY on that exact tuple is overridden to ALLOW by the agent.
  2. The override is validated with Ed25519 JWT signature re-verification (~50us) against the cached server public key.
  3. Expired or revoked tokens are rejected (lazy expiry on access + 60s background sweep).
  4. Destination scope mismatches (e.g. USB drive A approval used for USB drive B) are rejected.
  5. Every approval override emits an auditable `EventType::ApprovalOverride` event with approver SID, approval ID, expiry, and justification.
  6. The override check works in both the file monitor event loop and the hook DLL IPC handler.

**Plans**: 4 plans (66.1-01 through 66.1-04)

**Wave 1** *(no dependencies)*

- [ ] `66.1-01-PLAN.md` — Shared types: EvaluateResponse + matched_label_id, EventType::ApprovalOverride, backward-compat tests
- [ ] `66.1-02-PLAN.md` — Server-side: LabelService resolve_tier_and_label_id, PolicyStore::evaluate populates matched_label_id

**Wave 2** *(blocked on Wave 1 completion)*

- [ ] `66.1-03-PLAN.md` — Agent core: check_approval_override helper, ApprovalCacheKey::from_evaluation, spawn_event_loop wiring

**Wave 3** *(blocked on Wave 2 completion)*

- [ ] `66.1-04-PLAN.md` — Agent enforcement paths: run_event_loop override + audit, hook_ipc override + PID-to-SID resolution

### Phase 67: Print Watermarking — XPS Overlay

**Goal**: Every approved print job for T3/T4 data carries a visible watermark overlay containing user identity, timestamp, device fingerprint, data tier, and approval ID — embedded directly into the XPS spool file before it reaches the printer driver.
**Depends on**: Phase 61 (approval workflow tokens provide the approval ID to embed); Phase 64 (device fingerprint and health status feed the watermark context)
**Requirements**: WATERMARK-01, WATERMARK-02
**Success Criteria** (what must be TRUE):

  1. When a T3/T4 print job is approved (via Phase 61 workflow or pre-existing policy allow), the XPS spool file is intercepted after `FindFirstPrinterChangeNotification` fires `JOB_STATUS_SPOOLING`; the watermark is overlaid on every page before `EndDocPrinter` completes.
  2. The watermark text contains: Windows username, ISO-8601 timestamp, device fingerprint (first 8 hex chars), ResolvedTier label, and approval token ID (if applicable); font is Arial 8pt semi-transparent gray at bottom-right margin with 15 pt padding.
  3. The watermark survives rasterization through the printer driver's XPS-to-PDL conversion; a physical printout on a test laser printer shows the watermark legibly on every page.
  4. Watermark failures (XPS parse error, font load failure, disk-full during rewrite) emit `EventType::WatermarkFailure` with `triggers_alert = true` and route through SIEM; the print job is denied rather than allowed to proceed unwatermarked.
  5. An admin TUI screen lists watermark policy configuration (enable/disable per tier, font/size/position overrides) and a live feed of recent watermark events with preview paths.

**Plans**: 0/0 plans planned
**UI hint**: yes

---

## Progress Table

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 13. Conditions Builder | 2/2 | Reopened for review | - |
| 14. Policy Create | 2/2 | Reopened for review | - |
| 15. Policy Edit/Delete | 1/1 | Reopened for review | - |
| 16. Policy List/Simulate | 4/3 | Complete    | 2026-06-16 |
| 17. Import/Export | 2/2 | Complete    | 2026-06-17 |
| 18. Boolean Mode Engine + Wire Format | 2/1 | Complete    | 2026-06-21 |
| 19. Boolean Mode TUI Import/Export | 2/2 | Reopened for review | - |
| 20. Operator Expansion | 2/2 | Reopened for review | - |
| 21. In-Place Condition Editing | 1/1 | Reopened for review | - |
| 22. DLP-Common Foundation | 4/4 | Reopened for review | - |
| 23. USB Enumeration in DLP-Agent | 2/2 | Reopened for review | - |
| 24. Device Registry DB + Admin API | 4/4 | Reopened for review | - |
| 25. App Identity Capture in DLP-User-UI | 4/4 | Reopened for review | - |
| 26. ABAC Enforcement Convergence | 5/5 | Reopened for review | - |
| 27. USB Toast Notification | 2/2 | Reopened for review | - |
| 28. Admin TUI Screens | 5/5 | Complete    | 2026-06-21 |
| 47. Secrets Encryption at Rest (prerequisite) | 1/1 | Reopened for review | - |
| 48. Hook DLL Surface Expansion + Crash Hardening + Build Harness | 5/5 | Complete    | 2026-05-16 |
| 49. Universal Injection — ETW Process Watcher + Allowlist + AppInit Fallback | 5/5 | Complete    | 2026-05-19 |
| 50. Shared-Memory Classification Cache + Fail-Mode State Machine | 6/6 | Complete    | 2026-05-20 |
| 50.1 | Close gap FAIL-01/02/03 — verify ISOLATED->RESYNC->HEALTHY recovery at runtime (INSERTED) | 1/1 | Complete   | 2026-06-18 |
| 51. ntdll Syscall-Stub Trampolines + EDR Coexistence | 6/6 | Complete    | 2026-05-22 |
| 52. DACL Tripwire + Repair Watcher + Protected Paths + DPAPI Recovery Doc | 7/7 | Complete    | 2026-05-27 |
| 53. ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring | 6/6 | Complete    | 2026-05-28 |
| 53.1 | Close gap ETW-03 — add BypassAlert to IpcPayloadV1 and route in agent hook_ipc (INSERTED) | 4/4 | Complete   | 2026-06-17 |
| 54. Admin TUI Protected Paths + Bypass Alerts Screens | 6/6 | Complete    | 2026-05-28 |
| 55. Monitor-Only / Audit-Only Per-Policy Enforcement Mode | 7/7 | Complete    | 2026-05-29 |
| 56. SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004) | 6/6 | Complete | 2026-06-06 |
| 57. Operational Deployment Guide + AV/EDR Allowlist + UAT (ship gate) | 6/6 | Complete | 2026-06-10 |
| 58. Differentiators Bundle (cuttable to v0.10.1) | 6/6 | Complete | 2026-06-09 |
| 58.1 | Close v0.10.0 ship-gap verification items (INSERTED) | 4/4 | Complete    | 2026-06-23 |
| 58.2 | Fix double HookIpcServer and wire volume classes (INSERTED) | 3/3 | Complete    | 2026-06-24 |
| 58.3 | Close gap: OPS-04 — execute physical Windows 11 UAT (INSERTED) | 3/3 | Not started | - |
| 58.4 | Close gap: DIFF-02/03/04 — wire differentiators into hook DLL deny paths (INSERTED) | 5/5 | Complete    | 2026-06-29 |
| 59. Label Service — DB Schema + API + Folder Inheritance + Manual Assignment | 4/4 | Complete | 2026-05-21 |
| 60. Data Owner Review Queue + Admin TUI Screen | 1/1 | Complete | 2026-05-12 |
| 61. Approval Workflow Engine — T3 Data Owner + T4 Board Digital Signature | 4/4 | Complete | 2026-05-14 |
| 62. Syslog Forwarder — RFC 5424 + Encrypted Offline Queue | 4/4 | Complete | 2026-06-21 |
| 63. Tamper-Evident Audit — SHA-256 Hash Chain | 4/4 | Complete | 2026-06-06 |
| 64. Device Identity Expansion — Fingerprint + MAC + VPN + Health | 4/4 | Planned | 2026-06-07 |
| **v0.12.0** | | | | |
| 65 | File Scanner — Enumeration + Metadata + Rule Classifier (OCR deferred) | 0/0 | Not started | - |
| 66 | Screenshot Control + Policy Condition | 0/0 | Not started | - |
| 66.1 | Close gap: WORKFLOW-04 — wire ApprovalCache into enforcement (INSERTED) | 4/4 | Complete    | 2026-06-11 |
| 67 | Print Watermarking — XPS Overlay | 0/0 | Not started | - |
| 68 | Email/Outlook Interception + Browser Upload Detection | 0/0 | Not started | - |
| 68.1 | Close gap: DEVICE-05/TAMPER-03/04 — wire tamper detection to SIEM and health (INSERTED) | 3/3 | Complete | 2026-06-13 |
| 69 | RDP File Redirection + Bluetooth Transfer Blocking | 0/0 | Not started | - |
| 70 | Backup Policy Docs + Ransomware Heuristics + Canary Files | 0/0 | Not started | - |

---

## Phase Ordering Rationale

- **Spine first, branches later.** Phases 48 → 49 → 50 → 51 form the BLOCK chain; each depends on a stability invariant from its predecessor (signed dual-arch DLL → universal injection → cache-survivable hot path → safe ntdll patching).
- **Backstops parallel to spine.** Phase 52 (DACL) is independent of the BLOCK chain and can land from Phase 50 onwards. Phase 53 (ETW correlator) operationally requires Phase 51 (ntdll patching produces the events worth correlating) and Phase 50 (the journal ring).
- **UX after server endpoints.** Phase 54 waits on 52 + 53.
- **Safety mode before ship gate.** Phase 55 (monitor mode) is required for safe rollout; UAT in Phase 57 exercises monitor mode first.
- **OPS gate at end.** Phase 57 is the final ship gate; vendor outreach kicks off at Phase 48 so reference customers and EDR allowlist procedures are ready by then.
- **Differentiators last and cuttable.** Phase 58 is a single binary cut decision; if the milestone runs hot, all four DIFF requirements move to v0.10.1.
- **Continuous numbering preserves history.** Phase 47 shipped 2026-05-11 under the abandoned v1.0.0 milestone; v0.10.0 begins at Phase 48 with no gaps. v1.0.0 was abandoned 2026-05-12 with HARD-02..08 dropped per `PROJECT.md`.

## Coverage

44/44 active v0.10.0 requirements mapped:

- **BLOCK** (10): BLOCK-01..04 + BLOCK-10 → Phase 48; BLOCK-05..07 → Phase 49; BLOCK-08, BLOCK-09 → Phase 51
- **CACHE** (6): CACHE-01..06 → Phase 50
- **FAIL** (3): FAIL-01..03 → Phase 50
- **DACL** (5): DACL-01..05 → Phase 52
- **ETW** (5): ETW-01..05 → Phase 53
- **UX** (2): UX-01, UX-02 → Phase 54
- **MODE** (1): MODE-01 → Phase 55
- **DRIVE** (4): DRIVE-01..04 → Phase 56
- **OPS** (4): OPS-01..04 → Phase 57
- **DIFF** (4): DIFF-01..04 → Phase 58

Plus the carried-forward prerequisite: **HARD-01 → Phase 47 (validated 2026-05-11)**.

## Research Flags

Three phases have explicit research flags from `research/SUMMARY.md`. Treat these as advisories for `/gsd-plan-phase`:

- **Phase 51 (ntdll trampolines)** — HEAVY. ntdll stub layout varies per Windows build; EDR matrix needs empirical validation; `retour` 0.3.1 disassembler edge cases possible. Run `/gsd-research-phase` during planning.
- **Phase 53 (ETW correlation)** — MEDIUM. The +/-5 ms QPC tolerance default is engineering judgment; tune empirically with `wpr.exe` on Windows 11.
- **Phase 57 (OPS deployment guide)** — MEDIUM. Per-vendor allowlist UIs evolve quickly; verify each procedure during planning.

Standard patterns (likely skip phase research): Phases 48, 49, 50, 52, 54, 55, 56, 58.

---

*Last updated: 2026-06-09 — Phase 56 marked complete (all 6 plans verified), Phase 64 verified complete.*

### Phase 67.1: Print Watermarking — XPS Page Geometry + Text Metrics (INSERTED)

**Goal:** Deliver foundational XPS page geometry and text-metric modules for print watermarking.
**Requirements**: WATERMARK-01 (foundational), WATERMARK-02 (foundational)
**Depends on:** Phase 67
**Plans:** 2/6 plans complete (Plans 01-02 implemented; Plans 03-06 are gap closure for UAT)
Plans:

- [x] `67.1-01-PLAN.md` — XPS Page Geometry + Text Metrics: WatermarkGeometry, FontMetrics trait, TestFontMetrics, DirectWriteFontMetrics with ComGuard RAII
- [x] `67.1-02-PLAN.md` — XPS ZIP Watermark Injection: streaming XML reader-writer, namespace propagation, ZIP archive rewrite with compression preservation
- [ ] `67.1-03-PLAN.md` — Gap closure: cargo fmt import order in classification_cache.rs + rustdoc fixes in print_watermark.rs and print_watermark_directwrite.rs
- [ ] `67.1-04-PLAN.md` — Gap closure: rustdoc fixes in detection/, device_, dacl_tripwire.rs, and chrome/cache.rs
- [ ] `67.1-05-PLAN.md` — Gap closure: rustdoc fixes in chrome/frame.rs, offline.rs, audit_, clipboard, server_client, disk_enforcer, and etw_kernel_file.rs
- [ ] `67.1-06-PLAN.md` — Gap closure: rustdoc fixes in config.rs, ui_spawner.rs, ipc/pipe2.rs, hook_ipc.rs, password_stop.rs + full quality gates including sonar-scanner

**Cross-cutting constraints:**

- All public items have doc comments per CLAUDE.md section 9.3

### Phase 68.1: Close gap: DEVICE-05/TAMPER-03/04 — wire tamper detection to SIEM and health (INSERTED)

**Goal:** Close the integration gaps identified in the v0.11.0 milestone audit for DEVICE-05, TAMPER-03, and TAMPER-04. Wire tamper-evident hash-chain break detection into device health transitions, SIEM/syslog forwarding, and the admin TUI.
**Requirements**: DEVICE-05, TAMPER-03, TAMPER-04
**Depends on:** Phases 63 (hash chain), 64 (device health)
**Success Criteria** (what must be TRUE):

  1. When the server detects a hash-chain break for an agent, that agent transitions its local `DeviceHealthStatus` to `Tampered` and emits a `DeviceHealthChange` audit event (DEVICE-05).
  2. Synthetic `ChainBreakDetected` events reach both the SIEM relay (`SiemConnector::relay_events`) and the encrypted syslog queue (`SyslogQueueRepository`) — not only `alert_router` (TAMPER-03).
  3. ABAC `EvaluateRequest` carries the endpoint's live `current_health()` instead of the hardcoded `Healthy` default (DEVICE-05 / TAMPER-04 cross-cutting).
  4. The admin TUI provides an Audit Integrity screen that consumes `GET /admin/audit/integrity` and displays per-agent chain status and break count (TAMPER-04).
  5. All changes pass workspace tests, clippy (`-D warnings`), `cargo fmt --check`, and `sonar-scanner` quality gate.

**Plans:** 3/3 plans complete

**Wave 1** *(no dependencies)*

- [x] `68.1-01-PLAN.md` — Server ingest response + synthetic event relay: IngestEventsResponse, tamper flag in response, ChainBreakDetected to SIEM/syslog, agent IngestResponse type
- [x] `68.1-02-PLAN.md` — Agent health wiring: replace hardcoded DeviceHealthStatus::default() with current_health() in identity.rs and interception/mod.rs

**Wave 2** *(blocked on Wave 1 server endpoint)*

- [x] `68.1-03-PLAN.md` — Admin TUI Audit Integrity screen: AuditIntegrityList screen, client method, dispatch/render, SystemMenu entry

**Cross-cutting constraints:**

- All ingest response changes are backward-compatible via `#[serde(default)]`
- Synthetic events are appended to relay/syslog lists after persistence (relay failure does not roll back audit log)
- TUI screen follows the BypassAlertList pattern (list + detail popup + filter + pagination)
- SystemMenu item count updated from 14 to 15 with test coverage

### Phase 71: Implement admin allowlist API handlers in dlp-admin-cli and dlp-server

**Goal:** [To be planned]
**Requirements**: TBD
**Depends on:** Phase 65
**Plans:** 0 plans

Plans:

- [ ] TBD (run /gsd-plan-phase 71 to break down)

---

## Backlog

### Phase 999.28: Follow-up — Phase 28 incomplete plans (BACKLOG)

**Goal:** Resolve plans that ran without producing summaries during Phase 28 execution
**Source phase:** 28
**Deferred at:** 2026-06-20 during /gsd-progress --next advancement to Phase 55.1
**Plans:**

- [x] 28-05: admin-tui-screens (ran, no SUMMARY.md)
