---
milestone: v0.11.0
milestone_name: Label Service + Workflow + Audit
last_updated: 2026-05-15
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
- **v0.10.0 Real-Time File Access Prevention — Phases 47 (prerequisite) + 48–58 (active)**

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
| 47 | Encrypt secrets at rest in operator SQLite (PBKDF2 + DPAPI machine-bound KEK; AES-256-GCM versioned envelope; admin-CLI rotation) | HARD-01 | Reopened for review (was Validated 2026-05-11; commits `7846671`, `5a0619f`, `e6e4aa4`, `68f5e0c`) |

The DPAPI master-key recovery handoff originally slated for v1.0.0 Phase 52 is folded into v0.10.0 **Phase 52** (DACL-05) as `docs/operations/dpapi-recovery.md`.

## Phases (v0.10.0 active phases)

- [x] **Phase 48: Hook DLL Surface Expansion + Crash Hardening + Build Harness** — extend and harden the v0.9.0 hook into a single unified DLL with the full file-I/O surface, x86 sibling, and Authenticode signing pipeline. (completed 2026-05-15)
- [ ] **Phase 49: Universal Injection — ETW Process Watcher + Allowlist + AppInit Fallback** — drive the wider hook surface into every non-allowlisted user process via ETW Kernel-Process and `CreateRemoteThread`.
- [ ] **Phase 50: Shared-Memory Classification Cache + Fail-Mode State Machine** — give the hook DLL a survivable sub-50µs hot path and a tier-gated asymmetric fail policy.
- [ ] **Phase 51: ntdll Syscall-Stub Trampolines + EDR Coexistence** — close the direct-syscall bypass behind a default-off feature flag with detect-before-patch EDR safety.
- [ ] **Phase 52: DACL Tripwire + Repair Watcher + Protected Paths + DPAPI Recovery Doc** — kernel-enforced NTFS backstop for T3/T4 roots, plus the carried-forward DPAPI recovery runbook.
- [ ] **Phase 53: ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring** — turn hook-vs-ETW divergence into auditable BypassAlert events routed through SIEM and the alert router.
- [ ] **Phase 54: Admin TUI Protected Paths + Bypass Alerts Screens** — operator UX for the two new server surfaces.
- [ ] **Phase 55: Monitor-Only / Audit-Only Per-Policy Enforcement Mode** — safe-rollout mode every industry DLP requires before production deployment.
- [ ] **Phase 56: SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004)** — fold SEED-004 in: device enumeration, two new ABAC attributes, admin TUI extension.
- [ ] **Phase 57: Operational Deployment Guide + AV/EDR Allowlist + UAT** — the milestone ship gate; per-vendor allowlist procedures, hash publishing, and real-Windows UAT (folds in former HARD-05).
- [ ] **Phase 58: Differentiators Bundle (cuttable to v0.10.1 if scope pressure hits)** — cuttable as a unit to v0.10.1 if scope pressure hits; otherwise materially improves deployability.

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
**Plans:** 1 plan (60-01)

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
**Plans:** 1 plan (60-01)

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
**Plans:** 1 plan (60-01)

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
**Plans:** 1 plan (60-01)
**UI hint**: yes

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
**Plans:** 1 plan (60-01)

### Phase 54: Admin TUI Protected Paths + Bypass Alerts Screens
**Goal**: An operator can fully manage Protected Paths and triage Bypass Alerts from the admin TUI without touching SQLite, the registry, or any raw config file.
**Depends on**: Phases 52 (Protected Paths server endpoints) and 53 (Bypass Alerts server endpoints)
**Requirements**: UX-01, UX-02
**Success Criteria** (what must be TRUE):
  1. The Protected Paths screen lists every T3/T4 root with a visible diff between policy-derived defaults and operator overrides; add/remove actions round-trip through the admin API and reflect on the agent within one `policy_sync` cycle.
  2. The Bypass Alerts screen shows a paginated event feed with per-event detail (image path + SHA-256, file path, operation, QPC timestamp, correlation reason); the operator can ack/dismiss with a single keypress and filter by severity.
  3. Both screens follow the existing `screens/usb_enforcement.rs` and `screens/print_config.rs` pattern (mod/dispatch/render/client/app.rs extensions); navigation, focus, and Esc-back semantics match every other admin TUI screen.
  4. Eight new client methods (`list_protected_paths`, `create_protected_path`, `update_protected_path`, `delete_protected_path`, `list_bypass_alerts`, `ack_bypass_alert`, plus the two screens' navigation entry points) exist, are unit-tested, and surface server errors as user-readable toasts.
**Plans:** 1 plan (60-01)
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
**Plans:** 1 plan (60-01)
**UI hint**: yes

### Phase 56: SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004)
**Goal**: SD cards, optical (CD/DVD/Blu-ray), and virtual (Daemon Tools / VHD / VHDX / Explorer-mounted ISO) drives are first-class citizens in device enumeration and the ABAC engine, with policy expressible as `source_volume_class → destination_volume_class`.
**Depends on**: Phases 48-50 (hook DLL covers I/O for free regardless of volume class); independent of 51-54
**Requirements**: DRIVE-01, DRIVE-02, DRIVE-03, DRIVE-04
**Success Criteria** (what must be TRUE):
  1. On the test endpoint, an operator inserting an SD card, mounting a VHDX, and mounting an ISO via Explorer each produces a single distinct device-arrival audit event with the correct `volume_class` in {`LocalNTFS`, `USBRemovable`, `SDCard`, `Optical`, `Virtual`, `NetworkShare`} (disambiguated via `Win32_DiskDrive` + `Win32_LogicalDisk` WMI; `GetDriveTypeW` alone is insufficient).
  2. The ABAC attribute set grows from 5 to 7 with `source_volume_class` and `destination_volume_class`; an integration test proves a policy "DENY copy from LocalNTFS T4 to Optical" blocks an actual `CopyFileExW` to a registered optical drive on the test endpoint.
  3. The admin TUI Conditions Builder exposes `source_volume_class` and `destination_volume_class` as dropdowns with the six enum values; the existing USB/disk allowlist screens render SD/Optical/Virtual rows alongside USB without UI breakage.
  4. `WM_DEVICECHANGE` handlers cover virtual mounts (Daemon Tools, ISO mounting via Windows Explorer, VHD/VHDX mount) by registering `GUID_DEVINTERFACE_VOLUME` notification handlers for non-USB volume classes; the 500 ms deferred-processing pattern from v0.7.0 is preserved.
**Plans:** 1 plan (60-01)
**UI hint**: yes

### Phase 57: Operational Deployment Guide + AV/EDR Allowlist + UAT
**Goal**: An operator can deploy v0.10.0 to a real Windows fleet alongside any of the top 6 EDRs without false-positive quarantine, and the milestone passes a UAT smoke test on a real Windows 11 host with real cloud clients, real printers, and real removable media. **This phase is the milestone ship gate.**
**Depends on**: Phases 48-56 (deployment guide must reflect every shipped capability; UAT exercises every shipped feature)
**Requirements**: OPS-01, OPS-02, OPS-03, OPS-04
**Success Criteria** (what must be TRUE):
  1. `docs/operations/deployment-guide.md` exists and documents per-vendor AV/EDR allowlist procedures (with screenshots + console steps + IOC/hash exclusion examples) for Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Carbon Black, Sophos, and Trend Micro Apex One; an operator following the guide can deploy v0.10.0 alongside each EDR without quarantine.
  2. Every shipped binary has SHA-256 + SHA-512 hashes published in `RELEASE_NOTES.md`; the Microsoft binary submission flow (`wdsi/filesubmission`) is documented; a `signtool verify` command for Authenticode timestamp verification is included; reproducible by an operator from the documented commands alone.
  3. The deployment guide explicitly addresses Secure Boot reality (AppInit_DLLs is inert; `siem.appinit_dlls_disabled` will fire), the PPL coverage gap (lsass/MsMpEng/EDR-self) and the DACL-tripwire backstop, `SeSystemProfilePrivilege` preservation across upgrades, and the post-install reboot requirement for hook activation.
  4. UAT executes on a real Windows 11 host with real OneDrive/Google Drive/Dropbox/Box clients, real printers, and real USB/SD/optical/virtual drives; every v0.9.0 cloud-sync regression test plus every v0.10.0 active-blocking scenario passes; the CRIT-04 benchmark gate (<= 25% wall-clock overhead on representative `cargo build` + `Office app launch` workloads) holds; results are captured in `.planning/milestones/v0.10.0-UAT.md`.
**Plans:** 1 plan (60-01)

### Phase 58: Differentiators Bundle (Override + Diagnostic + Hash Evidence + Self-Health)
**Goal**: The four highest-value differentiators ship as a bundle that materially improves operator deployability and forensic posture; cuttable as a unit to v0.10.1 if scope pressure hits.
**Depends on**: Phases 48-57 (every differentiator depends on a prior shipped capability — override needs the hook + UI + audit enrichment, diagnostic mode needs the audit fields, hash evidence needs the file-handle plumbing, self-health needs the cache + injector)
**Requirements**: DIFF-01, DIFF-02, DIFF-03, DIFF-04
**Success Criteria** (what must be TRUE):
  1. On a DENY decision, the user sees a `dlp-user-ui` toast offering "Request override"; submitting a justification round-trips through `POST /admin/overrides`; an admin can grant a TTL-bounded approval (default 1 hour) via the new admin TUI screen, and the user can complete the originally-denied operation within the TTL window.
  2. The diagnostic-mode admin TUI screen displays the full decision tree per blocked event — which hook fired, classification source + age, ABAC subject/resource/action/environment values, matched policy ID + mode, decision latency in microseconds — sufficient to triage a real false-positive without leaving the TUI.
  3. Block events on `WriteFile`/`WriteFileEx` carry a `content_sha256` hash of the would-be-written content (computed via the OS file handle, NOT a second open); audit-event consumers and SIEM relay forward the hash unchanged for forensic chain-of-custody.
  4. The hook DLL emits per-host self-health counters (injected_pids, patched_modules, pipe_round_trips, cache_hit_rate, fail_state) that the admin TUI surfaces on a coexistence dashboard, letting an operator see at a glance which endpoints have healthy hooks and which are degraded by AV/EDR interaction.
**Plans:** 1 plan (60-01)
**UI hint**: yes

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
**Plans:** 1 plan (60-01)
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

---

## Progress Table

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 13. Conditions Builder | 2/2 | Reopened for review | - |
| 14. Policy Create | 2/2 | Reopened for review | - |
| 15. Policy Edit/Delete | 1/1 | Reopened for review | - |
| 16. Policy List/Simulate | 2/2 | Reopened for review | - |
| 17. Import/Export | 2/2 | Reopened for review | - |
| 18. Boolean Mode Engine + Wire Format | 2/2 | Reopened for review | - |
| 19. Boolean Mode TUI Import/Export | 2/2 | Reopened for review | - |
| 20. Operator Expansion | 2/2 | Reopened for review | - |
| 21. In-Place Condition Editing | 1/1 | Reopened for review | - |
| 22. DLP-Common Foundation | 4/4 | Reopened for review | - |
| 23. USB Enumeration in DLP-Agent | 2/2 | Reopened for review | - |
| 24. Device Registry DB + Admin API | 4/4 | Reopened for review | - |
| 25. App Identity Capture in DLP-User-UI | 4/4 | Reopened for review | - |
| 26. ABAC Enforcement Convergence | 5/5 | Reopened for review | - |
| 27. USB Toast Notification | 2/2 | Reopened for review | - |
| 28. Admin TUI Screens | 5/5 | Reopened for review | - |
| 47. Secrets Encryption at Rest (prerequisite) | 1/1 | Reopened for review | - |
| 48. Hook DLL Surface Expansion + Crash Hardening + Build Harness | 5/5 | Complete    | 2026-05-15 |
| 49. Universal Injection — ETW Process Watcher + Allowlist + AppInit Fallback | 0/0 | Not started | - |
| 50. Shared-Memory Classification Cache + Fail-Mode State Machine | 0/0 | Not started | - |
| 51. ntdll Syscall-Stub Trampolines + EDR Coexistence | 0/0 | Not started | - |
| 52. DACL Tripwire + Repair Watcher + Protected Paths + DPAPI Recovery Doc | 0/0 | Not started | - |
| 53. ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring | 0/0 | Not started | - |
| 54. Admin TUI Protected Paths + Bypass Alerts Screens | 0/0 | Not started | - |
| 55. Monitor-Only / Audit-Only Per-Policy Enforcement Mode | 0/0 | Not started | - |
| 56. SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004) | 0/0 | Not started | - |
| 57. Operational Deployment Guide + AV/EDR Allowlist + UAT (ship gate) | 0/0 | Not started | - |
| 58. Differentiators Bundle (cuttable to v0.10.1) | 0/0 | Not started | - |
| 59. Label Service — DB Schema + API + Folder Inheritance + Manual Assignment | 4/4 | Reopened for review | - |
| 60. Data Owner Review Queue + Admin TUI Screen | 1/1 | Reopened for review | - |
| 61. Approval Workflow Engine — T3 Data Owner + T4 Board Digital Signature | 4/4 | Complete   | 2026-05-13 |

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

*Last updated: 2026-05-15 — Phase 48 planned (5 plans: 48-01 through 48-05).*
