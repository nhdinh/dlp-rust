---
gsd_state_version: 1.0
milestone: v0.10.0
milestone_name: Real-Time File Access Prevention
current_phase: 58.8
current_phase_name: fix-diff-01-and-diff-04
status: executing
stopped_at: Completed 58.8-02-PLAN.md
last_updated: "2026-07-10T04:42:41.382Z"
last_activity: 2026-07-10
last_activity_desc: Completed 58.8-02 server-side DIFF-04 wiring
progress:
  total_phases: 51
  completed_phases: 39
  total_plans: 218
  completed_plans: 186
  percent: 76
---

# Project State

## Project Reference

**Project:** DLP-RUST — Enterprise DLP System (NTFS + Active Directory + ABAC)
**Core Value:** Prevent data exfiltration via a layered enforcement stack (NTFS + ABAC + AD identity)
**Current Focus:** Phase 58.8 — fix-diff-01-and-diff-04

---

## Current Position

Phase: 58.8 (fix-diff-01-and-diff-04) — EXECUTING
Plan: 4 of 4
Status: Ready to execute
Verification: cargo check, clippy, fmt, and dlp-server lib tests pass; sonar-scanner Quality Gate blocked on auth
Last activity: 2026-07-10 — Completed 58.8-02 server-side DIFF-04 wiring

### Previous: Phase 58.5 — COMPLETE

Plan: 1 of 8
Status: Phase 58.5 complete; quick plan `20260706-isolate-dlp-hook-tests` executed to stabilize the dlp-hook-dll test suite.
Verification: 10/10 must-haves verified, 0 gaps
Last activity: 2026-07-06 — Test isolation quick plan complete (329 lib tests passed, integration tests passed, run-isolated-tests.ps1 green)

### Quick Plan: Isolate dlp-hook-dll Tests (2026-07-06)

- Added unique named-pipe override, stoppable `MockAgentServer`, and `reset_for_test()` helper.
- Replaced all `DEFAULT_PIPE_NAME` call sites with `current_pipe_name()`; production still inlines the constant.
- Moved heavy integration tests to `dlp-hook-dll/tests/*.rs` and annotated stateful tests with `#[serial_test::serial]`.
- Fixed `unhook_all_internal` original-pointer read bug and a detached-thread busy-loop in forced background-thread timeout.
- Verification: `cargo fmt --check`, `cargo clippy -p dlp-hook-dll -- -D warnings`, `cargo build -p dlp-hook-dll`, `cargo test -p dlp-hook-dll --lib -- --test-threads=1`, all integration tests, and `run-isolated-tests.ps1` all pass.

Phase: 59 — Label Service — DB Schema + API + Folder Inheritance + Manual Assignment
Status: All 4 plans complete and verified (01: journal writes, 02: bypass correlator routing, 03: VERIFICATION.md artifacts, 04: OPS-04 UAT handoff)

Phase: 57 (operational-deployment-guide-av-edr-allowlist-uat) — IN PROGRESS
Status: 4 of 6 plans complete (UAT execution pending manual verification)

---

## Progress

```
v0.2.0 [Phase 0.1–12 done] (shipped 2026-04-13)
v0.3.0 [Phase 7–11 done]  (shipped 2026-04-16)
v0.4.0 [Phase 13–17 done] (shipped 2026-04-20)
v0.5.0 [Phase 18–21 done] (shipped 2026-04-21)
v0.6.0 [Phase 22–30 done] (shipped 2026-04-29)
v0.7.0 [Phase 33–38.2 done] (shipped 2026-05-06)
v0.7.1 [Phase 38.3–38.6 done] (shipped 2026-05-06)
v0.8.0 [Phase 39–42 done] (shipped 2026-05-07)
v0.8.1 [Phase 43–46 done] (shipped 2026-05-08)
v0.9.0 [M017 / pre-Phase 47 done] (shipped 2026-05-09)
v1.0.0 [abandoned 2026-05-12 — only Phase 47 (HARD-01) shipped]
v0.10.0 [Phase 47 done (prereq) | Phases 48–56 done | Phases 57–58 done | Phase 58.1 verified | Phase 58.2 verified] (in progress — UAT pending)
v0.11.0 [Phases 59–64 done] (shipped 2026-06-09 — Label Service + Workflow + Syslog + Hash + Device)
v0.12.0 [Phases 65–70 planned] (planned — Scanner + Screenshot + Watermark + Email + RDP + BT)
```

---

## Roadmap Summary (v0.11.0)

6 phases. 26/26 active requirements mapped.

| Phase | Goal | Requirements |
|-------|------|--------------|
| 47 (prereq) | Secrets Encryption at Rest (shipped 2026-05-11) | HARD-01 |
| 48 | Hook DLL Surface Expansion + Crash Hardening + Build Harness | BLOCK-01..04, BLOCK-10 |
| 49 | Universal Injection — ETW Process Watcher + Allowlist + AppInit Fallback | BLOCK-05..07 |
| 50 | Shared-Memory Classification Cache + Fail-Mode State Machine | CACHE-01..06, FAIL-01..03 |
| 50.1 | Close gap FAIL-01/02/03 — verify ISOLATED->RESYNC->HEALTHY recovery at runtime (INSERTED) | TBD |
| 51 | ntdll Syscall-Stub Trampolines + EDR Coexistence | BLOCK-08, BLOCK-09 |
| 52 | DACL Tripwire + Repair Watcher + Protected Paths + DPAPI Recovery Doc | DACL-01..05 |
| 53 | ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring | ETW-01..05 |
| 53.1 | Close gap ETW-03 — add BypassAlert to IpcPayloadV1 and route in agent hook_ipc (INSERTED) | ETW-03 |
| 54 | Admin TUI Protected Paths + Bypass Alerts Screens | UX-01, UX-02 |
| 55 | Monitor-Only / Audit-Only Per-Policy Enforcement Mode | MODE-01 |
| 55.1 | Close gap MODE-01 — read global_enforcement_mode in BypassCorrelator (INSERTED) | TBD |
| 56 | SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004) | DRIVE-01..04 |
| 56.1 | Close gap DRIVE-03/04 — add volume class fields to HookRequest and ABAC path (INSERTED) | TBD |
| 57 | Operational Deployment Guide + AV/EDR Allowlist + UAT (ship gate) | OPS-01..04 |
| 58 | Differentiators Bundle (cuttable to v0.10.1) | DIFF-01..04 |
| 58.1 | Close v0.10.0 ship-gap verification items (INSERTED) | OPS-04, ETW-03, DIFF-04 |
| 58.2 | Fix double HookIpcServer and wire volume classes (INSERTED) | TBD |
| 58.7 | Close gap: DACL protected_paths wiring (INSERTED) | DACL-01..05 |
| 58.8 | Fix DIFF-01 and DIFF-04 (INSERTED) | DIFF-01, DIFF-04 |
| **v0.11.0** | | |
| 59 | Label Service — DB Schema + API + Folder Inheritance + Manual Assignment | LABEL-01..07 |
| 60 | Data Owner Review Queue + Admin TUI Screen | LABEL-04 |
| 61 | Approval Workflow Engine — T3 Data Owner + T4 Board Digital Signature | WORKFLOW-01..06 |
| 62 | Syslog Forwarder — RFC 5424 + Encrypted Offline Queue | SYSLOG-01..04 |
| 63 | Tamper-Evident Audit — SHA-256 Hash Chain | HASH-01..04 |
| 64 | Device Identity Expansion — Fingerprint + MAC + VPN + Health | DEVICE-01..05 |
| **v0.12.0** | | |
| 65 | File Scanner — Enumeration + Metadata + Rule Classifier (OCR deferred) | SCANNER-01..06 |
| 66 | Screenshot Control + Policy Condition | SCREENSHOT-01..02 |
| 66.1 | Close gap: WORKFLOW-04 — wire ApprovalCache into enforcement | WORKFLOW-04 |
| 67 | Print Watermarking — XPS Overlay | WATERMARK-01..02 |
| 68 | Email/Outlook Interception + Browser Upload Detection | EMAIL-01..02 |
| 68.1 | Close gap: DEVICE-05/TAMPER-03/04 — wire tamper detection to SIEM and health | DEVICE-05, TAMPER-03, TAMPER-04 |
| 69 | RDP File Redirection + Bluetooth Transfer Blocking | RDP-01, BT-01 |
| 70 | Backup Policy Docs + Ransomware Heuristics + Canary Files | BCK-01..03 |

Research flags on Phases 51 (HEAVY — ntdll/EDR), 53 (MEDIUM — ETW correlation), 57 (MEDIUM — vendor allowlist procedures). See ROADMAP.md "Research Flags" section.

---

## Recent Decisions

1. Phase 60 completed 2026-05-12: Added SIEM audit events on confirm/reject, Data Owner scoping via JWT SID claims, scanner_confidence column, department filtering, and ABAC cache invalidation. All tests pass (1576 passed, 9 ignored). Clippy clean.
2. Milestone pivot 2026-05-12: v1.0.0 Enterprise Hardening dropped; v0.10.0 Real-Time File Access Prevention is the new active milestone.
3. Architecture stays user-mode: no kernel minifilter, no kernel driver, no EV cert. Real-blocking achieved via hybrid Option C (IAT hooks + DACL tripwire + ETW bypass detection).
4. v0.10.0 generalizes the v0.9.0 cloud-sync hook DLL pattern to all user-mode processes via agent-driven `CreateRemoteThread` (primary) and AppInit_DLLs (tertiary fallback on non-Secure-Boot endpoints only).
5. Direct-syscall bypass closed by in-memory `retour`-based Detours-style 5-byte JMP trampoline on ntdll syscall stubs; gated behind `enable_ntdll_patching` policy flag (default off; per-customer rollout).
6. Asymmetric fail semantics: fail-closed for T3/T4 on agent-unreachable, fail-open for T1/T2. Hook DLL holds a shared-memory `Global\DlpClassificationCache` to make decisions without a live pipe.
7. DACL tripwire is defense-in-depth on T3/T4 root paths only (not blanket); repair watcher uses `ReadDirectoryChangesW(FILE_NOTIFY_CHANGE_SECURITY)` + 60-s polling backstop with two-phase staged updates to suppress operator-initiated removal false-positives.
8. ETW Kernel-File consumer (via `ferrisetw` 1.2.0) surfaces suspected syscall-bypass events through the existing SIEM relay + alert router and a new admin TUI Bypass Alerts screen.
9. SEED-004 (SD / optical / virtual drive monitoring) folded into v0.10.0 Phase 56; I/O coverage comes for free via the universal hook, plus admin TUI policy UX and two new ABAC attributes (`source_volume_class`, `destination_volume_class`).
10. HARD-01 Phase 47 artifacts retained at `.planning/phases/47-secrets-encryption-at-rest/`. The DPAPI-recovery handoff originally slated for v1.0.0 Phase 52 now folds into v0.10.0 Phase 52 as DACL-05 (`docs/operations/dpapi-recovery.md`).
11. AV/EDR allowlist for global DLL injection is an operational landmine — v0.10.0 ships a deployment guide phase (Phase 57) rather than running through smoke testing without it. Vendor outreach starts at Phase 48 so reference customers exist by Phase 57.
12. Roadmap continuous-numbering: Phase 47 last shipped → v0.10.0 starts at Phase 48 with no gaps (per project convention). 11 active phases total.
13. Monitor-only / audit-only per-policy mode (Phase 55) is a hard requirement for safe production rollout — every industry DLP comparable ships this; not shipping it would make v0.10.0 unable to deploy to production.
14. **2026-05-12: Target architecture documents (`new_docs/`) merged into planning surface.** 47 gap items identified across 10 document areas. Gaps mapped to new requirements (LABEL-, WORKFLOW-, SYSLOG-, HASH-, DEVICE-, SCANNER-, SCREENSHOT-, WATERMARK-, EMAIL-, RDP-, BT-, BCK-). `new_docs/` deleted after merge to maintain single source of truth in `.planning/`.
15. **Pilot-first path selected:** v0.11.0 focuses on Label Service + Data Owner Queue + Approval Workflow (manual labels, no scanner yet). v0.12.0 adds Scanner + remaining endpoint controls. This prioritizes pilot readiness over building a complete scanner first.
16. **2026-05-12 (updated): Explicit minifilter ban reinforced.** Target architecture updated to forbid Windows Minifilter drivers and kernel-mode filesystem interception entirely. The existing user-mode architecture (IAT hooks + DACL tripwire + ETW + WFP + NTFS ACLs) already satisfies this constraint. New requirements ARCH-01..04 and pilot test TC-017 verify compliance. No code changes required — the constraint is architectural documentation and build-audit verification.
17. **2026-05-21: Phase 59 Plan 01 complete.** ResolvedTier enum added to dlp-server with strictness-aware folder inheritance. Tier::strictness_rank() and is_stricter_than() added to dlp-common. LabelCache upgraded to store full CacheEntry metadata. resolve_tier now returns ResolvedTier (not Result<Tier>) and implements D-07b strictest-tier-wins semantics. 18 new tests, 659 total passing, clippy clean.
18. **2026-05-22: Phase 51 Plans 01-04 complete.** EDR detection (edr_detector.rs), thread suspend protocol (thread_suspender.rs), ntdll patcher core with retour (ntdll_patcher.rs), ntdll trampoline bodies (trampolines.rs), and background re-verification thread (background_thread.rs) all shipped. 253 dlp-hook-dll tests pass, clippy clean. BLOCK-08 and BLOCK-09 requirements satisfied.
19. **2026-05-22: Phase 51 Plans 05-06 complete.** BypassAlert IPC types (dlp-common), enable_ntdll_patching config flag (dlp-agent), service startup SIEM emission, OnceLock lazy init integration in lib.rs, and chaos test fixture (1000 threads + 100 patch cycles) all shipped. 253 dlp-hook-dll tests pass, clippy clean. BLOCK-08 and BLOCK-09 requirements satisfied. Phase 51 COMPLETE.
20. **2026-05-27: Phase 52 Plan 06 complete.** Admin API CRUD for protected paths with Windows API validation (GetFullPathNameW), agent config payload extension, and AppState wiring. 520 dlp-server tests pass, all dlp-agent tests pass, clippy clean. DACL-03 requirement satisfied.
21. **2026-05-27: Phase 52 Plan 05 complete.** DPAPI recovery runbook (`docs/operations/dpapi-recovery.md`) with re-init-from-env-vars and restore-from-backup flows, PowerShell verification snippets, UAT checklist (7 positive + 6 negative cases). Audit wiring verified: `DaclTamperDetected` routes to SIEM with `triggers_alert=true`, `DaclTripwireTooLarge` routes with `triggers_alert=false`. Full workspace test suite passes (520 lib tests), clippy clean (-D warnings), cargo build clean. Beads issue `dlp-rust-aq4` closed. DACL-05 requirement satisfied. Phase 52 COMPLETE (all 7 plans).
22. **2026-05-28: Phase 53 Plan 04 complete.** Bypass correlator matching ETW Kernel-File events against hook DLL journal entries. Extended BypassReason with NoHookJournal/OpMismatch; extended BypassAlert with 10 v2 fields and #[serde(default)] backward compat. QPC calibration pair at startup (CR-01), on-demand journal discovery with exponential backoff capped at 30s (CR-02), exact filename allowlist (WR-01), severity mapping with reduced mode capping crit->warn (WR-03), image SHA cache with 1h/5min TTL (WR-06), PID reuse detection (WR-07), alert batching with UUID batch_id and max 3 retries with new batch_id per retry (WR-08, WR-10, IN-02), explicit file_object wiring from ETW event (CR-08). 28 unit tests, 689 dlp-agent tests pass, 252 dlp-common tests pass, clippy clean (-D warnings). ETW-03 requirement satisfied.
23. **2026-05-28: Phase 53 Plan 05 complete.** Server-side bypass alert storage: `bypass_alerts` SQLite table with CHECK constraints, 5 indexes (including pid per WR-05), composite unique constraint for dedup (WR-08). `BypassAlertsRepository` with list_by_filters, insert, insert_batch, ack_by_id, get_by_id — 15 unit tests. Three HTTP routes: POST /audit/bypass (agent JWT, max 100 alerts, v1+v2 deserialization), GET /admin/bypass-alerts (admin JWT, paginated filtered), POST /admin/bypass-alerts/{id}/ack (admin JWT, idempotent). 14 integration tests. SIEM relay for all alerts; alert router for crit severity. 542+ dlp-server tests pass, 14 integration tests pass, clippy clean (-D warnings), cargo build --workspace passes. ETW-04 requirement satisfied.
24. **2026-05-28: Phase 53 Plan 06 complete.** SIEM + alert router wiring verification: 3 unit tests in `siem_connector.rs` (`test_relay_bypass_alert_detected`, `test_relay_etw_consumer_gated_off`, `test_relay_skips_non_siem_events`), 1 unit test in `alert_router.rs` (`test_send_alert_crit_severity`), 6 integration tests in `bypass_alerts_integration.rs` (file_object preservation CR-08, mixed severity DB state, SIEM payload structure, crit/warn routing predicates, EtwConsumerGatedOff semantics CR-09). 20 total integration tests pass. Full workspace lib tests pass. Clippy clean on workspace libs. ETW-05 requirement satisfied. Phase 53 COMPLETE (all 6 plans).
25. **2026-05-28: Phase 54 Plan 04 complete.** BypassAlertList TUI screen: dispatch handler with optimistic ack (stable ID rollback, pending_ack_ids double-ack prevention), severity filter cycling (f), hide-acknowledged toggle (h), pagination (PgUp/PgDn), detail popup (Enter). Render function with severity badges (crit=Red+BOLD, warn=Yellow, info=Blue), relative time formatting, path truncation, human-friendly correlation reasons, acknowledged row dimming. 12 new unit tests (6 dispatch + 6 render). 184 dlp-admin-cli tests pass. Clippy clean (-D warnings). UX-02 requirement satisfied.
26. **2026-05-28: Phase 54 Plan 06 complete.** Integration verification: full workspace build with zero warnings, all 39 test suites pass (lib + tests), clippy clean (-D warnings) across workspace, cargo fmt clean. Fixed SystemMenu consistency between dispatch.rs and render.rs (added missing "Syslog Config" item). Added `system_menu_item_count_and_order` test verifying 14 items and correct cycling. Fixed cross-crate BypassAlert struct compatibility in dlp-hook-dll (added v2 field defaults). Fixed v1 backward compat integration test (added required DB fields for CHECK constraints). 188 dlp-admin-cli tests pass. Phase 54 COMPLETE (all 6 plans).
27. **2026-05-29: Phase 56 complete (all 6 plans).** Volume-class ABAC end-to-end integration tests: 5 passing mock-based tests + 1 hardware-dependent `#[ignore]` test in `dlp-server/tests/volume_class_integration.rs`. Added `inject_volume_class_for_test` helper to `VolumeDetector`. Fixed bincode compatibility by removing `skip_serializing_if` from volume class fields (caused `UnexpectedEof` on deserialize). Fixed all cross-crate `HookRequest` test initializers. Full workspace compiles, clippy clean, fmt clean. DRIVE-01..04 requirements satisfied. Phase 56 COMPLETE.
28. **2026-05-30: Phase 57 Plans 01-04 complete.** Deployment guide (`docs/operations/deployment-guide.md`) with per-vendor AV/EDR allowlist procedures for 6 vendors (Defender, CrowdStrike, SentinelOne, Carbon Black, Sophos, Trend Micro). RELEASE_NOTES.md with SHA-256/SHA-512 hash tables, artifact provenance, signing certificate info, WDSI submission flow, and signtool verification commands. v0.10.0 UAT test plan (`.planning/milestones/v0.10.0-UAT.md`) with 36 scenarios across 10 categories. Deployment reality documentation (57-04) covering Secure Boot, PPL coverage gaps, DACL tripwire backstop, privilege preservation, and reboot requirements. OPS-01, OPS-02, OPS-03 requirements satisfied. OPS-04 (UAT execution) PENDING manual execution on physical Windows 11 host.
29. **2026-05-30: Phase 57 Plans 05-06 complete.** Final integration verification: standardized DLL naming convention (`dlp_hook_dll.dll` with underscore, not hyphen) across all documentation. Added code block language tags to deployment guide for syntax highlighting. Phase 57 status: IN PROGRESS (4 of 6 plans complete). Ship/no-ship decision PENDING UAT results. See `57-VERIFICATION.md` for detailed status.
30. **2026-06-02: Phase 58 complete (all 6 plans).** Differentiators Bundle — override flow, diagnostics, health, hash evidence, admin TUI screens. Key deliverables: IpcPayloadV2 versioned envelope, DiagnosticSnapshot with 18 fields, content_hasher with 100MB/1GB boundaries, diagnostic_ring (1000-entry lock-free buffer), DecisionContext in all 12 trampolines, injected_pids/patched_modules counters, DiagnosticAggregator with 5-min history scanning, connected_pipes registry, concurrent pipe polling with JoinSet, server CachedDiagnostics with rate limiting, GET /admin/diagnostics + /admin/health endpoints, AuditEvent INSERT to SQLite, admin TUI Diagnostic List + Self-Health Dashboard screens, HookResponse.approval_override with TTL enforcement, 30s deduplication with strengthened key. Full workspace: 2158+ tests pass, clippy clean (-D warnings), cargo fmt clean. DIFF-01..04 requirements satisfied. Phase 58 COMPLETE.
31. **2026-06-23: Phase 58.1 verification complete.** Close v0.10.0 ship-gap verification items — ETW journal writes in hook DLL trampolines verified (D-03/D-04), BypassCorrelator::run() consumes bypass_rx and routes to alert storage verified, 7 missing VERIFICATION.md files created (phases 50, 50.1, 52, 53, 53.1, 56, 58), OPS-04 UAT handoff script and companion guide created. 14/14 observable truths verified. 18 tests pass (4 bypass_correlator_rx + 4 bypass_rx_batch + 7 journal_integration + 3 journal_degraded). PowerShell syntax valid. 0 gaps. Status: PASSED. See `58.1-VERIFICATION.md` for full report.
32. **2026-06-24: Phase 58.2 plans executed.** Plan 01: Consolidated HookIpcServer into single instance with HookIpcServerConfig builder, removed BlockingThreads::hook_ipc, wired all DIFF handlers. Plan 02: Added map_hook_action_to_abac, hook_request_to_evaluate_request, get_caller_sid with non-Windows test stub, handler closure with full decision flow (SID resolution -> approval cache -> volume class warning -> offline_decision). Plan 03: Added unit tests for helpers, fixed existing integration tests for API changes, created new hook_ipc_integration.rs with 5 tests proving consolidated server routes all four IpcPayloadV1 frame types. All targeted tests pass.
33. **2026-06-25: Phase 58.2 verification complete.** 10/10 observable truths verified. 0 gaps. All must-haves from all three plans verified. `cargo check -p dlp-agent` passes. `cargo test -p dlp-agent --test hook_ipc_integration` passes (5/5). `cargo test -p dlp-agent --test volume_class_integration` passes (14/14, 1 ignored). Targeted lib tests pass. Status: PASSED. See `58.2-VERIFICATION.md` for full report.

## Blockers

**Phase 57 — UAT Execution Required (Manual)**

- OPS-04 requirement (UAT execution on physical Windows 11 host) is pending manual execution.
- UAT must be run by operator on physical hardware with real cloud clients, real printers, and real USB/SD/optical/virtual drives.
- CRIT-04 benchmark gate (<= 25% wall-clock overhead) must be verified during UAT.
- See `.planning/phases/57-operational-deployment-guide-av-edr-allowlist-uat/57-VERIFICATION.md` for full status.

**Phase 58.8 — SonarCloud Token Auth Gate**

- `sonar-scanner` fails with `Not authorized` for project `nhdinh_dlp-rust` using the exported `SONAR_TOKEN`.
- Tried `sonar.login`, `sonar.token`, and `SONAR_TOKEN` environment variable.
- Quality Gate verification for 58.8-02 is blocked until the token is verified/regenerated at https://sonarcloud.io/account/security.

## Next Action

### Immediate: Close Phase 58.2

Phase 58.2 is verified complete. Next step:

1. **Update STATE.md** to mark Phase 58.2 as verified (done in this update).
2. **Proceed to milestone ship readiness review** — v0.10.0 is now blocked only on Phase 57 UAT execution (OPS-04).

### Background: Phase 57 UAT remains pending

OPS-04 UAT execution on physical Windows 11 hardware is still required before v0.10.0 can ship. Phase 58.2 was pre-ship gap closure and is now complete.

### v0.11.0 Active Phases (Post-v0.10.0 Ship)

Phase 59 and later are complete and shipped as part of v0.11.0.

---

## Historical Context

`.planning.legacy/STATE.md` preserves the v0.8.1-era state at the time of the GSD format migration. `.gsd.legacy/STATE.md` (gitignored) preserves the milestone-slice-task tooling state through M017 (v0.9.0). All historical decisions surface through `.planning.legacy/` milestone audits and `.gsd.legacy/milestones/M*/`. The v1.0.0 abandonment (2026-05-12) is captured in PROJECT.md "Dropped from v1.0.0 Enterprise Hardening" and REQUIREMENTS.md Out of Scope; HARD-01 remains the sole shipped v1.0.0 artifact and carries forward as v0.10.0 Phase 47 prerequisite.

## Session Continuity

Last session: 2026-07-10T04:41:34.693Z
Stopped at: Completed 58.8-02-PLAN.md
Resume file: None

## Operator Next Steps

- Phase 58.2: VERIFIED — no further action needed.
- Phase 58.5 test-isolation quick plan: COMPLETE.
- Phase 57: UAT execution on physical Windows 11 hardware remains the sole blocker for v0.10.0 ship.
- Phase 64: COMPLETE — all 4 plans executed. Run verification (/gsd:verify-phase or /gsd:verify-work).
- Milestone v0.11.0: All 6 phases (59-64) complete. Ready for milestone audit and transition to v0.12.0.

## Accumulated Context

### Roadmap Evolution

- Phase 50.1 inserted after Phase 50: Close gap FAIL-01/02/03 — verify ISOLATED->RESYNC->HEALTHY recovery at runtime (URGENT)
- Phase 53.1 inserted after Phase 53: Close gap ETW-03 — add BypassAlert to IpcPayloadV1 and route in agent hook_ipc (URGENT)
- Phase 56.1 inserted after Phase 56: Close gap DRIVE-03/04 — add volume class fields to HookRequest and ABAC path (URGENT)
- Phase 66.1 inserted after Phase 66: Close gap: WORKFLOW-04 — wire ApprovalCache into enforcement (URGENT)
- Phase 68.1 inserted after Phase 68: Close gap: DEVICE-05/TAMPER-03/04 — wire tamper detection to SIEM and health (URGENT)
- Phase 67.1 inserted after Phase 67: Print Watermarking — XPS Page Geometry + Text Metrics (URGENT)
- Phase 55.1 inserted after Phase 55: Close gap MODE-01 — read global_enforcement_mode in BypassCorrelator (URGENT)
- Phase 58.1 inserted after Phase 58: Close v0.10.0 ship-gap verification items: ETW journal writes, bypass correlator routing, OPS-04 UAT, missing VERIFICATION.md files (URGENT)
- Phase 58.2 inserted after Phase 58.1: Fix double HookIpcServer and wire volume classes (URGENT)
- Phase 58.3 inserted after Phase 58.2: Close gap: OPS-04 — execute physical Windows 11 UAT (URGENT)
- Phase 58.4 inserted after Phase 58.3: Close gap: DIFF-02/03/04 — wire differentiators into hook DLL deny paths (URGENT)
- Phase 58.5 inserted after Phase 58.4: Unhook dlp_hook_dll.dll when dlp-agent is killed/exited (URGENT)
- Phase 58.6 inserted after Phase 58.5: Targeted hook injection: only processes that perform file operations (URGENT)
- Phase 71 added: Implement admin allowlist API handlers in dlp-admin-cli and dlp-server
- Phase 58.7 inserted after Phase 58: Close gap: DACL protected_paths wiring (URGENT)

## Performance Metrics

| Phase | Plan | Duration | Notes |
|-------|------|----------|-------|
| Phase 18 P01 | 8m | 3 tasks | 0 files (verification-only) |
| Phase 53.1 P02 | 22m | 3 tasks | 3 files |
| Phase 53.1 P01 | 8m | 2 tasks | 3 files |
| Phase 66.1 P04 | 28m | - tasks | - files |
| Phase 55.1 P01 | 12m | 3 tasks | 2 files |
| Phase 55.1 P02 | 18m | 2 tasks | 1 file |
| Phase 58.2 P02 | 25min | 2 tasks | 4 files |
| Phase 58.2 P03 | ~45min | 4 tasks | 3 files |
| Phase 58.4 P03 | 25min | 4 tasks | 7 files | DIFF-04 health snapshot emission + ingestion |
| Phase 58.4 P04 | 25min | 3 tasks | 5 files |
| Phase 58.5 P01 | 18 min | 2 tasks | 2 files |
| Phase 58.5 P02 | 47min | 3 tasks | 11 files |
| Phase 58.5 P03 | 95min | 3 tasks | 7 files |
| Phase 58.5 P05 | 8min | 3 tasks | 9 files |
| Phase 58.5 P06 | 25min | 3 tasks | 6 files |
| Phase 58.5 P07 | 55 | 3 tasks | 2 files |
| Phase 58.7 P01 | 12min | 3 tasks | 2 files |
| Phase 58.7-close-gap-dacl-protected_paths-wiring P02 | 48min | 3 tasks | 1 files |
| Phase 58.7-close-gap-dacl-protected_paths-wiring P03 | 35min | 2 tasks | 2 files |
| Phase 58.7 P04 | 10min | 2 tasks | 3 files |
| Phase 58.8-fix-diff-01-and-diff-04 P01 | 90min | 4 tasks | 5 files |
| Phase 58.8-fix-diff-01-and-diff-04 P02 | 50min | 4 tasks | 5 files |
| Phase 58.8-fix-diff-01-and-diff-04 P03 | 20min | 4 tasks | 9 files |

## Quick Tasks Completed

| Date | Slug | Description | Status |
| ---- | ---- | ----------- | ------ |
| 2026-06-21 | construct-hook-ipc-server-wire-bypass | Wired `HookIpcServer` construction and `bypass_tx` into `dlp-agent/src/service.rs`; added shutdown-aware accept loop and unit tests. | complete |
| 2026-06-21 | fix-uat-benchmark-warmup | Fixed `scripts/Uat-Benchmark.ps1` cargo warm-up build failure caused by `$ErrorActionPreference = 'Stop'` treating cargo stderr as terminating error. Added `Invoke-CargoBuildCommand` helper. | complete |
| 2026-06-21 | verify-dlp-user-ui-not-spawned | Checked whether dlp-agent still spawns dlp-user-ui. Finding: it still spawns at startup and on session changes via ui_spawner::init() and session_monitor. | complete |
| 2026-07-06 | isolate-dlp-hook-tests | Stabilized dlp-hook-dll test suite with unique named pipes, stoppable MockAgentServer, reset_for_test() helper, integration-test binaries, and run-isolated-tests.ps1/.sh. | complete |

## Decisions

- [Phase 55.1]: Three-layer defense-in-depth guard pattern for Audit-mode suppression: efficiency at handle_etw_event entry, defense at submit_bypass_alert IPC boundary, safety net at emit_alert emission boundary
- [Phase 55.1]: PerPolicy mode explicitly tested as regression safety — it is the default production config and must NOT suppress bypass alerts
- [Phase ?]: Extracted compute_override_decision() as pure testable function from run_event_loop
- [Phase ?]: Added approver_sid and approval_expiry to AuditEvent in dlp-common for cross-crate sharing
- [Phase ?]: Hook DLL path approval override DEFERRED to follow-up phase — structural wiring only
- [Phase 58.1]: Verification passed 14/14 truths. 0 gaps. 18 tests pass. All key links wired. 7 missing VERIFICATION.md files created. OPS-04 UAT handoff script and companion guide exist and are self-contained.
- [Phase 58.2]: Verification passed 10/10 truths. 0 gaps. All must-haves from all three plans verified. `cargo check -p dlp-agent` passes. Integration tests pass. Targeted lib tests pass. See `58.2-VERIFICATION.md` for full report.
- [Phase 58.4 Plan 03]: Health snapshots use separate HEALTH_EMIT_INTERVAL=100 (distinct from legacy telemetry EMIT_INTERVAL=1000) to give operators fresher dashboard data without altering the legacy telemetry stream.
- [Phase 58.4 Plan 03]: IpcPayloadV1::HealthResponse is used for both agent response to PullHealth and one-way health snapshots pushed by the hook DLL; dual use is intentional for v0.10.0.
- [Phase 58.4 Plan 03]: Health snapshot emission is best-effort: pipe errors are ignored so that health telemetry never blocks the hooked file-operation path.
- [Phase 58.4 Plan 03]: DIFF-04 complete — 303 dlp-hook-dll tests pass, 899 dlp-agent tests pass, 8 integration tests pass, clippy clean. HookHealthSnapshot emitted every 100 pipe round-trips and on every FailState transition; agent-side HealthAggregator ingests one-way frames and maintains 12-snapshot rolling history.
- [Phase 58.4]: Made start_agent_mock_server pub for cross-module test reuse in trampolines.rs
- [Phase ?]: Placed new IpcPayloadV1 variants after HashEvidence to preserve existing bincode discriminant indexes
- [Phase ?]: Included creation_time in PollControl and UnhookAck to support PID-reuse-safe ProcessKey correlation in later waves
- [Phase ?]: UnhookFailure triggers_alert=true; AgentShutdownUnhook and WatchdogSelfUnload trigger no real-time alert
- [Phase ?]: Stored DLL HINSTANCE as raw isize in Mutex because HINSTANCE lacks Send/Sync.
- [Phase ?]: Started control-poll/watchdog thread from enter_hook_call as safest post-attach path.
- [Phase ?]: Used Mutex<Option<Mapping>> instead of OnceLock reset for safe shared-memory unmapping.
- [Phase ?]: Returned None from classify_and_log_path/handle during shutdown for original-API pass-through.
- [Phase ?]: Kept UNHOOK_WAIT_BUDGET at 5 seconds to preserve remaining SHUTDOWN_TIMEOUT budget — The existing service shutdown path has a 10-second SHUTDOWN_TIMEOUT; reserving 5 seconds for DLLs to poll and ack leaves 5 seconds for the rest of shutdown.
- [Phase ?]: Used Vec snapshot from iter_injected to avoid holding DashMap across await points — DashMap guards are not Send/Sync across await boundaries; returning a Vec snapshot keeps the async shutdown code simple and correct.
- [Phase 58.8 Plan 02]: Added Deserialize derives to admin response structs to enable integration-test assertions; no runtime behavior change.
- [Phase 58.8 Plan 02]: Used #[allow(dead_code)] temporarily on agent_auth_middleware so Task 3 could commit without routes, then removed it in Task 4.
- [Phase 58.8 Plan 02]: Keyed per-agent rate limiting on authenticated agent_id from request extensions, falling back to path segment and IP.
- [Phase ?]: Propagated per-thread audit capture token to mock server thread for multi-threaded test isolation — Audit events emitted on the mock server thread were not visible to the test thread's capture sink; a thread-local token propagated to the server thread makes cross-thread assertions deterministic.
- [Phase ?]: Retained unmatched watchdog evidence files and emitted untracked WatchdogSelfUnload audit — Deleting unmatched evidence would lose the signal that a prior agent crash occurred; retaining the file for bounded retry and emitting an untracked audit preserves observability.
- [Phase 58.5]: Rust OnceLock<Mutex<NtdllPatcher>> cannot be reset; reset helper disables NTDLL_PATCHING_ENABLED and unpatches any initialized stubs instead
- [Phase 58.5]: Kept default parallel test runner and serialized only tests that mutate process-global state, rather than forcing --test-threads=1
- [Phase 58.5]: Moved PHASE_58_5_TEST_LOCK from inline #[cfg(test)] mod tests to top-level #[cfg(test)] pub(crate) static so every module can import it directly
- [Phase ?]: [58.5-06] Kept StartDlpControlThread export idempotent and safe to call outside DllMain by delegating to the existing lazy-start control_thread::start_control_thread.
- [Phase ?]: [58.5-06] Cached the export RVA in HookInjector::new so each injection only creates the remote thread, avoiding repeated LoadLibraryExW/GetProcAddress calls.
- [Phase ?]: [58.5-06] Made get_process_creation_time pub so the integration test can query the child process creation time from outside the crate.
- [Phase ?]: [58.5-06] Capped the cooperative unhook budget to min(configured_budget, SHUTDOWN_TIMEOUT - elapsed) so earlier shutdown steps cannot starve the SCM deadline.
- [Phase ?]: Fixed 5-second CLEANUP_RESERVE guarantees remaining teardown steps cannot push service past SHUTDOWN_TIMEOUT.
- [Phase ?]: Reset UNHOOK_ALL_REQUESTED before hook IPC server stop so accept_loop observes normal shutdown and exits cleanly.
- [Phase ?]: Tests asserting on audit events from async code use current-thread tokio runtime to preserve thread-local capture tokens.
- [Phase 58.7]: Introduced a single canonical normalization helper and applied it at every trust boundary rather than letting each consumer canonicalize differently — Prevents case/trailing-slash mismatches between staging table, watcher, and cache
- [Phase 58.7]: Staging table migration runs automatically on DaclStaging::new so in-flight removals are not orphaned by the new key format — Backward-compatible upgrade path for existing staging rows
- [Phase 58.7]: Invalid or traversal paths are filtered with tracing::warn! audit logs rather than failing the entire service startup — Defense-in-depth: reject malicious server payloads without denying service
- [Phase 58.7-close-gap-dacl-protected_paths-wiring]: Grouped all DACL watcher handles into DaclWatcherBundle so the manager can atomically own and replace the entire subsystem — Replaces the previous nine-element tuple, enabling atomic runtime reinitialization in Plan 58.7-03.
- [Phase 58.7-close-gap-dacl-protected_paths-wiring]: Used try_send for Reinit and Shutdown commands to keep config polling and service shutdown non-blocking — Mitigates T-58.7-06 Denial of Service: a stuck manager cannot block config polling or service shutdown.
- [Phase 58.7-close-gap-dacl-protected_paths-wiring]: Retained the poll backstop shutdown sender inside the bundle instead of discarding it — The previous 9-tuple discarded the poll shutdown sender with _poll_shutdown_tx; the bundle now enables full graceful shutdown.
- [Phase 58.7-close-gap-dacl-protected_paths-wiring]: Kept parking_lot::RwLock instead of arc-swap to avoid a new dependency; migration to arc-swap is reserved for proven reader contention — The correlator reads protected_paths on every ETW event and writes only on policy sync. RwLock satisfies the hot path without adding a dependency; the ignored latency test documents the acceptance criterion.
- [Phase 58.7-close-gap-dacl-protected_paths-wiring]: Reordered run_loop_init so the bypass correlator is built before the DACL manager — The manager must hold a clone of the Arc<BypassCorrelator> to call set_protected_paths during Reinit without restarting the correlator task.
- [Phase 58.7-close-gap-dacl-protected_paths-wiring]: Reinit reads a fresh AgentConfig snapshot each time so global_mode cannot become stale — Threat T-58.7-08 requires that Reinit use current global_mode. Building the minimal reinit config inside the command handler from the shared config Arc guarantees a fresh snapshot.
- [Phase 58.7]: Phase 58.7: The per-path removal sequence (get_snapshot -> remove_tripwire_from_path -> mark_applied -> unregister) runs under DaclStaging::with_path_lock to prevent races with the repair task. — Prevents concurrent repair task from observing partial removal state or consuming a snapshot that unregister is about to delete.
- [Phase 58.8]: Pre-create next named-pipe instance in HookIpcServer accept_loop to eliminate fire-and-forget reconnect race — RequestOverride clients connect immediately after a HookRequest response; creating the next pipe during current connection handling removes the recreate window that caused 50% test flakiness.
- [Phase 58.8]: Keep RequestOverride fire-and-forget: agent writes no response frame — The DLL closes the pipe immediately after send_raw_oneway; writing a response risks broken pipe and contradicts the fire-and-forget contract.
- [Phase 58.8]: Fix hook_ipc_integration RequestOverride test to close client pipe and assert handler invocation — The previous test expected an ACK response that is never sent under fire-and-forget semantics, causing deadlock.
- [Phase ?]: Store the full OverrideRequest payload in PendingOverride so the later approval request can be rebuilt exactly from the original hook DLL intent
- [Phase ?]: Forward the complete OverrideRequest to the UI in Pipe1AgentMsg::OverrideRequest so the dialog can render all context without a second round-trip
- [Phase ?]: Use a bounded tokio::sync::mpsc channel (capacity 100) between Pipe 1 dispatch and the service task; try_send with a warning on saturation keeps the synchronous pipe loop non-blocking
- [Phase ?]: Read health_aggregator.get_current_status() every HEALTH_PUSH_INTERVAL (60 s) and submit only when a snapshot is present; failures are logged with tracing::warn! but do not stop the loop
- [Phase ?]: Carry the user's justification in Pipe1UiMsg::UserConfirmed and apply it in the server ApprovalRequest
