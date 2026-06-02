---
gsd_state_version: 1.0
milestone: v0.10.0
milestone_name: Real-Time File Access Prevention
status: executing
last_updated: "2026-06-02T08:14:57.891Z"
last_activity: 2026-06-02 -- Phase 58 planning complete
progress:
  total_phases: 15
  completed_phases: 12
  total_plans: 75
  completed_plans: 69
  percent: 80
---

# Project State

## Project Reference

**Project:** DLP-RUST — Enterprise DLP System (NTFS + Active Directory + ABAC)
**Core Value:** Prevent data exfiltration via a layered enforcement stack (NTFS + ABAC + AD identity)
**Current Focus:** Phase 57 — operational-deployment-guide-av-edr-allowlist-uat

---

## Current Position

Phase: 57 (operational-deployment-guide-av-edr-allowlist-uat) — EXECUTING
Plan: 4 of 6
Status: Ready to execute
Last activity: 2026-06-02 -- Phase 58 planning complete

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
v0.10.0 [Phase 47 done (prereq) | Phases 48–58 active] (in progress)
v0.11.0 [Phase 59 done | Phases 60–64 active] (in progress — Label Service + Workflow + Syslog + Hash + Device)
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
| 51 | ntdll Syscall-Stub Trampolines + EDR Coexistence | BLOCK-08, BLOCK-09 |
| 52 | DACL Tripwire + Repair Watcher + Protected Paths + DPAPI Recovery Doc | DACL-01..05 |
| 53 | ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring | ETW-01..05 |
| 54 | Admin TUI Protected Paths + Bypass Alerts Screens | UX-01, UX-02 |
| 55 | Monitor-Only / Audit-Only Per-Policy Enforcement Mode | MODE-01 |
| 56 | SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004) | DRIVE-01..04 |
| 57 | Operational Deployment Guide + AV/EDR Allowlist + UAT (ship gate) | OPS-01..04 |
| 58 | Differentiators Bundle (cuttable to v0.10.1) | DIFF-01..04 |
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
| 67 | Print Watermarking — XPS Overlay | WATERMARK-01..02 |
| 68 | Email/Outlook Interception + Browser Upload Detection | EMAIL-01..02 |
| 69 | RDP File Redirection + Bluetooth Transfer Blocking | RDP-01, BT-01 |
| 70 | Backup Policy Docs + Ransomware Heuristics + Canary Files | BCK-01..03 |

Research flags on Phases 51 (HEAVY — ntdll/EDR), 53 (MEDIUM — ETW correlation), 57 (MEDIUM — vendor allowlist procedures). See ROADMAP.md "Research Flags" section.

---

## Recent Decisions

1. Phase 60 completed 2026-05-12: Added SIEM audit events on confirm/reject, Data Owner scoping via JWT SID claims, scanner_confidence column, department filtering, and ABAC cache invalidation. All tests pass (1576 passed, 9 ignored). Clippy clean.
2. Milestone pivot 2026-05-12: v1.0.0 Enterprise Hardening dropped; v0.10.0 Real-Time File Access Prevention is the new active milestone.
2. Architecture stays user-mode: no kernel minifilter, no kernel driver, no EV cert. Real-blocking achieved via hybrid Option C (IAT hooks + DACL tripwire + ETW bypass detection).
3. v0.10.0 generalizes the v0.9.0 cloud-sync hook DLL pattern to all user-mode processes via agent-driven `CreateRemoteThread` (primary) and AppInit_DLLs (tertiary fallback on non-Secure-Boot endpoints only).
4. Direct-syscall bypass closed by in-memory `retour`-based Detours-style 5-byte JMP trampoline on ntdll syscall stubs; gated behind `enable_ntdll_patching` policy flag (default off; per-customer rollout).
5. Asymmetric fail semantics: fail-closed for T3/T4 on agent-unreachable, fail-open for T1/T2. Hook DLL holds a shared-memory `Global\DlpClassificationCache` to make decisions without a live pipe.
6. DACL tripwire is defense-in-depth on T3/T4 root paths only (not blanket); repair watcher uses `ReadDirectoryChangesW(FILE_NOTIFY_CHANGE_SECURITY)` + 60-s polling backstop with two-phase staged updates to suppress operator-initiated removal false-positives.
7. ETW Kernel-File consumer (via `ferrisetw` 1.2.0) surfaces suspected syscall-bypass events through the existing SIEM relay + alert router and a new admin TUI Bypass Alerts screen.
8. SEED-004 (SD / optical / virtual drive monitoring) folded into v0.10.0 Phase 56; I/O coverage comes for free via the universal hook, plus admin TUI policy UX and two new ABAC attributes (`source_volume_class`, `destination_volume_class`).
9. HARD-01 Phase 47 artifacts retained at `.planning/phases/47-secrets-encryption-at-rest/`. The DPAPI-recovery handoff originally slated for v1.0.0 Phase 52 now folds into v0.10.0 Phase 52 as DACL-05 (`docs/operations/dpapi-recovery.md`).
10. AV/EDR allowlist for global DLL injection is an operational landmine — v0.10.0 ships a deployment guide phase (Phase 57) rather than running through smoke testing without it. Vendor outreach starts at Phase 48 so reference customers exist by Phase 57.
11. Roadmap continuous-numbering: Phase 47 last shipped → v0.10.0 starts at Phase 48 with no gaps (per project convention). 11 active phases total.
12. Monitor-only / audit-only per-policy mode (Phase 55) is a hard requirement for safe production rollout — every industry DLP comparable ships this; not shipping it would make v0.10.0 unable to deploy to production.
13. **2026-05-12: Target architecture documents (`new_docs/`) merged into planning surface.** 47 gap items identified across 10 document areas. Gaps mapped to new requirements (LABEL-, WORKFLOW-, SYSLOG-, HASH-, DEVICE-, SCANNER-, SCREENSHOT-, WATERMARK-, EMAIL-, RDP-, BT-, BCK-). `new_docs/` deleted after merge to maintain single source of truth in `.planning/`.
14. **Pilot-first path selected:** v0.11.0 focuses on Label Service + Data Owner Queue + Approval Workflow (manual labels, no scanner yet). v0.12.0 adds Scanner + remaining endpoint controls. This prioritizes pilot readiness over building a complete scanner first.
15. **2026-05-12 (updated): Explicit minifilter ban reinforced.** Target architecture updated to forbid Windows Minifilter drivers and kernel-mode filesystem interception entirely. The existing user-mode architecture (IAT hooks + DACL tripwire + ETW + WFP + NTFS ACLs) already satisfies this constraint. New requirements ARCH-01..04 and pilot test TC-017 verify compliance. No code changes required — the constraint is architectural documentation and build-audit verification.
16. **2026-05-21: Phase 59 Plan 01 complete.** ResolvedTier enum added to dlp-server with strictness-aware folder inheritance. Tier::strictness_rank() and is_stricter_than() added to dlp-common. LabelCache upgraded to store full CacheEntry metadata. resolve_tier now returns ResolvedTier (not Result<Tier>) and implements D-07b strictest-tier-wins semantics. 18 new tests, 659 total passing, clippy clean.
17. **2026-05-22: Phase 51 Plans 01-04 complete.** EDR detection (edr_detector.rs), thread suspend protocol (thread_suspender.rs), ntdll patcher core with retour (ntdll_patcher.rs), ntdll trampoline bodies (trampolines.rs), and background re-verification thread (background_thread.rs) all shipped. 253 dlp-hook-dll tests pass, clippy clean. BLOCK-08 and BLOCK-09 requirements satisfied.
18. **2026-05-22: Phase 51 Plans 05-06 complete.** BypassAlert IPC types (dlp-common), enable_ntdll_patching config flag (dlp-agent), service startup SIEM emission, OnceLock lazy init integration in lib.rs, and chaos test fixture (1000 threads + 100 patch cycles) all shipped. 253 dlp-hook-dll tests pass, clippy clean. BLOCK-08 and BLOCK-09 requirements satisfied. Phase 51 COMPLETE.
19. **2026-05-27: Phase 52 Plan 06 complete.** Admin API CRUD for protected paths with Windows API validation (GetFullPathNameW), agent config payload extension, and AppState wiring. 520 dlp-server tests pass, all dlp-agent tests pass, clippy clean. DACL-03 requirement satisfied.
20. **2026-05-27: Phase 52 Plan 05 complete.** DPAPI recovery runbook (`docs/operations/dpapi-recovery.md`) with re-init-from-env-vars and restore-from-backup flows, PowerShell verification snippets, UAT checklist (7 positive + 6 negative cases). Audit wiring verified: `DaclTamperDetected` routes to SIEM with `triggers_alert=true`, `DaclTripwireTooLarge` routes with `triggers_alert=false`. Full workspace test suite passes (520 lib tests), clippy clean (-D warnings), cargo build clean. Beads issue `dlp-rust-aq4` closed. DACL-05 requirement satisfied. Phase 52 COMPLETE (all 7 plans).
21. **2026-05-28: Phase 53 Plan 04 complete.** Bypass correlator matching ETW Kernel-File events against hook DLL journal entries. Extended BypassReason with NoHookJournal/OpMismatch; extended BypassAlert with 10 v2 fields and #[serde(default)] backward compat. QPC calibration pair at startup (CR-01), on-demand journal discovery with exponential backoff capped at 30s (CR-02), exact filename allowlist (WR-01), severity mapping with reduced mode capping crit->warn (WR-03), image SHA cache with 1h/5min TTL (WR-06), PID reuse detection (WR-07), alert batching with UUID batch_id and max 3 retries with new batch_id per retry (WR-08, WR-10, IN-02), explicit file_object wiring from ETW event (CR-08). 28 unit tests, 689 dlp-agent tests pass, 252 dlp-common tests pass, clippy clean (-D warnings). ETW-03 requirement satisfied.
22. **2026-05-28: Phase 53 Plan 05 complete.** Server-side bypass alert storage: `bypass_alerts` SQLite table with CHECK constraints, 5 indexes (including pid per WR-05), composite unique constraint for dedup (WR-08). `BypassAlertsRepository` with list_by_filters, insert, insert_batch, ack_by_id, get_by_id — 15 unit tests. Three HTTP routes: POST /audit/bypass (agent JWT, max 100 alerts, v1+v2 deserialization), GET /admin/bypass-alerts (admin JWT, paginated filtered), POST /admin/bypass-alerts/{id}/ack (admin JWT, idempotent). 14 integration tests. SIEM relay for all alerts; alert router for crit severity. 542+ dlp-server lib tests pass, 14 integration tests pass, clippy clean (-D warnings), cargo build --workspace passes. ETW-04 requirement satisfied.
23. **2026-05-28: Phase 53 Plan 06 complete.** SIEM + alert router wiring verification: 3 unit tests in `siem_connector.rs` (`test_relay_bypass_alert_detected`, `test_relay_etw_consumer_gated_off`, `test_relay_skips_non_siem_events`), 1 unit test in `alert_router.rs` (`test_send_alert_crit_severity`), 6 integration tests in `bypass_alerts_integration.rs` (file_object preservation CR-08, mixed severity DB state, SIEM payload structure, crit/warn routing predicates, EtwConsumerGatedOff semantics CR-09). 20 total integration tests pass. Full workspace lib tests pass. Clippy clean on workspace libs. ETW-05 requirement satisfied. Phase 53 COMPLETE (all 6 plans).
24. **2026-05-28: Phase 54 Plan 04 complete.** BypassAlertList TUI screen: dispatch handler with optimistic ack (stable ID rollback, pending_ack_ids double-ack prevention), severity filter cycling (f), hide-acknowledged toggle (h), pagination (PgUp/PgDn), detail popup (Enter). Render function with severity badges (crit=Red+BOLD, warn=Yellow, info=Blue), relative time formatting, path truncation, human-friendly correlation reasons, acknowledged row dimming. 12 new unit tests (6 dispatch + 6 render). 184 dlp-admin-cli tests pass. Clippy clean (-D warnings). UX-02 requirement satisfied.
25. **2026-05-28: Phase 54 Plan 06 complete.** Integration verification: full workspace build with zero warnings, all 39 test suites pass (lib + tests), clippy clean (-D warnings) across workspace, cargo fmt clean. Fixed SystemMenu consistency between dispatch.rs and render.rs (added missing "Syslog Config" item). Added `system_menu_item_count_and_order` test verifying 14 items and correct cycling. Fixed cross-crate BypassAlert struct compatibility in dlp-hook-dll (added v2 field defaults). Fixed v1 backward compat integration test (added required DB fields for CHECK constraints). 188 dlp-admin-cli tests pass. Phase 54 COMPLETE (all 6 plans).
26. **2026-05-29: Phase 56 complete (all 6 plans).** Volume-class ABAC end-to-end integration tests: 5 passing mock-based tests + 1 hardware-dependent `#[ignore]` test in `dlp-server/tests/volume_class_integration.rs`. Added `inject_volume_class_for_test` helper to `VolumeDetector`. Fixed bincode compatibility by removing `skip_serializing_if` from volume class fields (caused `UnexpectedEof` on deserialize). Fixed all cross-crate `HookRequest` test initializers. Full workspace compiles, clippy clean, fmt clean. DRIVE-01..04 requirements satisfied. Phase 56 COMPLETE.
27. **2026-05-30: Phase 57 Plans 01-04 complete.** Deployment guide (`docs/operations/deployment-guide.md`) with per-vendor AV/EDR allowlist procedures for 6 vendors (Defender, CrowdStrike, SentinelOne, Carbon Black, Sophos, Trend Micro). RELEASE_NOTES.md with SHA-256/SHA-512 hash tables, artifact provenance, signing certificate info, WDSI submission flow, and signtool verification commands. v0.10.0 UAT test plan (`.planning/milestones/v0.10.0-UAT.md`) with 36 scenarios across 10 categories. Deployment reality documentation (57-04) covering Secure Boot, PPL coverage gaps, DACL tripwire backstop, privilege preservation, and reboot requirements. OPS-01, OPS-02, OPS-03 requirements satisfied. OPS-04 (UAT execution) PENDING manual execution on physical Windows 11 host.
28. **2026-05-30: Phase 57 Plans 05-06 complete.** Final integration verification: standardized DLL naming convention (`dlp_hook_dll.dll` with underscore, not hyphen) across all documentation. Added code block language tags to deployment guide for syntax highlighting. Phase 57 status: IN PROGRESS (4 of 6 plans complete). Ship/no-ship decision PENDING UAT results. See `57-VERIFICATION.md` for detailed status.

## Blockers

**Phase 57 — UAT Execution Required (Manual)**

- OPS-04 requirement (UAT execution on physical Windows 11 host) is pending manual execution.
- UAT must be run by operator on physical hardware with real cloud clients, real printers, and real USB/SD/optical/virtual drives.
- CRIT-04 benchmark gate (<= 25% wall-clock overhead) must be verified during UAT.
- See `.planning/phases/57-operational-deployment-guide-av-edr-allowlist-uat/57-VERIFICATION.md` for full status.

## Next Action

### Immediate: Complete Phase 57 UAT

Phase 57 is IN PROGRESS (4 of 6 plans complete). Remaining work:

1. **Manual UAT execution** on physical Windows 11 host (OPS-04)
   - Run all 36 scenarios from `.planning/milestones/v0.10.0-UAT.md`
   - Verify CRIT-04 benchmark gate (<= 25% overhead)
   - Record results in UAT document

2. **After UAT completes:**
   - Analyze results and make ship/no-ship decision
   - Update deployment guide with any UAT-discovered corrections
   - Create final VERIFICATION.md with PASS/FAIL determination
   - Update STATE.md and ROADMAP.md with Phase 57 completion

3. **Phase 58** (Differentiators Bundle) can proceed in parallel with UAT execution if resources allow.

### v0.11.0 Active Phases (Post-v0.10.0 Ship)

```
/gsd-autonomous --from 60
```

Phase 60 (Data Owner Review Queue + Admin TUI Screen) is the first active v0.11.0 phase. Standard pattern — no `/gsd-research-phase` needed.

### v0.11.0 Active Phases

1. **Phase 59** — Label Service DB schema + API + folder inheritance + manual assignment
2. **Phase 60** — Data Owner Review Queue + admin TUI screen
3. **Phase 61** — Approval Workflow Engine (T3 Data Owner + T4 Board digital signature)
4. **Phase 62** — Syslog Forwarder (RFC 5424 + encrypted offline queue)
5. **Phase 63** — Tamper-Evident Audit (SHA-256 hash chain)
6. **Phase 64** — Device Identity Expansion (fingerprint + MAC + VPN + health)

Then **v0.12.0**:

7. **Phase 65** — File Scanner (enumeration + metadata + classifier, OCR deferred)
8. **Phase 66** — Screenshot Control
9. **Phase 67** — Print Watermarking
10. **Phase 68** — Email/Outlook Interception
11. **Phase 69** — RDP + Bluetooth Blocking
12. **Phase 70** — Backup Policy + Ransomware Heuristics + Canary Files

Active surface to consume in v0.11.0 implementation:

- `dlp-hook-dll/` — cloud-sync hook DLL. v0.10.0 Phase 48 generalizes injection target, expands patched IAT surface, adds `catch_unwind` + SEH hardening; Phase 51 adds ntdll syscall-stub patching via `retour` 0.3.1.
- `dlp-agent/src/cloud_enforcer.rs` and `hook_injector.rs` — proven injection / named-pipe / fail-closed templates that the universal hook DLL will reuse (Phase 49 generalizes the injector via ETW Kernel-Process trigger).
- `dlp-agent/src/wfp_manager.rs` — defense-in-depth pattern; DACL tripwire watcher (Phase 52) follows similar shape.
- `dlp-common/src/classification.rs` — classification feeds the local hook DLL cache (Phase 50) and the asymmetric fail semantics.
- `AppState { pool, crypto, policy_store, siem, alert, ad }` (Phase 47) — every new admin TUI screen and ETW consumer reads from this struct; Phase 52/53 add `protected_paths`, `bypass_alerts`, `classification_publisher` Arcs.

---

## Historical Context

`.planning.legacy/STATE.md` preserves the v0.8.1-era state at the time of the GSD format migration. `.gsd.legacy/STATE.md` (gitignored) preserves the milestone-slice-task tooling state through M017 (v0.9.0). All historical decisions surface through `.planning.legacy/` milestone audits and `.gsd.legacy/milestones/M*/`. The v1.0.0 abandonment (2026-05-12) is captured in PROJECT.md "Dropped from v1.0.0 Enterprise Hardening" and REQUIREMENTS.md Out of Scope; HARD-01 remains the sole shipped v1.0.0 artifact and carries forward as v0.10.0 Phase 47 prerequisite.

## Plan 50-03 Completed (2026-05-20)

- Hook DLL shared-memory cache reader implemented
- CacheLookup with OnceLock lazy init, split validation, two-tier lookup
- Thread-local LRU (128 entries) with version invalidation
- Hardened path normalization (NT/DOS/UNC, rejects 8.3/ADS/volume GUID)
- Allowlist module with hardcoded system paths
- Trampoline integration: allowlist -> LRU -> cache -> pipe flow
- Tier-gated fast-path: T3/T4 write = deny, T1/T2 = allow
- 119 tests pass, clippy clean
- Commits: 7a87899, 547d209, 93089eb, 3aa0418

## Plan 51-01 Completed (2026-05-22)

- Two-phase EDR detection module (`edr_detector.rs`) with cached module enumeration
- Suspend-all-other-threads protocol (`thread_suspender.rs`) with RIP verification
- `ThreadSuspendGuard` Drop guard guarantees resume even on panic
- No disk-reading functions (D-06 compliance — avoids DoppelGate classifier triggers)
- 24 new tests (10 edr_detector + 14 thread_suspender), 227 total dlp-hook-dll tests pass
- Clippy clean (-D warnings)
- Commits: 7d0fc01, 65ea767

## Plan 51-02 Completed (2026-05-22)

- retour 0.4.0-alpha.4 dependency added for cross-architecture Detours-style trampolines
- Extended HookDescriptor with ntdll_stub_addr and original_ntdll_bytes (Copy-compatible)
- Created NtdllPatcher with per-stub state machine (StubPatchState enum)
- Implemented patch_all_stubs() consulting EDR detector before each patch
- Implemented patch_stub() using thread_suspender::with_suspended_threads for atomic safety
- Implemented unpatch_all_stubs() calling detour.disable() — never reads from disk (D-06)
- Static DETOURS Mutex array for RawDetour handle storage
- 12 unit tests covering state transitions, per-stub granularity, error paths
- All 239 dlp-hook-dll tests pass; clippy clean
- Commits: d9d38e5, a56028d

## Plan 51-03 Completed (2026-05-22)

- Four NtdllTrampoline* functions added: NtCreateFile, NtOpenFile, NtWriteFile, NtSetInformationFile
- All use guard_trampoline + with_reentrancy_guard + fail_closed! pattern
- Path-based trampolines call extract_nt_path; handle-based call classify_and_log_handle
- All call get_original_trampoline() for retour-generated trampoline, with fallback to resolve_ntdll_proc
- NTDLL_STUBS constant activated (removed #[cfg(any())] guard)
- find_detour_for_stub() wired to NTDLL_STUBS lookup
- Pub free function get_original_trampoline() added for trampoline access without NtdllPatcher instance
- 5 export tests added and passing
- All 244 dlp-hook-dll tests pass; clippy clean (-D warnings)
- Commits: a5c4a7b, ecf6f8a

## Plan 51-04 Completed (2026-05-22)

- StubIntegrity enum added (Clean, Overwritten, NotPatched, Unknown) per D-12/D-13
- verify_stub_integrity: reads first 5 bytes, checks 0xE9 JMP + rel32 target in our trampoline range (64KB window)
- mark_stub_overwritten: sets state to Overwritten, emits BypassAlert(HookOverwritten) per D-07
- verify_all_stubs: iterates all 4 stubs independently (per-stub granularity per D-13)
- is_target_in_our_trampoline_range: compares JMP target against NtdllTrampoline* function addresses
- TRAMPOLINE_VERIFY_INTERVAL_MS = 30_000, TRAMPOLINE_VERIFY_TICKS = 300
- start_background_thread extended with optional verify_fn callback
- background_thread_loop calls verify_fn every 300 ticks; existing ISOLATED/RESYNC logic unchanged
- trampolines.rs call site updated to pass None (wiring deferred to Plan 06)
- 12 new tests (7 ntdll_patcher + 5 background_thread), 253 total dlp-hook-dll tests pass
- Clippy clean (-D warnings)
- Commits: f9e4692, 7c90620, b7f4c14

## Plan 51-05 Completed (2026-05-22)

- BypassAlert struct and BypassReason enum added to dlp-common/src/hook_ipc.rs
- Three EventType variants added: NtdllPatchingEnabled, NtdllPatchingEdrDetected, HookOverwritten
- All three new variants wired to routed_to_siem()
- enable_ntdll_patching: Option<bool> added to AgentConfig with serde(default)
- Service startup emits EventType::NtdllPatchingEnabled SIEM event when flag is true
- 5 new tests in dlp-common (bypass_alert_roundtrip, bypass_reason_serde, 3 SIEM routing)
- 2 new tests in dlp-agent (enable_ntdll_patching default + deserialize)
- 197 dlp-common tests pass; 585 dlp-agent tests pass; clippy clean (-D warnings)
- Commits: 9a3ef9d, 7684fae, 49a5b34

## Plan 51-06 Completed (2026-05-22)

- NTDLL_PATCHER OnceLock<Mutex<NtdllPatcher>> added to lib.rs for lazy initialization
- lazy_init_ntdll_patcher function initializes patcher on first hook call (never from DllMain)
- NTDLL_PATCHING_ENABLED AtomicBool controls whether lazy init happens (~1ns fast-path)
- init() reads flag from shared memory stub but does NOT create patcher (avoids DllMain deadlock)
- All four NtdllTrampoline* functions call get_original_trampoline() free function for retour trampoline
- ntdll_patcher module changed to pub for integration test access
- ntdll_chaos_test.rs integration test: 1000 threads + 100 patch/unpatch cycles, marked #[ignore]
- ntdll_patcher_smoke_test runs by default: verifies state machine, get_original_trampoline, verify_stub_integrity
- 253 dlp-hook-dll tests pass; clippy clean (-D warnings)
- Commits: e9fb126, 0f37ba1, 28f2340

## Plan 52-04 Completed (2026-05-27)

- dacl_staging.rs created with StagingState enum, StagingRow struct, DaclStaging data layer
- Per-path locking via DashMap<String, Arc<parking_lot::Mutex<()>>>
- init_staging_table() creates protected_paths_staging with CHECK constraint and two indexes
- Methods: stage_removal, stage_add, mark_applied, is_staged, is_staged_and_applied, get_state, get_row, list_all, gc_expired_rows
- stage_removals() free function for batch integration with config diff logic (Plan 52-07)
- spawn_gc_task() for TTL-based GC with configurable interval
- 15 unit tests covering state machine, per-path locking, concurrent access, GC behavior, idempotency, batch staging, schema validation
- service.rs init_agent_db() creates staging table alongside existing agent tables
- lib.rs exports dacl_staging module
- Clippy clean (-D warnings), cargo fmt clean, cargo build -p dlp-agent passes
- Commit: c8c2787

## Operator Next Steps

- Phase 52: ALL 7 plans complete (DACL Tripwire, Repair Watcher, Protected Paths DB, Staging, DPAPI Recovery Doc, Admin API + Config Sync, Staged Update Integration). Phase 52 COMPLETE.
- Start the next milestone with /gsd-new-milestone
