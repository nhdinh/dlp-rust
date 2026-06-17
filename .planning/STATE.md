---
gsd_state_version: 1.0
milestone: v0.10.0
milestone_name: Real-Time File Access Prevention
status: verifying
stopped_at: Plan 01 complete — ready for Plan 02
last_updated: "2026-06-17T19:35:02.772Z"
last_activity: 2026-06-18 -- Phase 53.1 Plan 02 complete (Agent IPC routing for BypassAlert)
progress:
  total_phases: 41
  completed_phases: 31
  total_plans: 147
  completed_plans: 137
  percent: 76
---

# Project State

## Project Reference

**Project:** DLP-RUST — Enterprise DLP System (NTFS + Active Directory + ABAC)
**Core Value:** Prevent data exfiltration via a layered enforcement stack (NTFS + ABAC + AD identity)
**Current Focus:** Phase 53.1 — close-gap-etw-03-add-bypassalert-to-ipcpayloadv1-and-route-i

---

## Current Position

Phase: 53.1 (close-gap-etw-03-add-bypassalert-to-ipcpayloadv1-and-route-i) — VERIFYING
Plan: 4 of 4
Status: Phase complete — ready for verification
Last activity: 2026-06-18 -- Phase 53.1 Plan 02 complete (Agent IPC routing for BypassAlert)

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
v0.10.0 [Phase 47 done (prereq) | Phases 48–56 done | Phases 57–58 active] (in progress)
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
| 56 | SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004) | DRIVE-01..04 |
| 56.1 | Close gap DRIVE-03/04 — add volume class fields to HookRequest and ABAC path (INSERTED) | TBD |
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
| 66.1 | Close gap: WORKFLOW-04 — wire ApprovalCache into enforcement | WORKFLOW-04 |
| 67 | Print Watermarking — XPS Overlay | WATERMARK-01..02 |
| 68 | Email/Outlook Interception + Browser Upload Detection | EMAIL-01..02 |
| 68.1 | Close gap: DEVICE-05/TAMPER-03/04 — wire tamper detection to SIEM and health | DEVICE-05, TAMPER-03, TAMPER-04 |
| 69 | RDP File Redirection + Bluetooth Transfer Blocking | RDP-01, BT-01 |
| 70 | Backup Policy Docs + Ransomware Heuristics + Canary Files | BCK-01..03 |

Research flags on Phases 51 (HEAVY — ntdll/EDR), 53 (MEDIUM — ETW correlation), 57 (MEDIUM — vendor allowlist procedures). See ROADMAP.md "Research Flags" section.

---

## Recent Decisions

1. **2026-06-18: Phase 53.1 Plan 02 complete.** Added `submit_bypass_alert` to `BypassCorrelator` with agent-side enrichment (agent_id, severity, correlation_reason, image_path). Updated `handle_connection` in `dlp-agent/src/hook_ipc.rs` to deserialize `IpcEnvelope` first, then fall back to legacy `HookRequest`. Routes `BypassAlert` to bypass correlator via `crossbeam_channel::Sender`. Added `HookIpcServer::with_bypass_channel()` and `with_approval_cache_and_bypass()` constructors. Wired `BypassCorrelator::run()` to consume `bypass_rx` with 4th spawned task in `spawn_blocking`. Updated `service.rs` to create unbounded bypass channel pair. 11 new tests (3 submit_bypass_alert + 6 hook_ipc envelope + 2 bypass channel). cargo check clean, cargo clippy -D warnings clean, cargo fmt clean. Commits `3a6ccde`, `ad1fa38`, `b6503bc`, `e5c7ecb`. ETW-03 requirement satisfied. Plan 02 of 4 complete in Phase 53.1.
2. **2026-06-17: Phase 53.1 Plan 01 complete.** Added `BypassAlert(BypassAlert)` as 5th variant to `IpcPayloadV1` in `dlp-common/src/hook_ipc.rs`; bincode round-trip test passes; cross-crate references in dlp-agent and dlp-hook-dll compile cleanly. 309 dlp-common tests pass, clippy clean (-D warnings), cargo fmt clean. Commits `46f601b` (feat) and `83566be` (style). ETW-03 requirement satisfied. Plan 01 of 4 complete in Phase 53.1.
2. **2026-06-17: Phase 53.1 planned.** Gap closure for ETW-03 / INT-BLOCK-01: 4 plans created (Wave 0 test stubs + 3 implementation waves). Scope: add `BypassAlert(BypassAlert)` variant to `IpcPayloadV1` in `dlp-common`, route agent `handle_connection` to `BypassCorrelator::submit_bypass_alert`, and wrap hook DLL `emit_bypass_alert` in `IpcEnvelope::V1`. Verification passed. Ready for `/gsd-execute-phase 53.1`.
2. **2026-06-17: Phase 18 execution verified complete.** `PolicyMode` enum (ALL/ANY/NONE), `Policy.mode` field, DB `mode` column with idempotent migration, wire format round-trip, mode-aware evaluator, and full test coverage were all found already implemented. Verification: `cargo test --workspace` passes (no failures), `cargo clippy -- -D warnings` clean, `cargo fmt --check` clean. SonarQube scanner could not reach localhost:9000 (server unavailable). Phase 18 marked complete in STATE.md.
3. Milestone pivot 2026-05-12: v1.0.0 Enterprise Hardening dropped; v0.10.0 Real-Time File Access Prevention is the new active milestone.
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
20. **2026-05-27: Phase 52 Plan 05 complete.** DPAPI recovery runbook (`docs/operations/dpapi-recovery.md`) with re-init-from-env-vars and restore-from-backup flows, PowerShell verification snippets, UAT checklist (7 positive + 6 negative cases). Audit wiring verified: `DaclTamperDetected` routes to SIEM with `triggers_alert=true`, `DaclTripwireTooLarge` routes with `triggers_alert=false`. Full workspace test suite passes (520 lib tests), clippy clean (-D warnings), cargo build --workspace passes. Beads issue `dlp-rust-aq4` closed. DACL-05 requirement satisfied. Phase 52 COMPLETE (all 7 plans).
21. **2026-05-28: Phase 53 Plan 04 complete.** Bypass correlator matching ETW Kernel-File events against hook DLL journal entries. Extended BypassReason with NoHookJournal/OpMismatch; extended BypassAlert with 10 v2 fields and #[serde(default)] backward compat. QPC calibration pair at startup (CR-01), on-demand journal discovery with exponential backoff capped at 30s (CR-02), exact filename allowlist (WR-01), severity mapping with reduced mode capping crit->warn (WR-03), image SHA cache with 1h/5min TTL (WR-06), PID reuse detection (WR-07), alert batching with UUID batch_id and max 3 retries with new batch_id per retry (WR-08, WR-10, IN-02), explicit file_object wiring from ETW event (CR-08). 28 unit tests, 689 dlp-agent tests pass, 252 dlp-common tests pass, clippy clean (-D warnings). ETW-03 requirement satisfied.
22. **2026-05-28: Phase 53 Plan 05 complete.** Server-side bypass alert storage: `bypass_alerts` SQLite table with CHECK constraints, 5 indexes (including pid per WR-05), composite unique constraint for dedup (WR-08). `BypassAlertsRepository` with list_by_filters, insert, insert_batch, ack_by_id, get_by_id — 15 unit tests. Three HTTP routes: POST /audit/bypass (agent JWT, max 100 alerts, v1+v2 deserialization), GET /admin/bypass-alerts (admin JWT, paginated filtered), POST /admin/bypass-alerts/{id}/ack (admin JWT, idempotent). 14 integration tests. SIEM relay for all alerts; alert router for crit severity. 542+ dlp-server lib tests pass, 14 integration tests pass, clippy clean (-D warnings), cargo build --workspace passes. ETW-04 requirement satisfied.
23. **2026-05-28: Phase 53 Plan 06 complete.** SIEM + alert router wiring verification: 3 unit tests in `siem_connector.rs` (`test_relay_bypass_alert_detected`, `test_relay_etw_consumer_gated_off`, `test_relay_skips_non_siem_events`), 1 unit test in `alert_router.rs` (`test_send_alert_crit_severity`), 6 integration tests in `bypass_alerts_integration.rs` (file_object preservation CR-08, mixed severity DB state, SIEM payload structure, crit/warn routing predicates, EtwConsumerGatedOff semantics CR-09). 20 total integration tests pass. Full workspace lib tests pass. Clippy clean on workspace libs. ETW-05 requirement satisfied. Phase 53 COMPLETE (all 6 plans).
24. **2026-05-28: Phase 54 Plan 04 complete.** BypassAlertList TUI screen: dispatch handler with optimistic ack (stable ID rollback, pending_ack_ids double-ack prevention), severity filter cycling (f), hide-acknowledged toggle (h), pagination (PgUp/PgDn), detail popup (Enter). Render function with severity badges (crit=Red+BOLD, warn=Yellow, info=Blue), relative time formatting, path truncation, human-friendly correlation reasons, acknowledged row dimming. 12 new unit tests (6 dispatch + 6 render). 184 dlp-admin-cli tests pass. Clippy clean (-D warnings). UX-02 requirement satisfied.
25. **2026-05-28: Phase 54 Plan 06 complete.** Integration verification: full workspace build with zero warnings, all 39 test suites pass (lib + tests), clippy clean (-D warnings) across workspace, cargo fmt clean. Fixed SystemMenu consistency between dispatch.rs and render.rs (added missing "Syslog Config" item). Added `system_menu_item_count_and_order` test verifying 14 items and correct cycling. Fixed cross-crate BypassAlert struct compatibility in dlp-hook-dll (added v2 field defaults). Fixed v1 backward compat integration test (added required DB fields for CHECK constraints). 188 dlp-admin-cli tests pass. Phase 54 COMPLETE (all 6 plans).
26. **2026-06-05: Phase 57 complete.** Operational Deployment Guide + AV/EDR Allowlist + UAT ship gate. Deliverables: `docs/operations/deployment-guide.md` (master deployment guide with pre-flight checks, 6-vendor EDR allowlist procedures, hash verification, WDSI submission), `docs/RELEASE_NOTES.md` (SHA-256/SHA-512 hash generation commands, Authenticode verification, WDSI steps), 6 UAT PowerShell scripts (`Uat-CloudSync.ps1`, `Uat-PrintBlock.ps1`, `Uat-HookDll.ps1`, `Uat-DaclTripwire.ps1`, `Uat-EtwNtdll.ps1`, `Uat-Benchmark.ps1`), `.planning/milestones/v0.10.0-UAT.md` (test matrix with 8 groups, 30+ test cases, CRIT-04 benchmark gate). OPS-01..04 requirements satisfied. Phase 57 COMPLETE (all 6 plans).
27. **2026-06-07: Phase 64 Plan 01 complete.** Core data types for expanded device identity: `DeviceHealthStatus` enum (4 variants with Ord ordering), `EndpointIdentity` struct (5 fields with serde default), `PolicyCondition::DeviceHealth` variant (op + value pattern), `Subject.device_health` field. 13 new unit tests (9 in endpoint.rs, 4 in abac.rs). 299 total tests pass. Clippy clean. cargo fmt clean. DEVICE-01, DEVICE-02, DEVICE-05 requirements satisfied.
28. **2026-06-13: Phase 68.1 Plan 01 complete.** Server-side `IngestEventsResponse` with `tamper_detected_for_agent` and `chain_break_count`. Synthetic `ChainBreakDetected` events routed to SIEM relay and syslog queue. Agent-side `IngestResponse` with `#[serde(default)]` backward compat. `AuditBuffer::flush` checks tamper flag and calls `report_tamper_detected()`. 13 dlp-server tests pass, 829 dlp-agent tests pass, clippy clean, fmt clean.
29. **2026-06-16: Phase 16 Plan 01a complete.** Verified PolicyList TUI implementation matches 5-column spec (Priority/Name/Action/Enabled/Mode) with global_mode parameter, render_global_override_banner call, Char('n') branch to PolicyCreate, client-side sort with priority ascending + name tiebreak, malformed priority sinking via u32::MAX. Build passes, 210 tests pass. POLICY-01 requirement satisfied.
30. **2026-06-13: Phase 68.1 Plan 03 complete.** Admin TUI Audit Integrity screen: `audit_integrity.rs` constants module, `Screen::AuditIntegrityList` and `Screen::AuditIntegrityDetail` variants, `AuditIntegrityFilter` enum, `EngineClient::list_audit_integrity` client method, `handle_audit_integrity_list`/`handle_audit_integrity_detail`/`action_load_audit_integrity` dispatch handlers, `draw_audit_integrity_list`/`draw_audit_integrity_detail` render functions with OK/BROKEN banner and chain break detail. SystemMenu expanded to 15 items. 14 new unit tests (3 audit_integrity + 3 dispatch + 2 client + 4 render + 2 updated). 210 dlp-admin-cli tests pass, clippy clean (-D warnings), fmt clean. TAMPER-04 requirement satisfied. Phase 68.1 COMPLETE (all 3 plans).

## Blockers

None.

## Next Action

### Immediate: Phase 53.1 verification

All 4 plans in Phase 53.1 are complete. Ready for verification (/gsd:verify-phase or /gsd:verify-work).

**Scope:** Verify all 4 plans in Phase 53.1: Plan 00 (Wave 0 test stubs), Plan 01 (IpcPayloadV1 BypassAlert variant), Plan 02 (Agent IPC routing), Plan 03 (Hook DLL emit_bypass_alert).

---

## Historical Context

`.planning.legacy/STATE.md` preserves the v0.8.1-era state at the time of the GSD format migration. `.gsd.legacy/STATE.md` (gitignored) preserves the milestone-slice-task tooling state through M017 (v0.9.0). All historical decisions surface through `.planning.legacy/` milestone audits and `.gsd.legacy/milestones/M*/`. The v1.0.0 abandonment (2026-05-12) is captured in PROJECT.md "Dropped from v1.0.0 Enterprise Hardening" and REQUIREMENTS.md Out of Scope; HARD-01 remains the sole shipped v1.0.0 artifact and carries forward as v0.10.0 Phase 47 prerequisite.

## Session Continuity

Last session: 2026-06-17T18:55:33.526Z
Stopped at: Plan 01 complete — ready for Plan 02
Resume file: .planning/phases/53.1-close-gap-etw-03-add-bypassalert-to-ipcpayloadv1-and-route-i/53.1-01-SUMMARY.md

## Operator Next Steps

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

## Performance Metrics

| Phase | Plan | Duration | Notes |
|-------|------|----------|-------|
| Phase 53.1 P02 | 22m | 3 tasks | 3 files |
| Phase 53.1 P01 | 8m | 2 tasks | 3 files |
| Phase 66.1 P04 | 28m | - tasks | - files |

## Decisions

- [Phase ?]: Extracted compute_override_decision() as pure testable function from run_event_loop
- [Phase ?]: Added approver_sid and approval_expiry to AuditEvent in dlp-common for cross-crate sharing
- [Phase ?]: Hook DLL path approval override DEFERRED to follow-up phase — structural wiring only
