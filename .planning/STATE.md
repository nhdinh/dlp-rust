---
gsd_state_version: 1.0
milestone: v0.11.0
milestone_name: Real-Time File Access Prevention
status: planning
last_updated: "2026-05-21T02:55:00.000Z"
last_activity: 2026-05-21
progress:
  total_phases: 14
  completed_phases: 5
  total_plans: 25
  completed_plans: 23
  percent: 38
---

# Project State

## Project Reference

**Project:** DLP-RUST — Enterprise DLP System (NTFS + Active Directory + ABAC)
**Core Value:** Prevent data exfiltration via a layered enforcement stack (NTFS + ABAC + AD identity)
**Current Focus:** Phase 59 — label service

---

## Current Position

Phase: 59
Plan: 01 complete
Status: In progress
Last activity: 2026-05-20
Last activity: 2026-05-14 -- Phase 62 planning complete
Last activity: 2026-05-13 -- All phases reopened for plan re-review
Last activity: 2026-05-12 -- Phase 61 context, UI-SPEC, and 3 plans created
Last activity: 2026-05-12 -- Phase 60 complete, all tasks committed

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

## Blockers

None.

## Next Action

### Immediate: Continue v0.11.0

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
