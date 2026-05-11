---
gsd_state_version: 1.0
milestone: v0.10.0
milestone_name: Real-Time File Access Prevention
status: planning
last_updated: "2026-05-11T18:13:54.761Z"
last_activity: 2026-05-11
progress:
  total_phases: 0
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

**Project:** DLP-RUST — Enterprise DLP System (NTFS + Active Directory + ABAC)
**Core Value:** Prevent data exfiltration via a layered enforcement stack (NTFS + ABAC + AD identity)
**Current Focus:** Milestone v0.10.0 (Real-Time File Access Prevention) — defining requirements. Phase 47 (HARD-01 Secrets Encryption at Rest) shipped 2026-05-11 and carries forward as a v0.10.0 prerequisite. v1.0.0 Enterprise Hardening dropped; HARD-02..08 moved to Out of Scope (see PROJECT.md).

---

## Current Position

Phase: Not started (defining requirements)
Plan: —
Status: Defining requirements
Last activity: 2026-05-11 — Milestone v0.10.0 started

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
v0.10.0 [Phase 47 done | next phases TBD by roadmapper] (active — defining requirements)
```

---

## Recent Decisions

1. Milestone pivot 2026-05-12: v1.0.0 Enterprise Hardening dropped; v0.10.0 Real-Time File Access Prevention is the new active milestone.
2. Architecture stays user-mode: no kernel minifilter, no kernel driver, no EV cert. Real-blocking achieved via hybrid Option C (IAT hooks + DACL tripwire + ETW bypass detection).
3. v0.10.0 generalizes the v0.9.0 cloud-sync hook DLL pattern to all user-mode processes via `AppInit_DLLs` + agent-driven `CreateRemoteThread` on process-creation events.
4. Direct-syscall bypass closed by in-memory Detours-style trampoline on ntdll syscall stubs.
5. Asymmetric fail semantics: fail-closed for T3/T4 on agent-unreachable, fail-open for T1/T2. Hook DLL holds a local `path → classification` cache to make decisions without a live pipe.
6. DACL tripwire is defense-in-depth on T3/T4 root paths only (not blanket); repair watcher reverts/maintains under AD group changes and file moves.
7. ETW Kernel-File consumer surfaces suspected syscall-bypass events through SIEM, alert router, and a new admin TUI Bypass Alerts screen.
8. SEED-004 (SD / optical / virtual drive monitoring) folded into v0.10.0; coverage comes mostly for free via the IAT-hook surface, plus admin TUI policy UX.
9. HARD-01 Phase 47 artifacts retained at `.planning/phases/47-secrets-encryption-at-rest/` — the DPAPI-recovery handoff originally slated for v1.0.0 Phase 52 now folds into v0.10.0's narrower operational documentation surface.
10. AV/EDR allowlist for global DLL injection is an operational landmine — v0.10.0 ships a deployment guide phase rather than running through smoke testing without it.

## Blockers

None.

## Next Action

```
/gsd-roadmapper  (auto-invoked by /gsd-new-milestone)
```

After the roadmapper writes ROADMAP.md, the immediate next step will be:

```
/gsd-discuss-phase 48
```

Phase 48 will be the first v0.10.0 phase (continuous numbering — Phase 47 was the last shipped). The roadmapper will determine the exact phase breakdown from REQUIREMENTS.md.

Active surface to consume in v0.10.0 implementation:

- `dlp-hook-dll/` — cloud-sync hook DLL. v0.10.0 generalizes injection target, expands patched IAT surface, adds ntdll syscall-stub patching.
- `dlp-agent/src/cloud_enforcer.rs` and `hook_injector.rs` — proven injection / named-pipe / fail-closed templates that the universal hook DLL will reuse.
- `dlp-agent/src/wfp_manager.rs` — defense-in-depth pattern; DACL tripwire watcher follows similar shape.
- `dlp-common/src/classification.rs` — classification feeds the local hook DLL cache and the asymmetric fail semantics.
- `AppState { pool, crypto, policy_store, siem, alert, ad }` (Phase 47) — every new admin TUI screen and ETW consumer reads from this struct.

---

## Historical Context

`.planning.legacy/STATE.md` preserves the v0.8.1-era state at the time of the GSD format migration. `.gsd.legacy/STATE.md` (gitignored) preserves the milestone-slice-task tooling state through M017 (v0.9.0). All historical decisions surface through `.planning.legacy/` milestone audits and `.gsd.legacy/milestones/M*/`.
