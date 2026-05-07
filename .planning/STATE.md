---
gsd_state_version: 1.0
milestone: v0.8.1
milestone_name: Deferred Items & Issue Debt
status: planning
last_updated: "2026-05-07T08:09:31.628Z"
last_activity: 2026-05-07
progress:
  total_phases: 0
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

**Project**: DLP-RUST — Enterprise DLP System (NTFS + Active Directory + ABAC)
**Core Value**: Prevent data exfiltration via a layered enforcement stack (NTFS + ABAC + AD identity)
**Current Focus**: Planning next milestone after v0.8.0

---

## Current Position

Phase: Not started (defining requirements)
Plan: —
Status: Defining requirements
Last activity: 2026-05-07 — Milestone v0.8.1 started

## Progress

v0.7.0 [Phase 33 done | Phase 34 done | Phase 35 done | Phase 36 done | Phase 37 done | Phase 38 done | Phase 38.1 done | Phase 38.2 done]
v0.7.1 [Phase 38.3 done | Phase 38.4 done | Phase 38.5 done | Phase 38.6 done]
v0.8.0 [Phase 39 done | Phase 40 done | Phase 41 done | Phase 42 done]

---

## Decisions Made

1. Phase 38.2 enforcement scope: PnP CM_Disable_DevNode + Volume DACL deny-all as two real-time, OS-enforced layers. API hooking REJECTED; minifilter DEFERRED to v0.8.0+.
2. Phase 38.2 tier-change semantics: enable_usb_device and restore_volume_acl both fire on physical removal only.
3. Phase 38.3-38.6: v0.7.1 Operational Hardening shipped — all gaps closed.
4. EncryptionStatus serde mapping is manual: DB stores fully_encrypted/partially_encrypted; Rust enum serializes as encrypted/suspended.
5. Lock-order invariant: config mutex MUST be acquired and released BEFORE acquiring instance_id_map.write() (T-37-13).
6. Phase 39: UWP App Identity complete — AUMID resolution via GetApplicationUserModelId, ABAC evaluator extended, TUI conditions builder updated.
7. Phase 40: Drag-and-Drop Enforcement complete — WH_GETMESSAGE hook, WM_DROPFILES interception, app identity resolution, ABAC evaluation, service lifecycle integration.
8. Phase 41: Browser Origin Clipboard Policies complete — SourceOrigin/DestinationOrigin ABAC condition variants, origin condition matching in evaluator, Chrome handler ABAC evaluation with thread-local test isolation, admin TUI origin conditions builder.
9. Chrome Content Analysis API v1 limitation: destination_origin is always None; source_origin maps to the paste page URL.
10. Thread-local test override (TEST_EVALUATOR_OVERRIDE) eliminates parallel test races for Chrome handler ABAC tests.

---

## Session Continuity

Last session: 2026-05-07T07:42:36.869Z
Stopped at: Phase 43 context gathered (2026-05-07)
Resume file: .planning/phases/phase-43-pnp-disable-fix/phase-43-CONTEXT.md

---

## Pending Todos

None. v0.8.0 milestone complete. Ready for next milestone planning.

---

## Blockers

None. v0.8.0 complete.

---

## Accumulated Context

### Roadmap Evolution

- v0.8.0 Application-Aware DLP shipped (Phases 39-42):
  - Phase 39: UWP App Identity (APP-07) — DONE
  - Phase 40: Drag-and-Drop Enforcement (APP-08) — DONE
  - Phase 41: Browser Origin Clipboard Policies (BRW-04) — DONE
  - Phase 42: Audit Enrichment — App Identity Fields (AUDIT-04) — DONE
