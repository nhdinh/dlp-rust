---
gsd_state_version: 1.0
milestone: v0.8.0
milestone_name: - Application-Aware DLP
status: in_progress
stopped_at: Phase 40 complete, proceeding to Phase 41
last_updated: "2026-05-07T00:00:00.000Z"
last_activity: 2026-05-07 — Phase 40 complete, moving to Phase 41
progress:
  total_phases: 4
  completed_phases: 1
  total_plans: 8
  completed_plans: 4
  percent: 50
---

# Project State

## Project Reference

**Project**: DLP-RUST — Enterprise DLP System (NTFS + Active Directory + ABAC)
**Core Value**: Prevent data exfiltration via a layered enforcement stack (NTFS + ABAC + AD identity)
**Current Focus**: v0.8.0 Application-Aware DLP — Phase 41 next

---

## Current Position

Phase: 41 (Browser Origin Clipboard Policies)
Plan: —
Status: Not Started
Last activity: 2026-05-07 — Phase 40 complete (all 4 plans shipped)

## Progress

v0.7.0 [Phase 33 done | Phase 34 done | Phase 35 done | Phase 36 done | Phase 37 done | Phase 38 done | Phase 38.1 done | Phase 38.2 done]
v0.7.1 [Phase 38.3 done | Phase 38.4 done | Phase 38.5 done | Phase 38.6 done]
v0.8.0 [Phase 39 done | Phase 40 done | Phase 41 pending | Phase 42 pending]

---

## Decisions Made

1. Phase 38.2 enforcement scope: PnP CM_Disable_DevNode + Volume DACL deny-all as two real-time, OS-enforced layers. API hooking REJECTED; minifilter DEFERRED to v0.8.0+.
2. Phase 38.2 tier-change semantics: enable_usb_device and restore_volume_acl both fire on physical removal only.
3. Phase 38.3-38.6: v0.7.1 Operational Hardening shipped — all gaps closed.
4. EncryptionStatus serde mapping is manual: DB stores fully_encrypted/partially_encrypted; Rust enum serializes as encrypted/suspended.
5. Lock-order invariant: config mutex MUST be acquired and released BEFORE acquiring instance_id_map.write() (T-37-13).
6. Phase 39: UWP App Identity complete — AUMID resolution via GetApplicationUserModelId, ABAC evaluator extended, TUI conditions builder updated.
7. Phase 40: Drag-and-Drop Enforcement complete — WH_GETMESSAGE hook, WM_DROPFILES interception, app identity resolution, ABAC evaluation, service lifecycle integration.

---

## Session Continuity

Last session: 2026-05-07
Stopped at: Phase 40 complete, proceeding to Phase 41
Resume file: None

---

## Pending Todos

Phase 40: Drag-and-Drop Enforcement — COMPLETE
Phase 41: Browser Origin Clipboard Policies — next
Phase 42: Audit Enrichment — App Identity Fields — not started

---

## Blockers

None. Phase 40 complete. Phase 41 is next.

---

## Accumulated Context

### Roadmap Evolution

- v0.8.0 phases 39-42 define Application-Aware DLP:
  - Phase 39: UWP App Identity (APP-07) — DONE
  - Phase 40: Drag-and-Drop Enforcement (APP-08) — DONE
  - Phase 41: Browser Origin Clipboard Policies (BRW-04) — NEXT
  - Phase 42: Audit Enrichment — App Identity Fields (AUDIT-04) — pending
