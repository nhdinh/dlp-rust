---
id: M009
title: "v0.8.0 Application-Aware DLP"
status: complete
completed_at: 2026-05-08T05:52:30.213Z
key_decisions:
  - OLE drag-and-drop deferred to WM_DROPFILES hook for v0.8.0
  - Chrome Content Analysis API v1: destination_origin is always None; source_origin maps to paste page URL
  - Thread-local TEST_EVALUATOR_OVERRIDE for parallel test isolation
  - Server-side audit validation as hard gate (400 Bad Request)
  - AGENT-UNKNOWN sentinel as single fallback for unresolvable identity
key_files:
  - dlp-common/src/abac.rs
  - dlp-agent/src/detection/app_identity.rs
  - dlp-agent/src/interception/drag_drop.rs
  - dlp-agent/src/chrome/handler.rs
lessons_learned:
  - UWP AUMID resolution requires IShellItem::GetApplicationUserModelId from process handle
  - WM_DROPFILES hook is simpler than OLE IDropTarget for drag-and-drop interception
  - Chrome Content Analysis API v1 has origin limitations that affect destination tracking
  - Thread-local overrides enable parallel testing with global OnceLock state
---

# M009: v0.8.0 Application-Aware DLP

**v0.8.0 Application-Aware DLP shipped with UWP identity, drag-and-drop, origin policies, and audit enrichment.**

## What Happened

v0.8.0 delivered application-aware DLP with UWP app identity, drag-and-drop enforcement, browser origin clipboard policies, and comprehensive audit enrichment. All 18 requirements validated.

## Success Criteria Results

- UWP AUMID resolution working — PASS (S01)
- Drag-and-drop enforcement working — PASS (S02)
- Browser origin clipboard policies working — PASS (S03)
- All audit events enriched with app identity — PASS (S04)
- All 18 requirements validated — PASS (coverage audit)

## Definition of Done Results

All slices complete with verification evidence. All 18 requirements validated. Cross-slice integration verified. Milestone audit passed.

## Requirement Outcomes

| Requirement | Status | Evidence |
|-------------|--------|----------|
| APP-07 | validated | S01: UWP AUMID resolution and ABAC evaluation |
| APP-08 | validated | S02: Drag-and-drop interception and ABAC enforcement |
| BRW-04 | validated | S03: Chrome origin conditions and admin TUI builder |
| AUDIT-04 | validated | S04: All audit paths include app identity and origin fields |

## Deviations

OLE drag-and-drop (IDropTarget/DoDragDrop) deferred to WM_DROPFILES hook. Chrome Content Analysis API v1 limitation: destination_origin always None.

## Follow-ups

Native browser extension (Chrome/Edge Manifest V3) deferred to post-v0.8.0.
