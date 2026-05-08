---
id: T01
parent: S02
milestone: M009
key_files:
  - dlp-agent/src/interception/drag_drop.rs
  - dlp-agent/src/service.rs
key_decisions:
  - (none)
duration: 
verification_result: passed
completed_at: 2026-05-08T05:44:07.170Z
blocker_discovered: false
---

# T01: Drag-and-drop enforcement via WM_DROPFILES hook with ABAC evaluation.

**Drag-and-drop enforcement via WM_DROPFILES hook with ABAC evaluation.**

## What Happened

Implemented WH_GETMESSAGE hook for WM_DROPFILES interception. Resolved source application identity for both Win32 and UWP drag sources using S01 AppIdentity. Evaluated ABAC policy before drop completion. Wired toast notification and audit event on block. Integrated with service lifecycle.

## Verification

Unit tests pass for drag-and-drop interception and ABAC evaluation.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test --package dlp-agent drag_drop::` | 0 | ✅ pass | 15000ms |

## Deviations

OLE drag-and-drop (IDropTarget/DoDragDrop) deferred to WM_DROPFILES hook for v0.8.0.

## Known Issues

None.

## Files Created/Modified

- `dlp-agent/src/interception/drag_drop.rs`
- `dlp-agent/src/service.rs`
