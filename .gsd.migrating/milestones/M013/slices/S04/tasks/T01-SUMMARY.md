---
id: T01
parent: S04
milestone: M013
key_files:
  - dlp-admin-cli/src/screens/render.rs
  - dlp-admin-cli/src/screens/dispatch.rs
key_decisions:
  - (none)
duration: 
verification_result: passed
completed_at: 2026-05-08T05:45:45.349Z
blocker_discovered: false
---

# T01: In-place condition editing with pre-filled 3-step picker.

**In-place condition editing with pre-filled 3-step picker.**

## What Happened

Added edit_index to ConditionsBuilder. Implemented condition_to_prefill helper. Added 'e' key handler. Updated step-3 commit to replace at original index when editing. Updated render title/hint for edit mode. Added unit tests for edit, save, cancel, and attribute-change reset.

## Verification

Admin TUI tests pass.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test --package dlp-admin-cli` | 0 | ✅ pass | 15000ms |

## Deviations

None. Completed during original v0.5.0 phase execution (2026-04-21).

## Known Issues

None.

## Files Created/Modified

- `dlp-admin-cli/src/screens/render.rs`
- `dlp-admin-cli/src/screens/dispatch.rs`
