---
id: T01
parent: S04
milestone: M014
key_files:
  - dlp-admin-cli/src/screens/render.rs
  - dlp-admin-cli/src/screens/dispatch.rs
key_decisions:
  - (none)
duration: 
verification_result: passed
completed_at: 2026-05-08T05:46:43.771Z
blocker_discovered: false
---

# T01: Policy list and simulation with priority sort and Esc bug fix.

**Policy list and simulation with priority sort and Esc bug fix.**

## What Happened

Implemented PolicyList with Priority/Name/Action/Enabled columns, priority sort, n-key binding. Added PolicySimulate form with 10 rows. Submit posts to POST /evaluate. Renders matched policy ID, decision, reason. Fixed Esc-key bug (commit e1afee3).

## Verification

Admin TUI tests pass.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test --package dlp-admin-cli` | 0 | ✅ pass | 15000ms |

## Deviations

None. Completed during original v0.4.0 phase execution (2026-04-20).

## Known Issues

None.

## Files Created/Modified

- `dlp-admin-cli/src/screens/render.rs`
- `dlp-admin-cli/src/screens/dispatch.rs`
