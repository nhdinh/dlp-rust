---
id: T01
parent: S05
milestone: M014
key_files:
  - dlp-admin-cli/src/screens/render.rs
  - dlp-admin-cli/src/app.rs
key_decisions:
  - (none)
duration: 
verification_result: passed
completed_at: 2026-05-08T05:46:43.772Z
blocker_discovered: false
---

# T01: Policy import/export with conflict detection and native file dialogs.

**Policy import/export with conflict detection and native file dialogs.**

## What Happened

Implemented export to JSON with pretty-printing and user-chosen path. Implemented import with conflict diff and ImportConfirm screen. Abort-on-first-failure. Native file dialogs via rfd. Fixed GET path bug (commit 7dda578).

## Verification

Admin TUI tests pass.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test --package dlp-admin-cli` | 0 | ✅ pass | 15000ms |

## Deviations

TOML export deferred as POLICY-F4 due to serde tag incompatibility.

## Known Issues

None.

## Files Created/Modified

- `dlp-admin-cli/src/screens/render.rs`
- `dlp-admin-cli/src/app.rs`
