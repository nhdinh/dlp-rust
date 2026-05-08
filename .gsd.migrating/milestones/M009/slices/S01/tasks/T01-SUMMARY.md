---
id: T01
parent: S01
milestone: M009
key_files:
  - dlp-common/src/abac.rs
  - dlp-agent/src/detection/app_identity.rs
key_decisions:
  - (none)
duration: 
verification_result: passed
completed_at: 2026-05-08T05:44:07.168Z
blocker_discovered: false
---

# T01: UWP app identity via AUMID implemented and integrated into ABAC.

**UWP app identity via AUMID implemented and integrated into ABAC.**

## What Happened

Implemented UWP AUMID resolution via IShellItem::GetApplicationUserModelId. Added aumid field to AppIdentity struct. Extended ABAC evaluator to match on AUMID. Updated admin TUI conditions builder with AUMID picker. All unit tests pass.

## Verification

Unit tests pass for AUMID resolution and ABAC evaluation.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test --package dlp-agent app_identity:: && cargo test --package dlp-common abac::` | 0 | ✅ pass | 15000ms |

## Deviations

None. Completed during original v0.8.0 phase execution (2026-05-07).

## Known Issues

None.

## Files Created/Modified

- `dlp-common/src/abac.rs`
- `dlp-agent/src/detection/app_identity.rs`
