---
id: T01
parent: S04
milestone: M017
key_files:
  - dlp-common/src/abac.rs
  - dlp-agent/src/config.rs
  - dlp-agent/src/server_client.rs
  - dlp-agent/src/service.rs
  - dlp-agent/Cargo.toml
key_decisions:
  - Used literal variant name serde pattern (no rename) for PRINT action per MEM015 convention
  - Defined local default functions in server_client.rs for print payload defaults rather than adding dlp-common constants, since these defaults are agent-side config concerns
duration: 
verification_result: passed
completed_at: 2026-05-08T15:22:14.140Z
blocker_discovered: false
---

# T01: Added ABAC PRINT action, print config fields, hot-reload plumbing, and zip/quick-xml dependencies for M017/S04

**Added ABAC PRINT action, print config fields, hot-reload plumbing, and zip/quick-xml dependencies for M017/S04**

## What Happened

Added the `PRINT` variant to the `Action` enum in `dlp-common/src/abac.rs` with serde literal-variant-name semantics and round-trip tests. Extended `AgentConfig` in `dlp-agent/src/config.rs` with four new Option-wrapped fields: `print_enabled`, `print_xps_timeout_ms`, `print_unclassifiable_action`, and `print_max_pages`. Mirrored these as plain types with serde defaults in `AgentConfigPayload` in `dlp-agent/src/server_client.rs`, including dedicated default helper functions. Wired diff/apply logic into `apply_payload_to_config` in `dlp-agent/src/service.rs`, following the USB field pattern with None guards (to avoid spurious change logs when an old server omits the fields) and an empty-string guard for `print_unclassifiable_action`. Updated all test struct literals across both crates to include the new fields. Added `"Win32_Graphics_Printing"` to the `windows` crate features and `zip = "2"` and `quick-xml = "0.36"` to `dlp-agent/Cargo.toml`. Added comprehensive tests: PRINT action serde round-trip, print field apply/no-change/none-guard/empty-guard cases.

## Verification

cargo check -p dlp-agent passes with zero new warnings; cargo test -p dlp-common -p dlp-agent --lib passes all 549 tests (144 dlp-common + 405 dlp-agent)

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo check -p dlp-agent` | 0 | ✅ pass | 2200ms |
| 2 | `cargo test -p dlp-common -p dlp-agent --lib` | 0 | ✅ pass | 28900ms |

## Deviations

None

## Known Issues

None

## Files Created/Modified

- `dlp-common/src/abac.rs`
- `dlp-agent/src/config.rs`
- `dlp-agent/src/server_client.rs`
- `dlp-agent/src/service.rs`
- `dlp-agent/Cargo.toml`
