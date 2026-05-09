---
id: T01
parent: S01
milestone: M017
key_files:
  - dlp-common/src/abac.rs
  - dlp-agent/src/config.rs
  - dlp-agent/src/server_client.rs
  - dlp-agent/src/service.rs
key_decisions:
  - Action::CLOUD_UPLOAD uses literal variant name serde pattern (no rename), consistent with DRAG_DROP and DiskRegistry variants.
  - AgentConfig uses Option<bool>/Option<u64> for the three new fields to match existing optional config patterns and allow backward-compatible TOML parsing.
  - AgentConfigPayload uses plain bool/bool/u64 with serde(default) to match the server-side JSON push pattern, with a default_hook_classification_timeout_ms() returning 5000 ms.
duration: 
verification_result: passed
completed_at: 2026-05-08T07:52:21.032Z
blocker_discovered: false
---

# T01: Added Action::CLOUD_UPLOAD and cloud/WFP config fields to AgentConfig and AgentConfigPayload

**Added Action::CLOUD_UPLOAD and cloud/WFP config fields to AgentConfig and AgentConfigPayload**

## What Happened

Added the CLOUD_UPLOAD variant to the Action enum in dlp-common/src/abac.rs following the existing DRAG_DROP serde pattern (literal variant name, no rename). Added three unit tests for serialization, deserialization, and distinctness.

Added cloud_hook_enabled (Option<bool>), wfp_filter_enabled (Option<bool>), and hook_classification_timeout_ms (Option<u64>) to AgentConfig in dlp-agent/src/config.rs with #[serde(default)] for backward-compatible TOML parsing.

Added the same three fields to AgentConfigPayload in dlp-agent/src/server_client.rs as bool/bool/u64 with #[serde(default)] and a default_hook_classification_timeout_ms() function returning 5000 ms. Updated all test constructors in server_client.rs, service.rs, and config.rs to include the new fields.

All crates compile and tests pass.

## Verification

cargo check passes for both dlp-common and dlp-agent. All abac tests in dlp-common pass (28 unit tests + 1 cross-crate compat test). All server_client and config tests in dlp-agent pass (57+ tests).

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo check -p dlp-common -p dlp-agent` | 0 | ✅ pass | 1590ms |
| 2 | `cargo test -p dlp-common abac` | 0 | ✅ pass | 240ms |
| 3 | `cargo test -p dlp-agent server_client` | 0 | ✅ pass | 5330ms |

## Deviations

None.

## Known Issues

None.

## Files Created/Modified

- `dlp-common/src/abac.rs`
- `dlp-agent/src/config.rs`
- `dlp-agent/src/server_client.rs`
- `dlp-agent/src/service.rs`
