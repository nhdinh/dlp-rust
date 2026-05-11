# Phase 43 Plan 03: Agent-Side USB Config Pipeline Summary

**Plan:** 43-03
**Phase:** 43
**Subsystem:** dlp-agent (config struct, server client payload, service apply logic)
**Completed:** 2026-05-08
**Duration:** ~20 minutes

---

## Objective

Wire the three USB enforcement config fields through the agent-side config pipeline: payload definition, config struct, and diff/apply logic. Add None guard to prevent spurious "config changed" logs against older servers.

---

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Extend AgentConfig and AgentConfigPayload with USB fields | 08b92c2 | dlp-agent/src/config.rs, dlp-agent/src/server_client.rs |
| 2 | Wire USB config fields into apply_payload_to_config | bdb1ac2 | dlp-agent/src/service.rs |

---

## Key Changes

### dlp-agent/src/config.rs

- Added three `Option<String>` fields to `AgentConfig`:
  - `usb_blocked_failure_mode`
  - `usb_startup_resolution_mode`
  - `usb_none_serial_policy`
- Updated `AgentConfig::default()` test construction
- Added tests:
  - `test_agent_config_usb_fields_deserialize`: TOML parse with custom values
  - `test_agent_config_usb_fields_default`: default AgentConfig has None for all three

### dlp-agent/src/server_client.rs

- Imported shared constants from `dlp_common::usb`
- Added three `String` fields to `AgentConfigPayload` with `#[serde(default = "...")]`
- Added `default_usb_*` helper functions referencing dlp-common constants
- Added tests:
  - `test_agent_config_payload_usb_fields_default_when_missing`: backward compat
  - `test_agent_config_payload_usb_fields_roundtrip`: serde roundtrip

### dlp-agent/src/service.rs

- Imported shared constants from `dlp_common::usb`
- Extended `apply_payload_to_config` with diff/apply for all three USB fields
- **None guard**: skips diff when `cfg` field is `None` and payload equals system default (prevents spurious logs when new agent polls old server)
- **Empty-string guard**: skips apply with warning log when server sends empty string (defense-in-depth)
- Added 4 tests:
  - `test_apply_payload_usb_fields`: basic apply from default cfg
  - `test_apply_payload_usb_fields_no_change`: no diff when values match
  - `test_apply_payload_usb_fields_none_guard`: no diff when cfg=None and payload=default
  - `test_apply_payload_usb_fields_empty_guard`: preserves previous value on empty payload

---

## Verification Results

- `cargo test -p dlp-agent`: 588 passed, 9 ignored
- `cargo clippy -p dlp-agent -- -D warnings`: No issues in modified files (2 pre-existing errors in detection/disk.rs)
- `cargo fmt --check`: Pre-existing formatting issues in dlp-admin-cli only

---

## Deviations from Plan

None. Plan executed exactly as written.

---

## Auth Gates

None.

---

## Known Stubs

None. All USB config fields are fully wired from payload through config to TOML persistence.

---

## Threat Flags

None beyond what is documented in the plan's threat model. The empty-string guard mitigates T-43-06 (Tampering/malformed USB config values) as specified.

---

## Self-Check: PASSED

- [x] `AgentConfig` has three new `Option<String>` fields with `#[serde(default)]`
- [x] `AgentConfigPayload` has three new `String` fields with `#[serde(default = "...")]`
- [x] `apply_payload_to_config` diffs and applies all three fields
- [x] None guard prevents spurious diff when cfg is None and payload equals default
- [x] Empty-string guard skips apply for malformed server payloads
- [x] Config poll loop automatically logs and persists changes
- [x] All dlp-agent tests pass
- [x] Commits recorded: 08b92c2, bdb1ac2
