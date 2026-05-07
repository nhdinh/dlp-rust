# Phase 43 Plan 02: USB Enforcement Config Storage and API Summary

**Plan:** 43-02
**Phase:** 43
**Subsystem:** dlp-server (SQLite config storage, repository, admin API), dlp-common (shared constants)
**Completed:** 2026-05-07
**Duration:** ~29 minutes

---

## Objective

Add three runtime-configurable USB enforcement settings to the dlp-server SQLite config storage, repository, and admin API. Create shared enum constants in dlp-common to prevent value drift across server, agent, and TUI.

---

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create shared USB enum constants in dlp-common | e5f97b5 | dlp-common/src/usb.rs, dlp-common/src/lib.rs |
| 2 | Add DB migration and repository support | ac1a4f4 | dlp-server/src/db/mod.rs, dlp-server/src/db/repositories/agent_config.rs |
| 3 | Extend admin API payload and handlers | af6a6d1 | dlp-server/src/admin_api.rs, dlp-common/src/lib.rs, dlp-common/src/usb.rs |

---

## Key Changes

### dlp-common/src/usb.rs

- Added shared USB enforcement config constants:
  - `USB_FAILURE_MODES`: `["Hard error", "Warning only", "Retry then error"]`
  - `USB_RESOLUTION_MODES`: `["Volume GUID resolution", "VID/PID/serial fallback"]`
  - `USB_NONE_SERIAL_POLICIES`: `["Always Blocked", "Port-based disambiguation", "Allow unregistered"]`
- Added default constants:
  - `DEFAULT_USB_BLOCKED_FAILURE_MODE = "Warning only"`
  - `DEFAULT_USB_STARTUP_RESOLUTION_MODE = "VID/PID/serial fallback"`
  - `DEFAULT_USB_NONE_SERIAL_POLICY = "Always Blocked"`
- Added compile-time tests verifying no duplicate values in any constant array

### dlp-common/src/lib.rs

- Exported all new USB constants for cross-crate consumption

### dlp-server/src/db/mod.rs

- Added 6 `run_alter` migrations (3 for `global_agent_config`, 3 for `agent_config_overrides`)
- Added `test_global_agent_config_usb_columns` test verifying:
  - Columns exist in both tables
  - Seed row has correct default values

### dlp-server/src/db/repositories/agent_config.rs

- Extended `GlobalAgentConfigRow` with three new `String` fields
- Extended `AgentConfigOverrideRow` with three new `String` fields
- Updated `get_global` SELECT and row mapping
- Updated `update_global` UPDATE SET and params
- Updated `get_override` SELECT and row mapping
- Updated `upsert_override` INSERT columns, VALUES, and params (added `#[allow(clippy::too_many_arguments)]`)

### dlp-server/src/admin_api.rs

- Added USB constants import from `dlp_common`
- Extended `AgentConfigPayload` with three new fields using `#[serde(default = "...")]`
- Added `default_usb_*` helper functions
- Updated `get_global_agent_config_handler` to return new fields
- Updated `update_global_agent_config_handler` with:
  - Enum value validation (rejects values not in constant arrays)
  - Unimplemented mode rejection ("Volume GUID resolution", "Port-based disambiguation")
- Updated `get_agent_config_for_agent` with explicit merge logic for override vs global
- Updated `get_agent_config_override_handler` and `update_agent_config_override_handler`
- Updated all test `AgentConfigPayload` constructions
- Added `test_agent_config_payload_usb_fields_default` (serde defaults + roundtrip)
- Added `test_agent_config_payload_usb_fields_enum_validation` (invalid + unimplemented modes)

---

## Verification Results

- `cargo test -p dlp-common`: 147 passed
- `cargo test -p dlp-server --lib`: 236 passed, 2 ignored
- `cargo clippy -p dlp-server -- -D warnings`: No issues
- `cargo clippy -p dlp-common -- -D warnings`: No issues
- `cargo fmt --check`: Clean

---

## Deviations from Plan

None. Plan executed exactly as written.

---

## Auth Gates

None.

---

## Known Stubs

None. All data sources are wired to the database.

---

## Threat Flags

None beyond what is documented in the plan's threat model. The validation in `update_global_agent_config_handler` mitigates T-43-03 (Tampering/invalid config values) as specified.

---

## Self-Check: PASSED

- [x] `dlp-common/src/usb.rs` exports all constants
- [x] `dlp-common/src/lib.rs` re-exports constants
- [x] `dlp-server/src/db/mod.rs` has 6 run_alter migrations
- [x] `dlp-server/src/db/repositories/agent_config.rs` has updated CRUD
- [x] `dlp-server/src/admin_api.rs` has extended payload and handlers
- [x] All tests pass
- [x] Clippy clean
- [x] Format clean
- [x] Commits recorded: e5f97b5, ac1a4f4, af6a6d1
