# S05: Integration & UAT — Research

**Date:** 2026-05-09
**Status:** Ready for planning

## Summary

S05 is the integration and acceptance slice for M017. All unit-level work is complete across S01–S04: the workspace builds clean, all 172 comprehensive tests pass (TC-30..TC-33 for cloud, TC-34..TC-37 for share links, TC-50..TC-52 for print), and clippy is clean on `dlp-agent`. The slice has two remaining deliverables:

1. **Admin CLI screens for cloud provider status and print policy config.** The `SystemMenu` currently tops out at `USB Enforcement` (index 5). Two new screens — `CloudConfig` and `PrintConfig` — need to be added to the SystemMenu, wired into dispatch, rendered, and backed by the server's `GET/PUT /admin/agent-config` endpoint. The server's `AgentConfigPayload` struct is missing the `print_enabled`, `print_xps_timeout_ms`, `print_unclassifiable_action`, `print_max_pages`, and `cloud_hook_enabled` fields — these must be added to `dlp-server/src/admin_api.rs` before the CLI screens can read/write them.

2. **Pre-existing clippy failures in `dlp-admin-cli` must be fixed.** Four clippy errors (`doc_lazy_continuation` ×3, `needless_borrow` ×1) in `dlp-admin-cli/src/screens/dispatch.rs` prevent `-D warnings` compilation of the admin-cli crate. These are pre-existing but S05 must close them to achieve a clean gate.

The overall effort is low-risk and follows well-established patterns already present in the codebase. No new technology is involved.

## Recommendation

Decompose S05 into three tasks in dependency order:

1. **T01: Fix pre-existing admin-cli clippy errors** — four doc/borrow lint fixes in `dispatch.rs`. Fastest to clear, unblocks T02/T03 from having to work around the broken clippy gate.
2. **T02: Add cloud/print fields to server `AgentConfigPayload`** — add five `Option`-wrapped fields to `dlp-server/src/admin_api.rs` with `#[serde(default)]`, and update the server DB persistence layer (the existing agent-config read/write handlers in `admin_api.rs`). This is required before the CLI can round-trip cloud/print config.
3. **T03: Add `CloudConfig` and `PrintConfig` admin CLI screens** — add two new `Screen` variants, extend `SystemMenu` to 9 items, add render functions, wire dispatch handlers following the `UsbEnforcementConfig` pattern. Add unit tests for the new screen constants.

## Implementation Landscape

### Key Files

- `dlp-admin-cli/src/screens/dispatch.rs` — Main event dispatch for all screens. Lines 2819, 3027, 4073 have `doc_lazy_continuation` clippy errors; line 3623 has `needless_borrow`. `handle_system_menu` at ~line 210 needs to expand from 7 to 9 items and route new menu entries. `action_load_usb_enforcement_config` (~line 1702) and `action_save_usb_enforcement_config` (~line 1727) are the exact pattern to replicate for cloud and print.
- `dlp-admin-cli/src/screens/render.rs` — Renders all screens. `draw_usb_enforcement_config` (~line 2299) is the template to follow for `draw_cloud_config` and `draw_print_config`. `Screen::SystemMenu` render block at line 88 needs two new menu items (`"Cloud Config"`, `"Print Config"`).
- `dlp-admin-cli/src/screens/usb_enforcement.rs` — 88-line constants module. Two parallel files (`cloud_config.rs`, `print_config.rs`) should be created following the same shape.
- `dlp-admin-cli/src/screens/mod.rs` — Declares submodules. Add `pub mod cloud_config` and `pub mod print_config`.
- `dlp-admin-cli/src/app.rs` — `Screen` enum (~line 436). Add `CloudConfig { config, selected, editing, buffer }` and `PrintConfig { config, selected, editing, buffer }` variants (same field shape as `UsbEnforcementConfig`).
- `dlp-server/src/admin_api.rs` — `AgentConfigPayload` struct at line 273. Add five `#[serde(default)]` fields: `cloud_hook_enabled: bool`, `print_enabled: bool`, `print_xps_timeout_ms: u64`, `print_unclassifiable_action: String`, `print_max_pages: usize`. Update the `AgentConfigPayload` serde tests at ~line 3662.
- `dlp-agent/src/server_client.rs` — `AgentConfigPayload` is the agent-side mirror of the server struct (line ~123). Already has all cloud/print fields. The server-side gap is what drives T02.

### Build Order

1. **T01 first** (fix clippy errors in dispatch.rs) — clears the blocker that prevents `cargo clippy -p dlp-admin-cli -- -D warnings` from passing. No logic changes.
2. **T02 second** (server `AgentConfigPayload` extension) — adds the fields the CLI will read/write. The agent-side `AgentConfigPayload` in `server_client.rs` already has these fields with `serde(default)`, so the agent is backward-compatible with old servers; T02 makes the server forward-compatible.
3. **T03 third** (CLI screens) — depends on T02 so the fields exist in the server payload. Also depends on T01 so the clippy gate passes.

### Verification Approach

- `cargo clippy -p dlp-admin-cli -- -D warnings` → exit 0 (after T01)
- `cargo clippy -p dlp-server -- -D warnings` → exit 0 (after T02)
- `cargo test -p dlp-server` → all tests pass including updated `AgentConfigPayload` serde tests (after T02)
- `cargo test -p dlp-admin-cli` → 106+ tests pass including new constants/screen tests (after T03)
- `cargo build --workspace` → clean, only pre-existing `dlp-hook-dll` dead-code warning
- `cargo test --test comprehensive` → still 172/172 pass (regression check)

## Constraints

- `dlp-server`'s `AgentConfigPayload` persists fields to SQLite via the existing `agent_config` table. The print/cloud fields will need to round-trip as JSON via `serde_json::Value` — check whether the existing persistence layer uses the struct directly or stores raw JSON blobs. If the former, a schema migration may be needed; if the latter (likely, given `usb_blocked_failure_mode` is a `String` in the DB row), no migration is needed.
- The admin CLI uses a `serde_json::Value` round-trip for all config screens — it does NOT deserialize into the full `AgentConfigPayload` struct. This means adding fields to the server struct is sufficient; the CLI reads/writes the blob as JSON and only needs the keys to be present in the response.
- The `UsbEnforcementConfig` pattern uses picker-based editing (cycle through options with Up/Down). Print config fields are a mix of booleans (`print_enabled`), numerics (`print_xps_timeout_ms`, `print_max_pages`), and strings (`print_unclassifiable_action`). The print config screen should handle these three input types — the LDAP config screen (render.rs ~line 2382) handles both boolean toggles and numeric fields and is a better template for `PrintConfig` than `UsbEnforcementConfig`.
- Cloud config only has one boolean field (`cloud_hook_enabled`). Its screen is simpler — follow `UsbEnforcementConfig` pattern with a single toggle row.

## Common Pitfalls

- **SystemMenu item count** — `handle_system_menu` in dispatch.rs has a hardcoded nav count (`nav(selected, 7, key.code)`). Adding two new items requires changing this to `9`. Missing this will cause navigation to wrap incorrectly.
- **Back-return index** — The `Back` action and Esc handler in the new screen handlers must return to `Screen::SystemMenu { selected: N }` where N is the correct 0-based menu index for the new screen. After adding Cloud Config at index 6 and Print Config at index 7, Back must return to `{ selected: 6 }` and `{ selected: 7 }` respectively.
- **Server AgentConfigPayload serde tests** — Tests at `dlp-server/src/admin_api.rs` line ~3662 construct `AgentConfigPayload` with struct literals. Adding required fields will cause compile errors in those tests if they don't include the new fields with `..Default::default()` or explicit values.
- **Print config `unclassifiable_action` validation** — The server has validation for `usb_blocked_failure_mode` (line 1605). The same pattern should be applied to `print_unclassifiable_action` to prevent invalid values (`"Block"` and `"Allow"` only).

## Open Risks

- The server's agent-config persistence may store the full struct as a JSON blob or field-per-field. A grep of the handler (line ~1446) shows individual field mapping from a DB row (`row.usb_blocked_failure_mode`), which implies the SQLite schema has per-field columns. Adding five new fields to the struct without a schema migration will compile but may fail at runtime if the DB doesn't have those columns. This needs verification during T02 execution — either add a migration or confirm the table uses a JSON blob column.

## Current State Summary (as of research)

| Check | Status |
|-------|--------|
| `cargo build --workspace` | PASS (1 pre-existing dead_code warning in dlp-hook-dll) |
| `cargo test --test comprehensive` | PASS (172/172) |
| `cargo clippy -p dlp-agent -- -D warnings` | PASS |
| `cargo clippy -p dlp-admin-cli -- -D warnings` | FAIL (4 errors in dispatch.rs) |
| `cargo test -p dlp-admin-cli` | PASS (106/106) |
| TC-30..TC-33 (cloud_tc) | PASS |
| TC-34..TC-37 (share_link_tc) | PASS |
| TC-50..TC-52 (print_tc) | PASS |
| Admin CLI: Cloud Config screen | MISSING |
| Admin CLI: Print Config screen | MISSING |
| Server AgentConfigPayload: print/cloud fields | MISSING |
