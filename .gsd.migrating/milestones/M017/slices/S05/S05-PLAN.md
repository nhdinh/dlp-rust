# S05: Integration & UAT

**Goal:** Ship admin CLI screens for cloud and print config, fix pre-existing admin-cli clippy gate, and extend the server AgentConfigPayload + DB schema with cloud/print fields — closing M017's last open deliverables and proving the full milestone passes its quality gate.
**Demo:** Run full UAT: cloud upload blocked, print blocked, share link detected, all audit events flow to SIEM, admin CLI configures thresholds, TC-30..33 and TC-50..52 pass.

## Must-Haves

- cargo clippy -p dlp-admin-cli -- -D warnings exits 0; cargo clippy -p dlp-server -- -D warnings exits 0; cargo test -p dlp-server exits 0 (AgentConfigPayload serde tests pass with new fields); cargo test -p dlp-admin-cli exits 0 (106+ tests pass, new cloud/print screen constant tests included); cargo build --workspace exits 0; cargo test --test comprehensive exits 0 (172/172 — no regressions).

## Proof Level

- This slice proves: contract — verifies compile-time correctness, serde round-trips, and unit-level screen constant invariants; live admin-CLI round-trip to a running server is out of automated scope

## Integration Closure

Upstream surfaces consumed: dlp-server/src/admin_api.rs (AgentConfigPayload), dlp-server/src/db/mod.rs (run_migrations), dlp-server/src/db/repositories/agent_config.rs (GlobalAgentConfigRow/AgentConfigOverrideRow), dlp-admin-cli/src/app.rs (Screen enum), dlp-admin-cli/src/screens/dispatch.rs (handle_system_menu + load/save actions), dlp-admin-cli/src/screens/render.rs (SystemMenu draw + new draw_cloud_config/draw_print_config). New wiring: two Screen variants + two constants modules + two load/save action pairs + two render functions + SystemMenu expanded from 7 to 9 items. What remains before M017 is truly usable end-to-end: live smoke test (copy T4 file to OneDrive sync folder → block toast; print T4 doc → job cancelled; copy OneDrive share link → alert emitted); these require a real Windows host with sync clients installed and are out of automated CI scope.

## Verification

- Run the task and slice verification checks for this slice.

## Tasks

- [x] **T01: Fix four pre-existing clippy errors in dlp-admin-cli/src/screens/dispatch.rs** `est:30m`
  Four clippy errors in dispatch.rs prevent `cargo clippy -p dlp-admin-cli -- -D warnings` from passing, which blocks the S05 quality gate. Three are `doc_lazy_continuation` (orphan doc comment lines that continue a preceding doc block but are separated by a non-doc line, causing clippy to treat them as dangling continuation lines). One is `needless_borrow`. This task fixes all four with minimal, surgical edits — no logic changes.
  - Files: `dlp-admin-cli/src/screens/dispatch.rs`
  - Verify: cargo clippy -p dlp-admin-cli -- -D warnings && cargo test -p dlp-admin-cli

- [x] **T02: Extend server AgentConfigPayload and DB repository with cloud/print config fields** `est:1h`
  The server-side `AgentConfigPayload` in `dlp-server/src/admin_api.rs` (line ~273) is missing five fields that the agent-side mirror in `dlp-agent/src/server_client.rs` already declares: `cloud_hook_enabled: bool`, `print_enabled: bool`, `print_xps_timeout_ms: u64`, `print_unclassifiable_action: String`, `print_max_pages: usize`. Without these fields, `GET /admin/agent-config` omits them from the response and `PUT /admin/agent-config` ignores them — the admin CLI cannot configure cloud or print interception.
  - Files: `dlp-server/src/admin_api.rs`, `dlp-server/src/db/repositories/agent_config.rs`, `dlp-server/src/db/mod.rs`
  - Verify: cargo clippy -p dlp-server -- -D warnings && cargo test -p dlp-server

- [x] **T03: Add CloudConfig and PrintConfig admin CLI screens wired into SystemMenu** `est:1.5h`
  The admin CLI's `SystemMenu` tops out at index 5 ('USB Enforcement') with a back item at index 6. This task adds two new screens — `CloudConfig` (one boolean toggle: `cloud_hook_enabled`) and `PrintConfig` (five fields: `print_enabled` bool, `print_xps_timeout_ms` numeric, `print_unclassifiable_action` picker, `print_max_pages` numeric, `cloud_hook_enabled` is NOT on print config) — wired into the menu at indices 6 and 7 respectively, with Back shifting to index 8. The implementation follows established patterns: `cloud_config.rs` constants module follows `usb_enforcement.rs`; `print_config.rs` follows the same shape. Rendering follows `draw_usb_enforcement_config` for cloud (picker-only) and `draw_ldap_config` for print (bool + numeric + picker mix). Dispatch follows `handle_usb_enforcement_config` / `handle_ldap_config` as appropriate.
  - Files: `dlp-admin-cli/src/screens/cloud_config.rs`, `dlp-admin-cli/src/screens/print_config.rs`, `dlp-admin-cli/src/screens/mod.rs`, `dlp-admin-cli/src/app.rs`, `dlp-admin-cli/src/screens/dispatch.rs`, `dlp-admin-cli/src/screens/render.rs`
  - Verify: cargo clippy -p dlp-admin-cli -- -D warnings && cargo test -p dlp-admin-cli

## Files Likely Touched

- dlp-admin-cli/src/screens/dispatch.rs
- dlp-server/src/admin_api.rs
- dlp-server/src/db/repositories/agent_config.rs
- dlp-server/src/db/mod.rs
- dlp-admin-cli/src/screens/cloud_config.rs
- dlp-admin-cli/src/screens/print_config.rs
- dlp-admin-cli/src/screens/mod.rs
- dlp-admin-cli/src/app.rs
- dlp-admin-cli/src/screens/render.rs
