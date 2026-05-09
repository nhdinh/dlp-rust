---
estimated_steps: 66
estimated_files: 3
skills_used: []
---

# T02: Extend server AgentConfigPayload and DB repository with cloud/print config fields

The server-side `AgentConfigPayload` in `dlp-server/src/admin_api.rs` (line ~273) is missing five fields that the agent-side mirror in `dlp-agent/src/server_client.rs` already declares: `cloud_hook_enabled: bool`, `print_enabled: bool`, `print_xps_timeout_ms: u64`, `print_unclassifiable_action: String`, `print_max_pages: usize`. Without these fields, `GET /admin/agent-config` omits them from the response and `PUT /admin/agent-config` ignores them — the admin CLI cannot configure cloud or print interception.

The DB schema also lacks these columns. The repository layer (`GlobalAgentConfigRow`, `AgentConfigOverrideRow`, and their SQL queries) must be extended alongside the schema migration.

Why this task exists: T03 (CLI screens) reads/writes these fields as JSON keys via `serde_json::Value` round-trip. They must exist in the server payload before T03 ships.

## Steps

1. **Add fields to `AgentConfigPayload` in `dlp-server/src/admin_api.rs`:** After the existing `usb_none_serial_policy` field (line ~286), add:
   ```rust
   /// Whether the cloud sync hook DLL is enabled (M017/S01). Default: false.
   #[serde(default)]
   pub cloud_hook_enabled: bool,
   /// Whether print spooler interception is enabled (M017/S04). Default: false.
   #[serde(default)]
   pub print_enabled: bool,
   /// Timeout in milliseconds for XPS spool file parsing (M017/S04). Default: 5000.
   #[serde(default = "default_print_xps_timeout_ms")]
   pub print_xps_timeout_ms: u64,
   /// Action when a print job cannot be classified (M017/S04). Default: "Block".
   #[serde(default = "default_print_unclassifiable_action")]
   pub print_unclassifiable_action: String,
   /// Maximum pages to parse from an XPS spool file (M017/S04). Default: 100.
   #[serde(default = "default_print_max_pages")]
   pub print_max_pages: usize,
   ```
   Add the four default functions (matching the agent-side defaults in `server_client.rs`): `default_print_xps_timeout_ms() -> u64 { 5000 }`, `default_print_unclassifiable_action() -> String { "Block".to_string() }`, `default_print_max_pages() -> usize { 100 }`. `cloud_hook_enabled` and `print_enabled` use `#[serde(default)]` (bool defaults to false).

2. **Add validation for `print_unclassifiable_action`:** After the existing USB validation block (~line 1631), add:
   ```rust
   const PRINT_UNCLASSIFIABLE_ACTIONS: &[&str] = &["Block", "Allow"];
   if !PRINT_UNCLASSIFIABLE_ACTIONS.contains(&payload.print_unclassifiable_action.as_str()) {
       return Err(AppError::BadRequest(format!(
           "print_unclassifiable_action must be one of: {}",
           PRINT_UNCLASSIFIABLE_ACTIONS.join(", ")
       )));
   }
   ```

3. **Extend `GlobalAgentConfigRow` in `dlp-server/src/db/repositories/agent_config.rs`:** Add five fields after `usb_none_serial_policy`:
   ```rust
   pub cloud_hook_enabled: i64,   // 0/1 bool
   pub print_enabled: i64,        // 0/1 bool
   pub print_xps_timeout_ms: i64,
   pub print_unclassifiable_action: String,
   pub print_max_pages: i64,
   ```
   Similarly extend `AgentConfigOverrideRow` with the same five fields.

4. **Update `get_global` SQL query** to select the five new columns (append after `usb_none_serial_policy` in the SELECT and in the row mapping closure). Column indices shift: `cloud_hook_enabled` = 8, `print_enabled` = 9, `print_xps_timeout_ms` = 10, `print_unclassifiable_action` = 11, `print_max_pages` = 12.

5. **Update `update_global` SQL query** to SET the five new columns (append to the UPDATE SET list and to the `params![]` macro).

6. **Update `get_override` SQL query** similarly (SELECT + row mapping). Column indices: `cloud_hook_enabled` = 7, `print_enabled` = 8, `print_xps_timeout_ms` = 9, `print_unclassifiable_action` = 10, `print_max_pages` = 11.

7. **Update `upsert_override`** to accept and persist the five new parameters. The function currently has `#[allow(clippy::too_many_arguments)]` — add the five new parameters and bind them in the INSERT OR REPLACE statement. Update the INSERT column list and VALUES list.

8. **Update all call sites** in `admin_api.rs` that construct `AgentConfigPayload` from DB rows or construct `GlobalAgentConfigRow`/call `upsert_override` — there are approximately 4 construction sites. Use `..Default::default()` for any serde tests that use struct literal syntax.

9. **Add DB migrations** in `dlp-server/src/db/mod.rs` `run_migrations()`, following the exact Phase 43 pattern. Add five `run_alter` calls for `global_agent_config` and five for `agent_config_overrides`:
   ```
   cloud_hook_enabled INTEGER NOT NULL DEFAULT 0
   print_enabled INTEGER NOT NULL DEFAULT 0
   print_xps_timeout_ms INTEGER NOT NULL DEFAULT 5000
   print_unclassifiable_action TEXT NOT NULL DEFAULT 'Block'
   print_max_pages INTEGER NOT NULL DEFAULT 100
   ```

10. **Update `AgentConfigPayload` serde tests** (~line 3665): the test constructs `AgentConfigPayload` with a struct literal. Add `..Default::default()` to the literal (or add the five new fields explicitly with their default values) so the test compiles.

11. Run `cargo clippy -p dlp-server -- -D warnings` and fix any new warnings. Run `cargo test -p dlp-server` to confirm all tests pass.

## Must-Haves

- [ ] `AgentConfigPayload` in `admin_api.rs` has all five new fields with `#[serde(default)]`
- [ ] Five new DB columns exist in `global_agent_config` and `agent_config_overrides` via `run_migrations()`
- [ ] `GlobalAgentConfigRow` and `AgentConfigOverrideRow` structs match the extended schema
- [ ] All SQL SELECT/UPDATE/INSERT queries include the new columns
- [ ] All `AgentConfigPayload` construction sites in `admin_api.rs` compile
- [ ] `print_unclassifiable_action` is validated to `["Block", "Allow"]`
- [ ] `cargo clippy -p dlp-server -- -D warnings` exits 0
- [ ] `cargo test -p dlp-server` exits 0

## Inputs

- `dlp-server/src/admin_api.rs`
- `dlp-server/src/db/repositories/agent_config.rs`
- `dlp-server/src/db/mod.rs`
- `dlp-agent/src/server_client.rs`

## Expected Output

- `dlp-server/src/admin_api.rs`
- `dlp-server/src/db/repositories/agent_config.rs`
- `dlp-server/src/db/mod.rs`

## Verification

cargo clippy -p dlp-server -- -D warnings && cargo test -p dlp-server
