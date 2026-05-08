# S05: Server-Side Disk Registry + Admin TUI (Phases 37, 38, 38.1)

**Goal:** Admin manages disk allowlist via REST API and TUI. Server stores fleet-wide disk registry.
**Demo:** Admin manages disk allowlist via REST API and TUI. Server stores fleet-wide disk registry in SQLite.

## Must-Haves

- 1. SQLite disk registry with agent_id, instance_id, bus_type, encrypted, model
- 2. GET/POST/DELETE /admin/disk-registry
- 3. Admin TUI disk registry screen
- 4. LDAP config TUI screen

## Proof Level

- This slice proves: tested

## Integration Closure

Server-side complement to agent-side enforcement. Audit events for admin actions.

## Verification

- Admin action audit events.

## Tasks

- [x] **T01: Server-side disk registry and admin TUI** `est:6h`
  Create SQLite disk registry table with agent_id, instance_id, bus_type, encrypted, model, registered_at. Implement GET/POST/DELETE /admin/disk-registry endpoints with JWT auth. Add Disk Registry TUI screen under System menu. Add LDAP Config TUI screen. Emit AdminAction audit events on registry mutations.
  - Files: `dlp-server/src/db.rs`, `dlp-server/src/admin_api.rs`, `dlp-admin-cli/src/screens/render.rs`, `dlp-admin-cli/src/screens/dispatch.rs`
  - Verify: cargo test --package dlp-server admin_api:: && cargo test --package dlp-admin-cli

## Files Likely Touched

- dlp-server/src/db.rs
- dlp-server/src/admin_api.rs
- dlp-admin-cli/src/screens/render.rs
- dlp-admin-cli/src/screens/dispatch.rs
