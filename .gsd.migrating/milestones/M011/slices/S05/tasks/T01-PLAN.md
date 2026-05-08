---
estimated_steps: 1
estimated_files: 4
skills_used: []
---

# T01: Server-side disk registry and admin TUI

Create SQLite disk registry table with agent_id, instance_id, bus_type, encrypted, model, registered_at. Implement GET/POST/DELETE /admin/disk-registry endpoints with JWT auth. Add Disk Registry TUI screen under System menu. Add LDAP Config TUI screen. Emit AdminAction audit events on registry mutations.

## Inputs

- `Existing admin API patterns`
- `TUI screen conventions`
- `LDAP config from Phase 7`

## Expected Output

- `Disk registry table`
- `REST API handlers`
- `Disk Registry TUI`
- `LDAP Config TUI`
- `Audit events`

## Verification

cargo test --package dlp-server admin_api:: && cargo test --package dlp-admin-cli
