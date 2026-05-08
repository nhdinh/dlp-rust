---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Admin operation audit logging

Add AuditEvent emission for policy CRUD and password changes in admin_api.rs and admin_auth.rs. Use EventType::AdminAction. Set action_attempted to PolicyCreate|PolicyUpdate|PolicyDelete|PasswordChange. Set agent_id=server, classification=T3, decision=ALLOW. Add integration tests verifying exact SQLite contents.

## Inputs

- `Existing audit_store`
- `Admin API handlers`

## Expected Output

- `Audit emission in handlers`
- `AdminAction events`
- `Integration tests`

## Verification

cargo test --package dlp-server admin_audit_integration
