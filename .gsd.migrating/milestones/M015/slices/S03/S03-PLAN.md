# S03: Admin Operation Audit Logging (Phase 9)

**Goal:** Emit structured audit events for admin operations.
**Demo:** Policy CRUD and password changes emit AuditEvent with EventType::AdminAction. Queryable via API.

## Must-Haves

- 1. Policy create/update/delete audited
- 2. Password changes audited
- 3. EventType::AdminAction
- 4. Queryable via GET /audit/events

## Proof Level

- This slice proves: tested

## Integration Closure

Provides audit trail for S05 policy changes.

## Verification

- Admin action audit events in SQLite.

## Tasks

- [x] **T01: Admin operation audit logging** `est:3h`
  Add AuditEvent emission for policy CRUD and password changes in admin_api.rs and admin_auth.rs. Use EventType::AdminAction. Set action_attempted to PolicyCreate|PolicyUpdate|PolicyDelete|PasswordChange. Set agent_id=server, classification=T3, decision=ALLOW. Add integration tests verifying exact SQLite contents.
  - Files: `dlp-server/src/admin_api.rs`, `dlp-server/src/admin_auth.rs`, `dlp-server/tests/admin_audit_integration.rs`
  - Verify: cargo test --package dlp-server admin_audit_integration

## Files Likely Touched

- dlp-server/src/admin_api.rs
- dlp-server/src/admin_auth.rs
- dlp-server/tests/admin_audit_integration.rs
