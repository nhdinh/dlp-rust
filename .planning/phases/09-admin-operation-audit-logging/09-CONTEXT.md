# Phase 9: Admin Operation Audit Logging — Context

**Gathered:** 2026-04-14
**Status:** Ready for planning
**Source:** /gsd-discuss-phase

<domain>
## Phase Boundary

Emit structured `AuditEvent` records for policy CRUD operations (create/update/delete)
and admin password changes, persisted to the `audit_events` table with
`EventType::AdminAction`. Events are queryable via `GET /audit/events?event_type=ADMIN_ACTION`.

**In scope:**
- `EventType::AdminAction` is already defined in `dlp-common/src/audit.rs`
- Policy CRUD handlers in `dlp-server/src/admin_api.rs` (4 routes)
- Password change handler in `dlp-server/src/admin_auth.rs`
- Audit event persistence via `audit_store::ingest_events`

**Out of scope:**
- AD/LDAP integration (Phase 7) — SID field left NULL/empty until Phase 7 populates it
- Rate limiting on audit query endpoint (Phase 8)
- SQLite connection pool (Phase 10)
- Separate admin audit query endpoint (reuse existing `GET /audit/events`)

</domain>

<decisions>
## Implementation Decisions

### A — Audit Event Structure

- **Reuse existing `AuditEvent` struct** from `dlp-common/src/audit.rs` — no new event type needed
- `event_type` = `EventType::AdminAction`
- `agent_id` = `"server"` (the server itself is the actor for admin operations)
- `classification` = `Classification::T3` (admin operations are sensitive/confidential)
- `decision` = `Decision::Allow` for all admin actions (action already succeeded by the time we log)
- `resource_path` = `"type:identifier"` format:
  - Policy create/update/delete: `"policy:<policy_id>"` (e.g., `"policy:pii-block-v2"`)
  - Password change: `"password_change:<username>"` (e.g., `"password_change:admin@corp"`)
- All other file-op-specific fields (`application_path`, `resource_owner`, `network_location`, etc.) left empty/default

### B — Action Enum Variants

**Add four new admin action variants** to `dlp-common/src/abac.rs` `Action` enum:

```rust
pub enum Action {
    // ... existing variants ...
    /// Admin created a new policy.
    PolicyCreate,
    /// Admin updated an existing policy.
    PolicyUpdate,
    /// Admin deleted a policy.
    PolicyDelete,
    /// Admin changed own password.
    PasswordChange,
}
```

Rationale: Admin actions need their own semantic values distinct from file operations.
Using `"admin:policy.create"` as a string would work but is less type-safe than a proper enum variant.

### C — Admin Identity Capture

- `user_name` from JWT token payload (already available in all protected handlers)
- `user_sid` = empty string for now (`""`) — `admin_users` table has no SID column yet; will be populated when AD/LDAP Phase 7 adds it

**Schema change required:** Add `user_sid TEXT NULL` column to `admin_users` table in `dlp-server/src/db.rs` to support future SID capture. This is a NULL-safe column so Phase 9 works without AD integration.

### D — Query API

**No new endpoint.** Use the existing `GET /audit/events` with `event_type=ADMIN_ACTION` filter.

Rationale: The query endpoint already supports `event_type` filtering and JWT auth. A separate `/admin/audit/events` endpoint adds surface area for minimal benefit.

### E — Password Change Audit Scope

**Log successful password changes only.** Failed attempts already return HTTP 401 and are not admin actions — they are authentication failures, not authorization/compliance events.

Failed password attempts are out of scope for admin audit logging (Phase 8 / R-07 rate limiting handles brute-force protection).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase requirement
- `.planning/ROADMAP.md` — Phase 9 section (R-09 requirement, UAT criteria, file list)
- `.planning/REQUIREMENTS.md` — R-09 full text

### Existing audit infrastructure
- `dlp-common/src/audit.rs` — `EventType`, `AuditEvent` struct, `Decision` enum (add Action variants here)
- `dlp-common/src/abac.rs` — `Action` enum (add 4 admin variants here), `Decision` enum
- `dlp-server/src/audit_store.rs` — `ingest_events` handler, DB persistence pattern
- `dlp-server/src/admin_api.rs` — Policy CRUD handlers (lines 398–583), router structure
- `dlp-server/src/admin_auth.rs` — `change_password` handler (line 196+)
- `dlp-server/src/db.rs` — `CREATE TABLE` patterns, `admin_users` table schema (add `user_sid` column)

### Prior phase patterns
- `.planning/phases/06-wire-config-push-for-agent-config-distribution/06-CONTEXT.md` — DB-backed config pattern

### Established patterns to follow
- All admin API routes use `#[derive(serde::Deserialize)]` for request payloads
- Policy handlers use `spawn_blocking` for DB access
- Audit events use `Utc::now()` for timestamp
- JWT `Claims` struct provides `username` field

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `audit_store::ingest_events` — already handles batch event ingestion, no changes needed
- JWT `Claims` extraction via `require_auth` extractor — reuse for admin username
- Existing `Decision::Allow` used elsewhere — consistent

### Established Patterns
- Policy CRUD handlers call `spawn_blocking` for SQLite writes
- All admin routes are JWT-protected via `require_auth` extractor
- Config/audit DB writes follow `app_state.db.lock()` pattern

### Integration Points
- `admin_api.rs` policy handlers → emit `AuditEvent` before returning success response
- `admin_auth.rs` `change_password` → emit `AuditEvent` after successful password update
- Both call `audit_store::ingest_events` (or share the same underlying `spawn_blocking` DB logic)

</code_context>

<specifics>
## Specific Implementation Notes

### Policy CRUD audit emission

In each policy handler, emit audit event **after** the DB transaction commits but **before** returning the HTTP response:

```
POST /admin/policies   → AuditEvent { action: Action::PolicyCreate,  resource_path: "policy:<id>" }
PUT  /admin/policies/{id} → AuditEvent { action: Action::PolicyUpdate, resource_path: "policy:<id>" }
DELETE /admin/policies/{id} → AuditEvent { action: Action::PolicyDelete, resource_path: "policy:<id>" }
```

### Password change audit emission

In `admin_auth::change_password`, after `bcrypt::hash` succeeds and DB is updated, emit:

```
AuditEvent { action: Action::PasswordChange, resource_path: "password_change:<username>" }
```

### admin_users schema change

Add to `admin_users` CREATE TABLE in `db.rs`:

```sql
ALTER TABLE admin_users ADD COLUMN user_sid TEXT;
```

This is `NULL` until AD/LDAP Phase 7 populates it — no migration needed for Phase 9.

</specifics>

<deferred>
## Deferred Ideas

- Separate `GET /admin/audit/events` endpoint — not needed; existing filter works
- Failed password attempt logging — covered by Phase 7 rate limiting (R-07)
- Windows SID capture for admin users — Phase 7 AD/LDAP integration

</deferred>

---

*Phase: 09-admin-operation-audit-logging*
*Context gathered: 2026-04-14 via /gsd-discuss-phase*
