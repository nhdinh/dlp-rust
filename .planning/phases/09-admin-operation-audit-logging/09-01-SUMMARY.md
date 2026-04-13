# Phase 09 — Admin Operation Audit Logging: Plan 09-01 Summary

**Status:** Complete
**Date:** 2026-04-14
**Requirement:** R-09 — Admin operation audit logging (policy CRUD + password change)

---

## What Was Built

Structured `AuditEvent` records are now persisted to the `audit_events` table with
`EventType::AdminAction` for every policy creation, update, deletion, and successful
admin password change. Events are queryable via the existing `GET /audit/events?event_type=ADMIN_ACTION`
endpoint.

---

## Changes by File

### `dlp-common/src/abac.rs` — Action enum (4 new variants)

```rust
PolicyCreate,  // Admin created a new policy via the admin API.
PolicyUpdate,  // Admin updated an existing policy via the admin API.
PolicyDelete,  // Admin deleted a policy via the admin API.
PasswordChange, // Admin changed own password via the admin API.
```

### `dlp-server/src/db.rs` — `admin_users` schema

Added `user_sid TEXT NULL` column for Phase 7 AD/LDAP integration readiness:

```sql
CREATE TABLE IF NOT EXISTS admin_users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    user_sid      TEXT NULL,   -- NEW (Phase 7 readiness; empty until AD integration)
    created_at    TEXT NOT NULL
);
```

### `dlp-server/src/admin_auth.rs` — `AdminUsername::extract_from_headers`

Added a `pub fn extract_from_headers(&HeaderMap) -> Result<String, AppError>` helper
to extract the verified username from the Authorization header in handlers that
already consumed the request body. This avoids the `FromRequest` lifetime issues
that prevented `AdminUsername` from being a direct axum extractor.

Also added `From<JsonRejection>` and `From<PathRejection>` conversions to `AppError`
for cleaner extractor error handling.

### `dlp-server/src/audit_store.rs` — `store_events_sync`

```rust
pub fn store_events_sync(conn: &rusqlite::Connection, events: &[AuditEvent]) -> Result<(), AppError>
```

Synchronous DB-only insert helper for use inside `tokio::task::spawn_blocking` calls
(where the async `ingest_events` cannot be awaited). No SIEM relay, no alert routing —
admin audit events are DB-only by design.

### `dlp-server/src/admin_api.rs` — Policy CRUD + route additions

- `create_policy`: emits `AuditEvent { event_type: AdminAction, action: PolicyCreate }`
- `update_policy`: emits `AuditEvent { event_type: AdminAction, action: PolicyUpdate }`
- `delete_policy`: emits `AuditEvent { event_type: AdminAction, action: PolicyDelete }`

All handlers use `AdminUsername::extract_from_headers` to capture the acting admin's
username before consuming the request body. Audit events are emitted after the DB
transaction commits but before returning the HTTP response.

Added routes:
```
POST   /admin/policies           → create_policy
PUT    /admin/policies/:id      → update_policy
DELETE /admin/policies/:id      → delete_policy
```

Both `/policies/*` and `/admin/policies/*` are supported by `update_policy` (same handler
function handles both paths). `create_policy` is registered on both `/policies` and
`/admin/policies` for API compatibility.

### `dlp-server/src/lib.rs` — AppError extensions

```rust
impl From<JsonRejection> for AppError { ... }  // → BadRequest
impl From<PathRejection> for AppError { ... }  // → BadRequest
```

### `dlp-server/tests/admin_audit_integration.rs` — Integration tests (new file)

Four integration tests covering all audit event emissions:

| Test | Route | Expected Action | Expected Resource |
|------|-------|-----------------|-------------------|
| `test_policy_create_emits_admin_audit_event` | POST `/admin/policies` | `PolicyCreate` | `policy:<id>` |
| `test_policy_update_emits_admin_audit_event` | PUT `/admin/policies/:id` | `PolicyUpdate` | `policy:<id>` |
| `test_policy_delete_emits_admin_audit_event` | DELETE `/admin/policies/:id` | `PolicyDelete` | `policy:<id>` |
| `test_password_change_emits_admin_audit_event` | PUT `/auth/password` | `PasswordChange` | `password_change:<username>` |

All tests verify exact DB field values: `event_type`, `action_attempted`, `resource_path`,
`user_name`, `decision`, and `agent_id`.

---

## Audit Event Schema (Admin Actions)

| Field | Value |
|-------|-------|
| `event_type` | `"ADMIN_ACTION"` (SCREAMING_SNAKE_CASE via serde) |
| `user_sid` | `""` (empty until Phase 7 AD/LDAP integration) |
| `user_name` | Admin username from JWT token |
| `resource_path` | `policy:<id>` or `password_change:<username>` |
| `classification` | `T3` (Confidential) |
| `action_attempted` | `PolicyCreate`, `PolicyUpdate`, `PolicyDelete`, or `PasswordChange` |
| `decision` | `ALLOW` (action already succeeded at audit time) |
| `agent_id` | `"server"` |
| `session_id` | `0` |

---

## Verification

```
cargo test -p dlp-common --release          # 28 tests pass
cargo test -p dlp-server --release          # 74 tests pass, 2 ignored
cargo test -p dlp-server --test admin_audit_integration --release  # 4 tests pass
```

Manual verification steps (post-integration):
1. Start `dlp-server`
2. POST `/auth/login` with admin credentials → get JWT
3. POST `/admin/policies` with a test policy → expect HTTP 201
4. GET `/audit/events?event_type=ADMIN_ACTION` with JWT → expect event with `action_attempted: "PolicyCreate"`
5. PUT `/admin/policies/<id>` → query → expect `action_attempted: "PolicyUpdate"`
6. DELETE `/admin/policies/<id>` → query → expect `action_attempted: "PolicyDelete"`
7. PUT `/auth/password` (valid current password) → query → expect `action_attempted: "PasswordChange"`

---

## Deferred / Out of Scope

- **AD/LDAP SID capture:** `user_sid` column added to schema but remains empty until Phase 7
- **Failed password attempt logging:** Covered by Phase 8 rate limiting (R-07)
- **Separate admin audit endpoint:** Existing `GET /audit/events?event_type=ADMIN_ACTION` reused

---

## Decisions Made During Implementation

| Decision | Rationale |
|----------|-----------|
| `FromRequest` extractor for `AdminUsername` | Axum 0.7 lifetime constraints prevented direct implementation; sync helper is simpler and avoids lifetime gymnastics |
| Path extraction via `req.uri().path()` | Avoids consuming the body with `from_request_parts`; Json extractor handles body separately |
| JSON-quoted enum strings in DB | `serde_json::to_string` produces `"SCREAMING_SNAKE_CASE"` which is what gets stored |
| `store_events_sync` only (no SIEM/alert) | Admin actions are not agent-scoped; SIEM relay and alert routing are only for `DenyWithAlert` events |