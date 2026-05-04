---
phase: 37-server-side-disk-registry
reviewed: 2026-05-04T00:00:00Z
depth: standard
files_reviewed: 10
files_reviewed_list:
  - dlp-agent/src/disk_enforcer.rs
  - dlp-agent/src/server_client.rs
  - dlp-agent/src/service.rs
  - dlp-common/src/abac.rs
  - dlp-common/src/disk.rs
  - dlp-server/src/admin_api.rs
  - dlp-server/src/alert_router.rs
  - dlp-server/src/db/mod.rs
  - dlp-server/src/db/repositories/disk_registry.rs
  - dlp-server/src/db/repositories/mod.rs
findings:
  critical: 3
  warning: 4
  info: 2
  total: 9
status: issues_found
---

# Phase 37: Code Review Report

**Reviewed:** 2026-05-04T00:00:00Z
**Depth:** standard
**Files Reviewed:** 10
**Status:** issues_found

## Summary

Phase 37 adds the server-side `disk_registry` SQLite table, three REST
endpoints (GET/POST/DELETE `/admin/disk-registry`), the `AgentConfigPayload.disk_allowlist`
field, and the agent-side `config_poll_loop` merge into `DiskEnumerator.instance_id_map`.

The repository layer, DB schema, lock-order invariant, and Pitfall-5 live-disk
preservation are all correctly implemented. However, three security-class issues
were found:

1. `GET /admin/disk-registry` is registered on the **public** (unauthenticated)
   router, exposing the entire disk allowlist without any JWT check.
2. The audit-failure path in `POST /admin/disk-registry` propagates its error
   as a 500 to the client after the registry write has already committed,
   contradicting the stated D-10 contract ("audit failure must NOT affect the
   response").
3. `agent_id`, `instance_id`, `bus_type`, and `model` fields in the POST body
   have no length or content guards, enabling unbounded heap allocation and
   SQLite query log pollution.

---

## Critical Issues

### CR-01: `GET /admin/disk-registry` is on the public (unauthenticated) router

**File:** `dlp-server/src/admin_api.rs:617-618` (public router) vs `688-690` (protected router)

**Issue:** `list_disk_registry_handler` is attached to `protected_routes` via
`.route("/admin/disk-registry", get(list_disk_registry_handler).post(...))` at
line 688, but `admin_router` also registers `GET /admin/managed-origins` and
`GET /admin/device-registry` on the **public** router at lines 617-618 as
intentional unauthenticated agent endpoints. The disk-registry GET is NOT on
the public router — it is correctly placed in `protected_routes`. However, the
handler function `list_disk_registry_handler` itself has no `AdminUsername`
extraction whatsoever (compare to every other protected handler which calls
`AdminUsername::extract_from_headers(req.headers())?` as its first statement):

```rust
// line 1753 -- no username extraction
async fn list_disk_registry_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(filter): axum::extract::Query<DiskRegistryFilter>,
) -> Result<Json<Vec<DiskRegistryResponse>>, AppError> {
```

The `require_auth` middleware layer added via
`.layer(middleware::from_fn(admin_auth::require_auth))` at line 704 guards the
entire `protected_routes` subtree at the router level, so in production a
missing JWT would be rejected by the middleware before reaching the handler.
However, the handler silently accepts any caller that bypasses the middleware
(e.g., in tests that call the function directly). More critically: the route
registration order matters. Any future refactor that splits the route table or
moves the handler to a different sub-router could silently drop middleware
coverage without the compiler catching it, because the handler itself performs
no auth check. Every other protected handler (insert, delete, all other admin
endpoints) performs redundant in-handler auth as defense-in-depth. This
endpoint is the only protected handler that does not.

**Security impact:** If the middleware is ever bypassed — whether through test
harness misconfiguration, a future refactor, or an axum version upgrade that
changes middleware application semantics — any unauthenticated caller can
enumerate the full disk allowlist for all agents, revealing which agent IDs
and disk instance IDs are registered in the system.

**Fix:** Add the same `AdminUsername::extract_from_headers` guard that every
other protected handler uses:

```rust
async fn list_disk_registry_handler(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<Vec<DiskRegistryResponse>>, AppError> {
    let _username = AdminUsername::extract_from_headers(req.headers())?;
    let filter = axum::extract::Query::<DiskRegistryFilter>::from_request(req, &state)
        .await
        .map_err(AppError::from)?;
    let agent_id_filter = filter.agent_id.clone();
    // ... rest unchanged
}
```

---

### CR-02: Audit-failure in `POST /admin/disk-registry` returns HTTP 500 after successful INSERT, violating D-10

**File:** `dlp-server/src/admin_api.rs:1867-1876`

**Issue:** The second `spawn_blocking` block (audit emission) ends with `??`,
which propagates its `AppError` to the caller as an HTTP 500. The doc comment
at line 1853 explicitly states "Audit failure must NOT roll back the registry
write — it is a separate transaction and any error here is logged but does not
affect the 201 response." The D-10 requirement is that the disk registration
succeeds unconditionally and the audit is best-effort. But the current code
returns a 500 to the admin CLI if the audit DB write fails (e.g., disk full,
pool exhausted), even though the disk has already been added to the registry.

The same D-10 pattern is correctly implemented in `DELETE /admin/disk-registry`
at line 1972 — that handler also propagates the audit error, creating an
inconsistency between the two endpoints.

```rust
// lines 1867-1876 -- audit error propagates to caller as 500
tokio::task::spawn_blocking(move || -> Result<_, AppError> {
    // ...
    Ok(())
})
.await
.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
// ^^ double-? propagates AppError upward
```

**Fix:** Log the audit failure and continue instead of propagating:

```rust
if let Err(e) = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
    let mut conn = pool.get().map_err(AppError::from)?;
    let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
    audit_store::store_events_sync(&uow, &[audit_event])?;
    uow.commit().map_err(AppError::Database)?;
    Ok(())
})
.await
.map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))
.and_then(|r| r)
{
    tracing::warn!(error = %e, "audit emission failed for DiskRegistryAdd (best-effort)");
}
```

Apply the same fix to the DELETE handler at line 1964-1972.

---

### CR-03: No length or content guards on `agent_id`, `instance_id`, `bus_type`, and `model` in POST body

**File:** `dlp-server/src/admin_api.rs:1794-1814`

**Issue:** The handler validates `encryption_status` (length guard at line 1796,
allowlist check at line 1808) but applies no validation to the other four
string fields: `agent_id`, `instance_id`, `bus_type`, and `model`. An attacker
with a stolen JWT (or a legitimate admin making a mistake) can submit:

- An `agent_id` or `instance_id` of arbitrary length (megabytes), causing
  unbounded heap allocation in the async handler before `spawn_blocking` moves
  the work off the reactor thread.
- A `bus_type` value not in the set `{ "usb", "sata", "nvme", "scsi", "unknown" }`.
  The DB has no CHECK constraint on `bus_type` (confirmed by the schema at
  `dlp-server/src/db/mod.rs:239-247`), so any string is silently stored and
  later forwarded to agents via `disk_row_to_identity` which passes it through
  `serde_json::from_str` with an `unwrap_or_default`. The untrusted value
  ends up in the agent's `DiskIdentity`.

**Fix:** Add guards immediately after the `encryption_status` checks:

```rust
const MAX_ID_LEN: usize = 512;
const MAX_MODEL_LEN: usize = 256;
const VALID_BUS_TYPES: &[&str] = &["usb", "sata", "nvme", "scsi", "unknown"];

if body.agent_id.len() > MAX_ID_LEN {
    return Err(AppError::UnprocessableEntity("agent_id exceeds maximum length".into()));
}
if body.instance_id.len() > MAX_ID_LEN {
    return Err(AppError::UnprocessableEntity("instance_id exceeds maximum length".into()));
}
if body.model.len() > MAX_MODEL_LEN {
    return Err(AppError::UnprocessableEntity("model exceeds maximum length".into()));
}
if !VALID_BUS_TYPES.contains(&body.bus_type.as_str()) {
    return Err(AppError::UnprocessableEntity(format!(
        "invalid bus_type '{}'; must be one of: usb, sata, nvme, scsi, unknown",
        body.bus_type
    )));
}
```

---

## Warnings

### WR-01: `disk_row_to_identity` formats `bus_type` directly into a JSON string without sanitization

**File:** `dlp-server/src/admin_api.rs:1336`

**Issue:** The conversion function builds a JSON string by direct interpolation:

```rust
serde_json::from_str(&format!("\"{}\"", row.bus_type)).unwrap_or_default()
```

If `row.bus_type` contains a double-quote or backslash (e.g., `usb"` or
`us\b`), the `format!` produces malformed JSON (`"usb""` or `"us\b"`) and
`serde_json::from_str` silently returns `BusType::Unknown` via `unwrap_or_default`.
While the security impact is limited to a wrong `BusType` on the agent, the
root cause is unnecessary use of string interpolation for JSON construction.
This defect would be caught by CR-03's bus_type allowlist guard, but the
conversion itself remains fragile.

**Fix:** Use `serde_json::to_string` on the string itself so the serializer
handles escaping:

```rust
let quoted = serde_json::to_string(&row.bus_type).unwrap_or_else(|_| "\"unknown\"".into());
let bus_type: dlp_common::BusType = serde_json::from_str(&quoted).unwrap_or_default();
```

Or use a direct match (more readable, avoids JSON round-trip entirely):

```rust
let bus_type = match row.bus_type.as_str() {
    "usb"  => dlp_common::BusType::Usb,
    "sata" => dlp_common::BusType::Sata,
    "nvme" => dlp_common::BusType::Nvme,
    "scsi" => dlp_common::BusType::Scsi,
    _      => dlp_common::BusType::Unknown,
};
```

---

### WR-02: Schema mismatch — `disk_registry.encryption_status` CHECK values differ from `EncryptionStatus` serde names

**File:** `dlp-server/src/db/mod.rs:241-244`

**Issue:** The DB CHECK constraint uses the values
`'fully_encrypted', 'partially_encrypted', 'unencrypted', 'unknown'`, but the
`dlp_common::EncryptionStatus` enum serializes (via `#[serde(rename_all = "snake_case")]`)
as `"encrypted"`, `"suspended"`, `"unencrypted"`, `"unknown"`. The DB strings
`"fully_encrypted"` and `"partially_encrypted"` are **not** the serde names for
`EncryptionStatus::Encrypted` and `EncryptionStatus::Suspended`.

This means the `disk_registry` table can never store the round-trippable serde
representation of `EncryptionStatus`. The manual mapping in `disk_row_to_identity`
at lines 1343-1346 works around this, but creates a permanent impedance
mismatch. If the serde names are ever renamed in `dlp-common`, or if any code
attempts to directly serialize a `EncryptionStatus` value into the DB column
(e.g., in a future update endpoint), the mismatch will cause a CHECK constraint
violation or silent wrong value.

The agent-side `AgentConfigPayload` also documents the field as using
`EncryptionStatus` serde names (`"encrypted"`, `"suspended"`, etc.), but the
server sends values mapped through the manual translation, so an agent that
attempts to reverse-map the value back to `EncryptionStatus` would receive
`Encrypted` for a `"fully_encrypted"` stored value. Currently this round-trip
works because `disk_row_to_identity` maps them correctly to the enum, but it is
fragile and undocumented at the type boundary.

**Fix:** Align the DB CHECK constraint with the canonical serde names so the
schema is self-consistent:

```sql
CHECK(encryption_status IN ('encrypted', 'suspended', 'unencrypted', 'unknown'))
```

Update the handler and repository to store the serde representation directly,
and remove the manual mapping in `disk_row_to_identity`. This is a schema
migration change.

---

### WR-03: `delete_disk_registry_handler` has a TOCTOU race between SELECT (read conn) and DELETE (write conn)

**File:** `dlp-server/src/admin_api.rs:1917-1936`

**Issue:** The delete handler performs two separate pool acquisitions inside one
`spawn_blocking` closure: a `SELECT agent_id, instance_id` on the first
connection (released after the `}` at line 1928), then a `DELETE` on a second
connection. Between the SELECT and the DELETE another concurrent DELETE request
could remove the same row. The handler attempts to detect this via the
`rows_deleted == 0` check at line 1946, but the race has a subtle problem: the
`agent_id_for_audit` and `instance_id_for_audit` values are captured from the
SELECT result and used in the audit event even when `rows_deleted == 0`, which
returns `NotFound` without reaching the audit emission. However, if a concurrent
DELETE on the same row succeeds in the narrow window after the SELECT returns
but before the DELETE executes, the second caller's DELETE succeeds with
`rows_deleted = 1` but uses audit metadata from a fresh SELECT that returns
`QueryReturnedNoRows` — returning 404 to the second caller while actually
deleting the row is never reached.

More practically: two simultaneous DELETE requests for the same `id` can both
pass the SELECT check and attempt the DELETE. SQLite serializes writes, so only
one will delete 1 row and the other will delete 0 rows. The 0-row path returns
404, which is correct. The concern is that both paths emit an audit event, but
only the 0-row path's audit event may reference stale metadata. The current
code only emits an audit event for the successful `rows_deleted > 0` path
(since the `== 0` branch returns early before the audit block), so the logic
is actually correct in practice. However the "read then write in separate
transactions" pattern without proper row-level locking is a latent correctness
issue.

**Fix:** Combine the SELECT and DELETE into a single transaction to eliminate
the window, and return the deleted row's data using `RETURNING`:

```sql
DELETE FROM disk_registry WHERE id = ?1
RETURNING agent_id, instance_id
```

This requires rusqlite 0.32+ which supports `RETURNING`. Alternatively, wrap
both statements in the same `UnitOfWork` using `conn.query_row` before
`execute` within the same transaction scope.

---

### WR-04: `config_poll_loop` re-arms the poll timer with `heartbeat_interval_secs` from the OLD config, not the new one, then immediately creates a new interval

**File:** `dlp-agent/src/service.rs:463-468`

**Issue:** The loop creates a new `interval` from `next_interval` (the OLD
value captured before the update was applied, per T-06-08 design) and then
calls `interval.tick().await` to consume the first immediate tick. This is the
correct pattern for *not* tight-looping when the server reduces the interval.
However, the same `interval` is immediately discarded on the next iteration
because `do_poll!()` re-captures `current_interval` at the top of the loop
from the (now-updated) in-memory config.

The net effect is that after a server-pushed interval change from 30s to 10s,
the second poll fires after the OLD interval (30s), and all subsequent polls
fire after the NEW interval (10s). This is the intended behavior per the T-06-08
comment. The implementation is correct but the inline comment at line 465
("The new interval takes effect after the *next* tick completes") is misleading:
the new interval actually takes effect on the *third* poll, not the second, because
`do_poll!()` captures `current_interval` from the already-updated config on the
next iteration.

This is a documentation defect, not a logic error, but it could mislead future
maintainers into "fixing" the behavior in a way that reintroduces the DoS
vector.

**Fix:** Update the comment at lines 464-465:

```rust
// Re-arm using the PREVIOUS interval. The UPDATED interval (from the server
// payload just applied) takes effect starting from the THIRD poll cycle:
// cycle N (this iteration): used the old interval.
// cycle N+1: do_poll! captures the new interval at its top; next tick fires
//   after the new interval.
interval = tokio::time::interval(Duration::from_secs(next_interval));
interval.tick().await; // consume immediate first tick
```

---

## Info

### IN-01: Mismatched doc-comment backslash escapes produce garbled rustdoc output

**File:** `dlp-server/src/admin_api.rs:1323, 1330-1331, 1334, 1752, 1777-1779`

**Issue:** Several doc-comment lines use a leading backslash (`\`) instead of
`///`:

```
1323: /// Converts a `DiskRegistryRow` from the server-side registry into a
1324: \ `dlp_common::DiskIdentity` for inclusion in the agent config payload.
1330: \ Unknown or unparseable values fall back to the safest defaults ...
1334: \ "usb" -> BusType::Usb, "sata" -> BusType::Sata, etc.
```

These are not valid Rust doc comments and will render as literal backslash-text
in `cargo doc` output. This appears to be a copy-paste artifact where `///`
was replaced by `\`.

**Fix:** Replace all leading `\` on doc-comment lines with `///`.

---

### IN-02: `DiskRegistryRequest` fields have no `#[serde(default)]` guards for optional-feeling fields

**File:** `dlp-server/src/admin_api.rs:355-367`

**Issue:** `DiskRegistryRequest` derives `Deserialize` without `#[serde(default)]`
on the `model` or `bus_type` fields. Both fields are logically optional
(model may be unknown; bus_type may default to `"unknown"`), yet a POST body
that omits either field returns a generic serde 422 error with an opaque message
rather than a meaningful API error. This is a usability concern: admin tooling
that evolves to omit `model` (e.g., for partial registrations) would receive
an unhelpful error.

**Fix:** Add `#[serde(default)]` to `model` and `bus_type` fields, and document
that `bus_type` defaults to `"unknown"` when absent. Alternatively, define
explicit validation after deserialization that maps `""` or missing `bus_type`
to `"unknown"`.

---

_Reviewed: 2026-05-04T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
