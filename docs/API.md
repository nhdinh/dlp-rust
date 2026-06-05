<!-- generated-by: gsd-doc-writer -->

# API Reference

This document describes the HTTP API surface of `dlp-server`, the central management server for the Enterprise DLP System. The server is built on [axum](https://docs.rs/axum) and listens on `127.0.0.1:9090` by default (configurable via `--bind`).

---

## Authentication

The API uses **JWT Bearer tokens** for admin authentication.

### Obtaining a token

```bash
curl -X POST http://localhost:9090/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"dlp-admin","password":"your-password"}'
```

Response:
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_at": "2026-06-03T12:00:00+00:00"
}
```

### Using the token

Include the token in the `Authorization` header for all protected endpoints:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:9090/agents
```

### Token properties

| Property | Value |
|----------|-------|
| Algorithm | HS256 |
| Issuer | `dlp-server` |
| Expiry | 24 hours |
| Secret source | `JWT_SECRET` env var (first run) or encrypted `secrets_jwt` DB row |

### Password management

Authenticated admins can change their password:

```bash
curl -X PUT http://localhost:9090/auth/password \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"current_password":"old","new_password":"new"}'
```

---

## Rate Limits

Rate limiting is applied per-endpoint using `tower-governor`. Limits are keyed by agent ID for agent routes and by peer IP for all other routes.

| Endpoint group | Limit | Window |
|----------------|-------|--------|
| `/auth/login` | 5 requests | 60 seconds |
| `/agents/{id}/heartbeat` | 30 requests | 60 seconds |
| `/audit/events` (POST) | 200 requests | 60 seconds |
| `/audit/bypass` (POST) | 200 requests | 60 seconds |
| Policy CRUD (`/policies`, `/admin/policies`) | 60 requests | 60 seconds |
| All other protected routes | 100 requests | 60 seconds |

When a limit is exceeded, the server returns `429 Too Many Requests` with a `Retry-After` header:

```json
{
  "error": "rate_limit_exceeded",
  "retry_after": 45
}
```

---

## Endpoints Overview

### Unauthenticated endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness probe |
| GET | `/ready` | Readiness probe (verifies DB connectivity) |
| POST | `/evaluate` | ABAC policy evaluation (agent-to-server) |
| POST | `/auth/login` | Admin login (issues JWT) |
| POST | `/agents/register` | Agent self-registration |
| POST | `/agents/{id}/heartbeat` | Agent heartbeat |
| POST | `/audit/events` | Audit event ingestion (agent-to-server) |
| POST | `/audit/bypass` | Bypass alert batch ingestion (agent-to-server) |
| GET | `/agent-credentials/auth-hash` | Fetch agent authentication hash |
| GET | `/agent-config/{id}` | Resolved agent configuration (agent poll) |
| GET | `/admin/device-registry` | Public device list (no trust tiers) |
| GET | `/admin/managed-origins` | Managed origin list (agent + admin) |
| POST | `/agent/approval-request` | Submit approval request (agent) |
| GET | `/agent/approvals/active` | List active approval tokens (agent sync) |
| GET | `/agent/approvals/public-key` | Server Ed25519 verifying key (agent) |

### Authenticated endpoints (JWT required)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/agents` | List all registered agents |
| GET | `/agents/{id}` | Get single agent details |
| GET | `/audit/events` | Query audit events with filters |
| GET | `/audit/events/count` | Total audit event count |
| GET | `/policies` | List all policies |
| GET | `/policies/{id}` | Get single policy |
| POST | `/policies` | Create a new policy |
| PUT | `/policies/{id}` | Update a policy |
| DELETE | `/policies/{id}` | Delete a policy |
| POST | `/admin/policies` | Create policy (alternate path) |
| PUT | `/admin/policies/{id}` | Update policy (alternate path) |
| DELETE | `/admin/policies/{id}` | Delete policy (alternate path) |
| GET | `/admin/config/global-enforcement-mode` | Read global enforcement mode |
| PUT | `/admin/config/global-enforcement-mode` | Update global enforcement mode |
| GET | `/exceptions` | List all policy exceptions |
| GET | `/exceptions/{id}` | Get single exception |
| POST | `/exceptions` | Create a new exception |
| PUT | `/agent-credentials/auth-hash` | Set agent authentication hash |
| PUT | `/auth/password` | Change admin password |
| GET | `/admin/siem-config` | Get SIEM connector configuration |
| PUT | `/admin/siem-config` | Update SIEM connector configuration |
| GET | `/admin/alert-config` | Get alert router configuration |
| PUT | `/admin/alert-config` | Update alert router configuration |
| POST | `/admin/alert-config/test` | Send test alert |
| GET | `/admin/ldap-config` | Get LDAP/AD configuration |
| PUT | `/admin/ldap-config` | Update LDAP/AD configuration |
| GET | `/admin/agent-config` | Get global agent config default |
| PUT | `/admin/agent-config` | Update global agent config default |
| GET | `/admin/agent-config/{agent_id}` | Get per-agent config override |
| PUT | `/admin/agent-config/{agent_id}` | Upsert per-agent config override |
| DELETE | `/admin/agent-config/{agent_id}` | Remove per-agent config override |
| POST | `/admin/device-registry` | Upsert device registry entry |
| GET | `/admin/device-registry/full` | Full device list (with trust tiers) |
| DELETE | `/admin/device-registry/{id}` | Delete device registry entry |
| GET | `/admin/disk-registry` | List disk registry entries |
| POST | `/admin/disk-registry` | Insert disk registry entry |
| DELETE | `/admin/disk-registry/{id}` | Delete disk registry entry |
| POST | `/admin/managed-origins` | Create managed origin |
| DELETE | `/admin/managed-origins/{id}` | Delete managed origin |
| GET | `/admin/allowlist` | List allowlist entries |
| POST | `/admin/allowlist` | Create allowlist entry |
| GET | `/admin/allowlist/{id}` | Get allowlist entry |
| PUT | `/admin/allowlist/{id}` | Update allowlist entry |
| DELETE | `/admin/allowlist/{id}` | Delete allowlist entry |
| POST | `/admin/allowlist/{id}/disable` | Soft-disable allowlist entry |
| GET | `/admin/allowlist/{id}/audit` | List audit log for entry |
| POST | `/admin/secrets/rotate` | Rotate encryption keys (KEK rotation) |
| POST | `/admin/maintenance/enter` | Enter maintenance mode |
| POST | `/admin/maintenance/exit` | Exit maintenance mode |
| GET | `/admin/labels` | List data labels with filters |
| POST | `/admin/labels` | Create a new label |
| GET | `/admin/labels/{id}` | Get single label |
| PUT | `/admin/labels/{id}` | Update a label |
| DELETE | `/admin/labels/{id}` | Delete a label |
| POST | `/admin/labels/{id}/confirm` | Confirm a temporary label |
| POST | `/admin/labels/{id}/reject` | Reject a temporary label |
| POST | `/admin/labels/{id}/expire` | Expire a label |
| GET | `/admin/labels/departments` | List distinct departments |
| GET | `/admin/approvals` | List approval requests |
| POST | `/admin/approvals` | Create approval request |
| GET | `/admin/approvals/{id}` | Get approval details |
| POST | `/admin/approvals/{id}/grant` | Grant an approval |
| POST | `/admin/approvals/{id}/reject` | Reject an approval |
| POST | `/admin/approvals/{id}/revoke` | Revoke an approved approval |
| PUT | `/admin/board-public-key` | Update T4 Board public key |
| GET | `/admin/syslog-config` | Get syslog forwarder configuration |
| PUT | `/admin/syslog-config` | Update syslog configuration |
| POST | `/admin/syslog-config/test` | Send test syslog event |
| GET | `/admin/protected-paths` | List protected paths |
| POST | `/admin/protected-paths` | Create protected path |
| PUT | `/admin/protected-paths/{id}` | Update protected path |
| DELETE | `/admin/protected-paths/{id}` | Delete protected path |
| POST | `/admin/protected-paths/sync` | Auto-populate from labels |
| GET | `/admin/bypass-alerts` | List bypass alerts |
| POST | `/admin/bypass-alerts/{id}/ack` | Acknowledge bypass alert |

---

## Request/Response Formats

### Standard error response

All errors return a JSON body with an `error` field:

```json
{
  "error": "not found: policy pol-001"
}
```

### Health probes

**`GET /health`** — Liveness probe.

Response:
```json
{
  "status": "ok",
  "timestamp": "2026-06-02T10:00:00+00:00"
}
```

**`GET /ready`** — Readiness probe (verifies SQLite connectivity).

Response:
```json
{
  "status": "ready",
  "timestamp": "2026-06-02T10:00:00+00:00"
}
```

### ABAC Evaluation

**`POST /evaluate`** — Evaluates an access request against the loaded policy set. This endpoint is unauthenticated; agent identity is established by the `agent` field in the request body.

Request:
```json
{
  "subject": {
    "user_sid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
    "user_name": "jsmith",
    "groups": ["S-1-5-21-...-513"],
    "device_trust": "Managed",
    "network_location": "Corporate"
  },
  "resource": {
    "path": "C:\\Data\\Q4-Financials.xlsx",
    "classification": "T3"
  },
  "environment": {
    "timestamp": "2026-06-02T10:00:00Z",
    "session_id": 1,
    "access_context": "local"
  },
  "action": "COPY",
  "agent": {
    "machine_name": "WORKSTATION-01",
    "current_user": "jsmith"
  }
}
```

Response:
```json
{
  "decision": "DENY",
  "matched_policy_id": "pol-001",
  "reason": "T3 files cannot be copied to USB removable storage",
  "enforcement_mode": "Block",
  "would_have_denied": true
}
```

### Policy Management

**`GET /policies`** — List all policies.

Response:
```json
[
  {
    "id": "pol-001",
    "name": "Block T4 Copy to USB",
    "description": "Prevent copying T4 files to removable media",
    "priority": 1,
    "conditions": [
      {"attribute": "classification", "op": "eq", "value": "T4"},
      {"attribute": "action", "op": "eq", "value": "COPY"}
    ],
    "action": "DENY",
    "enabled": true,
    "mode": "ALL",
    "enforcement_mode": "Block",
    "version": 3,
    "updated_at": "2026-06-01T12:00:00Z"
  }
]
```

**`POST /policies`** — Create a new policy.

Request:
```json
{
  "id": "pol-002",
  "name": "Block T3 Copy to USB",
  "description": "Prevent copying T3 files to removable media",
  "priority": 2,
  "conditions": [
    {"attribute": "classification", "op": "eq", "value": "T3"},
    {"attribute": "action", "op": "eq", "value": "COPY"}
  ],
  "action": "DENY",
  "enabled": true,
  "mode": "ALL",
  "enforcement_mode": "Block"
}
```

Response: `201 Created` with the created policy.

### Audit Event Ingestion

**`POST /audit/events`** — Ingest a batch of audit events from agents.

Request:
```json
[
  {
    "timestamp": "2026-06-02T10:00:00Z",
    "event_type": "BLOCK",
    "user_sid": "S-1-5-21-...",
    "user_name": "jsmith",
    "resource_path": "C:\\Data\\secret.xlsx",
    "classification": "T4",
    "action_attempted": "COPY",
    "decision": "DENY",
    "policy_id": "pol-001",
    "policy_name": "Block T4 Copy to USB",
    "agent_id": "AGENT-001",
    "session_id": 1,
    "access_context": "local",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
    "source_application": {
      "publisher": "Microsoft Corporation",
      "image_path": "C:\\Windows\\explorer.exe",
      "trust_tier": "system"
    },
    "destination_application": null
  }
]
```

Response: `201 Created` (empty body).

### Agent Registration

**`POST /agents/register`** — Register or update an agent.

Request:
```json
{
  "agent_id": "AGENT-001",
  "hostname": "WORKSTATION-01",
  "ip": "10.0.0.5",
  "os_version": "Windows 11 23H2",
  "agent_version": "0.1.0"
}
```

Response:
```json
{
  "agent_id": "AGENT-001",
  "hostname": "WORKSTATION-01",
  "ip": "10.0.0.5",
  "os_version": "Windows 11 23H2",
  "agent_version": "0.1.0",
  "last_heartbeat": "2026-06-02T10:00:00Z",
  "status": "online",
  "registered_at": "2026-06-02T10:00:00Z"
}
```

### Agent Configuration

**`GET /agent-config/{id}``** — Returns the resolved configuration for a specific agent (unauthenticated). Tries per-agent override first, falls back to global default. Supports `If-None-Match` header for 304 optimization.

Response:
```json
{
  "monitored_paths": ["C:\\Data", "D:\\Shared"],
  "excluded_paths": ["C:\\Windows", "C:\\Program Files"],
  "heartbeat_interval_secs": 30,
  "offline_cache_enabled": true,
  "disk_allowlist": [],
  "usb_blocked_failure_mode": "Warning only",
  "usb_startup_resolution_mode": "VID/PID/serial fallback",
  "usb_none_serial_policy": "Always Blocked",
  "cloud_hook_enabled": false,
  "print_enabled": false,
  "print_xps_timeout_ms": 5000,
  "print_unclassifiable_action": "Block",
  "print_max_pages": 100,
  "allowlist_entries": [],
  "allowlist_version": 0,
  "protected_paths": [],
  "global_enforcement_mode": "PerPolicy"
}
```

### Approval Workflow

**`POST /admin/approvals`** — Create a pending approval (admin).

Request:
```json
{
  "requester_sid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
  "data_object_id": "label-001",
  "allowed_action": "WRITE",
  "destination_scope": "C:\\Data",
  "justification": "Business need for quarterly report",
  "device_fingerprint": null
}
```

**`POST /admin/approvals/{id}/grant`** — Grant a pending approval.

Request:
```json
{
  "valid_until": "2026-06-03T10:00:00Z",
  "signature": null
}
```

Response:
```json
{
  "approval": {
    "id": "app-001",
    "requester_sid": "S-1-5-21-...",
    "approver_sid": "admin",
    "data_object_id": "label-001",
    "allowed_action": "WRITE",
    "destination_scope": "C:\\Data",
    "valid_from": "2026-06-02T10:00:00Z",
    "valid_until": "2026-06-03T10:00:00Z",
    "signature": null,
    "status": "Approved",
    "justification": "Business need for quarterly report",
    "created_at": "2026-06-02T10:00:00Z",
    "updated_at": "2026-06-02T10:00:00Z"
  },
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9..."
}
```

T4 approvals require a valid Ed25519 Board signature in the `signature` field.

### Label Management

**`GET /admin/labels`** — List labels with optional filters.

Query params: `?state=temporary&tier=T3&owner_sid=...&department=Finance&limit=50&offset=0`

Response:
```json
{
  "labels": [
    {
      "id": "label-001",
      "path": "C:\\Data\\Finance",
      "object_type": "folder",
      "tier": "T3",
      "label_state": "temporary",
      "owner_sid": "S-1-5-21-...",
      "parent_label_id": null,
      "acl_snapshot_id": null,
      "hash": null,
      "scanner_confidence": 0.95,
      "department": "Finance",
      "created_at": "2026-06-01T10:00:00Z",
      "updated_at": "2026-06-01T10:00:00Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

### Protected Paths

**`GET /admin/protected-paths`** — List protected paths for DACL tripwire monitoring.

Response:
```json
[
  {
    "id": "path-001",
    "path": "C:\\Data\\Secret",
    "source": "manual",
    "is_override": false,
    "tier": "T4",
    "label_id": null,
    "created_at": "2026-06-01T10:00:00Z",
    "updated_at": "2026-06-01T10:00:00Z"
  }
]
```

### Bypass Alerts

**`POST /audit/bypass`** — Ingest bypass alert batch from agents.

Request:
```json
{
  "agent_id": "AGENT-001",
  "batch_id": "550e8400-e29b-41d4-a716-446655440000",
  "alerts": [
    {
      "pid": 1234,
      "image_path": "C:\\Windows\\System32\\notepad.exe",
      "image_sha256": "abc123...",
      "file_path": "C:\\Data\\secret.txt",
      "operation": "WRITE",
      "file_object": 42,
      "qpc_timestamp": 1234567890,
      "severity": "crit",
      "reason": "HookOverwritten"
    }
  ]
}
```

Response:
```json
{
  "inserted": 1,
  "skipped": 0
}
```

---

## Error Codes

The API uses standard HTTP status codes with consistent JSON error bodies.

| Status | Meaning | Typical causes |
|--------|---------|----------------|
| 200 | OK | Successful GET, PUT, POST |
| 201 | Created | Successful resource creation |
| 204 | No Content | Successful deletion or heartbeat |
| 304 | Not Modified | `If-None-Match` matched current version |
| 400 | Bad Request | Malformed JSON, missing required fields, validation failure |
| 401 | Unauthorized | Missing or invalid JWT token |
| 403 | Forbidden | Authenticated user lacks permission for the action |
| 404 | Not Found | Resource does not exist |
| 409 | Conflict | Unique constraint violation, resource already exists |
| 422 | Unprocessable Entity | Structurally valid JSON violates domain invariants (e.g., invalid enum value) |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Database failure, unexpected error |

Error response format:
```json
{
  "error": "bad request: event batch must not be empty"
}
```

---

## Key Types and Enums

### Classification tiers

| Value | Description |
|-------|-------------|
| `T1` | Public — low sensitivity |
| `T2` | Internal — moderate sensitivity |
| `T3` | Confidential — high sensitivity |
| `T4` | Restricted — highest sensitivity |

### Actions

| Value | Description |
|-------|-------------|
| `READ` | Read a file |
| `WRITE` | Write or modify a file |
| `COPY` | Copy a file |
| `DELETE` | Delete a file |
| `MOVE` | Move or rename a file |
| `PASTE` | Paste from clipboard |
| `DRAG_DROP` | Drag-and-drop operation |
| `CLOUD_UPLOAD` | Cloud upload |
| `PRINT` | Print operation |

### Decisions

| Value | Description |
|-------|-------------|
| `ALLOW` | Permit without logging |
| `DENY` | Block and log |
| `ALLOW_WITH_LOG` | Permit and log |
| `DENY_WITH_ALERT` | Block, log, and trigger alert |

### Enforcement modes

| Value | Description |
|-------|-------------|
| `Audit` | Log violations only |
| `Block` | Enforce blocking (default) |
| `AuditAndBlock` | Both log and block |
| `PerPolicy` | Defer to per-policy mode (global override only) |

### Device trust tiers

| Value | Description |
|-------|-------------|
| `Managed` | Organization-managed device |
| `Unmanaged` | Not organization-managed |
| `Compliant` | Meets compliance requirements |
| `Unknown` | Trust level indeterminate |

### Network locations

| Value | Description |
|-------|-------------|
| `Corporate` | On corporate network |
| `CorporateVpn` | Connected via VPN |
| `Guest` | Guest or untrusted network |
| `Unknown` | Location indeterminate |

---

## Secret Masking

GET endpoints that return sensitive configuration values (SIEM tokens, SMTP passwords, webhook secrets) replace the actual values with the sentinel `***MASKED***`. When updating via PUT, send the mask back to preserve the existing secret, send an empty string to clear it, or send a new plaintext value to replace it.

Example:
```bash
# GET returns masked values
curl -H "Authorization: Bearer <token>" http://localhost:9090/admin/alert-config
# { "smtp_password": "***MASKED***", ... }

# PUT with mask preserves existing secret
curl -X PUT -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"smtp_password":"***MASKED***",...}' \
  http://localhost:9090/admin/alert-config
```
