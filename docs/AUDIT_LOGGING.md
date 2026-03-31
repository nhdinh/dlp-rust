# Audit & Logging

**Document Version:** 1.0
**Date:** 2026-03-31
**Status:** Draft

## Overview

All dlp-agents emit structured JSON audit events for every intercepted file operation. Events flow through **dlp-server** — which provides central ingestion, append-only storage, SIEM relay, and an admin query API. No agent sends directly to SIEM.

## Audit Event Flow

```
dlp-agent (per endpoint)
  → HTTPS POST /audit/events ──→ dlp-server
                                    │
                                    ├── Append-only audit store
                                    │
                                    └── SIEM relay (batched)
                                          └── Splunk HEC / ELK HTTP Ingest
```

**Note:** Before Phase 5 (dlp-server deployment), agents buffer events locally in an encrypted append-only file (`F-AUD-04`). After Phase 5, all events flow through dlp-server.

## Events

| Event Type | Trigger | Routed to SIEM | Alert |
|-----------|---------|----------------|-------|
| `ACCESS` | File opened, read, written | Yes | No |
| `BLOCK` | Operation blocked by ABAC DENY | Yes | T3/T4 only |
| `ALERT` | DENY_WITH_ALERT triggered | Yes | Yes (email + webhook) |
| `CONFIG_CHANGE` | Policy or config changed | Yes | No |
| `SESSION_LOGOFF` | User logoff detected | Yes | No |
| `ADMIN_ACTION` | dlp-admin-portal API call | Yes | No |
| `SERVICE_STOP_FAILED` | Failed sc stop attempt | Yes | Yes |

## Log Format

All events are UTF-8 JSON matching the `AuditEvent` schema in `common-types/src/audit.rs`:

```json
{
  "timestamp": "2026-03-31T10:00:00.123Z",
  "event_type": "BLOCK",
  "user_sid": "S-1-5-21-123456789-...",
  "user_name": "jsmith",
  "resource_path": "C:\\Sensitive\\Q4-Financials.xlsx",
  "classification": "T3",
  "action_attempted": "COPY",
  "decision": "DENY_WITH_ALERT",
  "policy_id": "pol-003",
  "policy_name": "T3 USB Block",
  "agent_id": "AGENT-WS02-001",
  "session_id": "2",
  "device_trust": "Managed",
  "network_location": "Corporate VPN",
  "justification": null,
  "override_granted": false
}
```

> **Note:** File content (payload) is never included — only metadata.

## Integration

| Destination | Protocol | Authentication | Owner |
|-------------|----------|---------------|-------|
| dlp-server (`/audit/events`) | HTTPS / TLS 1.3 | mTLS or signed JWT per agent | dlp-agent → dlp-server |
| SIEM — Splunk HEC | HTTPS / TLS 1.3 | HEC token | dlp-server → Splunk |
| SIEM — ELK HTTP Ingest | HTTPS / TLS 1.3 | API key | dlp-server → ELK |

## SIEM Relay (dlp-server)

- **Batch size:** ≤ 1,000 events per batch
- **Batch latency:** ≤ 1 second
- **Fallback:** If SIEM is unreachable, dlp-server buffers events in local append-only storage (encrypted). Events are drained when SIEM connectivity is restored. Buffer has a configurable maximum size.

## Admin Audit Log

Every call to a dlp-admin-portal API is itself audited (F-AUD-09):

```json
{
  "timestamp": "2026-03-31T10:05:00.000Z",
  "event_type": "ADMIN_ACTION",
  "admin_user": "dlp-admin",
  "admin_sid": "S-1-5-21-...",
  "action": "POLICY_CREATE",
  "resource": "pol-010",
  "ip_address": "10.0.1.50",
  "user_agent": "dlp-admin-portal/1.0"
}
```

## Retention

- **dlp-server local store:** Minimum 90 days; configurable
- **SIEM:** Determined by SIEM retention policy
- **Compliance note:** Append-only storage satisfies F-AUD-06 (immutable audit logs)

## Integrity

- Audit events are immutable once written (append-only API, no update/delete)
- A hash chain (SHA-256) may be used for tamper detection (future enhancement)
