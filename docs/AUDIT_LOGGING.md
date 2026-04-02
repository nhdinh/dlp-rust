# Audit & Logging

**Document Version:** 1.1
**Date:** 2026-04-02
**Status:** Draft

**Changelog (v1.1):** Added Phase 1 implementation details — `dlp-agent` now writes directly to a local append-only JSONL file (`C:\ProgramData\DLP\logs\audit.jsonl`) with 50 MB size-based rotation and 9-generation retention. Audit pipeline fully wired: ETW → `run_event_loop` → `OfflineManager` → audit + Pipe 1. Clipboard T2+ events audited via `ClipboardListener`. `Action::PASTE` added.

## Overview

All dlp-agents emit structured JSON audit events for every intercepted file operation. Events flow through **dlp-server** (Phase 5) — which provides central ingestion, append-only storage, SIEM relay, and an admin query API. In Phase 1 (pre-dlp-server), agents write directly to a local append-only JSONL file.

## Phase 1 Audit Event Flow (Implemented)

```
ETW / Clipboard Hook
        │
        ▼
InterceptionEngine / ClipboardListener
        │
        ▼
run_event_loop / process_clipboard_text
        │
        ├──► OfflineManager::evaluate (Policy Engine or cache)
        │
        ├──► AuditEmitter::emit  ──► C:\ProgramData\DLP\logs\audit.jsonl
        │                                  (50 MB per file, 9 generations)
        │
        └──► Pipe1AgentMsg::BlockNotify  ──► UI (blocked decisions only)
```

## Phase 5 Audit Event Flow (Future)

```
dlp-agent (per endpoint)
  → HTTPS POST /audit/events ──→ dlp-server
                                    │
                                    ├── Append-only audit store
                                    │
                                    └── SIEM relay (batched)
                                          └── Splunk HEC / ELK HTTP Ingest
```

## Events

| Event Type | Trigger | Routed to SIEM | Alert |
|-----------|---------|----------------|-------|
| `ACCESS` | File opened, read, written | Yes (Phase 5) | No |
| `BLOCK` | Operation blocked by ABAC DENY | Yes (Phase 5) | T3/T4 only |
| `ALERT` | DENY_WITH_ALERT triggered | Yes (Phase 5) | Yes (email + webhook) |
| `CONFIG_CHANGE` | Policy or config changed | Yes (Phase 5) | No |
| `SESSION_LOGOFF` | User logoff detected | Yes (Phase 5) | No |
| `ADMIN_ACTION` | dlp-admin-portal API call | Yes (Phase 5) | No |
| `SERVICE_STOP_FAILED` | Failed sc stop attempt | Yes (Phase 5) | Yes |
| `EVASION_SUSPECTED` | ETW event not seen by hooks | Yes (Phase 5) | Yes |

> **Phase 1 note:** Events are written to `C:\ProgramData\DLP\logs\audit.jsonl` locally. SIEM routing activates when dlp-server is deployed (Phase 5).

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
| **Phase 1:** `C:\ProgramData\DLP\logs\audit.jsonl` | Local filesystem | Service account (LocalSystem) | dlp-agent → local file |
| **Phase 5:** dlp-server (`/audit/events`) | HTTPS / TLS 1.3 | mTLS or signed JWT per agent | dlp-agent → dlp-server |
| SIEM — Splunk HEC | HTTPS / TLS 1.3 | HEC token | dlp-server → Splunk |
| SIEM — ELK HTTP Ingest | HTTPS / TLS 1.3 | API key | dlp-server → ELK |

### Phase 1 Local Log

| Property | Value |
|----------|-------|
| Path | `C:\ProgramData\DLP\logs\audit.jsonl` |
| Format | JSONL (one JSON object per line, UTF-8) |
| Max file size | 50 MB |
| Rotation | 9 generations (`audit.jsonl.1.jsonl` … `audit.jsonl.9.jsonl`) |
| Append semantics | `FILE_APPEND_DATA` only — no read or write-after-append |
| Access | LocalSystem account (created automatically on first write) |

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
