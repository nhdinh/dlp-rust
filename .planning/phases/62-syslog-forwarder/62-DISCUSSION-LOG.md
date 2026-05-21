# Phase 62: Syslog Forwarder - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-21
**Phase:** 62-Syslog Forwarder
**Areas discussed:** Auto-update of existing context (originally gathered 2026-05-14)
**Mode:** `--auto` — all gray areas auto-selected with recommended defaults

---

## Auto-Update Summary

Existing CONTEXT.md (gathered 2026-05-14) was comprehensive. This auto-update refreshes metadata, incorporates Phase 61 completion status, and adds codebase scout findings.

### Gray Areas (All Pre-Resolved from Existing Context)

| Area | Status | Notes |
|------|--------|-------|
| Message format | Resolved (D-01, D-02) | JSON-in-MSG, flat object |
| Severity mapping | Resolved (D-03) | Configurable per event type |
| Facility code | Resolved (D-04) | LOCAL0-LOCAL7, default LOCAL4 |
| Batching | Resolved (D-05) | Batched default, single-msg debug mode |
| Queue architecture | Resolved (D-06, D-07) | Agent + server queues, DPAPI + KEK encryption |
| Retry strategy | Resolved (D-08) | FIFO tail-drop default |
| Max queue size | Resolved (D-09) | 10K agent, 100K server |
| TLS trust model | Resolved (D-10) | System CA store only |
| TLS version | Resolved (D-11) | TLS 1.2 min, TLS 1.3 preferred via rustls |

### Codebase Scout Findings Applied

- Confirmed `rustls` already in dependency tree via `reqwest` and `lettre`
- Confirmed no dedicated `syslog` crate present — RFC 5424 formatting will be inline
- Confirmed `SiemConnector` pattern is the canonical reusable asset
- Added Phase 61 (Approval Workflow) completion reference — approval events must flow through syslog

### Changes from 2026-05-14 Context

1. **Date updated** to 2026-05-21
2. **Phase 61 status** added — completed 2026-05-13; approval events (granted/revoked/expired/used) must forward through syslog
3. **Dependency note** added — no `syslog` crate in tree; use inline RFC 5424 + `tokio-rustls`
4. **Codebase maps** added to canonical refs (STACK.md, ARCHITECTURE.md, INTEGRATIONS.md)
5. **Out of scope** clarified — multiple syslog destinations explicitly excluded

---

## Claude's Discretion

All discretion items retained from 2026-05-14 context:
- Separate `syslog_queue` table (not reuse `audit_events`)
- `SyslogConnector` follows `SiemConnector` hot-reload pattern
- Agent queue: `agent_syslog_queue` with DPAPI-encrypted blob
- Exponential backoff: 1s start, 60s max, with jitter
- MSGID = event type string
- Hostname from `hostname::get()`
- Admin TUI mirrors `screens/siem_config.rs`
- Integration: `SyslogConnector::forward(events)` called from `audit_store.rs`

## Deferred Ideas

Retained from 2026-05-14 context:
- Custom CA upload (post-v0.11.0)
- mTLS client certs (post-v0.11.0)
- UDP transport (deferred indefinitely)
- Content redaction per destination (post-v0.11.0)
- Multiple destinations (deferred)
- TCP without TLS (deferred indefinitely)
