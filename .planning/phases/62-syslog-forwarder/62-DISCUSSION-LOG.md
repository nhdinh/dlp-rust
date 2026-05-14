# Phase 62: Syslog Forwarder - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-14
**Phase:** 62-Syslog Forwarder
**Areas discussed:** Message Format, Queue Architecture, TLS Trust Model

---

## Message Format

| Option | Description | Selected |
|--------|-------------|----------|
| JSON-in-MSG only | Embed stable JSON payload in RFC 5424 MSG field. Modern SIEMs parse JSON natively. | ✓ |
| RFC 5424 Structured Data only | Native structured data elements. Standards-compliant but harder for SIEMs. | |
| Both with toggle | Admin TUI lets operators choose. Most flexible but doubles test surface. | |

**User's choice:** JSON-in-MSG only
**Notes:** Modern SIEMs (Splunk, Elastic, Sentinel) all parse JSON natively. Single format reduces implementation and test surface.

---

## Severity Mapping

| Option | Description | Selected |
|--------|-------------|----------|
| Direct mapping | Alert=ERROR, Block=WARNING, Audit=INFO. Simple 1:1. | |
| Policy-tier mapping | T4=ERROR, T3=WARNING, T2/T1=INFO. Data-sensitivity driven. | |
| Configurable per event type | Admin TUI override. Default: Alert=ERROR, Block=WARNING, Audit=INFO. | ✓ |

**User's choice:** Configurable per event type
**Notes:** User wants operator flexibility. Default mapping covers 95% of cases; custom mapping for specialized SIEM routing.

---

## Facility Code

| Option | Description | Selected |
|--------|-------------|----------|
| LOCAL4 (dedicated) | LOCAL4 reserved for DLP. Clean separation. | |
| LOCAL0 (common) | Most commonly used. Simplest default. | |
| Configurable (LOCAL0-7) | Admin TUI picks. Default LOCAL4. | ✓ |

**User's choice:** Configurable (LOCAL0-LOCAL7)
**Notes:** Flexibility for environments where LOCAL4 is already claimed.

---

## Batching

| Option | Description | Selected |
|--------|-------------|----------|
| Single-message only | One syslog message per event. Simpler, no partial loss. | |
| Batched over TCP/TLS | Multiple newline-delimited messages per write. Better throughput. | |
| Both with toggle | Admin TUI chooses. Default batched for prod, single for debug. | ✓ |

**User's choice:** Both with toggle
**Notes:** Default batched for production throughput; single-message for debugging/tracing.

---

## Queue Architecture

| Option | Description | Selected |
|--------|-------------|----------|
| Agent-side only | Agent queues locally, forwards to server on reconnect. | |
| Server-side only | Server holds queue. Simpler but loses events on network partition. | |
| Both — agent AND server | Maximum reliability. Both queues encrypted. | ✓ |

**User's choice:** Both — agent AND server
**Notes:** Maximum audit compliance. Agent queues when server unreachable; server queues when syslog collector unreachable.

---

## Retry Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| FIFO with tail-drop | Oldest-first, drop newest when full. Audit-order preserving. | |
| FIFO with head-drop | Oldest-first, drop oldest when full. Newer events prioritized. | |
| Both with configurable policy | Admin TUI chooses. Default tail-drop. | ✓ |

**User's choice:** Both with configurable policy
**Notes:** Default FIFO tail-drop for compliance; head-drop option for real-time-prioritized deployments.

---

## Max Queue Size

| Option | Description | Selected |
|--------|-------------|----------|
| Different per side | Agent=10K, Server=100K. Accounts for disk capacity difference. | ✓ |
| Uniform | Same default both sides. Simpler config. | |
| Byte-based | Agent=1MB, Server=10MB. Accounts for variable event sizes. | |

**User's choice:** "All per your recommendations" — Claude chose different defaults per side.
**Notes:** Agent=10,000 events, Server=100,000 events. Both configurable in TUI. Rationale: endpoint disk is limited; server has more capacity.

---

## TLS Trust Model

| Option | Description | Selected |
|--------|-------------|----------|
| System CA store + custom CA | System CA + admin-uploaded PEM for internal PKI. | |
| System CA + custom CA + mTLS | Full support including mutual TLS. Most complex. | |
| System CA only (simple) | Windows system CA store. No custom CA or client certs. | ✓ |

**User's choice:** System CA only (keep it simple)
**Notes:** Covers majority of enterprise SIEMs. Custom CA and mTLS deferred to post-v0.11.0.

---

## TLS Version

| Option | Description | Selected |
|--------|-------------|----------|
| TLS 1.3 only | Modern security. Potential legacy compatibility issues. | |
| TLS 1.2 minimum (1.3 preferred) | Broad compatibility. 1.3 used when available. | ✓ |
| Admin TUI configurable | Operator picks minimum version. Default 1.2. | |

**User's choice:** TLS 1.2 minimum (1.3 preferred)
**Notes:** Broad enterprise SIEM compatibility while preferring modern TLS.

---

## Claude's Discretion

- Max queue sizes: Agent=10,000 events, Server=100,000 events (configurable)
- RFC 5424 header details (app-name, procid, msgid format)
- Reconnection backoff: exponential 1s → 60s with jitter
- Queue table schema (`syslog_queue` with `event_json`, `created_at`, `retry_count`, `last_error`)
- Agent-side DPAPI encryption approach
- Server-side KEK encryption with AAD pattern
- Integration point: call `syslog_connector.forward()` from `audit_store.rs`

## Deferred Ideas

- Custom CA certificate upload (post-v0.11.0)
- Mutual TLS (mTLS) client certificate authentication (post-v0.11.0)
- UDP syslog transport (uncommon, deferred indefinitely)
- Content redaction / field filtering per destination (post-v0.11.0)
- Multiple syslog destinations (single destination in Phase 62)
- Syslog over TCP without TLS (security risk, deferred indefinitely)
