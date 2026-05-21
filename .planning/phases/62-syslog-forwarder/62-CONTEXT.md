# Phase 62: Syslog Forwarder - Context

**Gathered:** 2026-05-21 (auto-updated from 2026-05-14)
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 62 delivers a **native RFC 5424 syslog forwarder** from `dlp-server` to configured SIEM/SOC collectors over TLS, with an encrypted offline queue on both agent and server sides. This is part of the v0.11.0 milestone (Label Service + Workflow + Audit).

**Depends on:** Phase 61 (Approval Workflow Engine) — syslog forwarder consumes the same audit event pipeline. Phase 61 completed 2026-05-13.
**Requirements:** SYSLOG-01, SYSLOG-02, SYSLOG-03, SYSLOG-04 (see `.planning/REQUIREMENTS.md`)

**What Phase 62 builds:**
1. `syslog_config` SQLite table with host, port, protocol, facility, format, severity mapping, batching mode
2. Server-side `SyslogConnector` module — RFC 5424 message formatting, TLS transport, retry with backoff
3. Agent-side encrypted offline queue — local SQLite, DPAPI-encrypted, drains to server on reconnect
4. Server-side queue — SQLite, KEK-encrypted, drains to syslog collector when reachable
5. Admin TUI syslog configuration screen — mirrors `screens/siem_config.rs` pattern
6. Stable JSON payload format with all required audit fields

**What Phase 62 does NOT build:**
- Custom CA certificate upload (TLS uses system CA store only in this phase)
- Mutual TLS (mTLS) client certificate authentication
- UDP syslog transport (TLS/TCP only)
- Syslog over TCP without TLS
- Content redaction / field filtering beyond what AlertRouter already does
- Multiple syslog destinations (single destination only)

</domain>

<decisions>
## Implementation Decisions

### Message Format
- **D-01:** JSON-in-MSG only — embed a stable JSON payload in the RFC 5424 MSG field. Modern SIEMs (Splunk, Elastic, Sentinel) parse JSON natively. No structured data toggle needed.
- **D-02:** JSON schema mirrors `AuditEvent` serde serialization with all fields: `event_id`, `timestamp` (UTC + local), `user_sid`, `user_upn`, `device_id`, `mac_addresses`, `fingerprint`, `hostname`, `source_path`, `destination`, `tier`, `data_owner`, `action`, `decision`, `rule_id`, `policy_version`, `approval_id`, `severity`.

### Severity Mapping
- **D-03:** Configurable per event type via admin TUI. Stored in `syslog_config` table. Default mapping: `Alert` (DenyWithAlert) -> syslog severity 3 (ERROR), `Block` (policy violation) -> severity 4 (WARNING), `Audit` (informational) -> severity 6 (INFO).

### Facility Code
- **D-04:** Configurable LOCAL0-LOCAL7 via admin TUI. Default LOCAL4 (dedicated to DLP). Stored in `syslog_config` table.

### Batching
- **D-05:** Configurable toggle via admin TUI. Default: batched over TCP/TLS for production (newline-delimited JSON, multiple events per write). Single-message mode available for debugging. Stored in `syslog_config` table.

### Queue Architecture
- **D-06:** Both agent-side AND server-side queues. Agent queues when server unreachable; server queues when syslog collector unreachable. Maximum reliability for audit compliance.
- **D-07:** Agent-side queue: local SQLite, DPAPI-encrypted (reuse Phase 47 crypto). Server-side queue: SQLite, KEK-encrypted (reuse existing `SecretCrypto`).

### Retry Strategy
- **D-08:** Configurable queue eviction policy via admin TUI. Options: FIFO with tail-drop (default), FIFO with head-drop, ring-buffer. Default is FIFO with tail-drop for audit compliance (strict ordering, drop newest when full).

### Max Queue Size
- **D-09:** Agent-side default: 10,000 events. Server-side default: 100,000 events. Both configurable in admin TUI. Rationale: endpoint disk is limited; server has more capacity.

### TLS Trust Model
- **D-10:** System CA store only. No custom CA upload or mTLS in Phase 62. Simplifies implementation and covers the majority of enterprise SIEM deployments.

### TLS Version
- **D-11:** TLS 1.2 minimum, TLS 1.3 preferred. Configurable via Rustls/rustls-native-certs. Broad compatibility with enterprise SIEM/SOC collectors. Rustls is already in the dependency tree via `reqwest` and `lettre`.

### Claude's Discretion
- Server-side queue should be a separate `syslog_queue` table (not reuse `audit_events`), with columns: `id`, `event_json`, `created_at`, `retry_count`, `last_error`. This keeps the queue distinct from the audit trail.
- The `SyslogConnector` should follow the `SiemConnector` pattern: hot-reload config from DB on every `forward()` call, no caching.
- Agent-side queue table: `agent_syslog_queue` with same schema but DPAPI-encrypted `event_json` blob.
- Reconnection backoff: exponential backoff starting at 1s, max 60s, with jitter. Reset on successful connection.
- Syslog message ID (`MSGID` field): use event type string (e.g., `DLP-BLOCK`, `DLP-ALERT`, `DLP-AUDIT`).
- Hostname field: use `hostname::get()` or agent heartbeat hostname.
- Admin TUI screen: mirror `screens/siem_config.rs` exactly — navigable row list with host, port, protocol toggle, format dropdown, facility dropdown, batching toggle, severity mapping, queue policy, test button.
- Integration point: `SyslogConnector::forward(events)` should be called from `audit_store.rs` after events are persisted, similar to how `SiemConnector::relay_events` is called.
- Approval workflow events (from Phase 61) MUST be forwarded through syslog: `approval_granted`, `approval_revoked`, `approval_expired`, `approval_used`.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Architecture
- `.planning/REQUIREMENTS.md` S"v0.11.0 — Syslog Forwarder" — SYSLOG-01..04 requirements
- `.planning/STATE.md` S"Pilot-First Path (post-v0.10.0)" — v0.11.0 phase breakdown
- `.planning/ROADMAP.md` S"v0.11.0 — Label Service + Workflow + Audit" — phase goal and success criteria
- `.planning/PROJECT.md` S"Tech Stack" — dependency versions and patterns

### Existing Code Patterns
- `dlp-server/src/siem_connector.rs` — `SiemConnector` pattern (hot-reload, batched relay, error handling). **MUST reuse** for `SyslogConnector`.
- `dlp-server/src/alert_router.rs` — `AlertRouter` pattern (fire-and-forget, config loading, test alert).
- `dlp-server/src/db/repositories/siem_config.rs` — `SiemConfigRepository` pattern (encrypted secrets, single-row config table).
- `dlp-server/src/db/mod.rs` — `init_tables()` shows schema initialization pattern.
- `dlp-admin-cli/src/screens/siem_config.rs` — Admin TUI config screen pattern. **Mirror for syslog screen.**
- `dlp-common/src/audit.rs` — `AuditEvent` struct and serde. JSON payload format derived from this.
- `dlp-agent/src/audit_emitter.rs` — Agent-side audit event emission. Queue drain logic plugs in here.
- `.planning/codebase/STACK.md` — Rust dependency stack; note rustls already present via reqwest/lettre.
- `.planning/codebase/ARCHITECTURE.md` — Audit/alert path data flow and crate boundaries.
- `.planning/codebase/INTEGRATIONS.md` — SIEM and event forwarding patterns.

### Related Docs
- No SPEC.md exists for Phase 62 — requirements are in REQUIREMENTS.md

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`SiemConnector`** (`dlp-server/src/siem_connector.rs`): Hot-reload config, batched HTTP relay, `SecretString` for secrets, error collection pattern. Model `SyslogConnector` after this.
- **`SiemConfigRepository`** (`dlp-server/src/db/repositories/siem_config.rs`): Single-row config table with encrypted secrets. Model `SyslogConfigRepository` after this.
- **`AlertRouter`** (`dlp-server/src/alert_router.rs`): Fire-and-forget alert delivery, test alert pattern, config loading.
- **`SecretCrypto`** (`dlp-server/src/crypto/mod.rs`): Phase 47 KEK infrastructure for encrypting secrets and queue data.
- **`AuditEvent`** (`dlp-common/src/audit.rs`): Common event format. JSON payload is `serde_json::to_string` of this struct.
- **`AppState { pool, crypto, policy_store, siem, alert, ad }`**: Add `syslog: Arc<SyslogConnector>` alongside `siem`.
- **Admin TUI `EngineClient`** (`dlp-admin-cli/src/client.rs`): HTTP client for admin API calls.
- **`rustls`** (via `reqwest` and `lettre`): Already in dependency tree. Use `tokio-rustls` or `rustls` directly for TLS syslog transport.

### Established Patterns
- **Repository pattern**: Stateless struct with `pool` parameter (like `SiemConfigRepository`).
- **Admin API CRUD**: `list` (GET), `get_by_id` (GET), `create` (POST), `update` (PUT), `delete` (DELETE) for config tables.
- **Config table**: Single-row table with `CHECK (id = 1)`, encrypted secrets, hot-reload on every use.
- **TUI config screen**: Navigable row list with editing mode and buffer (like `SiemConfig`).
- **Error handling**: Handlers return `Result<Json<T>, AppError>`. `AppError` defined in `dlp-server/src/error.rs`.
- **Fire-and-forget**: Alert and SIEM paths spawn async tasks that don't block the main request handler.
- **SQLite-backed queues**: Pattern from `audit_store.rs` — durable, polled, drained.

### Integration Points
- `dlp-server/src/db/mod.rs` — add `syslog_config` and `syslog_queue` tables to `init_tables()`.
- `dlp-server/src/admin_api.rs` — add `/admin/syslog-config` routes following existing `.route()` pattern.
- `dlp-server/src/main.rs` or `lib.rs` — add `syslog_connector: Arc<SyslogConnector>` to `AppState`.
- `dlp-server/src/audit_store.rs` — call `syslog_connector.forward(events)` after persisting audit events.
- `dlp-agent/src/audit_emitter.rs` — add agent-side `syslog_queue` SQLite table, drain logic on reconnect.
- `dlp-admin-cli/src/app.rs` — add `Screen::SyslogConfig` following `Screen::SiemConfig` pattern.

</code_context>

<specifics>
## Specific Ideas

- The JSON payload in the syslog MSG field should be a flat object (no nested structs) for maximum SIEM compatibility. Every field is a string or number.
- The `event_id` field should be a UUID v4 generated at event creation time, carried through audit_store -> syslog -> SIEM.
- The admin TUI syslog screen should have a "Test Connection" button that sends a synthetic `AuditEvent` with `event_type = TestAlert` through the syslog forwarder, similar to `AlertRouter::send_test_alert`.
- Agent-side queue encryption: encrypt the `event_json` string with DPAPI (`CryptProtectData`) before writing to SQLite. Decrypt with `CryptUnprotectData` on drain.
- Server-side queue encryption: reuse existing `SecretCrypto::encrypt()` with AAD `aad_for("syslog_queue", "event_json")`.
- RFC 5424 header format: `<priority>version timestamp hostname app-name procid msgid [structured-data] msg`
  - Example: `<134>1 2026-05-14T10:00:00.000Z webserver01 DLP-AUDIT 1234 DLP-BLOCK - {"event_id":"..."}`
  - Priority = facility * 8 + severity. Facility=LOCAL4=20, Severity=ERROR=3 -> priority=163. But since facility is configurable, compute at send time.
  - `app-name` = `DLP-AUDIT` (fixed).
  - `procid` = agent_id or server process ID.
  - `msgid` = event type (DLP-BLOCK, DLP-ALERT, DLP-AUDIT).
  - `structured-data` = `-` (nil value) since we're using JSON-in-MSG.
- No dedicated `syslog` crate in current dependency tree. Implement RFC 5424 formatting inline and use `tokio::net::TcpStream` + `tokio-rustls` for TLS transport.

</specifics>

<deferred>
## Deferred Ideas

- Custom CA certificate upload for TLS (post-v0.11.0 — requires cert management UI)
- Mutual TLS (mTLS) client certificate authentication (post-v0.11.0 — requires cert lifecycle management)
- UDP syslog transport (uncommon in enterprise, TLS is standard)
- Content redaction / field filtering per syslog destination (post-v0.11.0)
- Multiple syslog destinations (Phase 62 supports single destination; multi-destination deferred)
- Syslog over TCP without TLS (security risk — deferred indefinitely)

</deferred>

---

*Phase: 62-Syslog Forwarder*
*Context gathered: 2026-05-21*
