# REQUIREMENTS.md — v0.2.0 Feature Completion

## Milestone Goal

Complete all features that are implemented but not wired, and add AD integration for real ABAC attribute resolution.

## Requirements

### R-01: SIEM Relay Integration
**Priority:** Must
**Description:** Wire the existing `siem_connector` module into dlp-server startup. Splunk HEC and ELK/_bulk endpoints should receive audit events in real-time when configured via environment variables.
**Acceptance:** When SIEM env vars are set, audit events appear in the configured Splunk/ELK instance.

### R-02: Alert Routing (Email + Webhook)
**Priority:** Must
**Description:** Wire the existing `alert_router` module into dlp-server. DenyWithAlert decisions should trigger email (SMTP via lettre) and/or webhook notifications.
**Acceptance:** When SMTP/webhook env vars are set, T3/T4 block events trigger alerts.

### R-03: Policy Sync (Multi-Replica)
**Priority:** Should
**Description:** Wire the existing `policy_sync` module so policy CRUD operations are replicated to configured peer servers.
**Acceptance:** When `DLP_REPLICA_URLS` is set, policy create/update/delete propagates to peers.

### R-04: Config Push (Agent Config Distribution)
**Priority:** Should
**Description:** Wire the existing `config_push` module. Allow admins to push updated agent configs (monitored paths, exclusions, server URL) to registered agents via the server.
**Acceptance:** Admin can update agent config via API; agents receive updated config on next heartbeat.

### R-05: Active Directory Integration
**Priority:** Must
**Description:** Implement LDAP queries to Active Directory for real ABAC attribute resolution. The agent currently uses placeholder values for user groups, device trust, and network location.
**Acceptance:** ABAC evaluation uses real AD group membership and device attributes.

### R-06: Fix Integration Tests
**Priority:** Must
**Description:** `dlp-agent/tests/integration.rs` references removed `dlp_server` modules. Update to use current API.
**Acceptance:** `cargo test --workspace` passes with no compilation errors.

### R-07: Rate Limiting
**Priority:** Should
**Description:** Add tower rate limiting middleware to `/auth/login`, heartbeat, and event ingestion endpoints.
**Acceptance:** Brute-force login attempts are throttled. Event ingestion has per-agent rate limits.

### R-08: JWT Secret Configuration
**Priority:** Must
**Description:** Remove the hardcoded dev fallback JWT secret. Require `JWT_SECRET` env var in production; fail on startup if unset.
**Acceptance:** Server refuses to start without `JWT_SECRET` set (unless `--dev` flag).

### R-09: Agent Audit Logging for Admin Operations
**Priority:** Should
**Description:** Policy create/update/delete operations should be persisted as audit events (not just tracing logs) for compliance.
**Acceptance:** Admin CRUD operations appear in `audit_events` table with `EventType::AdminAction`.

### R-10: Connection Pool for SQLite
**Priority:** Could
**Description:** Replace single `Mutex<Connection>` with r2d2 or deadpool connection pool for better concurrent performance.
**Acceptance:** Multiple concurrent API requests don't serialize on a single mutex.
