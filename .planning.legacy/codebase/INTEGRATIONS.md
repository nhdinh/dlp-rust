# External Integrations

**Analysis Date:** 2026-05-06

## APIs & External Services

**Active Directory / LDAP:**
- Purpose: Identity resolution, group membership (`tokenGroups`), trust tier, VPN subnet detection
- SDK/Client: `ldap3` 0.11 (`dlp-common`)
- Config: `LDAP_URL`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD` env vars
- Implementation: `dlp-common/src/ad_client.rs`

**Chrome Enterprise Content Analysis API:**
- Purpose: Browser-level DLP integration (Google Chrome enterprise connector)
- Protocol: Protobuf over named pipes
- Implementation: `dlp-agent/src/chrome/` module
- SDK: `prost` for protobuf codegen

**SIEM Relay:**
- Purpose: Forward audit events to security information systems
- Platforms:
  - Splunk HEC (HTTP Event Collector)
  - ELK stack (Elasticsearch/Logstash)
- Client: `reqwest` (`dlp-server/src/siem_relay.rs`)
- Config: SIEM endpoint URL, API key/tokens

**Alert Router:**
- Purpose: Real-time alerting on policy violations
- Channels:
  - SMTP email (`lettre` 0.11)
  - Webhook (`reqwest`)
- Config: `ALERT_SMTP_HOST`, `ALERT_SMTP_USER`, `ALERT_WEBHOOK_URL` env vars
- Implementation: `dlp-server/src/alert_router.rs`

## Data Storage

**Databases:**
- SQLite (embedded, file-based)
  - Connection: `DATABASE_URL` env var or default path
  - Client: `rusqlite` 0.32 with `r2d2` connection pooling
  - Mode: WAL (`PRAGMA journal_mode=WAL`)
  - Schema: `dlp-server/src/db/mod.rs`
  - Tables: policies, agents, audit_events, device_registry, disk_registry, managed_origins, admin_users, sessions

**File Storage:**
- Local filesystem only
- Audit log: JSONL files (`dlp-agent/src/audit_emitter.rs`)
- Policy cache: In-memory (`RwLock<Vec<Policy>>`)

**Caching:**
- In-memory policy cache with TTL (300s refresh interval)
- `parking_lot::RwLock` for fast reads
- No external cache (Redis/Memcached) detected

## Authentication & Identity

**Auth Provider:**
- JWT Bearer tokens for admin API (`dlp-server`)
- Windows SIDs for endpoint identity (`dlp-agent`)
- Active Directory for group/trust resolution

**Implementation:**
- JWT generation/validation: `jsonwebtoken` 9.x (`dlp-server/src/auth.rs`)
- Windows SID resolution: `WindowsIdentity` struct (`dlp-agent/src/identity.rs`)
- Session identity map: `SessionIdentityMap` (`dlp-agent/src/session_identity.rs`)

## Monitoring & Observability

**Error Tracking:**
- Structured logging via `tracing` + `tracing-subscriber`
- Log levels: debug (development), info (production)
- No external error tracking service (Sentry, etc.) detected

**Logs:**
- Console output via `tracing` spans
- Audit events to JSONL files
- Server logs to stdout/stderr

## CI/CD & Deployment

**Hosting:**
- Windows Service (`dlp-agent`) via `windows-service` crate
- Standalone server binary (`dlp-server`)
- No containerization detected

**CI Pipeline:**
- SonarCloud scanning (`sonar-project.properties`)
- No GitHub Actions / Azure Pipelines files detected in repo

## Environment Configuration

**Required env vars:**
- `JWT_SECRET` - Token signing key
- `DATABASE_URL` - SQLite database path
- `LDAP_URL` - Active Directory server
- `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` - AD service account
- `SIEM_ENDPOINT` / `SIEM_API_KEY` - SIEM relay
- `ALERT_SMTP_HOST` / `ALERT_SMTP_USER` / `ALERT_SMTP_PASSWORD` - Email alerts
- `ALERT_WEBHOOK_URL` - Webhook alerts

**Secrets location:**
- `.env` file (development only, gitignored)
- Environment variables in production
- `secrecy` crate wrappers for in-memory secrets

## Webhooks & Callbacks

**Incoming:**
- None detected

**Outgoing:**
- SIEM relay HTTP POSTs (`dlp-server/src/siem_relay.rs`)
- Alert webhook POSTs (`dlp-server/src/alert_router.rs`)
- Admin CLI HTTP requests to server API (`dlp-admin-cli/src/api.rs`)

---

*Integration audit: 2026-05-06*
