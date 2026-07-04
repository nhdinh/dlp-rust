# External Integrations

**Analysis Date:** 2026-07-03

## APIs & External Services

**Identity:**
- **Active Directory / LDAP v3**
  - SDK/Client: `ldap3` 0.11 (`dlp-common/src/ad_client.rs`).
  - Auth: Machine-account Kerberos bind; optional TLS (`require_tls` flag stored in `ldap_config` table).
  - Usage: User/group resolution, group membership lookup, AD site detection, device trust (`NetGetJoinInformation`), network location (`GetAdaptersAddresses` + VPN subnet matching).

**Browser:**
- **Chrome Enterprise Content Analysis SDK**
  - Protocol: Named pipes + Protocol Buffers (proto2).
  - Client: `prost` 0.14 (`dlp-agent/src/chrome/`, `dlp-agent/build.rs`, `dlp-agent/proto/`).
  - Connectors: `FILE_DOWNLOADED`, `FILE_ATTACHED`, `BULK_DATA_ENTRY`, `PRINT`, `FILE_TRANSFER`.

**SIEM / Alerting:**
- **Splunk HEC** — HTTPS ingest to configurable base URL; token encrypted at rest (`dlp-server/src/siem_connector.rs`, admin API `/admin/siem-config`).
- **Elasticsearch / ELK** — HTTPS with API-key auth; encrypted at rest (`dlp-server/src/siem_connector.rs`).
- **Syslog (RFC 5424)** — TLS over TCP via `tokio-rustls`; native CA store; SQLite-backed queue with retry (`dlp-server/src/syslog_connector.rs`, admin API `/admin/syslog-config`).
- **SMTP** — Email alerts via `lettre` 0.11 (STARTTLS/SMTPS); password encrypted at rest (`dlp-server/src/alert_router.rs`, admin API `/admin/alert-router-config`).

**Windows Platform APIs:**
- Extensive use of the `windows` crate (0.58/0.62) across Security, FileSystem, Registry, Services, Threading, Networking, WFP, ETW, Printing, Devices, UI, and WDK features.

## Data Storage

**Databases:**
- **SQLite** (primary server store)
  - Connection: `dlp-server/src/db/mod.rs` via `r2d2` pool; path configurable via `DLP_DATABASE_PATH` or default file.
  - Client/ORM: `rusqlite` 0.39; raw SQL encapsulated in repository modules under `dlp-server/src/db/repositories/`.
  - WAL mode enabled; `secure_delete` PRAGMA enabled.

**Agent Local Storage:**
- DPAPI-encrypted SQLite offline audit queue (`dlp-agent/src/offline_audit_queue.rs`).
- Append-only JSONL local audit log (`dlp-agent/src/audit_emitter.rs`).
- TOML agent configuration (`dlp-agent/src/config.rs`).
- Windows Registry for service/Chrome settings.

**File Storage:**
- Local filesystem only; no external object store.
- Protected paths enforced via policy, not NTFS ACL modification.

**Caching:**
- In-memory caches: `dlp-server::policy_store`, `dlp-server::label_service`, `dlp-agent::cache`, `dlp-agent::classification_cache`, `dlp-agent::approval_cache`, `dlp-agent::hash_cache`, `dlp-hook-dll::classification_cache`.

## Authentication & Identity

**Auth Provider:**
- **Active Directory** — Source of identity truth for Windows users and groups (`dlp-common/src/ad_client.rs`).
- **Local DLP Admin** — JWT (HMAC-SHA256) with bcrypt password storage (`dlp-server/src/admin_auth.rs`, `admin_users` table).
- **Approval Workflow Tokens** — Ed25519 signed JWTs (`dlp-server/src/approval_token.rs`).
- **Windows Security Context** — SID resolution, token impersonation (`CreateProcessAsUserW`), DPAPI for machine-bound secrets.

## Monitoring & Observability

**Error Tracking:**
- Structured logging via `tracing`; no external error-tracking service detected.
- Audit events stored in SQLite and forwarded to SIEM/syslog/email.

**Logs:**
- `tracing-subscriber` with `EnvFilter`; JSON output for production.
- File-based logging via `tracing-appender` (rolling file appender).
- Local JSONL audit logs on agent.

**Health Monitoring:**
- `GET /health` on `dlp-server`.
- Agent-to-server heartbeat (`POST /agents/{id}/heartbeat`).
- Agent<->UI mutual health ping-pong (`dlp-agent/src/health_monitor.rs`).

## CI/CD & Deployment

**Hosting:**
- On-premise / self-managed Windows endpoints; central `dlp-server` can run on Windows or Linux.

**CI Pipeline:**
- GitHub Actions:
  - `.github/workflows/build.yml` — Build, clippy, fmt check, tests, SonarQube scan.
  - `.github/workflows/nightly.yml` — Release build, smoke tests, health checks.
  - `.github/workflows/release.yml` — Release build, Authenticode signing, artifact upload.

**Deployment Artifacts:**
- MSI installer (`installer/DLPAgent.wxs`, `installer/build.ps1`).
- Authenticode signing via `signtool` in release workflow.

## Environment Configuration

**Required env vars (examples):**
- `DLP_SERVER_URL` — Agent/CLI server discovery.
- `DLP_DATABASE_PATH` — SQLite database path.
- `JWT_SECRET` — Development fallback JWT signing secret.
- `SONAR_TOKEN` — SonarQube scanner authentication.

**Secrets location:**
- `.env` file (gitignored) for local development.
- Encrypted SQLite rows for production secrets (SMTP passwords, SIEM tokens, webhook secrets, JWT secret, KEK) via `dlp-server::crypto::SecretCrypto`.
- DPAPI for machine-bound agent-side secrets.

## Webhooks & Callbacks

**Incoming:**
- Admin API webhooks for alert routing (`dlp-server/src/alert_router.rs`).
- Agent registration and heartbeat endpoints (`dlp-server/src/agent_registry.rs`).
- Audit event ingestion (`POST /audit/events`).

**Outgoing:**
- SIEM relay HTTPS posts to Splunk HEC / Elasticsearch.
- Syslog forwarder TLS messages.
- SMTP alert emails.
- Policy sync pushes to replica `dlp-server` instances (`dlp-server/src/policy_sync.rs`).

---

*Integration audit: 2026-07-03*
