# External Integrations

**Analysis Date:** 2026-04-10

## APIs & External Services

**Policy Engine (Central DLP Evaluation):**
- Service: dlp-server REST API (local network HTTPS endpoint)
- What it's used for: File access policy evaluation
- SDK/Client: `reqwest` + `dlp-common::EvaluateRequest/Response`
- Protocol: HTTPS POST to `/evaluate` endpoint
- Client: `dlp-agent` via `EngineClient` (`dlp-agent/src/engine_client.rs`)
- Retry strategy: Exponential backoff (3 attempts, 200ms-4s)
- Timeout: 10 seconds
- Fallback behavior: Offline cache on unreachable (fails closed = DENY)

**SIEM Relay (Splunk & ELK/Elasticsearch):**
- Services: 
  - Splunk HTTP Event Collector (HEC) - `https://splunk:8088` (configurable)
  - Elasticsearch/ELK - `https://elastic:9200` (configurable)
- What it's used for: Batched streaming of audit events for SIEM analysis
- SDK/Client: `reqwest` HTTP client
- Location: `dlp-server/src/siem_connector.rs`
- Config source: Hot-reloaded from SQLite `siem_config` table (no restart required)
- Event batching: Single HTTP request per backend
- Supported fields: AuditEvent (all fields except file content/payload)

**Admin API (Server Management):**
- Service: dlp-server HTTP REST API
- Endpoints: 
  - `/admin/policies` - CRUD policy management
  - `/admin/exceptions` - Exception management
  - `/admin/siem-config` - SIEM endpoint configuration
  - Authentication: JWT Bearer token
- Client: `dlp-admin-cli` via `EngineClient` (`dlp-admin-cli/src/client.rs`)
- TLS: Optional mTLS with client certificates (via env vars)

## Data Storage

**Databases:**
- SQLite 3 (bundled)
  - Connection: Single `rusqlite::Connection` wrapped in `parking_lot::Mutex`
  - Client: `rusqlite` crate
  - Location: `dlp-server/src/db.rs`
  - Tables:
    - `audit_events` - Append-only audit trail
    - `agents` - Registered agent hostnames and last-seen timestamps
    - `siem_config` - Splunk/ELK configuration (single row, hot-reload)
    - `exceptions` - Policy exceptions/overrides
    - `admin_users` - dlp-admin user accounts (bcrypt hashed passwords)
  - WAL mode enabled (better concurrent read performance)
  - Concurrency note: Uses Tokio `spawn_blocking()` to avoid reactor blocking

**File Storage:**
- Local filesystem only (no cloud storage)
  - Agent logs: `C:\ProgramData\DLP\logs\` (rotated)
  - Server logs: stdout/JSON (configurable via tracing-appender)
  - Agent config: `C:\ProgramData\DLP\agent-config.toml`

**Caching:**
- In-memory policy cache (dlp-agent) - populated on startup from server
- SID→username cache (dlp-agent identity resolver) for performance

## Authentication & Identity

**Admin Auth (dlp-server):**
- Provider: Custom (server-generated)
- Implementation: JWT tokens signed with `JWT_SECRET` env var
- Token location: Bearer header in HTTP requests
- User database: SQLite `admin_users` table (bcrypt hashed passwords)
- First-run setup: Interactive prompt or `--init-admin <password>` CLI flag
- User count: Single `dlp-admin` superuser only

**Endpoint Identity (dlp-agent):**
- Windows user resolution via thread impersonation tokens
- SID extraction: `Win32_Security::Authorization::ConvertSidToStringSidW`
- Username lookup: `LookupAccountSidW` (cached)
- Groups: Not yet fetched (placeholder comment mentions "Groups are fetched via a separate AD lookup")
- Location: `dlp-agent/src/identity.rs`

**SMB Session Identity (dlp-agent on file servers):**
- File server scenario: Agent running on SMB share, intercepting remote user access
- Identity source: SMB session token (impersonation when hooked)
- User domain/username resolution: Similar to local identity
- Location: `dlp-agent/src/session_identity.rs`

**No Active Directory Integration (Currently):**
- LDAP3 dependency is present but not used in visible code
- AD lookup is noted as future work ("Groups are fetched via separate AD lookup")
- Domain name is resolved but only for context, not for group membership queries
- Current model: Windows token SID-based identity only

## Monitoring & Observability

**Error Tracking:**
- None (no external error tracking service)

**Logs:**
- Framework: `tracing` + `tracing-subscriber` (structured JSON logging)
- Output:
  - dlp-agent: File-based logs (JSON format) with rotation via `tracing-appender`
  - dlp-server: stdout/stderr (configurable via `--log-level` flag)
  - dlp-admin-cli: stderr via `tracing-subscriber::fmt::init()`
- Levels: trace, debug, info, warn, error (controlled by env var or CLI flag)
- All sensitive info redacted from logs (passwords, tokens never logged)

## CI/CD & Deployment

**Hosting:**
- Windows Server (native service deployment)
- Installer: WiX v4 MSI package generation
- Service account: Runs as SYSTEM (dlp-agent as Windows Service)

**CI Pipeline:**
- SonarCloud code quality scanning (`sonar-project.properties`)
- No CI/CD tool configured yet (ready for GitHub Actions, GitLab CI, etc.)

**Deployment Method:**
- MSI installer (`installer/DLPAgent.wxs`)
  - Package name: "DLP Agent"
  - Installs to: `C:\Program Files\DLP\`
  - Includes: dlp-agent.exe, dlp-user-ui.exe, dlp-admin-cli.exe, config/, logs/
  - Scope: Per-machine (ALLUSERS)
  - Service: Registered as Windows Service on install
  - Build: PowerShell script (`installer/build.ps1`)

## Environment Configuration

**Required env vars:**
- `JWT_SECRET` - for server JWT signing (required for admin API)

**Optional env vars (alert routing):**
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO` - email alerts
- `ALERT_WEBHOOK_URL`, `ALERT_WEBHOOK_SECRET` - webhook alerts
- `DLP_SERVER_REPLICAS` - comma-separated list of replica servers for policy sync

**Optional env vars (agent-server communication):**
- `DLP_SERVER_URL` - override default server URL (default: http://127.0.0.1:9090)
- `DLP_ENGINE_CERT_PATH`, `DLP_ENGINE_KEY_PATH` - mTLS client certificate paths
- `DLP_ENGINE_TLS_VERIFY` - set to `false` to disable TLS verification (dev only)

**Secrets location:**
- Environment variables only (no `.env` file checked in; `.gitignore` enforces this)
- Sensitive configs stored in:
  - `JWT_SECRET` - server process environment
  - `SMTP_PASSWORD`, `ALERT_WEBHOOK_SECRET` - server process environment
  - Passwords hashed with bcrypt before database storage

## Webhooks & Callbacks

**Incoming:**
- None

**Outgoing:**
- Alert webhook: POST to `ALERT_WEBHOOK_URL` with alert payload (optional)
- SIEM Splunk HEC: POST to `https://splunk:8088/services/collector` with batched events
- SIEM Elasticsearch: POST to `https://elastic:9200/{index}/_doc` with events
- Policy sync replicas: POST to peer servers with policy updates (not yet implemented)

## Named Pipes & IPC Mechanisms

**dlp-agent to dlp-user-ui (Named Pipes):**
- Protocol: Custom binary framing (length-prefixed messages)
- Pipes: Two named pipes (request/response style)
- Locations: `dlp-agent/src/ipc/pipe1.rs`, `dlp-agent/src/ipc/pipe2.rs`
- Messages: Defined in `dlp-agent/src/ipc/messages.rs`
- Frame format: `dlp-agent/src/ipc/frame.rs`
- Use cases: Notify UI of blocks, display dialogs, clipboard events

## Windows APIs & System Integration

**Security APIs (Win32_Security):**
- `ConvertSidToStringSidW` - SID to string conversion
- `ConvertStringSidToSidW` - String to SID conversion
- `LookupAccountSidW` - SID to username resolution
- `GetNamedSecurityInfoW` - NTFS ACL/owner retrieval
- `ImpersonateSelf`, `RevertToSelf` - Token impersonation for identity resolution
- Locations: `dlp-agent/src/identity.rs`, `dlp-agent/src/audit_emitter.rs`

**Process/Threading APIs:**
- `OpenProcess`, `OpenProcessToken` - Process token access
- `GetCurrentProcess`, `GetCurrentThread` - Current process/thread handles
- `CreateProcessAsUserW` - Spawn UI as user (not system)
- Locations: `dlp-agent/src/identity.rs`, `dlp-user-ui` process spawn

**File System Monitoring:**
- `notify` crate watches file system (abstraction over Windows APIs)
- Hooked via filter driver (not explicit WinAPI calls, handled by `notify`)
- Interception: Policy evaluation on PreCreate, PreWrite operations
- Location: `dlp-agent/src/interception/file_monitor.rs`, `dlp-agent/src/detection/mod.rs`

**Clipboard Monitoring:**
- `Win32_UI_WindowsAndMessaging`: `SetWindowsHookExW`, `RegisterClassW`
- Clipboard message interception (WH_CLIPBOARD hook)
- Locations: `dlp-agent/src/clipboard/listener.rs`, `dlp-user-ui` clipboard access
- Secure boundary: Protected clipboard browser boundary (SEED-002 design)

**USB Detection:**
- `RegisterDeviceNotificationW`, `DEV_BROADCAST_DEVICEINTERFACE_W`
- Device arrival/removal notification via WM_DEVICECHANGE
- Location: `dlp-agent/src/detection/usb.rs`

**Registry Access:**
- `RegOpenKeyExW`, `RegQueryValueExW` - Read registry values
- Used for: Auto-detecting dlp-server bind address
- Scope: HKEY_LOCAL_MACHINE
- Location: `dlp-admin-cli/src/registry.rs`

**Windows Service Control:**
- `windows-service` crate wraps service APIs
- Service installation, start, stop, removal
- Service main entry point
- Location: `dlp-agent/src/main.rs` (service loop)

**ETW (Event Tracing for Windows):**
- Win32_System_Diagnostics_Etw features referenced but not actively used in visible code
- Available for future event tracing integration

**Network APIs (MPR/WNet):**
- `WNetOpenEnumW`, `WNetEnumResourceW` - Enumerate network shares
- Used by: `dlp-agent/src/detection/network_share.rs`
- Purpose: Detect shared drives/network storage for monitoring scope

**Console/Pipe APIs:**
- Win32_System_Pipes: Named pipes for IPC
- Win32_System_Console: Console attachment (service logging)
- Win32_System_IO: I/O operations

---

*Integration audit: 2026-04-10*
