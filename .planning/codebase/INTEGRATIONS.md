# INTEGRATIONS

## Third-party APIs and services

## Active Directory / LDAP
- **Library:** `ldap3` (workspace dependency 0.11)
- **Where used:** server and shared layers (`dlp-server`, `dlp-common`, and agent-side AD resolution flows)
- **Purpose:**
  - User/group/device identity resolution
  - LDAP-backed policy context (group membership, trust/domain attributes)
  - Admin SID/group checks (from project docs and server module names)

## SIEM and event forwarding
- **Where configured:** `dlp-server` (`siem_connector`, `siem_config` endpoints in admin API)
- **External targets visible in code/comments:**
  - **Splunk HEC** (`splunk_url`, `splunk_token`)
  - **ELK/Elasticsearch** (`elk_url`, `elk_index`, optional `elk_api_key`)
- **Transport:** outbound HTTPS via `reqwest` (rustls)

## Webhook + SMTP alerting
- **Where used:** `dlp-server::alert_router`
- **Email:** `lettre` SMTP transport (`tokio1-rustls-tls` feature)
- **Webhook:** configured URL + optional secret in alert config payload
- **Use case:** deny/alert policy outcomes and operational notifications

## Policy/evaluation API integration
- **Agent -> Server:** `dlp-agent` uses `reqwest` to call `POST /evaluate` (default `http://127.0.0.1:9090`)
- **Admin CLI -> Server:** `dlp-admin-cli` talks to server REST endpoints for auth, policy CRUD, config and status
- **Framework on server side:** `axum`

## Database systems

## Primary data store
- **Database:** SQLite
- **Library:** `rusqlite` with `bundled` feature in `dlp-server`
- **Connection pooling:** `r2d2` + `r2d2_sqlite`
- **Observed usage:**
  - Admin users/auth material
  - Policy storage and versioning
  - Agent registry / heartbeat status
  - SIEM + alert + LDAP configuration rows
  - Audit/exception related stores (`audit_store`, `exception_store` modules)

## Authentication providers and mechanisms

## Admin authentication
- **Password hashing:** `bcrypt`
- **Token model:** JWT (`jsonwebtoken`)
- **API protection:** server routes split into public (health/ready/auth) and JWT-protected admin routes (per `admin_api` docs/comments)

## Endpoint/service identity context
- **Windows identity APIs:** extensive `windows` crate usage in `dlp-agent` and `dlp-common`
- **Directory-backed identity:** LDAP/AD config and client wiring

## Infrastructure and deployment platforms

## Runtime/deployment shape
- **Endpoint:** Windows Service (`dlp-agent`) + separate user-session UI process (`dlp-user-ui`)
- **Server:** standalone Rust HTTP service (`dlp-server`)
- **Admin tooling:** terminal UI client (`dlp-admin-cli`)
- **Installer stack:** WiX source (`installer/DLPAgent.wxs`) and PowerShell build script (`installer/build.ps1`)
- **Operations scripts:** PowerShell component/service management scripts under `scripts/`

## OS/platform dependencies
- Heavy integration with **Win32 APIs** via `windows` crate across agent/UI/hook DLL
- Hooking/enforcement-adjacent components include:
  - `dlp-hook-dll` (cdylib)
  - WFP module names in agent (`wfp_manager`, `wfp_ffi`)
  - Print subsystem modules (`print_watcher`, `print_enforcer`, parser)

## Communication services

## Network and messaging channels
- **HTTP/HTTPS:** internal API calls (agent/admin -> server), external SIEM/webhook egress
- **SMTP:** alert notifications via configured mail server
- **Named pipes / IPC:** local Windows IPC components present in agent/UI/hook modules (`hook_ipc`, `pipe_client`, `ipc` dirs)

## Not observed directly from scanned manifests
- No cloud-hosted managed DB/service SDKs (e.g., RDS/Azure SQL/Postgres clients) were seen in Cargo manifests.
- No OAuth/OpenID third-party auth provider crate usage was visible; auth appears custom JWT + bcrypt + AD/LDAP context.
