# DLP-RUST Architecture & Key Patterns

## System Component Diagram

DLP Server (axum)
├─ HTTP(S) port 9090: Auth, Audit Store, Policy Sync, Agent Registry
├─ SQLite DB: agents, audit_events, policies, exceptions, admin_users, siem_config
└─ External: Splunk HEC, ELK, SMTP (optional)
     ↕
DLP Agent (Windows Service)
├─ File Interception (notify crate)
├─ Policy Evaluation (HTTPS to Policy Engine)
├─ Offline Cache (60 s TTL, fail-closed for T3/T4)
├─ 3-Pipe IPC to DLP User UI
└─ Auth Hash Registry Cache
     ↕
DLP User UI (iced GUI)
├─ System Tray Icon + Context Menu
├─ Toast Notifications + Block Dialogs
└─ Password Prompts (DPAPI-wrapped)
     ↕
DLP Admin CLI (ratatui TUI)
├─ Server Management (policy/exception CRUD)
└─ User Authentication (JWT)

## Data Flow: File Operation to Decision

1. FILE INTERCEPTION: Windows event (notify) -> path, operation, PID
2. IDENTITY RESOLUTION: Resolve (user_sid, username) from PID
3. CLASSIFICATION: T1-T4 from extension or text pattern
4. POLICY EVALUATION: POST /evaluate to engine OR consult local cache
   - Network available? Call engine + cache result (60 s TTL)
   - Network down? Use local cache
   - T3/T4 + cache miss? DENY (fail-closed)
   - T1/T2 + cache miss? ALLOW (default-allow)
5. DECISION: Engine returns ALLOW | DENY | OVERRIDE_REQUEST | PROMPT
6. AUDIT EMISSION: Write to local JSONL + relay to server on heartbeat
7. UI NOTIFICATION: Send BlockNotify via Pipe1 if DENY/OVERRIDE

## Key Architectural Patterns

### 1. AppState Shared Axum State (dlp-server)

Single AppState passed to all HTTP handlers via axum State extractor.
- db: Mutex<rusqlite::Connection> (async handlers use spawn_blocking)
- siem: reads hot-reload config from siem_config table on each relay call
- Future: add connection pooling (r2d2 / deadpool)

### 2. Three-Pipe IPC Architecture

Named pipes enable SYSTEM service to communicate with user-session UI.

P1 (\.\pipe\DLPCommand): Bidirectional
- Agent->UI: BLOCK_NOTIFY, OVERRIDE_REQUEST, PASSWORD_DIALOG
- UI->Agent: PASSWORD_SUBMIT, PASSWORD_CANCEL, CLIPBOARD_READ

P2 (\.\pipe\DLPEventAgent2UI): Agent->UI
- TOAST, STATUS_UPDATE, HEALTH_PING, UI_RESPAWN, UI_CLOSING_SEQUENCE

P3 (\.\pipe\DLPEventUI2Agent): UI->Agent
- HEALTH_PONG, UI_READY, UI_CLOSING

Implementation: Raw Win32 calls on dedicated blocking threads
- CreateNamedPipeW, ConnectNamedPipe, ReadFile, WriteFile
- JSON frame encoding with message types
- Per-connection handler threads

### 3. Hot-Reload Configuration Pattern

SIEM Config: Single-row siem_config table (id=1)
- On each relay_events() call, re-read from DB
- Splunk/ELK endpoints change without server restart

Policies: Fetched on-demand from policies table
- Agent caches evaluated decisions (not policies)
- Policy changes via central cache invalidation

### 4. Offline-First Agent with Cache Fallback

Online: OfflineManager tracks state via Arc<AtomicBool>
- File operations -> Policy Engine via HTTPS
- Result cached locally (60 s TTL)

Offline (engine unreachable):
- Automatic transition on connection failure
- Consult local cache: Cache::get(resource_hash, subject_hash)
- T3/T4 sensitive + cache miss -> DENY (fail-closed)
- T1/T2 non-sensitive + cache miss -> ALLOW (default-allow)

Reconnection: Heartbeat task probes engine every 30 s

### 5. File-Based Stop-Password Flow

Prevents unauthorized service termination (sc stop) without dlp-admin credentials.

Sequence:
1. SCM issues sc stop
2. Agent sends PASSWORD_DIALOG over Pipe1
3. UI displays password prompt
4. UI returns PASSWORD_SUBMIT with DPAPI-wrapped plaintext
5. Agent unwraps via CryptUnprotectData (same session only)
6. Agent verifies against bcrypt hash in registry
   - Success: Proceed with shutdown
   - Failure (3 max): Abort stop

Hash sourced from (priority order):
- In-memory: AUTH_HASH static (process lifetime)
- Registry: HKLM\SOFTWARE\DLP\Agent\Credentials\DLPAuthHash (offline fallback)
- Server: GET /agent-credentials/auth-hash (canonical)

### 6. Server-Managed Auth Hash with Local Registry Cache

Credential storage hierarchy:
1. In-memory: AUTH_HASH static (fastest)
2. Registry: HKLM\SOFTWARE\DLP\Agent\Credentials (survives reboot)
3. Server: GET /agent-credentials/auth-hash (canonical)

Rationale: Agent never stores plaintext; password changes via server

### 7. Thread Model: dlp-agent Service Runtime

Main Service Thread
├─ Service Control Handler (register with SCM)
├─ Instance Mutex (single-instance lock)
├─ Process DACL Hardening (deny PROCESS_TERMINATE)
├─ Health Monitor Thread (ping-pong with UI)
├─ IPC Pipe Servers (3 blocking threads)
├─ Session Monitor Thread (poll new sessions every 2 s)
├─ USB Detection Thread (WM_DEVICECHANGE notifications)
├─ Tokio Async Runtime
│  ├─ File Interception Event Loop (notify -> evaluate -> audit)
│  ├─ Clipboard Listener (content classification)
│  ├─ Server Heartbeat + Audit Relay
│  └─ Health Pong Responder
└─ SCM Status Handle (report to Windows SCM)

Synchronization: BROADCASTER (RwLock), ROUTER (static), SESSION_IDENTITY_MAP
All pipe I/O on blocking threads (prevent async reactor stalls)

### 8. Database Schema Summary

agents: agent_id (PK), hostname, ip, os_version, agent_version, last_heartbeat, status
audit_events: id, timestamp, event_type, user_sid, user_name, resource_path, classification, decision, policy_id
policies: id (PK), name, priority, conditions (JSON), action, enabled, version
exceptions: id (PK), policy_id (FK), user_sid, approver, justification, duration_seconds
admin_users: username (PK), password_hash, created_at
agent_credentials: key (PK), value, updated_at (keys: auth-hash, policy-version)
siem_config: id (1), splunk_url/token/enabled, elk_url/index/api_key/enabled

## Trust Boundaries & Security Zones

ZONE 1: SYSTEM SERVICE (dlp-agent @ SYSTEM)
├─ File system interception (kernel-level via notify)
├─ Process identity resolution (impersonation)
├─ Registry HKLM read/write
├─ Named pipe server creation
├─ HTTPS client to Policy Engine
└─ Process DACL hardening

   Named Pipes + DPAPI Boundary

ZONE 2: USER SESSION (dlp-user-ui @ user)
├─ Pipe client (connect to pipes)
├─ Clipboard access (WH_GETMESSAGE hook)
├─ DPAPI wrap/unwrap (user context)
├─ UI rendering (iced + tray)
├─ Cannot: Write file system
└─ Cannot: Write registry

   HTTPS + JWT Boundary

ZONE 3: MANAGEMENT SERVER (dlp-server @ standard)
├─ SQLite database (audit log, policies)
├─ HTTP endpoint (axum, JWT auth)
├─ SIEM relay (Splunk/ELK HTTPS)
├─ SMTP alerting (lettre)
├─ Policy distribution
├─ Cannot: File system on endpoints
└─ Cannot: Process termination on endpoints

Trust Assumptions:
1. Network: HTTPS (TLS 1.2+), rustls
2. Auth: JWT tokens (RS256), bcrypt hashes
3. Authorization: Bearer token validation
4. Pipe Security: ACLs (SYSTEM + user session)
5. DPAPI: User session context encryption
6. Offline: Registry + memory cache trusted if server down

## Hot Paths & Performance

1. File Interception: Every write/delete -> event loop -> cache (60 s TTL)
2. Policy Cache: FNV-1a composite key (resource_hash, subject_hash)
3. Audit Buffering: JSONL on every event; relay on heartbeat
4. Pipe I/O: Blocking threads; payload < 64 KB per frame
5. Database: SQLite WAL mode (concurrent reads); no pool yet

## Future Enhancements

- LDAP3 integration (group membership)
- SIEM alert-on-deny pattern
- Policy version sync (agent <- server)
- Connection pool (r2d2)
- Agent config hot-reload (TOML)
- Multi-replica sync (HA)
- ELK field mapping standardization
