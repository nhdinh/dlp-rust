# Architecture

## Overall Style

**Monorepo workspace** with a centralized server and distributed endpoint agents. Four-layer defense architecture designed for enterprise Windows environments.

## High-Level Architecture

```
                    ┌─────────────────────┐
                    │   Active Directory  │
                    │   (Identity Layer)  │
                    └──────────┬──────────┘
                               │ LDAP/Kerberos
                               ▼
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  Admin CLI   │────▶│   DLP Server    │◀────│   SIEM/Alerts    │
│  (TUI)       │     │  (Policy Layer) │────▶│  Splunk/ELK/SMTP │
└──────────────┘     └────────┬────────┘     └──────────────────┘
                              │ HTTPS
                              ▼
                    ┌─────────────────────┐
                    │     DLP Agent       │
                    │ (Enforcement Layer) │
                    │  Windows Service    │
                    └──────────┬──────────┘
                               │ Named Pipes
                               ▼
                    ┌─────────────────────┐
                    │     User UI         │
                    │  (Notification)     │
                    └─────────────────────┘
```

## Four Defense Layers

| Layer | Component | Responsibility |
|-------|-----------|---------------|
| Identity | Active Directory | Source of identity truth (users, groups, SIDs) |
| Access | NTFS ACLs | Coarse-grained baseline enforcement |
| Policy | DLP Server (ABAC engine) | Fine-grained dynamic policy evaluation |
| Enforcement | DLP Agent (Windows Service) | Real-time interception and blocking |

**Critical Rule:** `NTFS ALLOW + ABAC DENY = DENY` (ABAC always wins on denial)

## Core Data Flow

### Policy Evaluation

```
1. Agent intercepts file operation (NTFS minifilter / clipboard hook / USB plug)
2. Agent resolves user identity (SID → AD groups via LDAP)
3. Agent sends evaluation request to Server (HTTPS POST /evaluate)
4. Server ABAC engine evaluates policies (priority-ordered, first-match)
5. Decision returned: ALLOW | DENY | AllowWithLog | DenyWithAlert
6. Agent enforces decision (block/allow + audit)
7. Audit event emitted (Agent JSONL → Server → SIEM)
```

### Tiered Default-Deny (D-01)

- T1/T2 (Public/Internal): ALLOW if no policy matches
- T3/T4 (Confidential/Restricted): DENY if no policy matches

## Key Design Patterns

### ABAC Policy Model

- **Subject attributes**: user SID, AD groups, department, clearance level
- **Resource attributes**: classification tier (T1–T4), file path, data type
- **Environment attributes**: network location (Corporate/VPN/Guest), device trust, time
- **Action attributes**: READ, WRITE, COPY, DELETE, MOVE, PASTE
- **Condition modes**: ALL (&&), ANY (||), NONE (!any)
- **Priority ordering**: Lowest number first, first-match wins

### Fail-Safe Patterns

| Scenario | Behavior |
|----------|----------|
| Server unreachable | Agent fails closed (DENY), uses local cache |
| AD unreachable | Returns empty groups (fail-open for identity) |
| SIEM unreachable | Continues operation, queues events |
| Agent offline | Local JSONL audit, cache-based policy |

### Hot-Reload Configuration

SIEM, LDAP, alert router, and policy configurations are re-read from SQLite on each operation. No server restart required for configuration changes.

### Named Pipe IPC (Agent ↔ UI)

- Length-prefixed framing protocol
- Typed messages: PolicyViolation, ClipboardBlocked, DeviceBlocked, OverrideRequest
- Agent spawns per-session UI process via `CreateProcessAsUserW`
- Health ping-pong between agent and UI

### Audit Architecture

- **Never stores content**: Only metadata (path, user, action, classification, decision)
- **Append-only**: Agent writes JSONL locally, replays to server
- **Fan-out**: Server relays to SIEM (Splunk HEC / ELK bulk) and alert router (SMTP / webhook)

## Module Boundaries

### dlp-common (shared kernel)

Pure types and logic with no runtime dependencies:
- ABAC model (Policy, Decision, Condition, Action)
- Data classification (4-tier model)
- Audit event types
- Device/endpoint identity types
- AD client (LDAP queries, SID parsing)

### dlp-server (policy authority)

Central brain, owns all persistent state:
- REST API (axum) for admin and agent communication
- ABAC evaluation engine (in-memory policy cache)
- SQLite database (schema, repositories, migrations)
- SIEM relay (batched HTTP forwarding)
- Alert routing (SMTP, webhook)
- Agent registry (heartbeat tracking, offline detection)

### dlp-agent (enforcement point)

Windows Service running as SYSTEM:
- File operation interception (NTFS minifilter)
- Clipboard monitoring (Win32 hooks)
- USB/disk detection and enforcement (SetupDi, WMI)
- Network share monitoring (WNet APIs)
- Chrome Enterprise Content Analysis (protobuf)
- Named pipe IPC to user UI
- Offline caching and fail-closed behavior
- Password-protected service stop

### dlp-admin-cli (management interface)

TUI application for system administration:
- Policy CRUD operations
- Agent monitoring and configuration
- Disk/device registry management
- LDAP/SIEM configuration

### dlp-user-ui (user-facing)

Per-session GUI spawned by agent:
- Policy violation notifications (toast)
- Clipboard block dialogs
- Override request forms
- System tray icon with status

## Concurrency Model

| Component | Model |
|-----------|-------|
| Server | Tokio async (multi-threaded), r2d2 connection pool |
| Agent | Tokio async + blocking Win32 threads, OnceLock singletons |
| Admin CLI | Single-threaded event loop (ratatui) + blocking HTTP |
| User UI | Iced event loop + background tokio runtime |

## Security Architecture

- **Process hardening**: Agent sets restrictive DACL on its own process
- **Secret management**: `secrecy` crate wraps all passwords/tokens
- **Auth**: JWT for admin sessions, per-agent credential hashes
- **Transport**: rustls-tls for all HTTPS (no OpenSSL)
- **Service stop protection**: bcrypt-hashed password required to stop agent
