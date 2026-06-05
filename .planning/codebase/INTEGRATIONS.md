# Integration Points

## Project: Enterprise DLP System (NTFS + Active Directory + ABAC)

---

## 1. External Services and APIs

### 1.1 Active Directory / LDAP

| Aspect | Detail |
|--------|--------|
| **Protocol** | LDAP v3 |
| **Library** | `ldap3` 0.11 |
| **Usage** | Identity resolution, group membership lookup, AD site detection |
| **Configuration** | URL, base DN, TLS requirement, cache TTL, VPN subnets stored in SQLite |
| **Security** | TLS optional (`require_tls` flag), credential redaction via `secrecy` crate |

### 1.2 Chrome Enterprise Content Analysis SDK

| Aspect | Detail |
|--------|--------|
| **Protocol** | Named pipes + Protocol Buffers (proto2) |
| **Library** | `prost` 0.14 (codegen), custom proto definitions |
| **Usage** | Browser integration for file download, attachment, print, clipboard monitoring |
| **Message Types** | `ContentAnalysisRequest`, `ContentAnalysisResponse` |
| **Connectors** | FILE_DOWNLOADED, FILE_ATTACHED, BULK_DATA_ENTRY, PRINT, FILE_TRANSFER |

### 1.3 Splunk (SIEM)

| Aspect | Detail |
|--------|--------|
| **Protocol** | HTTPS + Splunk HEC (HTTP Event Collector) |
| **Endpoint** | Configurable base URL (e.g., `https://splunk:8088`) |
| **Authentication** | Splunk HEC token (encrypted at rest) |
| **Library** | `reqwest` 0.12 |
| **Configuration** | Admin API: `GET/PUT /admin/siem-config` |

### 1.4 Elasticsearch / ELK

| Aspect | Detail |
|--------|--------|
| **Protocol** | HTTPS |
| **Endpoint** | Configurable base URL (e.g., `https://elastic:9200`) |
| **Authentication** | API key (encrypted at rest) |
| **Library** | `reqwest` 0.12 |
| **Configuration** | Admin API: `GET/PUT /admin/siem-config` |

### 1.5 Syslog (RFC 5424)

| Aspect | Detail |
|--------|--------|
| **Protocol** | TLS over TCP (RFC 5424) |
| **Library** | `tokio-rustls` 0.26 |
| **Certificate Store** | Native system CA (`rustls-native-certs` 0.8) |
| **Configuration** | Admin API: `GET/PUT /admin/syslog-config`, test endpoint |
| **Queue** | SQLite-backed persistent queue with retry logic |

### 1.6 SMTP (Email Alerts)

| Aspect | Detail |
|--------|--------|
| **Protocol** | SMTP over TLS (STARTTLS or SMTPS) |
| **Library** | `lettre` 0.11 (`tokio1-rustls-tls`, `smtp-transport`, `builder`) |
| **Usage** | Alert router for policy violation notifications |
| **Security** | Password encrypted at rest via `secrecy` |

---

## 2. Third-Party Libraries and SDKs

### 2.1 Windows Platform SDK (via `windows` crate)

Extensive use across all crates. Key API areas:

| API Area | Features Used | Purpose |
|----------|---------------|---------|
| **Security** | `Win32_Security`, `Win32_Security_Authorization`, `Win32_Security_Cryptography`, `Win32_Security_WinTrust` | ACLs, SIDs, DPAPI, code signing verification |
| **File System** | `Win32_Storage_FileSystem` | NTFS operations, file monitoring |
| **Registry** | `Win32_System_Registry` | Configuration storage, Chrome registry hooks |
| **Services** | `Win32_System_Services`, `Win32_System_Threading` | Windows Service lifecycle, process management |
| **Networking** | `Win32_NetworkManagement_WNet`, `Win32_Networking_ActiveDirectory`, `Win32_NetworkManagement_WindowsFilteringPlatform` | Network shares, AD site lookup, WFP egress filtering |
| **UI** | `Win32_UI_WindowsAndMessaging`, `Win32_UI_Shell`, `Win32_Graphics_Gdi` | Window hooks, drag-and-drop, tray icon |
| **Diagnostics** | `Win32_System_Diagnostics_Etw`, `Win32_System_Diagnostics_ToolHelp` | ETW process watching, process enumeration |
| **Devices** | `Win32_Devices_DeviceAndDriverInstallation`, `Win32_Devices_Properties` | USB device enumeration, PnP properties |
| **Printing** | `Win32_Graphics_Printing` | Print spooler monitoring, XPS parsing |
| **OLE** | `Win32_System_Ole` | Drag-and-drop interception |
| **AppX** | `Win32_Storage_Packaging_Appx` | UWP application identity resolution |
| **WDK** | `Wdk_System_SystemInformation`, `Wdk_System_Threading` | Kernel-level hooks (hook DLL) |

### 2.2 WMI

| Aspect | Detail |
|--------|--------|
| **Library** | `wmi` 0.18 |
| **Namespace** | `ROOT\CIMV2\Security\MicrosoftVolumeEncryption` |
| **Usage** | BitLocker status queries, encryption detection |
| **Features** | `chrono` support for WMI datetime types |

### 2.3 ETW (Event Tracing for Windows)

| Aspect | Detail |
|--------|--------|
| **Library** | `ferrisetw` 1.2.0 |
| **Usage** | Real-time process creation/termination monitoring |
| **Integration** | Universal injection allowlist, AppInit DLL management |

---

## 3. Database and Storage Integrations

### 3.1 SQLite (Primary Data Store)

| Aspect | Detail |
|--------|--------|
| **Library** | `rusqlite` 0.39 (bundled, chrono support) |
| **Connection Pooling** | `r2d2` 0.8 + `r2d2_sqlite` 0.33 |
| **Schema** | Single-file database (`dlp-server.db` or configurable path) |
| **WAL Mode** | Enabled for concurrent read/write |

### 3.2 Database Schema (Server)

| Table / Repository | Purpose |
|--------------------|---------|
| `policies` | ABAC policy storage |
| `labels` | Data classification labels |
| `protected_paths` | Path-based protection rules |
| `allowlist` | Process/application allowlists |
| `agents` | Registered endpoint agents |
| `device_registry` | Known USB/removable devices |
| `disk_registry` | Discovered disk/volume information |
| `audit_events` | Audit log entries |
| `admin_users` | Admin user accounts (bcrypt passwords) |
| `siem_config` | Splunk/ELK connector configuration |
| `syslog_config` | Syslog forwarder configuration |
| `alert_router_config` | Email alert routing rules |
| `ldap_config` | Active Directory connection settings |
| `jwt_secret` | JWT signing secret |
| `secret_kek` | Key Encryption Key for secrets at rest |
| `system_kv` | Generic key-value storage |
| `syslog_queue` | Pending syslog messages |
| `bypass_alerts` | Bypass attempt alerts |
| `approvals` | Approval workflow records |
| `exceptions` | Policy exception grants |
| `credentials` | Encrypted credential store |
| `managed_origins` | Managed origin domains |

### 3.3 Agent Local Storage

| Storage | Purpose |
|---------|---------|
| SQLite (DPAPI-encrypted) | Offline audit queue |
| TOML files | Agent configuration |
| Named pipes | IPC between agent, UI, and hook DLL |
| Windows Registry | Service configuration, Chrome extension settings |

### 3.4 File System

| Location | Purpose |
|----------|---------|
| `C:\ProgramData\DLP\` | Logs, config, runtime data |
| NTFS ACLs | Coarse-grained access control baseline |
| Protected paths | Policy-enforced file system restrictions |

---

## 4. Authentication and Identity Providers

### 4.1 Active Directory (Primary Identity Source)

| Aspect | Detail |
|--------|--------|
| **Role** | Source of identity truth |
| **Integration** | LDAP bind + search for user/group resolution |
| **Caching** | In-memory cache with configurable TTL |
| **VPN Detection** | Subnet-based VPN presence detection |

### 4.2 Local Authentication (DLP Admin)

| Aspect | Detail |
|--------|--------|
| **Mechanism** | JWT (JSON Web Tokens) |
| **Signing** | HMAC-SHA256 (server-side secret) / Ed25519 (approval tokens) |
| **Library** | `jsonwebtoken` 9 |
| **Password Hashing** | `bcrypt` 0.16 |
| **Storage** | SQLite (`admin_users` table) |

### 4.3 Approval Workflow Tokens

| Aspect | Detail |
|--------|--------|
| **Algorithm** | Ed25519 |
| **Library** | `ed25519-dalek` 2 |
| **Usage** | Cryptographically signed approval tokens for policy exceptions |

### 4.4 Windows Security Context

| Aspect | Detail |
|--------|--------|
| **SID Resolution** | `ConvertSidToStringSidW`, `ConvertStringSidToSidW` |
| **Token Impersonation** | `CreateProcessAsUserW` (UI spawning) |
| **DPAPI** | `CryptProtectData` / `CryptUnprotectData` for local secret encryption |

---

## 5. Monitoring and Observability Tools

### 5.1 Structured Logging

| Aspect | Detail |
|--------|--------|
| **Framework** | `tracing` + `tracing-subscriber` |
| **Output Formats** | Plain text (dev), JSON (production) |
| **Filtering** | `EnvFilter` for level-based filtering |
| **Appenders** | `tracing-appender` for file-based logging |
| **Levels** | trace, debug, info, warn, error |

### 5.2 Audit Logging

| Aspect | Detail |
|--------|--------|
| **Storage** | SQLite (`audit_events` table) |
| **Forwarding** | SIEM (Splunk/ELK), Syslog, Email alerts |
| **Content** | Policy evaluations, admin actions, agent events, bypass attempts |
| **Encryption** | Secrets encrypted at rest (AES-GCM + PBKDF2) |

### 5.3 Health Monitoring

| Aspect | Detail |
|--------|--------|
| **Endpoint** | `GET /health` (dlp-server) |
| **Agent Health** | Periodic heartbeat to server |
| **Nightly CI** | Smoke tests against release binaries |

### 5.4 Alert Routing

| Channel | Technology | Configuration |
|---------|-----------|---------------|
| SIEM | Splunk HEC, Elasticsearch | Admin API `/admin/siem-config` |
| Syslog | RFC 5424 over TLS | Admin API `/admin/syslog-config` |
| Email | SMTP | Admin API `/admin/alert-router-config` |

### 5.5 Static Analysis & Quality Gates

| Tool | Integration | Metrics |
|------|-------------|---------|
| SonarQube / SonarCloud | GitHub Actions | Bugs, vulnerabilities, code smells, coverage |
| `cargo clippy` | CI | Lint violations |
| `cargo fmt --check` | CI | Format compliance |
| `cargo test` | CI | Test pass/fail |

---

## 6. Inter-Process Communication (IPC)

### 6.1 Named Pipes

| Pipe | Direction | Purpose |
|------|-----------|---------|
| Pipe 1 | Agent -> UI | Stop password, override requests |
| Pipe 2 | UI -> Agent | User responses, dialog results |
| Pipe 3 | Agent -> Hook DLL | Classification cache, policy updates |

### 6.2 Protocol

| Aspect | Detail |
|--------|--------|
| **Framing** | Length-prefixed messages |
| **Serialization** | `bincode` (binary) + `serde` |
| **Security** | Pipe DACL restrictions (Windows ACLs on named pipes) |

---

## 7. Hook / Injection Architecture

### 7.1 API Hook DLL

| Aspect | Detail |
|--------|--------|
| **Crate** | `dlp-hook-dll` |
| **Type** | `cdylib` + `rlib` |
| **Targets** | Cloud sync clients (OneDrive, Dropbox, etc.) |
| **Technique** | `retour` for ntdll syscall-stub trampolines |
| **Architecture** | x64 + x86 (both targets built in CI) |

### 7.2 Injection Methods

| Method | Usage |
|--------|-------|
| **AppInit_DLLs** | Legacy application hooking |
| **Universal Injection** | ETW-based process watcher with allowlist |
| **WFP (Windows Filtering Platform)** | Network egress filtering |

---

## 8. Summary Matrix

| Integration Category | Technologies |
|---------------------|--------------|
| **Identity** | Active Directory (LDAP), Windows SIDs, JWT, Ed25519 |
| **Database** | SQLite (rusqlite), r2d2 connection pooling |
| **Web/API** | axum, tower, reqwest, JSON REST |
| **Browser** | Chrome Content Analysis SDK (protobuf over named pipes) |
| **SIEM** | Splunk HEC, Elasticsearch, Syslog (RFC 5424 over TLS) |
| **Email** | SMTP (lettre) |
| **Windows Platform** | windows crate (Security, FileSystem, Networking, UI, ETW, WFP, WMI) |
| **Crypto** | AES-GCM, PBKDF2, HMAC, SHA-256, Ed25519, bcrypt, DPAPI |
| **IPC** | Named pipes with bincode serialization |
| **Hooking** | retour trampolines, AppInit_DLLs, ETW process watching |
| **Observability** | tracing (structured logging), SonarQube, GitHub Actions CI |
