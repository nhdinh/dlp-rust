# External Dependencies & Integrations

## Active Directory / LDAP

| Property | Value |
|----------|-------|
| Client library | `ldap3` 0.11 |
| Authentication | Machine account via Kerberos TGT (no stored credentials) |
| Queries | `tokenGroups` attribute for full transitive group closure |
| Caching | In-memory with configurable TTL (60–3600s), evict-on-access |
| Failure mode | Fail-open (returns empty groups on AD errors) |
| Configuration | `ldap_config` SQLite table, hot-reloaded |
| VPN detection | Subnet-based classification via `DsGetSiteNameW` |

## Database

| Property | Value |
|----------|-------|
| Engine | SQLite 3 (bundled via rusqlite 0.39) |
| Connection pooling | r2d2 (5 max connections) |
| Journal mode | WAL (Write-Ahead Logging) |
| Foreign keys | Enforced per connection |
| Location | Server-local file |

**Tables:** agents, audit_events, exceptions, admin_users, agent_credentials, policies, device_registry, disk_registry, siem_config, alert_router_config, ldap_config, global_agent_config, agent_config_overrides, managed_origins

## SIEM Integration

### Splunk HEC

| Property | Value |
|----------|-------|
| Protocol | HTTP Event Collector (HTTPS POST) |
| Endpoint | `/services/collector/event` |
| Auth | HEC token |
| Batching | Single HTTP request per batch |
| Configuration | `siem_config` table (hot-reload) |

### Elasticsearch / ELK

| Property | Value |
|----------|-------|
| Protocol | Bulk ingest (HTTPS POST) |
| Endpoint | `/_bulk` |
| Auth | Optional API key |
| Batching | Single HTTP request per batch |
| Configuration | `siem_config` table (hot-reload) |

### Data Flow

```
Agent (JSONL) → Server POST /audit/events → SIEM Relay (Splunk HEC / ELK Bulk)
```

## Email Alerting (SMTP)

| Property | Value |
|----------|-------|
| Library | `lettre` 0.11 (tokio1-rustls-tls) |
| Protocol | SMTP over TLS |
| Trigger | DENY_WITH_ALERT policy decisions |
| Configuration | `alert_router_config` table (hot-reload) |
| Password handling | `SecretString` (prevents accidental logging) |

## Webhook Alerting

| Property | Value |
|----------|-------|
| Protocol | HTTP POST (configurable endpoint) |
| Payload | AuditEvent JSON |
| Configuration | `alert_router_config` table |

## Chrome Enterprise Content Analysis

| Property | Value |
|----------|-------|
| Protocol | Protobuf (proto2) |
| Library | `prost` 0.14 |
| Source | Vendored from Chromium Content Analysis SDK |
| Use cases | BRW-01 (upload scanning), BRW-03 (paste scanning) |
| Messages | ContentAnalysisRequest, ContentAnalysisResponse |

## Windows APIs (Win32)

| Category | APIs | Purpose |
|----------|------|---------|
| Service Management | `CreateMutexW`, `RegisterServiceCtrlHandlerW` | SCM registration, single-instance |
| Identity & SID | `ConvertSidToStringSidW`, `ConvertStringSidToSidW` | SID resolution |
| File System | `GetDriveTypeW`, minifilter communication | Disk classification, NTFS monitoring |
| Network | `WNetOpenEnumW`, `WNetEnumResourceW` | Network share enumeration |
| Active Directory | `DsGetSiteNameW` | VPN site detection |
| Clipboard | `SetWindowsHookExW` | Clipboard content interception |
| Device Detection | `SetupDiGetClassDevsW`, `SetupDiEnumDeviceInfo` | USB device enumeration |
| WMI / COM | `CoSetProxyBlanket` | BitLocker encryption queries |
| Registry | Win32_System_Registry | Configuration access |
| Device Notification | `RegisterDeviceNotificationW` | USB hotplug events |
| UI | `RegisterClassW`, `CreateWindowExW` | Hidden message windows |

## WMI (Windows Management Instrumentation)

| Property | Value |
|----------|-------|
| Library | `wmi` 0.14 |
| Namespace | `root\CIMV2\Security\MicrosoftVolumeEncryption` |
| Queries | `Win32_EncryptableVolume` (BitLocker status) |
| Auth | PktPrivacy via `CoSetProxyBlanket` |

## Infrastructure & Deployment

| Component | Deployment |
|-----------|-----------|
| dlp-server | Windows executable (background process or service) |
| dlp-agent | Windows Service (NT AUTHORITY\SYSTEM) |
| dlp-admin-cli | Interactive terminal application |
| dlp-user-ui | Per-session GUI spawned by agent (user context) |

## Communication Between Components

| Path | Protocol | Transport |
|------|----------|-----------|
| Agent → Server | HTTPS REST | reqwest + rustls-tls |
| Server → Agent | Config push (via agent poll) | HTTPS |
| Agent → User UI | Named Pipes (IPC) | Win32 CreateNamedPipe |
| Admin CLI → Server | HTTPS REST (blocking) | reqwest |
| Server → SIEM | HTTPS POST | reqwest |
| Server → SMTP | SMTP/TLS | lettre |
