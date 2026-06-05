# Architecture Overview

**Project:** Enterprise DLP System (NTFS + Active Directory + ABAC)
**Workspace:** `dlp-rust`
**Last Updated:** 2026-06-05

---

## 1. System Overview

The Enterprise DLP System is a multi-component Rust application that enforces data-loss-prevention policies on Windows endpoints. It combines four architectural layers:

1. **Identity Layer** — Active Directory (LDAP/Kerberos) provides authoritative user, group, and device identity.
2. **Access Layer** — NTFS ACLs provide the coarse-grained baseline enforcement.
3. **Policy Layer** — An ABAC (Attribute-Based Access Control) engine evaluates contextual access requests and renders decisions.
4. **Enforcement Layer** — A Windows Service agent intercepts file operations, clipboard events, print jobs, cloud uploads, and USB/disk activity, applying ABAC decisions in real time.

The **Critical Rule** governs all enforcement: `NTFS ALLOW + ABAC DENY = DENY`.

---

## 2. High-Level Component Diagram

```
+-------------------------------+
|     Active Directory          |
|  (LDAP / Kerberos / GSSAPI)   |
+---------------+---------------+
                | HTTPS / REST
                v
+-------------------------------------------------------------+
|                      dlp-server (axum)                      |
|  +----------------+  +----------------+  +----------------+ |
|  | Admin API      |  | Agent Registry |  | Audit Store    | |
|  | (JWT auth)     |  | + Heartbeat    |  | (SQLite JSONL) | |
|  +----------------+  +----------------+  +----------------+ |
|  +----------------+  +----------------+  +----------------+ |
|  | Policy Engine  |  | SIEM Relay     |  | Alert Router   | |
|  | (ABAC eval)    |  | (Splunk/ELK)   |  | (SMTP/Webhook) | |
|  +----------------+  +----------------+  +----------------+ |
|  +----------------+  +----------------+  +----------------+ |
|  | Approval Flow  |  | Syslog Fwd     |  | Label Service  | |
|  | (Ed25519 JWT)  |  | (RFC 5424 TLS) |  | (TTL cache)    | |
|  +----------------+  +----------------+  +----------------+ |
|                          |                                  |
|                     SQLite DB (WAL)                         |
+---------------+---------------------------+-----------------+
                | HTTPS REST
    +-----------+-----------+-----------+
    v                       v           v
+----------+        +----------+  +----------+
|dlp-agent |        |dlp-agent |  |dlp-agent |
|(WS01)    |        |(WS02)    |  |(WS03)    |
|SYSTEM svc|        |SYSTEM svc|  |SYSTEM svc|
+----+-----+        +----+-----+  +----+-----+
     |                   |            |
     | Pipe 1/2/3 IPC    |            |
     v                   v            v
+----------+        +----------+  +----------+
|dlp-user-ui|        |dlp-user-ui|  |dlp-user-ui|
|(per-sess)|        |(per-sess)|  |(per-sess)|
+----------+        +----------+  +----------+
```

---

## 3. Components

### 3.1 dlp-common -- Shared Types Library

A zero-runtime-dependency pure type crate shared by all other crates.

| Module | Responsibility |
|--------|--------------|
| `abac` | Core ABAC types: `Subject`, `Resource`, `Environment`, `Action`, `Policy`, `EvaluateRequest/Response`, `Decision`, `AbacContext`, `EnforcementMode`, `VolumeClass` |
| `ad_client` | Async LDAP client with machine-account Kerberos bind; group resolution cache; device trust (`NetGetJoinInformation`); network location (`GetAdaptersAddresses` + VPN subnet matching) |
| `audit` | `AuditEvent` schema and `EventType` enum |
| `classification` | Four-tier classification enum: T1 (Public) through T4 (Restricted) |
| `classifier` | Content-based text classifier (SSN / credit card / keyword heuristics) |
| `crypto` | DPAPI wrappers for Windows data protection |
| `disk` | Disk enumeration, encryption status (WMI `Win32_EncryptableVolume`), bus type detection |
| `endpoint` | `AppIdentity`, `AppTrustTier`, `DeviceIdentity`, `SignatureState`, `UsbTrustTier` |
| `hash` | `fnv1a_64` fast hash |
| `hook_ipc` | `HookRequest`, `HookResponse`, `HandleHookRequest` wire types for hook DLL IPC |
| `label` | `Label`, `LabelState`, `ObjectType`, `Tier` -- label-aware classification |
| `path_hash` | Path normalization, NT path to DOS path conversion, path hashing |
| `usb` | USB device enumeration, parsing, policy constants |

### 3.2 dlp-server -- Central Management Server

An async HTTP server built on `axum` with a SQLite backend.

| Module | Responsibility |
|--------|--------------|
| `main.rs` | CLI parsing, DB bootstrap, `SecretCrypto` KEK initialization, secrets migration, admin user provisioning, AD client init, background tasks (policy refresh, label flag refresh, syslog drain), graceful shutdown |
| `lib.rs` | `AppState` (shared state struct with pool, crypto, policy store, SIEM, alert router, AD client, label service, approval token service, syslog connector) and unified `AppError` |
| `admin_api.rs` | Full axum router: policy CRUD, agent management, exception management, SIEM/alert/LDAP/syslog/print/cloud config, label management, protected paths, bypass alerts, rate limiting |
| `admin_auth.rs` | JWT secret resolution (encrypted DB row > env var > dev fallback), bcrypt admin user creation/verification |
| `agent_registry.rs` | Agent registration, heartbeat ingestion, offline sweeper (90s timeout) |
| `audit_store.rs` | Audit event ingestion endpoint |
| `alert_router.rs` | SMTP email and webhook alerting with hot-reload config |
| `siem_connector.rs` | Batched Splunk HEC and ELK HTTP ingest relay |
| `syslog_connector.rs` | RFC 5424 syslog forwarding over TLS with encrypted local queue |
| `policy_store.rs` | In-memory policy cache with background refresh; ABAC evaluation engine |
| `policy_sync.rs` | Async push of policy changes to replica dlp-servers |
| `label_service.rs` | Label resolution with TTL caching and folder inheritance |
| `approval_api.rs` | REST endpoints for approval workflow (request/approve/deny/list) |
| `approval_token.rs` | Ed25519 JWT signing and verification for approval tokens |
| `rate_limiter.rs` | IP-based and agent-ID-based rate limiting via `governor` + `tower_governor` |
| `observability.rs` | Metrics recording (syslog queue depth, latency, TLS errors, retries) |
| `crypto/` | Secrets-at-rest cryptography: `SecretCrypto`, envelope encryption, KDF, DPAPI integration |
| `db/` | SQLite schema init (WAL + `secure_delete`), connection pool (`r2d2`), unit of work pattern, 20+ repositories |

### 3.3 dlp-agent -- Windows Service Enforcement Agent

Runs as a Windows Service under `SYSTEM`. Performs real-time interception and enforcement across multiple exfiltration channels.

| Module | Responsibility |
|--------|--------------|
| `main.rs` | Windows Service dispatcher entry point |
| `service.rs` | SCM lifecycle (Start/Stop/Pause/Resume), password-protected stop gate, global config OnceLock |
| `interception/` | File system monitoring via `notify` crate; `FileAction` events; policy mapping |
| `identity.rs` | SMB impersonation token user resolution; `to_subject_with_ad()` for AD group/trust/location |
| `session_identity.rs` | Per-session identity map with path heuristic |
| `engine_client.rs` | HTTPS client to dlp-server `/policies/evaluate` |
| `cache.rs` | Policy decision LRU cache with TTL |
| `offline.rs` | OfflineManager: cache hit > provisional classification > fail-closed (T3/T4 default DENY) |
| `audit_emitter.rs` | Append-only JSONL local audit log with rotation |
| `offline_audit_queue.rs` | DPAPI-encrypted SQLite queue for audit events when server is unreachable |
| `clipboard/` | Clipboard hooks (`SetWindowsHookExW`) + content classifier integration |
| `detection/` | USB mass storage detection (`GetDriveTypeW`), network share whitelisting, disk encryption, app identity |
| `wfp_ffi.rs` / `wfp_manager.rs` | Windows Filtering Platform FFI bindings; per-PID TCP/443 block filters |
| `hook_injector.rs` | IAT hook DLL injection via `CreateRemoteThread` + `LoadLibraryW` |
| `hook_ipc.rs` | Named-pipe IPC server for hook DLL communication |
| `chrome/` | Chrome Enterprise Content Analysis API integration (protobuf) |
| `print_watcher.rs` / `print_enforcer.rs` | Print spooler interception; XPS text extraction; job cancellation |
| `disk_enforcer.rs` / `usb_enforcer.rs` | USB/disk policy enforcement |
| `cloud_enforcer.rs` | Cloud upload channel enforcement |
| `share_link_enforcer.rs` | Clipboard share-link URL pattern detection and blocking |
| `ipc/` | Three named-pipe IPC servers (Pipe 1: agent->UI commands; Pipe 2: agent->UI events; Pipe 3: UI->agent) |
| `ui_spawner.rs` | Multi-session UI spawning via `WTSEnumerateSessionsW` + `CreateProcessAsUserW` |
| `session_monitor.rs` | Session logon/logoff handling |
| `health_monitor.rs` | Mutual agent<->UI health ping-pong |
| `protection.rs` | Process DACL hardening |
| `password_stop.rs` | Service stop password challenge (bcrypt, 3-attempt lockout) |
| `bypass_correlator.rs` | Bypass attempt correlation and detection |
| `universal_injector.rs` | Universal process injection framework (ETW watcher, allowlist, AppInit) |
| `dacl_tripwire.rs` / `dacl_repair_watcher.rs` | DACL integrity monitoring and repair |
| `process_watcher.rs` / `process_registry.rs` | Process lifecycle tracking |
| `device_registry.rs` / `device_controller.rs` | Endpoint device registration and control |
| `allowlist.rs` / `approval_cache.rs` / `classification_cache.rs` | Caching layers for performance |

### 3.4 dlp-user-ui -- Per-Session User Interface

An `iced` native GUI subprocess spawned by the agent into each interactive Windows session.

| Module | Responsibility |
|--------|--------------|
| `main.rs` | iced entry point; stop-password file-based mode |
| `lib.rs` | Public API: `run()`, `run_stop_password()` |
| `app.rs` | iced Application state machine |
| `tray.rs` | System tray icon and menu |
| `notifications.rs` | Windows toast notifications |
| `dialogs/` | Block dialog, override request dialog, stop-password dialog |
| `clipboard_monitor.rs` | Reads clipboard, invokes content classifier |
| `ipc/` | Named-pipe IPC client for all three pipes |

### 3.5 dlp-admin-cli -- Administrator TUI

A `ratatui` terminal UI for DLP administrators.

| Module | Responsibility |
|--------|--------------|
| `main.rs` | CLI parsing, raw-mode TUI bootstrap |
| `lib.rs` | Public module re-exports for e2e testing |
| `app.rs` | App state machine and `Screen` enum |
| `tui.rs` | Terminal setup, raw mode, panic hook |
| `event.rs` | crossterm key event polling |
| `client.rs` | Authenticated `reqwest` HTTP client (JWT Bearer) |
| `engine.rs` | `DLP_SERVER_URL` auto-detection (env / registry / port probe) |
| `login.rs` | Pre-TUI health check and login |
| `registry.rs` | HKLM registry read for server address |
| `screens/` | ratatui frame renderers: policy list, agent list, SIEM config, alert config, cloud config, print config, USB enforcement, labels, allowlist, approvals, bypass alerts, protected paths, syslog config |

### 3.6 dlp-hook-dll -- API Hook DLL

A `cdylib` injected into user-mode processes to intercept file I/O at the Win32/NT layer.

| Module | Responsibility |
|--------|--------------|
| `lib.rs` | DLL entry point (`DllMain`), IAT patching driven by `HOOKS` table, ntdll stub patching (Phase 51), path extraction, classification via named pipe |
| `trampolines.rs` | Hook trampolines for 12 functions (CreateFileW, NtCreateFile, WriteFile, WriteFileEx, MoveFileExW, CopyFileExW, DeleteFileW, ReplaceFileW, SetFileInformationByHandle, NtOpenFile, NtWriteFile, NtSetInformationFile) |
| `ntdll_patcher.rs` | `retour::RawDetour` based ntdll syscall stub patching |
| `pipe_client.rs` | Named-pipe client to agent hook IPC server |
| `classification_cache.rs` | In-DLL classification result cache |
| `allowlist.rs` | Self-allowlist check |
| `fail_closed.rs` / `fail_mode.rs` | Deny return value mapping |
| `crash_guard.rs` / `thread_suspender.rs` | Reentrancy guards and thread suspension |
| `edr_detector.rs` | EDR/AV compatibility detection |
| `perf_telemetry.rs` | Hook performance telemetry |
| `hook_journal.rs` | Hook operation journaling |
| `pe_utils.rs` | PE parsing utilities for IAT manipulation |

### 3.7 dlp-e2e -- Integration Test Harness

Shared helpers for end-to-end testing across the workspace.

| Module | Responsibility |
|--------|--------------|
| `server` | `build_test_app()` -- in-process axum router with temp SQLite DB; `mint_jwt()` |
| `mock_engine` | Mock axum evaluation servers with fixed responses or status codes |
| `tui` | Headless TUI testing: `build_test_app_with_mock_client`, `inject_key_sequence`, `render_to_buffer` |

---

## 4. Data Flows

### 4.1 File Interception Flow (Endpoint)

```
notify crate -> FileAction (Created/Written/Deleted/Moved/Read)
       |
       v
interception::run_event_loop (tokio task)
       |
       v
session_identity::SessionIdentityMap -> (user_sid, user_name)
       |
       v
interception::policy_mapper -> provisional classification (path + content scan)
       |
       v
offline.evaluate() -> EvaluateRequest -> HTTPS -> dlp-server /policies/evaluate
       |                                          |
       |  (Online)                                (Offline fallback)
       v                                          v
 EvaluateResponse                         Cache lookup -> default-deny
       |                                          (T3/T4 -> fail-closed)
       v
Decision { ALLOW | DENY | DenyWithAlert }
       |
       v
audit_emitter -> local append-only JSONL audit log
       |
       v
if DENY -> Pipe1AgentMsg::BlockNotify -> dlp-user-ui -> block dialog
```

### 4.2 Audit Event Flow (Server Ingestion)

```
dlp-agent --HTTPS POST /audit/events--> dlp-server
                                            |
                               +------------+------------+
                               |                         |
                               v                         v
                       SQLite audit_events         SIEM relay
                       (append-only JSONL)          (batched, async)
                               |
                               v
                     dlp-admin-cli / admin API
                     (query, export, alerts)
```

### 4.3 Agent Lifecycle

```
Agent starts
      |
      v
POST /agents/register -> dlp-server records agent
      |
      v
Periodic POST /agents/{id}/heartbeat -> dlp-server updates last_heartbeat
      |
      v
Background sweeper (30s interval) -> mark offline if > 90s silence
```

### 4.4 Policy Sync

```
Admin creates/updates policy via admin API
           |
           v
dlp-server writes to SQLite policies table
           |
           v
PolicySyncer -> PUT /policies/{id} -> replica dlp-servers
```

### 4.5 Cloud Channel Enforcement Flow

```
1. Admin enables cloud_hook_enabled via dlp-admin-cli
         |
2. dlp-server pushes updated AgentConfigPayload to dlp-agent
         |
3. HookInjector::inject() -> CreateRemoteThread + LoadLibraryW -> IAT hook DLL
         |
4. Hook DLL intercepts WinInet/WinHTTP -> HookRequest -> agent via named pipe
         |                               |
   ALLOW -> permit                  DENY -> WfpManager::block_pid(pid)
                                    |
                              WFP sublayer: per-PID TCP/443 block filter
         |
5. ShareLinkEnforcer intercepts clipboard copy of cloud share-link URLs
   -> evaluates SHARE_LINK ABAC action -> DENY clears clipboard
```

### 4.6 Print Spooler Enforcement Flow

```
1. Admin enables print_enabled via dlp-admin-cli
         |
2. dlp-server pushes config; agent starts PrintWatcher thread
         |
3. FindFirstPrinterChangeNotification (PRINTER_CHANGE_ADD_JOB)
         |
4. GetJobW -> JobInfo { job_id, document_name, user_name, pages, datatype }
         |
5. Read XPS spool file (ZIP) -> parse .fpage XML -> extract Glyphs UnicodeString
         |
6. ContentClassifier -> Classification (T1-T4)
   |- Classifiable + permitted -> ALLOW
   |- Classifiable + blocked   -> SetJobW(JOB_CONTROL_DELETE) + block dialog
   |- Unclassifiable           -> print_unclassifiable_action (Allow or Block)
         |
7. Audit event emitted for every enforcement decision
```

---

## 5. Layer Boundaries

| Layer | Crate(s) | Boundary Rules |
|-------|----------|----------------|
| Identity | `dlp-common::ad_client` | LDAP queries only; no direct NTFS or policy logic. Fail-open on AD unavailability. |
| Access (NTFS) | OS kernel | Baseline enforcement; agent does not modify NTFS ACLs. |
| Policy | `dlp-common::abac`, `dlp-server::policy_store` | Pure evaluation logic; no side effects. Stateless given input context. |
| Enforcement | `dlp-agent`, `dlp-hook-dll` | Intercepts operations, consults policy layer, applies decision, emits audit. Never makes policy changes. |
| Management | `dlp-server::admin_api`, `dlp-admin-cli` | CRUD for policies, agents, config, audit queries. No direct endpoint access. |
| Presentation | `dlp-user-ui` | User-facing dialogs and tray only. No policy or enforcement logic. |

---

## 6. Key Design Patterns

### 6.1 Hybrid RBAC + ABAC

- AD groups provide coarse role-like membership (`MemberOf` condition).
- ABAC adds dynamic context: device trust, network location, volume class, application identity, origin URL.
- First-match policy evaluation with priority sorting.

### 6.2 Fail-Closed / Fail-Open by Context

- **Policy evaluation**: Missing attributes fail the condition (fail-closed).
- **AD client**: Errors return safe defaults (fail-open) so AD outages do not block work.
- **Offline mode**: T3/T4 cache misses default to DENY; T1/T2 default to ALLOW.

### 6.3 Layered Caching

- `dlp-server::policy_store` -- in-memory policy cache refreshed every 5 minutes.
- `dlp-server::label_service` -- TTL-cached label resolution with folder inheritance.
- `dlp-agent::cache` -- per-decision LRU cache with TTL.
- `dlp-agent::classification_cache` -- classification result cache.
- `dlp-hook-dll::classification_cache` -- in-process hook DLL cache.

### 6.4 Secrets at Rest

- Phase 47: All sensitive columns (SMTP passwords, webhook secrets, SIEM tokens, JWT secrets) encrypted with AES-256-GCM via envelope encryption.
- KEK seed is DPAPI-wrapped on Windows; encrypted column values use per-row DEKs.
- `secure_delete` PRAGMA ensures freed SQLite pages are zero-overwritten.

### 6.5 Three-Pipe IPC

- **Pipe 1** (Agent -> UI): Commands (block notify, policy sync complete, agent status).
- **Pipe 2** (Agent -> UI): Async events.
- **Pipe 3** (UI -> Agent): User acknowledgements and override requests.
- Stop-password uses a file-based response path to avoid Pipe 1 deadlocks.

### 6.6 Hook DLL Architecture

- IAT patching for 12 Win32/NT file I/O functions.
- Optional ntdll syscall stub patching (Phase 51) via `retour::RawDetour`.
- Self-allowlist check before patching.
- Reentrancy guards and crash guards for stability.
- Classification requests sent to agent via named pipe (50ms timeout).

---

## 7. Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| **SQLite over external DB** | Single-file, zero-config, sufficient for central management of 10k+ agents. WAL mode for concurrency. |
| **axum for server** | Type-safe routing, middleware ecosystem (tower), async-native, good error handling ergonomics. |
| **Windows Service for agent** | Required for SYSTEM-level file interception, WFP filter installation, and cross-session operation. |
| **iced (tiny-skia) for user UI** | Software renderer avoids GPU initialization failures when spawned by SYSTEM into user sessions. |
| **ratatui for admin CLI** | Lightweight terminal UI; no GUI dependencies; works over SSH. |
| **Named pipes for IPC** | Native Windows IPC with built-in security descriptors; no network stack overhead. |
| **IAT + ntdll hooking** | Covers both high-level Win32 and low-level NT paths; defense in depth against bypass attempts. |
| **Envelope encryption (Phase 47)** | Allows KEK rotation without re-encrypting all rows; per-row DEKs limit blast radius. |
| **Ed25519 for approval tokens (Phase 61)** | Compact signatures, fast verification, no RSA complexity. |
| **Syslog queue with peek-confirm-delete** | At-least-once delivery semantics; exponential backoff on failure; encrypted at rest. |
| **Separate dlp-user-ui crate** | Windows session isolation requires a subprocess in the interactive user's session, not a thread in the SYSTEM service. |
| **dlp-common as pure type library** | Can be compiled into every crate without pulling in async runtimes or platform-specific code. |
