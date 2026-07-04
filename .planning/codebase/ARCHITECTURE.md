<!-- refreshed: 2026-07-03 -->
# Architecture

**Analysis Date:** 2026-07-03

## System Overview

```text
┌─────────────────────────────────────────────────────────────┐
│                 Management & Identity                        │
│  dlp-server (axum)  ←── Active Directory (LDAP/Kerberos)    │
│  dlp-admin-cli (TUI)                                        │
├──────────────────┬──────────────────┬───────────────────────┤
│   Admin API      │   Policy Engine  │   Audit/SIEM/Syslog   │
│  `dlp-server/    │  `dlp-server/    │  `dlp-server/src/     │
│   src/admin_api  │   src/policy_    │   siem_connector.rs`  │
│   .rs`           │   store.rs`      │                       │
└────────┬─────────┴────────┬─────────┴──────────┬────────────┘
         │                  │                     │
         │ HTTPS REST       │ HTTPS /evaluate     │ SQLite WAL
         ▼                  ▼                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Endpoint Enforcement (dlp-agent)                │
│         `dlp-agent/src/` (Windows Service, SYSTEM)           │
│  interception/  ipc/  chrome/  clipboard/  print_*/          │
│  detection/  wfp_*  hook_*  universal_injector/  etw_*       │
└─────────────────────────────────────────────────────────────┘
         │
         │ Named pipes (bincode) / DLL injection
         ▼
┌─────────────────────────────────────────────────────────────┐
│  User Interface (dlp-user-ui)  │  API Hook DLL (dlp-hook-dll)│
│  `dlp-user-ui/src/`            │  `dlp-hook-dll/src/`        │
│  per-session iced GUI          │  IAT + ntdll hooking        │
└─────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| ABAC Engine | Evaluate `Subject` + `Resource` + `Environment` + `Action` -> `Decision` | `dlp-common/src/abac.rs` |
| AD Client | LDAP bind, group cache, device trust, network location | `dlp-common/src/ad_client.rs` |
| Admin API | Full REST management surface (policies, agents, config, audit) | `dlp-server/src/admin_api.rs` |
| Policy Store | In-memory policy cache + ABAC evaluation entry point | `dlp-server/src/policy_store.rs` |
| Agent Service | SCM lifecycle, subsystem coordination, graceful shutdown | `dlp-agent/src/service.rs` |
| Interception | File event loop, `notify`-based monitoring, policy mapping | `dlp-agent/src/interception/mod.rs` |
| Engine Client | HTTPS client to `/policies/evaluate` with retry/offline fallback | `dlp-agent/src/engine_client.rs` |
| Hook DLL | IAT/ntdll hooking, classification requests via named pipe | `dlp-hook-dll/src/lib.rs` |
| User UI | Per-session GUI dialogs, tray, notifications | `dlp-user-ui/src/app.rs` |
| Admin CLI | ratatui administrator interface | `dlp-admin-cli/src/app.rs` |

## Pattern Overview

**Overall:** Layered defense-in-depth DLP with hybrid RBAC/ABAC.

**Key Characteristics:**
- NTFS provides coarse-grained baseline; ABAC provides fine-grained dynamic veto.
- Critical Rule: `NTFS ALLOW + ABAC DENY = DENY`.
- Agent runs as `LocalSystem` Windows Service for cross-session enforcement.
- User UI spawned as a subprocess into each interactive session.
- Hook DLL injected into cloud-sync client processes for inline interception.
- All secrets encrypted at rest via envelope encryption (AES-256-GCM + per-row DEKs).

## Layers

**Identity Layer:**
- Purpose: Resolve users, groups, device trust, and network location.
- Location: `dlp-common/src/ad_client.rs`
- Contains: Async LDAP client, group cache, VPN subnet matching, device trust helpers.
- Depends on: `ldap3`, Windows networking APIs.
- Used by: `dlp-server::policy_store`, `dlp-agent::identity`, `dlp-agent::engine_client`.

**Access Layer (NTFS):**
- Purpose: Coarse-grained OS-enforced file access baseline.
- Location: OS kernel / NTFS ACLs.
- Contains: No code; agent does not modify ACLs.
- Depends on: Windows security model.
- Used by: All file operations on protected endpoints.

**Policy Layer:**
- Purpose: Pure, stateless ABAC evaluation.
- Location: `dlp-common/src/abac.rs`, `dlp-server/src/policy_store.rs`.
- Contains: `Subject`, `Resource`, `Environment`, `Action`, `Policy`, `Decision`, evaluation logic.
- Depends on: Identity layer attributes.
- Used by: `dlp-server::admin_api`, `dlp-agent::engine_client`, `dlp-agent::offline`.

**Enforcement Layer:**
- Purpose: Intercept operations, consult policy, apply decisions, emit audit.
- Location: `dlp-agent/src/`, `dlp-hook-dll/src/`.
- Contains: File interception, clipboard hooks, print enforcement, USB/disk/cloud enforcers, WFP, hook DLL.
- Depends on: Policy layer decisions, IPC, named pipes.
- Used by: Endpoint users and processes.

**Management Layer:**
- Purpose: CRUD for policies, agents, configuration, audit queries.
- Location: `dlp-server/src/admin_api.rs`, `dlp-admin-cli/src/`.
- Contains: axum routers, handlers, TUI screens.
- Depends on: Policy layer, SQLite repositories, crypto.
- Used by: DLP administrators.

**Presentation Layer:**
- Purpose: User-facing block/override dialogs and tray notifications.
- Location: `dlp-user-ui/src/`.
- Contains: iced application, dialogs, IPC clients.
- Depends on: Agent IPC pipes.
- Used by: Interactive endpoint users.

## Data Flow

### Primary Request Path (File Interception)

1. `notify` crate emits `FileAction` (`dlp-agent/src/interception/file_monitor.rs`).
2. `interception::run_event_loop` routes the event (`dlp-agent/src/interception/mod.rs`).
3. `session_identity::SessionIdentityMap` resolves `(user_sid, user_name)` (`dlp-agent/src/session_identity.rs`).
4. `interception::policy_mapper` builds provisional classification and `EvaluateRequest` (`dlp-agent/src/interception/policy_mapper.rs`).
5. `offline::evaluate()` checks cache, else sends HTTPS `POST /policies/evaluate` via `engine_client` (`dlp-agent/src/offline.rs`, `dlp-agent/src/engine_client.rs`).
6. `dlp-server::policy_store` evaluates policies and returns `EvaluateResponse` (`dlp-server/src/policy_store.rs`).
7. `Decision` is applied; if `DENY`, `Pipe1AgentMsg::BlockNotify` is sent to `dlp-user-ui` (`dlp-agent/src/ipc/pipe1.rs`).
8. `audit_emitter` writes append-only JSONL log (`dlp-agent/src/audit_emitter.rs`).

### Audit Ingestion Flow

1. `dlp-agent` posts audit events to `POST /audit/events`.
2. `dlp-server::audit_store` ingests into SQLite `audit_events` table.
3. Background tasks forward to SIEM, syslog, and alert router.

### Cloud Channel Enforcement Flow

1. Admin enables `cloud_hook_enabled` via admin API/CLI.
2. `dlp-server` pushes `AgentConfigPayload` to `dlp-agent`.
3. `hook_injector::inject()` injects `dlp-hook-dll` via `CreateRemoteThread` + `LoadLibraryW`.
4. Hook DLL intercepts WinInet/WinHTTP; sends `HookRequest` to agent via named pipe.
5. Agent evaluates; `DENY` triggers `WfpManager::block_pid(pid)` to install per-PID TCP/443 filter.
6. `share_link_enforcer` evaluates clipboard share-link URLs and clears clipboard on `DENY`.

## Key Abstractions

**`EvaluateRequest` / `EvaluateResponse`:**
- Purpose: Canonical policy evaluation wire format.
- Examples: `dlp-common/src/abac.rs`, `dlp-common/src/hook_ipc.rs`.
- Pattern: Serde-driven structs shared across server, agent, and hook DLL.

**`AppState`:**
- Purpose: Shared server state passed to all axum handlers.
- Examples: `dlp-server/src/lib.rs`.
- Pattern: `Arc<AppState>` with `State` extractor; contains pool, crypto, policy store, SIEM, alert router, etc.

**`AppError`:**
- Purpose: Unified error type with `IntoResponse` for HTTP status mapping.
- Examples: `dlp-server/src/lib.rs`.
- Pattern: `thiserror` enum; `anyhow` at boundaries.

**`SecretCrypto`:**
- Purpose: Single abstraction for all secrets-at-rest operations.
- Examples: `dlp-server/src/crypto/mod.rs`.
- Pattern: Envelope encryption with KEK rotation support.

**`HOOKS` table:**
- Purpose: Declarative list of Win32/NT functions to hook.
- Examples: `dlp-hook-dll/src/lib.rs`.
- Pattern: Static array of hook descriptors consumed by IAT patcher and ntdll patcher.

## Entry Points

**dlp-server:**
- Location: `dlp-server/src/main.rs`
- Triggers: Direct execution or service runner.
- Responsibilities: CLI parsing, DB pool, crypto bootstrap, secrets migration, admin provisioning, AD client init, background tasks, axum serve with graceful shutdown.

**dlp-agent:**
- Location: `dlp-agent/src/main.rs`
- Triggers: Windows Service Control Manager.
- Responsibilities: Service dispatcher entry; non-Windows builds bail.

**dlp-user-ui:**
- Location: `dlp-user-ui/src/main.rs`
- Triggers: Spawned by agent per interactive session; or `--stop-password` file mode.
- Responsibilities: iced GUI event loop, IPC client, dialogs.

**dlp-admin-cli:**
- Location: `dlp-admin-cli/src/main.rs`
- Triggers: Direct execution with subcommands or TUI mode.
- Responsibilities: CLI parsing, server URL discovery, login, ratatui run.

**dlp-hook-dll:**
- Location: `dlp-hook-dll/src/lib.rs` (`DllMain`)
- Triggers: Loaded into target process via injection.
- Responsibilities: IAT patching, ntdll stub patching, classification requests.

## Architectural Constraints

- **Threading:** `dlp-agent` uses tokio multi-thread runtime plus Windows-specific threads for ETW, print watching, and hook background verification. `dlp-hook-dll` must minimize work inside hooked functions to avoid reentrancy/deadlock.
- **Global state:** Process-wide `OnceLock` singletons for agent config, SCM handle, agent DB, disk enumerator, and hook original function pointers. See `dlp-agent/src/service.rs`, `dlp-agent/src/lib.rs`, `dlp-hook-dll/src/lib.rs`.
- **Circular imports:** Not detected; crate DAG is `dlp-common` <- all others; `dlp-agent` <- `dlp-hook-dll` dev-dep.
- **Cross-platform compilation:** `dlp-agent` and `dlp-hook-dll` rely on `#[cfg(windows)]` and non-Windows stubs for compilation only.

## Anti-Patterns

### Global `static mut` Original Function Pointers

**What happens:** `dlp-hook-dll/src/lib.rs` stores original hooked function pointers in `static mut` arrays.
**Why it's wrong:** `static mut` is `unsafe` to access and easy to misuse across threads; aliasing violations can cause UB.
**Do this instead:** Replace with `OnceLock<Mutex<[AtomicPtr; N]>>` or `parking_lot::Mutex` wrapped in a safe API; access only through helpers that enforce synchronization.

### Large Shared `AppState` with Many Fields

**What happens:** `AppState` in `dlp-server/src/lib.rs` carries 15+ fields, making handler construction verbose.
**Why it's wrong:** High coupling; every handler test must populate unrelated fields.
**Do this instead:** Group related state into sub-structs (e.g., `AuditState`, `CryptoState`) and expose accessors.

## Error Handling

**Strategy:** Typed `thiserror` errors in library code; `anyhow` context at application boundaries; `AppError::IntoResponse` for HTTP mapping.

**Patterns:**
- Use `?` and `#[from]` for propagation.
- `.expect()` only for invariant violations with descriptive messages.
- Fail-closed: T3/T4 cache misses default to `DENY`; unknown volume class evaluates to `false`.

## Cross-Cutting Concerns

**Logging:** `tracing` with structured fields; never `println!` in library code; redact secrets in `Debug` impls.
**Validation:** Input validation in axum extractors and admin API handlers; URL SSRF checks; IP network validation.
**Authentication:** JWT Bearer for admin API; Ed25519 tokens for approvals; Windows SIDs/tokens for identity.

---

*Architecture analysis: 2026-07-03*
