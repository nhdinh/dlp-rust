# ARCHITECTURE

## Overall architecture style

- **Style:** Multi-crate Rust monorepo with clear role-based binaries/libraries.
- **Deployment topology:** Central management server + endpoint agent + endpoint UI + admin console.
- **Execution model:**
  - `dlp-server`: central control plane and policy/audit API (HTTP)
  - `dlp-agent`: endpoint enforcement plane (Windows Service)
  - `dlp-user-ui`: user-session UI companion process (notifications/dialogs/clipboard UX)
  - `dlp-admin-cli`: operator/admin management client (TUI)
  - `dlp-hook-dll`: Windows hook/injection component for cloud/file interception paths
  - `dlp-common`: shared domain model + ABAC types + cross-crate contracts

In practice this is a **modular monorepo with distributed runtime components**, not microservices in the cloud-native sense.

## Core data flow

## 1) Policy/evaluation path
1. Endpoint activity is observed/intercepted by `dlp-agent` (plus hook components where applicable).
2. Agent builds an `EvaluateRequest` (shared type from `dlp-common`).
3. Agent calls `dlp-server` `POST /evaluate` via `engine_client`.
4. Server converts request at API boundary into internal ABAC context and evaluates against in-memory policy cache (`policy_store`).
5. Server returns `EvaluateResponse`; agent enforces ALLOW/DENY behavior locally.

## 2) Management/config path
1. Admin operator uses `dlp-admin-cli`.
2. CLI authenticates with server admin API (bcrypt+JWT stack visible in dependencies/modules).
3. CLI performs policy/config CRUD through server endpoints.
4. Server persists to SQLite repositories and updates runtime state (policy cache refresh/hot-reload patterns present in main/API modules).

## 3) Audit/alert path
1. Enforcement/policy decisions are recorded server-side (`audit_store`, `exception_store` modules).
2. Server can relay/forward to SIEM backends (`siem_connector`) and alert channels (`alert_router`: SMTP/webhook).

## Key design patterns in use

## Shared contract crate
- `dlp-common` centralizes key data contracts and policy-related structures used by server, agent, and admin CLI.
- This reduces drift between wire formats and in-process domain models.

## Boundary conversion pattern
- In `admin_api`, wire request objects are explicitly converted to internal ABAC context early in handler flow (clear transport/domain boundary).

## Layered endpoint model
- README and crate/module boundaries reflect layered DLP model:
  - identity/directory context
  - policy decisioning (ABAC)
  - endpoint enforcement (service + hooks)
  - central audit/management

## Runtime cache + periodic refresh
- Server initializes policy store from DB and refreshes on interval in background task.
- Indicates a read-optimized evaluation path with DB as source-of-truth.

## Fail-open/fail-closed by subsystem
- Server startup includes fail-open behavior for AD client initialization (server runs with AD features disabled if AD unavailable).
- Memory and module notes indicate some endpoint interception paths are fail-closed by design (deny on unreachable agent/pipe timeout in hook flow).

## Windows split-session pattern
- Agent runs as SYSTEM service (session 0) while user-facing monitoring/UX is delegated to user-session UI process (`dlp-user-ui`).

## Module/package boundaries

## Workspace-level boundaries
- `dlp-common`: shared domain and transport types (no UI/server-specific logic expected)
- `dlp-server`: HTTP API surface, persistence, policy cache/evaluator orchestration, registries, SIEM/alerts
- `dlp-agent`: OS-level enforcement, collectors/watchers/interceptors, server communication
- `dlp-user-ui`: desktop interaction layer and local IPC endpoints
- `dlp-admin-cli`: operator control interface over server APIs
- `dlp-hook-dll`: low-level interception integration point
- `dlp-e2e`: cross-component integration harness

## Intra-crate boundary examples
- `dlp-server/src/db/repositories/*`: repository-style persistence layer
- `dlp-server/src/admin_api.rs`: route/handler aggregation layer
- `dlp-agent/src/*_enforcer.rs`, `*_watcher.rs`, `engine_client.rs`: separated concern modules for transport/enforcement/detection
- `dlp-user-ui/src/dialogs`, `src/ipc`, `src/detection`: UI + IPC + signal handling separation

## Architectural characteristics from observed codebase

- **State management:** SQLite-backed durable state with process-local caches where performance-sensitive.
- **Integration strategy:** direct protocol integrations (LDAP, SMTP, HTTP SIEM/webhook) rather than message-bus/event-stream platform.
- **Platform bias:** Windows-first architecture with extensive Win32 API usage (`windows` crate across major runtime crates).
- **Testing architecture:** package-local tests plus dedicated `dlp-e2e` crate for integrated scenarios.

## Constraints and implications

- Strong Windows dependency means portability is intentionally limited for enforcement/runtime binaries.
- Central SQLite persistence is simpler operationally but couples scale profile to single-node DB characteristics unless evolved later.
- Clear crate boundaries reduce accidental coupling, but shared contracts (`dlp-common`) become a critical compatibility surface for all components.
