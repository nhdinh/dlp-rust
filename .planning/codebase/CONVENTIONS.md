# Code Conventions and Patterns

**Analysis Date:** 2026-06-05
**Workspace:** Enterprise DLP System (NTFS + Active Directory + ABAC)
**Crates:** dlp-common, dlp-agent, dlp-server, dlp-admin-cli, dlp-user-ui, dlp-hook-dll, dlp-e2e

---

## 1. Naming Conventions

### 1.1 Files and Modules
- **Source files:** Lowercase with underscores: `audit_emitter.rs`, `policy_mapper.rs`, `engine_client.rs`
- **Module entry points:** `mod.rs` convention: `ipc/mod.rs`, `detection/mod.rs`, `db/repositories/mod.rs`
- **Test files:** Collocated in `tests/` directory with descriptive suffixes:
  - `integration.rs` — Component integration tests
  - `comprehensive.rs` — Multi-component boundary tests
  - `negative.rs` — Error and failure-path tests
  - `*_integration.rs` — Feature-specific integration tests

### 1.2 Functions
- **Snake_case** for all functions: `resolve_caller_identity()`, `emit_audit()`, `fail_closed_response()`
- **Async functions:** Return `Result<T, E>` and use `pub async fn` prefix
- **Query/predicate functions:** Descriptive prefixes:
  - `resolve_*` — Resolution operations (`resolve_volume_class_from_path()`)
  - `get_*` — Simple accessors (`get_active()`, `get_by_version()`)
  - `is_*` — Boolean predicates (`is_denied()`, `is_blocking()`, `is_sensitive()`)
  - `requires_*` — Capability checks (`requires_audit()`)
  - `with_*` — Builder-style setters (`with_policy()`, `with_blocked_disk()`)

### 1.3 Variables and Constants
- **Variables:** Snake_case: `user_sid`, `process_id`, `cache_entry`
- **Constants:** SCREAMING_SNAKE_CASE: `SERVICE_NAME`, `SHUTDOWN_TIMEOUT`, `DEFAULT_BIND`
- **Static globals:** Snake_case with type annotation: `static CONFIG: OnceLock<...>`, `static SCM_HANDLE: OnceLock<...>`

### 1.4 Types
- **Structs/Enums/Traits:** PascalCase: `Subject`, `AuditEvent`, `AppState`, `SecretCrypto`
- **Error types:** PascalCase with `Error` suffix: `AppError`, `CryptoError`, `CacheError`
- **Repository types:** PascalCase with `Repository` suffix: `PolicyRepository`, `AuditEventRepository`
- **Row types:** PascalCase with `Row` suffix: `PolicyRow`, `AuditEventRow`

### 1.5 Enum Variants
- **Action enum:** SCREAMING_SNAKE_CASE verbs: `READ`, `WRITE`, `COPY`, `DELETE`, `PASTE`, `DRAG_DROP`, `CLOUD_UPLOAD`
- **Decision enum:** Mixed for readability: `ALLOW`, `DENY`, `AllowWithLog`, `DenyWithAlert`
- **Status enums:** PascalCase: `Managed`, `Unmanaged`, `Compliant`, `Unknown`
- **Serde rename attributes:** Match wire format exactly:
  - `#[serde(rename_all = "snake_case")]` — `AppTrustTier` (`trusted`, `untrusted`, `unknown`)
  - `#[serde(rename_all = "PascalCase")]` — `VolumeClass` (`LocalNTFS`, `USBRemovable`)
  - `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` — `EventType` (`BLOCK`, `CONFIG_CHANGE`)
  - `#[serde(rename_all = "UPPERCASE")]` — `Classification` (`T1`, `T2`, `T3`, `T4`)

---

## 2. Code Style Rules

### 2.1 Formatting
- **Line length:** 100 characters (rustfmt default)
- **Indentation:** 4 spaces, never tabs
- **Import organization:** Three groups separated by blank lines:
  1. Standard library: `use std::sync::Arc;`
  2. External crates: `use tokio::sync::mpsc;`, `use tracing::{info, warn};`
  3. Workspace/local: `use dlp_common::*;`, `use crate::db::Pool;`

### 2.2 Linting
- `cargo clippy -- -D warnings` — all warnings treated as errors
- `cargo fmt --check` — format verification
- `sonar-scanner` — static analysis and security scanning (required before commits)
- Common clippy allows (used sparingly):
  - `#[allow(clippy::too_many_arguments)]` — for `AuditEvent::new()` and similar
  - `#[allow(clippy::type_complexity)]` — for internal cache types
  - `#[allow(clippy::enum_variant_names)]` — when variant names share a prefix

### 2.3 Import Rules
- **No wildcard imports** in production code except preludes
- **Test modules:** `use super::*;` is the only wildcard allowed
- **Barrel exports:** `pub use abac::*;` in `dlp-common/src/lib.rs` for shared types
- **Module preludes:** `dlp-agent/src/lib.rs` defines `pub mod prelude { pub use dlp_common::*; }`

---

## 3. Error Handling Patterns

### 3.1 Error Type Hierarchy
- **Library code:** Custom error types with `thiserror`:
  ```rust
  #[derive(Debug, thiserror::Error)]
  pub enum AppError {
      #[error("database error: {0}")]
      Database(#[from] rusqlite::Error),
      #[error("json error: {0}")]
      Json(#[from] serde_json::Error),
      #[error("internal error: {0}")]
      Internal(#[from] anyhow::Error),
      #[error("not found: {0}")]
      NotFound(String),
      #[error("bad request: {0}")]
      BadRequest(String),
      #[error("unauthorized: {0}")]
      Unauthorized(String),
      #[error("unprocessable entity: {0}")]
      UnprocessableEntity(String),
      #[error("conflict: {0}")]
      Conflict(String),
      #[error("forbidden: {0}")]
      Forbidden(String),
  }
  ```
- **Application boundaries:** `anyhow::Result<T>` with `.context()`:
  ```rust
  fn main() -> anyhow::Result<()> {
      windows_service::service_dispatcher::start(SERVICE_NAME, ffi_entry)
          .context("service dispatcher failed")?;
      Ok(())
  }
  ```

### 3.2 Error Propagation
- Use `?` operator for fallible operations
- Use `#[from]` derive for automatic conversion
- Use `.context()` from `anyhow` at application boundaries
- **Never use `.unwrap()`** in production code; `.expect()` only for invariant violations with descriptive messages

### 3.3 HTTP Error Mapping (dlp-server)
- `AppError` implements `IntoResponse` mapping variants to status codes:
  - `Database` / `Internal` / `Json` -> 500
  - `NotFound` -> 404
  - `BadRequest` -> 400
  - `Unauthorized` -> 401
  - `UnprocessableEntity` -> 422
  - `Conflict` -> 409
  - `Forbidden` -> 403
- Axum extractor rejections (`JsonRejection`, `PathRejection`) convert to `AppError::BadRequest`

### 3.4 Fail-Closed Semantics
- Security-critical paths default to DENY:
  - T3/T4 cache miss -> `fail_closed_response(classification)` returns DENY
  - Unknown volume class -> condition evaluates to `false` (does not match)
  - Unknown device trust -> `Blocked` (default enum variant)

---

## 4. Logging and Observability Conventions

### 4.1 Framework
- **Primary:** `tracing` crate with structured fields
- **Compat:** `log` crate as a facade shim for libraries that expect it
- **Initialization:** `tracing_subscriber::fmt::init()` or `tracing_subscriber::util::SubscriberInitExt`
- **Never use `println!`** in production code; use `tracing::info!`, `tracing::error!`, etc.

### 4.2 Log Levels
- `trace!` — Very low-level details (IPC frame parsing, raw Windows API results)
- `debug!` — Operational details (cache hits, path resolution, config reads)
- `info!` — Significant events (service startup, policy loaded, connection established)
- `warn!` — Recoverable errors and fallback behavior (retry, fallback to offline mode)
- `error!` — Errors requiring attention (DB failure, encryption failure, service errors)

### 4.3 Structured Fields
- Use key-value field syntax: `info!(metric = "syslog_queue_depth", depth, "...")`
- Format specifiers: `%` for Display, `?` for Debug
- Examples:
  ```rust
  tracing::error!(error = %e, attempts, retryable, "Policy Engine evaluation failed");
  tracing::warn!(error = %e, attempts, ?backoff, "Policy Engine unreachable — retrying");
  tracing::info!(url = %url, "using DLP_SERVER_URL env var");
  ```

### 4.4 Metrics
- Atomic counters for observability (in `observability.rs`):
  ```rust
  static QUEUE_DEPTH: AtomicU64 = AtomicU64::new(0);
  static RETRY_COUNT: AtomicU64 = AtomicU64::new(0);
  static DROP_COUNT: AtomicU64 = AtomicU64::new(0);
  ```
- Metrics are emitted via `tracing::info!` with `metric = "name"` field for external scraping

### 4.5 Secrets in Logs
- **Never log:** passwords, tokens, API keys, KEK material
- SIDs and usernames are logged only in audit context, not debug/trace
- Use `secrecy::SecretString` for sensitive data; redact in `Debug` impls:
  ```rust
  impl std::fmt::Debug for SecretCrypto {
      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
          f.debug_struct("SecretCrypto")
              .field("version", &self.version)
              .field("kek", &"<redacted>")
              .finish()
      }
  }
  ```

---

## 5. API Design Patterns

### 5.1 HTTP API (dlp-server with axum)
- **Handlers:** Async, return `Result<Response, AppError>`:
  ```rust
  pub async fn list_policies(
      State(state): State<Arc<AppState>>,
  ) -> Result<Json<Vec<PolicyResponse>>, AppError> { ... }
  ```
- **Shared state:** `Arc<AppState>` passed via axum's `State` extractor
- **Layered extractors:** Extract path params, query params, and JSON body separately
- **Middleware:** `tower` middleware for timeouts, tracing, compression

### 5.2 Builder Pattern
- Used for complex struct construction: `AuditEvent::new(...).with_policy(...).with_access_context(...)`
- Chainable setters return `Self` by value

### 5.3 Repository Pattern (dlp-server)
- One repository per database table in `db/repositories/`
- All raw SQL encapsulated in repositories; no `conn.execute()` outside this module
- Stateless structs with static methods: `PolicyRepository::list(pool)`
- Row types for read operations: `PolicyRow`, `AuditEventRow`
- Upsert types for writes: `PolicyUpdateRow<'a>`, `ApprovalUpsertRow`

### 5.4 IPC Protocol
- Named pipe IPC with typed message enums:
  - `Pipe1AgentMsg` / `Pipe1UiMsg` — Command channel
  - `Pipe2AgentMsg` / `Pipe2UiMsg` — Agent-to-UI notifications
  - `Pipe3AgentMsg` / `Pipe3UiMsg` — UI-to-agent requests
- Messages serialize via `serde_json` with version fields for backward compatibility

### 5.5 Windows API Wrappers
- Unsafe code isolated in platform-specific modules
- `#[cfg(windows)]` guards on Windows-only modules and functions
- `#[cfg(not(windows))]` stubs for cross-platform compilation and testing
- Safety invariants documented in comments above each `unsafe` block

### 5.6 Global State
- `std::sync::OnceLock` for process-wide singletons:
  - `static CONFIG: OnceLock<Arc<Mutex<AgentConfig>>>`
  - `static SCM_HANDLE: OnceLock<ServiceStatusHandle>`
  - `static AGENT_DB: OnceLock<Mutex<rusqlite::Connection>>`
- Access via helper functions that return `Option<R>` or panic with context

---

## 6. Documentation Conventions

### 6.1 Required Doc Comments
All public items MUST have doc comments with:
- One-sentence summary
- Longer description if behavior is non-obvious
- `# Arguments` — for functions with parameters
- `# Returns` — for non-void functions
- `# Errors` — for fallible functions
- `# Examples` — for complex functions

### 6.2 Module Documentation
- Crate-level doc comments in `lib.rs` explaining architecture
- Module-level doc comments explaining integration points
- Phase/task references in comments: `(Phase 47, Task 47-08)`, `(AUDIT-02, Phase 36)`

### 6.3 Security Invariants
- Documented inline with `## Fail-Closed Invariant` or `## Threat model` sections
- Example from `abac.rs`:
  ```rust
  /// ## Fail-Closed Invariant
  /// When a path cannot be classified, the classification returns `None`,
  /// NOT `LocalNTFS`. A `None` volume class causes volume-class conditions
  /// to evaluate to `false`.
  /// NEVER use `VolumeClass::default()` as a fallback for unclassifiable paths.
  ```

---

## 7. Type System Practices

### 7.1 Derives
- Standard derives on almost all public types:
  - `#[derive(Debug, Clone)]` — baseline
  - `#[derive(PartialEq, Eq)]` — value types and enums
  - `#[derive(Serialize, Deserialize)]` — wire-format types
  - `#[derive(Default)]` — when sensible defaults exist
- Copy derives for small value types: `#[derive(Debug, Clone, Copy, PartialEq, Eq)]`

### 7.2 Option vs Sentinel
- Use `Option<T>` for optional fields; never use empty string or `-1` as sentinel
- `#[serde(default)]` for backward-compatible optional fields
- `#[serde(skip_serializing_if = "Option::is_none")]` to omit nulls from JSON

### 7.3 Must Use
- `#[must_use]` on all non-side-effect query methods:
  ```rust
  #[must_use]
  pub fn is_denied(self) -> bool { ... }
  #[must_use]
  pub fn default_allow() -> Self { ... }
  ```

### 7.4 Newtypes
- Not heavily used; paths and SIDs remain `String` for simplicity
- `Zeroizing<[u8; 32]>` used for cryptographic key material

---

## 8. Memory and Performance

### 8.1 Allocations
- Prefer `&str` over `String` in function parameters
- Use `Cow<'_, str>` when ownership is conditionally needed
- Pre-allocate `Vec` capacity when size is known: `Vec::with_capacity(capacity)`
- Use `String::new()` for empty strings (no allocation)

### 8.2 Cloning
- Explicit `.clone()` calls required; no implicit clones in closures
- `Arc::clone()` for shared reference counting (not `.clone()` on the inner type)

### 8.3 Concurrency
- **Async:** `tokio` runtime with `full` features
- **CPU-bound:** `rayon` for data parallelism (where applicable)
- **Shared state:** `Arc<RwLock<T>>` or `Arc<Mutex<T>>` (parking_lot preferred)
- **Channels:** `tokio::sync::mpsc` for message passing
- **Offload:** CPU-bound work to `tokio::task::spawn_blocking` to avoid blocking the reactor

---

## 9. Security Practices

### 9.1 Secrets
- No hardcoded credentials in source code
- Configuration from `.env` (in `.gitignore`)
- `secrecy` crate for sensitive data types
- DPAPI for machine-bound encryption on Windows

### 9.2 Unsafe Code
- 623+ `unsafe` blocks, all isolated in Windows API modules
- Each block documented with safety invariants
- Minimized surface area; safe wrappers around unsafe primitives

### 9.3 Platform Guards
- 245 `#[cfg(windows)]` annotations
- 60 `#[cfg(not(windows))]` stub implementations
- Ensures code compiles on all platforms even if runtime behavior is Windows-only
