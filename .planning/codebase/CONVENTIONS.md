# Coding Conventions

**Analysis Date:** 2026-07-03

## Naming Patterns

**Files:**
- Lowercase with underscores: `audit_emitter.rs`, `policy_mapper.rs`, `engine_client.rs`.
- Module entry points use `mod.rs`: `ipc/mod.rs`, `detection/mod.rs`, `db/repositories/mod.rs`.
- Test files use descriptive suffixes: `integration.rs`, `comprehensive.rs`, `negative.rs`, `*_integration.rs`.

**Functions:**
- Snake_case for all functions: `resolve_caller_identity()`, `emit_audit()`, `fail_closed_response()`.
- Async functions return `Result<T, E>`: `pub async fn evaluate(...) -> Result<..., Error>`.
- Query/predicate prefixes:
  - `resolve_*` — resolution operations (`resolve_volume_class_from_path()`)
  - `get_*` — simple accessors (`get_active()`, `get_by_version()`)
  - `is_*` — boolean predicates (`is_denied()`, `is_blocking()`, `is_sensitive()`)
  - `requires_*` — capability checks (`requires_audit()`)
  - `with_*` — builder-style setters (`with_policy()`, `with_blocked_disk()`)

**Variables:**
- Snake_case: `user_sid`, `process_id`, `cache_entry`.
- Constants: SCREAMING_SNAKE_CASE: `SERVICE_NAME`, `SHUTDOWN_TIMEOUT`, `DEFAULT_BIND`.
- Static globals: snake_case with type annotation: `static CONFIG: OnceLock<...>`, `static SCM_HANDLE: OnceLock<...>`.

**Types:**
- Structs/enums/traits: PascalCase: `Subject`, `AuditEvent`, `AppState`, `SecretCrypto`.
- Error types: PascalCase with `Error` suffix: `AppError`, `CryptoError`, `CacheError`.
- Repository types: PascalCase with `Repository` suffix: `PolicyRepository`, `AuditEventRepository`.
- Row types: PascalCase with `Row` suffix: `PolicyRow`, `AuditEventRow`.

**Enum Variants:**
- Action enum: SCREAMING_SNAKE_CASE verbs: `READ`, `WRITE`, `COPY`, `DELETE`, `PASTE`, `DRAG_DROP`, `CLOUD_UPLOAD`.
- Decision enum: mixed for readability: `ALLOW`, `DENY`, `AllowWithLog`, `DenyWithAlert`.
- Status enums: PascalCase: `Managed`, `Unmanaged`, `Compliant`, `Unknown`.
- Serde rename attributes must match wire format exactly:
  - `#[serde(rename_all = "snake_case")]`
  - `#[serde(rename_all = "PascalCase")]`
  - `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`
  - `#[serde(rename_all = "UPPERCASE")]`

## Code Style

**Formatting:**
- Tool: `rustfmt` (line length 100, 4 spaces, no tabs).
- Verify with `cargo fmt --check`.

**Linting:**
- Tool: `cargo clippy -- -D warnings`.
- Common allows (use sparingly):
  - `#[allow(clippy::too_many_arguments)]` for constructors like `AuditEvent::new()`.
  - `#[allow(clippy::type_complexity)]` for internal cache types.
  - `#[allow(clippy::enum_variant_names)]` when variant names share a prefix.

## Import Organization

**Order:**
1. Standard library: `use std::sync::Arc;`
2. External crates: `use tokio::sync::mpsc;`, `use tracing::{info, warn};`
3. Workspace/local: `use dlp_common::*;`, `use crate::db::Pool;`

**Path Aliases:**
- `dlp_common::*` re-exported in `dlp-agent/src/lib.rs` `prelude` module.
- No wildcard imports in production code except preludes.
- Test modules: `use super::*;` is the only allowed wildcard.

## Error Handling

**Patterns:**
- Custom error types with `thiserror` in library code.
- `anyhow::Result<T>` with `.context()` at application boundaries.
- Use `?` and `#[from]` for propagation.
- Never use `.unwrap()` in production code; `.expect()` only for invariant violations with descriptive messages.
- `AppError` in `dlp-server/src/lib.rs` maps to HTTP status codes via `IntoResponse`.

## Logging

**Framework:** `tracing` (+ `tracing-subscriber`, `tracing-appender`).

**Patterns:**
- Use `tracing::error!` / `warn!` / `info!` / `debug!` / `trace!` instead of `println!`.
- Structured fields: `info!(metric = "syslog_queue_depth", depth, "...")`.
- `%` for Display, `?` for Debug.
- Never log secrets, tokens, passwords, or KEK material.
- Redact sensitive data in `Debug` impls (e.g., `SecretCrypto`).

## Comments

**When to Comment:**
- Doc comments required for all public functions, structs, enums, methods.
- Include `# Arguments`, `# Returns`, `# Errors`, and `# Examples` where applicable.
- Phase/task references in comments: `(Phase 47, Task 47-08)`.
- Security invariants documented inline with `## Fail-Closed Invariant` or `## Threat model`.

**JSDoc/TSDoc:**
- Not applicable; Rust doc comments (`///`) are used exclusively.

## Function Design

**Size:** Keep functions focused on a single responsibility; decompose long functions.
- `clippy::too_many_lines` is generally enabled; suppress only with justification.

**Parameters:** Limit to 5 or fewer; use a config struct for more.

**Return Values:** Return `Result<T, E>` for fallible operations; prefer `Option<T>` over sentinel values.

## Module Design

**Exports:**
- Crate `lib.rs` re-exports public modules.
- `dlp-common/src/lib.rs` uses `pub use abac::*;` for shared types.
- `dlp-agent/src/lib.rs` defines `pub mod prelude { pub use dlp_common::*; }`.

**Barrel Files:**
- Repository barrel: `dlp-server/src/db/repositories/mod.rs` re-exports all repositories.
- Use sparingly beyond crate boundaries to avoid leaking internal modules.

---

*Convention analysis: 2026-07-03*
