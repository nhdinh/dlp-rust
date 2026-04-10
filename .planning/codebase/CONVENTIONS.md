# Coding Conventions

**Analysis Date:** 2026-04-10

## Naming Patterns

**Files:**
- Lowercase with underscores: `engine_client.rs`, `audit_emitter.rs`, `policy_mapper.rs`
- Module files use `mod.rs` convention: `clipboard/mod.rs`, `detection/mod.rs`, `interception/mod.rs`
- Test files suffix: `integration.rs`, `comprehensive.rs`, `negative.rs` (collocated in `tests/` directory)

**Functions:**
- Snake_case for all public and private functions: `resolve_caller_identity()`, `run_event_loop()`, `fail_closed_response()`
- Async functions return `Result<T>` or `Result<T, CustomError>` pattern
- Getter/query functions use descriptive prefixes: `resolve_`, `get_`, `is_`, `contains_`
- Example: `get_application_metadata()`, `is_denied()`, `requires_audit()`

**Variables:**
- Snake_case throughout: `user_sid`, `process_id`, `device_trust`, `cache_entry`
- Constants use SCREAMING_SNAKE_CASE: `DEFAULT_TTL`, `MAX_RETRIES`, `INITIAL_BACKOFF`, `DEFAULT_ENGINE_URL`
- Struct field names match Rust style: `pub user_sid: String`, `pub matched_policy_id: Option<String>`

**Types:**
- PascalCase for all structs, enums, traits: `Subject`, `Resource`, `Environment`, `Decision`, `EngineClient`, `Cache`, `AuditEmitter`
- Enum variants use both PascalCase and SCREAMING_SNAKE_CASE based on semantics:
  - Enum variant names: `READ`, `WRITE`, `COPY`, `DELETE`, `MOVE`, `PASTE` (Action enum — actions as verbs)
  - Decision variants: `ALLOW`, `DENY`, `AllowWithLog`, `DenyWithAlert` (mixed for readability)
  - Status variants: `Managed`, `Unmanaged`, `Compliant`, `Unknown` (DeviceTrust enum)
- Custom error enums use PascalCase with `Error` suffix: `EngineClientError`, `IdentityError`, `AppError`

## Code Style

**Formatting:**
- Uses `rustfmt` default settings (100-character line length)
- 4 spaces for indentation (verified in dlp-agent/Cargo.toml dependencies)
- No tabs used anywhere

**Linting:**
- Code must pass `cargo clippy -- -D warnings` (all warnings treated as errors)
- Static analysis via `sonar-scanner` required before commits
- Verified: dlp-common, dlp-agent, dlp-server all follow idiomatic Rust style

## Import Organization

**Order:**
1. Standard library imports: `use std::...`
2. External crate imports: `use tokio::...`, `use serde::...`, `use anyhow::...`
3. Workspace imports: `use dlp_common::...`
4. Local module imports: `use crate::...`

**Examples from codebase:**
```rust
// dlp-agent/src/engine_client.rs
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use dlp_common::{EvaluateRequest, EvaluateResponse};
use reqwest::Client;
use tracing::{debug, error, warn};
```

**Path Aliases:**
- Uses `crate::prelude` for re-exports of shared types (`dlp-agent/src/lib.rs`):
  ```rust
  pub mod prelude {
      pub use dlp_common::*;
  }
  ```
- Modules export commonly-used types via `pub use` barrels

**Wildcard Imports:**
- Avoided except in test modules: `use super::*;` in `#[cfg(test)]` blocks
- No wildcard imports in production code; all imports are explicit

## Error Handling

**Patterns:**
- Use `thiserror` for domain-specific error types (`EngineClientError`, `IdentityError`)
- Use `anyhow::Result<T>` for application-level error propagation at boundary layers (main.rs, async spawn blocks)
- Define custom error enums with `#[derive(Debug, thiserror::Error)]`
- Errors are propagated with `?` operator; no `.unwrap()` in production paths

**Examples:**
```rust
// dlp-agent/src/engine_client.rs — Custom error type
#[derive(Debug, thiserror::Error)]
pub enum EngineClientError {
    #[error("Policy Engine is unreachable after {attempts} attempts")]
    Unreachable { attempts: u32 },

    #[error("HTTP error {status} from Policy Engine: {body}")]
    HttpError { status: u16, body: String },

    #[error("TLS verification failed: {0}")]
    TlsError(String),
}

// Return custom error type from library functions
pub async fn evaluate(
    &self,
    request: &EvaluateRequest,
) -> Result<EvaluateResponse, EngineClientError> { ... }
```

```rust
// dlp-agent/src/main.rs — Application boundary uses anyhow
fn main() -> anyhow::Result<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_entry)
        .context("service dispatcher failed")?;
    Ok(())
}
```

**Fail-closed for sensitive data:**
- T3/T4 classifications must DENY on cache miss / offline (enforced in `dlp-agent/src/cache.rs`)
- Pattern: `cache.get()` returns `Option<EvaluateResponse>`; on `None` for T3/T4, call `cache::fail_closed_response(classification)` which returns DENY decision

## Logging

**Framework:** `tracing` crate for structured logging with spans

**Imports:** 
- `use tracing::{debug, info, warn, error};`
- Do NOT use `log::` or `println!`

**Patterns:**
- Use `debug!()` for low-level operational details (cache hits, parse operations)
- Use `info!()` for significant events (service startup, configuration loaded)
- Use `warn!()` for recoverable errors and fallback behavior
- Use `error!()` only for errors that require immediate attention

**Examples:**
```rust
// dlp-agent/src/cache.rs
debug!(
    resource_path,
    user_sid,
    decision = ?e.response.decision,
    "cache hit"
);

// dlp-agent/src/engine_client.rs
error!(error = %e, attempts, retryable, "Policy Engine evaluation failed");
warn!(error = %e, attempts, ?backoff, "Policy Engine unreachable — retrying");

// dlp-admin-cli/src/engine.rs
info!(url = %url, "using DLP_SERVER_URL env var");
debug!(addr = %addr, url = %url, "read BIND_ADDR from registry");
```

**Structured fields:**
- Include contextual fields in log calls: `error!(path = %path, error = %e, "..."`
- Use `%` for Display and `?` for Debug formatting in field values

## Comments

**When to Comment:**
- Doc comments (starting with `///`) on all public functions, structs, enums, methods
- No inline code comments unless explaining non-obvious Rust semantics or Windows API subtleties
- Module-level doc comments explaining the crate's purpose and integration points

**JSDoc/TSDoc Pattern — Rust Doc Comments:**
Required format for public items:

```rust
/// [One-sentence summary].
///
/// [Longer description if needed, explaining the behavior and use cases].
///
/// # Arguments
///
/// * `param1` - Description of param1
/// * `param2` - Description of param2
///
/// # Returns
///
/// [Description of return value]
///
/// # Errors
///
/// Returns `ErrorType::Variant` if [condition]
/// Returns `ErrorType::Other` if [other condition]
///
/// # Examples
///
/// ```
/// let result = my_function(arg1, arg2)?;
/// assert_eq!(result, expected);
/// ```
pub fn my_function(param1: &str, param2: u32) -> Result<String> { ... }
```

**Examples from codebase:**
- `dlp-agent/src/cache.rs::get()` — documents TTL behavior, fail-closed semantics, expiry mechanics
- `dlp-agent/src/audit_emitter.rs::emit()` — documents append-only semantics, rotation, and no-blocking behavior
- `dlp-common/src/classifier.rs::classify_text()` — includes examples showing each tier classification

## Function Design

**Size:** Functions are kept small and focused; longest ones are ~100 lines (event loop in `interception/mod.rs`)

**Parameters:** 
- Maximum 5 parameters before switching to a config/builder struct
- Prefer borrowing (`&T`, `&mut T`) over ownership transfers
- Result types returned as `Result<T, E>` (never unwrap in library code)
- Lifetimes used where needed for string slices and borrowed data

**Return Values:**
- Async functions return `Result<T, E>` where `E` is a custom error type or `anyhow::Error`
- Queries return `Option<T>` (not default/sentinel values)
- Boolean checks return `bool` with `is_*()` naming: `is_denied()`, `is_alert()`, `requires_audit()`

**Early Return Pattern:**
```rust
// dlp-admin-cli/src/engine.rs::resolve_engine_url()
pub fn resolve_engine_url() -> String {
    // Try env var first
    if let Ok(url) = std::env::var("DLP_SERVER_URL") {
        if !url.is_empty() {
            info!(url = %url, "using DLP_SERVER_URL env var");
            return url;
        }
    }
    // Try registry
    if let Ok(addr) = registry::read_registry_string(KEY, VALUE) {
        // ... setup ...
        return url;
    }
    // Fallback
    DEFAULT_URL.to_string()
}
```

## Module Design

**Exports:**
- Public types exported via module's `lib.rs` or `mod.rs`
- `dlp-agent/src/lib.rs` exports major modules and provides a prelude for dlp-common re-exports
- Each module documents its integration point with a comment block

**Barrel Files:**
- `dlp-common/src/lib.rs` re-exports all submodules: `pub use abac::*; pub use audit::*; pub use classification::*; pub use classifier::classify_text;`
- `dlp-agent/src/lib.rs` does NOT wildcard-export all modules; lists them explicitly for clarity

**Module Structure:**
- One struct/type system per file (or closely-related variants)
- `mod.rs` used to glue submodules together and export the public API
- Private modules via `mod private_name;` without `pub` keyword

## Derive Macros

**Standard derives:**
- `#[derive(Debug, Clone)]` — on almost all public types
- `#[derive(PartialEq, Eq)]` — on value types (enums, small structs used in comparisons)
- `#[derive(Serialize, Deserialize)]` — on types crossing IPC/HTTP boundaries
- `#[derive(Default)]` — on types with sensible defaults

**Examples:**
```rust
// dlp-common/src/abac.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Action { READ, WRITE, COPY, DELETE, MOVE, PASTE }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Subject { ... }
```

## Type System Practices

**Newtypes:** Not heavily used in this codebase; paths/SIDs are `String`

**Option vs Sentinel:**
- Use `Option<String>` for optional fields: `pub matched_policy_id: Option<String>`
- Never use empty string or `-1` as sentinel values

**#[must_use]:**
- Applied to all non-side-effect query methods:
  ```rust
  #[must_use]
  pub fn is_denied(self) -> bool { ... }
  
  #[must_use]
  pub fn default_allow() -> Self { ... }
  ```

## Memory and Performance

**Allocations:**
- Use `&str` for string slices (not `String`) in function parameters
- Use `Cow<'_, str>` when ownership is conditionally needed
- Pre-allocate `Vec` capacity when size is known: `Vec::with_capacity(capacity)`

**Cloning:**
- Explicit `.clone()` calls required; no implicit clones hidden in closures
- Example: `cache.insert(action.path().to_string(), ...)` — `.to_string()` is explicit String allocation

## Concurrency

**Async/Await:**
- Uses `tokio` runtime with feature `"full"` for all async operations
- Async functions are marked `pub async fn` and return `Result<T, E>`
- Spawn long-running tasks with `tokio::spawn(async { ... })` to avoid blocking the reactor

**Thread Safety:**
- Shared state uses `Arc<RwLock<T>>` or `Arc<Mutex<T>>` (parking_lot preferred)
- Cache uses `Arc<Cache>` with internal `RwLock<HashMap>`
- Channels use `tokio::sync::mpsc` for message passing (FileAction events, IPC commands)

**Example:**
```rust
// dlp-agent/src/cache.rs
pub struct Cache {
    inner: RwLock<HashMap<CacheKey, CacheEntry>>,
    ttl: Duration,
}
```

## Security

**Secrets Handling:**
- No hardcoded credentials or API keys in code
- Configuration loaded from `.env` (must be in `.gitignore`)
- Sensitive data types use `secrecy` crate where needed (not yet applied; aspirational from CLAUDE.md)

**Logging:**
- Never log sensitive information: passwords, tokens, API keys, PII (SIDs are logged for audit purposes)
- SIDs and usernames are logged only in audit context, not in debug/trace logs

**Windows API Safety:**
- Unsafe code is isolated in platform-specific modules (`audit_emitter.rs`, `identity.rs`)
- Each unsafe block is clearly documented with safety invariants
- Example in `audit_emitter.rs`: unsafe calls to `OpenProcess`, `GetModuleFileNameExW` are wrapped with error handling

---

## Aspirational vs Actual

**Fully Implemented (from CLAUDE.md):**
- Error handling with `thiserror` and `anyhow` ✓
- `tracing` for structured logging ✓
- Doc comments on public items ✓
- Snake/Pascal/SCREAMING_SNAKE_CASE conventions ✓
- `Result<T, E>` error propagation ✓
- No `.unwrap()` in production paths ✓
- Explicit `.clone()` calls ✓
- `tokio` for async runtime ✓

**Partially Implemented:**
- `#[must_use]` on non-side-effect functions (used selectively, not universally) ~
- Newtypes for semantic distinction (not used; paths/SIDs remain `String`) ~

**Not Yet Applied (aspirational in CLAUDE.md):**
- `secrecy` crate for sensitive types (no secrets stored in code currently)
- `polars` for data processing (not applicable to this domain)
- `indicatif` for progress bars (not needed in service/agent)
- `ratatui` for TUI (dlp-admin-cli has custom TUI, not using ratatui)

---

*Convention analysis: 2026-04-10*
