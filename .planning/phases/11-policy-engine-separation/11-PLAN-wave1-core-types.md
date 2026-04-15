---
wave: 1
depends_on: []
order: 1
description: Create PolicyEngineError type, PolicyStore struct with ABAC evaluation, and wire modules into lib.rs.
files_modified:
  - dlp-server/src/policy_engine_error.rs  (create)
  - dlp-server/src/policy_store.rs          (create)
  - dlp-server/src/lib.rs                  (modify)
---

# Wave 1: Core Types and `PolicyStore` Struct

## Objective

Create the foundational error type, the `PolicyStore` struct with all evaluation logic, and declare both modules in `lib.rs`. The cache is read-only on the hot path; write-lock only needed for `invalidate` and `refresh`.

---

## Task 1.1 — Create `policy_engine_error.rs`

### Purpose

Define the `PolicyEngineError` enum used when a policy lookup fails (e.g., in `get_policy` handlers ported from `policy_api.rs`).

### `<read_first>`

```
dlp-server/src/policy_api.rs
```

Read the import of `PolicyEngineError` on line 27 of `policy_api.rs`:
```rust
use crate::policy_engine_error::PolicyEngineError;
```

Read the `AppError` definition in `dlp-server/src/lib.rs` lines 64–89 to understand error variant names.

### `<action>`

Create `dlp-server/src/policy_engine_error.rs`:

```rust
//! Error types emitted by the policy engine layer.

use thiserror::Error;

/// Errors that can occur during policy engine operations.
#[derive(Debug, Error)]
pub enum PolicyEngineError {
    /// The requested policy was not found.
    #[error("policy not found: {0}")]
    PolicyNotFound(String),
}
```

Notes:
- Only `PolicyNotFound` variant is needed right now. More variants can be added in later waves if needed.
- File MUST contain a doc comment at the top (e.g., `//! Error types emitted by the policy engine layer.`).
- Use `use thiserror::Error;` on its own line, then `#[derive(Debug, Error)]` on the enum — do NOT put `thiserror::Error` on the same line as `#[derive(...)]`.

### `<acceptance_criteria>`

- [ ] File `dlp-server/src/policy_engine_error.rs` exists
- [ ] Contains `pub enum PolicyEngineError` with `PolicyNotFound(String)` variant
- [ ] File compiles with `cargo build -p dlp-server` (no warnings, no errors)
- [ ] `PolicyEngineError` implements `std::error::Error` (via `thiserror`)

---

## Task 1.2 — Create `policy_store.rs`

### Purpose

Implement the `PolicyStore` struct: load policies from DB at startup, cache them in a `RwLock<Vec<Policy>>`, and provide a synchronous `evaluate()` for the hot path.

### `<read_first>`

```
dlp-server/src/db/repositories/policies.rs        (PolicyRepository::list, PolicyRow struct)
dlp-common/src/abac.rs                           (EvaluateRequest, EvaluateResponse, Policy, PolicyCondition, Decision, default_deny, default_allow)
dlp-common/src/classification.rs                (Classification enum T1–T4)
dlp-server/src/policy_engine_error.rs            (from Task 1.1)
dlp-server/src/lib.rs                           (Pool type alias)
```

Read `PolicyRepository::list` in `policies.rs` lines 70–104 — note it takes `&Pool`, not `Arc<Pool>`. When calling `PolicyRepository::list(&pool)` where `pool: Arc<Pool>`, Rust will automatically coerce `Arc<Pool>` to `&Pool` via `Deref` — no explicit deref needed.

Read `PolicyCondition` variants in `dlp-common/src/abac.rs` lines 216–247 — note `#[serde(tag = "attribute")]`, `MemberOf { group_sid: String }` (NOT a list), and the `#[serde(rename = "op")]` field.

Read `Policy::default_deny()` and `Policy::default_allow()` in `dlp-common/src/abac.rs` lines 193–210.

Read `Subject` and `Resource` in `dlp-common/src/abac.rs` to understand what fields are on the evaluation request.

Read `Action` in `dlp-common/src/abac.rs` to verify the serde format used for the `action` field in `EvaluateRequest`.

### `<action>`

Create `dlp-server/src/policy_store.rs` with this exact structure:

```rust
//! In-memory policy cache with ABAC evaluation engine.
//!
//! ## Cache Strategy
//! - Load all policies from DB at startup via `PolicyRepository::list`.
//! - Cache lives in `RwLock<Vec<Policy>>` — read path needs no lock acquisition.
//! - `invalidate()` and `refresh()` acquire write lock and swap in a new Vec.
//!
//! ## Evaluation Order
//! Policies are evaluated in ascending `priority` order (lowest first, first-match wins).
//! Disabled policies are skipped entirely.

use std::sync::Arc;

use dlp_common::abac::{
    AccessContext, Classification, Decision, DeviceTrust, EvaluateRequest,
    EvaluateResponse, NetworkLocation, Policy, PolicyCondition, Subject,
};
use parking_lot::RwLock;
use tracing::{error, info, warn};

use crate::db::repositories::PolicyRepository;
use crate::db::Pool;
use crate::policy_engine_error::PolicyEngineError;

/// Background cache refresh interval (5 minutes).
const POLICY_REFRESH_INTERVAL_SECS: u64 = 300;

/// The policy evaluation store.
///
/// Holds an in-memory cache of all policies loaded from the database.
/// Evaluation is a read-only cache hit — no database call on the hot path.
pub struct PolicyStore {
    cache: RwLock<Vec<Policy>>,
    pool: Arc<Pool>,
}

impl PolicyStore {
    /// Loads all policies from the database and builds the in-memory cache.
    ///
    /// Called once at startup. Blocks briefly while SQLite reads all rows.
    ///
    /// # Arguments
    ///
    /// * `pool` — Shared database connection pool.
    ///
    /// # Errors
    ///
    /// Returns `PolicyEngineError` if the initial load fails.
    pub fn new(pool: Arc<Pool>) -> Result<Self, PolicyEngineError> {
        let policies = Self::load_from_db(&pool)
            .map_err(|e| PolicyEngineError::PolicyNotFound(e.to_string()))?;
        info!(count = policies.len(), "policy store loaded");
        Ok(Self {
            cache: RwLock::new(policies),
            pool,
        })
    }

    /// Re-reads all enabled policies from the database and replaces the cache.
    ///
    /// Called by the background refresh task. Logs errors but does NOT panic —
    /// a failed refresh means the stale cache is used until the next interval.
    pub fn refresh(&self) {
        match Self::load_from_db(&self.pool) {
            Ok(policies) => {
                let count = policies.len();
                *self.cache.write() = policies;
                info!(count, "policy store refreshed");
            }
            Err(e) => {
                error!(error = %e, "policy store refresh failed — using stale cache");
            }
        }
    }

    /// Immediately invalidates the cache and reloads from the database.
    ///
    /// Called by admin CRUD handlers after a successful DB commit so the next
    /// evaluation request sees the updated policy set.
    pub fn invalidate(&self) {
        match Self::load_from_db(&self.pool) {
            Ok(policies) => {
                let count = policies.len();
                *self.cache.write() = policies;
                info!(count, "policy store invalidated");
            }
            Err(e) => {
                warn!(error = %e, "policy store invalidation failed — keeping stale cache");
            }
        }
    }

    /// Evaluates `request` against the cached policy set.
    ///
    /// Returns a decision for the first enabled policy whose conditions all
    /// match. If no policy matches, applies tiered default-deny (D-01):
    /// - T1 / T2 → `Decision::ALLOW`
    /// - T3 / T4 → `Decision::DENY`
    ///
    /// This is the **hot path** — it acquires only a read lock on the cache.
    pub fn evaluate(&self, request: &EvaluateRequest) -> EvaluateResponse {
        let cache = self.cache.read();

        for policy in cache.iter() {
            if !policy.enabled {
                continue;
            }
            if policy.conditions.iter().all(|c| condition_matches(c, request)) {
                return EvaluateResponse {
                    decision: policy.action,
                    matched_policy_id: Some(policy.id.clone()),
                    reason: format!("matched policy '{}'", policy.name),
                };
            }
        }

        // No policy matched — tiered default-deny (D-01).
        match request.resource.classification {
            Classification::T1 | Classification::T2 => EvaluateResponse::default_allow(),
            Classification::T3 | Classification::T4 => EvaluateResponse::default_deny(),
        }
    }

    /// Lists all cached policies (for admin read-back / diagnostics).
    #[must_use]
    pub fn list_policies(&self) -> Vec<Policy> {
        self.cache.read().clone()
    }

    /// Loads all policies from the database via `PolicyRepository::list`.
    fn load_from_db(pool: &Pool) -> Result<Vec<Policy>, rusqlite::Error> {
        let rows = PolicyRepository::list(pool)?;

        // Deserialize each policy row. Skip rows with invalid JSON rather than
        // crashing the server — log and continue.
        let mut policies = Vec::with_capacity(rows.len());
        for row in rows {
            match deserialize_policy_row(&row) {
                Ok(p) => policies.push(p),
                Err(e) => {
                    warn!(policy_id = %row.id, error = %e, "skipped policy with malformed conditions");
                }
            }
        }

        // Policies are already sorted by priority ASC from the SQL query.
        Ok(policies)
    }
}

/// Deserializes a `PolicyRow` into a `Policy`.
///
/// Handles the translation from DB `action` string (`"Allow"`, `"Deny"`, etc.)
/// to the `Decision` enum.
fn deserialize_policy_row(row: &crate::db::repositories::policies::PolicyRow) -> Result<Policy, serde_json::Error> {
    let conditions: Vec<PolicyCondition> = serde_json::from_str(&row.conditions)?;
    let action = match row.action.to_lowercase().as_str() {
        "allow" => Decision::ALLOW,
        "deny" => Decision::DENY,
        "allow_with_log" | "allowwithlog" => Decision::AllowWithLog,
        "deny_with_alert" | "denywithalert" => Decision::DenyWithAlert,
        _ => Decision::DENY,
    };
    Ok(Policy {
        id: row.id.clone(),
        name: row.name.clone(),
        description: row.description.clone(),
        priority: row.priority as u32,
        conditions,
        action,
        enabled: row.enabled != 0,
        version: row.version as u64,
    })
}

/// Evaluates a single condition against an evaluation request.
///
/// Returns `true` if the condition matches, `false` otherwise.
/// Operators `"in"` and `"not_in"` on non-MemberOf conditions return `false`
/// defensively (they only apply to group membership checks).
fn condition_matches(condition: &PolicyCondition, request: &EvaluateRequest) -> bool {
    match condition {
        PolicyCondition::Classification { op, value } => {
            compare_op(op, &request.resource.classification, value)
        }
        PolicyCondition::MemberOf { op, group_sid } => {
            memberof_matches(op, group_sid, &request.subject.groups)
        }
        PolicyCondition::DeviceTrust { op, value } => {
            compare_op(op, &request.subject.device_trust, value)
        }
        PolicyCondition::NetworkLocation { op, value } => {
            compare_op(op, &request.subject.network_location, value)
        }
        PolicyCondition::AccessContext { op, value } => {
            compare_op(op, &request.environment.access_context, value)
        }
    }
}

/// Compares two values using the given operator string.
///
/// Supports `"eq"` and `"neq"` for all `T: PartialEq` types.
/// Operators `"in"` and `"not_in"` return `false` (not applicable to scalar types).
fn compare_op<T: PartialEq>(op: &str, actual: &T, expected: &T) -> bool {
    match op {
        "eq" => actual == expected,
        "neq" => actual != expected,
        // Defensive: "in"/"not_in" on non-MemberOf conditions never match.
        "in" | "not_in" => false,
        _ => false,
    }
}

/// Evaluates a MemberOf condition against the subject's group SID list.
///
/// - `"in"`: matches if ANY group SID in `subject_groups` equals `group_sid`
/// - `"not_in"`: matches if NO group SID in `subject_groups` equals `group_sid`
/// - `"eq"` / `"neq"`: delegates to `compare_op` (single-value semantics)
fn memberof_matches(op: &str, target_sid: &str, subject_groups: &[String]) -> bool {
    match op {
        "in" => subject_groups.iter().any(|sid| sid == target_sid),
        "not_in" => subject_groups.iter().all(|sid| sid != target_sid),
        // Fall back to scalar semantics for eq/neq (treat as single-element list).
        "eq" => subject_groups.iter().any(|sid| sid == target_sid),
        "neq" => subject_groups.iter().all(|sid| sid != target_sid),
        _ => false,
    }
}
```

### `<acceptance_criteria>`

- [ ] File `dlp-server/src/policy_store.rs` exists
- [ ] `PolicyStore::new(pool: Arc<Pool>) -> Result<Self, PolicyEngineError>` — signature matches exactly
- [ ] `PolicyStore::evaluate(&self, request: &EvaluateRequest) -> EvaluateResponse` — hot path, no `async`
- [ ] `PolicyStore::refresh(&self)` — reloads cache from DB, logs errors but does not panic
- [ ] `PolicyStore::invalidate(&self)` — immediately reloads cache from DB
- [ ] `condition_matches` handles all 5 condition types: Classification, MemberOf, DeviceTrust, NetworkLocation, AccessContext
- [ ] `"in"` / `"not_in"` operators on non-MemberOf conditions return `false` (defensive)
- [ ] MemberOf `"in"` matches if ANY group SID equals `group_sid`; `"not_in"` matches if NONE equals
- [ ] Tiered default-deny: T1/T2 → ALLOW, T3/T4 → DENY
- [ ] `evaluate()` is `&self` (not `&mut self`), read-only on hot path
- [ ] Policy rows with malformed JSON conditions are skipped with a warning log (not hard errors)
- [ ] `parking_lot::RwLock` is used (not `std::sync::RwLock`) for faster uncontended read path
- [ ] File compiles with `cargo build -p dlp-server` — no warnings, no errors

---

## Task 1.3 — Add module declarations to `lib.rs`

### Purpose

Expose `policy_store` and `policy_engine_error` as public submodules of `dlp-server`, and add the `impl From<PolicyEngineError> for AppError` conversion so `?` works on `PolicyEngineError` in handlers.

### `<read_first>`

```
dlp-server/src/lib.rs
```

Read the `pub mod` block at lines 6–15 to find where to insert the new modules.

### `<action>`

In `dlp-server/src/lib.rs`:

1. Add these two lines inside the existing module block:

   ```rust
   pub mod policy_engine_error;
   pub mod policy_store;
   ```

   Place them alphabetically between `exception_store` and `policy_sync` or at the end before the blank line.

2. Add the `impl From<PolicyEngineError> for AppError` conversion **with the required import** — add this import near the other `use crate::` imports at the top of the file (or in the impl block proximity):

   ```rust
   use crate::policy_engine_error::PolicyEngineError;
   ```

   Then add the impl block:

   ```rust
   /// Maps `PolicyEngineError::PolicyNotFound` to `AppError::NotFound`.
   impl From<PolicyEngineError> for AppError {
       fn from(e: PolicyEngineError) -> Self {
           match e {
               PolicyEngineError::PolicyNotFound(id) => AppError::NotFound(id),
           }
       }
   }
   ```

   The `use` statement must appear before the `impl` block in source order.

### `<acceptance_criteria>`

- [ ] `pub mod policy_engine_error;` declared in `lib.rs`
- [ ] `pub mod policy_store;` declared in `lib.rs`
- [ ] `use crate::policy_engine_error::PolicyEngineError;` present before the `impl From` block
- [ ] `impl From<PolicyEngineError> for AppError` present, mapping `PolicyNotFound` → `AppError::NotFound`
- [ ] `lib.rs` compiles with `cargo build -p dlp-server` — no warnings, no errors
- [ ] `dlp-server/src/policy_store.rs` and `dlp-server/src/policy_engine_error.rs` can both be imported as `crate::policy_store::PolicyStore` and `crate::policy_engine_error::PolicyEngineError`
