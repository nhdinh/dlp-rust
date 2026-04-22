# Phase 22: dlp-common Foundation — Research

**Researched:** 2026-04-22
**Domain:** Rust shared-type library design; serde serialization patterns; workspace-wide type propagation
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** New dedicated module `dlp-common/src/endpoint.rs` for all endpoint-identity types: `AppIdentity`, `DeviceIdentity`, `UsbTrustTier`, `AppTrustTier`, `SignatureState`. Re-export from `lib.rs` alongside existing `pub use abac::*`.
- **D-02:** `abac.rs` is NOT extended with endpoint types — it stays focused on policy/evaluation types.
- **D-03:** `AppIdentity` fields: `image_path: String`, `publisher: String`, `trust_tier: AppTrustTier`, `signature_state: SignatureState`. All fields non-optional inside the struct; the struct itself is `Option<AppIdentity>` at call sites.
- **D-04:** `AppTrustTier` is a **separate enum** from `UsbTrustTier`. Variants: `Trusted`, `Untrusted`, `Unknown` — `#[default]` is `Unknown`.
- **D-05:** `SignatureState` variants: `Valid`, `Invalid`, `NotSigned`, `Unknown` — `#[default]` is `Unknown`.
- **D-06:** `DeviceIdentity` fields: `vid: String`, `pid: String`, `serial: String`, `description: String`. All `String` (not `u16`).
- **D-07:** `UsbTrustTier` variants: `Blocked`, `ReadOnly`, `FullAccess` — serialized as `"blocked"`, `"read_only"`, `"full_access"`. `#[default]` is `Blocked`.
- **D-08:** `EvaluateRequest` gains `source_application: Option<AppIdentity>` and `destination_application: Option<AppIdentity>` with `#[serde(default)]` and `#[serde(skip_serializing_if = "Option::is_none")]`.
- **D-09:** New `AbacContext` struct introduced in `abac.rs` (not yet wired into `evaluate()`). Mirrors `EvaluateRequest` fields plus app identity fields.
- **D-10:** `AbacContext` carries: `subject`, `resource`, `environment`, `action`, `source_application: Option<AppIdentity>`, `destination_application: Option<AppIdentity>`. No `agent` field.
- **D-11:** `AuditEvent` gains `source_application: Option<AppIdentity>` and `destination_application: Option<AppIdentity>` with `#[serde(default)]` and `#[serde(skip_serializing_if = "Option::is_none")]`.
- **D-12:** `AuditEvent` gains `device_identity: Option<DeviceIdentity>` for USB block events.
- **D-13:** No breaking change to existing `AuditEvent` — all new fields use `#[serde(default)]`.
- **D-14:** IPC message files remain duplicated between `dlp-agent/src/ipc/messages.rs` and `dlp-user-ui/src/ipc/messages.rs`.
- **D-15:** `Pipe3UiMsg::ClipboardAlert` in both files gains `source_application: Option<AppIdentity>` and `destination_application: Option<AppIdentity>` with `#[serde(default)]`.
- **D-16:** `Pipe2AgentMsg` (Toast) does NOT get app identity fields.
- **D-17:** All five crates compile with `cargo build --workspace` and zero warnings after Phase 22.

### Claude's Discretion

- `AppIdentity` builder methods (e.g., `with_publisher()`) — Claude decides based on ergonomics.
- Whether `AppTrustTier` and `UsbTrustTier` derive `PartialOrd`/`Ord` — Claude decides.
- `DeviceIdentity` constructor convenience method — Claude decides.

### Deferred Ideas (OUT OF SCOPE)

- IPC message consolidation into dlp-common
- `AppTrustTier` → `PartialOrd` for policy range comparisons (deferred to Phase 26 if needed)
- UWP app identity via AUMID — deferred per REQUIREMENTS.md (APP-07)
</user_constraints>

---

## Summary

Phase 22 is a pure type-definition phase. No evaluation logic, no enforcement, no UI changes. The entire deliverable is a new `dlp-common/src/endpoint.rs` module containing five new types (`AppIdentity`, `DeviceIdentity`, `UsbTrustTier`, `AppTrustTier`, `SignatureState`), plus targeted additions to three existing files (`abac.rs` for `AbacContext` + `EvaluateRequest` fields, `audit.rs` for new `AuditEvent` fields, and both IPC `messages.rs` files for `ClipboardAlert` struct fields). The phase gate is `cargo build --workspace` with zero warnings.

The codebase currently compiles cleanly (verified via `cargo check --workspace`). The five downstream crates all depend on `dlp-common` via `{ path = "../dlp-common" }`. The existing serde conventions (wildcard re-exports from `abac::*`, `audit::*`, builder-pattern with `with_*()` methods, `#[serde(skip_serializing_if = "Option::is_none")]` per-field) are well-established and must be followed exactly.

**Primary recommendation:** Create `endpoint.rs` with the five new types first, add named re-exports to `lib.rs`, then extend `abac.rs`, `audit.rs`, and both IPC `messages.rs` files in sequence. Run `cargo build --workspace` after each file to catch compilation breaks early.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| `AppIdentity` / `DeviceIdentity` / `UsbTrustTier` / `AppTrustTier` / `SignatureState` type definitions | dlp-common (shared library) | — | All downstream crates reference these types via Cargo path dependency; single source of truth prevents wire-format divergence |
| `EvaluateRequest` extension (`source_application`, `destination_application`) | dlp-common / abac.rs | dlp-server (evaluator) | Wire-format struct consumed by the evaluator; dlp-server's `PolicyStore::evaluate()` receives `EvaluateRequest` today and will receive `AbacContext` in Phase 26 |
| `AbacContext` (internal evaluator context) | dlp-common / abac.rs | dlp-server | Internal evaluation boundary type — only the server's `PolicyStore` will call it; defined in common so types are shared at compile time |
| `AuditEvent` extension | dlp-common / audit.rs | dlp-server (audit_store), dlp-agent (audit_emitter) | Both agent and server emit/receive `AuditEvent`; changes must compile in both |
| IPC `ClipboardAlert` extension | dlp-agent / ipc/messages.rs AND dlp-user-ui / ipc/messages.rs | — | Kept deliberately duplicated (D-14); both copies must be updated identically to maintain protocol compatibility |

---

## Standard Stack

### Core (verified in codebase)

| Library | Version | Purpose | How Used |
|---------|---------|---------|----------|
| serde | 1 (workspace) | Serialization/deserialization | `#[derive(Serialize, Deserialize)]` on all dlp-common types |
| serde_json | 1 (workspace) | JSON encoding for wire format and IPC | `serde_json::to_string` / `from_str` in tests and IPC layer |
| thiserror | 1 (workspace) | Custom error types | Used in `ad_client.rs`; available if new error types needed |

No new dependencies are required for Phase 22. All needed types (`String`, `Option<T>`) and serde features are already in `dlp-common/Cargo.toml`. [VERIFIED: codebase grep]

**No `Cargo.toml` changes needed.**

---

## Architecture Patterns

### System Architecture Diagram

```
New types in dlp-common/src/endpoint.rs
  AppIdentity, DeviceIdentity, UsbTrustTier, AppTrustTier, SignatureState
            |
            | re-exported from lib.rs (named pub use)
            |
    +-------+--------+------------------+--------------------+
    |                |                  |                    |
abac.rs extends:  audit.rs extends:  dlp-agent/          dlp-user-ui/
  EvaluateRequest   AuditEvent         ipc/messages.rs     ipc/messages.rs
  AbacContext         + source_app      ClipboardAlert       ClipboardAlert
  + source_app        + dest_app        + source_app         + source_app
  + dest_app          + device_id       + dest_app           + dest_app
                          |                 (Option<AppIdentity>, #[serde(default)])
                          |
            dlp-server consumes EvaluateRequest + AuditEvent
            dlp-admin-cli consumes dlp_common::abac::* types
```

### Recommended File Modification Order

```
1. dlp-common/src/endpoint.rs      (NEW — all five types)
2. dlp-common/src/lib.rs           (add pub mod endpoint + named re-exports)
3. dlp-common/src/abac.rs          (extend EvaluateRequest + add AbacContext)
4. dlp-common/src/audit.rs         (extend AuditEvent + add builder methods)
5. dlp-agent/src/ipc/messages.rs   (extend Pipe3UiMsg::ClipboardAlert)
6. dlp-user-ui/src/ipc/messages.rs (same change mirrored)
```

Run `cargo build --workspace` after step 2 (baseline) and after each subsequent step.

### Pattern 1: New enum with serde rename_all (UsbTrustTier)

The existing pattern for `DeviceTrust` and `NetworkLocation` uses `PascalCase` via `#[serde(rename_all = "PascalCase")]`. `UsbTrustTier` deviates: it must serialize as `"blocked"`, `"read_only"`, `"full_access"` (DB CHECK constraint values per USB-02). Use `rename_all = "snake_case"` to achieve this automatically.

```rust
// Source: dlp-common/src/abac.rs (AccessContext pattern) + REQUIREMENTS.md USB-02
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UsbTrustTier {
    /// Device is blocked — all I/O denied.
    #[default]
    Blocked,
    /// Device allows reads; writes denied.
    ReadOnly,
    /// Device allows full read/write access.
    FullAccess,
}
```

Verification: `serde_json::to_string(&UsbTrustTier::ReadOnly)` must produce `"read_only"`, matching the Phase 24 DB CHECK constraint. [VERIFIED: REQUIREMENTS.md USB-02; serde rename_all = "snake_case" behavior confirmed by project pattern in AccessContext]

### Pattern 2: Optional wire field (skip_serializing_if = "Option::is_none")

The existing `EvaluateRequest.agent` field establishes the exact pattern to follow for all new optional fields:

```rust
// Source: dlp-common/src/abac.rs lines 176-178
#[serde(default, skip_serializing_if = "Option::is_none")]
pub agent: Option<AgentInfo>,
```

All new optional fields in `EvaluateRequest`, `AbacContext`, `AuditEvent`, and both `ClipboardAlert` structs MUST use this exact pair of attributes.

### Pattern 3: Named re-exports in lib.rs (no wildcard for endpoint)

`lib.rs` currently uses `pub use abac::*` and `pub use audit::*` (wildcard). Decision D-01 specifies named re-exports for `endpoint`. This follows the explicit style already used for `ad_client` and `classifier`:

```rust
// Source: dlp-common/src/lib.rs (existing pattern for ad_client)
pub use ad_client::{get_device_trust, get_network_location, AdClient, AdClientError, LdapConfig};

// New additions for endpoint (named, explicit)
pub mod endpoint;
pub use endpoint::{AppIdentity, AppTrustTier, DeviceIdentity, SignatureState, UsbTrustTier};
```

Downstream crates that need these types will import via `dlp_common::AppIdentity` (if using the wildcard `pub use abac::*` — but they won't for endpoint because it's named). Crates like `dlp-admin-cli` that already use `dlp_common::abac::PolicyMode` syntax may need `dlp_common::endpoint::AppIdentity` or `dlp_common::AppIdentity` depending on import style.

**Important:** `dlp-agent` uses `pub mod prelude { pub use dlp_common::*; }` — this will automatically re-export all named `pub use` entries from `dlp_common`, so `AppIdentity` will be available as `crate::prelude::AppIdentity` in `dlp-agent` after the re-export is added to `lib.rs`. [VERIFIED: dlp-agent/src/lib.rs line 27]

### Pattern 4: AbacContext (defined-but-unused in Phase 22)

`AbacContext` must compile but is not wired into `PolicyStore::evaluate()` until Phase 26. The `#[allow(dead_code)]` attribute must NOT be applied — it must be pub so downstream can reference it. Define it as a full public struct with proper doc comments and derive traits:

```rust
/// Internal ABAC evaluation context.
///
/// Constructed from [`EvaluateRequest`] at the evaluate boundary in Phase 26.
/// Fields mirror `EvaluateRequest` minus wire-only metadata (no `agent` field).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AbacContext {
    pub subject: Subject,
    pub resource: Resource,
    pub environment: Environment,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_application: Option<AppIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_application: Option<AppIdentity>,
}
```

Because `AbacContext` will be in `abac.rs` but `AppIdentity` will be in `endpoint.rs`, `abac.rs` needs `use crate::endpoint::AppIdentity;` (or use `super::endpoint::AppIdentity` — same thing from inside the module). The `AppIdentity` type is defined in the same crate, so no new Cargo dependency is needed. [VERIFIED: Rust module system behavior]

### Pattern 5: AuditEvent builder extension

The AuditEvent builder pattern adds individual `with_*()` methods that take ownership and return `Self`. New fields follow the same pattern:

```rust
// Source: dlp-common/src/audit.rs (with_application method as example)
pub fn with_source_application(mut self, app: Option<AppIdentity>) -> Self {
    self.source_application = app;
    self
}

pub fn with_destination_application(mut self, app: Option<AppIdentity>) -> Self {
    self.destination_application = app;
    self
}

pub fn with_device_identity(mut self, device: Option<DeviceIdentity>) -> Self {
    self.device_identity = device;
    self
}
```

The `AuditEvent::new()` constructor must also initialize these three new fields to `None` to maintain the exhaustive struct initialization invariant. [VERIFIED: audit.rs lines 183-207]

### Anti-Patterns to Avoid

- **Wildcard re-export for endpoint:** D-01 specifies named re-exports. `pub use endpoint::*` would expose all types but violates the "explicit public API surface" constraint.
- **Adding `#[allow(dead_code)]` to `AbacContext`:** `AbacContext` is public; use it in a test or doc-test to prevent dead_code lint. A unit test in `abac.rs` that constructs `AbacContext::default()` satisfies this.
- **Applying `#[serde(default)]` at struct level only without per-field `skip_serializing_if`:** The existing pattern applies `#[serde(default)]` at struct level AND `#[serde(skip_serializing_if = "Option::is_none")]` on each optional field individually. Struct-level `skip_serializing_if` does not exist in serde.
- **Making `UsbTrustTier` serialize as PascalCase:** Would break Phase 24 DB CHECK constraint `"blocked"`, `"read_only"`, `"full_access"`. Must use `rename_all = "snake_case"`.
- **Forgetting to update `AuditEvent::new()` initializer:** Rust requires exhaustive struct initialization. Adding fields to `AuditEvent` without adding them to the `Self { ... }` block in `new()` will fail to compile — this is the build break detection mechanism.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Enum serialization to snake_case | Custom `Serialize` impl | `#[serde(rename_all = "snake_case")]` | serde derive handles all variants automatically; custom impls break on new variants |
| Optional field skip-on-none | Manual `if let Some` in serialize | `#[serde(skip_serializing_if = "Option::is_none")]` | Declarative, zero-cost, consistent with existing codebase |
| Default variant for enums | Explicit `impl Default` | `#[derive(Default)]` + `#[default]` on variant | Rust 1.62+ supports `#[default]` derive; matches existing project patterns |

**Key insight:** This is a type-definition phase. All "logic" lives in serde derive attributes. The entire implementation is declarations and derive macros.

---

## Common Pitfalls

### Pitfall 1: AbacContext dead_code warning

**What goes wrong:** `AbacContext` is defined but not referenced in any `use` statement or function in Phase 22. Rust emits a `dead_code` warning for unused public items in library crates if they are only declared but never referenced within the crate itself.

**Why it happens:** Library crates warn on dead code differently from binary crates. A `pub struct` with no internal usages in the library produces `unused` or `dead_code` warnings.

**How to avoid:** Add a unit test in `abac.rs` that constructs `AbacContext::default()` and asserts it has no application fields. This serves as both dead-code suppression and a regression test. Alternatively, reference `AbacContext` in a doc-comment example.

**Warning signs:** `warning: struct is never constructed: AbacContext`

### Pitfall 2: Cross-module type reference in abac.rs

**What goes wrong:** `abac.rs` needs to reference `AppIdentity` (defined in `endpoint.rs`) without a circular dependency.

**Why it happens:** `abac.rs` and `endpoint.rs` are sibling modules under `lib.rs`. From `abac.rs`, the correct import is `use crate::endpoint::AppIdentity;` — NOT `use super::AppIdentity` (which would look in `lib.rs`).

**How to avoid:** Use `use crate::endpoint::AppIdentity;` at the top of `abac.rs`. The same pattern is already used: `abac.rs` references `crate::Classification` on line 137. [VERIFIED: abac.rs line 137]

**Warning signs:** `error[E0432]: unresolved import` or `error[E0412]: cannot find type AppIdentity in this scope`

### Pitfall 3: Forgetting to mirror IPC changes in both files

**What goes wrong:** `dlp-agent/src/ipc/messages.rs` is updated but `dlp-user-ui/src/ipc/messages.rs` is not (or vice versa). The IPC protocol breaks silently at runtime — the agent sends a JSON payload with new fields, the UI deserializes fine (due to `#[serde(default)]`), but the UI side never populates the fields because its struct definition is stale.

**Why it happens:** Files are intentionally duplicated per D-14. There is no compile-time enforcement of their equivalence.

**How to avoid:** Update both files in the same task. The `Pipe3UiMsg::ClipboardAlert` struct definition must be byte-for-byte identical in both files (field names, types, serde attributes).

**Warning signs:** No compile error — only runtime behavior divergence. Tests that check IPC roundtrip behavior would catch this.

### Pitfall 4: AuditEvent::new() exhaustive struct init

**What goes wrong:** Adding three new fields (`source_application`, `destination_application`, `device_identity`) to `AuditEvent` but forgetting to add them to the `Self { ... }` block in `new()`.

**Why it happens:** Rust struct initialization is exhaustive. This will always be caught at compile time as `error[E0063]: missing field`.

**How to avoid:** Initialize all three to `None` in `AuditEvent::new()`. This is the compile-time verification mechanism — if `new()` doesn't compile, the fields were missed.

### Pitfall 5: Existing AuditEvent tests failing on skip_serializing_if assertion

**What goes wrong:** `test_skip_serializing_none_fields()` in `audit.rs` already asserts that `None` optional fields don't appear in JSON output. The new fields must also pass this test — they must not serialize as `"source_application":null`.

**Why it happens:** Forgetting to add `#[serde(skip_serializing_if = "Option::is_none")]` to each new field. `#[serde(default)]` at struct level only controls deserialization, not serialization.

**How to avoid:** Apply both `#[serde(default)]` and `#[serde(skip_serializing_if = "Option::is_none")]` per-field on each new `Option<T>` field.

---

## Code Examples

Verified patterns from existing codebase:

### Complete endpoint.rs structure

```rust
// Source: derived from abac.rs + audit.rs patterns; serde conventions from classification.rs
use serde::{Deserialize, Serialize};

/// The Authenticode signature verification result for a process image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignatureState {
    /// Authenticode signature is cryptographically valid.
    Valid,
    /// Authenticode signature is present but invalid (tampered or expired).
    Invalid,
    /// No Authenticode signature present.
    NotSigned,
    /// Signature state could not be determined.
    #[default]
    Unknown,
}

/// Application trust tier — distinct from USB trust tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AppTrustTier {
    Trusted,
    Untrusted,
    #[default]
    Unknown,
}

/// USB device trust tier — serializes as DB CHECK constraint values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UsbTrustTier {
    /// All I/O to this device is denied.
    #[default]
    Blocked,
    /// Reads allowed; writes denied.
    ReadOnly,
    /// Full read/write access.
    FullAccess,
}

/// Resolved application identity for a running process.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AppIdentity {
    pub image_path: String,
    pub publisher: String,
    pub trust_tier: AppTrustTier,
    pub signature_state: SignatureState,
}

/// Captured USB device identity from SetupDi APIs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DeviceIdentity {
    pub vid: String,
    pub pid: String,
    pub serial: String,
    pub description: String,
}
```

### lib.rs additions

```rust
// Source: dlp-common/src/lib.rs — follow named re-export pattern from ad_client
pub mod endpoint;
pub use endpoint::{AppIdentity, AppTrustTier, DeviceIdentity, SignatureState, UsbTrustTier};
```

### EvaluateRequest extension (abac.rs)

```rust
// Source: existing agent: Option<AgentInfo> field at abac.rs lines 176-178
use crate::endpoint::AppIdentity;

// Inside EvaluateRequest struct:
#[serde(default, skip_serializing_if = "Option::is_none")]
pub source_application: Option<AppIdentity>,
#[serde(default, skip_serializing_if = "Option::is_none")]
pub destination_application: Option<AppIdentity>,
```

### UsbTrustTier serde verification (unit test)

```rust
#[test]
fn test_usb_trust_tier_serde_values() {
    // DB CHECK constraint requires exact lowercase_snake values (REQUIREMENTS.md USB-02)
    assert_eq!(serde_json::to_string(&UsbTrustTier::Blocked).unwrap(), "\"blocked\"");
    assert_eq!(serde_json::to_string(&UsbTrustTier::ReadOnly).unwrap(), "\"read_only\"");
    assert_eq!(serde_json::to_string(&UsbTrustTier::FullAccess).unwrap(), "\"full_access\"");
}
```

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in (`#[test]`) |
| Config file | none — `cargo test` discovers tests via `#[cfg(test)]` modules |
| Quick run command | `cargo test -p dlp-common -- --nocapture` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map

Phase 22 is infrastructure (no single REQ-ID). Tests verify the five success criteria from ROADMAP.md:

| Success Criterion | Test Type | Automated Command | Test Location |
|-------------------|-----------|-------------------|--------------|
| SC-1: AppIdentity compiles in all five crates | compile-time | `cargo build --workspace` | N/A |
| SC-2: DeviceIdentity + UsbTrustTier serializable | unit | `cargo test -p dlp-common` | `dlp-common/src/endpoint.rs` `#[cfg(test)]` |
| SC-3: AbacContext carries app identity fields with `#[serde(default)]` | unit | `cargo test -p dlp-common` | `dlp-common/src/abac.rs` `#[cfg(test)]` |
| SC-4: AuditEvent backward-compat (old JSON deserializes without error) | unit | `cargo test -p dlp-common` | `dlp-common/src/audit.rs` `#[cfg(test)]` |
| SC-5: IPC ClipboardAlert compiles + workspace zero warnings | compile-time | `cargo build --workspace 2>&1 \| grep -c warning` | N/A |

### Required Tests to Add

All tests go inside `#[cfg(test)]` modules in the respective source files:

**In `dlp-common/src/endpoint.rs`:**

1. `test_usb_trust_tier_serde_values` — asserts `"blocked"`, `"read_only"`, `"full_access"` exact strings
2. `test_usb_trust_tier_default_is_blocked` — asserts `UsbTrustTier::default() == UsbTrustTier::Blocked`
3. `test_app_trust_tier_default_is_unknown` — asserts `AppTrustTier::default() == AppTrustTier::Unknown`
4. `test_signature_state_default_is_unknown` — asserts `SignatureState::default() == SignatureState::Unknown`
5. `test_app_identity_serde_round_trip` — constructs `AppIdentity`, serializes, deserializes, asserts equality
6. `test_device_identity_serde_round_trip` — same for `DeviceIdentity`
7. `test_app_identity_none_skipped` — verifies `Option<AppIdentity>::None` is omitted from JSON output when used inside a struct with `skip_serializing_if`

**In `dlp-common/src/abac.rs` (additions to existing tests):**

8. `test_abac_context_default` — constructs `AbacContext::default()`, asserts `source_application.is_none()`
9. `test_evaluate_request_app_identity_fields` — verifies new `EvaluateRequest` fields round-trip through serde; verifies `None` fields are absent from JSON
10. `test_evaluate_request_backward_compat` — deserializes a JSON string WITHOUT `source_application` / `destination_application` fields and asserts it succeeds (no `unknown field` error)

**In `dlp-common/src/audit.rs` (additions to existing tests):**

11. `test_audit_event_app_identity_fields` — constructs AuditEvent with `with_source_application()`, asserts fields serialize; asserts `None` fields skip
12. `test_audit_event_backward_compat` — deserializes old AuditEvent JSON (no app/device fields), asserts `source_application.is_none()`

### Sampling Rate

- **Per task commit:** `cargo test -p dlp-common`
- **Phase gate:** `cargo build --workspace` with zero warnings (`cargo build --workspace 2>&1 | grep -v "^$" | grep -E "^warning" | wc -l` must output `0`)

### Wave 0 Gaps

None. `dlp-common` already has a `#[cfg(test)]` module in every source file and `cargo test` discovers them automatically. No new test infrastructure files needed.

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | no | — |
| V5 Input Validation | no | Pure type definitions; no input parsing in Phase 22 |
| V6 Cryptography | no | — |

**Security note:** `SignatureState` encodes the Authenticode result — the `Unknown` default (D-05) is safe because callers in Phase 25/26 will treat `Unknown` as untrusted for enforcement decisions. The default-most-restrictive principle applies to `UsbTrustTier::Blocked` (D-07). Both align with CLAUDE.md's Default Deny principle.

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| All types in `abac.rs` | Domain-split: `abac.rs` (policy), `endpoint.rs` (identity) | Phase 22 | Cleaner module boundaries; `abac.rs` stays policy-only |
| `EvaluateRequest` carries all context | `EvaluateRequest` (wire) + `AbacContext` (internal) two-type split | Phase 22 (AbacContext defined) / Phase 26 (wired) | Wire format remains stable; evaluation boundary gains type-safe internal context |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `pub use endpoint::{...}` naming makes types available as `dlp_common::AppIdentity` to all downstream crates | Standard Stack | If wrong, downstream crates need `dlp_common::endpoint::AppIdentity` — minor import path adjustment only |
| A2 | `dlp-agent`'s `pub use dlp_common::*` prelude automatically picks up the new `pub use endpoint::*` exports | Architecture Patterns | If wrong, `dlp-agent/src/ipc/messages.rs` must add an explicit `use dlp_common::AppIdentity` import |

Both assumptions are LOW-risk and verifiable immediately at `cargo build --workspace` time.

---

## Open Questions

1. **`PartialOrd` on `UsbTrustTier`**
   - What we know: D-07 doesn't require it; Phase 26 USB enforcement uses exact tier matching (`== Blocked`), not range comparisons.
   - What's unclear: Phase 26 might benefit from `tier >= ReadOnly` range expressions.
   - Recommendation: Add `PartialOrd` now. It costs nothing (copyable enum with 3 variants), and the ordering is unambiguous: `Blocked < ReadOnly < FullAccess`. Derive `PartialOrd, Ord` alongside the existing derives. This is Claude's discretion per the locked decisions.

2. **`AppIdentity` builder methods**
   - What we know: Not required by success criteria; Phase 25 will be the first consumer.
   - Recommendation: Omit in Phase 22. Phase 25 will know what construction patterns it needs. Adding premature builders risks dead_code warnings before Phase 25 uses them.

---

## Environment Availability

Step 2.6: SKIPPED — Phase 22 is purely code changes within an existing Rust workspace. No external tools, services, or databases are required. Verified: workspace compiles cleanly as of 2026-04-22 (`cargo check --workspace` succeeded in 18.52s).

---

## Sources

### Primary (HIGH confidence)
- `[VERIFIED: codebase]` `dlp-common/src/abac.rs` — existing serde patterns for `EvaluateRequest`, `PolicyCondition`, `AgentInfo`, enum serialization
- `[VERIFIED: codebase]` `dlp-common/src/audit.rs` — builder pattern for `AuditEvent`; `skip_serializing_if` per-field convention
- `[VERIFIED: codebase]` `dlp-common/src/lib.rs` — named vs wildcard re-export distinction
- `[VERIFIED: codebase]` `dlp-agent/src/ipc/messages.rs` and `dlp-user-ui/src/ipc/messages.rs` — current `ClipboardAlert` struct definition
- `[VERIFIED: codebase]` `dlp-common/Cargo.toml` — no new dependencies needed
- `[VERIFIED: cargo check]` Workspace compiles cleanly before Phase 22 changes

### Secondary (MEDIUM confidence)
- `[CITED: REQUIREMENTS.md USB-02]` — `blocked`, `read_only`, `full_access` as DB CHECK constraint values for `UsbTrustTier`
- `[CITED: .planning/phases/22-dlp-common-foundation/22-CONTEXT.md]` — all 17 locked decisions

---

## Metadata

**Confidence breakdown:**
- Type definitions: HIGH — all patterns are directly present in codebase; no new dependencies
- serde conventions: HIGH — verified against existing code with identical requirements
- Compilation impact: HIGH — `cargo check --workspace` confirmed current baseline; changes are additive only
- Test strategy: HIGH — follows established `#[cfg(test)]` module pattern used in every dlp-common file

**Research date:** 2026-04-22
**Valid until:** 2026-05-22 (stable — no moving targets; all decisions are locked)
