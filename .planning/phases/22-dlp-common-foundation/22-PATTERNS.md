# Phase 22: dlp-common Foundation - Pattern Map

**Mapped:** 2026-04-22
**Files analyzed:** 6 (1 new, 5 modified)
**Analogs found:** 6 / 6

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-common/src/endpoint.rs` | model | transform | `dlp-common/src/classification.rs` | exact — enum + struct type-definition module with serde derive |
| `dlp-common/src/lib.rs` | config | — | `dlp-common/src/lib.rs` (self) | self — add `pub mod` + named `pub use` |
| `dlp-common/src/abac.rs` | model | request-response | `dlp-common/src/abac.rs` (self) | self — extend EvaluateRequest, add AbacContext |
| `dlp-common/src/audit.rs` | model | event-driven | `dlp-common/src/audit.rs` (self) | self — extend AuditEvent struct + builder methods |
| `dlp-agent/src/ipc/messages.rs` | model | request-response | `dlp-agent/src/ipc/messages.rs` (self) | self — extend Pipe3UiMsg::ClipboardAlert variant |
| `dlp-user-ui/src/ipc/messages.rs` | model | request-response | `dlp-user-ui/src/ipc/messages.rs` (self) | self — mirror identical change to agent-side file |

---

## Pattern Assignments

### `dlp-common/src/endpoint.rs` (model, transform) — NEW FILE

**Analog:** `dlp-common/src/classification.rs` (enum with serde derive, Default, PartialOrd) and `dlp-common/src/abac.rs` (struct with serde default, doc comments, cfg(test) module)

**Imports pattern** (`classification.rs` lines 10, `abac.rs` line 6):
```rust
use serde::{Deserialize, Serialize};
```
No additional imports needed — all types are primitive or defined in this file.

**Enum with rename_all + #[default] on variant** (`classification.rs` lines 16-28):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum Classification {
    #[default]
    T1,
    T2,
    T3,
    T4,
}
```
Adapt for `UsbTrustTier` with `rename_all = "snake_case"` and `#[default]` on `Blocked`. Adapt for `AppTrustTier` and `SignatureState` similarly (snake_case serialization, `#[default]` on `Unknown` variant).

**Enum with lowercase serde serialization** (`abac.rs` lines 38-46):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AccessContext {
    #[default]
    Local,
    Smb,
}
```
`UsbTrustTier` uses `snake_case` instead of `lowercase` because `ReadOnly` must serialize as `"read_only"` (not `"readonly"`). Use `#[serde(rename_all = "snake_case")]`.

**Struct with serde default + doc comment** (`abac.rs` lines 156-164):
```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentInfo {
    /// Machine hostname, e.g. "WORKSTATION-01".
    pub machine_name: Option<String>,
    /// The Windows username of the interactive session that triggered the request,
    /// e.g. "jsmith".
    pub current_user: Option<String>,
}
```
`AppIdentity` and `DeviceIdentity` follow this exact struct-level `#[serde(default)]` pattern. Fields are non-optional `String` inside the struct (unlike `AgentInfo`). Derive `Default` so the struct compiles with `EvaluateRequest::default()`.

**Test module structure** (`classification.rs` lines 57-107):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classification_order() { ... }

    #[test]
    fn test_serde_round_trip() {
        for cls in [Classification::T1, Classification::T2, ...] {
            let json = serde_json::to_string(&cls).unwrap();
            let round_trip: Classification = serde_json::from_str(&json).unwrap();
            assert_eq!(cls, round_trip);
        }
    }

    #[test]
    fn test_default_is_t1() {
        assert_eq!(Classification::default(), Classification::T1);
    }
}
```
Mirror this structure for `endpoint.rs` tests: one `test_*_default` per enum, one `test_*_serde_round_trip` per type, plus `test_usb_trust_tier_serde_values` with exact string assertions.

---

### `dlp-common/src/lib.rs` (config) — MODIFY

**Analog:** `dlp-common/src/lib.rs` lines 1-18 (self — current file)

**Current state** (lines 7-18):
```rust
pub mod abac;
pub mod ad_client;
pub mod audit;
pub mod classification;
pub mod classifier;

pub use abac::*;
pub use ad_client::{get_device_trust, get_network_location, AdClient, AdClientError, LdapConfig};
pub use audit::*;
pub use classification::*;
pub use classifier::classify_text;
```

**Addition pattern — named re-export** (`lib.rs` line 14, ad_client style):
```rust
pub use ad_client::{get_device_trust, get_network_location, AdClient, AdClientError, LdapConfig};
```
This is the exact model for the `endpoint` addition. Insert before the `pub use abac::*` line:
```rust
pub mod endpoint;
pub use endpoint::{AppIdentity, AppTrustTier, DeviceIdentity, SignatureState, UsbTrustTier};
```
Do NOT use `pub use endpoint::*` — Decision D-01 requires named re-exports for `endpoint` to keep the public API surface explicit. The `abac::*` and `audit::*` wildcards are pre-existing and not changed.

---

### `dlp-common/src/abac.rs` (model, request-response) — MODIFY

**Analog:** `dlp-common/src/abac.rs` lines 156-178 (self — AgentInfo + EvaluateRequest as structural pattern)

**Target 1: Add import for AppIdentity** (insert after line 6, before existing types):
```rust
use crate::endpoint::AppIdentity;
```
Precedent: `abac.rs` line 137 already references `crate::Classification` inside `Resource`, confirming that sibling-module cross-references use `crate::` prefix, not `super::`.

**Target 2: Extend `EvaluateRequest`** — existing optional field pattern (lines 174-178):
```rust
pub struct EvaluateRequest {
    pub subject: Subject,
    pub resource: Resource,
    pub environment: Environment,
    pub action: Action,
    /// Agent endpoint identity — machine name and interactive user.
    /// Logged by the Policy Engine for request tracing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentInfo>,
}
```
Append two new fields after `agent`, using the identical `#[serde(default, skip_serializing_if = "Option::is_none")]` attribute pair on each:
```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_application: Option<AppIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_application: Option<AppIdentity>,
```

**Target 3: New `AbacContext` struct** — modeled on `EvaluateRequest` (lines 167-178) but without `agent` field (Decision D-10):
```rust
/// Internal ABAC evaluation context.
///
/// Constructed from [`EvaluateRequest`] at the evaluate boundary (Phase 26).
/// Mirrors `EvaluateRequest` minus wire-only metadata (no `agent` field).
/// Defined here in Phase 22 so downstream crates can compile against the type
/// before Phase 26 wires it into [`PolicyStore::evaluate`].
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
Add a test `test_abac_context_default` in the existing `#[cfg(test)]` block (lines 289-367) to prevent dead_code warning:
```rust
#[test]
fn test_abac_context_default() {
    let ctx = AbacContext::default();
    assert!(ctx.source_application.is_none());
    assert!(ctx.destination_application.is_none());
}
```

**Test additions** — follow existing test structure (`abac.rs` lines 289-367, `#[cfg(test)] mod tests { use super::*; }`):
- `test_abac_context_default` — constructs `AbacContext::default()`, asserts both app fields are `None`
- `test_evaluate_request_app_identity_fields` — round-trip through serde with populated `AppIdentity`; assert `None` fields absent from JSON
- `test_evaluate_request_backward_compat` — deserialize JSON without the new fields; assert succeeds and fields are `None`

---

### `dlp-common/src/audit.rs` (model, event-driven) — MODIFY

**Analog:** `dlp-common/src/audit.rs` lines 99-260 (self — AuditEvent struct + builder methods)

**Import addition** (after line 19 `use uuid::Uuid;`):
```rust
use crate::endpoint::{AppIdentity, DeviceIdentity};
```

**Target 1: Extend `AuditEvent` struct** — follow the existing optional-field pattern (lines 117-155). Each new optional field uses `#[serde(skip_serializing_if = "Option::is_none")]` (no `#[serde(default)]` needed on field because `AuditEvent` does not derive `Default` at struct level — it uses an explicit `new()` constructor):
```rust
    /// Resolved identity of the application that initiated the operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_application: Option<AppIdentity>,
    /// Resolved identity of the destination application (e.g., paste target).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_application: Option<AppIdentity>,
    /// USB device identity for block events involving removable storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_identity: Option<DeviceIdentity>,
```
Add these three fields to the `AuditEvent` struct definition after `resource_owner` (line 155).

**Target 2: Extend `AuditEvent::new()` initializer** (lines 183-207) — Rust requires exhaustive struct init. Add all three new fields to the `Self { ... }` block:
```rust
        source_application: None,
        destination_application: None,
        device_identity: None,
```

**Target 3: New builder methods** — follow the existing pattern (`with_policy` lines 210-213, `with_application` lines 246-254):
```rust
/// Sets the source application identity.
pub fn with_source_application(mut self, app: Option<AppIdentity>) -> Self {
    self.source_application = app;
    self
}

/// Sets the destination application identity.
pub fn with_destination_application(mut self, app: Option<AppIdentity>) -> Self {
    self.destination_application = app;
    self
}

/// Sets the USB device identity for block events.
pub fn with_device_identity(mut self, device: Option<DeviceIdentity>) -> Self {
    self.device_identity = device;
    self
}
```

**Existing test to extend** — `test_skip_serializing_none_fields` (lines 344-364) already asserts `None` fields are absent. Add assertions for the three new fields:
```rust
assert!(!json.contains("\"source_application\":null"));
assert!(!json.contains("\"destination_application\":null"));
assert!(!json.contains("\"device_identity\":null"));
```

**New tests** to add to the existing `#[cfg(test)]` block (lines 263-392):
- `test_audit_event_app_identity_fields` — build event with `with_source_application(Some(...))`, assert serialized JSON contains `"source_application"`, assert `destination_application` absent
- `test_audit_event_backward_compat` — deserialize JSON string without the three new fields; assert succeeds and all three fields are `None`

---

### `dlp-agent/src/ipc/messages.rs` (model, request-response) — MODIFY

**Analog:** `dlp-agent/src/ipc/messages.rs` lines 86-106 (self — `Pipe3UiMsg` enum and `ClipboardAlert` variant)

**Import addition** (after line 7 `use serde::{Deserialize, Serialize};`):
```rust
use dlp_common::AppIdentity;
```
Verify that `dlp-agent` re-exports `AppIdentity` via its prelude. Per RESEARCH.md §Pattern 3, `dlp-agent/src/lib.rs` line 27 has `pub use dlp_common::*;` which will pick up the new `pub use endpoint::{AppIdentity, ...}` re-export from `dlp-common/src/lib.rs`. Alternatively use `dlp_common::endpoint::AppIdentity` if the top-level re-export is not confirmed at compile time.

**Target: Extend `ClipboardAlert` variant** (lines 96-105) — current struct:
```rust
    ClipboardAlert {
        /// Session ID where the paste occurred.
        session_id: u32,
        /// Classification tier of the pasted content.
        classification: String,
        /// Truncated preview of the pasted text.
        preview: String,
        /// Total length of the pasted text.
        text_length: usize,
    },
```
Add two new fields after `text_length`, using `#[serde(default)]` (Decision D-15 — no `skip_serializing_if` required here, but add it for consistency with the codebase pattern):
```rust
        /// Identity of the application that initiated the clipboard paste.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_application: Option<AppIdentity>,
        /// Identity of the application that is the paste destination.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        destination_application: Option<AppIdentity>,
```
Note: Fields inside enum variants are named struct fields — the `#[serde]` attribute goes on the field, which is valid Rust for named-field enum variants.

---

### `dlp-user-ui/src/ipc/messages.rs` (model, request-response) — MODIFY

**Analog:** `dlp-user-ui/src/ipc/messages.rs` lines 83-101 (self — must mirror agent-side file byte-for-byte on the `ClipboardAlert` variant)

**Identical change as `dlp-agent/src/ipc/messages.rs`.** The `dlp-user-ui` copy currently has `#[allow(dead_code)]` on `Pipe3UiMsg` (line 86). Do NOT remove that attribute — it is needed because the UI-side enum variants are not all used in the UI codebase yet.

**Import addition** (after line 7):
```rust
use dlp_common::AppIdentity;
```

**Target: Extend `ClipboardAlert` variant** (lines 95-100) — add the same two fields in the same order with the same serde attributes as the agent-side file:
```rust
    ClipboardAlert {
        session_id: u32,
        classification: String,
        preview: String,
        text_length: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_application: Option<AppIdentity>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        destination_application: Option<AppIdentity>,
    },
```

**Critical constraint (Decision D-14 + Pitfall 3):** The `ClipboardAlert` struct definition must be byte-for-byte identical across both files (field names, types, serde attributes, field order). No compile-time enforcement exists — divergence causes silent runtime protocol mismatch.

---

## Shared Patterns

### Serde optional field — skip on None
**Source:** `dlp-common/src/abac.rs` lines 176-177 and `dlp-common/src/audit.rs` lines 117-155
**Apply to:** All new `Option<T>` fields in `EvaluateRequest`, `AbacContext`, `AuditEvent`, and both `ClipboardAlert` variants

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub field_name: Option<SomeType>,
```

The two attributes serve different roles:
- `#[serde(default)]` — deserialization: missing JSON key → `None` (backward-compat)
- `#[serde(skip_serializing_if = "Option::is_none")]` — serialization: `None` value → key omitted from JSON output

Both must appear together on every new optional field.

### Enum serde with named variants
**Source:** `dlp-common/src/abac.rs` lines 38-46 (AccessContext, `rename_all = "lowercase"`) and `dlp-common/src/classification.rs` lines 16-28 (`rename_all = "UPPERCASE"`)
**Apply to:** `UsbTrustTier`, `AppTrustTier`, `SignatureState` in `endpoint.rs`

```rust
// Pattern: rename_all controls ALL variant serialization automatically
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]  // use "snake_case" for DB CHECK constraint compatibility
pub enum EnumName {
    #[default]          // Rust 1.62+ — marks the Default variant
    DefaultVariant,
    OtherVariant,
}
```

`UsbTrustTier` must use `snake_case` (not `lowercase`) because `ReadOnly` -> `"read_only"` requires the underscore insertion that only `snake_case` provides.

### Struct-level serde default
**Source:** `dlp-common/src/abac.rs` lines 156-164 (AgentInfo), lines 167-178 (EvaluateRequest)
**Apply to:** `AppIdentity`, `DeviceIdentity` (new structs), `AbacContext` (new struct)

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]   // struct-level: all fields get serde default on deserialization
pub struct StructName {
    pub field: String,
}
```

`#[serde(default)]` at the struct level means every field with a missing JSON key uses its own `Default` impl. `String::default()` is `""`, which is appropriate for `AppIdentity` and `DeviceIdentity` fields.

### Builder method pattern (consume-and-return)
**Source:** `dlp-common/src/audit.rs` lines 210-260 (`with_policy`, `with_application`, `with_resource_owner`)
**Apply to:** Three new `with_*` methods on `AuditEvent`

```rust
/// Sets the <field description>.
pub fn with_field_name(mut self, value: Option<SomeType>) -> Self {
    self.field_name = value;
    self
}
```

Take ownership (`mut self`), mutate, return `Self`. Callers chain: `.with_source_application(Some(identity)).with_device_identity(None)`.

### Cross-module type reference (sibling modules)
**Source:** `dlp-common/src/abac.rs` line 137 (`crate::Classification` in Resource struct)
**Apply to:** `use crate::endpoint::AppIdentity;` in `abac.rs` and `audit.rs`

```rust
// In abac.rs or audit.rs — reference type from sibling endpoint module:
use crate::endpoint::AppIdentity;
use crate::endpoint::DeviceIdentity;  // audit.rs only
```

Do NOT use `super::AppIdentity` (that would look in `lib.rs` scope, not `endpoint` module).

### Named pub use re-export in lib.rs
**Source:** `dlp-common/src/lib.rs` line 14
**Apply to:** `endpoint` module re-export

```rust
// Current named re-export pattern (ad_client):
pub use ad_client::{get_device_trust, get_network_location, AdClient, AdClientError, LdapConfig};

// New endpoint re-export follows same style:
pub mod endpoint;
pub use endpoint::{AppIdentity, AppTrustTier, DeviceIdentity, SignatureState, UsbTrustTier};
```

`pub mod endpoint;` must appear in the `pub mod` block. `pub use endpoint::{...}` must list all five types explicitly — no wildcard.

### Test module boilerplate
**Source:** `dlp-common/src/abac.rs` lines 289-291 and `dlp-common/src/classification.rs` lines 57-59
**Apply to:** `#[cfg(test)]` module in new `endpoint.rs` and additions to `abac.rs` / `audit.rs` test modules

```rust
#[cfg(test)]
mod tests {
    use super::*;   // wildcard import allowed in test modules per CLAUDE.md §9.9

    #[test]
    fn test_name() {
        // Arrange-Act-Assert pattern
    }
}
```

---

## No Analog Found

All six files have close analogs within the codebase. No files require falling back to RESEARCH.md patterns exclusively.

---

## Metadata

**Analog search scope:** `dlp-common/src/`, `dlp-agent/src/ipc/`, `dlp-user-ui/src/ipc/`
**Files read:** 7 (`abac.rs`, `audit.rs`, `lib.rs`, `classification.rs`, `dlp-agent/src/ipc/messages.rs`, `dlp-user-ui/src/ipc/messages.rs`, both CONTEXT.md and RESEARCH.md)
**Pattern extraction date:** 2026-04-22
