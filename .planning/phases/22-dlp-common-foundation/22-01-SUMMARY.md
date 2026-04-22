---
phase: 22-dlp-common-foundation
plan: "01"
subsystem: dlp-common
tags:
  - rust
  - dlp-common
  - serde
  - types
  - foundation
dependency_graph:
  requires: []
  provides:
    - dlp-common::AppIdentity
    - dlp-common::AppTrustTier
    - dlp-common::DeviceIdentity
    - dlp-common::SignatureState
    - dlp-common::UsbTrustTier
  affects:
    - dlp-agent (Phase 25 — AppIdentity consumer)
    - dlp-user-ui (Phase 25 — AppIdentity consumer)
    - dlp-server (Phase 24 — DeviceIdentity + UsbTrustTier consumer)
    - dlp-common Plan 02 (Phase 22 — EvaluateRequest extension)
    - dlp-common Plan 03 (Phase 22 — AuditEvent extension)
tech_stack:
  added: []
  patterns:
    - serde rename_all snake_case enum (matching existing abac.rs AccessContext pattern)
    - struct-level serde(default) for safe deserialization of partial JSON (matching abac.rs AgentInfo pattern)
    - PartialOrd/Ord derived on enums for enforcement tier comparisons
key_files:
  created:
    - dlp-common/src/endpoint.rs
  modified:
    - dlp-common/src/lib.rs
decisions:
  - "PartialOrd/Ord derived on UsbTrustTier and AppTrustTier: zero-cost at Phase 22, enables tier >= ReadOnly comparisons in Phase 26 enforcement"
  - "AppIdentity builder methods omitted: Phase 25 is first consumer; premature builders cause dead_code warnings in this phase"
  - "DeviceIdentity constructor convenience method omitted: Phase 23 will decide if helpers are needed"
  - "Named re-export (not wildcard) for endpoint types per D-01 convention: explicit API surface"
metrics:
  duration: "~35 minutes"
  completed: "2026-04-22"
  tasks_completed: 2
  tasks_total: 2
  files_created: 1
  files_modified: 1
  tests_added: 13
requirements:
  - PHASE-22-INFRA
---

# Phase 22 Plan 01: Endpoint Identity Foundation Types Summary

**One-liner:** Five endpoint-identity types (AppIdentity, DeviceIdentity, UsbTrustTier, AppTrustTier, SignatureState) with serde snake_case wire format and Default Deny defaults, unblocking all v0.6.0 enforcement tracks.

## What Was Built

New file `dlp-common/src/endpoint.rs` introduces the five shared types that all of v0.6.0 depends on:

| Type | Kind | Default | Wire format |
|------|------|---------|-------------|
| `UsbTrustTier` | enum (3 variants) | `Blocked` | `"blocked"`, `"read_only"`, `"full_access"` |
| `AppTrustTier` | enum (3 variants) | `Unknown` | `"trusted"`, `"untrusted"`, `"unknown"` |
| `SignatureState` | enum (4 variants) | `Unknown` | `"valid"`, `"invalid"`, `"not_signed"`, `"unknown"` |
| `AppIdentity` | struct (4 fields) | all-default | serde(default) at struct level |
| `DeviceIdentity` | struct (4 fields) | empty strings | serde(default) at struct level |

`dlp-common/src/lib.rs` updated with `pub mod endpoint;` and named re-export:
```
pub use endpoint::{AppIdentity, AppTrustTier, DeviceIdentity, SignatureState, UsbTrustTier};
```

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create dlp-common/src/endpoint.rs with five types and unit tests | 7dd2d04 | dlp-common/src/endpoint.rs (new, 248 lines) |
| 2 | Expose endpoint module via named re-exports in lib.rs | f2a8a35 | dlp-common/src/lib.rs (+3 lines) |

## Verification Results

- `cargo test -p dlp-common --lib endpoint::` — 13/13 tests pass
- `cargo test -p dlp-common --lib` — 53/53 tests pass (all existing tests preserved)
- `cargo build -p dlp-common` — zero warnings
- `cargo check --workspace` — exits 0 (additive re-exports cause no downstream breakage)

## Deviations from Plan

None - plan executed exactly as written.

The plan's "Notes on discretion calls" were honored as specified:
- `AppIdentity` builder methods: omitted (no dead_code warnings)
- `PartialOrd`/`Ord` on `UsbTrustTier` and `AppTrustTier`: derived as directed
- `DeviceIdentity` constructor: omitted (Phase 23 decides)

## Known Stubs

None. All five types are fully implemented with correct serde wire format and defaults. No placeholder values or TODO markers present.

## Threat Flags

No new threat surface introduced. This is a compile-time-only type-definition plan with no runtime enforcement surface. All STRIDE mitigations from the plan's threat model are implemented:

| Threat ID | Mitigation Status |
|-----------|------------------|
| T-22-01 (UsbTrustTier tampering) | Mitigated via `#[serde(rename_all = "snake_case")]` + `test_usb_trust_tier_serde_values` |
| T-22-02 (AppIdentity logging) | Accepted (Phase 26 concern) |
| T-22-03 (malformed deserialization DoS) | Mitigated via `#[serde(default)]` + empty-object tests |
| T-22-04 (insecure defaults elevation) | Mitigated via `UsbTrustTier::Blocked` default + `test_usb_trust_tier_default_is_blocked` |
| T-22-05 (spoofing via name collision) | Accepted (compile-time, closed workspace) |

## Downstream Handoff

- **Plan 02** (Phase 22): Can now `use crate::endpoint::{AppIdentity, DeviceIdentity};` inside dlp-common sibling modules to extend `EvaluateRequest` and `EvaluateResponse`.
- **Plan 03** (Phase 22): Can `use crate::endpoint::{AppIdentity, DeviceIdentity};` to extend `AuditEvent`.
- **Phase 23+**: Can import via `dlp_common::AppIdentity`, `dlp_common::DeviceIdentity`, `dlp_common::UsbTrustTier` from the crate root.
- **Phase 24**: `UsbTrustTier` wire strings `"blocked"`, `"read_only"`, `"full_access"` satisfy the `device_registry.trust_tier` DB CHECK constraint (REQUIREMENTS.md USB-02).

## Self-Check: PASSED

- `dlp-common/src/endpoint.rs` exists: FOUND
- `dlp-common/src/lib.rs` updated: FOUND
- Commit 7dd2d04 exists: FOUND
- Commit f2a8a35 exists: FOUND
- 13 endpoint tests pass: VERIFIED
- Zero build warnings: VERIFIED
- Workspace check clean: VERIFIED
