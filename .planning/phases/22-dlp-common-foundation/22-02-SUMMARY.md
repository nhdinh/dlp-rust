---
phase: 22-dlp-common-foundation
plan: "02"
subsystem: dlp-common
tags:
  - rust
  - dlp-common
  - serde
  - abac
  - audit
dependency_graph:
  requires:
    - dlp-common::AppIdentity (Plan 01)
    - dlp-common::DeviceIdentity (Plan 01)
  provides:
    - dlp-common::abac::AbacContext
    - EvaluateRequest::source_application
    - EvaluateRequest::destination_application
    - AuditEvent::source_application
    - AuditEvent::destination_application
    - AuditEvent::device_identity
    - AuditEvent::with_source_application
    - AuditEvent::with_destination_application
    - AuditEvent::with_device_identity
  affects:
    - dlp-server (Phase 25 — writes source_application/destination_application)
    - dlp-agent (Phase 25 — populates AppIdentity on clipboard events)
    - dlp-common Plan 03 (Phase 22 — ClassificationResult + PolicyViolation)
    - Phase 26 (AbacContext enforcement)
    - Phase 27 (AuditEvent device_identity on USB block)
tech_stack:
  added: []
  patterns:
    - struct-level serde(default) on Subject/Resource/Environment for partial-JSON backward compat
    - skip_serializing_if = "Option::is_none" on new AuditEvent fields (matching existing pattern)
    - Default::default() struct-update syntax for additive EvaluateRequest callers
    - Builder pattern (consume-and-return) for new AuditEvent methods
key_files:
  created: []
  modified:
    - dlp-common/src/abac.rs
    - dlp-common/src/audit.rs
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-server/src/alert_router.rs
    - dlp-agent/src/interception/mod.rs
    - dlp-agent/src/offline.rs
decisions:
  - "Added #[serde(default)] to Subject, Resource, Environment structs: required for test_evaluate_request_backward_compat_missing_new_fields to deserialize '{} ' payloads — without it serde requires all String fields to be present"
  - "Used ..Default::default() in downstream callers (dispatch.rs, offline.rs, interception/mod.rs) rather than listing new None fields explicitly: forwards-compatible pattern, consistent with EvaluateRequest having struct-level #[serde(default)]"
  - "Used explicit None fields in alert_router.rs AuditEvent literal: AuditEvent does not derive Default, so ..Default::default() is not available; explicit None fields match existing literal style"
metrics:
  duration: "~25 minutes"
  completed: "2026-04-22"
  tasks_completed: 2
  tasks_total: 2
  files_created: 0
  files_modified: 6
  tests_added: 9
requirements:
  - PHASE-22-INFRA
---

# Phase 22 Plan 02: ABAC Context and Audit Identity Extension Summary

**One-liner:** EvaluateRequest and AbacContext extended with two optional AppIdentity fields; AuditEvent extended with three optional identity fields plus builder methods — all additive, backward-compatible, zero warnings.

## What Was Built

### dlp-common/src/abac.rs

Extended `EvaluateRequest` with two new optional fields and introduced the new `AbacContext` struct:

| Change | Detail |
|--------|--------|
| `use crate::endpoint::AppIdentity` import | Added after existing `use serde` line |
| `EvaluateRequest::source_application` | `Option<AppIdentity>` with `#[serde(default, skip_serializing_if = "Option::is_none")]` |
| `EvaluateRequest::destination_application` | `Option<AppIdentity>` with `#[serde(default, skip_serializing_if = "Option::is_none")]` |
| New `AbacContext` struct | Mirrors EvaluateRequest minus `agent` field (D-10); same two app-identity fields |
| `#[serde(default)]` on `Subject`, `Resource`, `Environment` | Enables backward-compat deserialization of partial JSON payloads |

### dlp-common/src/audit.rs

Extended `AuditEvent` with three new optional fields and three builder methods:

| Change | Detail |
|--------|--------|
| `use crate::endpoint::{AppIdentity, DeviceIdentity}` import | Added after existing `use uuid::Uuid` line |
| `AuditEvent::source_application` | `Option<AppIdentity>` with `#[serde(skip_serializing_if = "Option::is_none")]` |
| `AuditEvent::destination_application` | `Option<AppIdentity>` with `#[serde(skip_serializing_if = "Option::is_none")]` |
| `AuditEvent::device_identity` | `Option<DeviceIdentity>` with `#[serde(skip_serializing_if = "Option::is_none")]` |
| `AuditEvent::new()` initializer | Three new `None` initializers added (exhaustive struct init) |
| `with_source_application(Option<AppIdentity>) -> Self` | Builder method |
| `with_destination_application(Option<AppIdentity>) -> Self` | Builder method |
| `with_device_identity(Option<DeviceIdentity>) -> Self` | Builder method |
| Extended `test_skip_serializing_none_fields` | 3 new assertions for Phase 22 fields |

### Downstream caller fixes (Rule 1 - Bug)

Four callers building `EvaluateRequest` or `AuditEvent` by exhaustive field literal required updates:

| File | Fix |
|------|-----|
| `dlp-admin-cli/src/screens/dispatch.rs` | Added `..Default::default()` to EvaluateRequest |
| `dlp-agent/src/interception/mod.rs` | Added `..Default::default()` to EvaluateRequest |
| `dlp-agent/src/offline.rs` | Added `..Default::default()` to EvaluateRequest |
| `dlp-server/src/alert_router.rs` | Added three explicit `None` fields to AuditEvent literal |

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Extend EvaluateRequest and add AbacContext in abac.rs | 4558ded | dlp-common/src/abac.rs |
| 2 | Extend AuditEvent with app/device identity fields and builder methods | c7ba3ca | dlp-common/src/audit.rs |
| - | Fix downstream callers for new mandatory fields | bd58df0 | 4 files across dlp-admin-cli, dlp-server, dlp-agent |

## Tests Added

### abac.rs (5 new tests)
- `test_abac_context_default` — D-10 invariant: no agent field, both app fields None
- `test_abac_context_round_trip` — serde round-trip with source_application set
- `test_evaluate_request_app_identity_fields_round_trip` — both new fields round-trip
- `test_evaluate_request_omits_none_app_identity_fields` — SC-3: None fields absent from JSON
- `test_evaluate_request_backward_compat_missing_new_fields` — legacy payload deserializes

### audit.rs (4 new tests + 3 assertions in existing test)
- `test_audit_event_with_source_application` — builder sets field, others remain None
- `test_audit_event_with_destination_application_and_device_identity` — chained builders
- `test_audit_event_app_and_device_serde_round_trip` — SC-4: fields serialize/deserialize correctly
- `test_audit_event_backward_compat_missing_new_fields` — D-13: legacy JSON still deserializes
- Extended `test_skip_serializing_none_fields` — 3 new None-skip assertions

## Verification Results

- `cargo test -p dlp-common --lib` — 62/62 tests pass (all pre-existing + 9 new)
- `cargo build -p dlp-common` — zero warnings
- `cargo clippy -p dlp-common --lib -- -D warnings` — exits 0 (no dead_code warning for AbacContext)
- `cargo check --workspace` — exits 0 (all downstream crates compile cleanly)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Added #[serde(default)] to Subject, Resource, Environment structs**
- **Found during:** Task 1, test_evaluate_request_backward_compat_missing_new_fields
- **Issue:** The backward-compat test sends `"subject": {}` but Subject's String fields (user_sid, user_name) have no default — serde required them to be present, causing deserialization failure
- **Fix:** Added struct-level `#[serde(default)]` to Subject, Resource, and Environment. All three already derive Default and their String fields default to empty strings, which is correct for a heartbeat/probe request
- **Files modified:** dlp-common/src/abac.rs
- **Commit:** 4558ded

**2. [Rule 1 - Bug] Fixed four downstream callers with exhaustive struct literals**
- **Found during:** Post-Task-2 workspace check
- **Issue:** EvaluateRequest and AuditEvent callers in dlp-admin-cli, dlp-server, dlp-agent built structs with exhaustive field lists; the two new EvaluateRequest fields and three new AuditEvent fields caused E0063 compile errors
- **Fix:** Added `..Default::default()` to EvaluateRequest callers; added explicit `None` fields to the AuditEvent literal (AuditEvent does not derive Default)
- **Files modified:** dlp-admin-cli/src/screens/dispatch.rs, dlp-server/src/alert_router.rs, dlp-agent/src/interception/mod.rs, dlp-agent/src/offline.rs
- **Commit:** bd58df0

## Known Stubs

None. All new fields are properly typed Option<T> with correct serde attributes. No placeholder values or TODO markers. Phase 25 will populate source_application and destination_application on clipboard events; Phase 26/27 will populate device_identity on USB block events.

## Threat Flags

No new threat surface beyond what was analyzed in the plan's threat model (T-22-06 through T-22-10). All mitigations implemented:

| Threat ID | Mitigation |
|-----------|-----------|
| T-22-06 (AuditEvent backward compat) | test_audit_event_backward_compat_missing_new_fields pins the invariant |
| T-22-07 (EvaluateRequest backward compat) | test_evaluate_request_backward_compat_missing_new_fields + struct-level #[serde(default)] |
| T-22-08 (DoS via large AppIdentity) | Pre-existing request size limits in tower middleware |
| T-22-09 (AppIdentity path in logs) | No tracing calls on new fields in this plan |
| T-22-10 (EoP via omitted source_application) | None = least privilege; policy DENY-on-no-match applies |

## Downstream Handoff

- **Plan 03** (Phase 22): Can now use AbacContext as the context type in ClassificationResult/PolicyViolation
- **Phase 25**: Can populate `EvaluateRequest::source_application` and `destination_application` from clipboard resolver; can call `AuditEvent::with_source_application()` / `with_destination_application()`
- **Phase 26**: Can use `AbacContext` (no agent field) as the internal ABAC evaluation context at PolicyStore::evaluate()
- **Phase 27**: Can call `AuditEvent::with_device_identity()` on USB block events

## Self-Check: PASSED

- `dlp-common/src/abac.rs` modified: FOUND
- `dlp-common/src/audit.rs` modified: FOUND
- `AbacContext` struct in abac.rs: FOUND (grep -c 'pub struct AbacContext' = 1)
- `with_source_application` in audit.rs: FOUND (grep -c = 1)
- Commit 4558ded exists: FOUND
- Commit c7ba3ca exists: FOUND
- Commit bd58df0 exists: FOUND
- 62 dlp-common tests pass: VERIFIED
- Zero build warnings: VERIFIED
- Clippy clean: VERIFIED
- Workspace check clean: VERIFIED
