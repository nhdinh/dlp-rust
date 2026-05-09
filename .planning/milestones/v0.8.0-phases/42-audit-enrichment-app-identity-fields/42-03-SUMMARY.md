---
phase: 42-audit-enrichment-app-identity-fields
plan: 03
status: complete
completed: "2026-05-07"
---

# Plan 42-03: Audit Schema Guarantee and AGENT-UNKNOWN Fallback — Summary

## What Was Built

Enforced audit schema guarantees: every emitted audit event has non-null `source_application` and `destination_application`, with AGENT-UNKNOWN as the sentinel for unresolvable identity.

### Changes

- **`dlp-agent/src/audit_emitter.rs`**
  - Extracted inline AGENT-UNKNOWN fallback from `emit_audit()` into public `ensure_app_identity_fields(event)` function
  - Added structured `tracing::debug!` logs with correlation_id when fallback is applied
  - Added 3 schema guarantee integration tests:
    - `test_emit_audit_guarantees_source_application`
    - `test_emit_audit_guarantees_destination_application`
    - `test_emit_audit_preserves_resolved_identity`

- **`dlp-common/src/audit.rs`**
  - Updated doc comments on `source_application` and `destination_application` to reference AUDIT-04, Phase 42 (replaced AUDIT-05, Phase 38.3 references)

- **`dlp-server/src/audit_store.rs`**
  - Added server-side validation in `ingest_events()` rejecting audit events with missing `source_application` or `destination_application`
  - Returns `400 Bad Request` with `tracing::warn!` log including correlation_id

- **`dlp-server/src/admin_api.rs`**
  - Updated test helpers and inline test events to include app identity fields
  - Updated `sample_audit_event()`, `seed_tc_audit_event()`, and all inline `AuditEvent::new()` calls used in `/audit/events` tests

- **`dlp-e2e/tests/hot_reload_config.rs`**
  - Fixed `EvaluateRequest` construction to include `source_origin: None` and `destination_origin: None`

## Verification

- `cargo test -p dlp-agent` — 579 passed, 9 ignored
- `cargo test -p dlp-server` — 260 passed, 3 ignored
- `cargo clippy --all -- -D warnings` — clean
- `cargo fmt` — applied
