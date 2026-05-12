# Phase 59: Label Service - Validation Strategy

**Date:** 2026-05-12
**Phase:** 59-label-service
**Status:** Validation strategy defined

---

## Validation Architecture

### Dimension 1: Type Safety
- All new types (`Label`, `LabelState`, `ObjectType`, `Tier`) have unit tests for serde round-trip, Display, and TryFrom conversions.
- `Tier::to_classification()` returns `Option<Classification>` — test that `UnclassifiedBlocked` returns `None`.

### Dimension 2: API Contract Validation
- Integration tests for all 7 admin endpoints (GET list, GET by id, POST, PUT, confirm, reject, DELETE).
- Each endpoint tested for: success case, 401 without JWT, 422 with invalid data, 404 for missing ID.

### Dimension 3: DB Constraint Validation
- `labels` table CHECK constraints tested via integration tests (invalid tier, object_type, label_state).
- Foreign key validation: `parent_label_id` must point to existing `folder` label.

### Dimension 4: Inheritance Resolution
- Unit tests for `LabelService::resolve_tier()`:
  - Exact path match returns direct label tier
  - Child file inherits parent folder tier
  - No label found returns `UnclassifiedBlocked`
  - Cache hit returns cached value without DB query
  - Cache miss queries DB and populates cache
  - Cache invalidation on label mutation

### Dimension 5: ABAC Integration
- Unit tests for `PolicyStore::evaluate()` with label-aware mode ON and OFF.
- When ON: `Resource.classification` overridden by label tier.
- When OFF: existing behavior preserved exactly.
- `UnclassifiedBlocked` maps to deny-all action.

### Dimension 6: TUI Integration
- `cargo check -p dlp-admin-cli` passes after all TUI changes.
- Dispatch arms for new screens compile and route correctly.
- Render arms for new screens compile without warnings.

### Dimension 7: End-to-End Flow
- Manual label assignment: TUI creation → POST API → DB storage → ABAC evaluation → correct decision.
- Confirm/reject flow: temporary label → confirm → state change → ABAC uses confirmed tier.

### Automated Verification Commands

```bash
# Unit tests for new types
cargo test -p dlp-common --lib label::

# Unit tests for LabelService
cargo test -p dlp-server label_service::

# Integration tests for admin API
cargo test -p dlp-server admin_api::label

# Unit tests for ABAC integration
cargo test -p dlp-common abac::
cargo test -p dlp-server policy_store::

# TUI compilation check
cargo check -p dlp-admin-cli

# Full workspace build
cargo build --workspace

# Linting
cargo clippy --all-targets -- -D warnings

# Formatting check
cargo fmt --check

# SonarQube scan
sonar-scanner
```

### Coverage Targets
- New code: >80% line coverage
- Integration tests: all 7 admin endpoints covered
- TUI: compilation + manual smoke test

---

*Validation strategy for Phase 59 — Label Service.*
