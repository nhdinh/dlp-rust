# Phase 59: Label Service - Context

**Gathered:** 2026-05-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 59 delivers the **Label Service** — a central database for file/folder/archive labels with tier classification, state machine (temporary/confirmed/rejected/expired), folder inheritance, and manual assignment API. This is the foundational phase for v0.11.0 pilot readiness.

**Already implemented:**
- `labels` SQLite table with CHECK constraints (tier, object_type, label_state)
- 5 indexes (path, tier, state, owner, parent)
- `LabelRepository` with CRUD + inheritance queries (list, list_by_state, get_by_id, get_by_path, insert, update, update_state, delete, find_parent_label)
- Full unit tests for CRUD, state transitions, parent lookup, CHECK constraints, delete cascade

**Remaining work:**
- dlp-common types (`Label`, `LabelState`, `ObjectType` structs/enums with serde)
- Admin API endpoints (RESTful, following existing patterns)
- Label resolution service (folder inheritance at enforcement time)
- Label-aware ABAC integration (`Resource.tier` resolves from label service)
- Admin TUI screen for label management and Data Owner review queue

**Requirements:** LABEL-01..07 (see `.planning/REQUIREMENTS.md` §v0.11.0)

</domain>

<decisions>
## Implementation Decisions

### dlp-Common Types
- **D-01:** Create a new `dlp-common/src/label.rs` module with:
  - `Label` struct with all fields matching `LabelRow` (id, path, object_type, tier, label_state, owner_sid, parent_label_id, acl_snapshot_id, hash, created_at, updated_at)
  - `LabelState` enum: `Temporary`, `Confirmed`, `Rejected`, `Expired` — with `Display` and serde
  - `ObjectType` enum: `File`, `Folder`, `Archive` — with `Display` and serde
  - `Tier` enum extending `Classification` with `UnclassifiedBlocked` variant (needed for LABEL-05 fallback behavior)
  - All types derive `Debug`, `Clone`, `PartialEq`, `Eq`, `Serialize`, `Deserialize`
  - Conversion impls: `From<LabelState> for &'static str`, `TryFrom<&str> for LabelState`, same for `ObjectType` and `Tier`
- **D-02:** `Tier` enum lives in `label.rs` (not `classification.rs`) to avoid circular deps. `Classification` remains unchanged for backward compatibility. `Tier::from_classification()` and `Classification::try_from(Tier)` conversion methods bridge the two. `UnclassifiedBlocked` is label-service-only.

### Admin API Design
- **D-03:** Follow the `disk_registry` / `device_registry` pattern from `admin_api.rs`:
  - `GET /admin/labels` — list all labels, optional query filters (`?state=temporary`, `?tier=T3`, `?owner_sid=...`)
  - `GET /admin/labels/:id` — get single label by ID
  - `POST /admin/labels` — create new label (manual assignment, LABEL-07)
  - `PUT /admin/labels/:id` — update label (path, tier, owner, parent)
  - `POST /admin/labels/:id/confirm` — confirm a temporary label (LABEL-04)
  - `POST /admin/labels/:id/reject` — reject a temporary label (LABEL-04)
  - `DELETE /admin/labels/:id` — delete label
- **D-04:** Request/response payloads use the dlp-common `Label` type with JSON serialization. No custom payload structs needed — `Label` + `Json<Label>` extractors. For `POST/PUT`, the server generates `id` (UUID v4) and `created_at`/`updated_at` timestamps if not provided.
- **D-05:** `POST /admin/labels` validation: `path` must be absolute (`\\server\share\...` or `C:\...`), `object_type` must be valid, `tier` must be valid. If `parent_label_id` is provided, verify it points to a `folder` label.

### Folder Inheritance Resolution
- **D-06:** Inheritance resolves at **enforcement time** (when ABAC evaluates), not at API time. The `LabelRepository::find_parent_label()` query walks up the directory tree on each resolution. This avoids stale data when folders are renamed or reorganized.
- **D-07:** Resolution order (most specific wins):
  1. Exact path match in `labels` table
  2. Walk up parent directories, find nearest `folder` label
  3. If no label found, fallback to `UnclassifiedBlocked` (LABEL-05 requirement)
- **D-08:** Cache label resolution results in `PolicyStore` or a new `LabelCache` (RwLock<HashMap<PathBuf, (Tier, Instant)>>) with a 30-second TTL to avoid repeated DB walks. Invalidation triggers on any label CRUD operation.

### Label-Aware ABAC Integration
- **D-09:** Extend `AbacContext` in `dlp-common` with `resource_path: Option<String>`. When `resource_path` is present, the ABAC evaluator calls `LabelService::resolve_tier(path)` before evaluating `Classification` conditions.
- **D-10:** `PolicyStore::evaluate()` checks for label resolution first. If a label exists, `Resource.classification` is overridden by the label's tier. If no label exists, fallback to `UnclassifiedBlocked` (deny-all for unlabeled resources in pilot mode).
- **D-11:** This is a **breaking change** to evaluation semantics. Existing policies that expect `T1` default for unclassified resources will now see `UnclassifiedBlocked`. Mitigation: the admin API returns a warning when enabling label-aware evaluation, and a `system_kv` flag `label_aware_evaluation_enabled` gates the behavior (default off until operator opts in).

### Admin TUI Screen
- **D-12:** Two TUI screens:
  1. **Label Management** (`Screen::LabelList`) — follows `PolicyList` pattern: scrollable table of labels with `n` (new), `e` (edit), `d` (delete), `v` (view detail). Filter by state via `f` key (cycles: all → temporary → confirmed → rejected → expired).
  2. **Data Owner Review Queue** (`Screen::LabelReviewQueue`) — follows `UsbEnforcementConfig` pattern: list of `temporary` labels with `c` (confirm), `r` (reject), arrow keys to navigate. Shows path, tier, owner_sid, and a confidence score field (placeholder for v0.12.0 scanner).
- **D-13:** Label creation/editing uses a multi-step form (like `RegisterDevice` flow in `InputPurpose`):
  - Step 1: path (text input)
  - Step 2: object_type picker (file/folder/archive)
  - Step 3: tier picker (T1/T2/T3/T4/Unclassified-Blocked)
  - Step 4: owner_sid (text input, optional)
  - Step 5: parent_label_id (text input, optional)
  - Step 6: confirm and submit

### Metadata Layers (LABEL-06)
- **D-14:** **Deferred to Phase 60 or later.** NTFS ADS and sidecar metadata are out of scope for Phase 59. The central DB is the single source of truth for pilot. A `system_kv` flag `metadata_layers_enabled` is reserved for future activation.

### State Machine (LABEL-03)
- **D-15:** Transitions allowed:
  - `temporary` → `confirmed` (via admin API/TUI confirm action)
  - `temporary` → `rejected` (via admin API/TUI reject action)
  - `confirmed` → `expired` (via background task or admin action)
  - Any state → `expired` (via background task, based on `updated_at` + policy TTL)
  - No direct `confirmed` → `temporary` or `rejected` → `temporary` (prevents downgrade without new scan)
- **D-16:** Expiry is manual/admin-driven in Phase 59. Automatic expiry based on TTL is deferred to Phase 61 (Approval Workflow Engine).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Architecture
- `.planning/REQUIREMENTS.md` §"v0.11.0 — Label Service + Data Owner Queue" — LABEL-01..07 requirements
- `.planning/STATE.md` §"Pilot-First Path (post-v0.10.0)" — v0.11.0 phase breakdown
- `.planning/MILESTONES.md` §"v0.11.0 Label Service + Data Owner Queue + Approval Workflow" — milestone goals and planned features

### Existing Code Patterns
- `dlp-server/src/db/repositories/labels.rs` — `LabelRepository` (already implemented, MUST reuse)
- `dlp-server/src/db/mod.rs` — `init_tables()` shows labels table schema and index definitions
- `dlp-server/src/admin_api.rs` — Admin API handler patterns (disk_registry, device_registry, managed_origins)
- `dlp-common/src/classification.rs` — `Classification` enum (T1..T4)
- `dlp-admin-cli/src/app.rs` — `Screen` enum and `InputPurpose` patterns
- `dlp-admin-cli/src/screens/usb_enforcement.rs` — Constants pattern for picker-based forms

### Related Docs
- No SPEC.md exists for Phase 59 — requirements are in REQUIREMENTS.md

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`LabelRepository`** (`dlp-server/src/db/repositories/labels.rs`): Full CRUD + inheritance queries already implemented. All remaining API and TUI work should call into this repository.
- **`UnitOfWork`** (`dlp-server/src/db/unit_of_work.rs`): Transaction wrapper already used by `LabelRepository`. Continue using for all write operations.
- **`AppState`** (`dlp-server/src/main.rs` or `lib.rs`): Contains `pool`, `crypto`, `policy_store`, etc. Add `label_cache: Arc<RwLock<LabelCache>>` for resolution caching.
- **Admin API router** (`dlp-server/src/admin_api.rs:696`): `admin_router()` function — add label routes following the same `.route()` pattern.
- **JWT auth middleware** (`dlp-server/src/admin_api.rs`): Already applied to `/admin/*` routes. Label endpoints automatically protected.
- **TUI `EngineClient`** (`dlp-admin-cli/src/client.rs`): HTTP client with GET/POST/PUT/DELETE methods. Reuse for label API calls.
- **`Screen::PolicyList`** pattern (`dlp-admin-cli/src/app.rs:446`): Scrollable table with selected index — model LabelList after this.

### Established Patterns
- **Repository pattern**: Stateless struct with `pool` or `uow` parameter. `LabelRepository` already follows this.
- **Admin API CRUD**: `list` (GET, optional query filters), `get_by_id` (GET), `create` (POST), `update` (PUT), `delete` (DELETE). Request/response types are JSON-serializable structs in dlp-common.
- **TUI multi-step input**: `InputPurpose` enum carries state across text input screens (e.g., `RegisterDeviceVid` → `RegisterDevicePid` → ...). Use this pattern for label creation.
- **TUI config form**: `SiemConfig` / `AlertConfig` / `LdapConfig` / `UsbEnforcementConfig` — navigable row list with editing mode and buffer. NOT used for label screens (they use PolicyList pattern instead).
- **Error handling**: Handlers return `Result<Json<T>, AppError>`. `AppError` is defined in `dlp-server/src/error.rs`.

### Integration Points
- **ABAC Evaluator** (`dlp-server/src/policy_store.rs` or `dlp-common/src/abac.rs`): Add label resolution before condition evaluation. The `Resource` struct needs a `tier` field that can be overridden by label lookup.
- **Agent config** (`dlp-server/src/admin_api.rs` agent-config endpoints): Label-aware evaluation flag (`label_aware_evaluation_enabled`) should be part of global agent config.
- **Audit events** (`dlp-server/src/db/audit_events.rs`): Label CRUD operations should emit `EventType::AdminAction` audit events (follow Phase 9 pattern).
- **dlp-common types**: New `label.rs` module must be exported from `dlp-common/src/lib.rs`.

</code_context>

<specifics>
## Specific Ideas

- Label creation TUI should use the proven multi-step `InputPurpose` flow (like device registration), not the config-form pattern. This avoids a complex modal with many fields.
- The Data Owner review queue screen should mirror the visual style of `PolicyList` but with action keys `c` (confirm) and `r` (reject) instead of `e`/`d`.
- Folder inheritance should use the existing `find_parent_label` query. No new SQL needed — just wire it into a `LabelService` struct that wraps the repository.
- `UnclassifiedBlocked` tier is label-service-only and does not extend `Classification`. Keep them separate to avoid polluting the four-tier enum used throughout v0.10.0.

</specifics>

<deferred>
## Deferred Ideas

- **NTFS ADS metadata layer** (LABEL-06) — deferred to Phase 60+; central DB is pilot SOT
- **Sidecar metadata files** (LABEL-06) — deferred to Phase 60+
- **Automatic label expiry based on TTL** — deferred to Phase 61 (Approval Workflow Engine)
- **Scanner-driven temporary labels** (LABEL-03) — deferred to Phase 65 (File Scanner); manual assignment only in Phase 59
- **Data Owner digital signature for T4** (WORKFLOW-03..06) — deferred to Phase 61

</deferred>

---

*Phase: 59-Label Service*
*Context gathered: 2026-05-12*
