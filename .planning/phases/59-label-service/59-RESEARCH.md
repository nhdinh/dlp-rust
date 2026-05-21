# Phase 59 Research: Label Service

**Date:** 2026-05-12
**Status:** Research complete (synthesized from codebase analysis)

---

## 1. dlp-Common Types

### Existing Classification System
- `dlp-common/src/classification.rs` has `Classification` enum: T1, T2, T3, T4
- Derives: Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Serialize, Deserialize, Default
- Has `is_sensitive()` (T3/T4) and `label()` methods
- Serde serializes as UPPERCASE ("T1", "T2", etc.)

### Required New Types
- `Label` struct — mirrors `LabelRow` in repository (10 fields)
- `LabelState` enum — 4 variants: Temporary, Confirmed, Rejected, Expired
- `ObjectType` enum — 3 variants: File, Folder, Archive
- `Tier` enum — extends Classification with `UnclassifiedBlocked`

### Pattern: Enum with String Conversion
Existing codebase uses `match` for Display and `TryFrom<&str>` for parsing. Follow the `Classification` pattern exactly.

### Integration Risk
`Classification` is used extensively in ABAC evaluation, audit events, and policy conditions. `Tier` must convert to/from `Classification` without breaking existing logic. `UnclassifiedBlocked` is label-service-only and should not leak into `Classification`.

---

## 2. Admin API Patterns

### Existing CRUD Endpoints (from `dlp-server/src/admin_api.rs`)

**Device Registry pattern:**
- `GET /admin/device-registry` — list (unauthenticated for agents)
- `GET /admin/device-registry/full` — list with all fields (JWT auth)
- `POST /admin/device-registry` — upsert (JWT auth)
- `DELETE /admin/device-registry/{id}` — delete (JWT auth)
- Request: `DeviceRegistryRequest { id, vid, pid, serial, owner_sid, owner_user, description, trust_tier }`
- Response: `DeviceRegistryResponse { entries: Vec<DeviceRegistryEntry> }`

**Disk Registry pattern:**
- `GET /admin/disk-registry` — list with optional `?agent_id=` filter
- `POST /admin/disk-registry` — insert
- `DELETE /admin/disk-registry/{id}` — delete
- Uses `Json<DiskRegistryRequest>` extractor, returns `Json<DiskRegistryResponse>`

**Common patterns observed:**
1. All admin endpoints use `State<Arc<AppState>>` extractor
2. JWT auth via `RequireAuth` layer on `/admin/*` routes
3. Handlers return `Result<Json<T>, AppError>`
4. Request/response types defined in `admin_api.rs` module (not separate files)
5. POST validates fields before DB write (e.g., `trust_tier` enum validation)
6. DB access via repository pattern (`DeviceRegistryRepo`, `DiskRegistryRepo`)
7. Audit events emitted for mutations via `audit_store::emit_admin_action()`

### AppState Extension
Current `AppState` contains: pool, crypto, policy_store, siem, alert, ad. Need to add `label_cache` for resolution caching.

---

## 3. Folder Inheritance Resolution

### Existing Query
`LabelRepository::find_parent_label()` already walks up the directory tree:
```rust
pub fn find_parent_label(pool: &Pool, child_path: &str) -> rusqlite::Result<Option<LabelRow>>
```
- Uses `rfind` for path separators (`\` and `/`)
- Queries DB for `object_type = 'folder'` at each parent level
- Returns first match

### Caching Strategy
Options:
1. **No cache** — simplest, but N DB queries per evaluation
2. **In-memory HashMap with TTL** — RwLock<HashMap<String, (Tier, Instant)>>, 30s TTL
3. **Integrated into PolicyStore** — PolicyStore already has 5-min background refresh; add label cache there

Recommendation: Option 2 (dedicated cache) for Phase 59. PolicyStore cache invalidation is more complex and better left for later optimization.

### Resolution Order
1. Exact path match
2. Nearest parent folder label
3. Fallback: `UnclassifiedBlocked`

---

## 4. Label-Aware ABAC Integration

### Current ABAC Flow
1. `EvaluateRequest` comes in with `resource_path` and `classification`
2. `AbacContext` is built from request
3. `PolicyStore::evaluate()` checks conditions against `AbacContext`
4. `Resource.classification` is part of `AbacContext`

### Required Changes
- Add `resource_path: Option<String>` to `AbacContext`
- Create `LabelService` struct that wraps `LabelRepository` + cache
- In `PolicyStore::evaluate()`, if `resource_path` is present and label-aware evaluation is enabled, resolve tier from label service instead of using request's classification
- `system_kv` flag `label_aware_evaluation_enabled` gates this behavior (default off)

### Risk: Breaking Change
Existing policies expect T1 default for unclassified. With label-aware mode, unclassified becomes `UnclassifiedBlocked` (deny-all). The flag protects against surprise breakages.

---

## 5. Admin TUI Patterns

### PolicyList Pattern (for LabelList)
```rust
PolicyList {
    policies: Vec<serde_json::Value>,
    selected: usize,
}
```
- Scrollable table
- `n` new, `e` edit, `d` delete actions
- HTTP GET to fetch data
- Navigable with arrow keys

### Multi-step Input Pattern (for Label Creation)
```rust
RegisterDeviceVid,       // step 1
RegisterDevicePid { vid }, // step 2
RegisterDeviceSerial { vid, pid }, // step 3
...
```
- Each step is an `InputPurpose` variant
- State carried forward through enum variants
- Final step submits via HTTP POST

### Config Form Pattern (NOT for labels)
`SiemConfig`, `AlertConfig`, `LdapConfig`, `UsbEnforcementConfig`:
- JSON object with `selected`, `editing`, `buffer` fields
- Row-based navigation
- Enter commits buffer to field
- NOT suitable for label management (labels are records, not config)

---

## 6. Code Structure Recommendations

### Files to Create
1. `dlp-common/src/label.rs` — types (Label, LabelState, ObjectType, Tier)
2. `dlp-server/src/label_service.rs` — LabelService with resolution + caching
3. `dlp-server/src/admin_api.rs` (modify) — add label endpoints
4. `dlp-admin-cli/src/screens/labels.rs` — constants for label screens
5. `dlp-admin-cli/src/app.rs` (modify) — add Screen variants + InputPurpose variants
6. `dlp-admin-cli/src/screens/render.rs` (modify) — add render arms
7. `dlp-admin-cli/src/screens/dispatch.rs` (modify) — add dispatch arms

### Files to Modify
1. `dlp-common/src/lib.rs` — export label module
2. `dlp-server/src/main.rs` or `lib.rs` — add label_cache to AppState
3. `dlp-server/src/db/mod.rs` — already has labels table (done)
4. `dlp-server/src/db/repositories/mod.rs` — already exports LabelRepository (done)
5. `dlp-server/src/policy_store.rs` — integrate label resolution
6. `dlp-admin-cli/src/client.rs` — add label API methods

---

## 7. Risks and Landmines

1. **Path normalization**: Windows paths use `\`, but labels may reference UNC paths (`\\server\share`). The `find_parent_label` query uses exact string matching — path normalization (case, trailing slashes) must be consistent between insert and lookup.

2. **Tier ↔ Classification conversion**: `UnclassifiedBlocked` has no `Classification` equivalent. Conversion must be explicit and fail-safe. `Tier::to_classification()` should return `Option<Classification>` (None for UnclassifiedBlocked).

3. **Cache invalidation**: Any label CRUD must invalidate the cache. The `LabelService` should expose `invalidate_cache()` and all mutating admin endpoints should call it.

4. **ABAC fallback default**: When label-aware mode is OFF, the existing behavior must be preserved exactly. No changes to `PolicyStore::evaluate()` path when flag is disabled.

5. **DB constraint violations**: The `labels` table has CHECK constraints. API must validate before DB write to return 422 instead of 500.

6. **Foreign key: parent_label_id**: Self-referencing FK to `labels(id)` with `ON DELETE SET NULL`. API must validate that `parent_label_id` points to a `folder` type label.

---

## 8. Testing Strategy

- **Unit tests**: `dlp-common/src/label.rs` — serde round-trip, Display, TryFrom, Tier/Classification conversions
- **Integration tests**: Admin API endpoints — follow existing `admin_api.rs` test module pattern (~4000 lines of tests)
- **Repository tests**: Already done (440 lines in `labels.rs` test module)
- **TUI tests**: LabelList rendering, dispatch arms — follow existing TUI test patterns

---

*Research synthesized from codebase analysis. No external research needed — this phase builds entirely on existing in-project patterns.*
