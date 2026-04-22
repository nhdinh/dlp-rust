# Phase 26: ABAC Enforcement Convergence - Context

**Gathered:** 2026-04-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Two parallel enforcement tracks:

1. **APP-03** — Add `SourceApplication` and `DestinationApplication` variants to `PolicyCondition` and wire them into `condition_matches()` so admin-authored policies can match clipboard events by publisher, image path, or app trust tier. Migrate `PolicyStore::evaluate()` to accept `&AbacContext` (Phase 22 D-09); the HTTP handler converts `EvaluateRequest → AbacContext` at the boundary.

2. **USB-03** — Enforce USB device trust tiers at file I/O time in `run_event_loop`. A `blocked` device denies all `FileAction` variants; a `read_only` device denies write-class actions (Written, Created, Deleted, Renamed) and allows Read. Introduce a thin `UsbEnforcer` struct that bridges the two existing caches (Phase 23 drive-letter map + Phase 24 trust-tier map) and is passed into `run_event_loop` as a new parameter.

Requirements in scope: APP-03, USB-03
</domain>

<decisions>
## Implementation Decisions

### APP-03: PolicyCondition Variants

- **D-01:** Two new variants added to `PolicyCondition` enum in `dlp-common/src/abac.rs`:
  ```rust
  SourceApplication { field: AppField, op: String, value: String },
  DestinationApplication { field: AppField, op: String, value: String },
  ```
  JSON wire format: `{"attribute": "source_application", "field": "publisher", "op": "eq", "value": "Microsoft"}`.

- **D-02:** New `AppField` enum in `dlp-common/src/abac.rs`:
  ```rust
  pub enum AppField { Publisher, ImagePath, TrustTier }
  ```
  Serialized as `"publisher"`, `"image_path"`, `"trust_tier"` (snake_case). Matching in `condition_matches` dispatches by `field` to the corresponding `AppIdentity` field on `EvaluateRequest.source_application` / `destination_application`.

- **D-03:** `condition_matches` for `SourceApplication`/`DestinationApplication`: if the `Option<AppIdentity>` is `None`, the condition does NOT match (fails closed — no identity = no allow). For `TrustTier` field, `value` is compared as a string against `AppTrustTier`'s serialized form (`"trusted"`, `"untrusted"`, `"unknown"`). Supported operators: `eq`, `ne` for all three fields; `contains` for `ImagePath` (substring match on path).

### APP-03: evaluate() Signature Migration

- **D-04:** `PolicyStore::evaluate()` signature changes from `&EvaluateRequest` to `&AbacContext` (Phase 22 D-09). The conversion `EvaluateRequest → AbacContext` happens in `dlp-server/src/routes/public_routes.rs` at the HTTP evaluate handler, immediately after deserialization.

- **D-05:** `condition_matches` is updated to take `&AbacContext` instead of `&EvaluateRequest`. All existing condition arms (Classification, MemberOf, DeviceTrust, NetworkLocation, AccessContext) map to the same fields on `AbacContext` — no behavioral change, just a struct rename at the call site.

- **D-06:** All existing `evaluate()` call sites in tests use `EvaluateRequest` directly. Tests in `policy_store.rs` construct `AbacContext` after this change. A `From<EvaluateRequest> for AbacContext` impl (or explicit conversion helper) keeps existing test construction minimal.

### USB-03: UsbEnforcer Struct

- **D-07:** New `UsbEnforcer` struct in `dlp-agent/src/usb_enforcer.rs`:
  - Wraps `Arc<UsbDetector>` (drive-letter → `DeviceIdentity`) and `Arc<DeviceRegistryCache>` (VID/PID/serial → `UsbTrustTier`)
  - Exposes: `pub fn check(&self, path: &str, action: &FileAction) -> Option<Decision>`
  - Returns `Some(Decision::DENY)` if the drive is `Blocked`; `Some(Decision::DENY)` if drive is `ReadOnly` and action is a write-class variant; `None` if `FullAccess` or path has no drive letter (non-USB path falls through to ABAC evaluate).

- **D-08:** Write-class `FileAction` variants (blocked for `read_only` devices): `Written`, `Created`, `Deleted`, `Renamed`. `Read` is the only allowed action on `read_only` devices.

- **D-09:** Drive-letter extraction from path: take the first character of the path, check `is_ascii_alphabetic()`, uppercase it. If path does not start with a drive letter (e.g., UNC paths), return `None` immediately — UsbEnforcer only applies to lettered drives.

### USB-03: run_event_loop Wiring

- **D-10:** `run_event_loop` gains one new parameter: `usb_enforcer: Option<Arc<UsbEnforcer>>`. Placed after `ad_client` in the signature. `None` = USB enforcement disabled (matches existing offline/no-AD fallback pattern).

- **D-11:** USB check fires **before** `offline.evaluate()`. If `usb_enforcer.check()` returns `Some(Decision::DENY)`, the event loop short-circuits: emits an audit event with `EventType::Block` and the path/drive info, then continues to next event without calling the ABAC engine.

- **D-12:** `service.rs` wires `UsbEnforcer`: after the existing `set_registry_cache(registry_cache.clone())` call, construct `Arc::new(UsbEnforcer::new(usb_detector_arc, registry_cache_arc))` and pass it into `run_event_loop`.

### Claude's Discretion

- Exact doc structure for `UsbEnforcer` (module-level vs inline doc)
- Whether `From<EvaluateRequest> for AbacContext` is a standalone impl block or a conversion helper function
- Test helper construction style for the new `AbacContext`-based `evaluate()` tests

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements
- `.planning/REQUIREMENTS.md` — APP-03 and USB-03 requirement definitions
- `.planning/ROADMAP.md` §Phase 26 — 4 success criteria (app-identity condition matching, USB blocked/read_only enforcement, cache invalidation without restart)

### Prior Phase Type Definitions (do not redefine)
- `dlp-common/src/endpoint.rs` — `AppIdentity`, `AppTrustTier`, `SignatureState`, `DeviceIdentity`, `UsbTrustTier`
- `dlp-common/src/abac.rs` — `PolicyCondition` (5 current variants), `AbacContext`, `EvaluateRequest`, `PolicyMode`

### Files Requiring Modification
- `dlp-common/src/abac.rs` — add `AppField` enum; add `SourceApplication`/`DestinationApplication` variants to `PolicyCondition`; update `condition_matches` (in policy_store.rs)
- `dlp-server/src/policy_store.rs` — migrate `evaluate()` and `condition_matches()` to `&AbacContext`
- `dlp-server/src/routes/public_routes.rs` — add `EvaluateRequest → AbacContext` conversion at the HTTP handler boundary
- `dlp-agent/src/interception/mod.rs` — add `usb_enforcer` param to `run_event_loop`; insert pre-ABAC USB check
- `dlp-agent/src/service.rs` — wire `UsbEnforcer` into both production and test `run_event_loop` call sites

### New Files
- `dlp-agent/src/usb_enforcer.rs` — `UsbEnforcer` struct (D-07 through D-09)

### Prior Phase Context (read for wiring details)
- `.planning/phases/22-dlp-common-foundation/22-CONTEXT.md` — D-08/D-09: `EvaluateRequest` wire fields + `AbacContext` definition
- `.planning/phases/23-usb-enumeration-in-dlp-agent/23-CONTEXT.md` — D-09: `device_identities: RwLock<HashMap<char, DeviceIdentity>>` in `UsbDetector`
- `.planning/phases/24-device-registry-db-admin-api/24-CONTEXT.md` — D-07/D-12: `DeviceRegistryCache.trust_tier_for(vid, pid, serial)`; agent-side module at `dlp-agent/src/device_registry.rs`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `PolicyStore::evaluate()` in `dlp-server/src/policy_store.rs:110` — current signature `(&EvaluateRequest)`, migrates to `(&AbacContext)` in this phase
- `condition_matches()` in `dlp-server/src/policy_store.rs:217` — 5 existing arms; 2 new arms added here
- `DeviceRegistryCache::trust_tier_for()` in `dlp-agent/src/device_registry.rs:65` — ready to use, returns `UsbTrustTier::Blocked` as default
- `UsbDetector::device_identities` — `RwLock<HashMap<char, DeviceIdentity>>` at `dlp-agent/src/detection/usb.rs`
- `run_event_loop` in `dlp-agent/src/interception/mod.rs:57` — current signature; USB check inserts before `offline.evaluate()` at line 127

### Established Patterns
- `condition_matches` dispatch style — match on `PolicyCondition` variant, call a compare helper; new arms follow the same shape
- `Option<Arc<T>>` parameter pattern for optional subsystems — `ad_client: Arc<Option<AdClient>>` in `run_event_loop`
- Pre-check before `offline.evaluate()` — consistent with how `is_excluded()` short-circuits the file monitor before events reach the loop

### Integration Points
- `dlp-agent/src/service.rs:396` — `registry_cache` is constructed here; `UsbDetector` Arc must also be available at this point for `UsbEnforcer` construction
- `dlp-agent/src/service.rs:514` — `run_event_loop` is spawned here; the new `usb_enforcer` argument is passed at this call site

</code_context>

<specifics>
## Specific Ideas

- `None` identity on a condition (D-03) fails closed — if an app-identity policy condition fires on an event where `source_application` is `None`, the condition does not match. This is deliberate: if identity capture failed, the evaluator cannot confirm the condition is met, so it conservatively does not trigger an ALLOW that depends on identity.
- `UsbEnforcer::check()` returning `Option<Decision>` (not `Decision`) keeps the non-USB-path case zero-cost — the `None` return is a signal to skip the USB gate entirely, not a "default allow".

</specifics>

<deferred>
## Deferred Ideas

- USB-05: Audit events with device identity fields (VID, PID, serial, description) on block — already deferred in REQUIREMENTS.md, not in scope for Phase 26
- Phase 28 TUI picker for `AppField` variants — authoring `SourceApplication`/`DestinationApplication` conditions via TUI is Phase 28's job
- Operators beyond `eq`/`ne`/`contains` for app-identity conditions — sufficient for v0.6.0; richer operators deferred
- `From<EvaluateRequest> for AbacContext` as a public conversion API — implementation detail for Claude's discretion

</deferred>

---

*Phase: 26-abac-enforcement-convergence*
*Context gathered: 2026-04-22*
