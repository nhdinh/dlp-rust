# Phase 29: Chrome Enterprise Connector - Context

**Gathered:** 2026-04-29
**Status:** Ready for planning

<domain>
## Phase Boundary

Chrome browser clipboard events are intercepted and evaluated by the DLP system so paste operations from managed origins to unmanaged destinations are blocked at the browser level.

**Deliverables:**
1. **Named-pipe server** at `\\.\pipe\brcm_chrm_cas` in `dlp-agent` — accepts protobuf-framed scan requests from Chrome
2. **Protobuf decode** — minimal Request/Response/Action message types from Google's Content Analysis protocol
3. **Browser clipboard block + audit** — origin-based allow/block decision using the managed-origins cache, with audit events containing `source_origin` and `destination_origin`

**Requirements in scope:** BRW-01, BRW-03

</domain>

<decisions>
## Implementation Decisions

### Protobuf Protocol

- **D-01:** Use `prost` with a minimal vendored `.proto` file. Only 3 message types: `ContentAnalysisRequest`, `ContentAnalysisResponse`, and `Action`.
  - Vendored `.proto` lives at `dlp-agent/proto/content_analysis.proto`
  - `prost-build` runs in `dlp-agent/build.rs` to generate Rust types
  - Generated module: `dlp-agent/src/chrome/proto.rs` (or inline in a `chrome` module)
  - The frame protocol is `[4-byte little-endian length][protobuf payload]` — handled in a `chrome::frame` module

### Decision Logic

- **D-02:** Agent polls `GET /admin/managed-origins` and caches results locally, exactly mirroring the Phase 24 `DeviceRegistryCache` pattern.
  - New `ManagedOriginsCache` struct: `RwLock<HashSet<String>>` holding origin pattern strings
  - Poll interval: 30 seconds (same as device registry)
  - Cache seeded at agent startup, refreshed on each poll
  - Chrome scan request evaluated locally: if `source_origin` is in the cache and `destination_origin` is not → BLOCK

### HKLM Registration

- **D-03:** Self-registration at service startup.
  - Write `HKLM\SOFTWARE\Google\Chrome\3rdparty\cas_agents` (or the documented Chrome registry path) with pipe name `\\.\pipe\brcm_chrm_cas`
  - Test override: `DLP_SKIP_CHROME_REG=1` skips HKLM writes (consistent with Phase 30 env-var pattern: `DLP_SKIP_HARDENING`, `DLP_SKIP_IPC`)
  - Registration is idempotent — safe to write on every startup

### Audit Event Fields

- **D-04:** Two new `Option<String>` fields on `AuditEvent`: `source_origin` and `destination_origin`.
  - Both use `#[serde(skip_serializing_if = "Option::is_none")]` for backward compat
  - Reuse existing `EventType::Block` — no new event type needed
  - Populated by the Chrome scan handler before emitting the audit event
  - Fields mirror the Phase 22 pattern used for `source_application`/`destination_application`

### Named Pipe Architecture

- **D-05:** Chrome pipe server runs as a 4th IPC server alongside P1/P2/P3, but in a dedicated `chrome` module (not mixed with agent↔UI pipes).
  - Uses the same `CreateNamedPipeW` + `ConnectNamedPipeW` pattern as `pipe1.rs`
  - Runs on its own thread: `chrome-pipe`
  - Pipe name: `\\.\pipe\brcm_chrm_cas` (Google's documented name)
  - Frame parsing (length-prefix + protobuf) happens in the thread before dispatching to the decision handler

### Chrome→Agent Request Handling

- **D-06:** On receiving a `ContentAnalysisRequest`:
  1. Extract `source_url` and `destination_url` from the request
  2. Normalize to origin strings (scheme + host, strip path/query)
  3. Check `ManagedOriginsCache`: is source in cache? Is destination NOT in cache?
  4. If (source ∈ managed) AND (destination ∉ managed) → construct `ContentAnalysisResponse` with `Action::Block`
  5. Otherwise → `Action::Allow`
  6. Build and send the protobuf response frame back through the pipe

### Claude's Discretion

- Exact `prost-build` configuration (whether to use `prost-build` directly or `tonic` — recommend `prost-build` only, no gRPC)
- Whether to normalize origin strings with or without trailing slash (e.g. `https://example.com` vs `https://example.com/`)
- Exact HKLM registry key path if Google's documented path differs from the one above
- Whether `ManagedOriginsCache` supports wildcard patterns (e.g. `*.sharepoint.com`) or exact-match only
- Error handling strategy for malformed protobuf frames (close connection vs send Block vs log and continue)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements
- `.planning/REQUIREMENTS.md` — BRW-01 and BRW-03 requirement definitions
- `.planning/ROADMAP.md` §Phase 29 — 4 success criteria

### Prior Phase Context (must read for patterns)
- `.planning/phases/24-device-registry-db-admin-api/24-CONTEXT.md` — Device registry cache pattern, poll loop, `DeviceRegistryCache` structure
- `.planning/phases/28-admin-tui-screens/28-CONTEXT.md` — Managed origins API shape (D-06..D-10), `GET /admin/managed-origins` is unauthenticated
- `.planning/phases/22-dlp-common-foundation/22-CONTEXT.md` — Optional field pattern on `AuditEvent` with `#[serde(skip_serializing_if)]`

### Key Source Files (read before touching)
- `dlp-agent/src/ipc/pipe1.rs` — Named pipe server pattern (`CreateNamedPipeW`, `ConnectNamedPipeW`, frame loop)
- `dlp-agent/src/ipc/server.rs` — `start_all()` readiness barrier pattern
- `dlp-agent/src/device_registry.rs` — `DeviceRegistryCache` as template for `ManagedOriginsCache`
- `dlp-server/src/admin_api.rs` — `list_managed_origins_handler` (line ~1730), unauthenticated GET endpoint
- `dlp-server/src/db/repositories/managed_origins.rs` — `ManagedOriginsRepository::list_all` as the data source
- `dlp-common/src/audit.rs` — `AuditEvent` struct with optional field patterns
- `dlp-agent/src/service.rs` — `run_loop` where IPC servers are started and where the new Chrome pipe thread would be spawned

### External Reference
- Google Chrome Enterprise Content Analysis documentation (public) — defines the named pipe name `brcm_chrm_cas`, protobuf message shapes, and HKLM registration path

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DeviceRegistryCache` in `dlp-agent/src/device_registry.rs` — template for `ManagedOriginsCache` (same `RwLock<HashMap>` pattern, same poll loop structure)
- `pipe1::serve_with_ready` in `dlp-agent/src/ipc/pipe1.rs` — template for the Chrome pipe server loop (blocking read, process, blocking write)
- `ipc::server::start_all()` — readiness barrier pattern; extend to start a 4th thread for the Chrome pipe
- `AuditEvent::with_source_application()` / `with_device_identity()` — builder pattern for adding optional context fields

### Established Patterns
- Agent config polling: `spawn_blocking` loop + `tokio::time::sleep` + HTTP GET + cache update (seen in `device_registry.rs`)
- Named pipe server: `CreateNamedPipeW` → `ConnectNamedPipeW` → read loop → process → write response (seen in `pipe1.rs`, `pipe2.rs`, `pipe3.rs`)
- Optional audit fields: `#[serde(skip_serializing_if = "Option::is_none")]` + builder method (Phase 22)
- Test env-var overrides: `DLP_SKIP_*=1` pattern for bypassing system-level side effects in tests (Phase 30)

### Integration Points
- `dlp-agent/src/service.rs` — add Chrome pipe thread spawn alongside existing `ipc::start_all()` call
- `dlp-agent/Cargo.toml` — add `prost`, `prost-build` (build-dependency), `bytes` dependencies
- `dlp-common/src/audit.rs` — add `source_origin` and `destination_origin` fields to `AuditEvent`
- `dlp-agent/src/audit_emitter.rs` — wire Chrome block events into the audit pipeline
- `dlp-agent/src/chrome/` (new module) — frame parser, protobuf decode/encode, decision handler, cache

</code_context>

<specifics>
## Specific Ideas

- The Chrome pipe should be isolated from the agent↔UI pipes — it uses a different protocol (protobuf binary vs JSON text) and a different trust model (Chrome browser vs user UI process)
- Cache invalidation should follow the same pattern as device registry: on every poll, replace the entire HashSet (not incremental updates) — simple and correct
- Wildcard matching for origins (e.g. `*.sharepoint.com`) is out of scope for this phase — exact string match only; wildcards deferred to a future phase

</specifics>

<deferred>
## Deferred Ideas

- Wildcard/pattern matching for managed origins (e.g. `*.sharepoint.com/*`) — future phase
- Edge for Business / Microsoft Purview integration — separate integration track, out of scope
- Native browser extension (Chrome Manifest V3) — Path A of SEED-002, deferred until Path B (this phase) is proven
- Per-tab origin tracking (vs per-paste origin) — future enhancement
- Chrome Enterprise policy enforcement (managed policy via GPO) — separate IT admin workflow

</deferred>

---

*Phase: 29-chrome-enterprise-connector*
*Context gathered: 2026-04-29*
