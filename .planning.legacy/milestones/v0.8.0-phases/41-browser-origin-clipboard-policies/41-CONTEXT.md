# Phase 41: Browser Origin Clipboard Policies - Context

**Gathered:** 2026-05-07
**Status:** Ready for planning
**Mode:** Smart discuss (autonomous)

<domain>
## Phase Boundary

Phase 41 extends the Chrome Enterprise Connector (shipped in Phase 29) with origin-specific clipboard policies via the full ABAC evaluator. Currently, the Chrome handler performs a simple managed-origins cache check: if the page URL is in the cache, block the paste. This phase replaces that simple check with ABAC policy evaluation, enabling admin-authored rules based on origin conditions.

**In scope:**
- Add `SourceOrigin` and `DestinationOrigin` as new `PolicyCondition` variants in the ABAC evaluator
- Extend `EvaluateRequest`/`AbacContext` with `source_origin` and `destination_origin` fields
- Wire the Chrome handler to construct an `EvaluateRequest` and call the local policy cache
- Support `eq`, `ne`, `contains` operators for origin conditions
- Update the admin TUI conditions builder to allow origin-based policy authoring
- Audit events include origin fields populated from the Chrome request

**Out of scope:**
- Clipboard origin tracking (tracking which page content was copied from) — Chrome Content Analysis API v1 does not expose this. Deferred to v0.9.0+ (native browser extension BRW-05).
- Non-clipboard Chrome events (downloads, print) — deferred to future milestone.
- Wildcard subdomain matching (`*.example.com`) — `contains` operator provides sufficient granularity for v0.8.0.
- Pattern lists (`in`/`not_in` for origins) — `ANY` mode with multiple conditions provides OR-logic.

</domain>

<decisions>
## Implementation Decisions

### ABAC Origin Condition Design
- Add `SourceOrigin` and `DestinationOrigin` as new `PolicyCondition` variants — follows the exact pattern of `SourceApplication`/`DestinationApplication` (Phase 26)
- Operators: `eq`, `ne`, `contains` — same as `ImagePath` and `Aumid`
- No special "is managed origin" operator — origins are pure policy conditions; the managed-origins cache becomes input to policy authoring, not a hardcoded check
- No pattern lists — single value per condition; use `ANY` mode for OR-logic across multiple origin conditions

### Chrome Handler ABAC Integration
- Chrome handler calls the full ABAC evaluator — unifies all enforcement behind ABAC
- Local policy cache access — pass `Arc<PolicyCache>` to handler at startup via `OnceLock` (same pattern as `ManagedOriginsCache`)
- No server round-trip on hot path — `RwLock` read is sub-millisecond
- No classification for Chrome clipboard — Chrome events don't have file resources; origin conditions alone drive decisions
- Clipboard-only scope — non-clipboard Chrome events deferred to future milestone

### Origin Semantics for Browser Clipboard
- `source_origin` = page URL from Chrome request (where paste is occurring) — Chrome Content Analysis API v1 only provides one URL
- `destination_origin` = `None` — API does not provide destination origin
- No clipboard origin tracking — Chrome API doesn't expose copy events; deferred to v0.9.0+ browser extension
- Audit event: populate `source_origin` with page URL, `destination_origin` as `None` with debug trace explaining the limitation

### TUI Conditions Builder
- Add `SourceOrigin` and `DestinationOrigin` to the attribute picker
- Display as text inputs with placeholder examples (e.g., `https://sharepoint.com`)
- Follow existing 3-step picker pattern: attribute → operator → value

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `PolicyCondition` enum in `dlp-common/src/abac.rs` — add `SourceOrigin` and `DestinationOrigin` variants
- `EvaluateRequest`/`AbacContext` in `dlp-common/src/abac.rs` — add `source_origin` and `destination_origin` fields
- `condition_matches()` in `dlp-server/src/policy_store.rs` — add new branches for origin conditions
- `app_identity_matches()` pattern — origin matching follows same structure (field + op + value)
- Chrome handler (`dlp-agent/src/chrome/handler.rs`) — replace `dispatch_request` simple check with ABAC evaluation
- `ManagedOriginsCache` (`dlp-agent/src/chrome/cache.rs`) — remains for backward-compat and admin UI; evaluation shifts to ABAC
- Admin TUI conditions builder — add origin attributes to picker

### Established Patterns
- New condition variants: add to `PolicyCondition`, derive Serialize/Deserialize, update `condition_matches`
- New fields on `EvaluateRequest`: add `Option<String>`, `#[serde(default, skip_serializing_if = "Option::is_none")]`
- Chrome handler: `#[cfg(windows)]` gated, `OnceLock` for global cache, protobuf frame protocol
- TUI picker: attribute enum maps to display labels; operator set varies by attribute type
- Audit: `AuditEvent::with_source_origin()` / `with_destination_origin()` already exist

### Integration Points
- **dlp-common**: `PolicyCondition` + `EvaluateRequest` + `AbacContext` changes propagate to all crates
- **dlp-server**: `policy_store.rs` evaluator needs origin condition branches; DB schema unchanged (conditions stored as JSON)
- **dlp-agent**: Chrome handler needs policy cache reference; `InterceptionEngine` or service startup wires it
- **dlp-admin-cli**: Conditions builder needs new picker options
- **dlp-user-ui**: No changes (Chrome handler lives in dlp-agent)

</code_context>

<specifics>
## Specific Ideas

### New PolicyCondition Variants
```rust
SourceOrigin { op: String, value: String }
DestinationOrigin { op: String, value: String }
```

### EvaluateRequest Extension
```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub source_origin: Option<String>,
#[serde(default, skip_serializing_if = "Option::is_none")]
pub destination_origin: Option<String>,
```

### Chrome Handler Refactor
- `dispatch_request()` currently checks `ORIGINS_CACHE.is_managed(origin)`
- Replace with: construct `EvaluateRequest` with `action: Action::PASTE`, `source_origin: Some(origin)`, call policy cache
- Keep `emit_chrome_block_audit()` but populate both origin fields

### TUI Changes
- Add `SourceOrigin` and `DestinationOrigin` to the conditions builder attribute enum
- Operator set: `eq`, `ne`, `contains`
- Placeholder: `https://company.sharepoint.com`

### Test Coverage
- Unit tests for `condition_matches` with origin conditions
- Chrome handler tests: verify ABAC evaluation path, verify audit event fields
- Policy round-trip: create policy with origin condition → evaluate → verify decision
- TUI tests: origin attribute appears in picker, condition serializes correctly

</specifics>

<deferred>
## Deferred Ideas

- Clipboard origin tracking (true source→destination semantics) — requires Chrome API v2 or native browser extension (BRW-05, v0.9.0+)
- Wildcard subdomain matching (`*.example.com`) — `contains` is sufficient for v0.8.0
- Pattern lists for origins (`in`/`not_in`) — `ANY` mode provides equivalent OR-logic
- Non-clipboard Chrome events (downloads, print) through ABAC — separate phase
- `destination_origin` population — Chrome Content Analysis API v1 limitation
- Origin-based classification (assign classification tier based on origin) — future enhancement
</deferred>
