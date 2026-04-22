# Phase 22: dlp-common Foundation - Context

**Gathered:** 2026-04-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Add shared endpoint-identity types to dlp-common that gate all three v0.6.0 enforcement tracks (APP, USB, BRW). This is a pure type-definition phase — no evaluation logic, no enforcement, no UI changes. Downstream crates (dlp-agent, dlp-server, dlp-user-ui, dlp-admin-cli) must compile cleanly against the new types with zero warnings before any Phase 23+ work begins.

</domain>

<decisions>
## Implementation Decisions

### Module Organization

- **D-01:** New dedicated module `dlp-common/src/endpoint.rs` for all endpoint-identity types: `AppIdentity`, `DeviceIdentity`, `UsbTrustTier`, `AppTrustTier`, `SignatureState`. Re-export from `lib.rs` alongside existing `pub use abac::*`.
- **D-02:** `abac.rs` is NOT extended with endpoint types — it stays focused on policy/evaluation types (PolicyCondition, PolicyMode, EvaluateRequest, etc.).

### AppIdentity Struct

- **D-03:** `AppIdentity` fields: `image_path: String`, `publisher: String`, `trust_tier: AppTrustTier`, `signature_state: SignatureState`. All fields non-optional inside the struct; the struct itself is `Option<AppIdentity>` at call sites.
- **D-04:** `AppTrustTier` is a **separate enum** from `UsbTrustTier` (different enforcement semantics). Variants: `Trusted`, `Untrusted`, `Unknown` — `#[default]` is `Unknown`.
- **D-05:** `SignatureState` variants: `Valid`, `Invalid`, `NotSigned`, `Unknown` — `#[default]` is `Unknown`. Covers all `WinVerifyTrust` outcomes.

### DeviceIdentity + UsbTrustTier

- **D-06:** `DeviceIdentity` fields: `vid: String`, `pid: String`, `serial: String`, `description: String`. All `String` (not u16 for vid/pid) to avoid serde/display friction and match what `SetupDi` returns as strings.
- **D-07:** `UsbTrustTier` variants: `Blocked`, `ReadOnly`, `FullAccess` — serialized as `"blocked"`, `"read_only"`, `"full_access"` (lowercase_snake to match Phase 24 DB CHECK constraint values in REQUIREMENTS.md). `#[default]` is `Blocked` (safe default — unknown device = most restrictive).

### AbacContext vs EvaluateRequest

- **D-08:** `EvaluateRequest` (the HTTP wire-format struct used by agents) gains two new optional fields with `#[serde(default)]`:
  - `source_application: Option<AppIdentity>`
  - `destination_application: Option<AppIdentity>`
  These are skipped in serialization when `None` (`#[serde(skip_serializing_if = "Option::is_none")]`).
- **D-09:** A new `AbacContext` struct is introduced in `abac.rs` as the **internal evaluation context** that `PolicyStore::evaluate` will accept in Phase 26. For Phase 22, it is defined but not yet wired into `evaluate()`. It mirrors `EvaluateRequest` fields plus the app identity fields. Phase 26 will convert `EvaluateRequest` → `AbacContext` at the evaluate boundary.
- **D-10:** `AbacContext` in Phase 22: carries `subject`, `resource`, `environment`, `action`, `source_application: Option<AppIdentity>`, `destination_application: Option<AppIdentity>`. No `agent` field (that's wire-only metadata).

### AuditEvent Wire Format

- **D-11:** `AuditEvent` in `audit.rs` gains two new optional fields with `#[serde(default)]` and `#[serde(skip_serializing_if = "Option::is_none")]`:
  - `source_application: Option<AppIdentity>`
  - `destination_application: Option<AppIdentity>`
- **D-12:** `AuditEvent` also gains `device_identity: Option<DeviceIdentity>` for USB block events (Phase 26/27 will populate it). Added in Phase 22 for wire-format stability.
- **D-13:** No breaking change to existing `AuditEvent` — all new fields use `#[serde(default)]` so old events deserialize without errors.

### IPC Message Changes

- **D-14:** IPC message files remain **duplicated** between `dlp-agent/src/ipc/messages.rs` and `dlp-user-ui/src/ipc/messages.rs`. No consolidation into dlp-common in this phase.
- **D-15:** `Pipe3UiMsg::ClipboardAlert` in both files gains:
  - `source_application: Option<AppIdentity>` with `#[serde(default)]`
  - `destination_application: Option<AppIdentity>` with `#[serde(default)]`
- **D-16:** `Pipe2AgentMsg` (Toast) does NOT get app identity fields — it's a display-only message and doesn't carry enforcement data.

### Compilation Guarantee

- **D-17:** All five crates (dlp-common, dlp-agent, dlp-server, dlp-user-ui, dlp-admin-cli) must compile with `cargo build --workspace` and zero warnings after Phase 22. This is the phase's primary acceptance test.

### Claude's Discretion

- `AppIdentity` builder methods (e.g., `with_publisher()`) — Claude decides whether to add them based on ergonomics; not required by success criteria.
- Whether `AppTrustTier` and `UsbTrustTier` derive `PartialOrd`/`Ord` — not required in Phase 22; Claude decides.
- `DeviceIdentity` constructor convenience method — Claude decides.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### v0.6.0 Requirements
- `.planning/REQUIREMENTS.md` — APP-01..06, BRW-01..03, USB-01..04; UsbTrustTier DB CHECK values defined (USB-02: `blocked`, `read_only`, `full_access`)

### Phase Success Criteria
- `.planning/ROADMAP.md` §Phase 22 — 5 success criteria; item 5 requires zero-warning workspace compile

### Existing Type Patterns
- `dlp-common/src/abac.rs` — existing EvaluateRequest, PolicyCondition, PolicyMode patterns; serde conventions to match
- `dlp-common/src/audit.rs` — existing AuditEvent builder pattern; new fields follow same `#[serde(skip_serializing_if = "Option::is_none")]` convention
- `dlp-agent/src/ipc/messages.rs` — canonical IPC message source; UI copy mirrors it
- `dlp-user-ui/src/ipc/messages.rs` — UI-side IPC copy; both must be updated identically

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `dlp-common/src/abac.rs`: EvaluateRequest (extend with new optional fields D-08), AbacContext (new type D-09), serde patterns with `#[serde(default)]`
- `dlp-common/src/audit.rs`: AuditEvent builder pattern — new fields follow `.with_*()` builder convention
- `dlp-agent/src/ipc/messages.rs` + `dlp-user-ui/src/ipc/messages.rs`: Both files need identical Pipe3UiMsg::ClipboardAlert changes

### Established Patterns
- All dlp-common types: `#[derive(Debug, Clone, Serialize, Deserialize)]` + `#[serde(default)]` on struct; `Default` impl or derive
- Optional wire fields: `#[serde(skip_serializing_if = "Option::is_none")]` on each field (not struct-level)
- Enum serde: `#[serde(rename_all = "snake_case")]` where DB/wire values must be lowercase_snake (UsbTrustTier)
- No `pub use endpoint::*` wildcard — named re-exports only to keep public API surface explicit

### Integration Points
- `dlp-common/src/lib.rs`: Add `pub mod endpoint;` + named re-exports
- `dlp-agent/src/ipc/messages.rs`: Pipe3UiMsg::ClipboardAlert struct gains two fields
- `dlp-user-ui/src/ipc/messages.rs`: Same change mirrored
- `dlp-common/src/abac.rs`: EvaluateRequest + new AbacContext struct

</code_context>

<specifics>
## Specific Ideas

- `UsbTrustTier` default is `Blocked` (not `FullAccess`) — unknown device = most restrictive by default, aligns with CLAUDE.md Default Deny principle.
- `DeviceIdentity` uses `String` for vid/pid (not `u16`) — avoids hex-formatting complexity at the wire layer; Phase 24 can normalize later.
- `AbacContext` is defined now but only used by Phase 26 — Phase 22 just establishes the type so it compiles across all crates.

</specifics>

<deferred>
## Deferred Ideas

- IPC message consolidation into dlp-common — kept as known duplication; a future refactor phase could address this
- `AppTrustTier` → `PartialOrd` for policy range comparisons — deferred to Phase 26 if needed
- UWP app identity via AUMID (`GetApplicationUserModelId`) — deferred per REQUIREMENTS.md (APP-07, separate spike needed)

</deferred>

---

*Phase: 22-dlp-common-foundation*
*Context gathered: 2026-04-22*
