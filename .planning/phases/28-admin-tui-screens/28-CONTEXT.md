# Phase 28: Admin TUI Screens - Context

**Gathered:** 2026-04-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Three deliverables in `dlp-admin-cli`, plus one new server-side API:

1. **Device Registry TUI screen** — list/register/delete USB devices against the existing `GET/POST/DELETE /admin/device-registry` API.
2. **Managed Origins TUI screen + server API** — new `managed_origins` DB table + `GET/POST/DELETE /admin/managed-origins` endpoints; TUI surfaces list/add/remove of URL-pattern origin strings.
3. **App-identity conditions builder extension** — add `SourceApplication` and `DestinationApplication` as two new `ConditionAttribute` variants in the existing 3-step picker; add a field sub-picker between Steps 1 and 2.

Requirements in scope: APP-04, BRW-02

</domain>

<decisions>
## Implementation Decisions

### Device Registry TUI Screen

- **D-01:** List display is compact one-line-per-device: `[TRUST_TIER] VID:{vid} PID:{pid} "{description}"`. Matches `PolicyList` density.
- **D-02:** Register flow uses sequential text inputs — one field at a time: VID → PID → serial → description → trust tier. Uses `Screen::TextInput` + `InputPurpose` for each step, accumulating into a new `DeviceRegisterState` or equivalent accumulator in the `App`.
- **D-03:** Trust tier step cycles on Enter: `blocked` → `read_only` → `full_access`. Matches the DeviceTrust/NetworkLocation cycle pattern in `PolicySimulate`.
- **D-04:** Delete uses `Screen::Confirm` with a new `ConfirmPurpose::DeleteDevice { id: String }`.
- **D-05:** Keyboard shortcuts on the list: `r` to start register flow, `d` to delete selected device, Enter to (optionally) view detail. Matches `PolicyList` key conventions.

### Managed Origins TUI Screen + Server API

- **D-06:** A "managed origin" is a **URL pattern string** (e.g. `"https://company.sharepoint.com/*"`). One field per entry. This matches the Chrome Enterprise Content Analysis connector format that Phase 29 will consume.
- **D-07:** New `managed_origins` DB table: `id TEXT PRIMARY KEY` (UUID), `origin TEXT NOT NULL UNIQUE`. Follows the `device_registry` table pattern exactly.
- **D-08:** Server API endpoints:
  - `GET /admin/managed-origins` — **unauthenticated** (Phase 29 agent/Chrome connector polls it); returns `Vec<{ id, origin }>`.
  - `POST /admin/managed-origins` — JWT-protected; body `{ "origin": "https://..." }`; upserts on `origin` conflict.
  - `DELETE /admin/managed-origins/{id}` — JWT-protected; deletes by UUID.
  All three mirror the device-registry route pattern in `admin_api.rs`.
- **D-09:** Add flow is a single text input (the URL pattern string). Uses `Screen::TextInput` + a new `InputPurpose::AddManagedOrigin`.
- **D-10:** Delete uses `Screen::Confirm` with a new `ConfirmPurpose::DeleteManagedOrigin { id: String }`.

### App-Identity Conditions Builder Extension

- **D-11:** Two new `ConditionAttribute` variants: `SourceApplication` and `DestinationApplication`. Added to the existing enum in `app.rs`. They appear as two distinct choices at Step 1 alongside the existing five attributes.
- **D-12:** A new sub-step is inserted between Step 1 and Step 2: an **AppField picker** showing `publisher`, `image_path`, `trust_tier`. Stored as a new field `selected_field: Option<dlp_common::abac::AppField>` on the `Screen::ConditionsBuilder` variant. The `step: u8` field stays 1/2/3; sub-step position is tracked by whether `selected_field` is `None` (sub-step not yet resolved) vs `Some(field)` (ready to advance to Step 2).
- **D-13:** Operator set is field-constrained:
  - `publisher`, `image_path` → `eq`, `ne`, `contains`
  - `trust_tier` → `eq`, `ne` only
  Implemented by extending `operators_for()` dispatch to handle the two new `ConditionAttribute` variants (with field argument, or by branching on `selected_field` in the builder state).
- **D-14:** Value entry:
  - `publisher`, `image_path` → free-text buffer input (same path as `MemberOf`).
  - `trust_tier` → list picker showing `trusted`, `untrusted`, `unknown` (same path as Classification Step 3).
- **D-15:** Wire format at construction: `PolicyCondition::SourceApplication { field: AppField, op: String, value: String }` / `PolicyCondition::DestinationApplication { ... }`. Already defined in Phase 26 (D-01/D-02 of 26-CONTEXT.md). TUI constructs these directly at Step 3 commit.

### Navigation Wiring

- **D-16:** Device Registry and Managed Origins screens are reachable from a new **"Devices & Origins"** submenu in `MainMenu`. This keeps `SystemMenu` focused on server/agent ops and avoids overloading `PolicyMenu`.
- **D-17:** `ConditionsBuilder` app-identity variants are wired into the existing conditions builder flow — no new menu entry needed.

### Claude's Discretion

- Exact field name and type for the accumulator that holds in-progress Device Register state across the sequential TextInput steps (could be fields on `App`, or a dedicated struct stored in a new `Screen` variant, or an `InputPurpose` chain)
- Whether the `operators_for()` function signature changes to accept an `Option<AppField>` parameter or whether dispatch branches in the caller before calling `operators_for()`
- Exact column order and alignment for the one-line device list format
- Whether `GET /admin/managed-origins` returns plain `Vec<String>` or `Vec<{ id, origin }>` (recommend `Vec<{ id, origin }>` so the TUI has UUIDs for delete without a second lookup)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements
- `.planning/REQUIREMENTS.md` — APP-04 and BRW-02 requirement definitions
- `.planning/ROADMAP.md` §Phase 28 — 4 success criteria

### Prior Phase Context (must read for patterns)
- `.planning/phases/24-device-registry-db-admin-api/24-CONTEXT.md` — Device registry API shape, D-01..D-12; upsert-on-conflict pattern
- `.planning/phases/26-abac-enforcement-convergence/26-CONTEXT.md` — `PolicyCondition::SourceApplication`/`DestinationApplication` wire format (D-01, D-02); `AppField` enum (D-02)

### Key Source Files (read before touching)
- `dlp-admin-cli/src/app.rs` — `Screen` enum, `ConditionAttribute` enum, `ConditionsBuilder` variant, all `InputPurpose`/`ConfirmPurpose` variants
- `dlp-admin-cli/src/screens/dispatch.rs` — `operators_for()`, `value_count_for()`, `condition_to_prefill()`, `ConditionsBuilder` event handling
- `dlp-admin-cli/src/screens/render.rs` — all `Screen` render arms (match existing layout style)
- `dlp-server/src/admin_api.rs` — `DeviceRegistryRequest`/`DeviceRegistryResponse`, route registration pattern (lines 528, 586–590), handler pattern
- `dlp-server/src/db/repositories/` — `DeviceRegistryRepository` as the model for `ManagedOriginsRepository`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `Screen::Confirm` + `ConfirmPurpose` — delete confirmation dialogs; add two new `ConfirmPurpose` variants (`DeleteDevice`, `DeleteManagedOrigin`)
- `Screen::TextInput` + `InputPurpose` — sequential field entry; add `InputPurpose::AddManagedOrigin` and device register step purposes
- `ConditionAttribute` enum + `operators_for()` / `value_count_for()` — extend with `SourceApplication`, `DestinationApplication` variants
- `DeviceRegistryRepository` in `dlp-server/src/db/repositories/device_registry.rs` — template for `ManagedOriginsRepository`
- `list_device_registry_handler` / `upsert_device_registry_handler` / `delete_device_registry_handler` in `admin_api.rs` — template for managed-origins handlers

### Established Patterns
- Screen state machine: each screen variant owns its full display state; navigation is `App.screen = Screen::NextScreen { ... }`
- Sequential text input chain: `InputPurpose` carries the "next step" intent; dispatch handler transitions to next purpose after each Enter
- DB-backed config: SQLite table + repository struct + admin API (GET unauthenticated, POST/DELETE JWT) + TUI screen — established on SIEM, alert, device-registry
- Conditions builder sub-flow: `step: u8` + optional state fields track position; Step 3 commit constructs `PolicyCondition` and pushes to `pending`

### Integration Points
- `MainMenu` in `app.rs` and `dispatch.rs` — add "Devices & Origins" menu item and `Screen::DevicesMenu { selected: usize }` variant
- `Screen::ConditionsBuilder` variant in `app.rs` — add `selected_field: Option<dlp_common::abac::AppField>` field
- `dlp-server/src/db/mod.rs` — add `managed_origins` table DDL and `run_migrations()` call
- Route registration in `admin_api.rs` around lines 528/586 — add managed-origins routes

</code_context>

<specifics>
## Specific Ideas

- The one-line device list format should use the trust tier as a tag prefix: `[BLOCKED]`, `[READ_ONLY]`, `[FULL_ACCESS]` — uppercase, bracket-delimited, consistent with audit log style used elsewhere
- `GET /admin/managed-origins` should return `Vec<{ id, origin }>` (not bare strings) so the TUI has UUIDs for delete without a second lookup

</specifics>

<deferred>
## Deferred Ideas

- None — discussion stayed within phase scope

</deferred>

---

*Phase: 28-admin-tui-screens*
*Context gathered: 2026-04-23*
