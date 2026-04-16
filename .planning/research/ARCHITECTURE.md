# Architecture Patterns — v0.4.0 Policy Authoring TUI

**Domain:** Policy CRUD TUI for existing DLP admin CLI
**Researched:** 2026-04-16
**Overall confidence:** HIGH (all findings from direct source reading)

---

## Existing Architecture — What v0.4.0 Adds To

### Current dispatch pattern (HIGH confidence — source-verified)

`dlp-admin-cli` is a pure state-machine TUI. Every screen is a variant of the
`Screen` enum in `app.rs`. Navigation is driven by:

1. `app.screen` — single field controls what is rendered and what key events mean
2. `screens/dispatch.rs` — one `handle_*` function per `Screen` variant; all wired
   in the top-level `handle_event` match
3. `screens/render.rs` — one `draw_*` function per `Screen` variant; wired in `draw_screen`
4. `App::rt.block_on(...)` — blocking async pattern; the TUI event loop is synchronous,
   async HTTP calls are executed via a captured `tokio::Runtime`

Purpose enums (`InputPurpose`, `PasswordPurpose`, `ConfirmPurpose`) carry multi-step
wizard state inside `Screen` variants. This is the idiomatic extension point.

### Existing policy-related screens (already in `Screen` enum)

- `PolicyMenu { selected }` — submenu already present; currently exposes Get/Create/Update/Delete via raw JSON file path inputs
- `PolicyList { policies, selected }` — already rendered; Enter navigates to `PolicyDetail`
- `PolicyDetail { policy }` — read-only JSON dump view
- `Confirm { message, yes_selected, purpose: ConfirmPurpose::DeletePolicy { id } }` — already used for delete confirmation

The existing policy screens are functional but use raw file-path inputs for create/update.
v0.4.0 replaces those flows with structured TUI forms.

---

## New Screen Variants Required

### Core policy lifecycle screens

| Screen Variant | Purpose | Parent Screen |
|---|---|---|
| `PolicyCreateForm { draft: PolicyDraft, focused_field: usize }` | New policy creation form — name, description, priority, action, enabled | `PolicyMenu` |
| `PolicyEditForm { policy_id: String, draft: PolicyDraft, focused_field: usize }` | Same form pre-filled for edit | `PolicyDetail` or `PolicyList` |
| `ConditionBuilder { conditions: Vec<PolicyCondition>, step: ConditionStep, pending: PendingCondition }` | Stepped attribute/op/value picker; used as sub-state embedded in the form | (sub-state of `PolicyCreateForm` / `PolicyEditForm`) |
| `PolicySimulate { draft: SimulateDraft, focused_field: usize, result: Option<EvaluateResult> }` | Fill EvaluateRequest, post to /evaluate, show decision | `PolicyMenu` |
| `PolicyImport { file_path: String, conflict_mode: ConflictMode }` | File path input + conflict choice | `PolicyMenu` |
| `PolicyExport { file_path: String, format: ExportFormat }` | File path + format choice | `PolicyMenu` |

### Supporting struct additions to `app.rs`

```rust
/// Working state for the policy create/edit form.
pub struct PolicyDraft {
    pub id: String,          // empty on create, filled on edit
    pub name: String,
    pub description: String,
    pub priority: String,    // string for editing; parsed to u32 on submit
    pub action: Decision,
    pub enabled: bool,
    pub conditions: Vec<PolicyCondition>,
}

/// Three-step condition picker state.
pub enum ConditionStep {
    PickAttribute { selected: usize },
    PickOperator  { attribute: AttributeKind, selected: usize },
    PickValue     { attribute: AttributeKind, op: String, input: String, selected: usize },
}

/// Tracks a condition in progress before it is committed to the list.
pub struct PendingCondition {
    pub step: ConditionStep,
}

pub enum AttributeKind {
    Classification,
    MemberOf,
    DeviceTrust,
    NetworkLocation,
    AccessContext,
}
```

### Purpose enum additions

```rust
// No new InputPurpose variants needed — structured forms replace the
// current TextInput-based policy flows.

// New ConfirmPurpose variant for the export overwrite prompt:
pub enum ConfirmPurpose {
    DeletePolicy { id: String },
    OverwriteExportFile { path: String, format: ExportFormat },  // NEW
}
```

---

## Conditions Builder Architecture

### Recommendation: embed as sub-state inside the form screen, not a separate modal

**Rationale:**

The existing TUI has no modal/overlay mechanism. Every `Screen` variant IS the
full screen. Introducing a true modal would require adding an `overlay: Option<ModalScreen>`
field to `App` and teaching `render.rs` to composite two layers — significant scope
increase with no other user in v0.4.0.

The SIEM and Alert config screens demonstrate the correct pattern: complex sub-state
(editing a specific field, bool toggles) is encoded directly inside the `Screen`
variant. The conditions builder follows the same pattern.

**Design: `ConditionStep` embedded in `PolicyCreateForm` / `PolicyEditForm`**

The form variant holds `conditions: Vec<PolicyCondition>` plus an optional
`pending: Option<PendingCondition>`. When `pending` is `Some`, the render function
draws the attribute/op/value picker in the lower portion of the form area (replacing
or extending the main form layout). When `pending` is `None`, the form shows the
current conditions list with an `[Add Condition]` entry at the bottom.

Keyboard flow:
1. User navigates to `[Add Condition]` in the form → sets `pending = Some(PendingCondition { step: PickAttribute { selected: 0 } })`
2. User picks attribute (Up/Down, Enter) → `step` advances to `PickOperator`
3. User picks operator → `step` advances to `PickValue`
4. User enters/picks value, presses Enter → condition serialised to `PolicyCondition`, pushed to `conditions`, `pending = None`
5. User presses Esc at any step → `pending = None` (cancel)

Each condition in the list has a `[x]` delete affordance navigable with Tab or a
dedicated key.

**Why not a separate screen:** The draft form data would need to survive a screen
transition, requiring either cloning into the next screen variant or storing it in
`App` as a separate field. Embedding avoids that coupling.

---

## PolicyMenu Changes

The existing `PolicyMenu` has 6 items (List, Get, Create, Update, Delete, Back).
Replace the old raw-JSON Create/Update entries with structured forms and add new items:

| Index | Item | Action |
|---|---|---|
| 0 | List Policies | `action_list_policies` (unchanged) |
| 1 | Create Policy | push `PolicyCreateForm` with empty `PolicyDraft` |
| 2 | Simulate Policy | push `PolicySimulate` with empty draft |
| 3 | Import Policies | push `PolicyImport` |
| 4 | Export Policies | push `PolicyExport` |
| 5 | Back | `Screen::MainMenu { selected: 1 }` |

Deleted: "Get Policy" (absorbed into PolicyList + PolicyDetail) and "Update Policy"
(absorbed into PolicyDetail → edit action). The count changes from 6 to 6 (same count,
different items) — the `nav(selected, 6, ...)` call in `handle_policy_menu` stays valid.

---

## PolicyList Changes

Add a keypress in `handle_policy_list`:

- `Enter` → `PolicyDetail` (unchanged)
- `n` or `Insert` → `PolicyCreateForm` with empty draft (shortcut)
- `e` → `PolicyEditForm` pre-filled from the selected policy
- `d` or `Delete` → `Confirm { purpose: ConfirmPurpose::DeletePolicy }` (unchanged path)

The `selected` index already tracks the highlighted row, so the selected
`PolicyResponse` is available for pre-filling the edit form.

---

## PolicyDetail Changes

Add keypresses in `handle_view` (currently handles `Enter`/`Esc` only):

- `e` → load the policy by ID and push `PolicyEditForm`
- `d` → push `Confirm { purpose: ConfirmPurpose::DeletePolicy }`

The `policy: serde_json::Value` stored in `PolicyDetail` already contains the full
`PolicyResponse` body needed to pre-fill the edit form draft.

---

## Data Flow: Create / Edit

```
PolicyCreateForm (draft in Screen variant)
  -> user fills name/desc/priority/action/enabled
  -> user adds conditions via ConditionBuilder sub-state
  -> [Save]: action_create_policy(draft) -> POST /admin/policies
             serialize draft.conditions: Vec<PolicyCondition> to serde_json::Value
             using serde_json::to_value(&conditions)?
  -> on success: set_status + navigate to PolicyList

PolicyEditForm (policy_id + draft in Screen variant)
  -> same form, pre-filled from PolicyResponse
  -> [Save]: action_update_policy(id, draft) -> PUT /admin/policies/{id}
  -> on success: set_status + navigate to PolicyDetail or PolicyList
```

The conditions `Vec<PolicyCondition>` is serialised to `serde_json::Value` at submit
time to match the `PolicyPayload.conditions: serde_json::Value` the server expects.
This is a one-way conversion at the boundary — the builder works with typed
`PolicyCondition` values internally throughout.

When loading a policy for edit, the `conditions: serde_json::Value` from
`PolicyResponse` must be deserialised back to `Vec<PolicyCondition>`:
```rust
let conditions: Vec<PolicyCondition> =
    serde_json::from_value(policy_response.conditions.clone())?;
```
This round-trip works because `PolicyCondition` uses `#[serde(tag = "attribute")]`
and the server stores the same JSON shape.

---

## Policy Simulate Data Flow

```
PolicySimulate screen
  -> fields: subject.user_sid, subject.user_name, subject.groups (comma-sep),
             subject.device_trust (picker), subject.network_location (picker),
             resource.path, resource.classification (picker),
             action (picker), environment.session_id
  -> [Run]: build EvaluateRequest, call POST /evaluate (unauthenticated endpoint)
  -> result stored in screen variant: Option<(Decision, Option<String>, String)>
  -> render shows decision + matched_policy_id + reason in a result panel
     within the same screen (no screen transition for the result — inline display)
```

`EvaluateRequest` and `EvaluateResponse` are already in `dlp-common::abac`, so the
CLI can use them directly with `dlp_common::EvaluateRequest`. The POST /evaluate
endpoint is unauthenticated and uses the same `client.post` helper.

---

## Import / Export: File Format Placement

### Recommendation: define the serialization types in `dlp-admin-cli`, not `dlp-common`

**Rationale:**

The server already has `PolicyPayload` and `PolicyResponse` in `dlp-server::admin_api`.
Import/export is a CLI-side administrative operation — no other crate needs it at runtime.
The server does not bulk-import/export; it only handles individual CRUD via the REST API.

Adding import/export types to `dlp-common` would introduce a file-format concern into
a shared crate consumed by `dlp-agent` and `dlp-user-ui`, which have no use for it.

**Format recommendation: TOML (primary), JSON (secondary via flag)**

TOML is already the agent config format in this project (agent-config.toml). It is
human-editable, comment-supporting, and unambiguous for the admin's use case of
reviewing and tweaking policy sets before importing.

The export file structs:

```rust
// In dlp-admin-cli, e.g. src/policy_file.rs

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyFile {
    pub version: u32,       // schema version, start at 1
    pub exported_at: String, // ISO 8601 timestamp
    pub policies: Vec<PolicyFileEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyFileEntry {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: Vec<PolicyCondition>,  // typed, not serde_json::Value
    pub action: String,
    pub enabled: bool,
}
```

`PolicyCondition` is in `dlp-common` so `PolicyFileEntry.conditions` can use the
typed enum directly — no duplication needed.

**Import conflict detection:**

On import, for each entry in the file, check if an ID already exists via
`GET /admin/policies/{id}`. If it does, present the admin with options:
- Skip (leave existing untouched)
- Replace (PUT with imported data)
- Rename (generate a new ID with a suffix)

The `PolicyImport` screen encodes this as a `ConflictMode` enum stored in the
`Screen` variant. Conflict resolution is per-file not per-policy (keep it simple
for v0.4.0).

---

## Component Boundaries

| Component | What Changes | Notes |
|---|---|---|
| `dlp-admin-cli/src/app.rs` | Add new `Screen` variants + supporting structs | Core state machine extension |
| `dlp-admin-cli/src/screens/dispatch.rs` | Add `handle_*` functions for new screens; extend `handle_policy_list`, `handle_policy_menu`, `handle_view` | All action functions (`action_*`) live here |
| `dlp-admin-cli/src/screens/render.rs` | Add `draw_*` functions for new screens | No logic — pure layout + widget calls |
| `dlp-admin-cli/src/policy_file.rs` | New file: `PolicyFile`, `PolicyFileEntry`, TOML read/write | Import/export logic |
| `dlp-common/src/abac.rs` | No changes needed | `PolicyCondition`, `EvaluateRequest`, etc. already correct |
| `dlp-server` | No changes needed | `/admin/policies` CRUD + `/evaluate` already complete |

---

## Build Order with Dependency Rationale

### Phase A — Conditions Builder (no API dependency)

Build `ConditionBuilder` sub-state types (`ConditionStep`, `AttributeKind`,
`PendingCondition`), the render function for the picker, and unit tests for the
step transitions. This has zero API dependency — it is pure local TUI state.

Delivers: the picker component that Phase B requires.

### Phase B — Policy Create Form (depends on A)

Add `PolicyDraft`, `PolicyCreateForm` screen variant, `handle_policy_create_form`,
`draw_policy_create_form`. Wire the ConditionBuilder sub-state from Phase A into the form.
Add `action_create_policy` which serialises `PolicyDraft` to `PolicyPayload` and calls
`POST /admin/policies`.

Delivers: POLICY-02 (create with conditions), POLICY-05 (structured picker).

Update `PolicyMenu` to route item 1 to `PolicyCreateForm` instead of the old
`TextInput { purpose: CreatePolicyFromFile }` path.

### Phase C — Policy Edit + Delete (depends on B, reuses A)

Add `PolicyEditForm` screen variant (reuses `PolicyDraft` and ConditionBuilder from A/B).
Add `action_update_policy` that calls `PUT /admin/policies/{id}`.
Extend `handle_policy_list` and `handle_view` with `e` / `d` keypresses.
The delete flow already works via `Confirm` — just wire it from the new entry points.

Delivers: POLICY-03 (edit), POLICY-04 (delete from list/detail), POLICY-01 (list already works).

### Phase D — Policy Simulate (depends on dlp-common types only, parallel-capable with B/C)

Add `PolicySimulate` screen variant and supporting draft struct. Build the EvaluateRequest
form fields (fixed number of fields, similar to the SIEM/Alert config pattern).
Add `action_simulate_policy` calling `POST /evaluate`.
Wire into `PolicyMenu` item 2.

Delivers: POLICY-06.

### Phase E — Import / Export (depends on B for `PolicyFileEntry` shape)

Create `policy_file.rs` with `PolicyFile` / `PolicyFileEntry` and TOML serialization.
Add `PolicyExport` and `PolicyImport` screen variants.
Implement `action_export_policies` (GET list + serialize + write file) and
`action_import_policies` (read file + conflict check + POST each entry).
Wire into `PolicyMenu` items 3 and 4.

Delivers: POLICY-07 (export), POLICY-08 (import).

**Dependency summary:**

```
A (ConditionBuilder types) --> B (CreateForm) --> C (EditForm)
                                               --> E (ImportExport, needs PolicyFileEntry shape)
D (Simulate) -- no dependency on A/B/C; parallel with B
```

Phases B and D can be developed in parallel after A is complete. Phase E needs B
complete so the file entry structure mirrors what the create form builds.

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: Storing policy draft in `App` as a top-level field

Putting `pending_draft: Option<PolicyDraft>` on `App` means two sources of truth when
the draft screen is active. The SIEM/Alert config precedent is correct: all screen
state lives inside the `Screen` variant. Follow that pattern.

### Anti-Pattern 2: Adding `PolicyCondition` serialization to `dlp-server`

The server's `PolicyPayload.conditions` is already `serde_json::Value`. Do not change
this to `Vec<PolicyCondition>`. The server is the authoritative persistence layer; the
CLI is the structured interface. Converting at the CLI boundary (as described above)
keeps the API surface stable and avoids forcing `dlp-agent` to depend on admin API types.

### Anti-Pattern 3: Using `TextInput` with raw JSON for condition entry

The existing `CreatePolicyFromFile` / `UpdatePolicyFile` flows are the exact pattern
to replace. Do not build the new create/edit forms as further variations of
`InputPurpose` over `TextInput`. The structured picker exists specifically to
eliminate this.

### Anti-Pattern 4: Separate TUI modal for the conditions builder

As discussed above, ratatui's widget model renders into a full frame each cycle.
There is no lightweight overlay/modal in the existing codebase. Introducing one adds
a new `App` field, double-dispatch in `handle_event`, and composite rendering. The
embedded sub-state pattern used by SIEM/Alert config handles the same requirement
with one-third the code.

### Anti-Pattern 5: Export format defined in `dlp-common`

`dlp-common` is consumed by `dlp-agent` at runtime on Windows endpoints. A policy
file format struct adds compile-time and binary-size cost to the agent crate with zero
operational benefit. Keep it in `dlp-admin-cli/src/policy_file.rs`.

---

## Integration Points Summary

| Existing Mechanism | How v0.4.0 Uses It |
|---|---|
| `Screen` enum in `app.rs` | Add 6 new variants (CreateForm, EditForm, Simulate, Import, Export + ConditionBuilder as sub-state) |
| `dispatch.rs` top-level match | Add 5 new `handle_*` arms; extend 3 existing (PolicyMenu, PolicyList, handle_view) |
| `render.rs` `draw_screen` match | Add 5 new `draw_*` arms |
| `App::rt.block_on(client.*())` | Action functions follow the exact same pattern; no new async machinery |
| `ConfirmPurpose` enum | Add `OverwriteExportFile` variant |
| `dlp-common::PolicyCondition` | Used typed in builder; serialised to `serde_json::Value` at API boundary |
| `dlp-common::EvaluateRequest / Response` | Used directly in PolicySimulate action |
| `EngineClient::post / get / put / delete` | All policy API calls use the existing generic HTTP helpers; no new client methods needed |

---

## Sources

All findings are from direct source reading — no external references needed.

- `dlp-admin-cli/src/app.rs` — `Screen` enum, `App` struct, purpose enums
- `dlp-admin-cli/src/screens/dispatch.rs` — full dispatch pattern, all action functions
- `dlp-admin-cli/src/screens/render.rs` — render pattern, SIEM/Alert form examples
- `dlp-admin-cli/src/client.rs` — `EngineClient` generic HTTP methods
- `dlp-common/src/abac.rs` — `PolicyCondition`, `EvaluateRequest`, `EvaluateResponse`, `Policy`
- `dlp-common/src/classification.rs` — `Classification` enum values
- `dlp-server/src/admin_api.rs` — `PolicyPayload`, `PolicyResponse`, `/admin/policies` routes, `/evaluate` handler
- `.planning/PROJECT.md` — v0.4.0 requirements POLICY-01 through POLICY-08
