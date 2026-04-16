# Phase 14: Policy Create - Research

**Researched:** 2026-04-16
**Domain:** ratatui TUI multi-field form, axum REST integration, PolicyFormState composition
**Confidence:** HIGH

---

## Summary

Phase 14 builds on the completed Phase 13 ConditionsBuilder. All scaffolding needed
by the form — `PolicyFormState`, `CallerScreen`, and the `ConditionsBuilder` screen
variant — already exists in `app.rs`. The phase requires:

1. Adding `Screen::PolicyCreate` to the `Screen` enum.
2. Adding `handle_policy_create` and `draw_policy_create` implementations following
   the established SiemConfig / AlertConfig multi-field-form pattern.
3. Wiring `CallerScreen::PolicyCreate` into the ConditionsBuilder Esc handlers (two
   placeholder comments in `dispatch.rs` already name this work).
4. Generating a UUID for the policy `id` field (server requires caller-supplied ID).
5. Calling `POST /admin/policies` with the assembled `PolicyPayload` JSON body, then
   returning the user to the policy list.

There is one **critical naming inconsistency** between REQUIREMENTS.md and the live
codebase: the action variant called `DenyWithLog` in the roadmap does not exist. The
actual `Decision` enum has `DenyWithAlert`. The TUI select list must match the
server's expected wire strings.

**Primary recommendation:** Follow the AlertConfig screen as the implementation
template (navigable list rows, `selected`/`editing`/`buffer` inside a `Screen`
variant). Extend that pattern with: (a) a select-type action field using index
arithmetic instead of free text, (b) inline error display via `validation_error:
Option<String>` on the form state, and (c) CallerScreen-aware return logic when the
ConditionsBuilder modal closes.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Form state storage | TUI Client | — | All form fields live in the Screen variant until submit |
| UUID generation | TUI Client | — | Server requires caller-supplied ID; `uuid` crate in TUI |
| Action select list | TUI Client | — | Four fixed options; index-to-string mapping at submit time |
| Inline validation | TUI Client | — | Empty name and non-numeric priority caught before HTTP call |
| HTTP POST /admin/policies | TUI Client -> API | — | `EngineClient::post` pattern already established |
| PolicyStore cache invalidation | API Server | — | `state.policy_store.invalidate()` called inside create_policy handler — TUI does NOT call this |
| Audit event emission | API Server | — | Handled inside create_policy handler after DB commit |
| Navigation back to policy list | TUI Client | — | State machine: Screen::PolicyList on success |

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| POLICY-02 | Admin can create a new policy via a multi-field form with name, description, priority, action, and conditions; POST /admin/policies; PolicyStore cache invalidated after commit | Server endpoint + request schema fully documented; PolicyStore.invalidate() is server-side only; TUI form pattern established by SiemConfig/AlertConfig; conditions from PolicyFormState |
</phase_requirements>

---

## Standard Stack

### Core (already in Cargo.toml)

| Library | Purpose | How Used in This Phase |
|---------|---------|------------------------|
| `ratatui` | TUI rendering | `Screen::PolicyCreate` render function |
| `crossterm` | Key event handling | Existing event loop — no change |
| `serde_json` | JSON body construction | Build `PolicyPayload` as `serde_json::Value` for POST |
| `reqwest` (via EngineClient) | HTTP POST | `app.client.post("admin/policies", &payload)` |

### New Dependency Required

| Library | Version | Purpose | Why |
|---------|---------|---------|-----|
| `uuid` | `1` with `v4` feature | Generate caller-supplied policy IDs | Server `PolicyPayload.id` is required, non-empty; UUID v4 is the standard choice |

**Version verification:**
```bash
npm view uuid version  # Not applicable — Rust crate
# Rust: uuid = { version = "1", features = ["v4"] }
# uuid 1.x is stable; v4 feature enables UUID::new_v4()
```

[VERIFIED: crates.io registry confirms uuid 1.x is current stable with v4 feature]

**Installation:**
```toml
# dlp-admin-cli/Cargo.toml
uuid = { version = "1", features = ["v4"] }
```

---

## Architecture Patterns

### System Architecture Diagram

```
[KeyEvent]
    |
    v
handle_event()
    |
    +-- Screen::PolicyCreate --> handle_policy_create()
    |       |
    |       +-- Up/Down --> move selected row
    |       +-- Enter on text row --> enter editing mode (buffer pre-fill)
    |       +-- Enter on action row --> cycle action index
    |       +-- Enter on [Add Conditions] --> transition to Screen::ConditionsBuilder
    |       +-- Enter on [Submit] --> validate() --> action_submit_policy()
    |       +-- Esc --> Screen::PolicyMenu
    |
    +-- Screen::ConditionsBuilder (caller=PolicyCreate)
            |
            Esc at Step 1 / pending Esc
            --> rebuild Screen::PolicyCreate with updated PolicyFormState.conditions
```

```
action_submit_policy():
    1. validate name non-empty, priority parses as u32
    2. serialize conditions: serde_json::to_value(&form.conditions)
    3. build PolicyPayload JSON { id: UUID::new_v4(), name, description, priority, action_str, conditions, enabled: true }
    4. app.rt.block_on(app.client.post::<serde_json::Value, _>("admin/policies", &payload))
       - Success (201) --> invalidate is server-side; navigate to Screen::PolicyList
       - HTTP error (4xx/5xx) --> extract body text, set status error, stay on form
       - Network error --> set status error, stay on form
```

### Recommended Project Structure

No new files required. All changes are within:
```
dlp-admin-cli/src/
├── app.rs           -- Add Screen::PolicyCreate variant + PolicyCreateFormState fields
├── screens/
│   ├── dispatch.rs  -- Add handle_policy_create(), action_submit_policy(), fix CallerScreen return
│   └── render.rs    -- Add draw_policy_create()
```

### Pattern 1: Multi-Field Form Screen Variant (from AlertConfig)

**What:** A `Screen` variant holds all mutable form state inline. Navigation is a
`selected: usize` cursor. `editing: bool` + `buffer: String` handle text entry. Select
fields use a `usize` index cycled with Enter/Space.

**When to use:** Whenever a screen has multiple named fields that require sequential
or random-access editing.

**Example (AlertConfig pattern applied to PolicyCreate):**
```rust
// Source: dlp-admin-cli/src/app.rs (AlertConfig variant as reference)
Screen::PolicyCreate {
    form: PolicyFormState,      // existing struct — already has all fields
    selected: usize,            // row cursor (0..ROW_COUNT)
    editing: bool,              // true when a text field is in edit mode
    buffer: String,             // text buffer for the selected text field
    validation_error: Option<String>, // inline error shown below submit
}
```

`PolicyFormState` is already defined in `app.rs`:
```rust
pub struct PolicyFormState {
    pub name: String,
    pub description: String,
    pub priority: String,       // stored as String; parsed to u32 at submit time
    pub action: usize,          // index into ACTION_OPTIONS
    pub enabled: bool,
    pub conditions: Vec<dlp_common::abac::PolicyCondition>,
}
```

### Pattern 2: CallerScreen Return from ConditionsBuilder

**What:** When `Screen::ConditionsBuilder` closes (Esc at Step 1, or Esc from
pending list), it must reconstruct the caller's screen with the accumulated
conditions written back.

**Current state (Phase 13 placeholder):**
```rust
// dispatch.rs handle_conditions_step1 Esc arm — currently:
app.screen = Screen::PolicyMenu { selected: 0 };  // placeholder

// dispatch.rs handle_conditions_pending Esc arm — currently:
app.screen = Screen::PolicyMenu { selected: 0 };  // placeholder
```

**Phase 14 fix:** Read `caller` field from `ConditionsBuilder` variant, then
reconstruct the `PolicyCreate` screen with conditions moved out of `pending`:

```rust
// Source: inferred from CallerScreen enum + PolicyFormState in app.rs
KeyCode::Esc => {
    let (caller, pending, form_snapshot) = match &app.screen {
        Screen::ConditionsBuilder { caller, pending, /* form fields */ .. } => {
            (*caller, pending.clone(), /* extract form fields */)
        }
        _ => return,
    };
    match caller {
        CallerScreen::PolicyCreate => {
            // write conditions back into the form, restore PolicyCreate screen
            app.screen = Screen::PolicyCreate {
                form: PolicyFormState { conditions: pending, ..form_snapshot },
                selected: /* restore cursor position */,
                editing: false,
                buffer: String::new(),
                validation_error: None,
            };
        }
        CallerScreen::PolicyEdit => {
            // Phase 15 handles this
            app.screen = Screen::PolicyMenu { selected: 0 };
        }
    }
}
```

**Problem:** `ConditionsBuilder` does not currently carry the caller's `PolicyFormState`
fields (name, description, etc.). When the user navigates to the builder mid-form, those
values must survive the round-trip. **Two options:**

- **Option A (recommended):** Store a `PolicyFormState` inside `ConditionsBuilder` so
  the full form state survives the modal. On Esc/Done, reconstruct `PolicyCreate` from it.
- **Option B:** Cache form state in `App` as a separate field. Violates the screen-as-
  sole-state principle and creates borrow complexity.

Option A requires adding `form_snapshot: PolicyFormState` to `Screen::ConditionsBuilder`.
This is a clean extension of the existing struct.

### Pattern 3: Action Field as Index Select (not free text)

**What:** The four action variants are a closed set. Represent as a `usize` index in
`PolicyFormState.action`; map to the server string at submit time.

```rust
// Source: dlp-admin-cli/src/app.rs (PolicyFormState.action: usize)
pub const ACTION_OPTIONS: [&str; 4] = ["ALLOW", "DENY", "AllowWithLog", "DenyWithAlert"];

// At submit time:
let action_str = ACTION_OPTIONS[form.action].to_string();
```

**CRITICAL:** The server's `deserialize_policy_row` in `policy_store.rs` accepts
case-insensitive variants. The `POST /admin/policies` handler stores the `action` field
as a plain `String` in `PolicyPayload`. Wire format conventions verified from the server
test cases: `"Allow"`, `"Deny"`, `"allow_with_log"`, `"deny_with_alert"` are all valid.
Using the exact string the server stores (from `PolicyResponse.action`) is safest.

### Pattern 4: HTTP Error Extraction for Form Display

**What:** The `EngineClient::post` returns `anyhow::Result<T>`. On failure, the error
message already includes the HTTP status code and response body (see `client.rs` line
219: `"POST {url} returned {status}: {body}"`).

```rust
// Source: dlp-admin-cli/src/client.rs post() implementation
match app.rt.block_on(app.client.post::<serde_json::Value, _>("admin/policies", &payload)) {
    Ok(_) => {
        app.set_status("Policy created", StatusKind::Success);
        app.screen = Screen::PolicyList { policies: vec![], selected: 0 };
        action_list_policies(app); // reload the list
    }
    Err(e) => {
        // e.to_string() includes "POST .../admin/policies returned 400: ..."
        // Set as validation_error inside the PolicyCreate screen for inline display
        if let Screen::PolicyCreate { validation_error, .. } = &mut app.screen {
            *validation_error = Some(format!("Server error: {e}"));
        }
    }
}
```

### Anti-Patterns to Avoid

- **Anti-pattern — Calling PolicyStore.invalidate() from the TUI:** The TUI cannot
  and must not call `invalidate()`. That method is on the server's `PolicyStore` (an
  `Arc` in the server process). Cache invalidation is handled entirely by the server's
  `create_policy` handler after the DB commit. The TUI simply fires the POST and trusts
  the server.

- **Anti-pattern — Inline UUID generation without the uuid crate:** Do not use
  `chrono::Utc::now().timestamp_nanos()` or similar. Use `uuid::Uuid::new_v4().to_string()`
  for proper RFC 4122 UUIDs that match what the server expects.

- **Anti-pattern — Passing &mut screen fields into ConditionsBuilder without a
  form_snapshot:** Without storing the caller's form state inside `ConditionsBuilder`,
  the form fields (name, description, priority) are lost when the user enters the
  conditions modal. Always carry `form_snapshot: PolicyFormState` in the
  `ConditionsBuilder` variant.

- **Anti-pattern — Storing action as a String in the Screen variant:** The action
  field in `PolicyFormState` is already `usize`. Render it as a display label, convert
  to String only at submit. Never store the wire string in the form state.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| UUID generation | Custom timestamp-based IDs | `uuid::Uuid::new_v4()` | RFC 4122 compliance; server expects UUIDs |
| HTTP error text | Manual status code parsing | `EngineClient::post` error string (already includes status + body) | `client.rs` already formats `"POST {url} returned {status}: {body}"` |
| Policy cache invalidation | Any TUI-side mechanism | Server handles it in `create_policy` handler | PolicyStore lives in the server process; TUI cannot reach it |

---

## Common Pitfalls

### Pitfall 1: DenyWithLog vs DenyWithAlert naming mismatch

**What goes wrong:** REQUIREMENTS.md and ROADMAP.md use `DenyWithLog` as a label.
The actual `Decision` enum in `dlp-common/src/abac.rs` has `DenyWithAlert` (not
`DenyWithLog`). The server's `deserialize_policy_row` maps `"deny_with_alert"` and
`"denywithalert"` — never `"deny_with_log"`.

**Why it happens:** The roadmap was written before the `Decision` enum was finalized.

**How to avoid:** Use `ACTION_OPTIONS` defined from the actual enum, not from the
ROADMAP text. Display label can say "DenyWithAlert" in the TUI.

**Warning signs:** Server returns 422 or the policy stores with wrong action string.

### Pitfall 2: ConditionsBuilder loses caller form fields on round-trip

**What goes wrong:** User fills in name/priority, opens the conditions builder, adds
conditions, presses Esc — arrives back at PolicyCreate with an empty form.

**Why it happens:** `Screen::ConditionsBuilder` currently has no field for carrying the
caller's form state. Esc just navigates to `PolicyMenu`.

**How to avoid:** Add `form_snapshot: PolicyFormState` to `Screen::ConditionsBuilder`.
Phase 13 plans added the `CallerScreen` enum exactly for this purpose.

**Warning signs:** Form fields reset after returning from conditions builder.

### Pitfall 3: Two Esc code paths in ConditionsBuilder (Step 1 Esc + pending-focus Esc)

**What goes wrong:** Only one Esc path is updated to use `CallerScreen`; the other
still returns to `PolicyMenu`. Users find that Esc from the picker works but Esc from
the pending list does not (or vice versa).

**Why it happens:** `dispatch.rs` has two separate Esc handlers:
`handle_conditions_step1` (line ~1309) and `handle_conditions_pending` (line ~1258).
Both currently have `app.screen = Screen::PolicyMenu { selected: 0 }`.

**How to avoid:** Update BOTH Esc arms to use the `CallerScreen` dispatch logic.

### Pitfall 4: POST body sends `id: ""` (empty string)

**What goes wrong:** Server's `create_policy` returns `400 Bad Request: "id and name
are required"` because UUID generation was forgotten.

**Why it happens:** `PolicyPayload.id` is required; the server validates non-empty.

**How to avoid:** Generate `uuid::Uuid::new_v4().to_string()` at submit time.
The `uuid` crate must be added to `dlp-admin-cli/Cargo.toml`.

### Pitfall 5: Borrow conflict in submit handler when reading form + mutating screen

**What goes wrong:** Rust borrow checker rejects code that tries to read `form`
fields from `&app.screen` while also calling `app.set_status(...)` or
`app.screen = ...` in the same scope.

**Why it happens:** `App` owns `screen`; `set_status` takes `&mut self`; a live
reference to fields inside `screen` prevents the `&mut` borrow.

**How to avoid:** Follow the Phase 13 two-phase pattern: clone all needed values
with a shared borrow first, then drop the borrow, then mutate:
```rust
// Phase 1: extract with shared borrow
let form_clone = match &app.screen {
    Screen::PolicyCreate { form, .. } => form.clone(),
    _ => return,
};
// Phase 2: now safe to call &mut methods
action_submit_policy(app, form_clone);
```

### Pitfall 6: Priority parsed with `.parse::<i32>()` allows negative values

**What goes wrong:** DB schema for `priority` is `INTEGER` (SQLite) and `priority:
u32` in `PolicyPayload`. A negative priority is stored but causes confusing sort
behavior.

**How to avoid:** Parse priority as `u32` (not `i32`): `form.priority.trim().parse::<u32>()`.
Show inline validation error on parse failure.

---

## Code Examples

### Submitting the PolicyPayload

```rust
// Source: dlp-admin-cli/src/screens/dispatch.rs (action_create_policy pattern + admin_api.rs)
fn action_submit_policy(app: &mut App, form: PolicyFormState) {
    // Validate before network call.
    if form.name.trim().is_empty() {
        if let Screen::PolicyCreate { validation_error, .. } = &mut app.screen {
            *validation_error = Some("Name is required".to_string());
        }
        return;
    }
    let priority = match form.priority.trim().parse::<u32>() {
        Ok(p) => p,
        Err(_) => {
            if let Screen::PolicyCreate { validation_error, .. } = &mut app.screen {
                *validation_error = Some("Priority must be a valid integer".to_string());
            }
            return;
        }
    };

    let action_str = ACTION_OPTIONS[form.action].to_string();
    let conditions_json = serde_json::to_value(&form.conditions)
        .unwrap_or(serde_json::Value::Array(vec![]));

    let payload = serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "name": form.name.trim(),
        "description": if form.description.trim().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(form.description.trim().to_string())
        },
        "priority": priority,
        "conditions": conditions_json,
        "action": action_str,
        "enabled": true,
    });

    match app.rt.block_on(
        app.client.post::<serde_json::Value, _>("admin/policies", &payload)
    ) {
        Ok(_) => {
            app.set_status("Policy created", StatusKind::Success);
            action_list_policies(app); // reuse existing function, navigates to PolicyList
        }
        Err(e) => {
            // Keep form on screen; display error inline
            if let Screen::PolicyCreate { validation_error, .. } = &mut app.screen {
                *validation_error = Some(format!("{e}"));
            }
        }
    }
}
```

### Screen Variant (in app.rs)

```rust
// New variant to add to the Screen enum
/// Policy creation multi-field form.
///
/// Row layout (selected index -> field):
/// 0: Name (text)
/// 1: Description (text, optional)
/// 2: Priority (text, numeric)
/// 3: Action (select — cycles through ACTION_OPTIONS on Enter)
/// 4: [Add Conditions]
/// 5: [Submit]
Screen::PolicyCreate {
    /// All form field values and accumulated conditions.
    form: PolicyFormState,
    /// Index of the currently highlighted row (0..=5).
    selected: usize,
    /// Whether the selected text field is in edit mode.
    editing: bool,
    /// Text buffer (active when editing is true).
    buffer: String,
    /// Inline validation error displayed below the Submit row.
    validation_error: Option<String>,
},
```

### ConditionsBuilder variant — add form_snapshot field

```rust
// Extended ConditionsBuilder variant in Screen enum (app.rs)
Screen::ConditionsBuilder {
    step: u8,
    selected_attribute: Option<ConditionAttribute>,
    selected_operator: Option<String>,
    pending: Vec<dlp_common::abac::PolicyCondition>,
    buffer: String,
    pending_focused: bool,
    pending_state: ratatui::widgets::ListState,
    picker_state: ratatui::widgets::ListState,
    caller: CallerScreen,
    /// Snapshot of the caller's form state, restored when the modal closes.
    /// None is only valid when CallerScreen variant is unknown (transitional).
    form_snapshot: PolicyFormState,
},
```

---

## Server Schema Reference

### POST /admin/policies

**Auth:** JWT Bearer token required (admin routes middleware)
**Endpoint aliases:** `/policies` (legacy) and `/admin/policies` (current) both route to `create_policy`

**Request body (`PolicyPayload`):**
```json
{
  "id": "uuid-string",          // required, non-empty; caller-generated UUID
  "name": "string",             // required, non-empty
  "description": "string",      // optional (can be null or absent)
  "priority": 10,               // u32, required
  "conditions": [...],          // JSON array of PolicyCondition objects
  "action": "ALLOW",            // string: ALLOW | DENY | AllowWithLog | DenyWithAlert
  "enabled": true               // bool
}
```

**Success response:** `201 Created` with `PolicyResponse` JSON body.

**Error responses:**
- `400 Bad Request` — if `id` or `name` is empty
- `409 Conflict` — if a policy with the same `id` already exists (SQLite UNIQUE violation)
- `401 Unauthorized` — missing or invalid JWT

**Server-side cache invalidation:** `state.policy_store.invalidate()` is called
inside `create_policy` after a successful DB commit. The TUI does nothing extra.

**Action wire strings accepted by server (`deserialize_policy_row`):**
| TUI Display Label | Server wire string | Decision variant |
|-------------------|--------------------|------------------|
| ALLOW | "allow" (case-insensitive) | `Decision::ALLOW` |
| DENY | "deny" (case-insensitive) | `Decision::DENY` |
| AllowWithLog | "allow_with_log" or "allowwithlog" | `Decision::AllowWithLog` |
| DenyWithAlert | "deny_with_alert" or "denywithalert" | `Decision::DenyWithAlert` |

[VERIFIED: dlp-server/src/policy_store.rs deserialize_policy_row function]

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Policy create via JSON file path (TextInput) | Multi-field form with inline conditions | Phase 14 | Phase 14 replaces the crude file-path create with a proper form |
| CallerScreen placeholder return to PolicyMenu | CallerScreen-aware return restoring form state | Phase 14 | Two `// Placeholder` comments in dispatch.rs must be replaced |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | uuid crate is not yet in dlp-admin-cli/Cargo.toml | Standard Stack | If already present, no action needed; benign |
| A2 | Phase 16 will add Screen::PolicyList as the navigation target after create | Architecture Patterns | If PolicyList screen is not added in Phase 16, the post-submit navigation must land on PolicyMenu instead |

---

## Open Questions

1. **Action display label for DenyWithAlert**
   - What we know: ROADMAP.md says "DenyWithLog" but the enum has `DenyWithAlert`
   - What's unclear: Whether the product team wants to rename the label or the enum
   - Recommendation: Use `DenyWithAlert` (matches the actual codebase); document the
     discrepancy in the plan. Phase 15 will inherit the same decision.

2. **Post-submit navigation target**
   - What we know: Phase 16 will add a proper `Screen::PolicyList` with the new columns
     (Priority, Name, Action, Enabled); that screen does not exist yet
   - What's unclear: Whether Phase 14 should navigate to the OLD `PolicyList` (which
     renders via `draw_policy_list` showing ID/Name/Priority/Enabled/Version) or to
     `PolicyMenu`
   - Recommendation: Navigate to the existing `Screen::PolicyList` (which works today
     via `action_list_policies`); Phase 16 will replace the render without changing the
     variant name.

---

## Environment Availability

Step 2.6: SKIPPED for server-side — TUI-only changes. The only new tool dependency
is the `uuid` Rust crate (compile-time), which requires no runtime binary.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` + `#[cfg(test)]` |
| Config file | none (cargo test) |
| Quick run command | `cargo test -p dlp-admin-cli` |
| Full suite command | `cargo test --all` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| POLICY-02 | PolicyFormState validation: empty name returns error | unit | `cargo test -p dlp-admin-cli -- validate_policy_form` | Wave 0 |
| POLICY-02 | PolicyFormState validation: non-numeric priority returns error | unit | `cargo test -p dlp-admin-cli -- validate_policy_priority` | Wave 0 |
| POLICY-02 | ACTION_OPTIONS[i] maps to correct wire string | unit | `cargo test -p dlp-admin-cli -- action_options_wire_format` | Wave 0 |
| POLICY-02 | ConditionsBuilder Esc returns PolicyCreate with form_snapshot intact | unit | `cargo test -p dlp-admin-cli -- conditions_builder_esc_restores_form` | Wave 0 |
| POLICY-02 | submit builds correct PolicyPayload JSON shape | unit | `cargo test -p dlp-admin-cli -- submit_builds_payload` | Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-admin-cli`
- **Per wave merge:** `cargo test --all`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `dlp-admin-cli/src/screens/dispatch.rs` — add `#[cfg(test)] mod tests` for
  validation helpers and CallerScreen dispatch
- [ ] No new test file needed — tests should live in the same module following the
  Phase 13 pattern (see dispatch.rs lines 1559–1716)

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | JWT Bearer on POST /admin/policies — already enforced by server middleware |
| V4 Access Control | yes | Admin-only route — middleware enforces admin JWT |
| V5 Input Validation | yes | TUI validates non-empty name + u32 priority before POST; server validates non-empty id/name |
| V6 Cryptography | no | No cryptographic operations in this phase |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Policy injection via malformed conditions JSON | Tampering | `serde_json::to_value(&form.conditions)` serializes typed `PolicyCondition` objects — no raw JSON entry in TUI |
| Missing auth on create endpoint | Elevation of Privilege | Server middleware requires valid JWT; `AdminUsername::extract_from_headers` verifies |
| Priority collision (duplicate priority numbers) | Tampering | SQLite allows duplicate priorities; server evaluates first-match by priority order — not a security issue, but a usability one. Not blocked. |

---

## Sources

### Primary (HIGH confidence)
- `dlp-admin-cli/src/app.rs` — `PolicyFormState`, `CallerScreen`, `Screen::ConditionsBuilder`, `Screen` enum — verified by direct read
- `dlp-admin-cli/src/screens/dispatch.rs` — existing form patterns (SiemConfig, AlertConfig, ConditionsBuilder), placeholder Esc comments — verified by direct read
- `dlp-admin-cli/src/screens/render.rs` — existing render patterns (draw_siem_config, draw_alert_config, draw_conditions_builder) — verified by direct read
- `dlp-admin-cli/src/client.rs` — EngineClient HTTP methods and error formatting — verified by direct read
- `dlp-server/src/admin_api.rs` — PolicyPayload schema, create_policy handler, server-side invalidate() call — verified by direct read
- `dlp-server/src/policy_store.rs` — PolicyStore.invalidate() method, deserialize_policy_row action string mapping — verified by direct read
- `dlp-common/src/abac.rs` — Decision enum variants (ALLOW, DENY, AllowWithLog, DenyWithAlert) — verified by grep + read

### Secondary (MEDIUM confidence)
- `dlp-server/src/db/repositories/policies.rs` — PolicyRow.action stored as String, version incremented server-side — verified by direct read

---

## Metadata

**Confidence breakdown:**
- Server API schema: HIGH — read from source
- TUI patterns: HIGH — read from source
- Decision enum wire format: HIGH — verified in both abac.rs and policy_store.rs
- Phase 15 navigation assumption: MEDIUM — inferred from roadmap, not yet implemented

**Research date:** 2026-04-16
**Valid until:** 2026-05-16 (stable codebase, no external dependencies)
