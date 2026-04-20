---
phase: 19-boolean-mode-tui-import-export
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - dlp-admin-cli/src/app.rs
  - dlp-admin-cli/src/screens/dispatch.rs
autonomous: true
requirements: [POLICY-09]

must_haves:
  truths:
    - "dlp-admin-cli::app::PolicyResponse carries a typed mode: PolicyMode field with #[serde(default)]"
    - "dlp-admin-cli::app::PolicyPayload carries a typed mode: PolicyMode field with #[serde(default)]"
    - "From<PolicyResponse> for PolicyPayload copies mode unchanged (PolicyMode: Copy)"
    - "PolicyFormState carries a pub mode: PolicyMode field (in-memory only, no serde attribute)"
    - "action_submit_policy sends mode in the POST body (fixes silent-drop bug)"
    - "action_submit_policy_update sends mode in the PUT body (fixes silent-drop bug)"
    - "action_load_policy_for_edit copies mode from the GET response into PolicyFormState"
    - "A PolicyResponse JSON literal without a mode key deserializes with mode = PolicyMode::ALL"
    - "A PolicyPayload round-trips through serde_json preserving ALL / ANY / NONE verbatim"
  artifacts:
    - path: "dlp-admin-cli/src/app.rs"
      provides: "PolicyFormState.mode, PolicyResponse.mode, PolicyPayload.mode, From impl copies mode, unit tests"
      contains: "pub mode: dlp_common::abac::PolicyMode"
    - path: "dlp-admin-cli/src/screens/dispatch.rs"
      provides: "mode in submit JSON payloads (POST + PUT), mode prefill in load_policy_into_form"
      contains: "\"mode\""
  key_links:
    - from: "dlp-admin-cli::app::PolicyFormState"
      to: "dlp_common::abac::PolicyMode"
      via: "direct field (pub mode: PolicyMode)"
      pattern: "pub mode: dlp_common::abac::PolicyMode"
    - from: "dlp-admin-cli::screens::dispatch::action_submit_policy"
      to: "HTTP POST body"
      via: "serde_json::json!({..., \"mode\": mode_str, ...})"
      pattern: "\"mode\""
    - from: "dlp-admin-cli::screens::dispatch::action_submit_policy_update"
      to: "HTTP PUT body"
      via: "serde_json::json!({..., \"mode\": mode_str, ...})"
      pattern: "\"mode\""
---

<objective>
Extend the admin-cli typed wire-format structs (`PolicyPayload`, `PolicyResponse`)
and the in-memory form state (`PolicyFormState`) with a `mode: PolicyMode` field,
and fix the two `serde_json::json!()` submit payload macros in
`dispatch.rs` so that POST/PUT requests carry the authored mode.
Without this plan, the TUI silently drops the mode (server `#[serde(default)]`
refills it to `ALL`), making mode unauthorable from the TUI even after Wave 2
adds the picker row.

Purpose: Unblock Wave 2. The TUI form row is useless unless the submit path
carries `mode` on the wire; the import/export round-trip is incorrect unless
the typed structs carry `mode` with `#[serde(default)]` for legacy-file
tolerance.

Output:
- Three struct extensions in `dlp-admin-cli/src/app.rs`
- Two JSON payload fixes + one prefill extension in `dlp-admin-cli/src/screens/dispatch.rs`
- Unit tests proving serde round-trip, legacy-default, and `From` field copy
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@.planning/ROADMAP.md
@.planning/REQUIREMENTS.md
@.planning/phases/19-boolean-mode-tui-import-export/19-CONTEXT.md
@.planning/phases/19-boolean-mode-tui-import-export/19-RESEARCH.md
@.planning/phases/19-boolean-mode-tui-import-export/19-PATTERNS.md
@.planning/phases/18-boolean-mode-engine-wire-format/SUMMARY.md

<interfaces>
<!-- Contracts the executor needs. Extracted from codebase. -->

From dlp-common/src/abac.rs §249-263 (already shipped in Phase 18):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PolicyMode {
    #[default]
    ALL,
    ANY,
    NONE,
}
```
Serializes verbatim to `"ALL"` / `"ANY"` / `"NONE"`. `PolicyMode: Copy`, so no `.clone()` needed.

From dlp-server/src/admin_api.rs §107-127 (already shipped in Phase 18 — shape to mirror verbatim):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPayload {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    #[serde(default)]
    pub mode: PolicyMode,
}
```

From dlp-admin-cli/src/app.rs §123-140 (CURRENT — extended by this plan):
```rust
#[derive(Debug, Clone, Default)]
pub struct PolicyFormState {
    pub name: String,
    pub description: String,
    pub priority: String,
    pub action: usize,
    pub enabled: bool,
    pub conditions: Vec<dlp_common::abac::PolicyCondition>,
    pub id: String,
    // NEW: pub mode: dlp_common::abac::PolicyMode,
}
```

From dlp-admin-cli/src/app.rs §241-284 (CURRENT — extended by this plan):
```rust
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PolicyResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    #[serde(default)]
    pub version: i64,
    #[serde(default)]
    pub updated_at: String,
    // NEW: #[serde(default)] pub mode: dlp_common::abac::PolicyMode,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyPayload {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    // NEW: #[serde(default)] pub mode: dlp_common::abac::PolicyMode,
}

impl From<PolicyResponse> for PolicyPayload {
    fn from(r: PolicyResponse) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            priority: r.priority,
            conditions: r.conditions,
            action: r.action,
            enabled: r.enabled,
            // NEW: mode: r.mode,
        }
    }
}
```

From dlp-admin-cli/src/screens/dispatch.rs §1321-1333 (CURRENT — POST payload, mode MISSING — bug):
```rust
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
    "enabled": form.enabled,
});
```

From dlp-admin-cli/src/screens/dispatch.rs §1610-1622 (CURRENT — PUT payload, mode MISSING — bug):
```rust
let payload = serde_json::json!({
    "id": id,
    "name": form.name.trim(),
    "description": if form.description.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(form.description.trim().to_string())
    },
    "priority": priority,
    "conditions": conditions_json,
    "action": action_str,
    "enabled": form.enabled,
});
```

From dlp-admin-cli/src/screens/dispatch.rs §1390-1401 (CURRENT — load_policy_into_form, mode MISSING):
```rust
let form = PolicyFormState {
    name: policy["name"].as_str().unwrap_or("").to_string(),
    description: policy["description"].as_str().unwrap_or("").to_string(),
    priority: policy["priority"]
        .as_i64()
        .map(|n| n.to_string())
        .unwrap_or_default(),
    action: action_idx,
    enabled: policy["enabled"].as_bool().unwrap_or(true),
    conditions,
    id: id.to_string(),
    // NEW: mode: <parsed from policy["mode"].as_str()>,
};
```
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Extend PolicyResponse, PolicyPayload, PolicyFormState, and From impl with mode field</name>
  <files>dlp-admin-cli/src/app.rs</files>
  <read_first>
    - dlp-admin-cli/src/app.rs (ENTIRE FILE — confirm struct line positions, existing serde attributes, and check the bottom of the file for an existing `#[cfg(test)] mod tests` block; if none exists, create one at the end)
    - dlp-common/src/abac.rs §249-263 (PolicyMode enum definition — MUST import via `dlp_common::abac::PolicyMode`, no local re-export)
    - dlp-server/src/admin_api.rs §107-127 (server-side PolicyPayload — verify mode field shape matches exactly)
  </read_first>
  <behavior>
    - Test 1 `test_policy_response_defaults_missing_mode_to_all`: JSON literal `{"id":"p","name":"n","description":null,"priority":1,"conditions":[],"action":"ALLOW","enabled":true}` deserializes into `PolicyResponse` with `mode == PolicyMode::ALL`.
    - Test 2 `test_policy_response_preserves_explicit_mode_any`: JSON literal with `"mode":"ANY"` deserializes into `PolicyResponse` with `mode == PolicyMode::ANY`.
    - Test 3 `test_policy_payload_roundtrips_all_three_modes`: Three `PolicyPayload` values (one per mode) serialize to JSON containing `"mode":"ALL"`, `"mode":"ANY"`, `"mode":"NONE"` verbatim, then deserialize back preserving each `mode` exactly.
    - Test 4 `test_policy_payload_legacy_default_on_missing_mode`: JSON literal without a `mode` key deserializes into `PolicyPayload` with `mode == PolicyMode::ALL`.
    - Test 5 `test_policy_response_into_payload_copies_mode`: `PolicyPayload::from(PolicyResponse { ..mode: PolicyMode::NONE })` produces a `PolicyPayload` with `mode == PolicyMode::NONE`.
    - Test 6 `test_policy_form_state_default_mode_is_all`: `PolicyFormState::default().mode == PolicyMode::ALL`.
  </behavior>
  <action>
    Write tests first (see Test 1-6 in &lt;behavior&gt; above), confirm they FAIL with a compile error (field does not exist), then implement:

    **Change 1 (dlp-admin-cli/src/app.rs §123-140):** Extend `PolicyFormState` by appending one field after the existing `id` field. Add a doc comment. NO `#[serde(default)]` — this struct is not a wire type (Research Pitfall 3, PATTERNS §92-94).

    Exact lines to insert (after line 139, before the closing `}`):
    ```rust
        /// Boolean composition mode (ALL / ANY / NONE). Defaults to ALL via
        /// `PolicyMode::default()`. In-memory UI state only — never serialized.
        pub mode: dlp_common::abac::PolicyMode,
    ```

    **Change 2 (dlp-admin-cli/src/app.rs §241-255):** Extend `PolicyResponse` by appending one field after `updated_at`. Insert BEFORE the closing `}` of the struct:
    ```rust
        /// Boolean composition mode for the conditions list. Defaults to ALL
        /// on legacy v0.4.0 exports that omit the field.
        #[serde(default)]
        pub mode: dlp_common::abac::PolicyMode,
    ```

    **Change 3 (dlp-admin-cli/src/app.rs §261-270):** Extend `PolicyPayload` by appending one field after `enabled`. Insert BEFORE the closing `}`:
    ```rust
        /// Boolean composition mode for the conditions list.
        #[serde(default)]
        pub mode: dlp_common::abac::PolicyMode,
    ```

    **Change 4 (dlp-admin-cli/src/app.rs §272-284):** Extend `From<PolicyResponse> for PolicyPayload` by appending `mode: r.mode,` after `enabled: r.enabled,`. `PolicyMode: Copy`, so this is a field copy, not a clone. Final shape:
    ```rust
    impl From<PolicyResponse> for PolicyPayload {
        fn from(r: PolicyResponse) -> Self {
            Self {
                id: r.id,
                name: r.name,
                description: r.description,
                priority: r.priority,
                conditions: r.conditions,
                action: r.action,
                enabled: r.enabled,
                mode: r.mode,
            }
        }
    }
    ```

    **Change 5 (new `#[cfg(test)] mod tests` block at bottom of dlp-admin-cli/src/app.rs):**
    Append (or extend if tests module already exists at EOF):
    ```rust
    #[cfg(test)]
    mod tests {
        use super::*;
        use dlp_common::abac::PolicyMode;

        #[test]
        fn test_policy_response_defaults_missing_mode_to_all() {
            let json = r#"{"id":"p","name":"n","description":null,"priority":1,"conditions":[],"action":"ALLOW","enabled":true}"#;
            let got: PolicyResponse = serde_json::from_str(json).expect("deserialize without mode");
            assert_eq!(got.mode, PolicyMode::ALL);
        }

        #[test]
        fn test_policy_response_preserves_explicit_mode_any() {
            let json = r#"{"id":"p","name":"n","description":null,"priority":1,"conditions":[],"action":"ALLOW","enabled":true,"mode":"ANY"}"#;
            let got: PolicyResponse = serde_json::from_str(json).expect("deserialize with mode=ANY");
            assert_eq!(got.mode, PolicyMode::ANY);
        }

        #[test]
        fn test_policy_payload_roundtrips_all_three_modes() {
            for mode in [PolicyMode::ALL, PolicyMode::ANY, PolicyMode::NONE] {
                let payload = PolicyPayload {
                    id: "p".into(),
                    name: "n".into(),
                    description: None,
                    priority: 1,
                    conditions: serde_json::json!([]),
                    action: "DENY".into(),
                    enabled: true,
                    mode,
                };
                let json = serde_json::to_string(&payload).expect("serialize");
                let expected = match mode {
                    PolicyMode::ALL => "\"mode\":\"ALL\"",
                    PolicyMode::ANY => "\"mode\":\"ANY\"",
                    PolicyMode::NONE => "\"mode\":\"NONE\"",
                };
                assert!(json.contains(expected), "json `{json}` missing `{expected}`");
                let round_trip: PolicyPayload =
                    serde_json::from_str(&json).expect("deserialize");
                assert_eq!(round_trip.mode, mode);
            }
        }

        #[test]
        fn test_policy_payload_legacy_default_on_missing_mode() {
            let json = r#"{"id":"p","name":"n","description":null,"priority":1,"conditions":[],"action":"ALLOW","enabled":true}"#;
            let got: PolicyPayload = serde_json::from_str(json).expect("legacy deserialize");
            assert_eq!(got.mode, PolicyMode::ALL);
        }

        #[test]
        fn test_policy_response_into_payload_copies_mode() {
            let resp = PolicyResponse {
                id: "p".into(),
                name: "n".into(),
                description: None,
                priority: 1,
                conditions: serde_json::json!([]),
                action: "DENY".into(),
                enabled: true,
                version: 0,
                updated_at: String::new(),
                mode: PolicyMode::NONE,
            };
            let payload: PolicyPayload = resp.into();
            assert_eq!(payload.mode, PolicyMode::NONE);
        }

        #[test]
        fn test_policy_form_state_default_mode_is_all() {
            let form = PolicyFormState::default();
            assert_eq!(form.mode, PolicyMode::ALL);
        }
    }
    ```

    Per CLAUDE.md §9.8 these are `#[cfg(test)]` module tests. Per §9.2 use 4-space indent and snake_case test names. Per §9.4 no `.unwrap()` in production code — test bodies are allowed `.expect("...")` with descriptive messages.
  </action>
  <verify>
    <automated>cargo test -p dlp-admin-cli --lib test_policy_response_defaults_missing_mode_to_all test_policy_response_preserves_explicit_mode_any test_policy_payload_roundtrips_all_three_modes test_policy_payload_legacy_default_on_missing_mode test_policy_response_into_payload_copies_mode test_policy_form_state_default_mode_is_all</automated>
  </verify>
  <acceptance_criteria>
    - `grep -n "pub mode: dlp_common::abac::PolicyMode" dlp-admin-cli/src/app.rs` shows THREE lines (one in PolicyFormState, one in PolicyResponse, one in PolicyPayload)
    - `grep -n "#\[serde(default)\]" dlp-admin-cli/src/app.rs` shows at least FOUR lines (existing two on version/updated_at plus two new on PolicyResponse.mode and PolicyPayload.mode — NOT on PolicyFormState.mode)
    - `grep -n "mode: r.mode" dlp-admin-cli/src/app.rs` shows at least ONE line (in the `From` impl)
    - `cargo test -p dlp-admin-cli --lib test_policy_response_defaults_missing_mode_to_all` → PASS
    - `cargo test -p dlp-admin-cli --lib test_policy_response_preserves_explicit_mode_any` → PASS
    - `cargo test -p dlp-admin-cli --lib test_policy_payload_roundtrips_all_three_modes` → PASS
    - `cargo test -p dlp-admin-cli --lib test_policy_payload_legacy_default_on_missing_mode` → PASS
    - `cargo test -p dlp-admin-cli --lib test_policy_response_into_payload_copies_mode` → PASS
    - `cargo test -p dlp-admin-cli --lib test_policy_form_state_default_mode_is_all` → PASS
    - `cargo check -p dlp-admin-cli` → no warnings, no errors
  </acceptance_criteria>
  <done>All 6 new unit tests pass; `cargo check -p dlp-admin-cli` is warning-free; grep checks above all match.</done>
</task>

<task type="auto">
  <name>Task 2: Add mode to POST and PUT submit JSON payloads + prefill mode on load-for-edit</name>
  <files>dlp-admin-cli/src/screens/dispatch.rs</files>
  <read_first>
    - dlp-admin-cli/src/screens/dispatch.rs §1280-1356 (entire `action_submit_policy` function — the POST path)
    - dlp-admin-cli/src/screens/dispatch.rs §1362-1417 (entire `action_load_policy_for_edit` function — the edit-form prefill path)
    - dlp-admin-cli/src/screens/dispatch.rs §1566-1644 (entire `action_submit_policy_update` function — the PUT path)
    - dlp-admin-cli/src/screens/dispatch.rs §1-50 (confirm existing imports; check whether `PolicyMode` is already imported in this file)
    - .planning/phases/19-boolean-mode-tui-import-export/19-RESEARCH.md §349-361 (Pitfall 1 — the silent-drop bug this task fixes)
    - .planning/phases/19-boolean-mode-tui-import-export/19-PATTERNS.md §172-244 (submit payload analog + load_policy_into_form extension pattern)
  </read_first>
  <action>
    This task fixes the Phase 19 wire-format silent-drop bug identified in RESEARCH Pitfall 1 and wires up mode prefill on edit.

    **Change 1 — Add import (if not already present):** Near the top of `dlp-admin-cli/src/screens/dispatch.rs` (with the other `use dlp_common::abac::*;` style imports near line 1-50), add:
    ```rust
    use dlp_common::abac::PolicyMode;
    ```
    If `dlp_common::abac::PolicyMode` is already imported (e.g., via a grouped `use`), skip this change. If only `PolicyCondition` is in a grouped `use dlp_common::abac::{PolicyCondition}`, extend the grouping to `use dlp_common::abac::{PolicyCondition, PolicyMode}`.

    **Change 2 — Introduce an inline helper** immediately above `action_submit_policy` (dispatch.rs §1280 — add as a free function at file scope, top-level):
    ```rust
    /// Maps a `PolicyMode` to its wire-format string. The server accepts the
    /// verbatim variant names `"ALL"` / `"ANY"` / `"NONE"` per Phase 18 D-02.
    ///
    /// Mirrors the `mode_str` helper in `dlp-server/src/policy_store.rs` §29 —
    /// duplicated here because that helper is `pub(crate)` to its server crate.
    fn policy_mode_to_wire(mode: PolicyMode) -> &'static str {
        match mode {
            PolicyMode::ALL => "ALL",
            PolicyMode::ANY => "ANY",
            PolicyMode::NONE => "NONE",
        }
    }
    ```
    Per CLAUDE.md §9.3 the doc comment is required. Per §9.10 the match is exhaustive (no `_`).

    **Change 3 — POST payload (dispatch.rs §1321-1333):** Add one key-value line to the `serde_json::json!` macro. Insert between the existing `"enabled": form.enabled,` line and the closing `});`:
    ```rust
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
            "enabled": form.enabled,
            "mode": policy_mode_to_wire(form.mode),
        });
    ```

    **Change 4 — PUT payload (dispatch.rs §1610-1622):** Identical addition in `action_submit_policy_update`. Insert between `"enabled": form.enabled,` and the closing `});`:
    ```rust
        let payload = serde_json::json!({
            "id": id,
            "name": form.name.trim(),
            "description": if form.description.trim().is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(form.description.trim().to_string())
            },
            "priority": priority,
            "conditions": conditions_json,
            "action": action_str,
            "enabled": form.enabled,
            "mode": policy_mode_to_wire(form.mode),
        });
    ```

    **Change 5 — Prefill on load (dispatch.rs §1390-1401):** Extend the `let form = PolicyFormState { ... };` literal in `action_load_policy_for_edit`. Insert a new line between `conditions,` and `id: id.to_string(),` (keeping declaration order close to the wire-order in `PolicyResponse`). Final shape:
    ```rust
            let form = PolicyFormState {
                name: policy["name"].as_str().unwrap_or("").to_string(),
                description: policy["description"].as_str().unwrap_or("").to_string(),
                priority: policy["priority"]
                    .as_i64()
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                action: action_idx,
                enabled: policy["enabled"].as_bool().unwrap_or(true),
                conditions,
                mode: match policy["mode"].as_str() {
                    Some("ALL") => PolicyMode::ALL,
                    Some("ANY") => PolicyMode::ANY,
                    Some("NONE") => PolicyMode::NONE,
                    _ => PolicyMode::ALL,
                },
                id: id.to_string(),
            };
    ```
    The `_ => PolicyMode::ALL` fallback matches the `unwrap_or(true)` / `unwrap_or("ALLOW")` tolerant-read pattern used elsewhere in this function (dispatch.rs §1398, §1368). Per CLAUDE.md §9.4, no `.unwrap()` is used.

    **Do NOT** refactor to typed-struct serialization in this plan (the research "Open Question 1" alternative) — the minimal-diff approach above is sufficient to fix the bug and lands a 4-line change per call site. The typed-struct refactor can be a follow-up if operational feedback warrants.

    **Do NOT** change any row-index constants, render arms, or POLICY_FIELD_LABELS in this plan — those are Wave 2's responsibility and depend on POLICY_MODE_ROW insertion. This plan is purely wire-format plumbing.
  </action>
  <verify>
    <automated>cargo check -p dlp-admin-cli --tests &amp;&amp; cargo clippy -p dlp-admin-cli --lib -- -D warnings</automated>
  </verify>
  <acceptance_criteria>
    - `grep -n "fn policy_mode_to_wire" dlp-admin-cli/src/screens/dispatch.rs` → exactly ONE match
    - `grep -n "\"mode\": policy_mode_to_wire(form.mode)" dlp-admin-cli/src/screens/dispatch.rs` → exactly TWO matches (one in `action_submit_policy`, one in `action_submit_policy_update`)
    - `grep -n "mode: match policy\[\"mode\"\].as_str()" dlp-admin-cli/src/screens/dispatch.rs` → exactly ONE match (in `action_load_policy_for_edit`)
    - `grep -n "use dlp_common::abac::PolicyMode" dlp-admin-cli/src/screens/dispatch.rs` OR `grep -n "dlp_common::abac::{.*PolicyMode" dlp-admin-cli/src/screens/dispatch.rs` → at least ONE match
    - `cargo check -p dlp-admin-cli --tests` → compiles cleanly, zero warnings
    - `cargo clippy -p dlp-admin-cli --lib -- -D warnings` → passes
    - `cargo test -p dlp-admin-cli --lib` → all 6 tests from Task 1 still pass (no regression)
  </acceptance_criteria>
  <done>Both `json!()` macros send `"mode"`; `load_policy_into_form` prefills `form.mode` from the GET response; clippy is clean; no regressions.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| admin-cli → dlp-server HTTP | Authenticated (JWT) admin POST/PUT bodies cross here; server validates and persists |
| JSON file → admin-cli import | User-supplied JSON deserialized into `Vec<PolicyResponse>` via `serde_json::from_str` |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-19-01 | Tampering | Policy wire payload | mitigate | `PolicyMode` is an exhaustive enum; serde rejects any string not in `{"ALL","ANY","NONE"}`. `policy_mode_to_wire` produces only those three values — no attacker-controlled string flows into the payload. |
| T-19-02 | Information Disclosure | Mode value in HTTP body | accept | Mode is a low-sensitivity authorization attribute, not PII or a secret; JWT-protected admin channel is already the appropriate boundary per Phase 9. |
| T-19-03 | Denial of Service | Malformed import JSON | mitigate | Import pipeline already delegates to `serde_json::from_str::<Vec<PolicyResponse>>`; `#[serde(default)]` on `mode` means legacy files without the key deserialize successfully rather than failing the entire import batch. Malformed mode strings fail cleanly with a `serde_json::Error` per Phase 18 T10 hardening. |
| T-19-04 | Repudiation | Edit-path prefill accepts any string | accept | `action_load_policy_for_edit` uses a tolerant match with `_ => PolicyMode::ALL` fallback, consistent with the existing `unwrap_or("ALLOW")` pattern for `action` at §1368. Admin operations are captured via Phase 9 admin audit logging at the server side. |
</threat_model>

<verification>
Overall Wave 1 verification (run before commit):
- `cargo fmt --all -- --check` → clean
- `cargo clippy --workspace --lib -- -D warnings` → clean
- `cargo test -p dlp-admin-cli --lib` → all prior tests + 6 new tests pass
- `cargo check --workspace` → clean
</verification>

<success_criteria>
- All 6 new unit tests in `dlp-admin-cli/src/app.rs` pass.
- `grep "mode" dlp-admin-cli/src/screens/dispatch.rs` shows the field present in both `json!()` macros and the `load_policy_into_form` prefill.
- Workspace builds zero-warning via `cargo check --workspace`.
- Wave 2 can now assume `PolicyFormState.mode`, `PolicyResponse.mode`, `PolicyPayload.mode`, and the submit path carrying `mode` all exist — Wave 2 becomes a pure TUI rendering/dispatch task.
</success_criteria>

<output>
After completion, Wave 2 (plan 02) can:
1. Insert `POLICY_MODE_ROW = 5` and renumber the three trailing row constants (in `dispatch.rs` §873-887).
2. Add the cycle-on-Enter arm in both `handle_policy_create_nav` and `handle_policy_edit_nav` that mutates `form.mode` (which this plan added).
3. Extend `POLICY_FIELD_LABELS` from 8 to 9 rows and add the matching `5 => ...` render arm in both `draw_policy_create` and `draw_policy_edit`.
4. Add the footer advisory overlay gated on `form.mode != PolicyMode::ALL && form.conditions.is_empty()`.
5. Create the `dlp-server/tests/mode_end_to_end.rs` integration tests.

Create `.planning/phases/19-boolean-mode-tui-import-export/19-01-SUMMARY.md` covering:
- Exact struct field additions (three structs + From impl + 6 tests)
- The two JSON-payload fix locations (dispatch.rs §1321, §1610)
- The edit-form prefill extension (dispatch.rs §1390)
- Verification outputs (cargo test / clippy / fmt / check)
- Any deviations from this plan (e.g., if `PolicyMode` was already imported in a grouped `use`)
</output>
