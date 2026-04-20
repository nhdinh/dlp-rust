# Phase 19: Boolean Mode in TUI + Import/Export - Pattern Map

**Mapped:** 2026-04-20
**Files analyzed:** 4 modified + 1 new
**Analogs found:** 5 / 5

## File Classification

| File | New/Modified | Role | Data Flow | Closest Analog | Match Quality |
|------|--------------|------|-----------|----------------|---------------|
| `dlp-admin-cli/src/app.rs` | modified | struct-def (form state + typed wire) | state-to-render + wire-roundtrip | `dlp-server/src/admin_api.rs` §107-127 (server-side `PolicyPayload` with `#[serde(default)] mode`) | exact |
| `dlp-admin-cli/src/screens/dispatch.rs` | modified | handler (event-to-dispatch) + HTTP-roundtrip | event-to-dispatch + request-response | `POLICY_ACTION_ROW` cycler §1232-1237 (enum cycle-on-Enter) + `action_submit_policy` §1280-1356 (POST payload) | exact |
| `dlp-admin-cli/src/screens/render.rs` | modified | render (state-to-paint) | state-to-render | existing `draw_policy_create` §804-944 (row-`match i` arms) + `validation_error` overlay §922-935 (1-row paragraph at `area.y + area.height - 2`) | exact |
| `dlp-server/tests/mode_end_to_end.rs` | **new** | integration-test | HTTP-roundtrip (in-process) | `dlp-server/tests/admin_audit_integration.rs` §1-130 (verbatim reusable harness: `test_app`, `seed_admin_user`, `mint_jwt`, `tower::ServiceExt::oneshot`) | exact |

**Secondary analog — `app.rs` PolicyFormState mode field:** `PolicyFormState.action: usize` (§132) + `ACTION_OPTIONS` (§147) pattern for enum-index storage, OR (recommended) `dlp_common::abac::PolicyMode` (§254) stored directly, since `PolicyMode` is `Copy` with `#[default] ALL` and only 3 variants.

---

## Pattern Assignments

### `dlp-admin-cli/src/app.rs` (struct-def, state-to-render + wire-roundtrip)

**Analog 1 — Server-side `PolicyPayload` with `mode` field**
**Source:** `dlp-server/src/admin_api.rs` §107-127

```rust
// Source: dlp-server/src/admin_api.rs:107-127
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPayload {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    /// Boolean composition mode for the conditions list.
    #[serde(default)]
    pub mode: PolicyMode,
}
```

**Pattern to apply for `dlp-admin-cli::app::PolicyResponse` (§241-255, currently 10 fields incl. 2 `#[serde(default)]`):**
- Append field `#[serde(default)] pub mode: dlp_common::abac::PolicyMode,` after `updated_at` (current last field).
- Mirror exactly the pattern at server-side `admin_api.rs` §124-126 (doc comment + `#[serde(default)]` + field).

**Pattern to apply for `dlp-admin-cli::app::PolicyPayload` (§261-270):**
- Append the same field. The server-side payload already has it at admin_api.rs §124-126 — this is a literal shape-match.

**Analog 2 — existing `From<PolicyResponse> for PolicyPayload`**
**Source:** `dlp-admin-cli/src/app.rs` §272-284 (CURRENT)

```rust
// Source: dlp-admin-cli/src/app.rs:272-284
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
        }
    }
}
```

**Pattern to extend:** add one line `mode: r.mode,` after `enabled`. `PolicyMode: Copy` (dlp-common/src/abac.rs §254) — no clone needed.

**Analog 3 — `PolicyFormState` + `#[derive(Default)]`**
**Source:** `dlp-admin-cli/src/app.rs` §123-140 (CURRENT)

```rust
// Source: dlp-admin-cli/src/app.rs:123-140
#[derive(Debug, Clone, Default)]
pub struct PolicyFormState {
    pub name: String,
    pub description: String,
    pub priority: String,
    /// Index into the action options list (ALLOW/DENY/AllowWithLog/DenyWithAlert).
    pub action: usize,
    pub enabled: bool,
    pub conditions: Vec<dlp_common::abac::PolicyCondition>,
    pub id: String,
}
```

**Pattern to extend (per D-08, research A1 recommends direct-enum storage):**
- Append `pub mode: dlp_common::abac::PolicyMode,` to the struct.
- **Do NOT add `#[serde(default)]`** — this is an in-memory UI-state struct, not a wire type (Pitfall 3).
- `#[derive(Default)]` already correctly defaults the new field via `PolicyMode::default() == ALL` (dlp-common/src/abac.rs §254-258, `#[default]` on the `ALL` variant).

### Unit tests to add (#[cfg(test)] module at bottom of `app.rs`)

Research Test Map rows 3-5 call for three serde-focused unit tests; pattern below uses the struct literal shape from `admin_audit_integration.rs:145-154` (verbatim form):

```rust
// Pattern template — mirror admin_audit_integration.rs:145-154 for struct-literal shape
#[test]
fn test_policy_response_defaults_missing_mode_to_all() {
    let json = r#"{"id":"p","name":"n","priority":1,"conditions":[],"action":"ALLOW","enabled":true}"#;
    let got: PolicyResponse = serde_json::from_str(json).expect("deserialize without mode");
    assert_eq!(got.mode, dlp_common::abac::PolicyMode::ALL);
}
```

---

### `dlp-admin-cli/src/screens/dispatch.rs` (handler, event-to-dispatch + request-response)

**Analog 1 — Row-index constants (renumber in place)**
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` §873-887 (CURRENT)

```rust
// Source: dlp-admin-cli/src/screens/dispatch.rs:873-887
/// Row indices for the PolicyCreate/PolicyEdit form (Phase 15: 8 rows).
const POLICY_NAME_ROW: usize = 0;
const POLICY_DESC_ROW: usize = 1;
const POLICY_PRIORITY_ROW: usize = 2;
const POLICY_ACTION_ROW: usize = 3;
const POLICY_ENABLED_ROW: usize = 4;
const POLICY_ADD_CONDITIONS_ROW: usize = 5;
const POLICY_CONDITIONS_DISPLAY_ROW: usize = 6;
const POLICY_SAVE_ROW: usize = 7;
const POLICY_ROW_COUNT: usize = 8;
```

**Pattern to apply (per research Pattern 1 + D-02):** insert `const POLICY_MODE_ROW: usize = 5;` after `POLICY_ENABLED_ROW`, shift the three trailing consts to 6/7/8, update `POLICY_ROW_COUNT = 9`, and update the doc comment to `(Phase 19: 9 rows)`. All dispatch-side call sites are named (verified research §699), so this const renumber is zero-literal-sweep.

**Analog 2 — Enum cycle-on-Enter (the canonical cycler per D-01)**
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` §1232-1237 (PolicyCreate) + §1506-1510 (PolicyEdit)

```rust
// Source: dlp-admin-cli/src/screens/dispatch.rs:1232-1237 (PolicyCreate variant)
POLICY_ACTION_ROW => {
    // Cycle the action index (wraps at end of ACTION_OPTIONS).
    if let Screen::PolicyCreate { form, .. } = &mut app.screen {
        form.action = (form.action + 1) % ACTION_OPTIONS.len();
    }
}
```

```rust
// Source: dlp-admin-cli/src/screens/dispatch.rs:1506-1510 (PolicyEdit variant — mirror)
POLICY_ACTION_ROW => {
    if let Screen::PolicyEdit { form, .. } = &mut app.screen {
        form.action = (form.action + 1) % ACTION_OPTIONS.len();
    }
}
```

**Pattern to apply for new `POLICY_MODE_ROW` handler (one arm in `handle_policy_create`, one in `handle_policy_edit`):**

```rust
// Direct-enum 3-way match (recommended — research "Code Examples" §228-239, Claim A2)
POLICY_MODE_ROW => {
    if let Screen::PolicyCreate { form, .. } = &mut app.screen {
        form.mode = match form.mode {
            PolicyMode::ALL => PolicyMode::ANY,
            PolicyMode::ANY => PolicyMode::NONE,
            PolicyMode::NONE => PolicyMode::ALL,
        };
    }
}
```

Factor out a `fn cycle_mode(m: PolicyMode) -> PolicyMode` helper only if the plan wires the cycler in both Create and Edit (it does — so the helper wins, DRY per CLAUDE.md §9.1).

**Analog 3 — POST payload `json!()` macro**
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` §1321-1333 (CURRENT — mode is MISSING, per research Pitfall 1)

```rust
// Source: dlp-admin-cli/src/screens/dispatch.rs:1321-1333
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

**Pattern to extend (research Open-Question 1 recommends typed-struct refactor; minimal patch also shown):**

*Option A — minimal (add one key):*
```rust
let payload = serde_json::json!({
    // ... existing keys ...
    "enabled": form.enabled,
    "mode": form.mode,   // PolicyMode: Serialize -> "ALL"/"ANY"/"NONE" verbatim
});
```

*Option B — typed struct (recommended, research Assumption A2):*
```rust
let payload = PolicyPayload {
    id: uuid::Uuid::new_v4().to_string(),
    name: form.name.trim().to_string(),
    description: if form.description.trim().is_empty() { None }
                 else { Some(form.description.trim().to_string()) },
    priority,
    conditions: conditions_json,
    action: action_str,
    enabled: form.enabled,
    mode: form.mode,
};
let payload = serde_json::to_value(&payload).map_err(...)?;
```

**Mirror identical change at `action_submit_policy_update` §1610-1622** (research §703 — the PUT path has the same omission).

**Analog 4 — `action_load_policy_for_edit` field-copy pattern**
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` §1390-1401 (CURRENT)

```rust
// Source: dlp-admin-cli/src/screens/dispatch.rs:1390-1401
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
};
```

**Pattern to extend (per D-03, research Open-Question 3):**
- Add one field copy: `mode: policy["mode"].as_str().and_then(mode_from_str).unwrap_or_default(),`.
- Helper `mode_from_str(&str) -> Option<PolicyMode>` already exists per Phase 18 SUMMARY (research §717) — reuse it. If not importable into admin-cli, inline a 3-arm match with `.unwrap_or(PolicyMode::ALL)` fallback consistent with the `.unwrap_or("ALLOW")` pattern at §1368.
- Placement: insert between `enabled:` and `conditions:` to keep wire-order consistency with `PolicyResponse`.

**Analog 5 — Stale `selected > 2` guards**
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` §1245 (PolicyCreate) + §1538 (PolicyEdit)

```rust
// Source: dlp-admin-cli/src/screens/dispatch.rs:1245
if selected > 2 {
    return;
}
```

**Pattern to migrate (research §68 — consistency polish, not a bug):**
Replace bare `2` with `POLICY_PRIORITY_ROW` at both call sites. This is a const-rename, not a row-number shift (Name/Desc/Priority stay at 0/1/2).

---

### `dlp-admin-cli/src/screens/render.rs` (render, state-to-paint)

**Analog 1 — `POLICY_FIELD_LABELS` const**
**Source:** `dlp-admin-cli/src/screens/render.rs` §597-607 (CURRENT)

```rust
// Source: dlp-admin-cli/src/screens/render.rs:597-607
/// Display labels for each row in the PolicyCreate/PolicyEdit form (8 rows, indices 0-7).
const POLICY_FIELD_LABELS: [&str; 8] = [
    "Name",
    "Description",
    "Priority",
    "Action",
    "Enabled",
    "[Add Conditions]",
    "Conditions",
    "[Submit]",
];
```

**Pattern to extend (D-02):** change `[&str; 8]` to `[&str; 9]`, insert `"Mode"` between `"Enabled"` and `"[Add Conditions]"`. Update doc comment to `(9 rows, indices 0-8)`.

**Analog 2 — Row `match i` arms + `Vec::with_capacity`**
**Source:** `dlp-admin-cli/src/screens/render.rs` §814-900 (`draw_policy_create`) and §973-1047 (`draw_policy_edit`)

```rust
// Source: dlp-admin-cli/src/screens/render.rs:816-900 (excerpted arm shapes)
let mut items: Vec<ListItem> = Vec::with_capacity(POLICY_FIELD_LABELS.len());
for (i, label) in POLICY_FIELD_LABELS.iter().enumerate() {
    let line = match i {
        0 => { /* Name with edit-buffer / (empty) / value */ }
        1 => { /* Description */ }
        2 => { /* Priority */ }
        3 => {
            // Action (select — cycles on Enter, no edit mode)
            let action_label = ACTION_OPTIONS[form.action];
            Line::from(format!("{label}:            {action_label}"))
        }
        4 => {
            // Enabled (bool toggle)
            let enabled_val = if form.enabled { "Yes" } else { "No" };
            Line::from(format!("{label}:              {enabled_val}"))
        }
        5 => { /* [Add Conditions] action row: format!("  {label}") */ }
        6 => { /* Conditions summary */ }
        7 => { /* [Submit] action row */ }
        _ => Line::from(""),
    };
    items.push(ListItem::new(line));
}
```

**Pattern to apply (research Pitfall 2 — this is the #1 risk in Phase 19):**

1. **New arm 5 — Mode cycle-display** (mirror Action row shape at §857-861):
   ```rust
   5 => {
       // Mode (select enum — cycles on Enter, no edit mode, same as Action)
       let mode_label = match form.mode {
           PolicyMode::ALL  => "ALL",
           PolicyMode::ANY  => "ANY",
           PolicyMode::NONE => "NONE",
       };
       Line::from(format!("{label}:              {mode_label}"))
   }
   ```
2. **Renumber arms 5→6, 6→7, 7→8** in both `draw_policy_create` (§867-897) and `draw_policy_edit` (§1021-1045).
3. **Fix hardcoded `Vec::with_capacity(8)` at §973** (edit form) → `Vec::with_capacity(POLICY_FIELD_LABELS.len())` (matches create-form convention at §814, self-healing going forward).
4. **Keep `selected == 0/1/2` literals** at §820, §833, §846 (create) and §978, §990, §1002 (edit) — Name/Desc/Priority stay at rows 0/1/2 (research Pitfall 2 step 4).

**Analog 3 — 1-row footer paragraph (for D-04 advisory hint)**
**Source:** `dlp-admin-cli/src/screens/render.rs` §922-935 (`validation_error` overlay)

```rust
// Source: dlp-admin-cli/src/screens/render.rs:922-935
// Validation error overlay below the Submit row (not a list item).
if let Some(err) = validation_error {
    // Position: bottom-2 row (above hints bar at bottom-1).
    if area.height >= 4 {
        let err_area = Rect {
            x: area.x + 2,
            y: area.y + area.height - 2,
            width: area.width.saturating_sub(4),
            height: 1,
        };
        let err_para = Paragraph::new(err).style(Style::default().fg(Color::Red));
        frame.render_widget(err_para, err_area);
    }
}
```

**Pattern to apply (per D-04, research Pattern 3):**

```rust
// Advisory hint — render ONLY when no validation_error is shown
// (both share the area.y + area.height - 2 slot; errors take priority).
if validation_error.is_none()
    && form.mode != PolicyMode::ALL
    && form.conditions.is_empty()
    && area.height >= 4
{
    let hint = match form.mode {
        PolicyMode::ANY  => "Note: mode=ANY with no conditions will never match.",
        PolicyMode::NONE => "Note: mode=NONE with no conditions matches every request.",
        PolicyMode::ALL  => "",  // guarded above; required for exhaustive match
    };
    let hint_area = Rect {
        x: area.x + 2,
        y: area.y + area.height - 2,
        width: area.width.saturating_sub(4),
        height: 1,
    };
    let hint_para = Paragraph::new(hint).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(hint_para, hint_area);
}
```

Mirror identical block in `draw_policy_edit` just before its `draw_hints` call (§1082).

---

### `dlp-server/tests/mode_end_to_end.rs` (integration-test, HTTP-roundtrip, NEW FILE)

**Analog — verbatim harness template**
**Source:** `dlp-server/tests/admin_audit_integration.rs` §1-80 (imports + `test_app` + `seed_admin_user` + `mint_jwt`)

```rust
// Source: dlp-server/tests/admin_audit_integration.rs:1-80 (imports + helpers)
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use dlp_common::abac::PolicyMode;
use dlp_server::admin_api::{admin_router, PolicyPayload};
use dlp_server::admin_auth::{set_jwt_secret, Claims};
use dlp_server::{alert_router, db, policy_store, siem_connector, AppState};
use jsonwebtoken::{encode, EncodingKey, Header};
use tempfile::NamedTempFile;
use tower::ServiceExt;

const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

fn test_app() -> (axum::Router, Arc<db::Pool>) {
    set_jwt_secret(TEST_JWT_SECRET.to_string());
    let tmp = NamedTempFile::new().expect("create temp db");
    let pool = Arc::new(db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let siem = siem_connector::SiemConnector::new(Arc::clone(&pool));
    let alert = alert_router::AlertRouter::new(Arc::clone(&pool));
    let policy_store =
        Arc::new(policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"));
    let state = Arc::new(AppState {
        pool: Arc::clone(&pool),
        policy_store,
        siem,
        alert,
        ad: None,
    });
    (admin_router(state), pool)
}

fn seed_admin_user(pool: &db::Pool, username: &str, password_plain: &str) {
    let hash = bcrypt::hash(password_plain, 4).expect("bcrypt hash in tests");
    let now = Utc::now().to_rfc3339();
    let conn = pool.get().expect("acquire connection");
    conn.execute(
        "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![username, hash, now],
    )
    .expect("seed admin user");
}

fn mint_jwt(username: &str) -> String {
    let claims = Claims {
        sub: username.to_string(),
        exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        iss: "dlp-server".to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("mint JWT")
}
```

**Pattern — POST `/admin/policies` request shape**
**Source:** `dlp-server/tests/admin_audit_integration.rs` §138-177 (`test_policy_create_emits_admin_audit_event`)

```rust
// Source: dlp-server/tests/admin_audit_integration.rs:138-177
let (app, pool) = test_app();
seed_admin_user(&pool, "audit-admin", "currentpass");
let jwt = mint_jwt("audit-admin");

let payload = PolicyPayload {
    id: policy_id.to_string(),
    name: "Create Audit Test".to_string(),
    description: Some("testing policy-create audit".to_string()),
    priority: 100,
    conditions: serde_json::json!([]),
    action: "DENY".to_string(),
    enabled: true,
    mode: PolicyMode::ALL,       // already exercises the mode field — directly reusable
};
let body = serde_json::to_vec(&payload).expect("serialise payload");

let req = Request::builder()
    .method("POST")
    .uri("/admin/policies")
    .header("Authorization", format!("Bearer {jwt}"))
    .header("Content-Type", "application/json")
    .body(Body::from(body))
    .expect("build request");

let resp = app.oneshot(req).await.expect("oneshot");
assert_eq!(resp.status(), StatusCode::CREATED, "create should return 201");
```

**Pattern to apply (per D-14 — three test functions):**
Mirror the above shape verbatim three times (`test_mode_all_matches_when_all_conditions_hit`, `test_mode_any_matches_when_one_condition_hits`, `test_mode_none_matches_when_no_conditions_hit`). Each test body:
1. `POST /admin/policies` with `mode: PolicyMode::{ALL|ANY|NONE}` and 2 conditions.
2. `POST /evaluate` with an `EvaluateRequest` that hits a controlled subset of those conditions (see research §473-535 for the full shape).
3. Assert `body["decision"]` and `body["matched_policy_id"]` per boolean semantics.

**Important — `/evaluate` is UNAUTHENTICATED:** admin_api.rs §405-488 confirms `/evaluate` is public; only `/admin/*` requires JWT. Omit the `Authorization` header on the evaluate request.

**Pattern — Response-body deserialization**
```rust
let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
assert_eq!(body["decision"], "DENY");
assert_eq!(body["matched_policy_id"], "policy-any");
```

**Additional data-layer round-trip test (D-15)** — same file, no HTTP, pure serde:

```rust
#[test]
fn test_policy_payload_roundtrip_preserves_all_three_modes() {
    let policies = vec![
        PolicyPayload { id: "p1".into(), name: "all".into(), description: None, priority: 1,
            conditions: serde_json::json!([]), action: "DENY".into(), enabled: true, mode: PolicyMode::ALL },
        PolicyPayload { id: "p2".into(), name: "any".into(), description: None, priority: 2,
            conditions: serde_json::json!([]), action: "DENY".into(), enabled: true, mode: PolicyMode::ANY },
        PolicyPayload { id: "p3".into(), name: "none".into(), description: None, priority: 3,
            conditions: serde_json::json!([]), action: "DENY".into(), enabled: true, mode: PolicyMode::NONE },
    ];
    let json = serde_json::to_string_pretty(&policies).expect("serialize");
    assert!(json.contains("\"mode\": \"ALL\""));
    assert!(json.contains("\"mode\": \"ANY\""));
    assert!(json.contains("\"mode\": \"NONE\""));
    let round_trip: Vec<PolicyPayload> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(round_trip[0].mode, PolicyMode::ALL);
    assert_eq!(round_trip[1].mode, PolicyMode::ANY);
    assert_eq!(round_trip[2].mode, PolicyMode::NONE);
}
```

---

## Shared Patterns

### `#[serde(default)]` on typed wire structs (legacy-file tolerance)
**Source:** `dlp-server/src/admin_api.rs` §124-126 (server PolicyPayload.mode) + `dlp-common/src/abac.rs` §283-284 (Policy.mode) + existing admin-cli `PolicyResponse.version` / `.updated_at` (app.rs §251-254)
**Apply to:** `dlp-admin-cli::app::PolicyPayload.mode`, `dlp-admin-cli::app::PolicyResponse.mode` (D-05, D-06)
**Do NOT apply to:** `PolicyFormState.mode` — it's an in-memory UI struct, not a wire type (research Pitfall 3).
```rust
#[serde(default)]
pub mode: dlp_common::abac::PolicyMode,   // defaults to PolicyMode::ALL via #[default] on the enum
```

### `#[derive(Default)]` on UI-state structs
**Source:** `dlp-admin-cli/src/app.rs` §123 (`PolicyFormState`)
**Apply to:** Phase 19 adds one new `PolicyMode` field; existing `Default` derive handles it automatically because `PolicyMode::default() == ALL` (dlp-common/src/abac.rs §254-258).

### Named row-index constants over numeric literals
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` §874-887
**Apply to:** All `dispatch.rs` call sites already conform. `render.rs` does NOT (research §364-366); migration is out-of-scope for Phase 19 beyond the Mode row addition (research Anti-Pattern: "don't perpetuate the anti-pattern with 10/11 literal arms in future phases" — extending, not refactoring, is fine for this phase).

### Enum cycle-on-Enter for form fields
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` §1232-1237 (ACTION cycler)
**Apply to:** New MODE row handler in both `handle_policy_create` and `handle_policy_edit`. Consider factoring out `fn cycle_mode(PolicyMode) -> PolicyMode` since it's used in two places (DRY per CLAUDE.md §9.1).

### 1-row paragraph overlay at `area.y + area.height - 2`
**Source:** `dlp-admin-cli/src/screens/render.rs` §922-935 (`validation_error` overlay)
**Apply to:** Footer advisory hint (D-04). Mutually exclusive with `validation_error` — show error first if both conditions hold (research Pattern 3 caveat).

### Integration test harness (in-memory SQLite + admin_router + oneshot)
**Source:** `dlp-server/tests/admin_audit_integration.rs` §37-80
**Apply to:** `dlp-server/tests/mode_end_to_end.rs` — copy helpers verbatim. **Caveat:** `test_app()` uses a process-level `OnceLock` for JWT secret (see docstring §34-36). Multiple tests in the same file share state correctly because they all call `set_jwt_secret(TEST_JWT_SECRET)`.

### Rust project coding-standard constraints (CLAUDE.md §9)
**Apply to:** ALL Phase 19 code:
- No `.unwrap()` in production paths (§9.4) — use `?` or `.unwrap_or(PolicyMode::ALL)`.
- `tracing::*` macros for logs (§9.1) — not `println!`.
- Doc comments on public items (§9.3) — `PolicyFormState.mode`, `POLICY_MODE_ROW` const, new test helpers all need `///`.
- No emoji or emoji-like unicode in footer hint text (§9.2) — plain ASCII only.
- `cargo fmt` + `cargo clippy -- -D warnings` before commit (§9.17).

---

## No Analog Found

None. Every Phase 19 file change has at least one same-role analog in the codebase (strongest confidence: research Source list §693-720, all files verified by direct read).

---

## Metadata

**Analog search scope:**
- `dlp-admin-cli/src/app.rs` (full file)
- `dlp-admin-cli/src/screens/dispatch.rs` (§870-900, §1225-1420, §1500-1650)
- `dlp-admin-cli/src/screens/render.rs` (§590-1090 — both `draw_policy_create` and `draw_policy_edit` in full)
- `dlp-server/tests/admin_audit_integration.rs` (full file, 316 lines)
- `dlp-server/src/admin_api.rs` §97-135 (typed request/response structs)
- `dlp-common/src/abac.rs` §245-290 (PolicyMode + Policy)

**Files scanned:** 6
**Pattern extraction date:** 2026-04-20
**Output file:** `.planning/phases/19-boolean-mode-tui-import-export/19-PATTERNS.md`
