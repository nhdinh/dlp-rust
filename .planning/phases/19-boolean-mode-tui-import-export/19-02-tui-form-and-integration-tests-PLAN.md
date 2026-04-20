---
phase: 19-boolean-mode-tui-import-export
plan: 02
type: execute
wave: 2
depends_on: ["19-01"]
files_modified:
  - dlp-admin-cli/src/screens/dispatch.rs
  - dlp-admin-cli/src/screens/render.rs
  - dlp-server/tests/mode_end_to_end.rs
autonomous: true
requirements: [POLICY-09]

must_haves:
  truths:
    - "POLICY_FIELD_LABELS has 9 rows with `Mode` at index 5"
    - "draw_policy_create renders the Mode row showing ALL / ANY / NONE from form.mode"
    - "draw_policy_edit renders the Mode row showing ALL / ANY / NONE from form.mode"
    - "POLICY_MODE_ROW const is 5; POLICY_ADD_CONDITIONS_ROW is 6; POLICY_CONDITIONS_DISPLAY_ROW is 7; POLICY_SAVE_ROW is 8; POLICY_ROW_COUNT is 9"
    - "Pressing Enter or Space on POLICY_MODE_ROW cycles form.mode: ALL -> ANY -> NONE -> ALL in both Create and Edit"
    - "Footer advisory renders `Note: mode=ANY with no conditions will never match.` when form.mode == ANY && conditions is empty (no validation error present)"
    - "Footer advisory renders `Note: mode=NONE with no conditions matches every request.` when form.mode == NONE && conditions is empty (no validation error present)"
    - "Footer advisory does NOT render when form.mode == ALL"
    - "Footer advisory does NOT render when conditions is non-empty"
    - "Footer advisory does NOT render when validation_error is Some(_) (error takes priority)"
    - "Creating a policy with mode=ALL and all conditions satisfied produces decision DENY + matched_policy_id via /evaluate"
    - "Creating a policy with mode=ANY and only ONE of two conditions satisfied produces decision DENY + matched_policy_id via /evaluate"
    - "Creating a policy with mode=NONE and NO conditions satisfied produces decision DENY + matched_policy_id via /evaluate"
    - "Three PolicyPayload values (one per mode) serialize to pretty JSON containing `\"mode\": \"ALL\"`, `\"mode\": \"ANY\"`, `\"mode\": \"NONE\"` respectively and deserialize back preserving each mode"
  artifacts:
    - path: "dlp-admin-cli/src/screens/dispatch.rs"
      provides: "POLICY_MODE_ROW const + renumbered trailing consts + cycle handler in both Create and Edit + cycle_mode helper"
      contains: "POLICY_MODE_ROW"
    - path: "dlp-admin-cli/src/screens/render.rs"
      provides: "9-row POLICY_FIELD_LABELS + `Mode` render arm + footer advisory overlay in both Create and Edit"
      contains: "POLICY_FIELD_LABELS: [&str; 9]"
    - path: "dlp-server/tests/mode_end_to_end.rs"
      provides: "Three HTTP integration tests + one data-layer round-trip test"
      contains: "test_mode_all_matches_when_all_conditions_hit"
  key_links:
    - from: "dlp-admin-cli::screens::dispatch::handle_policy_create_nav"
      to: "PolicyFormState.mode"
      via: "cycle_mode(form.mode) on Enter or Space at POLICY_MODE_ROW"
      pattern: "POLICY_MODE_ROW"
    - from: "dlp-admin-cli::screens::render::draw_policy_create"
      to: "PolicyFormState.mode / PolicyFormState.conditions"
      via: "match i { 5 => render mode label } + footer advisory overlay"
      pattern: "PolicyMode::ANY =>"
    - from: "dlp-server/tests/mode_end_to_end.rs"
      to: "admin_router (POST /admin/policies + POST /evaluate)"
      via: "tower::ServiceExt::oneshot"
      pattern: "oneshot"
---

<objective>
Surface the Phase 19 boolean mode in the admin TUI and prove end-to-end
boolean semantics via server integration tests. This plan consumes Wave 1's
`PolicyFormState.mode`, the typed struct fields, and the fixed submit
payloads — it adds the form row, the dispatch cycler, the footer advisory,
and the three-mode HTTP integration tests that close POLICY-09's
user-facing acceptance bar.

Purpose: Complete POLICY-09. Deliver the five ROADMAP success criteria
(mode picker on Create, prefill on Edit, export includes mode, import
tolerates missing mode, three modes produce three different decisions
via the HTTP `/evaluate` endpoint).

Output:
- Row-index const renumber + cycle handler + cycle_mode helper in `dispatch.rs`
- POLICY_FIELD_LABELS extended to 9 rows + new Mode render arm + footer advisory in `render.rs` (both Create and Edit)
- New integration test file `dlp-server/tests/mode_end_to_end.rs` with 3 HTTP tests + 1 data-layer round-trip test
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
@.planning/phases/19-boolean-mode-tui-import-export/19-VALIDATION.md
@.planning/phases/19-boolean-mode-tui-import-export/19-01-wire-format-and-submit-fix-PLAN.md
@.planning/phases/18-boolean-mode-engine-wire-format/SUMMARY.md

<interfaces>
<!-- Contracts the executor needs. Extracted from codebase + Wave 1 output. -->

From dlp-admin-cli/src/screens/dispatch.rs §873-887 (CURRENT — to be renumbered):
```rust
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

From dlp-admin-cli/src/screens/render.rs §597-607 (CURRENT — extend to 9 rows):
```rust
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

From dlp-admin-cli/src/screens/render.rs §816-898 (CURRENT — draw_policy_create arm shapes):
```rust
for (i, label) in POLICY_FIELD_LABELS.iter().enumerate() {
    let line = match i {
        0 => { /* Name with edit-buffer / (empty) / value */ }
        1 => { /* Description */ }
        2 => { /* Priority */ }
        3 => { /* Action (cycles on Enter) -- format: "{label}:            {ACTION_OPTIONS[form.action]}" */ }
        4 => { /* Enabled (Yes/No) -- format: "{label}:              {enabled_val}" */ }
        5 => { /* [Add Conditions] -- format: "  {label}" */ }
        6 => { /* Conditions summary */ }
        7 => { /* [Submit] */ }
        _ => Line::from(""),
    };
}
```

From dlp-admin-cli/src/screens/render.rs §922-935 (CURRENT — validation_error overlay pattern; direct template for footer advisory):
```rust
if let Some(err) = validation_error {
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

From dlp-server/tests/admin_audit_integration.rs §14-80 (TEMPLATE to copy verbatim):
```rust
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

Important: `/evaluate` is UNAUTHENTICATED (admin_api.rs §405-488 confirms `/evaluate` is a public route). Omit the `Authorization` header on the evaluate request.
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Renumber row-index constants, add cycle_mode helper, wire Mode cycler in both Create and Edit nav handlers</name>
  <files>dlp-admin-cli/src/screens/dispatch.rs</files>
  <read_first>
    - dlp-admin-cli/src/screens/dispatch.rs §870-890 (current POLICY_*_ROW consts block — the renumber target)
    - dlp-admin-cli/src/screens/dispatch.rs §1184-1273 (entire `handle_policy_create_nav` function — where the new cycle arm lands)
    - dlp-admin-cli/src/screens/dispatch.rs §1473-1564 (entire `handle_policy_edit` nav path — where the second cycle arm lands; look for the `KeyCode::Enter => match selected {` block inside the edit handler)
    - dlp-admin-cli/src/screens/dispatch.rs §1243-1246 (the `if selected > 2 { return; }` guard in Create)
    - dlp-admin-cli/src/screens/dispatch.rs §1537-1540 (the `if selected > 2 { return; }` guard in Edit)
    - dlp-admin-cli/src/screens/dispatch.rs (search for all occurrences of `POLICY_ROW_COUNT` and `POLICY_SAVE_ROW` to verify no stray uses need updating beyond the const declarations themselves)
    - .planning/phases/19-boolean-mode-tui-import-export/19-PATTERNS.md §114-170 (row-index + cycler analogs)
  </read_first>
  <action>
    This task lands ONLY in `dispatch.rs`. Render-side changes are Task 2.

    **Change 1 — Renumber consts (dispatch.rs §873-887).** Replace the existing const block with:
    ```rust
    /// Row indices for the PolicyCreate/PolicyEdit form (Phase 19: 9 rows).
    const POLICY_NAME_ROW: usize = 0;
    const POLICY_DESC_ROW: usize = 1;
    const POLICY_PRIORITY_ROW: usize = 2;
    const POLICY_ACTION_ROW: usize = 3;
    /// Row index of the Enabled toggle.
    const POLICY_ENABLED_ROW: usize = 4;
    /// Row index of the Mode cycler (ALL / ANY / NONE), cycles on Enter or Space.
    const POLICY_MODE_ROW: usize = 5;
    /// Row index of the [Add Conditions] action row.
    const POLICY_ADD_CONDITIONS_ROW: usize = 6;
    /// Row index of the Conditions summary display row.
    const POLICY_CONDITIONS_DISPLAY_ROW: usize = 7;
    /// Row index of the [Save] / [Submit] action row.
    const POLICY_SAVE_ROW: usize = 8;
    /// Total rows in the PolicyCreate/PolicyEdit form (0..=8).
    const POLICY_ROW_COUNT: usize = 9;
    ```

    **Change 2 — Add cycle_mode helper** immediately after the const block (above any `fn alert_is_bool` definition):
    ```rust
    /// Cycles a `PolicyMode` to the next variant: ALL -> ANY -> NONE -> ALL.
    ///
    /// Matches the `Action` enum cycler pattern (see §1232-1237). `PolicyMode`
    /// is `Copy`, so the argument is taken by value and a new value is returned.
    ///
    /// # Arguments
    ///
    /// * `mode` - current mode
    ///
    /// # Returns
    ///
    /// The next mode in the cycle.
    fn cycle_mode(mode: dlp_common::abac::PolicyMode) -> dlp_common::abac::PolicyMode {
        use dlp_common::abac::PolicyMode;
        match mode {
            PolicyMode::ALL => PolicyMode::ANY,
            PolicyMode::ANY => PolicyMode::NONE,
            PolicyMode::NONE => PolicyMode::ALL,
        }
    }
    ```

    **Change 3 — Insert POLICY_MODE_ROW arm in `handle_policy_create_nav` (dispatch.rs §1184-1273).** Locate the `KeyCode::Enter => match selected { ... }` block. Insert a new match arm AFTER the existing `POLICY_ENABLED_ROW => {...}` arm and BEFORE `POLICY_ACTION_ROW`, OR place it after `POLICY_ACTION_ROW` for readability — anywhere in the match, since arms are order-independent. Insert:
    ```rust
                POLICY_MODE_ROW => {
                    // Cycle the boolean mode (ALL -> ANY -> NONE -> ALL).
                    if let Screen::PolicyCreate { form, .. } = &mut app.screen {
                        form.mode = cycle_mode(form.mode);
                    }
                }
    ```
    Also extend the `KeyCode::Enter` handling to ALSO trigger on `KeyCode::Char(' ')` for this row. The simplest approach: add a new outer arm in the `match key.code { ... }` block of `handle_policy_create_nav` that specifically intercepts Space when `selected == POLICY_MODE_ROW`. Concretely, add immediately BEFORE the existing `KeyCode::Esc | KeyCode::Char('q') => { ... }` arm:
    ```rust
            KeyCode::Char(' ') if selected == POLICY_MODE_ROW => {
                // Same cycle-on-activate UX as Enter for the Mode row.
                if let Screen::PolicyCreate { form, .. } = &mut app.screen {
                    form.mode = cycle_mode(form.mode);
                }
            }
    ```

    **Change 4 — Mirror the same two arms in the PolicyEdit nav path (dispatch.rs §1473-1564).** The Edit handler's `KeyCode::Enter => match selected { ... }` block is at §1493-1558. Insert the identical `POLICY_MODE_ROW` arm but gated on `Screen::PolicyEdit`:
    ```rust
                POLICY_MODE_ROW => {
                    if let Screen::PolicyEdit { form, .. } = &mut app.screen {
                        form.mode = cycle_mode(form.mode);
                    }
                }
    ```
    And the Space arm (placed before the `KeyCode::Esc | KeyCode::Char('q')` arm in the Edit handler):
    ```rust
            KeyCode::Char(' ') if selected == POLICY_MODE_ROW => {
                if let Screen::PolicyEdit { form, .. } = &mut app.screen {
                    form.mode = cycle_mode(form.mode);
                }
            }
    ```

    **Change 5 — Migrate stale `selected > 2` guards** (dispatch.rs §1245 in Create, §1538 in Edit). Replace bare literal `2` with the named const — Name/Desc/Priority still occupy rows 0/1/2 after the renumber:
    ```rust
    // BEFORE: if selected > 2 { return; }
    // AFTER:
    if selected > POLICY_PRIORITY_ROW {
        return;
    }
    ```
    This is a consistency polish (PATTERNS §246-256); `POLICY_PRIORITY_ROW == 2` so behavior is unchanged.

    **Change 6 — Audit for other row-index literal uses.** Run `grep -n "POLICY_ROW_COUNT\|POLICY_SAVE_ROW\|POLICY_ADD_CONDITIONS_ROW\|POLICY_CONDITIONS_DISPLAY_ROW" dlp-admin-cli/src/screens/dispatch.rs` to confirm no other call site hardcodes a numeric literal for those rows. All uses should already go through the named consts (verified by Research §699). If any bare `7` or `8` literal appears in a row-index context (e.g., a `match selected { 7 => ... }` or `nav(..., 8, ...)`), replace with the appropriate const. Current analysis shows no such literals exist, so this is a safety check, not an expected change.

    **Per CLAUDE.md:** `cycle_mode` must have a `///` doc comment (§9.3). No `.unwrap()` — the match is exhaustive (§9.4, §9.10). `snake_case` function name (§9.2).
  </action>
  <verify>
    <automated>cargo check -p dlp-admin-cli --tests &amp;&amp; cargo clippy -p dlp-admin-cli --lib -- -D warnings &amp;&amp; cargo test -p dlp-admin-cli --lib</automated>
  </verify>
  <acceptance_criteria>
    - `grep -n "const POLICY_MODE_ROW: usize = 5;" dlp-admin-cli/src/screens/dispatch.rs` → exactly ONE match
    - `grep -n "const POLICY_ADD_CONDITIONS_ROW: usize = 6;" dlp-admin-cli/src/screens/dispatch.rs` → exactly ONE match
    - `grep -n "const POLICY_CONDITIONS_DISPLAY_ROW: usize = 7;" dlp-admin-cli/src/screens/dispatch.rs` → exactly ONE match
    - `grep -n "const POLICY_SAVE_ROW: usize = 8;" dlp-admin-cli/src/screens/dispatch.rs` → exactly ONE match
    - `grep -n "const POLICY_ROW_COUNT: usize = 9;" dlp-admin-cli/src/screens/dispatch.rs` → exactly ONE match
    - `grep -n "fn cycle_mode" dlp-admin-cli/src/screens/dispatch.rs` → exactly ONE match
    - `grep -nc "form.mode = cycle_mode(form.mode);" dlp-admin-cli/src/screens/dispatch.rs` → 4 (two arms each in Create and Edit: Enter + Space)
    - `grep -n "if selected > 2" dlp-admin-cli/src/screens/dispatch.rs` → NO matches (both migrated to `POLICY_PRIORITY_ROW`)
    - `grep -nc "if selected > POLICY_PRIORITY_ROW" dlp-admin-cli/src/screens/dispatch.rs` → 2 (Create + Edit)
    - `cargo check -p dlp-admin-cli --tests` → clean, zero warnings
    - `cargo clippy -p dlp-admin-cli --lib -- -D warnings` → passes
    - `cargo test -p dlp-admin-cli --lib` → all Wave 1 tests still pass
  </acceptance_criteria>
  <done>Const block renumbered, `cycle_mode` helper exists, both Create and Edit handlers have working Enter + Space cyclers for the Mode row, both `selected > 2` guards migrated to `POLICY_PRIORITY_ROW`, clippy is clean.</done>
</task>

<task type="auto">
  <name>Task 2: Extend POLICY_FIELD_LABELS to 9 rows, add Mode render arm, renumber trailing arms, add footer advisory overlay in both Create and Edit</name>
  <files>dlp-admin-cli/src/screens/render.rs</files>
  <read_first>
    - dlp-admin-cli/src/screens/render.rs §597-607 (POLICY_FIELD_LABELS const — array length and `Mode` insertion point)
    - dlp-admin-cli/src/screens/render.rs §793-944 (entire `draw_policy_create` function — arm migration + footer advisory insertion point)
    - dlp-admin-cli/src/screens/render.rs §946-1088 (entire `draw_policy_edit` function — mirror changes)
    - dlp-admin-cli/src/screens/render.rs §922-935 (validation_error overlay — direct template for the footer advisory; advisory must NOT render when error is present)
    - dlp-admin-cli/src/screens/render.rs §1-40 (confirm existing imports; check for `Paragraph`, `Color`, `Rect`, `Style`, `Span` imports. If `PolicyMode` is not imported, add it.)
    - .planning/phases/19-boolean-mode-tui-import-export/19-PATTERNS.md §261-378 (render pattern map with exact arm shapes)
    - .planning/phases/19-boolean-mode-tui-import-export/19-RESEARCH.md §362-376 (Pitfall 2 — the #1 risk: render.rs renumber)
  </read_first>
  <action>
    All changes land in `render.rs`. No `dispatch.rs` edits here.

    **Change 1 — Extend POLICY_FIELD_LABELS (render.rs §597-607):** Replace the 8-element array with a 9-element array. Insert `"Mode"` between `"Enabled"` (index 4) and `"[Add Conditions]"` (now index 6):
    ```rust
    /// Display labels for each row in the PolicyCreate/PolicyEdit form (9 rows, indices 0-8).
    const POLICY_FIELD_LABELS: [&str; 9] = [
        "Name",
        "Description",
        "Priority",
        "Action",
        "Enabled",
        "Mode",
        "[Add Conditions]",
        "Conditions",
        "[Submit]",
    ];
    ```

    **Change 2 — Add `PolicyMode` import** near the top of render.rs with the other imports. If a grouped `use dlp_common::abac::{...}` already exists, extend it. Otherwise add:
    ```rust
    use dlp_common::abac::PolicyMode;
    ```

    **Change 3 — Migrate `draw_policy_create` arms (render.rs §816-898):**

    a. Insert a NEW arm at `5 => {...}` for the Mode row. The format mirrors the Action row (§857-861 "{label}:            {value}"):
    ```rust
            5 => {
                // Mode (select enum — cycles on Enter/Space, no edit mode).
                let mode_label = match form.mode {
                    PolicyMode::ALL => "ALL",
                    PolicyMode::ANY => "ANY",
                    PolicyMode::NONE => "NONE",
                };
                Line::from(format!("{label}:              {mode_label}"))
            }
    ```
    Use the same spacing (`:              `) as the `Enabled` row at §865 so columns align after the longest column (Name).

    b. Renumber the trailing arms: `5 => [Add Conditions]` becomes `6 =>`, `6 => Conditions summary` becomes `7 =>`, `7 => [Submit]` becomes `8 =>`. Each arm body is preserved verbatim; only the left-hand-side integer changes. After this change the `draw_policy_create` match has 9 arms plus the `_ => Line::from("")` catch-all. **Verify the catch-all remains (Rust requires exhaustive match on `usize`).**

    c. **DO NOT** change the `selected == 0/1/2` literals at §820, §833, §846 — those rows (Name/Desc/Priority) stay at indices 0/1/2.

    d. The `Vec::with_capacity(POLICY_FIELD_LABELS.len())` at §814 is self-healing (uses the const) — no change needed.

    **Change 4 — Insert footer advisory overlay in `draw_policy_create`** IMMEDIATELY BEFORE the existing `if let Some(err) = validation_error { ... }` block (render.rs §922). The advisory and the error share the `area.y + area.height - 2` slot; the advisory must be gated on `validation_error.is_none()`. Insert:
    ```rust
        // Empty-conditions mode advisory (Phase 19 D-04). Shown in the same
        // bottom-2 row slot as the validation_error overlay (see below); errors
        // take priority, so this block is gated on `validation_error.is_none()`.
        if validation_error.is_none()
            && form.mode != PolicyMode::ALL
            && form.conditions.is_empty()
            && area.height >= 4
        {
            let hint = match form.mode {
                PolicyMode::ANY => "Note: mode=ANY with no conditions will never match.",
                PolicyMode::NONE => "Note: mode=NONE with no conditions matches every request.",
                PolicyMode::ALL => "",
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
    Note: the `PolicyMode::ALL => ""` arm is unreachable given the `form.mode != PolicyMode::ALL` guard above, but Rust requires an exhaustive match on the three-variant enum. The empty string renders nothing even if reached.

    **Change 5 — Mirror Changes 3 and 4 in `draw_policy_edit` (render.rs §946-1088):**

    a. Fix the hardcoded `Vec::with_capacity(8)` at §973 → `Vec::with_capacity(POLICY_FIELD_LABELS.len())` (PATTERNS §327, Pitfall 2 step 5).

    b. Insert a NEW arm at `5 => {...}` identical to the Create form's Mode arm (Change 3a above). Use the SAME `mode_label` match and the SAME `"{label}:              {mode_label}"` format string.

    c. Renumber arms `5 => (Add Conditions)` → `6 =>`, `6 => (Conditions summary)` → `7 =>`, `7 => [Save]` → `8 =>`. The existing Save arm (§1042-1045) keeps its hardcoded `"  [Save]"` literal — only the match arm integer changes.

    d. Insert the same footer advisory overlay block (Change 4) immediately BEFORE the `if let Some(err) = validation_error { ... }` block at render.rs §1069.

    **Per CLAUDE.md:** 4-space indent (§9.2), doc comments updated on the const (§9.3), exhaustive match (§9.10), no commented-out old arms — delete the old literals, do not comment them (§9.14).

    **Do NOT** refactor render.rs to use `POLICY_*_ROW` consts instead of literals — Research §68 + PATTERNS §539 explicitly says that refactor is OUT OF SCOPE for this phase (the anti-pattern warning is about future phases expanding past 9 arms). This plan preserves the literal-arm style and merely extends it by one arm.
  </action>
  <verify>
    <automated>cargo check -p dlp-admin-cli &amp;&amp; cargo clippy -p dlp-admin-cli --lib -- -D warnings &amp;&amp; cargo test -p dlp-admin-cli --lib</automated>
  </verify>
  <acceptance_criteria>
    - `grep -n "const POLICY_FIELD_LABELS: \[&str; 9\]" dlp-admin-cli/src/screens/render.rs` → exactly ONE match
    - `grep -c "\"Mode\"," dlp-admin-cli/src/screens/render.rs` → at least 1 (the new element in POLICY_FIELD_LABELS)
    - `grep -nc "PolicyMode::ALL => \"ALL\"" dlp-admin-cli/src/screens/render.rs` → 2 (one arm body each in draw_policy_create and draw_policy_edit)
    - `grep -nc "Note: mode=ANY with no conditions will never match." dlp-admin-cli/src/screens/render.rs` → 2 (one hint block each in Create and Edit)
    - `grep -nc "Note: mode=NONE with no conditions matches every request." dlp-admin-cli/src/screens/render.rs` → 2 (one hint block each in Create and Edit)
    - `grep -nc "validation_error.is_none()" dlp-admin-cli/src/screens/render.rs` → at least 2 (the gate for each footer advisory block; may also appear elsewhere)
    - `grep -n "Vec::with_capacity(8)" dlp-admin-cli/src/screens/render.rs` → NO matches (replaced in draw_policy_edit)
    - `grep -n "8 => Line::from(\"  \\[Submit\\]\")\\|8 => {" dlp-admin-cli/src/screens/render.rs` → at least 1 (the Submit arm moved from 7 to 8 in draw_policy_create; Edit's Save arm is a literal string at index 8)
    - `cargo check -p dlp-admin-cli` → clean, zero warnings
    - `cargo clippy -p dlp-admin-cli --lib -- -D warnings` → passes
    - `cargo test -p dlp-admin-cli --lib` → all Wave 1 tests still pass
  </acceptance_criteria>
  <done>Both `draw_policy_create` and `draw_policy_edit` render 9 rows with a `Mode` row at index 5 showing the current `form.mode`; the footer advisory renders only when mode != ALL && conditions is empty && no validation_error; the edit form's hardcoded `Vec::with_capacity(8)` is migrated; clippy is clean.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: Create dlp-server/tests/mode_end_to_end.rs with three HTTP integration tests plus one data-layer round-trip test</name>
  <files>dlp-server/tests/mode_end_to_end.rs</files>
  <read_first>
    - dlp-server/tests/admin_audit_integration.rs (ENTIRE FILE — this is the template: imports, `test_app`, `seed_admin_user`, `mint_jwt` all copied verbatim)
    - dlp-server/src/admin_api.rs §56-135 (evaluate_handler + PolicyPayload/PolicyResponse types — confirm field shapes and `/evaluate` unauthenticated status)
    - dlp-server/src/admin_api.rs §405-488 (admin_router construction — confirm `/evaluate` is public; `/admin/*` requires JWT)
    - dlp-common/src/abac.rs (ENTIRE FILE — PolicyCondition variant shapes for building the `conditions` JSON array; EvaluateRequest shape; AccessContext / DeviceTrust / NetworkLocation enum variant names as serialized by serde)
    - .planning/phases/19-boolean-mode-tui-import-export/19-PATTERNS.md §381-517 (integration test harness pattern + full example test body)
    - .planning/phases/19-boolean-mode-tui-import-export/19-RESEARCH.md §473-568 (complete example test bodies and the data-layer round-trip shape)
  </read_first>
  <behavior>
    - Test 1 `test_mode_all_matches_when_all_conditions_hit`: Create a policy with `mode: ALL` and 2 conditions (e.g., `classification == T3` AND `access_context == Local`). POST `/evaluate` with an `EvaluateRequest` where BOTH conditions are satisfied (resource T3, access_context Local). Assert response decision is `"DENY"` (policy.action) and `matched_policy_id` equals the policy's id.
    - Test 2 `test_mode_any_matches_when_one_condition_hits`: Create a policy with `mode: ANY` and 2 conditions. POST `/evaluate` with a request where ONLY ONE condition is satisfied. Assert decision `"DENY"` and the policy id matches.
    - Test 3 `test_mode_none_matches_when_no_conditions_hit`: Create a policy with `mode: NONE` and 2 conditions. POST `/evaluate` with a request where NEITHER condition is satisfied. Assert decision `"DENY"` and the policy id matches.
    - Test 4 `test_policy_payload_roundtrip_preserves_all_three_modes`: Pure data-layer (no HTTP). Build three `PolicyPayload` values (one per mode), `serde_json::to_string_pretty` them, assert the JSON substring contains `"mode": "ALL"`, `"mode": "ANY"`, `"mode": "NONE"` respectively, then `serde_json::from_str::<Vec<PolicyPayload>>` the combined pretty JSON and assert each element's `mode` matches.
  </behavior>
  <action>
    This is a NEW file. Create `dlp-server/tests/mode_end_to_end.rs` with the complete contents below.

    Write the full file in one shot:
    ```rust
    //! End-to-end integration tests for Phase 19 boolean mode.
    //!
    //! Proves that:
    //!   - Creating a policy with `mode=ALL` requires ALL conditions to match
    //!     for the policy to fire on `/evaluate`.
    //!   - `mode=ANY` fires when at least one condition matches.
    //!   - `mode=NONE` fires when no condition matches.
    //!   - Serializing and deserializing a `PolicyPayload` round-trips the mode
    //!     verbatim for all three variants.
    //!
    //! Harness (`test_app`, `seed_admin_user`, `mint_jwt`) is copied verbatim
    //! from `admin_audit_integration.rs` — same in-memory SQLite pool, same
    //! admin_router, same JWT secret constant.
    //!
    //! `/evaluate` is unauthenticated (admin_api.rs §405-488), so the evaluate
    //! requests below omit the Authorization header.

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

    /// Builds a POST /admin/policies request with the given typed payload.
    fn build_create_policy_request(jwt: &str, payload: &PolicyPayload) -> Request<Body> {
        let body = serde_json::to_vec(payload).expect("serialise policy payload");
        Request::builder()
            .method("POST")
            .uri("/admin/policies")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build create request")
    }

    /// Builds a POST /evaluate request (unauthenticated).
    fn build_evaluate_request(eval_body: &serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(eval_body).expect("serialise eval request"),
            ))
            .expect("build evaluate request")
    }

    /// Reads the full HTTP response body and parses it as JSON.
    async fn read_body_as_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 8192)
            .await
            .expect("read response body");
        serde_json::from_slice(&bytes).expect("parse response as JSON")
    }

    /// Builds a test EvaluateRequest body with the caller able to override the
    /// classification and access_context (the two condition attributes exercised).
    fn evaluate_body(classification: &str, access_context: &str) -> serde_json::Value {
        serde_json::json!({
            "subject": {
                "user_sid": "S-1-5-21-1",
                "user_name": "tester",
                "groups": [],
                "device_trust": "Unknown",
                "network_location": "Unknown"
            },
            "resource": {
                "path": "C:\\test.txt",
                "classification": classification
            },
            "environment": {
                "timestamp": "2026-04-20T00:00:00Z",
                "session_id": 1,
                "access_context": access_context
            },
            "action": "READ"
        })
    }

    #[tokio::test]
    async fn test_mode_all_matches_when_all_conditions_hit() {
        let (app, pool) = test_app();
        seed_admin_user(&pool, "mode-admin", "pw");
        let jwt = mint_jwt("mode-admin");

        let payload = PolicyPayload {
            id: "policy-all".to_string(),
            name: "all mode test".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([
                { "attribute": "classification", "op": "eq", "value": "T3" },
                { "attribute": "accesscontext",  "op": "eq", "value": "Local" }
            ]),
            action: "DENY".to_string(),
            enabled: true,
            mode: PolicyMode::ALL,
        };

        let resp = app
            .clone()
            .oneshot(build_create_policy_request(&jwt, &payload))
            .await
            .expect("oneshot create");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Both conditions match: classification=T3 AND access_context=Local.
        let eval = evaluate_body("T3", "Local");
        let resp = app
            .oneshot(build_evaluate_request(&eval))
            .await
            .expect("oneshot evaluate");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_as_json(resp).await;
        assert_eq!(body["decision"], "DENY", "ALL mode should fire when all conditions match");
        assert_eq!(body["matched_policy_id"], "policy-all");
    }

    #[tokio::test]
    async fn test_mode_any_matches_when_one_condition_hits() {
        let (app, pool) = test_app();
        seed_admin_user(&pool, "mode-admin", "pw");
        let jwt = mint_jwt("mode-admin");

        let payload = PolicyPayload {
            id: "policy-any".to_string(),
            name: "any mode test".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([
                { "attribute": "classification", "op": "eq", "value": "T3" },
                { "attribute": "accesscontext",  "op": "eq", "value": "Smb" }
            ]),
            action: "DENY".to_string(),
            enabled: true,
            mode: PolicyMode::ANY,
        };

        let resp = app
            .clone()
            .oneshot(build_create_policy_request(&jwt, &payload))
            .await
            .expect("oneshot create");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Only the FIRST condition matches: classification=T3 but access_context=Local (not Smb).
        let eval = evaluate_body("T3", "Local");
        let resp = app
            .oneshot(build_evaluate_request(&eval))
            .await
            .expect("oneshot evaluate");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_as_json(resp).await;
        assert_eq!(body["decision"], "DENY", "ANY mode should fire when exactly one condition matches");
        assert_eq!(body["matched_policy_id"], "policy-any");
    }

    #[tokio::test]
    async fn test_mode_none_matches_when_no_conditions_hit() {
        let (app, pool) = test_app();
        seed_admin_user(&pool, "mode-admin", "pw");
        let jwt = mint_jwt("mode-admin");

        let payload = PolicyPayload {
            id: "policy-none".to_string(),
            name: "none mode test".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([
                { "attribute": "classification", "op": "eq", "value": "T4" },
                { "attribute": "accesscontext",  "op": "eq", "value": "Smb" }
            ]),
            action: "DENY".to_string(),
            enabled: true,
            mode: PolicyMode::NONE,
        };

        let resp = app
            .clone()
            .oneshot(build_create_policy_request(&jwt, &payload))
            .await
            .expect("oneshot create");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Neither condition matches: classification=T1 (not T4) and access_context=Local (not Smb).
        let eval = evaluate_body("T1", "Local");
        let resp = app
            .oneshot(build_evaluate_request(&eval))
            .await
            .expect("oneshot evaluate");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_as_json(resp).await;
        assert_eq!(body["decision"], "DENY", "NONE mode should fire when no condition matches");
        assert_eq!(body["matched_policy_id"], "policy-none");
    }

    #[test]
    fn test_policy_payload_roundtrip_preserves_all_three_modes() {
        let policies = vec![
            PolicyPayload {
                id: "p1".into(),
                name: "all".into(),
                description: None,
                priority: 1,
                conditions: serde_json::json!([]),
                action: "DENY".into(),
                enabled: true,
                mode: PolicyMode::ALL,
            },
            PolicyPayload {
                id: "p2".into(),
                name: "any".into(),
                description: None,
                priority: 2,
                conditions: serde_json::json!([]),
                action: "DENY".into(),
                enabled: true,
                mode: PolicyMode::ANY,
            },
            PolicyPayload {
                id: "p3".into(),
                name: "none".into(),
                description: None,
                priority: 3,
                conditions: serde_json::json!([]),
                action: "DENY".into(),
                enabled: true,
                mode: PolicyMode::NONE,
            },
        ];

        let json = serde_json::to_string_pretty(&policies).expect("serialize");
        assert!(
            json.contains("\"mode\": \"ALL\""),
            "expected ALL in json: {json}"
        );
        assert!(
            json.contains("\"mode\": \"ANY\""),
            "expected ANY in json: {json}"
        );
        assert!(
            json.contains("\"mode\": \"NONE\""),
            "expected NONE in json: {json}"
        );

        let round_trip: Vec<PolicyPayload> =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round_trip.len(), 3);
        assert_eq!(round_trip[0].mode, PolicyMode::ALL);
        assert_eq!(round_trip[1].mode, PolicyMode::ANY);
        assert_eq!(round_trip[2].mode, PolicyMode::NONE);
    }
    ```

    **Important notes:**
    - The `classification` / `access_context` values must match the EXACT serde-serialized form expected by `dlp-common::abac::EvaluateRequest`. From the Phase 18 integration test (which passed), `"T3"` and `"Local"` / `"Smb"` are correct. If compilation or test failure reveals a different case (e.g., server accepts case-insensitive via custom deserializer), adjust by reading the actual `EvaluateRequest` struct + `AccessContext` enum in `dlp-common/src/abac.rs`.
    - The `conditions` JSON shape uses `attribute` and `op` keys per PATTERNS §304-307. If the `PolicyCondition` variants use different tag fields (e.g., `#[serde(tag = "attribute")]`), the JSON must match exactly — verify against `dlp-common/src/abac.rs`.
    - Per CLAUDE.md §9.8 this is a `tests/` integration test (standalone binary), not a `#[cfg(test)] mod`. No `.unwrap()` — `.expect("...")` with descriptive messages is acceptable per §9.4 exception for tests.
    - Per CLAUDE.md §9.2 no tabs, 4-space indent. Per §9.9 imports organized: std, external crates, local.
  </action>
  <verify>
    <automated>cargo test -p dlp-server --test mode_end_to_end</automated>
  </verify>
  <acceptance_criteria>
    - File `dlp-server/tests/mode_end_to_end.rs` exists
    - `grep -n "fn test_mode_all_matches_when_all_conditions_hit" dlp-server/tests/mode_end_to_end.rs` → exactly ONE match
    - `grep -n "fn test_mode_any_matches_when_one_condition_hits" dlp-server/tests/mode_end_to_end.rs` → exactly ONE match
    - `grep -n "fn test_mode_none_matches_when_no_conditions_hit" dlp-server/tests/mode_end_to_end.rs` → exactly ONE match
    - `grep -n "fn test_policy_payload_roundtrip_preserves_all_three_modes" dlp-server/tests/mode_end_to_end.rs` → exactly ONE match
    - `grep -nc "mode: PolicyMode::" dlp-server/tests/mode_end_to_end.rs` → at least 6 (3 HTTP tests + 3 struct literals in round-trip test)
    - `cargo test -p dlp-server --test mode_end_to_end test_mode_all_matches_when_all_conditions_hit` → PASS
    - `cargo test -p dlp-server --test mode_end_to_end test_mode_any_matches_when_one_condition_hits` → PASS
    - `cargo test -p dlp-server --test mode_end_to_end test_mode_none_matches_when_no_conditions_hit` → PASS
    - `cargo test -p dlp-server --test mode_end_to_end test_policy_payload_roundtrip_preserves_all_three_modes` → PASS
    - `cargo clippy -p dlp-server --tests -- -D warnings` → passes
  </acceptance_criteria>
  <done>All four tests in `dlp-server/tests/mode_end_to_end.rs` pass; clippy is clean; the file compiles with no warnings.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| keyboard → TUI dispatch | Crossterm key events dispatched by `handle_policy_create` / `handle_policy_edit` — untrusted source but scoped to the running TTY |
| TUI form → admin-cli HTTP submit | Authenticated (JWT) POST/PUT crosses here; `form.mode` serialized into the wire payload |
| /evaluate → policy_store | Unauthenticated POST body from agent/test client; consumed by `PolicyStore::evaluate` (Phase 18 territory, no change in Phase 19) |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-19-05 | Tampering | TUI Mode row dispatch | mitigate | `cycle_mode` accepts only a `PolicyMode` (typed enum) and returns a `PolicyMode`; no attacker-controlled string can influence the cycle. The three-way exhaustive match rejects any compiler-bypassed invalid value. |
| T-19-06 | Elevation of Privilege | POLICY_MODE_ROW event routing | mitigate | The new cycle arm only mutates `form.mode`; it does NOT bypass the `POLICY_SAVE_ROW` submit path's existing validation (name non-empty, priority parseable). All existing CSRF/JWT protections at the server boundary remain unchanged (Phase 9). |
| T-19-07 | Information Disclosure | Footer advisory string | accept | The advisory string is static compile-time text and reveals no sensitive data about policies, users, or system state. Plain ASCII per CLAUDE.md §9.2. |
| T-19-08 | Denial of Service | /evaluate with crafted mode-aware policy | accept | Evaluator is the same Phase 18 code path; the three new integration tests exercise it under controlled conditions. No new loop, no new allocation, no new lock acquired — Phase 18's performance characteristics persist. |
| T-19-09 | Repudiation | Mode change on PolicyEdit | mitigate | `action_submit_policy_update` (dispatch.rs §1571) uses the existing admin audit path (Phase 9, POLICY-06); mode changes are captured in `audit_events` with the same event_type/action_attempted contract as every other policy mutation. No Phase 19 change required. |
</threat_model>

<verification>
Wave 2 phase gate (run before declaring the phase complete):
- `cargo fmt --all -- --check` → clean
- `cargo clippy --workspace -- -D warnings` → clean
- `cargo test --workspace --tests` → all tests pass (includes the new `mode_end_to_end.rs` integration test + all Wave 1 unit tests + all Phase 18 tests)
- `cargo check --workspace` → clean

Manual verification (see 19-VALIDATION.md Manual-Only Verifications table):
- Launch `dlp-admin-cli`, enter Policy Create, observe 9-row form with `Mode: ALL` at row 5; press Enter 3 times on Mode row, observe ALL → ANY → NONE → ALL cycle
- With conditions empty and mode=ANY, observe footer advisory `Note: mode=ANY with no conditions will never match.` in DarkGray
- Set a Name, Priority, cycle Mode to NONE, observe `Note: mode=NONE with no conditions matches every request.`
- Add one condition — observe the footer advisory disappears
- Submit the policy; re-enter Policy Edit for that policy; observe the Mode row pre-filled with the submitted value
- Cycle to a different mode on Edit, submit; GET the policy via `curl` or CLI; confirm the server persisted the new mode
</verification>

<success_criteria>
- POLICY-09 ROADMAP success criterion 1: Policy Create form shows a `Mode: [ALL] / ANY / NONE` row above the conditions builder — PROVEN by Task 2 render arm + Task 1 cycler.
- POLICY-09 ROADMAP success criterion 2: Policy Edit form pre-fills the mode from `PolicyResponse.mode` — PROVEN by Wave 1 Task 2 (prefill) + Task 2 render arm.
- POLICY-09 ROADMAP success criterion 3: Export includes `mode` on every policy — PROVEN transitively by Phase 18 server behavior + Task 3 data-layer round-trip test (`"mode": "ALL"` etc. substring assertions).
- POLICY-09 ROADMAP success criterion 4: Legacy v0.4.0 export files (no `mode` key) import successfully with `mode = ALL` — PROVEN by Wave 1 `test_policy_response_defaults_missing_mode_to_all` + `test_policy_payload_legacy_default_on_missing_mode`.
- POLICY-09 ROADMAP success criterion 5: Three policies (one per mode) against the same `EvaluateRequest` produce three different decisions per boolean semantics — PROVEN by Task 3's three HTTP integration tests.
- All phase gates pass: fmt, clippy `-D warnings`, workspace tests all green.
</success_criteria>

<output>
After completion, create `.planning/phases/19-boolean-mode-tui-import-export/19-02-SUMMARY.md` covering:
- Const renumber (POLICY_MODE_ROW=5, trailing consts shifted) and `cycle_mode` helper
- Render arm migration: POLICY_FIELD_LABELS 8→9, new `5 => Mode` arm + renumbered 6/7/8 in both Create and Edit
- Footer advisory overlay added to both Create and Edit
- New `dlp-server/tests/mode_end_to_end.rs` with 4 tests (3 HTTP + 1 data-layer)
- Verification outputs (cargo test / clippy / fmt / check)
- Any deviations (e.g., if the conditions JSON shape had to be adjusted to match `PolicyCondition` variant tags)

Then create `.planning/phases/19-boolean-mode-tui-import-export/SUMMARY.md` as the phase-level rollup referencing both wave summaries.

Finally, update `.planning/ROADMAP.md` Phase 19 row to `Complete` (date it) and `.planning/STATE.md` to advance to Phase 20.
</output>
