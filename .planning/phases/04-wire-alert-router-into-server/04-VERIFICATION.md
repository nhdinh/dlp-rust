---
phase: 04-wire-alert-router-into-server
verified: 2026-04-10T00:00:00Z
status: human_needed
score: 10/10 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Admin configures SMTP via dlp-admin-cli TUI, triggers DenyWithAlert, verifies email arrives at destination"
    expected: "Email delivered to every address in smtp_to with the full AuditEvent JSON in the body and subject line '[DLP ALERT] <event_type> on <resource_path> by <user_name>'"
    why_human: "Exercises real SMTP transport (lettre + STARTTLS) against a live mail server; no mock harness in workspace"
  - test: "Admin configures webhook URL via TUI, triggers DenyWithAlert, verifies webhook receiver logs the POST"
    expected: "Receiver logs a POST with body == serde_json::to_string_pretty(event) and Content-Type application/json"
    why_human: "Exercises real reqwest::Client against a live webhook receiver; no mock harness in workspace"
  - test: "Admin updates smtp_host via TUI WITHOUT restarting dlp-server, then triggers a second DenyWithAlert"
    expected: "The second alert uses the new host (hot-reload working — no cached config)"
    why_human: "Hot-reload is covered by unit test test_hot_reload at the load_config level, but end-to-end verification through the HTTP + TUI path needs operator interaction"
  - test: "PUT /admin/alert-config with webhook_url https://127.0.0.1 returns HTTP 400 end-to-end"
    expected: "curl returns 400 Bad Request with body text containing 'loopback addresses not allowed'. The integration test test_put_alert_config_rejects_loopback already covers this at the handler level; UAT reverifies over real HTTP."
    why_human: "Integration tests mount the router in-process with tower::ServiceExt; UAT confirms the response flows correctly through axum + tokio TCP + TLS in a deployed environment"
  - test: "dlp-admin-cli Alert Config screen renders 12 selectable rows"
    expected: "User can Tab/arrow through exactly 12 rows: 10 editable fields (smtp_host, smtp_port, smtp_username, smtp_password, smtp_from, smtp_to, smtp_enabled, webhook_url, webhook_secret, webhook_enabled) + [Save] + [Back]. smtp_password and webhook_secret render as ***** outside edit mode."
    why_human: "Visual TUI rendering + keystroke navigation cannot be verified programmatically without a headless terminal harness"
---

# Phase 04: Wire Alert Router into Server — Verification Report

**Phase Goal:** Wire AlertRouter into server startup and into the audit ingestion path, AND move alert configuration from env vars to the SQLite `alert_router_config` table. JWT-protected GET/PUT `/admin/alert-config` endpoints, dlp-admin-cli TUI screen under the System menu, hot-reload on every `send_alert`. Route DenyWithAlert audit events to configured email (SMTP via lettre) and/or webhook destinations via fire-and-forget background tasks. Webhook URL is validated at PUT time (https-only, loopback/link-local blocked).

**Verified:** 2026-04-10
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (10 must-haves)

| # | Must-Have | Status | Evidence |
|---|-----------|--------|----------|
| 1 | `alert_router_config` table with CHECK(id=1) + default-disabled seed row | PASS | `dlp-server/src/db.rs:142-156` — DDL + `CHECK (id = 1)` + `INSERT OR IGNORE INTO alert_router_config (id) VALUES (1)`. `test_alert_router_config_seed_row` passes. |
| 2 | `AlertRouter` holds `Arc<Database>`, hot-reloads on every `send_alert` | PASS | `alert_router.rs:82` (`db: Arc<Database>`), `:118` (`pub fn new(db: Arc<Database>)`), `:184-185` (`pub async fn send_alert` calls `self.load_config()?` as its FIRST line — no caching field on the struct). `test_hot_reload` passes. |
| 3 | `AppState.alert` populated at server startup | PASS | `dlp-server/src/lib.rs:33` (`pub alert: alert_router::AlertRouter`), `main.rs:151` (`let alert = AlertRouter::new(Arc::clone(&db));`), `main.rs:154` (`AppState { db, siem, alert }`). |
| 4 | `ingest_events` fire-and-forget spawn filters DenyWithAlert, never awaits | PASS | `audit_store.rs:147-176`. Filter at `:149`, spawn at `:169` (NOT awaited — no `.await` on the JoinHandle), guarded by `!alert_events.is_empty()` at `:167`. Handler returns `Ok(StatusCode::CREATED)` at `:179` immediately after spawn. IN-02 in REVIEW.md explicitly verified this isolation. |
| 5 | GET + PUT `/admin/alert-config` JWT-protected | PASS | `admin_api.rs:313-314` registers both routes in `protected_routes` Router, which applies `.layer(middleware::from_fn(admin_auth::require_auth))` at `:315`. `test_get_alert_config_requires_auth` asserts 401 on unauth GET. `test_put_alert_config_roundtrip` asserts PUT → GET round-trip of the full payload. |
| 6 | `validate_webhook_url` rejects http/loopback/link-local, allows RFC1918 + public https; BL-01 fix in place | PASS | 28-case table at `admin_api.rs:952-981`. Cases 27 (`https://[::ffff:127.0.0.1]`) and 28 (`https://[::ffff:169.254.169.254]`) both present and expect `false`. Fix at `admin_api.rs:221-226` using `ip.to_ipv4_mapped()` to re-check the v4 blocklist. Commit `0e32e7b` confirmed in git log. `cargo test test_validate_webhook_url` passes. |
| 7 | dlp-admin-cli System menu has "Alert Config" row opening `Screen::AlertConfig` | PASS | `render.rs:72-75` System menu array: `"Server Status", "Agent List", "SIEM Config", "Alert Config"` (plus implicit Back → 5 entries). `Screen::AlertConfig` present in `app.rs` (1 hit), `render.rs` (1 hit), `dispatch.rs` (15 hits including router arm, handlers, actions, test). `system_menu_has_alert_config` unit test passes. |
| 8 | `tracing::warn!` exclusive — no metrics in alert_router.rs | PASS | `grep -c 'tracing::warn' alert_router.rs` → **2**. `grep -cE 'AtomicU64\|counter\|metrics\|prometheus\|opentelemetry' alert_router.rs` → **0**. TM-04 honored verbatim. |
| 9 | `send_email` sends full AuditEvent as-is + TM-03 forward-compat rule documented | PASS | `grep sample_content\|content_snippet\|body_excerpt\|snippet dlp-common/src/audit.rs` → no matches (AuditEvent has no content fields today). Forward-compat rule documented at `alert_router.rs:7-19` (module doc), `:240` (function doc), `:252-254` (inline in send_email body). All three sites use "TM-03" + "forward-compat" keywords. |
| 10 | `from_env`, `load_smtp_config`, `load_webhook_config`, `test_from_env_no_vars` DELETED | PASS | `grep -cE 'from_env\|load_smtp_config\|load_webhook_config\|test_from_env_no_vars' alert_router.rs` → **0**. All env-var scaffolding removed. |

**Score:** 10/10 must-haves verified.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `dlp-server/src/db.rs` | `alert_router_config` table DDL + seed | VERIFIED | Lines 142-156; table/seed test passes |
| `dlp-server/src/alert_router.rs` | DB-backed AlertRouter with hot-reload | VERIFIED | 299 lines, `new(Arc<Database>)`, `load_config`, `send_alert`, `send_email`, `send_webhook`. Env-var helpers fully deleted. |
| `dlp-server/src/lib.rs` | `AppState.alert` field | VERIFIED | `pub alert: alert_router::AlertRouter` at line 33 |
| `dlp-server/src/main.rs` | AlertRouter construction + AppState wiring | VERIFIED | `AlertRouter::new(Arc::clone(&db))` at line 151; field included in AppState at line 154 |
| `dlp-server/src/admin_api.rs` | Payload + validator + 2 handlers + 2 routes | VERIFIED | `AlertRouterConfigPayload` (10 editable fields), `validate_webhook_url` (28-case test including BL-01 fix), `get_alert_config_handler`, `update_alert_config_handler`, both routes inside protected group |
| `dlp-server/src/audit_store.rs` | Fire-and-forget DenyWithAlert spawn | VERIFIED | Lines 147-176. Filter + guarded spawn; never awaited. |
| `dlp-admin-cli/src/app.rs` | `Screen::AlertConfig` variant | VERIFIED | Variant added with `(config, selected, editing, buffer)` shape mirroring `Screen::SiemConfig` |
| `dlp-admin-cli/src/screens/render.rs` | draw_alert_config + 5-item System menu | VERIFIED | Menu extended to 5 items; `const ALERT_FIELD_LABELS: [&str; 12]`; is_alert_secret/bool/numeric helpers present |
| `dlp-admin-cli/src/screens/dispatch.rs` | Handlers, actions, router arm, unit test | VERIFIED | `ALERT_ROW_COUNT = 12`, `action_load_alert_config`, `action_save_alert_config`, `handle_alert_config*` family, G9 numeric branch using `Value::Number`, pinning unit test |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `audit_store::ingest_events` | `AlertRouter::send_alert` | `state.alert.clone()` + `tokio::spawn` | WIRED | `audit_store.rs:168-171`. Fire-and-forget. |
| `main.rs` | `AppState.alert` | `AlertRouter::new(Arc::clone(&db))` | WIRED | `main.rs:151, 154` |
| `AlertRouter::send_alert` | `alert_router_config` row | `self.load_config()` → SQLite SELECT | WIRED | `alert_router.rs:185` (first line of send_alert) |
| `update_alert_config_handler` | `validate_webhook_url` | direct call before DB UPDATE | WIRED | `admin_api.rs` (non-empty webhook_url guarded) — `test_put_alert_config_rejects_http` + `test_put_alert_config_rejects_loopback` + `test_put_alert_config_accepts_rfc1918` all pass |
| admin_router | `get/update_alert_config_handler` | `.route("/admin/alert-config", ...)` inside `protected_routes` + JWT middleware layer | WIRED | `admin_api.rs:313-315` |
| dlp-admin-cli TUI `action_load_alert_config` | `GET /admin/alert-config` | `client.get::<Value>("admin/alert-config")` | WIRED | `dispatch.rs` |
| dlp-admin-cli TUI `action_save_alert_config` | `PUT /admin/alert-config` | `client.put::<Value, _>("admin/alert-config", &payload)` | WIRED | `dispatch.rs` (Value::Number for port, Value::Bool for enabled, Value::String for text) |
| `Screen::SystemMenu` index 3 | `action_load_alert_config` | `handle_system_menu` dispatch arm `3 => action_load_alert_config(app)` | WIRED | `dispatch.rs` (nav extended to 5 entries) |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `AlertRouter::send_alert` | `AlertRouterConfigRow` | `self.load_config()` → SELECT from SQLite | Yes (DB-backed, hot-reloaded per call) | FLOWING |
| `get_alert_config_handler` | `Json<AlertRouterConfigPayload>` | `spawn_blocking` SELECT on `alert_router_config` | Yes | FLOWING |
| `audit_store::ingest_events` → alert spawn | `alert_events: Vec<AuditEvent>` | Filter on `events.iter()` for `Decision::DenyWithAlert` | Yes (real audit events from POST body) | FLOWING |
| TUI Alert Config screen | `config: serde_json::Value` | `client.get("admin/alert-config")` → reaches real server handler | Yes | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Workspace builds clean | `cargo build --workspace` | Finished dev profile in 5.41s, 0 warnings | PASS |
| All tests pass | `cargo test --workspace` | 376 passed, 0 failed | PASS |
| Clippy clean (-D warnings) | `cargo clippy --workspace -- -D warnings` | Finished, 0 warnings | PASS |
| Formatter clean | `cargo fmt --check` | No output, exit 0 | PASS |
| validate_webhook_url 28-case table | `cargo test -p dlp-server --lib admin_api::tests::test_validate_webhook_url` | 1 passed, 0 failed | PASS |
| TM-04 warn! count | `grep -c 'tracing::warn' dlp-server/src/alert_router.rs` | 2 | PASS |
| TM-04 no metrics | `grep -cE 'AtomicU64\|counter\|metrics\|prometheus\|opentelemetry' dlp-server/src/alert_router.rs` | 0 | PASS |
| Env helpers deleted | `grep -cE 'from_env\|load_smtp_config\|load_webhook_config\|test_from_env_no_vars' dlp-server/src/alert_router.rs` | 0 | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| R-02 | 04-01, 04-02 | Route DenyWithAlert audit events to configured email and webhook destinations | SATISFIED | (a) Audit ingestion path filters DenyWithAlert and spawns `alert.send_alert` fire-and-forget at `audit_store.rs:147-176`. (b) SMTP path active iff `smtp_enabled && !host.empty() && !to.empty()`; webhook path active iff `webhook_enabled && !url.empty()` (`alert_router.rs` send_alert body). (c) Admin can configure both channels without restart via TUI → JWT-protected PUT → DB write → next send_alert picks it up. (d) BL-01 SSRF bypass fixed. End-to-end delivery requires human UAT (real SMTP/webhook), listed in human_verification section. |

### Anti-Patterns Found

No blocker-class anti-patterns were introduced by Phase 4. The REVIEW.md advisory findings (HI-01 reqwest timeout, HI-02 SMTP transport rebuild, ME-01 plaintext secrets on GET, ME-02 partial email failures, ME-03 doc asymmetry, LO-01..LO-03) are all documented in `04-REVIEW.md` and are scoped for `/gsd-code-review-fix`. None of them prevent the phase goal from being achievable; they are resilience and hardening follow-ups.

| Category | Count | Notes |
|----------|-------|-------|
| Blockers (phase-goal-breaking) | 0 | BL-01 was blocker-class but is fixed at commit 0e32e7b and re-verified via tests 27 + 28 |
| High (REVIEW.md advisory) | 2 | HI-01, HI-02 — tracked for gsd-code-review-fix, not verification gaps |
| Medium (REVIEW.md advisory) | 3 | ME-01..ME-03 — tracked for gsd-code-review-fix |
| Low (REVIEW.md advisory) | 3 | LO-01..LO-03 — tracked for gsd-code-review-fix |
| TODO/FIXME/placeholder in phase-touched files | 0 | No stubs; both SUMMARYs declare "Known Stubs: None" |

### Human Verification Required

See frontmatter `human_verification` block. Five operator-facing tests are required because they exercise real external services (SMTP server, webhook receiver) or visual TUI rendering that cannot be verified via grep/cargo-test.

### Gaps Summary

**No goal-blocking gaps.** All 10 must-haves verified against the actual codebase, all workspace tests pass (376/0), clippy and fmt are clean, the BL-01 SSRF bypass fix is in place with regression tests 27 + 28, TM-01..TM-04 are honored verbatim, and R-02 is structurally satisfied end-to-end (audit ingestion → DB config read → SMTP + webhook send, all behind fire-and-forget spawn).

The phase cannot be marked `passed` because delivery against a real SMTP server and a real webhook receiver has not been exercised — that is the R-02 "does it actually send the email" moment and requires live external services. Hence **human_needed**.

The REVIEW.md HI/MED/LOW findings are tracked separately for `/gsd-code-review-fix` and are NOT verification gaps — they are code-quality follow-ups that do not prevent the phase goal from being achievable.

---

_Verified: 2026-04-10_
_Verifier: Claude (gsd-verifier)_
