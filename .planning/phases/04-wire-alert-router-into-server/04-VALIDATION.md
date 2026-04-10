---
phase: 4
slug: wire-alert-router-into-server
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-10
---

# Phase 4 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Draft skeleton — planner will flesh out the Per-Task Verification Map with
> real task IDs after PLAN.md is produced. Do not sign off until every task
> in PLAN.md has a row below.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust built-in, workspace crates `dlp-server`, `dlp-admin-cli`, `dlp-common`) |
| **Config file** | `Cargo.toml` workspace root — no extra config |
| **Quick run command** | `cargo test -p dlp-server alert_router --lib` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~90 seconds full, ~15 seconds scoped |

---

## Sampling Rate

- **After every task commit:** `cargo test -p dlp-server alert_router --lib` (scoped to alert module)
- **After every plan wave:** `cargo test --workspace` (full) + `cargo clippy --workspace -- -D warnings` + `cargo fmt --check`
- **Before `/gsd-verify-work`:** Full workspace test + clippy must be green
- **Max feedback latency:** 90 seconds

---

## Per-Task Verification Map

> Populated by planner after PLAN.md tasks are enumerated. Each task must
> map to an automated command or a Wave 0 dependency row. Draft rows below
> anchor the expected coverage — planner replaces task IDs with real ones.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 4-01-XX | 01 | 1 | R-02 | TM-01 | `alert_router_config` row stores smtp_password as plaintext TEXT column (residual risk acknowledged) | unit | `cargo test -p dlp-server db::tests::test_alert_router_config_seed_row` | ❌ W0 | ⬜ pending |
| 4-01-XX | 01 | 1 | R-02 | TM-02 | `validate_webhook_url` rejects http://, loopback (127/8, ::1), link-local (169.254/16, fe80::/10); accepts RFC1918 + public https | unit | `cargo test -p dlp-server admin_api::tests::validate_webhook_url` | ❌ W0 | ⬜ pending |
| 4-01-XX | 01 | 1 | R-02 | TM-03 | `send_email` sends full `AuditEvent` fields; code-review checklist rule documented in PLAN Threat Model | manual (review) | — (documentation check) | N/A | ⬜ pending |
| 4-01-XX | 01 | 1 | R-02 | TM-04 | Exactly one `tracing::warn!` call per failure path in `send_alert`; no metrics crates added | unit | `cargo test -p dlp-server alert_router::tests::test_send_alert_warns_on_failure` + `grep -c 'tracing::warn' dlp-server/src/alert_router.rs` | ❌ W0 | ⬜ pending |
| 4-01-XX | 01 | 2 | R-02 | — | `AlertRouter::load_config` round-trips the DB row (default disabled → updated enabled) | unit | `cargo test -p dlp-server alert_router::tests::test_load_config_roundtrip` | ❌ W0 | ⬜ pending |
| 4-01-XX | 01 | 2 | R-02 | — | `AlertRouter::send_alert` hot-reloads config on every call (no caching) | unit | `cargo test -p dlp-server alert_router::tests::test_send_alert_hot_reloads` | ❌ W0 | ⬜ pending |
| 4-01-XX | 01 | 2 | R-02 | — | `GET /admin/alert-config` without JWT returns 401 | integration | `cargo test -p dlp-server admin_api::tests::get_alert_config_requires_auth` | ❌ W0 | ⬜ pending |
| 4-01-XX | 01 | 2 | R-02 | — | `PUT /admin/alert-config` round-trips payload through JWT auth | integration | `cargo test -p dlp-server admin_api::tests::put_alert_config_roundtrip` | ❌ W0 | ⬜ pending |
| 4-01-XX | 01 | 2 | R-02 | TM-02 | `PUT /admin/alert-config` with `http://` URL returns 400 with error body referencing "https" | integration | `cargo test -p dlp-server admin_api::tests::put_alert_config_rejects_http` | ❌ W0 | ⬜ pending |
| 4-01-XX | 01 | 2 | R-02 | TM-02 | `PUT /admin/alert-config` with loopback URL returns 400 | integration | `cargo test -p dlp-server admin_api::tests::put_alert_config_rejects_loopback` | ❌ W0 | ⬜ pending |
| 4-01-XX | 01 | 3 | R-02 | — | `ingest_events` spawns alert fire-and-forget without awaiting (ingest latency unchanged) | integration | `cargo test -p dlp-server audit_store::tests::ingest_events_alert_spawn_non_blocking` | ❌ W0 | ⬜ pending |
| 4-02-XX | 02 | 3 | R-02 | — | dlp-admin-cli System menu exposes "Alert Config" row (5-item menu) and `Screen::AlertConfig` renders 12 rows | unit | `cargo test -p dlp-admin-cli screens::dispatch::tests::system_menu_has_alert_config` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-server/src/db.rs` — add `test_alert_router_config_seed_row` test under existing `#[cfg(test)]` module
- [ ] `dlp-server/src/alert_router.rs` — rewrite `#[cfg(test)]` module with `test_load_config_roundtrip`, `test_send_alert_hot_reloads`, `test_send_alert_warns_on_failure`, `test_alert_router_disabled_default`; delete `test_from_env_no_vars`
- [ ] `dlp-server/src/admin_api.rs` — add test module (or extend existing) with `validate_webhook_url` table-driven tests covering the 26 cases from RESEARCH.md §validate_webhook_url, plus `get_alert_config_requires_auth`, `put_alert_config_roundtrip`, `put_alert_config_rejects_http`, `put_alert_config_rejects_loopback`
- [ ] `dlp-server/src/audit_store.rs` — add `ingest_events_alert_spawn_non_blocking` test using a mock AlertRouter that blocks indefinitely; assert ingest response returns under 100ms
- [ ] `dlp-admin-cli/src/screens/dispatch.rs` — add `system_menu_has_alert_config` test verifying 5-item match and label list

*Existing workspace test harness (`cargo test`) covers all requirements — no new frameworks.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| End-to-end DenyWithAlert email delivery | R-02 UAT | Requires real SMTP relay; integration test mocks the transport | 1. `cargo run -p dlp-server`. 2. In dlp-admin-cli System → Alert Config, set SMTP to a throwaway Mailtrap/Ethereal account, enable. 3. Trigger a DenyWithAlert via dlp-agent policy hit. 4. Verify email arrives with full AuditEvent payload. |
| End-to-end DenyWithAlert webhook delivery | R-02 UAT | Requires a live webhook receiver | 1. Run `python -m http.server 8080` or use webhook.site. 2. Set webhook_url to the receiver, enable. 3. Trigger DenyWithAlert. 4. Verify receiver logs the POST body. |
| Hot-reload (no restart) | R-02 UAT | Timing-sensitive; covered by unit test but UAT re-verifies | 1. With server running, change SMTP host via TUI. 2. Immediately trigger a DenyWithAlert. 3. Verify new host is used (check SMTP relay logs) without restarting dlp-server. |
| TM-03 forward-compat code-review rule | R-02 | Rule is a process, not code | When reviewing any future PR that adds a `sample_content` / content snippet field to `AuditEvent`, verify the same PR updates `send_email` to redact or omit it. Document in PLAN.md Threat Model section so reviewers can grep for the rule. |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter (set by planner after task map is finalized)

**Approval:** pending
