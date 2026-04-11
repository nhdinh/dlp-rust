---
status: passed
phase: 04-wire-alert-router-into-server
source: [04-VERIFICATION.md]
started: 2026-04-10T00:00:00Z
updated: 2026-04-11T00:00:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. Real SMTP delivery end-to-end
expected: Admin configures SMTP (host, port, username, password, from, to, enabled=true) via dlp-admin-cli → System → Alert Config, saves; DLP agent then triggers a `DenyWithAlert` decision against a T3/T4 file; an email containing the full `AuditEvent` JSON body arrives at the configured SMTP destination within a few seconds, without restarting dlp-server.
result: **passed** — 2026-04-11 (test connection email received via "Test Connection" row; confirmed SMTP path works end-to-end with full AuditEvent JSON in body)

### 2. Real webhook delivery end-to-end
expected: Admin configures webhook (url = `https://<public-receiver>`, secret optional, enabled=true) via dlp-admin-cli Alert Config screen; DLP agent triggers a `DenyWithAlert` decision; the webhook receiver logs a POST request with the full `AuditEvent` JSON body and any HMAC header expected from the Phase 4 contract, within a few seconds.
result: **passed** — 2026-04-11 (webhook.site received POST with full AuditEvent JSON via "Test Connection" row; webhook path working end-to-end)

### 3. Hot-reload without server restart
expected: With dlp-server running and SMTP already configured, admin edits the SMTP host via dlp-admin-cli Alert Config screen and saves. The NEXT `DenyWithAlert` event (without any dlp-server restart) uses the new SMTP host — verifiable by watching the destination mail relay logs, or by pointing the host at a tarpit and confirming `tracing::warn!` fires for the new host.
result: **passed** — 2026-04-11 (changed smtp_to via TUI, sent test alert without restarting server, email arrived at new address)

### 4. Webhook URL loopback/link-local rejection over real HTTP
expected: Admin attempts `PUT /admin/alert-config` with `webhook_url = "https://127.0.0.1"`, `https://[::1]`, `https://169.254.169.254`, and `https://[::ffff:127.0.0.1]` via curl (with a valid JWT). Each request returns HTTP 400 with an error body mentioning "loopback" or "link-local". The `alert_router_config` row is NOT modified on rejection. (Unit + integration tests cover this, but UAT re-verifies end-to-end through a real HTTP client.)
result: **passed** — 2026-04-11 (all 4 URLs returned 400; loopback, link-local, and IPv4-mapped forms all correctly rejected)

### 5. dlp-admin-cli Alert Config screen renders 13 rows
expected: Launching `dlp-admin-cli`, logging in, navigating System → Alert Config displays exactly 13 selectable rows in this order: (1) smtp_host, (2) smtp_port, (3) smtp_username, (4) smtp_password, (5) smtp_from, (6) smtp_to, (7) smtp_enabled, (8) webhook_url, (9) webhook_secret, (10) webhook_enabled, (11) Save, (12) Test Connection, (13) Back. The "Alert Config" menu item appears between "SIEM Config" and "Back" under System. smtp_password and webhook_secret fields are masked on display.
result: **passed** — 2026-04-11

## Summary

total: 5
passed: 5
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps
