---
status: partial
phase: 04-wire-alert-router-into-server
source: [04-VERIFICATION.md]
started: 2026-04-10T00:00:00Z
updated: 2026-04-10T00:00:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. Real SMTP delivery end-to-end
expected: Admin configures SMTP (host, port, username, password, from, to, enabled=true) via dlp-admin-cli → System → Alert Config, saves; DLP agent then triggers a `DenyWithAlert` decision against a T3/T4 file; an email containing the full `AuditEvent` JSON body arrives at the configured SMTP destination within a few seconds, without restarting dlp-server.
result: [pending]

### 2. Real webhook delivery end-to-end
expected: Admin configures webhook (url = `https://<public-receiver>`, secret optional, enabled=true) via dlp-admin-cli Alert Config screen; DLP agent triggers a `DenyWithAlert` decision; the webhook receiver logs a POST request with the full `AuditEvent` JSON body and any HMAC header expected from the Phase 4 contract, within a few seconds.
result: [pending]

### 3. Hot-reload without server restart
expected: With dlp-server running and SMTP already configured, admin edits the SMTP host via dlp-admin-cli Alert Config screen and saves. The NEXT `DenyWithAlert` event (without any dlp-server restart) uses the new SMTP host — verifiable by watching the destination mail relay logs, or by pointing the host at a tarpit and confirming `tracing::warn!` fires for the new host.
result: [pending]

### 4. Webhook URL loopback/link-local rejection over real HTTP
expected: Admin attempts `PUT /admin/alert-config` with `webhook_url = "https://127.0.0.1"`, `https://[::1]`, `https://169.254.169.254`, and `https://[::ffff:127.0.0.1]` via curl (with a valid JWT). Each request returns HTTP 400 with an error body mentioning "loopback" or "link-local". The `alert_router_config` row is NOT modified on rejection. (Unit + integration tests cover this, but UAT re-verifies end-to-end through a real HTTP client.)
result: [pending]

### 5. dlp-admin-cli Alert Config screen renders 12 rows
expected: Launching `dlp-admin-cli`, logging in, navigating System → Alert Config displays exactly 12 selectable rows in this order: (1) smtp_host, (2) smtp_port, (3) smtp_username, (4) smtp_password, (5) smtp_from, (6) smtp_to, (7) smtp_enabled, (8) webhook_url, (9) webhook_secret, (10) webhook_enabled, (11) Save, (12) Back. The "Alert Config" menu item appears between "SIEM Config" and "Back" under System. smtp_password and webhook_secret fields are masked on display.
result: [pending]

## Summary

total: 5
passed: 0
issues: 0
pending: 5
skipped: 0
blocked: 0

## Gaps
