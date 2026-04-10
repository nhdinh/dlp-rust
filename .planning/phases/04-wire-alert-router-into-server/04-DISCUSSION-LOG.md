# Phase 4: Wire Alert Router into Server — Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in `04-CONTEXT.md` — this log preserves the alternatives considered.

**Date:** 2026-04-10 (focused review pass)
**Phase:** 04-wire-alert-router-into-server
**Mode:** Focused review (CONTEXT.md already existed — supplementing, not re-creating)
**Areas discussed:** SMTP secret storage, webhook SSRF hardening, email PII redaction, alert delivery observability

---

## Context at entry

- `04-CONTEXT.md` already existed from commit `7663bc5` (221 lines), with the full DB-backed-approach locked, `<decisions>` populated, `<canonical_refs>` built, and the threat model inputs explicitly flagged as MANDATORY for the PLAN.md security gate — but with no user ratification.
- `04-PLAN.md` already existed from commit `16475d5`, already aligned with the DB-backed approach.
- Code state: `alert_router.rs` still has `from_env()` / `load_smtp_config` / `load_webhook_config` / `test_from_env_no_vars` (i.e., Phase 4 is not yet executed — the plan is waiting).
- This focused review ratified the four open threat-model items and fixed stale ROADMAP and REQUIREMENTS text.

---

## TM-01: SMTP secret storage

| Option | Description | Selected |
|--------|-------------|----------|
| Plaintext, match Phase 3.1 (Recommended) | Store `smtp_password` as plaintext TEXT in `alert_router_config`, same as `splunk_token`. Rely on the DB file ACL. Document accepted residual risk. Zero added complexity, consistent with Phase 3.1 precedent. | ✓ |
| Column-level encryption | Encrypt `smtp_password` at rest with a key derived from `JWT_SECRET` or a new `DLP_DB_KEY` env var. Adds `aes-gcm` or `ring` dependency, new encrypt/decrypt path, breaks direct-DB diagnostics. | |
| Defer to future key-management phase | Ratify plaintext for now AND explicitly defer encryption-at-rest of ALL DB secrets to a dedicated future phase. | |

**User's choice:** Plaintext, match Phase 3.1.
**Notes:** Recommended default accepted. Documented in `<decisions>` as TM-01 and reinforced in `<deferred>` — encryption-at-rest for all secret columns (splunk_token, elk_api_key, smtp_password, webhook_secret) goes into a dedicated key-management phase.

---

## TM-02: Webhook SSRF hardening

| Option | Description | Selected |
|--------|-------------|----------|
| Validate scheme + block loopback/link-local (Recommended) | `PUT /admin/alert-config` parses the URL, requires `scheme == "https"`, rejects loopback (`127.0.0.0/8`, `::1`), rejects link-local (`169.254.0.0/16`, `fe80::/10`), ALLOWS RFC1918 (`10/8`, `172.16/12`, `192.168/16`). Textual validation only — no DNS round-trip. Factor into a standalone `validate_webhook_url` function with table-driven tests. | ✓ |
| https-only, no host check | Enforce `scheme == "https"` but do no host filtering. Allows `https://localhost`, `https://169.254.169.254` (cloud metadata). | |
| No validation (trust admin) | Match Phase 3.1's minimal validation for `splunk_url` / `elk_url`. Fully trusts admin + DB boundary. | |
| Allow-list in config | Add an allow-list of permitted webhook hosts in env var or DB. Strongest defense, highest operational friction. | |

**User's choice:** Validate scheme + block loopback/link-local.
**Notes:** Recommended default accepted. Validation is purely textual (no DNS lookup) to avoid TOCTOU and API latency. RFC1918 allowed because on-prem webhooks (internal Slack/Teams) are a legitimate DLP use case. Empty `webhook_url` is permitted and means webhook delivery is disabled. DNS-based validation and an http-with-`--dev`-flag escape hatch both deferred.

---

## TM-03: Email body PII redaction

**First round (based on false premise):**

| Option | Description | Selected |
|--------|-------------|----------|
| Redact sample_content, send the rest (Recommended) | Replace `sample_content` with `[REDACTED — N bytes]` before serializing. | ✓ (later corrected) |
| Send full event, no redaction | Serialize `AuditEvent` exactly as stored. | |
| Send only event ID + link | Email body = `event_id` + `event_type` + `classification` + a URL. | |

Claude then inspected `dlp-common/src/audit.rs:99-156` and discovered **`AuditEvent` has no `sample_content` field**. The first-round answer was aimed at a non-existent field. Claude surfaced the correction and re-asked.

**Second round (corrected):**

| Option | Description | Selected |
|--------|-------------|----------|
| Send full event as-is, forward-compatible redaction rule (Recommended) | Serialize every field. Lock a PLAN.md code-review rule: any future phase adding a content-snippet field MUST update `send_email` in the same phase. | ✓ |
| Redact resource_path + justification now | Basename-only for `resource_path`, redact `justification` to `[REDACTED — N chars]`. Adds a projection step. | |
| Send only event ID + dashboard link | Email body = `event_id` + metadata + URL. Requires `GET /audit/events/{id}` support. | |
| Redact resource_path only, keep justification | Basename-only path, keep the full justification text. | |

**User's final choice:** Send full event as-is, forward-compatible redaction rule.
**Notes:** Rationale: no content-snippet field exists in `AuditEvent` today. Every field is either metadata or operator-useful routing data. The PLAN.md security checklist must include the forward-compatible rule: any field name matching `sample_content`, `content_preview`, `matched_text`, `snippet`, `body`, `raw`, `payload_content`, `clipboard_text`, `file_excerpt`, `plaintext` (or similar) added in a future phase triggers a required update to `send_email` in that same phase.

---

## TM-04: Alert delivery observability

| Option | Description | Selected |
|--------|-------------|----------|
| tracing::warn only (Recommended) | Match Phase 3.1's SIEM relay. Log at warn level. Trust the operator's log aggregation. | ✓ |
| Per-alert counter in AppState | `alert_failures: Arc<AtomicU64>` on AppState, new `GET /admin/alert-status` endpoint, surface in dlp-admin-cli Server Status. | |
| Audit-event backchannel | Insert `EventType::SystemAlertFailed` rows into `audit_events`. Queryable via `GET /audit/events`. | |

**User's choice:** tracing::warn only.
**Notes:** Recommended default accepted. Consistent with Phase 3.1 observability pattern. Operators running dlp-server already require log aggregation for the SIEM relay pattern, so adding a second observability channel for alerts would be disproportionate scope. Concrete log message format locked in `<decisions>` TM-04: `tracing::warn!(error = %e, "alert email delivery failed (best-effort)")` and `tracing::warn!(error = %e, "alert webhook delivery failed (best-effort)")`. Future observability work (counters, metrics, dashboards) deferred to a dedicated phase.

---

## Claude's Discretion (carried forward from original CONTEXT.md)

- Exact handler function names and module layout (follow Phase 3.1 naming style).
- Exact wording of tracing log messages at INFO / WARN level (except TM-04 WARN messages which are now locked).
- Exact wording of TUI footer hints and status messages.
- Whether to add a dedicated `test_alert_config_seed_row` or reuse `test_tables_created`-style assertion.
- How SMTP port is validated (u16 vs i64 with cast).

## Deferred Ideas (carried forward + expanded in this round)

- HMAC signing of webhook payloads using `webhook_secret` — future security phase.
- Rate limiting of alerts — Phase 8 or its own phase.
- Alert acknowledgment / escalation — new capability, out of scope.
- Encryption-at-rest for all DB secret columns — dedicated key-management phase (TM-01 ratified this deferral).
- Mock-SMTP test path — later test-hardening phase.
- Alert delivery metrics / counters / dashboards — dedicated observability phase (TM-04 ratified this deferral).
- DNS-based webhook_url validation — future policy phase (TM-02 explicitly chose textual-only).
- http:// webhook support via `--dev` flag — revisit only if https-only proves too painful operationally.

## Housekeeping (not a decision, but done in this pass)

- **Fixed stale ROADMAP description** for Phase 4 — previous text said "Initialize AlertRouter from env vars at startup", now reflects the DB-backed approach and the full file list.
- **Fixed stale REQUIREMENTS.md R-02 acceptance criterion** — previous text said "When SMTP/webhook env vars are set…", now reflects the dlp-admin-cli TUI workflow.
