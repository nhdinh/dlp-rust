# Phase 60: Data Owner Review Queue + Admin TUI Screen - Context

**Gathered:** 2026-05-21
**Status:** Ready for planning
**Previous:** 2026-05-12 (updated after Phase 59 completion)

<domain>
## Phase Boundary

Phase 60 completes the **Data Owner Review Queue** workflow that Phase 59-04 started. Phase 59-04 built the LabelReviewQueue TUI screen and the confirm/reject API endpoints. Phase 60 adds the backend workflow features needed for production pilot use:

1. **Audit events** — every confirm/reject action emits a SIEM-ready audit event
2. **Data Owner filtering** — queue is scoped to the authenticated user's AD SID; admins see all
3. **Scanner confidence column** — add `scanner_confidence` to labels table for future scanner integration
4. **Department filter** — `GET /admin/labels` grows a `department` query parameter
5. **ABAC cache invalidation** — confirmed labels immediately invalidate the label resolution cache so policy enforcement sees the new tier

**Already implemented in Phase 59-04:**
- `LabelReviewQueue` TUI screen with c/r navigation
- `POST /admin/labels/{id}/confirm` and `POST /admin/labels/{id}/reject` endpoints
- `LabelList`, `LabelDetail`, `LabelForm` screens
- Basic `GET /admin/labels?state=temporary` filtering

**Phase 60 does NOT build:**
- A separate Data Owner CLI tool (deferred)
- Email-based approval links (deferred)
- Bulk confirm/reject (deferred to Phase 61)
- Auto-expiry (deferred to Phase 61)

**Phase 59 completion verified (2026-05-21):**
- `LabelService::invalidate_cache()` exists and works (`dlp-server/src/label_service.rs:259`)
- `confirm_label`/`reject_label` handlers exist in `dlp-server/src/admin_api.rs`
- `LabelReviewQueue` screen exists across `dlp-admin-cli/src/screens/labels.rs`, `render.rs`, `dispatch.rs`
- All integration points stable — Phase 60 plan can proceed as written.

</domain>

<decisions>
## Implementation Decisions

### Scope Boundary
- **D-01:** Phase 60 adds audit events + Data Owner filtering + notification hooks. The UI (LabelReviewQueue screen) already exists from Phase 59-04.
- **D-02:** Reuse `GET /admin/labels?state=temporary` — do NOT create a separate `/admin/labels/pending` alias. Add `department` filter to the existing `LabelFilter` query struct.
- **D-03:** Add `scanner_confidence` column to `labels` table now (f32, nullable, default NULL) so the v0.12.0 scanner can populate it without a schema migration.
- **D-04:** Confirm/reject emit standard SIEM audit events via the existing `audit_log` table with `action = "label_confirmed"` or `"label_rejected"`.

### Data Owner Access Model
- **D-05:** Data Owners access the queue through the same `dlp-admin-cli` TUI. No separate tool.
- **D-06:** Non-admin Data Owners can open the TUI if they belong to the AD `dlp-data-owners` group. Their queue view is read-only (confirm/reject only, no create/edit/delete).
- **D-07:** Admins see all labels in the queue; Data Owners see only labels where `owner_sid` matches their authenticated AD SID.

### Workflow Integration
- **D-08:** Confirm triggers label resolution cache invalidation (`LabelCache` RwLock clear) so ABAC enforcement sees the new tier within the next evaluation.
- **D-09:** Rejected labels remain in `rejected` state (audit trail preserved). Optional hard delete is admin-only via existing `DELETE /admin/labels/:id`.
- **D-10:** No auto-expiry in Phase 60. Expiry logic deferred to Phase 61 (Approval Workflow Engine).

### Claude's Discretion
- **D-11:** Department extraction from AD SID: use the SID's domain prefix as a lightweight department proxy, or require explicit `department` field on labels. Prefer explicit field for correctness.
- **D-12:** Notification hooks: emit a placeholder event (e.g., `alert_router::send` with `alert_type = "label_pending_review"`) that Phase 62 (Syslog Forwarder) or Phase 68 (Email) can consume. Do not build a full notification pipeline.
- **D-13:** JWT claims extension: add `sid: Option<String>` to `Claims` struct in `admin_auth.rs`. Look up SID from AD client at login time. Use this for owner scoping in label handlers without adding query params.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 59 Artifacts (integration points)
- `.planning/phases/59-label-service/59-01-SUMMARY.md` — ResolvedTier, LabelCache, strictness semantics
- `.planning/phases/59-label-service/59-02-SUMMARY.md` — Admin API handlers, pagination, expire endpoint
- `.planning/phases/59-label-service/59-03-SUMMARY.md` — ABAC integration, label_aware_enabled, fail-closed matrix
- `.planning/phases/59-label-service/59-04-SUMMARY.md` — LabelReviewQueue TUI screen, confirm/reject handlers

### Requirements
- `.planning/REQUIREMENTS.md` — LABEL-04 requirement traceability
- `.planning/ROADMAP.md` — Phase 60 goal and milestone context (v0.11.0)

### UI Specification
- `.planning/phases/60-data-owner-review-queue-admin-tui-screen/60-UI-SPEC.md` — TUI screen layout and interaction design

### Code References
- `dlp-server/src/label_service.rs` — `LabelService::invalidate_cache()` integration point
- `dlp-server/src/admin_api.rs` — Existing confirm/reject handlers to extend
- `dlp-admin-cli/src/screens/labels.rs` — LabelReviewQueue screen implementation
- `dlp-server/src/db/repositories/labels.rs` — LabelRepository patterns
- `dlp-server/src/siem_connector.rs` — SIEM relay for audit events
- `dlp-server/src/admin_auth.rs` — JWT Claims struct (to be extended with `sid`)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `LabelRepository` in `dlp-server/src/db/repositories/labels.rs` — has `list`, `list_by_state`, `get_by_id`, `update_state`
- `LabelFilter` in `dlp-server/src/admin_api.rs` — Query struct with `state`, `tier`, `owner_sid`
- `LabelReviewQueue` screen in `dlp-admin-cli/src/screens/dispatch.rs` and `render.rs`
- `AppState { pool, policy_store, siem, alert, ad }` — shared state pattern
- `audit_log` table — existing audit infrastructure
- `run_alter()` migration helper in `dlp-server/src/db/mod.rs` — idempotent column addition

### Established Patterns
- Admin API handlers return `Result<Json<T>, AppError>` with `tokio::task::spawn_blocking` for DB ops
- TUI screens follow `mod/dispatch/render/client/app.rs` extension pattern
- Cache invalidation: `policy_store.label_cache.clear()` (to be added)
- SIEM relay: `siem_connector::relay(audit_event)`
- Migrations: `run_alter(conn, sql, column, table)` swallows duplicate-column errors

### Integration Points
- `dlp-server/src/admin_api.rs` — add `department` to `LabelFilter`, add `scanner_confidence` to `LabelResponse`
- `dlp-common/src/label.rs` — add `scanner_confidence: Option<f32>` to `Label` struct
- `dlp-server/src/db/schema.rs` — add `scanner_confidence` column to labels table
- `dlp-admin-cli/src/client.rs` — add `department` param to `list_labels`
- `dlp-admin-cli/src/app.rs` — queue screen already exists; may need owner-scoping logic

</code_context>

<specifics>
## Specific Ideas

- The `scanner_confidence` column should be displayed in the LabelReviewQueue TUI as a percentage (e.g., "85%") when present, or "—" when null. This gives Data Owners a signal for prioritization even before the real scanner exists.
- Department filter should use a dropdown in the TUI (not free-text) to avoid mismatches. Populate from distinct `department` values in the labels table.
- Audit events should include the `before_state` and `after_state` (e.g., `temporary` -> `confirmed`) for compliance traceability.
- JWT `sid` claim: minimal change — add `sid: Option<String>` to `Claims`, look up from AD at login, use for owner scoping. Local "dlp-admin" gets `sid: None` and bypasses scoping.

</specifics>

<deferred>
## Deferred Ideas

- Bulk confirm/reject operations (Phase 61 — Approval Workflow Engine)
- Auto-expiry of pending labels (Phase 61)
- Email-based approval links for Data Owners (Phase 68 — Email/Outlook)
- Separate Data Owner CLI tool (not planned — same TUI with role filter is sufficient)
- Full notification pipeline with webhooks/Slack (post-v0.12.0)

</deferred>
