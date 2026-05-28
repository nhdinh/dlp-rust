# Phase 54: Admin TUI Protected Paths + Bypass Alerts Screens - Context

**Gathered:** 2026-05-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 54 delivers two new admin TUI screens that let an operator fully manage Protected Paths and triage Bypass Alerts without touching SQLite, the registry, or any raw config file.

**Depends on:** Phase 52 (Protected Paths server endpoints: CRUD + sync) and Phase 53 (Bypass Alerts server endpoints: list + ack)
**Requirements:** UX-01, UX-02

**What Phase 54 builds:**
1. **Protected Paths screen** — scrollable list of all T3/T4 protected paths with visual diff between policy-derived (`source = "auto"`) and operator-override (`source = "manual"`) entries; add/remove actions round-trip through admin API; sync action re-imports policy-derived paths
2. **Bypass Alerts screen** — paginated event feed with per-event detail (image path + SHA-256, file path, operation, QPC timestamp, correlation reason); ack with single keypress; filter by severity and acknowledged status
3. **Eight new client methods** in `EngineClient` (`list_protected_paths`, `create_protected_path`, `update_protected_path`, `delete_protected_path`, `sync_protected_paths`, `list_bypass_alerts`, `ack_bypass_alert`, plus screen navigation entry points)
4. **Full TUI wiring** — `Screen` enum variants, dispatch handlers, render functions, menu placement, unit tests

**What Phase 54 does NOT build:**
- Bulk add/remove for protected paths (deferred)
- Bulk ack for bypass alerts (deferred)
- Real-time auto-refresh feed for bypass alerts (manual refresh only)
- Graphical path browser (free-text input only)
- Bypass alert dismissal separate from ack (server only supports ack)
- Email/webhook notification on new bypass alert (deferred to Phase 68)

</domain>

<decisions>
## Implementation Decisions

### Protected Paths Screen Layout
- **D-01:** Single scrollable list with source badge — each row shows path, tier, and a badge indicating `auto` (policy-derived) or `manual` (operator override). No separate tabs or dual-pane layout. The badge is a short prefix like `[A]` or `[M]` with color (auto = dim gray, manual = bright cyan).
- **D-02:** Tier display as colored text — T3 in yellow, T4 in red, matching existing TUI color conventions for classification tiers.
- **D-03:** Path validation happens server-side via `GetFullPathNameW` (already implemented in Phase 52). The TUI sends the raw path string; the server returns 400 with a clear error if validation fails. The TUI surfaces this as a toast.

### Protected Paths Add/Remove UX
- **D-04:** Add path via `TextInput` screen (reused pattern) — operator types a raw path, client calls `POST /admin/protected-paths` with `source = "manual"`. On success, returns to the ProtectedPaths list with refreshed data.
- **D-05:** Delete requires confirmation — `d` key on a selected path opens `Confirm` dialog with `ConfirmPurpose::DeleteProtectedPath`. Only `manual` entries can be deleted; `auto` entries show an error toast if delete is attempted.
- **D-06:** Sync action (`s` key) calls `POST /admin/protected-paths/sync` to re-import policy-derived paths from labels. This is idempotent and preserves manual entries. Shows success toast with count of synced paths.

### Bypass Alerts Screen Layout
- **D-07:** Compact list view as default — columns: severity (colored badge), timestamp (relative, e.g. "2m ago"), image_path (truncated), file_path (truncated), correlation_reason. Enter opens `BypassAlertDetail` popup with full fields.
- **D-08:** Detail popup shows all fields from `BypassAlertRow`: id, agent_id, severity, correlation_reason, image_path, image_sha256, file_path, operation, timestamp, file_object, pid, acknowledged, created_at. SHA-256 is shown as truncated hex (first 16 chars) with full value available via copy-to-clipboard (deferred — display only in Phase 54).
- **D-09:** Only `ack` action exists — the server endpoint is `POST /admin/bypass-alerts/{id}/ack`. No dismiss/delete. Acknowledged alerts remain in the database but are visually dimmed and can be filtered out.

### Bypass Alerts Filtering
- **D-10:** Severity filter cycles through: All → Crit → Warn → Info → All (bound to `f` key, matching `ApprovalFilter` pattern). This maps to the `severity` query param on `GET /admin/bypass-alerts`.
- **D-11:** Acknowledged toggle (bound to `h` key for "hide ack'd") — cycles between showing unacknowledged only and showing all. Maps to `acknowledged=false` or no filter.
- **D-12:** Manual refresh via `r` key — no auto-refresh timer. The operator explicitly refreshes. This avoids distracting the operator during triage.

### Keyboard Shortcuts
- **D-13:** Protected Paths screen: `a` = add new path (TextInput), `d` = delete selected (Confirm, manual only), `s` = sync policy-derived paths, `r` = refresh list, Esc = back to SystemMenu.
- **D-14:** Bypass Alerts screen: `a` = ack selected alert, `f` = cycle severity filter, `h` = toggle hide-acknowledged, `r` = refresh, Enter = open detail, Esc = back to SystemMenu.
- **D-15:** Navigation keys (Up/Down) follow existing `nav()` helper pattern; PageUp/PageDown for pagination if list exceeds screen height.

### Navigation Placement
- **D-16:** Both screens live in `SystemMenu` — "Protected Paths" and "Bypass Alerts" added after "Approval Management" (index 10 and 11, pushing "Back" to index 12). This groups operational/security screens together.

### Pagination
- **D-17:** Both screens use client-side pagination with fixed page size of 20 items. Server supports `limit`/`offset`; TUI fetches page-by-page. Page info shown in status bar: "Page 1/3 (45 total)".

### Claude's Discretion
- Protected Paths list should be sorted by path alphabetically (server-side `ORDER BY path`).
- Bypass Alerts list should be sorted by `created_at DESC` (newest first, server-side).
- On ack, the TUI should immediately mark the row as acknowledged in local state (optimistic UI) and show a success toast. If the server call fails, revert the local state and show an error toast.
- Error toasts should use `StatusKind::Error` (red) for server errors, `StatusKind::Success` (green) for successful actions, `StatusKind::Info` (white) for neutral messages.
- The `file_object` field in bypass alert detail should be displayed as hex (e.g., `0x00007FF6...`) since it's a Windows kernel pointer value.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 52 Artifacts (Protected Paths server API)
- `.planning/phases/52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-doc/52-06-SUMMARY.md` — Protected Paths Admin API + Config Sync (CRUD routes, Windows API path validation, AgentConfigPayload extension)
- `.planning/phases/52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-doc/52-03-SUMMARY.md` — Protected Paths Server-Side Schema (SQLite schema, repository, conflict-aware sync)

### Phase 53 Artifacts (Bypass Alerts server API)
- `.planning/phases/53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring/53-05-SUMMARY.md` — Server-Side Bypass Alert Storage (SQLite schema, repository, HTTP routes, SIEM relay)
- `.planning/phases/53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring/53-06-SUMMARY.md` — SIEM + Alert Router Wiring (event routing, integration tests)

### Requirements & Roadmap
- `.planning/ROADMAP.md` — Phase 54 goal, success criteria, requirements UX-01/UX-02
- `.planning/PROJECT.md` — Tech stack (ratatui 0.29, crossterm 0.28), TUI architecture

### Existing TUI Patterns (MUST follow)
- `dlp-admin-cli/src/screens/labels.rs` — LabelList + LabelReviewQueue screen pattern (scrollable table, pagination, filter cycling)
- `dlp-admin-cli/src/screens/approvals.rs` — ApprovalList + ApprovalDetail + ApprovalGrant pattern (list with actions, detail popup, grant form)
- `dlp-admin-cli/src/screens/dispatch.rs` — Event dispatch routing pattern
- `dlp-admin-cli/src/screens/render.rs` — Render function pattern
- `dlp-admin-cli/src/client.rs` — EngineClient HTTP client pattern (GET/POST/PUT/DELETE)
- `dlp-admin-cli/src/app.rs` — Screen enum, App state, filter enums, ConfirmPurpose pattern

### Server API Contracts
- `dlp-server/src/admin_api.rs` — Protected paths handlers (lines ~4845-5000) and bypass alerts handlers (lines ~5235-5300)
- `dlp-server/src/db/repositories/protected_paths.rs` — ProtectedPathsRepository
- `dlp-server/src/db/repositories/bypass_alerts.rs` — BypassAlertsRepository, BypassAlertFilter, BypassAlertRow

### Code Conventions
- `.planning/codebase/CONVENTIONS.md` — Rust coding standards, naming, error handling, doc comments
- `.planning/codebase/STRUCTURE.md` — dlp-admin-cli module organization
- `.planning/codebase/STACK.md` — Dependency versions (ratatui 0.29, crossterm 0.28, reqwest 0.12)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`LabelList` / `LabelReviewQueue` screens** (`dlp-admin-cli/src/screens/labels.rs` via dispatch/render) — scrollable table with selected index, pagination, filter cycling. Model both new screens after this pattern.
- **`ApprovalList` / `ApprovalDetail` screens** (`dlp-admin-cli/src/screens/approvals.rs` via dispatch/render) — list with actions, detail popup, status message. Bypass Alerts screen closely mirrors this.
- **`EngineClient`** (`dlp-admin-cli/src/client.rs`) — Already has GET/POST/PUT/DELETE helpers. Add 8 new methods following existing patterns.
- **`TextInput` screen** (`dlp-admin-cli/src/app.rs` + dispatch/render) — Reuse for protected path add flow. Use `InputPurpose::AddProtectedPath`.
- **`Confirm` dialog** (`dlp-admin-cli/src/app.rs` + dispatch/render) — Reuse for delete confirmation. Add `ConfirmPurpose::DeleteProtectedPath`.
- **`LabelFilter` / `ApprovalFilter` enums** (`dlp-admin-cli/src/app.rs`) — Model `BypassAlertSeverityFilter` after these with `next()` cycling and `as_str()` wire mapping.

### Established Patterns
- **Screen lifecycle**: Enum variant in `app.rs` → dispatch handler in `dispatch.rs` → render function in `render.rs` → client method in `client.rs` → menu entry in `handle_main_menu`/`handle_system_menu`.
- **Config form screens** (SiemConfig, AlertConfig, etc.) use navigable row lists with editing mode. Protected Paths and Bypass Alerts are **list screens**, not config forms — follow `PolicyList`/`LabelList` pattern instead.
- **Error surfacing**: All client methods return `Result<T>`. Server errors are caught and displayed as `StatusKind::Error` toasts via `app.set_status()`.
- **Pagination**: `page` (0-based) + `page_size` (fixed at 20) + `total` from server. Page count = `(total + page_size - 1) / page_size`.
- **Filter cycling**: `f` key advances filter enum; filter value sent as query param on refresh.

### Integration Points
- `dlp-admin-cli/src/app.rs` — Add `Screen::ProtectedPathList`, `Screen::ProtectedPathDetail`, `Screen::BypassAlertList`, `Screen::BypassAlertDetail` variants. Add `BypassAlertSeverityFilter` enum. Add `ConfirmPurpose::DeleteProtectedPath`, `InputPurpose::AddProtectedPath`.
- `dlp-admin-cli/src/client.rs` — Add `list_protected_paths()`, `create_protected_path()`, `update_protected_path()`, `delete_protected_path()`, `sync_protected_paths()`, `list_bypass_alerts()`, `ack_bypass_alert()`.
- `dlp-admin-cli/src/screens/dispatch.rs` — Add `handle_protected_path_list()`, `handle_bypass_alert_list()`, `handle_bypass_alert_detail()`, etc.
- `dlp-admin-cli/src/screens/render.rs` — Add `draw_protected_path_list()`, `draw_bypass_alert_list()`, `draw_bypass_alert_detail()`, etc.
- `dlp-server/src/admin_api.rs` — API already exists from Phases 52/53; no server changes needed for Phase 54.

</code_context>

<specifics>
## Specific Ideas

- The Protected Paths screen should visually distinguish `auto` entries from `manual` entries. `auto` entries are dimmer and have a lock icon or `[A]` prefix to indicate they cannot be deleted (only overridden by adding a manual entry with the same path). Manual entries have `[M]` and can be deleted.
- The Bypass Alerts detail popup should show the image SHA-256 as a truncated hex string (first 16 chars) because full SHA-256 is 64 chars and overwhelms the TUI width. Consider showing the full value on a second line.
- The `correlation_reason` field values (`NoHookJournal`, `OpMismatch`, `HookOverwritten`) should have human-friendly display text in the TUI (e.g., "No Hook Journal", "Operation Mismatch", "Hook Overwritten").
- Severity badges: `crit` = red background, `warn` = yellow, `info` = blue — matching conventional alert coloring.
- The sync action on Protected Paths should show a confirmation toast like "Synced 3 policy-derived paths" or "No changes" to give the operator feedback.
- Both screens should support the existing `PageUp`/`PageDown` keys for pagination navigation, not just `r` for refresh.

</specifics>

<deferred>
## Deferred Ideas

- Bulk ack for bypass alerts (select multiple, ack all at once) — deferred to operational efficiency phase
- Real-time auto-refresh bypass alerts feed (WebSocket or polling) — deferred; manual refresh is sufficient for v0.10.0
- Graphical path browser dialog — out of scope; free-text input is standard for this TUI
- Bypass alert export to CSV/JSON — deferred to reporting phase
- Protected Paths drag-and-drop reordering — not needed; alphabetical sort is sufficient
- Copy SHA-256 or path to clipboard from detail view — requires clipboard crate integration; deferred

</deferred>

---

*Phase: 54-Admin TUI Protected Paths + Bypass Alerts Screens*
*Context gathered: 2026-05-28*
