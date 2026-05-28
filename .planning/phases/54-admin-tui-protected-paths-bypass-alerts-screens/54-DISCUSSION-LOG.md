# Phase 54: Admin TUI Protected Paths + Bypass Alerts Screens - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-28
**Phase:** 54-Admin TUI Protected Paths + Bypass Alerts Screens
**Areas discussed:** Protected Paths diff visualization, Protected Paths add/remove UX, Bypass Alerts list/detail view, Bypass Alerts ack semantics, Keyboard shortcuts, Navigation placement, Bypass Alerts filtering, Protected Paths tier display
**Mode:** `--auto` (Claude auto-selected recommended options for all gray areas)

---

## Protected Paths Diff Visualization

| Option | Description | Selected |
|--------|-------------|----------|
| Single list with source badge | One scrollable list; each row shows path, tier, and an `[A]`/`[M]` badge for auto/manual | ✓ |
| Two separate lists | Split pane or tabs: "Policy-Derived" and "Operator Overrides" | |
| Single list with override highlighting | Manual entries highlighted with bright color; auto entries dimmed | |

**Auto-selected:** Single list with source badge (follows existing list screen patterns; clear visual distinction without complex layout)
**Notes:** Badge uses `[A]` for auto (dim gray) and `[M]` for manual (bright cyan). Auto entries cannot be deleted. Manual entries can be deleted. This matches the `source` field already present in the server API.

---

## Protected Paths Add/Remove UX

| Option | Description | Selected |
|--------|-------------|----------|
| Free-text input + server validation + confirm dialog | Reuse `TextInput` screen for add; `Confirm` dialog for delete | ✓ |
| Multi-step form with browse dialog | Graphical directory picker (would require new crate) | |
| Inline editing | Edit path directly in the list row | |

**Auto-selected:** Free-text input + server validation + confirm dialog (reuses existing TUI patterns; server already validates via `GetFullPathNameW`)
**Notes:** Add flow: `a` key → `TextInput` → `POST /admin/protected-paths` → refresh list. Delete: `d` key → `Confirm` → `DELETE /admin/protected-paths/{id}`. Only manual entries can be deleted; attempting to delete auto shows error toast.

---

## Bypass Alerts List vs Detail View

| Option | Description | Selected |
|--------|-------------|----------|
| Compact list + Enter opens detail popup | List shows severity, timestamp, image_path, file_path, correlation_reason; Enter opens full detail | ✓ |
| Inline expansion | Each row expands in-place to show full details | |
| Always-full-detail list | Every row shows all fields (would be too wide for TUI) | |

**Auto-selected:** Compact list + Enter opens detail popup (follows `ApprovalDetail` pattern; keeps list readable)
**Notes:** Detail popup shows all `BypassAlertRow` fields including truncated SHA-256 (first 16 chars) and hex-formatted `file_object`.

---

## Bypass Alerts Ack Semantics

| Option | Description | Selected |
|--------|-------------|----------|
| Ack only | Single action: ack marks alert as acknowledged. No dismiss/delete. | ✓ |
| Ack + Dismiss | Two separate actions: ack = "I've seen this", dismiss = "not important" | |
| Ack + Delete | Ack marks seen; delete removes from database | |

**Auto-selected:** Ack only (server API only has `POST /admin/bypass-alerts/{id}/ack`; no dismiss or delete endpoint)
**Notes:** Acknowledged alerts remain in DB but are visually dimmed and can be filtered out via `h` key toggle. This matches the `acknowledged` boolean field on `BypassAlertRow`.

---

## Keyboard Shortcuts

| Option | Description | Selected |
|--------|-------------|----------|
| a/d/s/r/f/h pattern | `a`=add/ack, `d`=delete, `s`=sync, `r`=refresh, `f`=filter, `h`=hide ack'd | ✓ |
| Enter-based modal actions | All actions via Enter on action rows (slower, more keystrokes) | |
| Vim-style bindings | `j`/`k` nav, `x` delete, etc. (inconsistent with existing TUI) | |

**Auto-selected:** a/d/s/r/f/h pattern (consistent with existing screens: `a` for action, `d` for delete, `f` for filter cycling, `r` for refresh)
**Notes:** Protected Paths: `a`=add, `d`=delete, `s`=sync, `r`=refresh, Esc=back. Bypass Alerts: `a`=ack, `f`=cycle severity filter, `h`=toggle hide-acknowledged, `r`=refresh, Enter=detail, Esc=back.

---

## Navigation Placement

| Option | Description | Selected |
|--------|-------------|----------|
| SystemMenu | Both screens added to SystemMenu alongside Label Review Queue and Approval Management | ✓ |
| Top-level MainMenu | Direct access from main menu | |
| Submenu under Security | New "Security" submenu | |

**Auto-selected:** SystemMenu (groups operational/security screens together; avoids main menu bloat)
**Notes:** Placement: "Protected Paths" at index 10, "Bypass Alerts" at index 11, "Back" shifts to index 12.

---

## Bypass Alerts Filtering

| Option | Description | Selected |
|--------|-------------|----------|
| Severity cycling + acknowledged toggle | `f` cycles All/Crit/Warn/Info; `h` toggles hide-acknowledged | ✓ |
| Full multi-field filter | Filter by agent_id, pid, time range, severity, reason (complex UI) | |
| Server-side only | No client filters; always fetch all from server | |

**Auto-selected:** Severity cycling + acknowledged toggle (simple, covers 90% of triage workflows; matches existing filter patterns)
**Notes:** Severity maps to comma-separated `severity` query param. Acknowledged toggle maps to `acknowledged=false` or omitted.

---

## Protected Paths Tier Display

| Option | Description | Selected |
|--------|-------------|----------|
| Colored text | T3 = yellow, T4 = red, matching existing tier color conventions | ✓ |
| Text only | Plain "T3" / "T4" without color | |
| Icon/badge | Visual icon per tier | |

**Auto-selected:** Colored text (consistent with existing TUI color coding for classification tiers)

---

## Claude's Discretion

The following areas were auto-resolved based on codebase patterns and best practices:

- **Sort order:** Protected Paths sorted alphabetically by path (server-side `ORDER BY path`). Bypass Alerts sorted newest-first (server-side `ORDER BY created_at DESC`).
- **Optimistic UI on ack:** Local state updated immediately; reverted on server failure.
- **Toast colors:** Error = red, Success = green, Info = white.
- **file_object display:** Hex format (e.g., `0x00007FF6...`) since it's a kernel pointer.
- **correlation_reason display:** Human-friendly mapping (`NoHookJournal` → "No Hook Journal", etc.).
- **Pagination:** Fixed 20 items per page; page info in status bar.

---

## Deferred Ideas

- Bulk ack for bypass alerts — deferred to operational efficiency phase
- Real-time auto-refresh feed — deferred; manual refresh sufficient for v0.10.0
- Graphical path browser — out of scope for TUI
- Bypass alert export to CSV/JSON — deferred to reporting phase
- Copy-to-clipboard from detail view — requires clipboard crate; deferred
