# Phase 61: Approval Workflow Engine — UI Design Contract

**Date:** 2026-05-12
**Scope:** Admin TUI approval management screen + dlp-user-ui override request flow
**Base:** Phase 59/60 UI-SPECs — all screen patterns, navigation, and styling inherited

---

## Screens

### 1. ApprovalList (`Screen::ApprovalList`)

**Pattern:** `PolicyList` — scrollable table with inline actions

**Layout:**
- Header: "Approval Management"
- Table columns: Requester, Object, Action, Status, Expires
- Footer hint bar: `[g] Grant  [r] Revoke  [v] View  [f] Filter  [Esc] Back`

**Status indicators:**
- `pending` — yellow text
- `approved` — green text
- `rejected` — red text
- `revoked` — grey/dim text
- `expired` — grey/dim text with strikethrough

**Navigation:**
- ↑/↓: move selection
- `g`: grant selected pending approval (opens ApprovalGrant form)
- `r`: revoke selected approved approval (with confirmation)
- `v`: view detail (read-only popup)
- `f`: cycle filter (all → pending → approved → rejected → revoked → expired)
- Esc: return to SystemMenu

**Data source:** `GET /admin/approvals` (with optional `?status=` filter)

**Sorting:**
- Default: pending first, then by `valid_until` ascending (soonest to expire at top)

---

### 2. ApprovalDetail (read-only popup)

**Pattern:** `PolicyDetail` — single item read-only view

**Layout:**
- Full approval fields displayed as labeled rows:
  - ID
  - Requester SID
  - Approver SID (if granted)
  - Data Object ID / Path
  - Allowed Action
  - Destination Scope
  - Valid From / Valid Until
  - Status
  - Signature (for T4: shows "Board signed" or "Pending signature")
  - Created At
- Press Enter or Esc to dismiss

---

### 3. ApprovalGrant (form)

**Pattern:** `SiemConfig`/`LdapConfig` editing contract — navigable row list with editing mode and buffer

**Layout:**
- Header: "Grant Approval"
- Read-only rows (from the pending request):
  - Requester: `{sid}`
  - Object: `{path or object_id}`
  - Action: `{action}`
  - Destination: `{destination_scope}`
- Editable rows:
  - Expiry: `[1 hour]` (default, editable) — dropdown/picker with: 1h, 4h, 8h, 24h, custom
  - T4 Signature: `[ ] Required` (checkbox, read-only indicator if T4)
- Action row:
  - `[Enter] Grant  [Esc] Cancel`

**T4 flow:**
- If the object's tier is T4:
  - Show additional row: "Board Digital Signature Required"
  - Approver must check a confirmation box: "I have obtained Board digital signature"
  - The `POST /admin/approvals/:id/grant` request includes a `signature` field (hex-encoded Ed25519 signature)
  - If signature missing or invalid, server returns 400 with "T4 approval requires valid Board signature"

**Data source:** `POST /admin/approvals/:id/grant` with body `{ "valid_until": "ISO8601", "signature": "hex" (optional) }`

---

### 4. User UI Override Request (dlp-user-ui)

**Pattern:** Toast notification with optional action button

**Trigger:** When hook DLL returns DENY and the user clicks "Request Override"

**Flow:**
1. Toast appears: "Operation blocked by DLP policy. [Request Override]"
2. Clicking opens a small dialog:
   - Header: "Request Override"
   - Read-only: Action (`Write`/`Copy`/`Delete`/etc.), Path
   - Editable: Justification text (max 500 chars, multi-line)
   - Buttons: `[Submit]  [Cancel]`
3. On Submit:
   - Agent sends `UserMessage::RequestApproval` via named pipe
   - Server creates pending approval record
   - User sees confirmation: "Override request submitted. You will be notified when approved."
4. On approval grant:
   - Agent receives `UserMessage::ApprovalGranted` with token
   - User sees toast: "Override approved. You may retry the operation."
   - The token is cached in agent; next identical operation is ALLOWED

**Error states:**
- "Failed to submit request. Try again later."
- "An approval request for this operation is already pending."

---

## Visual Style

- Follow existing ratatui theme (borders, colors, highlight styles from `render.rs`)
- No new colors or styles — reuse existing `Style` constants
- Status colors:
  - `pending`: `Color::Yellow`
  - `approved`: `Color::Green`
  - `rejected`: `Color::Red`
  - `revoked`: `Color::DarkGray`
  - `expired`: `Color::DarkGray`
- Table rows: alternating background optional (follow PolicyList)
- Selected row: reverse video highlight

## Interaction Patterns

- All list screens follow `PolicyList` keyboard contract
- All form screens follow `SiemConfig`/`LdapConfig` editing contract
- All confirmation dialogs use `Confirm` screen
- HTTP errors display in status bar (follow existing error handling in dispatch.rs)
- T4 signature checkbox uses `InputPurpose::Toggle` pattern (like boolean config fields)

## Accessibility / Usability

- Row count displayed in header (e.g., "Approval Management (12 approvals)")
- Filter state displayed when active (e.g., "[Filter: pending]")
- Empty state: "No approvals found."
- Expiry picker shows human-readable labels ("1 hour", "4 hours") not raw timestamps
- T4 approvals visually distinguished with a `[T4]` badge in the Status column

---

*UI-SPEC generated for Phase 61 — delta from Phase 59/60 base. All core patterns inherited.*
