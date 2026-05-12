# Phase 59: Label Service — UI Design Contract

**Date:** 2026-05-12
**Scope:** Admin TUI screens for label management and Data Owner review queue

---

## Screens

### 1. LabelList (`Screen::LabelList`)

**Pattern:** `PolicyList` — scrollable table with inline actions

**Layout:**
- Header: "Label Management"
- Table columns: Path (truncated), Type, Tier, State, Owner
- Footer hint bar: `[n] New  [e] Edit  [d] Delete  [v] View  [f] Filter  [Esc] Back`

**Navigation:**
- ↑/↓: move selection
- `n`: start label creation (multi-step input flow)
- `e`: edit selected label (multi-step input flow, pre-filled)
- `d`: delete with confirmation
- `v`: view detail (read-only popup)
- `f`: cycle filter (all → temporary → confirmed → rejected → expired)
- Esc: return to SystemMenu

**Data source:** `GET /admin/labels` (with optional `?state=` filter)

### 2. LabelReviewQueue (`Screen::LabelReviewQueue`)

**Pattern:** Simplified `PolicyList` with action keys instead of navigation

**Layout:**
- Header: "Data Owner Review Queue"
- Table columns: Path, Tier, Owner SID, Created
- Footer hint bar: `[c] Confirm  [r] Reject  [↑/↓] Navigate  [Esc] Back`

**Navigation:**
- ↑/↓: move selection
- `c`: confirm selected temporary label → `POST /admin/labels/{id}/confirm`
- `r`: reject selected temporary label → `POST /admin/labels/{id}/reject`
- Esc: return to SystemMenu

**Data source:** `GET /admin/labels?state=temporary`

### 3. LabelDetail (read-only popup)

**Pattern:** `PolicyDetail` — single item read-only view

**Layout:**
- Full label fields displayed as labeled rows
- Press Enter or Esc to dismiss

### 4. Multi-step Label Creation/Edit

**Pattern:** `RegisterDevice` multi-step `InputPurpose` flow

**Steps:**
1. `InputPurpose::LabelPath` — text input for absolute path
2. `InputPurpose::LabelObjectType` — picker (file/folder/archive)
3. `InputPurpose::LabelTier` — picker (T1/T2/T3/T4/Unclassified-Blocked)
4. `InputPurpose::LabelOwnerSid` — text input for owner SID (optional, Enter to skip)
5. `InputPurpose::LabelParentId` — text input for parent label ID (optional, Enter to skip)
6. Confirmation screen showing all values, then `POST /admin/labels`

For edit flow: pre-fill all steps with existing values, use `PUT /admin/labels/{id}`

---

## Visual Style

- Follow existing ratatui theme (borders, colors, highlight styles from `render.rs`)
- No new colors or styles — reuse existing `Style` constants
- Table rows: alternating background optional (follow PolicyList)
- Selected row: reverse video highlight

## Interaction Patterns

- All list screens follow `PolicyList` keyboard contract
- All form screens follow `SiemConfig`/`LdapConfig` editing contract
- All confirmation dialogs use `Confirm` screen
- HTTP errors display in status bar (follow existing error handling in dispatch.rs)

## Accessibility / Usability

- Row count displayed in header (e.g., "Label Management (42 labels)")
- Filter state displayed when active (e.g., "[Filter: temporary]")
- Empty state: "No labels found. Press [n] to create one."

---

*UI-SPEC generated for Phase 59 — simple TUI screens following established patterns. No novel UI components required.*
