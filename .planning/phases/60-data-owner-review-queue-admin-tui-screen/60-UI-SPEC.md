# Phase 60: Data Owner Review Queue — UI Design Contract (Delta)

**Date:** 2026-05-12
**Scope:** UI enhancements to existing Phase 59-04 LabelReviewQueue and LabelList screens
**Base:** Phase 59 UI-SPEC (`.planning/phases/59-label-service/59-UI-SPEC.md`) — all screen patterns, navigation, and styling inherited

---

## Changes from Phase 59

### 1. LabelReviewQueue — Add Scanner Confidence Column

**Layout change:**
- Table columns: Path, Tier, Owner SID, **Confidence**, Created
- Confidence displays:
  - Value present: `87%` (f32 * 100, rounded, no decimal)
  - Value null/None: `—` (em-dash, centered in cell)
- Column width: 12 chars (sufficient for "100%" or "—")

**Sorting:**
- Default sort: descending by `scanner_confidence` (highest confidence first), then by `created_at` ascending
- This lets Data Owners prioritize high-confidence scanner results

### 2. LabelList — Add Department Filter

**Filter enhancement:**
- `f` key cycling: all → temporary → confirmed → rejected → expired → **by department**
- When department filter is active:
  - Header shows: "Label Management [Dept: Engineering]"
  - A second key `d` (when in department mode) cycles through distinct department values from the DB
  - Or: show a picker popup with department list (follows `LabelTier` picker pattern)

**Preferred approach:** picker popup
- Press `f` until "Filter by Department" appears in status bar
- Press Enter to open picker with distinct `department` values from DB
- ↑/↓ to select, Enter to apply, Esc to cancel

### 3. Owner Scoping Indicator

**Layout change:**
- When a non-admin Data Owner (AD group `dlp-data-owners`) opens LabelReviewQueue:
  - Header shows: "Data Owner Review Queue [Your Queue]"
  - Only labels where `owner_sid` matches the authenticated user's SID are shown
  - `c` and `r` actions are enabled
- When an admin opens LabelReviewQueue:
  - Header shows: "Data Owner Review Queue [All Owners]"
  - All `temporary` labels shown
  - `c` and `r` actions are enabled

**Implementation note:** Owner scoping is server-side (API filters by authenticated SID), not client-side. The TUI reflects what the API returns.

### 4. Audit Toast on Confirm/Reject

**Interaction enhancement:**
- After `c` (confirm) or `r` (reject):
  - Existing: item disappears from queue (state changed, filter no longer matches)
  - New: status bar shows toast for 3 seconds: "Label confirmed — audit event emitted" or "Label rejected — audit event emitted"
  - Follows existing toast pattern in `dispatch.rs`

---

## Visual Style

- No new colors or styles — all reuse Phase 59 / existing ratatui theme
- Confidence column uses same text style as other data columns
- Department picker uses same popup style as `LabelTier` picker

## Accessibility / Usability

- Confidence percentage gives Data Owners a prioritization signal even before the scanner is built
- Department filter helps large organizations with multiple Data Owners
- Queue header clearly indicates scoped vs. admin view

---

*UI-SPEC generated for Phase 60 — delta-only. All base patterns, navigation, and styling defined in Phase 59 UI-SPEC.*
