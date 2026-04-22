# Phase 28: Admin TUI Screens - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-23
**Phase:** 28-admin-tui-screens
**Areas discussed:** Device Registry TUI Screen, Managed Origins TUI + API, App-Identity Conditions Builder, Navigation Wiring

---

## Device Registry TUI Screen

| Option | Description | Selected |
|--------|-------------|----------|
| One line per device | `[BLOCKED] VID:1234 PID:5678 "SanDisk Ultra"` — compact, fits more devices | ✓ |
| Multi-line per device | Device name on top, VID/PID/serial below, trust tier on the right | |
| You decide | Match whatever looks closest to `PolicyList` existing style | |

**User's choice:** One line per device

| Option | Description | Selected |
|--------|-------------|----------|
| Sequential text inputs | One field at a time (VID → PID → serial → description → trust tier) | ✓ |
| Multi-row form | All 5 fields visible at once, Up/Down to navigate, Enter to edit | |
| You decide | Pick whichever is less code given the existing patterns | |

**User's choice:** Sequential text inputs

| Option | Description | Selected |
|--------|-------------|----------|
| Cycle on Enter | Enter cycles `blocked` → `read_only` → `full_access` | ✓ |
| Numbered list picker | Show all three options as a menu, arrow to select | |
| You decide | — | |

**User's choice:** Cycle on Enter

| Option | Description | Selected |
|--------|-------------|----------|
| Yes/No dialog | Reuses `Screen::Confirm` + `ConfirmPurpose` (same as policy delete) | ✓ |
| Inline confirmation | Press `d` to select, then `d` again to confirm | |
| You decide | — | |

**User's choice:** Yes/No dialog

---

## Managed Origins TUI + API (auto-selected)

| Option | Description | Selected |
|--------|-------------|----------|
| Domain string only | `"company.sharepoint.com"` — one field | |
| URL pattern | `"https://company.sharepoint.com/*"` — matches Chrome Enterprise format | ✓ |
| You decide | Pick whichever Chrome's Content Analysis connector expects | |

**User's choice:** [auto] URL pattern — matches Chrome Enterprise Content Analysis connector format

**Notes:** All remaining managed-origins decisions auto-selected at user's request.

---

## App-Identity Conditions Builder (auto-selected)

**User's choice:** [auto] Two separate `ConditionAttribute` variants (`SourceApplication`, `DestinationApplication`); AppField sub-picker inserted between Steps 1 and 2; field-constrained operators; trust_tier uses list picker, publisher/image_path use text buffer.

---

## Navigation Wiring (auto-selected)

**User's choice:** [auto] New "Devices & Origins" submenu in MainMenu for Device Registry and Managed Origins; app-identity picker wired into existing ConditionsBuilder flow.

---

## Claude's Discretion

- Accumulator type for in-progress Device Register sequential state
- Whether `operators_for()` takes an `Option<AppField>` parameter or caller branches
- `GET /admin/managed-origins` response shape (recommend `Vec<{ id, origin }>`)
- Exact column alignment for one-line device list

## Deferred Ideas

None — discussion stayed within phase scope.
