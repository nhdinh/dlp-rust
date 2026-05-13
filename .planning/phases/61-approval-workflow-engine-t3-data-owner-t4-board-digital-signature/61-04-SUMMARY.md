---
phase: 61
plan: 04
subsystem: dlp-admin-cli
subsystem_name: Admin TUI
subsystem_description: Approval management screens for the admin CLI
status: completed
completed_date: 2026-05-14
dependencies:
  - phase: 61
    plan: 02
    description: Approval API + Agent endpoints
  - phase: 59
    plan: 01
    description: Label Service DB schema + API
  - phase: 60
    plan: 01
    description: Data Owner Review Queue
---

# Phase 61 Plan 04: Admin TUI Approval Management Screens

## Overview

Implemented the admin TUI screens for approval workflow management: ApprovalList (with pagination and filtering), ApprovalDetail (with T4 canonical message display), and ApprovalGrant form (with T4 signature input). Follows existing screen patterns from PolicyList and LabelList.

## Changes Made

### New Files

| File | Description |
|------|-------------|
| `dlp-admin-cli/src/screens/approvals.rs` | Shared constants: hints, empty states, expiry options |

### Modified Files

| File | Changes |
|------|---------|
| `dlp-admin-cli/src/app.rs` | Added `ApprovalFilter` enum, `Screen::ApprovalList`, `Screen::ApprovalDetail`, `Screen::ApprovalGrant` variants, `ConfirmPurpose::RevokeApproval` |
| `dlp-admin-cli/src/client.rs` | Added 5 approval API methods: `list_approvals`, `get_approval`, `grant_approval`, `reject_approval`, `revoke_approval` |
| `dlp-admin-cli/src/screens/mod.rs` | Added `mod approvals;` |
| `dlp-admin-cli/src/screens/dispatch.rs` | Added `handle_approval_list`, `handle_approval_detail`, `handle_approval_grant`, `action_load_approval_list`, `action_revoke_approval`; updated SystemMenu (11 items) |
| `dlp-admin-cli/src/screens/render.rs` | Added `draw_approval_list`, `draw_approval_detail`, `draw_approval_grant` with status colors and T4 badge |

## Features Implemented

### ApprovalList Screen
- Scrollable table with columns: Requester, Object, Action, Status, Expires
- Status colors per UI-SPEC: pending=yellow, approved=green, rejected=red, revoked=grey, expired=grey+strikethrough
- [T4] badge shown for T4-tier approvals
- Pagination: PgUp/PgDn changes page, shows "Page X of Y (N total)"
- Filter cycling: `f` cycles through All/Pending/Approved/Rejected/Revoked/Expired and triggers API reload
- Keyboard shortcuts: `g` (grant), `r` (revoke with confirmation), `v` (view detail), `Esc` (back)

### ApprovalDetail Screen
- Read-only view showing all approval fields
- T4 canonical message displayed in copy-pasteable block for board member use
- Enter/Esc dismisses and returns to list

### ApprovalGrant Screen
- Read-only request info (requester, object, action, destination)
- Expiry picker with 4 options: 1h, 4h, 8h, 24h
- T4 signature hex input field (shown only for T4-tier approvals)
- Enter submits, Esc cancels

### SystemMenu Integration
- "Approval Management" added at index 9 (SystemMenu expanded to 11 items)

## Verification

```
cargo test -p dlp-admin-cli    # 242 passed
cargo clippy -p dlp-admin-cli -- -D warnings  # clean
cargo fmt --check -p dlp-admin-cli  # clean
cargo build --workspace  # succeeds
```

## Deviations from Plan

### Auto-fixed Issues

**None** — plan executed exactly as written. All acceptance criteria met.

### Architectural Notes

1. **State in Screen variants**: Followed existing codebase pattern (LabelList, PolicyList) by embedding state directly in Screen enum variants rather than adding separate fields to App struct. This maintains consistency with the existing architecture.

2. **serde_json::Value for API responses**: Followed existing client pattern — approval API methods return `serde_json::Value` rather than typed server response structs. This avoids pulling dlp-server into the admin CLI dependency graph.

3. **Context preservation on Esc from detail**: The plan required preserving list context. Since ApprovalDetail only stores the single detail response (not the full list), returning to the list triggers a reload via `action_load_approval_list`. This is the same pattern used by `handle_label_detail`.

## Threat Model Compliance

| Threat ID | Disposition | Implementation |
|-----------|-------------|----------------|
| T-61-18 (Spoofing / T4 signature) | mitigate | Signature validated server-side; TUI only collects input |
| T-61-19 (Info Disclosure / detail) | accept | Detail shows same fields as API returns |
| T-61-20 (DoS / filter cycling) | accept | Filter triggers server-side filtering |
| T-61-21 (EoP / revoke without confirm) | mitigate | Confirm screen requires explicit 'y' |
| T-61-27 (Info Disclosure / T4 canonical message) | accept | Message contains only public metadata |

## Self-Check

All 15 verification checks passed:
- approvals.rs exists: PASS
- ApprovalList variant in app.rs: PASS
- ApprovalFilter enum in app.rs: PASS
- RevokeApproval in ConfirmPurpose: PASS
- list_approvals client method: PASS
- grant_approval client method: PASS
- revoke_approval client method: PASS
- draw_approval_list in render.rs: PASS
- draw_approval_detail in render.rs: PASS
- draw_approval_grant in render.rs: PASS
- handle_approval_list in dispatch.rs: PASS
- handle_approval_grant in dispatch.rs: PASS
- action_load_approval_list in dispatch.rs: PASS
- SystemMenu has 11 items (verified by inspection): PASS
- Commit f7f8a58 exists: PASS

## Commit

- `f7f8a58` feat(61-04): add approval screen variants, client methods, and shared constants
