---
phase: 22-dlp-common-foundation
plan: "03"
subsystem: dlp-agent, dlp-user-ui
tags:
  - rust
  - dlp-agent
  - dlp-user-ui
  - ipc
  - serde
dependency_graph:
  requires:
    - dlp-common::AppIdentity (from Plan 01)
  provides:
    - Pipe3UiMsg::ClipboardAlert.source_application Option<AppIdentity>
    - Pipe3UiMsg::ClipboardAlert.destination_application Option<AppIdentity>
  affects:
    - dlp-agent/src/ipc/messages.rs (extended)
    - dlp-user-ui/src/ipc/messages.rs (extended identically)
    - dlp-agent/src/ipc/pipe3.rs (pattern match updated)
    - dlp-user-ui/src/ipc/pipe3.rs (struct literal updated)
tech_stack:
  added: []
  patterns:
    - serde(default, skip_serializing_if = "Option::is_none") for optional wire fields
    - Deliberate duplication of IPC message structs across crates (D-14)
    - Backward-compatible JSON deserialization via serde(default)
key_files:
  created: []
  modified:
    - dlp-agent/src/ipc/messages.rs
    - dlp-agent/src/ipc/pipe3.rs
    - dlp-user-ui/src/ipc/messages.rs
    - dlp-user-ui/src/ipc/pipe3.rs
decisions:
  - "No test module added to dlp-user-ui/src/ipc/messages.rs — agent-side tests cover the serde behavior; duplicating tests adds maintenance burden with no protection gain"
  - "pipe3.rs files updated with None for new fields rather than forwarding real identity — Phase 25 is the designated consumer; premature population would be out of scope"
  - "Rule 1 auto-fix applied to pipe3.rs in both crates — struct literals missing required fields after ClipboardAlert extension"
metrics:
  duration: "~20 minutes"
  completed: "2026-04-22"
  tasks_completed: 2
  tasks_total: 2
  files_created: 0
  files_modified: 4
  tests_added: 4
requirements:
  - PHASE-22-INFRA
---

# Phase 22 Plan 03: Pipe3 ClipboardAlert AppIdentity Extension Summary

**One-liner:** Pipe3UiMsg::ClipboardAlert extended with source_application and destination_application Option<AppIdentity> fields in both dlp-agent and dlp-user-ui, byte-for-byte identical, with serde(default) backward compatibility.

## What Was Built

Two IPC message files extended identically with new optional fields on `Pipe3UiMsg::ClipboardAlert`:

| Field | Type | Serde behavior |
|-------|------|----------------|
| `source_application` | `Option<AppIdentity>` | skipped when None; defaults to None on missing JSON key |
| `destination_application` | `Option<AppIdentity>` | skipped when None; defaults to None on missing JSON key |

Both fields use `#[serde(default, skip_serializing_if = "Option::is_none")]` ensuring:
- Legacy ClipboardAlert frames (no new fields) deserialize successfully with both fields as `None`
- Frames with `None` values serialize without the keys (wire-format compatibility)
- Phase 25 can populate these fields when the source-resolver is wired up

The `Pipe2AgentMsg::Toast` variant was explicitly NOT modified (D-16 compliance).

The two `messages.rs` files remain deliberately duplicated (D-14). Consolidation into `dlp-common` is deferred beyond Phase 22.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Extend Pipe3UiMsg::ClipboardAlert in dlp-agent + 4 unit tests | a362a54 | dlp-agent/src/ipc/messages.rs, dlp-agent/src/ipc/pipe3.rs |
| 2 | Mirror identical ClipboardAlert extension in dlp-user-ui | aaf4464 | dlp-user-ui/src/ipc/messages.rs, dlp-user-ui/src/ipc/pipe3.rs |

## Verification Results

- `cargo test -p dlp-agent --lib ipc::messages` — 4/4 new tests pass
- `cargo test -p dlp-agent --lib` — 149/149 tests pass (zero regressions)
- `cargo build -p dlp-agent` — zero warnings
- `cargo build -p dlp-user-ui` — zero warnings
- `cargo build --workspace` — zero warnings
- Byte-for-byte serde attribute mirror check (Pitfall 3 mitigation): `diff` on serde attribute and field declaration lines between both files — empty output (clean)
- `grep -c '#[allow(dead_code)]' dlp-user-ui/src/ipc/messages.rs` — 2 (both Pipe2AgentMsg and Pipe3UiMsg preserved)
- `grep -c 'Toast { title: String, body: String }'` — 1 in each file (D-16 honored)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Pattern match in dlp-agent/src/ipc/pipe3.rs missing `..` wildcard**
- **Found during:** Task 1 — first `cargo test` compile
- **Issue:** `Pipe3UiMsg::ClipboardAlert` match arm in `pipe3.rs route()` did not use `..` to ignore the two new fields, causing E0027
- **Fix:** Added `..` to the existing pattern (line 198 of pipe3.rs)
- **Files modified:** dlp-agent/src/ipc/pipe3.rs
- **Commit:** a362a54

**2. [Rule 1 - Bug] Struct literal in dlp-user-ui/src/ipc/pipe3.rs missing new required fields**
- **Found during:** Task 2 — `cargo build -p dlp-user-ui`
- **Issue:** `send_clipboard_alert()` constructs `Pipe3UiMsg::ClipboardAlert { ... }` without the two new fields, causing E0063
- **Fix:** Added `source_application: None, destination_application: None` with a comment noting Phase 25 will populate them
- **Files modified:** dlp-user-ui/src/ipc/pipe3.rs
- **Commit:** aaf4464

## Known Stubs

`dlp-user-ui/src/ipc/pipe3.rs` `send_clipboard_alert()` passes `source_application: None` and `destination_application: None`. This is intentional — Phase 25's source-resolver is the designated consumer. The stub is documented in a code comment.

## Threat Flags

No new threat surface beyond what the plan's threat model covers. T-22-12 (file-divergence tampering) is mitigated by the byte-for-byte diff check confirmed in verification above. All other threats (T-22-11, T-22-13, T-22-14, T-22-15) accepted per plan rationale.

## Downstream Handoff

- **Phase 25**: Wire `source_application` and `destination_application` in `send_clipboard_alert()` using the WinVerifyTrust resolver results. Both IPC structs are ready to carry the identity data.
- **Phase 26**: Policy evaluator can match on `source_application.trust_tier` and `destination_application.trust_tier` from the ClipboardAlert payload.

## Self-Check: PASSED

- `dlp-agent/src/ipc/messages.rs` modified: FOUND
- `dlp-user-ui/src/ipc/messages.rs` modified: FOUND
- `dlp-agent/src/ipc/pipe3.rs` modified: FOUND
- `dlp-user-ui/src/ipc/pipe3.rs` modified: FOUND
- Commit a362a54 exists: FOUND
- Commit aaf4464 exists: FOUND
- 4 new tests pass: VERIFIED
- 149 total dlp-agent lib tests pass: VERIFIED
- Zero build warnings (workspace): VERIFIED
- Byte-for-byte serde mirror: VERIFIED
- D-16 honored (Pipe2AgentMsg unchanged): VERIFIED
