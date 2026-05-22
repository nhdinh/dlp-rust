# Phase 52: DACL Tripwire + Repair Watcher + Protected Paths + DPAPI Recovery Doc - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-22
**Phase:** 52-DACL Tripwire + Repair Watcher + Protected Paths + DPAPI Recovery Doc
**Areas discussed:** Protected Path Source, Subtree Application, Repair Watcher Architecture, Two-Phase Staged Update, ACE Canonical Order, ACL Size Guard, DPAPI Recovery Doc

---

## Protected Path Source

| Option | Description | Selected |
|--------|-------------|----------|
| Auto-populate from Label Service | Derive protected paths from Phase 59 T3/T4 confirmed labels; allow operator overrides | ✓ |
| Manual-only | Operator configures every protected path via admin API; no auto-discovery | |

**Auto-selected:** `[--auto] Selected: Auto-populate from Label Service (recommended default).`
**Notes:** Label Service already exists with T3/T4 paths. Auto-population reduces operator toil while preserving override capability.

---

## Subtree Application

| Option | Description | Selected |
|--------|-------------|----------|
| Recursive with 10K limit | Apply Deny ACEs recursively to all existing files under root; 10,000-file cap | ✓ |
| Root-only | Apply Deny ACE only to the root directory; rely on inheritance for children | |

**Auto-selected:** `[--auto] Selected: Recursive with 10K limit (recommended default).`
**Notes:** Root-only leaves existing files with broken inheritance unprotected. Recursive is thorough and the limit prevents runaway walks.

---

## Repair Watcher Architecture

| Option | Description | Selected |
|--------|-------------|----------|
| In-agent module (WfpManager pattern) | New `dacl_watcher.rs` in dlp-agent with dedicated OS thread + channel | ✓ |
| Separate watcher process | Standalone executable for watcher; more complex IPC | |

**Auto-selected:** `[--auto] Selected: In-agent module (recommended default).`
**Notes:** Follows existing WfpManager pattern. Simpler lifecycle, no new binary to deploy.

---

## Two-Phase Staged Update

| Option | Description | Selected |
|--------|-------------|----------|
| Agent-side staging table | `protected_paths_staging` SQLite table; agent polls via policy_sync | ✓ |
| Signed operation tokens | Cryptographic tokens from server to agent; more complex, no replay protection needed | |

**Auto-selected:** `[--auto] Selected: Agent-side staging table (recommended default).`
**Notes:** SQLite staging is simpler and sufficient. The agent already polls config; extending with staging rows is minimal overhead.

---

## ACE Canonical Order

| Option | Description | Selected |
|--------|-------------|----------|
| DLP Deny first, then explicit allows, then inherited | Standard Windows canonical order with DLP at the top | ✓ |
| DLP Deny appended at end | Simpler but less deterministic; could be overridden by explicit allows | |

**Auto-selected:** `[--auto] Selected: DLP Deny first, then explicit allows, then inherited (recommended default).`
**Notes:** Deny-first is the Windows canonical order and ensures the tripwire is evaluated before any allow ACEs.

---

## DPAPI Recovery Doc Depth

| Option | Description | Selected |
|--------|-------------|----------|
| Full operational runbook | Prerequisites, both recovery flows, PowerShell snippets, UAT checklist | ✓ |
| Minimal two-flow doc | Just re-init-from-env-vars and restore-from-backup without detailed steps | |

**Auto-selected:** `[--auto] Selected: Full operational runbook (recommended default).`
**Notes:** DPAPI recovery is a critical operational procedure. Full runbook with verification steps is essential for production deployments.

---

## Claude's Discretion

- Raw ACL buffer construction reuses `protection.rs` pattern with `Authenticated Users` SID.
- `DaclWatcher` uses `parking_lot::Mutex` for handle map consistency.
- Agent applies all protected path ACLs before starting watcher.
- SDDL snapshot for canonical ACL storage (human-readable).
- `SetFileSecurityW` with complete SECURITY_DESCRIPTOR for atomic repair.
- 5-minute TTL on staging rows with 60-second garbage collection.

## Deferred Ideas

- Admin TUI Protected Paths screen (Phase 54)
- ETW Kernel-File consumer for bypass correlation (Phase 53)
- Monitor-only / audit-only mode awareness in tripwire (Phase 55)
- SD/optical/virtual drive volume-class tripwire (Phase 56)
- Automatic discovery of new subdirectories under protected roots (post-v0.10.0)
