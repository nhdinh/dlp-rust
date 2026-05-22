# Phase 52: DACL Tripwire + Repair Watcher + Protected Paths + DPAPI Recovery Doc - Context

**Gathered:** 2026-05-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 52 delivers a **kernel-enforced NTFS DACL backstop** for T3/T4 root paths that holds even when the hook DLL is unloaded, bypassed, or the agent crashes. It also ships the carried-forward DPAPI master-key recovery runbook.

**What Phase 52 builds:**
1. **Protected Paths registry** — SQLite tables (`protected_paths`, `protected_path_aces`) with foreign keys, CRUD admin API, and agent-side config sync.
2. **DACL tripwire application** — agent writes explicit Deny ACEs for `Authenticated Users` on T3/T4 root paths via `SetFileSecurity`, leaving SYSTEM and the DLP-Admin AD group unaffected.
3. **Repair watcher** — detects out-of-band ACL tampering via `ReadDirectoryChangesW(FILE_NOTIFY_CHANGE_SECURITY)` + 60-second polling backstop; restores canonical ACE order via subtree-walk replace-not-append.
4. **Two-phase staged update** — operator-initiated removals flow through a staging table to suppress spurious tamper alerts.
5. **DPAPI recovery runbook** — `docs/operations/dpapi-recovery.md` documenting re-init-from-env-vars and restore-from-backup flows.

**What Phase 52 does NOT build:**
- Admin TUI screens for Protected Paths management (Phase 54 — UX-01)
- Bypass Alerts feed integration (Phase 53/54)
- Monitor-only / audit-only mode awareness in tripwire (Phase 55)
- SD/optical/virtual drive volume-class tripwire (Phase 56)
- Automatic discovery of new subdirectories under protected roots (out of scope; repair handles existing files only)

**Depends on:** Phase 47 (DPAPI envelope from HARD-01); independent of BLOCK chain — can land in parallel from Phase 50 onwards
**Requirements:** DACL-01, DACL-02, DACL-03, DACL-04, DACL-05

</domain>

<decisions>
## Implementation Decisions

### Protected Path Source
- **D-01:** Auto-populate from Label Service T3/T4 paths. The `protected_paths` table stores a `source` enum (`auto` | `manual`) and an `is_override` flag. Auto-derived paths come from Phase 59's `labels` table where `tier IN ('T3', 'T4')` and `label_state = 'confirmed'`. Operator overrides take precedence.
- **D-02:** Manual entries are allowed for paths not in the label service (e.g., legacy data, non-file resources). The admin API accepts any absolute NTFS path with validation.

### Subtree Application Strategy
- **D-03:** Initial registration applies Deny ACEs **recursively** to all existing files and directories under the root. The repair watcher also operates recursively. A 10,000-file limit per protected path prevents runaway walks; exceeding the limit logs a warning and emits a `siem.dacl_tripwire_too_large` audit event.
- **D-04:** New files created under a protected root inherit the parent's ACL (including the Deny ACE) through normal NTFS inheritance, provided the parent has `SE_DACL_PROTECTED` unset. The agent does NOT intercept file creation events to patch ACLs — inheritance handles this. Broken inheritance (e.g., from `icacls /inheritance:r`) is repaired on the next watcher cycle.

### Repair Watcher Architecture
- **D-05:** In-agent module following the `WfpManager` pattern. A `DaclWatcher` struct owns a dedicated `std::thread` that calls `ReadDirectoryChangesW` in a blocking loop, pushing events through a bounded `crossbeam::channel` to a tokio task that performs ACL repair. This mirrors the Phase 49 ETW consumer architecture.
- **D-06:** Per-path watcher registration: each protected root gets its own `ReadDirectoryChangesW` handle. A `HashMap<PathBuf, WatcherHandle>` tracks active watchers. On protected path removal, the watcher is unregistered and the handle closed.
- **D-07:** 60-second polling backstop: a lightweight `tokio::time::interval` task independently scans all protected paths, comparing current ACLs against the canonical snapshot. This catches changes that `ReadDirectoryChangesW` might miss (e.g., network paths, recovery from agent downtime).

### Two-Phase Staged Update Protocol
- **D-08:** Agent-side `protected_paths_staging` SQLite table stores pending operations: `path TEXT PRIMARY KEY, operation TEXT CHECK(operation IN ('add', 'remove')), staged_at TEXT, applied_at TEXT`. The agent polls this table alongside the existing `policy_sync` cadence (30 seconds).
- **D-09:** When the server signals a removal, it inserts a `remove` row into the staging table. The agent applies the ACL removal, marks `applied_at`, and waits for the watcher to observe the ACE change. Because the staging row exists, the watcher suppresses the tamper alert. After 5 minutes, the staging row is garbage-collected.
- **D-10:** Out-of-band tampering (no staging row) triggers the full tamper response: restore canonical ACL + emit `siem.dacl_tamper_detected` audit event + route through SIEM relay.

### ACE Canonical Order and Content
- **D-11:** The canonical ACL order for a protected path is: (1) Explicit Deny ACEs (DLP tripwire first), (2) Explicit Allow ACEs, (3) Inherited ACEs. The DLP Deny ACE is an `ACCESS_DENIED_ACE` for the `Authenticated Users` SID (S-1-5-11) with mask `FILE_GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER`.
- **D-12:** SYSTEM (S-1-5-18) and the DLP-Admin AD group retain full access through explicit Allow ACEs placed before the Deny ACE. The DLP-Admin group SID is resolved from AD at agent startup and cached.
- **D-13:** The repair watcher stores a canonical ACL snapshot (serialized as SDDL string) per protected path in agent SQLite. Repair replaces the entire DACL with the canonical snapshot rather than appending, ensuring deterministic order.

### ACL Size Guard
- **D-14:** 60 KB ACL size limit. If a path's ACL exceeds 60 KB after adding the DLP Deny ACE, the operation is rejected with a clear error: `ERROR_INVALID_ACL` mapped to a user-readable message. This prevents pathological ACLs from destabilizing the agent.

### DPAPI Recovery Documentation
- **D-15:** Full operational runbook at `docs/operations/dpapi-recovery.md`. Includes: prerequisites, `re-init-from-env-vars` flow (regenerate KEK from env var seed), `restore-from-backup` flow (restore `secret_kek_history` row from offline backup), PowerShell verification snippets, and a UAT checklist.

### Claude's Discretion
- Use `protection.rs`'s raw ACL buffer construction pattern (`build_deny_everyone_dacl`) as the foundation, extended to target `Authenticated Users` instead of `Everyone`.
- The `DaclWatcher` should use `parking_lot::Mutex` for the watcher handle map (not `std::sync::Mutex`) for consistency with the codebase.
- Agent startup should apply all protected path ACLs before starting the watcher, ensuring the tripwire is active before monitoring begins.
- The `policy_sync` response should include a new `protected_paths` array alongside existing config sections.
- SDDL snapshot storage: use `ConvertSecurityDescriptorToStringSecurityDescriptorW` to generate the canonical SDDL, store as TEXT in agent SQLite.
- Repair should use `SetFileSecurityW` with a complete `SECURITY_DESCRIPTOR` (not incremental edits) to avoid partial-update races.
</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Architecture
- `.planning/ROADMAP.md` S"Phase 52: DACL Tripwire + Repair Watcher + Protected Paths + DPAPI Recovery Doc" — phase goal and 5 success criteria
- `.planning/PROJECT.md` S"Current Milestone: v0.10.0 Real-Time File Access Prevention" — milestone context, minifilter ban
- `.planning/STATE.md` S"Recent Decisions" — Decision 6: DACL tripwire design; Decision 4: asymmetric fail semantics

### Existing Code Patterns
- `dlp-agent/src/protection.rs` — Raw ACL buffer construction (`build_deny_everyone_dacl`). **MUST reuse** for tripwire Deny ACE.
- `dlp-agent/src/wfp_manager.rs` — `WfpManager` lifecycle pattern (`new`/`register`/`unregister`). **MUST mirror** for `DaclWatcher`.
- `dlp-agent/src/service.rs` — Agent service startup; where `DaclWatcher` is initialized.
- `dlp-agent/src/engine_client.rs` — Agent config polling (30s TOML hot-reload). **Extend** with `protected_paths` section.
- `dlp-server/src/db/mod.rs` — `init_tables()` and `run_migrations()` patterns. **Add** `protected_paths` and `protected_path_aces` tables.
- `dlp-server/src/admin_api.rs` — Admin API CRUD route pattern. **Add** `/admin/protected-paths` routes.
- `dlp-server/src/policy_store.rs` — In-memory cache pattern for protected paths.
- `dlp-common/src/audit.rs` — `AuditEvent` types. **Add** `dacl_tamper_detected` and `dacl_tripwire_too_large` event types.

### Related Phase Context
- `.planning/phases/50-shared-memory-classification-cache-fail-mode-state-machine/50-CONTEXT.md` — Shared-memory cache, fail-mode state machine, background thread decisions
- `.planning/phases/51-ntdll-syscall-stub-trampolines-edr-coexistence/51-CONTEXT.md` — Ntdll patching, `BypassAlert` types, background thread extension

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`build_deny_everyone_dacl`** (`dlp-agent/src/protection.rs`): Builds raw ACL buffers with `ACCESS_DENIED_ACE`. Extend to target `Authenticated Users` (S-1-5-11) with `FILE_GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER` mask.
- **`WfpManager`** (`dlp-agent/src/wfp_manager.rs`): `new`/`register`/`unregister` lifecycle pattern. Model `DaclWatcher` after this — struct with init, start, stop methods.
- **`AppState { pool, policy_store, siem, alert, ad }`** (`dlp-server/src/lib.rs`): Shared state pattern. Add `protected_paths: Arc<ProtectedPathsRepository>`.
- **`EngineClient`** (`dlp-admin-cli/src/client.rs`): HTTP client for admin API calls.
- **`crossbeam::channel`** (Phase 49): Bounded channel pattern between blocking OS thread and tokio task.

### Established Patterns
- **Repository pattern**: Stateless struct with `pool` parameter (like `AllowlistRepository`).
- **Admin API CRUD**: `list` (GET), `get_by_id` (GET), `create` (POST), `update` (PUT), `delete` (DELETE).
- **Agent config TOML poll**: 30s cadence, hash-based reload. New `[protected_paths]` section.
- **SIEM audit events**: `siem_connector::relay(audit_event)` for structured audit logging.
- **SQLite-backed staging**: Table with `staged_at`/`applied_at` timestamps for two-phase operations.
- **Raw Win32 ACL manipulation**: `SetFileSecurityW`, `GetFileSecurityW`, `InitializeSecurityDescriptor`, `SetSecurityDescriptorDacl`.

### Integration Points
- `dlp-server/src/db/mod.rs` — add `protected_paths` and `protected_path_aces` tables to `init_tables()`.
- `dlp-server/src/admin_api.rs` — add `/admin/protected-paths` routes following existing `.route()` pattern.
- `dlp-server/src/policy_store.rs` — add `protected_paths_cache: Arc<RwLock<Vec<ProtectedPath>>>`.
- `dlp-agent/src/service.rs` — add `DaclWatcher` initialization after agent startup.
- `dlp-agent/src/lib.rs` — add `dacl_watcher.rs` module.
- `dlp-agent/src/engine_client.rs` — extend config parsing with `protected_paths` array.
- `dlp-common/src/audit.rs` — add `DaclTamperDetected` and `DaclTripwireTooLarge` event type variants.
- `dlp-admin-cli/src/app.rs` — add `Screen::ProtectedPaths` (Phase 54 builds the full screen; Phase 52 adds backend only).

</code_context>

<specifics>
## Specific Ideas

- The `Authenticated Users` SID (S-1-5-11) should be constructed as a well-known SID via `CreateWellKnownSid(WinAuthenticatedUserSid, ...)` rather than hardcoding bytes, for clarity and architecture safety.
- The ACL mask for the Deny ACE should be `FILE_GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER` (0x00120116 | 0x00010000 | 0x00040000 | 0x00080000 = 0x00170116). This blocks write, delete, and permission changes while allowing read and execute.
- The canonical ACL snapshot should be stored as SDDL (Security Descriptor Definition Language) string, not raw bytes, for human-readable debugging and easier diff computation. Use `ConvertSecurityDescriptorToStringSecurityDescriptorW`.
- Repair watcher thread should use `WaitForSingleObject` on a shutdown event handle (not a busy loop), matching the Phase 50 background thread pattern.
- The 10,000-file limit for recursive application should use `WalkDir` or a custom BFS with depth-first ordering, skipping junctions and symlinks to avoid loops.
- For the DPAPI recovery doc, include a PowerShell one-liner to verify KEK integrity: `Test-Path "HKLM:\SOFTWARE\DLP\Backup"` and a restore script that reads the backup seed and re-initializes the KEK history table.
- The `protected_paths_staging` table should have a 5-minute TTL. A background task runs every 60 seconds and deletes rows where `applied_at IS NOT NULL AND datetime(staged_at, '+5 minutes') < datetime('now')`.
</specifics>

<deferred>
## Deferred Ideas

- Admin TUI Protected Paths screen (Phase 54 — UX-01)
- Admin TUI Bypass Alerts screen (Phase 54 — UX-02)
- ETW Kernel-File consumer for bypass correlation (Phase 53 — ETW-01..05)
- Monitor-only / audit-only per-policy mode awareness in tripwire (Phase 55 — MODE-01)
- SD/optical/virtual drive volume-class tripwire (Phase 56 — DRIVE-01..04)
- Automatic discovery of new subdirectories under protected roots (post-v0.10.0 — requires filesystem monitoring)
</deferred>

---

*Phase: 52-DACL Tripwire + Repair Watcher + Protected Paths + DPAPI Recovery Doc*
*Context gathered: 2026-05-22*
