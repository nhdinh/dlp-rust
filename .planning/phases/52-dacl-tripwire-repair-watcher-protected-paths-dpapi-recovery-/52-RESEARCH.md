# Phase 52: DACL Tripwire + Repair Watcher + Protected Paths + DPAPI Recovery Doc - Research

**Researched:** 2026-05-22
**Domain:** Windows NTFS DACL manipulation, `ReadDirectoryChangesW` security monitoring, SQLite schema design, DPAPI operational recovery
**Confidence:** HIGH for Windows APIs and codebase patterns; MEDIUM for two-phase staged update edge cases

---

## Summary

Phase 52 delivers a kernel-enforced NTFS DACL backstop for T3/T4 root paths that holds even when the hook DLL is unloaded, bypassed, or the agent crashes. The implementation spans three architectural layers: (1) server-side SQLite registry of protected paths with admin CRUD API, (2) agent-side DACL tripwire writer that injects explicit Deny ACEs for `Authenticated Users` via `SetFileSecurityW`, and (3) a repair watcher using `ReadDirectoryChangesW(FILE_NOTIFY_CHANGE_SECURITY)` with a 60-second polling backstop to detect and repair out-of-band ACL tampering.

The DPAPI recovery runbook (DACL-05) documents re-init-from-env-vars and restore-from-backup flows when DPAPI unprotect fails on agent restart, building on Phase 47's `secret_kek_history` table and `SecretCrypto` envelope.

**Primary recommendation:** Build the `DaclWatcher` as an in-agent module following the established `WfpManager` lifecycle pattern (`new`/`register`/`unregister`), with a dedicated `std::thread` for `ReadDirectoryChangesW` blocking loops, crossbeam channel to tokio repair task, and `parking_lot::Mutex` for the per-path watcher handle map. Use SDDL strings for canonical ACL snapshot storage (human-readable, diffable). Apply the raw ACL buffer construction pattern from `protection.rs` extended to target `Authenticated Users` (S-1-5-11).

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Protected Paths registry | API / Backend (dlp-server) | -- | SQLite tables + admin CRUD; single source of truth |
| DACL tripwire application | API / Backend (dlp-agent service) | -- | Agent runs as SYSTEM; has privilege to modify ACLs on T3/T4 paths |
| Repair watcher (event-driven) | API / Backend (dlp-agent service) | -- | `ReadDirectoryChangesW` on dedicated OS thread; blocks until event or shutdown |
| Repair watcher (polling backstop) | API / Backend (dlp-agent service) | -- | `tokio::time::interval` task; lightweight ACL comparison |
| Two-phase staged updates | API / Backend (dlp-agent service) | -- | Agent-side SQLite `protected_paths_staging` table; polled alongside config sync |
| DPAPI recovery documentation | CDN / Static (docs) | -- | Operational runbook; no runtime component |
| Admin API CRUD | API / Backend (dlp-server) | -- | JWT-protected axum routes following existing pattern |
| Agent config sync | API / Backend (dlp-agent) | API / Backend (dlp-server) | Server pushes `protected_paths` array in `AgentConfigPayload`; agent polls every 30s |

---

## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Auto-populate from Label Service T3/T4 paths. `protected_paths` table stores `source` enum (`auto` | `manual`) and `is_override` flag.
- **D-02:** Manual entries allowed for paths not in label service.
- **D-03:** Initial registration applies Deny ACEs recursively to all existing files/directories under root. 10,000-file limit per protected path.
- **D-04:** New files inherit parent's ACL through normal NTFS inheritance. Agent does NOT intercept file creation events.
- **D-05:** `DaclWatcher` follows `WfpManager` pattern: dedicated `std::thread` + `crossbeam::channel` to tokio task.
- **D-06:** Per-path watcher registration: each protected root gets its own `ReadDirectoryChangesW` handle. `HashMap<PathBuf, WatcherHandle>` tracks active watchers.
- **D-07:** 60-second polling backstop independently scans all protected paths, comparing current ACLs against canonical snapshot.
- **D-08:** Agent-side `protected_paths_staging` SQLite table: `path TEXT PRIMARY KEY, operation TEXT, staged_at TEXT, applied_at TEXT`.
- **D-09:** Server signals removal via staging table. Agent applies ACL removal, marks `applied_at`. Watcher suppresses tamper alert while staging row exists. 5-minute GC after `applied_at`.
- **D-10:** Out-of-band tampering triggers full response: restore canonical ACL + emit `siem.dacl_tamper_detected` + SIEM relay.
- **D-11:** Canonical ACL order: (1) Explicit Deny ACEs (DLP tripwire first), (2) Explicit Allow ACEs, (3) Inherited ACEs.
- **D-12:** SYSTEM (S-1-5-18) and DLP-Admin AD group retain full access through explicit Allow ACEs before Deny.
- **D-13:** Repair stores canonical ACL snapshot as SDDL string per protected path. Repair replaces entire DACL (not appends).
- **D-14:** 60 KB ACL size limit. Exceeded → reject with `ERROR_INVALID_ACL` mapped to user-readable message.
- **D-15:** DPAPI recovery runbook at `docs/operations/dpapi-recovery.md` with prerequisites, both flows, PowerShell snippets, UAT checklist.

### Claude's Discretion
- Use `protection.rs`'s raw ACL buffer construction (`build_deny_everyone_dacl`) extended for `Authenticated Users`.
- `DaclWatcher` uses `parking_lot::Mutex` for watcher handle map (not `std::sync::Mutex`).
- Agent startup applies all protected path ACLs before starting watcher.
- `policy_sync` response includes `protected_paths` array alongside existing config sections.
- SDDL snapshot storage via `ConvertSecurityDescriptorToStringSecurityDescriptorW`.
- Repair uses `SetFileSecurityW` with complete `SECURITY_DESCRIPTOR` (not incremental edits).

### Deferred Ideas (OUT OF SCOPE)
- Admin TUI Protected Paths screen (Phase 54 -- UX-01)
- Admin TUI Bypass Alerts screen (Phase 54 -- UX-02)
- ETW Kernel-File consumer for bypass correlation (Phase 53 -- ETW-01..05)
- Monitor-only / audit-only mode awareness in tripwire (Phase 55 -- MODE-01)
- SD/optical/virtual drive volume-class tripwire (Phase 56 -- DRIVE-01..04)
- Automatic discovery of new subdirectories under protected roots (post-v0.10.0)

---

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DACL-01 | Tripwire writer using `SetNamedSecurityInfoW` + `PROTECTED_DACL_SECURITY_INFORMATION`; explicit `ACCESS_DENIED_ACE` at top of DACL with `OBJECT_INHERIT_ACE \| CONTAINER_INHERIT_ACE`; mask covers `FILE_WRITE_DATA \| FILE_APPEND_DATA \| DELETE \| FILE_WRITE_ATTRIBUTES \| WRITE_DAC \| WRITE_OWNER`; SID = S-1-5-11; 60 KB ACL guard | `protection.rs` provides raw ACL buffer pattern; `device_controller.rs` provides `SetFileSecurityW` + SDDL patterns; `Win32_Security_Authorization` feature already enabled |
| DACL-02 | Repair watcher using `ReadDirectoryChangesW` with `FILE_NOTIFY_CHANGE_SECURITY` per root; 60s poll backstop; subtree-walk replace-not-append for ACE updates (canonical order per MS-DTYP) | `process_watcher.rs` provides crossbeam channel + dedicated thread pattern; `notify` crate not used for security events -- raw `ReadDirectoryChangesW` needed |
| DACL-03 | `protected_paths` + `protected_path_aces` SQLite tables with FKs; repository; admin API CRUD (`GET`/`POST`/`PUT`/`DELETE /admin/protected-paths/:id`); agent pulls via `policy_sync` | `allowlist.rs` repository provides CRUD pattern; `admin_api.rs` provides axum route pattern; `db/mod.rs` provides `init_tables()` + `run_migrations()` |
| DACL-04 | Two-phase staged updates: server sends `protected_paths_pending_change` first → agent stages expected-state diff → on next ACE event watcher knows operator-initiated removals don't trigger spurious tamper alerts | `apply_payload_to_config()` in `service.rs` provides config diff/merge pattern; agent SQLite `offline_audit_queue` provides local table pattern |
| DACL-05 | DPAPI master-key recovery runbook: documents `re-init-from-env-vars` and `restore-from-backup` flows when DPAPI unprotect fails; lives at `docs/operations/dpapi-recovery.md` | Phase 47 research documents DPAPI failure modes; `secret_kek_history` table schema documented; `SecretCrypto::load_active_or_bootstrap()` failure path exists |

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `windows` | 0.62.2 (agent), 0.58 (server) [VERIFIED: cargo registry] | Win32 API bindings (`SetFileSecurityW`, `GetFileSecurityW`, `ReadDirectoryChangesW`, `CreateWellKnownSid`, `ConvertSecurityDescriptorToStringSecurityDescriptorW`, `ConvertStringSecurityDescriptorToSecurityDescriptorW`) | Already in workspace; `Win32_Security_Authorization` feature already enabled in dlp-agent |
| `rusqlite` | 0.39.0 [VERIFIED: cargo registry] | SQLite for agent-side `protected_paths_staging` table and server-side `protected_paths` tables | Already in both `dlp-agent` and `dlp-server` Cargo.toml |
| `crossbeam-channel` | 0.5.15 [VERIFIED: cargo registry] | Bounded channel between `ReadDirectoryChangesW` blocking thread and tokio repair task | Already in `dlp-agent/Cargo.toml` from Phase 49 |
| `parking_lot` | 0.12.5 [VERIFIED: cargo registry] | `Mutex` for watcher handle map (faster, no poisoning) | Already in workspace; used by `WfpManager` |
| `serde` + `serde_json` | workspace | Config serialization, audit event JSON | Project standard |
| `thiserror` | workspace | Error type definitions | Project standard |
| `tracing` | workspace | Structured logging | Project standard |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `walkdir` | 2.5.0 [VERIFIED: cargo registry] | Recursive directory traversal for subtree ACE application | When implementing the 10,000-file limit recursive walk; `std::fs::read_dir` is alternative but `walkdir` handles junctions/symlinks correctly |
| `uuid` | workspace | UUID generation for `protected_paths` table rows | Server-side row IDs |
| `chrono` | workspace | ISO-8601 timestamp generation | `staged_at`, `applied_at`, `created_at` fields |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `ReadDirectoryChangesW` (raw) | `notify` crate (8.2.0) | `notify` abstracts `ReadDirectoryChangesW` but does NOT expose `FILE_NOTIFY_CHANGE_SECURITY` in its public API -- the security filter is required for ACL tamper detection. Raw Win32 API is necessary. [VERIFIED: notify crate docs -- no security event type] |
| `walkdir` | `std::fs::read_dir` recursive | `std::fs::read_dir` requires manual junction/symlink loop detection. `walkdir` provides `follow_links` and `same_file_system` options out of the box. Accept the dependency. |
| SDDL snapshot | Raw security descriptor bytes | SDDL is human-readable for debugging and diff computation. Raw bytes are smaller but opaque. SDDL is the right choice for operational visibility. |
| `SetFileSecurityW` | `SetNamedSecurityInfoW` | Both work. `SetNamedSecurityInfoW` can target owner/group/DACL/SACL independently and is used by `audit_emitter.rs`. `SetFileSecurityW` is used by `device_controller.rs`. Either is acceptable; `SetNamedSecurityInfoW` is more explicit about which security info is being set. |

**Installation:**
```bash
# For dlp-agent (add to [target.'cfg(windows)'.dependencies] or [dependencies]):
# walkdir = "2.5"  -- if chosen over std::fs::read_dir

# No new dependencies required for core functionality -- all already in workspace.
```

---

## Package Legitimacy Audit

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| `windows` | crates.io | 4+ yrs | 50M+/mo | github.com/microsoft/windows-rs | [OK] | Approved |
| `rusqlite` | crates.io | 8+ yrs | 10M+/mo | github.com/rusqlite/rusqlite | [OK] | Approved |
| `crossbeam-channel` | crates.io | 6+ yrs | 50M+/mo | github.com/crossbeam-rs/crossbeam | [OK] | Approved |
| `parking_lot` | crates.io | 7+ yrs | 100M+/mo | github.com/Amanieu/parking_lot | [OK] | Approved |
| `walkdir` | crates.io | 8+ yrs | 50M+/mo | github.com/BurntSushi/walkdir | [OK] | Approved |
| `notify` | crates.io | 8+ yrs | 10M+/mo | github.com/notify-rs/notify | [OK] | Approved (not used directly for security events) |

**Packages removed due to slopcheck [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

---

## Architecture Patterns

### System Architecture Diagram

```
+-----------------------------------------------------------+
|                        dlp-server                          |
|  +----------------+    +-----------------------------+    |
|  | protected_paths|    | protected_path_aces         |    |
|  | (SQLite table) |<---| (FK to protected_paths)     |    |
|  +----------------+    +-----------------------------+    |
|           ^                                               |
|           | CRUD                                          |
|     +-----+-----+                                         |
|     | admin_api |  JWT-protected axum routes              |
|     +-----------+                                         |
|           |                                               |
|     GET /agent-config/{id}                                |
|           | includes protected_paths[]                    |
+-----------|-----------------------------------------------+
            |
            | HTTPS poll (30s, If-None-Match)
            v
+-----------------------------------------------------------+
|                        dlp-agent                           |
|                                                            |
|  +------------------+     +---------------------------+   |
|  | policy_sync loop |---->| AgentConfigPayload        |   |
|  | (existing)       |     | + protected_paths: Vec<..>|   |
|  +------------------+     +---------------------------+   |
|            |                                              |
|            v                                              |
|  +------------------+     +---------------------------+   |
|  | DaclTripwriter   |     | DaclWatcher               |   |
|  | (startup apply)  |     |                           |   |
|  | - SetFileSecurityW|    | + watcher thread          |   |
|  | - SDDL canonical  |    |   ReadDirectoryChangesW   |   |
|  |   snapshot store  |    |   (FILE_NOTIFY_CHANGE_    |   |
|  +------------------+     |    SECURITY)              |   |
|            |              | + crossbeam channel       |   |
|            v              | + tokio repair task       |   |
|  +------------------+     | + 60s poll backstop       |   |
|  | agent.db (SQLite)|     | + staging table check     |   |
|  | protected_paths_ |     +---------------------------+   |
|  | _staging         |              |                      |
|  +------------------+              v                      |
|                            +------------------+          |
|                            | AuditEvent       |          |
|                            | DaclTamperDetected|         |
|                            | -> SIEM relay    |          |
|                            +------------------+          |
+-----------------------------------------------------------+
```

### Recommended Project Structure

```
dlp-agent/src/
├── dacl_tripwire.rs          # DACL-01: Tripwire writer
│   ├── build_deny_authusers_dacl()  # Raw ACL buffer for S-1-5-11
│   ├── apply_tripwire_to_path()     # SetFileSecurityW + snapshot
│   └── apply_tripwire_recursive()   # Subtree walk with 10K limit
├── dacl_repair_watcher.rs    # DACL-02: Repair watcher
│   ├── DaclWatcher                  # WfpManager-pattern struct
│   ├── WatcherHandle                # Per-path ReadDirectoryChangesW state
│   ├── start_watcher_thread()       # Blocking OS thread
│   └── repair_acl()                 # Canonical restore + audit emit
├── dacl_staging.rs           # DACL-04: Two-phase staging
│   ├── init_staging_table()         # SQLite schema
│   ├── stage_removal()              # Insert staging row
│   └── gc_staging_rows()            # 5-minute TTL cleanup
└── lib.rs                    # Add module declarations

dlp-server/src/
├── db/
│   ├── mod.rs                # Add protected_paths + protected_path_aces tables
│   └── repositories/
│       └── protected_paths.rs # Repository: list, get, create, update, delete
├── admin_api.rs              # Add /admin/protected-paths routes
├── policy_sync.rs            # Include protected_paths in AgentConfigPayload
└── lib.rs                    # Add ProtectedPathsRepository to AppState

dlp-common/src/
└── audit.rs                  # Add DaclTamperDetected + DaclTripwireTooLarge

docs/operations/
└── dpapi-recovery.md         # DACL-05: Operational runbook
```

### Pattern 1: Raw ACL Buffer Construction (from `protection.rs`)
**What:** Manually construct an `ACCESS_DENIED_ACE` for a well-known SID in a raw byte buffer, then wrap it in a `SECURITY_DESCRIPTOR` for `SetKernelObjectSecurity` or `SetFileSecurityW`.
**When to use:** When you need a minimal, correct DACL with exactly one Deny ACE and no dependency on `SetEntriesInAclW` (which has ergonomic issues in windows-rs).
**Example:**
```rust
// Source: dlp-agent/src/protection.rs (build_deny_everyone_dacl)
fn build_deny_authusers_dacl(denied_mask: u32) -> Result<Vec<u8>> {
    // Authenticated Users SID: S-1-5-11
    // Revision=1, SubAuthorityCount=1, IdentifierAuthority={0,0,0,0,0,5},
    // SubAuthority[0]=11
    let authusers_sid: [u8; 12] = [
        1, // Revision
        1, // SubAuthorityCount
        0, 0, 0, 0, 0, 5, // IdentifierAuthority = SECURITY_NT_AUTHORITY
        11, 0, 0, 0, // SubAuthority[0] = 11 (Authenticated Users)
    ];

    let ace_size: u16 = 4 + 4 + authusers_sid.len() as u16;
    let acl_size: u16 = 8 + ace_size;
    let mut buf = vec![0u8; acl_size as usize];

    // ACL header
    buf[0] = 2; // ACL_REVISION
    buf[2..4].copy_from_slice(&acl_size.to_le_bytes());
    buf[4..6].copy_from_slice(&1u16.to_le_bytes()); // AceCount = 1

    // ACCESS_DENIED_ACE
    let ace_offset = 8usize;
    buf[ace_offset] = 1; // AceType = ACCESS_DENIED_ACE_TYPE
    buf[ace_offset + 1] = 0x03; // AceFlags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    buf[ace_offset + 2..ace_offset + 4].copy_from_slice(&ace_size.to_le_bytes());
    buf[ace_offset + 4..ace_offset + 8].copy_from_slice(&denied_mask.to_le_bytes());
    buf[ace_offset + 8..ace_offset + 8 + authusers_sid.len()].copy_from_slice(&authusers_sid);

    Ok(buf)
}
```

### Pattern 2: WfpManager Lifecycle (from `wfp_manager.rs`)
**What:** A struct with `new()` → `register()` → `unregister()` lifecycle, using `parking_lot::Mutex` for internal state.
**When to use:** Any subsystem that needs init/start/stop with shared mutable state across threads.
**Example:**
```rust
// Source: dlp-agent/src/wfp_manager.rs
pub struct WfpManager {
    engine: Mutex<Option<HANDLE>>,
    sublayer_key: GUID,
    filters: Mutex<HashMap<u32, u64>>,
}

impl WfpManager {
    pub fn new() -> Result<Self, WfpError> { /* open engine */ }
    pub fn register(&self) -> Result<(), WfpError> { /* register sublayer */ }
    pub fn unregister(&self) -> Result<(), WfpError> { /* cleanup */ }
}
```

### Pattern 3: crossbeam Channel Between Blocking Thread and Tokio
**What:** A dedicated OS thread runs a blocking Win32 API loop, pushing events through a bounded `crossbeam::channel` to a tokio task.
**When to use:** Any Windows API that blocks the calling thread (ETW `ProcessTrace`, `ReadDirectoryChangesW`, `WaitForSingleObject`).
**Example:**
```rust
// Source: dlp-agent/src/process_watcher.rs
let (tx, rx) = bounded::<ProcessEvent>(CHANNEL_CAPACITY);
let handle = thread::Builder::new()
    .name("etw-process-watcher".into())
    .spawn(move || {
        run_etw_loop(tx, shutdown, healthy, sweep_trigger);
    })?;
// Tokio task reads from rx and performs async work.
```

### Pattern 4: SDDL to SECURITY_DESCRIPTOR Conversion
**What:** Use `ConvertStringSecurityDescriptorToSecurityDescriptorW` to parse an SDDL string into a `PSECURITY_DESCRIPTOR`.
**When to use:** When you have a human-readable SDDL representation of a security descriptor (e.g., canonical snapshot) and need to apply it.
**Example:**
```rust
// Source: dlp-agent/src/ipc/pipe_security.rs
let sddl_wide: Vec<u16> = PIPE_SDDL.encode_utf16().collect();
let mut sd_ptr = PSECURITY_DESCRIPTOR::default();
unsafe {
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
        PCWSTR::from_raw(sddl_wide.as_ptr()),
        1, // SDDL_REVISION_1
        &mut sd_ptr,
        None,
    )?;
}
// Use sd_ptr with SetFileSecurityW...
// Free with LocalFree when done.
```

### Pattern 5: Repository CRUD (from `allowlist.rs`)
**What:** Stateless struct with associated functions taking `&Pool` for reads and `&UnitOfWork` for writes.
**When to use:** All new SQLite-backed entities in dlp-server.
**Example:**
```rust
// Source: dlp-server/src/db/repositories/allowlist.rs
pub struct AllowlistRepository;

impl AllowlistRepository {
    pub fn list_all(pool: &Pool) -> rusqlite::Result<Vec<AllowlistEntryRow>> { /* ... */ }
    pub fn insert(uow: &UnitOfWork<'_>, row: &AllowlistEntryRow) -> rusqlite::Result<()> { /* ... */ }
    pub fn update(uow: &UnitOfWork<'_>, row: &AllowlistEntryRow) -> rusqlite::Result<usize> { /* ... */ }
    pub fn delete_by_id(uow: &UnitOfWork<'_>, id: &str) -> rusqlite::Result<usize> { /* ... */ }
}
```

### Anti-Patterns to Avoid
- **Appending ACEs instead of replacing:** Appending the DLP Deny ACE to an existing DACL can place it after Allow ACEs, causing the Deny to be ineffective (Windows evaluates ACEs in order). Always replace the entire DACL with the canonical snapshot. [CITED: MS-DTYP 2.4.5 "ACL Evaluation"]
- **Using `std::sync::Mutex` for watcher map:** `std::sync::Mutex` can poison on panic. Use `parking_lot::Mutex` for consistency with the codebase and no poisoning. [VERIFIED: `wfp_manager.rs` uses `parking_lot::Mutex`]
- **Calling `ReadDirectoryChangesW` from a tokio task:** This API blocks the calling thread until a change occurs or the handle is closed. Never call it from an async task -- use a dedicated `std::thread`. [CITED: Microsoft Learn -- ReadDirectoryChangesW]
- **Storing raw security descriptor bytes instead of SDDL:** Raw bytes are opaque and hard to diff/debug. SDDL strings are human-readable and the same information density. [DECISION: D-13 in CONTEXT.md]
- **Forgetting to skip junctions/symlinks in subtree walk:** Recursive directory traversal that follows junctions can loop infinitely (e.g., `C:\Users\...\Application Data` junction). Use `walkdir` with `follow_links(false)` or manually check `FILE_ATTRIBUTE_REPARSE_POINT`. [CITED: walkdir crate documentation]

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Recursive directory traversal with loop detection | Custom BFS/DFS over `std::fs::read_dir` | `walkdir` 2.5.0 | Handles junctions, symlinks, depth limits, and cross-device detection correctly. ~500 lines of edge-case handling you don't want to maintain. |
| Windows SID string conversion | Manual SID byte parsing | `ConvertSidToStringSidW` / `ConvertStringSidToSidW` (windows-rs) | Already used in `audit_emitter.rs`. Correctly handles variable-length SIDs. |
| SDDL parsing/generation | Manual ACL header construction for snapshots | `ConvertSecurityDescriptorToStringSecurityDescriptorW` / `ConvertStringSecurityDescriptorToSecurityDescriptorW` | Microsoft-tested, handles all ACE types, correct canonical ordering. |
| SQLite connection pooling | Custom pool | `r2d2` + `r2d2_sqlite` | Already in `dlp-server`. Battle-tested, handles timeouts, max connections. |
| Admin API route protection | Custom JWT middleware | `axum::middleware::from_fn(admin_auth::require_auth)` | Already used in `admin_api.rs`. Standard pattern. |

**Key insight:** The Windows security descriptor APIs are complex and full of edge cases (ACL revision levels, ACE type compatibility, SID alignment). Always use the Microsoft-provided conversion functions rather than hand-rolling SDDL or SID parsing.

---

## Common Pitfalls

### Pitfall 1: ACL Size Limit (60 KB Guard)
**What goes wrong:** A path with thousands of inherited ACEs or deeply nested explicit ACEs exceeds the 60 KB limit when the DLP Deny ACE is added. `SetFileSecurityW` returns `ERROR_INVALID_ACL` (1336) or `ERROR_INSUFFICIENT_BUFFER` (122).
**Why it happens:** NTFS has no hard ACL size limit, but the Win32 API has practical limits. Some organizations apply complex group policies that generate massive ACLs.
**How to avoid:** Query the current ACL size before modification. If adding the DLP ACE would exceed 60 KB, reject the operation and emit `DaclTripwireTooLarge` audit event. Log the path and current ACE count for operator investigation.
**Warning signs:** `GetFileSecurityW` returns `required_len > 61440` (60 KB).

### Pitfall 2: ReadDirectoryChangesW Misses Events
**What goes wrong:** `ReadDirectoryChangesW` can miss events under high-volume change scenarios or if the buffer overflows. The 60-second polling backstop is required, not optional.
**Why it happens:** The API delivers events through a fixed-size buffer. If more changes occur than fit in the buffer between reads, events are dropped with `ERROR_NOTIFY_ENUM_DIR` (1022).
**How to avoid:** Always run the polling backstop alongside the event-driven watcher. On `ERROR_NOTIFY_ENUM_DIR`, trigger an immediate full scan of the affected path.
**Warning signs:** `ReadDirectoryChangesW` returns error 1022; polling backstop detects changes that the watcher missed.

### Pitfall 3: Staging Row Race Condition
**What goes wrong:** An operator removes a protected path. The server inserts a staging row. The agent applies the removal. Before the agent can mark `applied_at`, the watcher thread observes the ACL change and fires a tamper alert.
**Why it happens:** The watcher thread and the staging application task run concurrently. There is a window between "ACL changed on disk" and "staging row marked applied."
**How to avoid:** The staging table must be checked **before** the watcher emits a tamper alert. The watcher should query the staging table for the path; if a matching row exists with `operation = 'remove'`, suppress the alert. The GC task (5-minute TTL) must only delete rows where `applied_at IS NOT NULL`.

### Pitfall 4: Canonical Order Violation After Repair
**What goes wrong:** An out-of-band tamper adds an explicit Allow ACE before the DLP Deny ACE. The repair restores the canonical snapshot, but the tamperer's ACE is lost (replaced). This is correct behavior, but operators may be confused if they intentionally added an ACE.
**Why it happens:** Repair replaces the entire DACL. Any non-canonical ACEs are removed.
**How to avoid:** Document this behavior in the operator runbook. The canonical snapshot is the single source of truth. If operators need additional ACEs, they must be added through the admin API (which updates the canonical snapshot).

### Pitfall 5: DPAPI Master Key Loss
**What goes wrong:** After a Windows reimage or profile reset, `CryptUnprotectData` fails with `NTE_BAD_KEY_STATE`. All secrets in `secret_kek_history` become unrecoverable.
**Why it happens:** DPAPI with `CRYPTPROTECT_LOCAL_MACHINE` binds to the machine's LSA secret. A reimage generates a new LSA secret.
**How to avoid:** Document the recovery flows in `dpapi-recovery.md`: (1) re-init-from-env-vars -- operator sets `DLP_KEK_SEED` env var, agent regenerates KEK from seed; (2) restore-from-backup -- restore `secret_kek_history` row from offline backup. Both flows require operator intervention.

### Pitfall 6: Inheritance Breakage (icacls /inheritance:r)
**What goes wrong:** An operator runs `icacls /inheritance:r` on a protected path, breaking NTFS inheritance. New files created under this path no longer inherit the DLP Deny ACE.
**Why it happens:** `SE_DACL_PROTECTED` is set, blocking inheritance.
**How to avoid:** The repair watcher detects this on its next cycle (the ACL change triggers `FILE_NOTIFY_CHANGE_SECURITY`). The repair restores the canonical snapshot, which includes inheritance flags. However, existing files that were created during the inheritance-breakage window will NOT have the Deny ACE. The 60-second polling backstop must recursively check all children, not just the root.

---

## Code Examples

### Verified Pattern: GetNamedSecurityInfoW + ConvertSidToStringSidW
```rust
// Source: dlp-agent/src/audit_emitter.rs
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT, ConvertSidToStringSidW};
use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
use windows::Win32::Foundation::LocalFree;

fn get_file_owner_sid(path: &str) -> Option<String> {
    let path_wide: Vec<u16> = std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut owner_sid = PSID::default();
        let mut sd = PSECURITY_DESCRIPTOR::default();

        let err = GetNamedSecurityInfoW(
            PCWSTR::from_raw(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner_sid),
            None, None, None,
            &mut sd,
        );
        if err.is_err() { return None; }

        let mut sid_str = windows::core::PWSTR::null();
        ConvertSidToStringSidW(owner_sid, &mut sid_str).ok()?;
        let result = sid_str.to_string().ok();

        if !sd.0.is_null() {
            let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(sd.0)));
        }
        if !sid_str.is_null() {
            let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(sid_str.as_ptr() as *mut _)));
        }
        result
    }
}
```

### Verified Pattern: SetFileSecurityW with SDDL
```rust
// Source: dlp-agent/src/device_controller.rs (set_volume_readonly)
let sddl = "D:(D;;WDWO;;;S-1-1-0)(D;;WDWO;;;S-1-5-11)(A;;0x1200A9;;;S-1-1-0)(A;;FA;;;S-1-5-18)(A;;FA;;;S-1-5-32-544)";
let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
let mut p_sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());

unsafe {
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
        PCWSTR(sddl_wide.as_ptr()),
        1, // SDDL_REVISION_1
        &mut p_sd,
        None,
    )?;

    let set_ok = SetFileSecurityW(path_pcwstr, DACL_SECURITY_INFORMATION, p_sd);

    if !p_sd.0.is_null() {
        let _ = LocalFree(Some(HLOCAL(p_sd.0)));
    }
    set_ok?;
}
```

### Verified Pattern: ReadDirectoryChangesW Blocking Loop
```rust
// Pattern from process_watcher.rs adapted for file security monitoring.
// NOTE: This is a research-derived pattern, not from existing codebase.
use windows::Win32::Storage::FileSystem::{
    ReadDirectoryChangesW, FILE_NOTIFY_CHANGE_SECURITY,
    FILE_NOTIFY_INFORMATION, FILE_LIST_DIRECTORY,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::CreateFileW;
use windows::Win32::Security::SECURITY_ATTRIBUTES;

fn run_security_watcher(
    path: &std::path::Path,
    tx: crossbeam_channel::Sender<SecurityEvent>,
    shutdown: Arc<AtomicBool>,
) {
    let path_wide: Vec<u16> = path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            FILE_LIST_DIRECTORY.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(
                FILE_SHARE_READ.0 | FILE_SHARE_DELETE.0,
            ),
            None,
            windows::Win32::Storage::FileSystem::OPEN_EXISTING,
            windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        tracing::error!(path = %path.display(), "failed to open directory for watching");
        return;
    }

    let mut buffer = [0u8; 4096];
    let mut bytes_returned: u32 = 0;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let result = unsafe {
            ReadDirectoryChangesW(
                handle,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                true, // bWatchSubtree
                FILE_NOTIFY_CHANGE_SECURITY,
                &mut bytes_returned,
                None,
                None,
            )
        };

        if result.is_err() {
            tracing::warn!(path = %path.display(), "ReadDirectoryChangesW failed");
            break;
        }

        if bytes_returned > 0 {
            // Parse FILE_NOTIFY_INFORMATION entries...
            let _ = tx.try_send(SecurityEvent { path: path.to_path_buf() });
        }
    }

    unsafe { CloseHandle(handle); }
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Volume-level DACL (Phase 38, `device_controller.rs`) | Per-path DACL tripwire (Phase 52) | v0.10.0 | Finer-grained protection: T3/T4 roots only, not entire volumes |
| `notify` crate for file monitoring (`file_monitor.rs`) | Raw `ReadDirectoryChangesW` for security events | Phase 52 | `notify` does not expose security change events; raw API required |
| Process-level DACL hardening (`protection.rs`) | File-system-level DACL tripwire | Phase 52 | Extends defense-in-depth from process to data |
| Single-phase config apply | Two-phase staged updates with suppression | Phase 52 | Eliminates false-positive tamper alerts on operator-initiated changes |

**Deprecated/outdated:**
- `SetEntriesInAclW` / `TRUSTEE_W`: Not used in this codebase due to ergonomic issues in windows-rs. Raw ACL buffer construction is the established pattern. [VERIFIED: `protection.rs` uses raw buffers]

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `ReadDirectoryChangesW` with `FILE_NOTIFY_CHANGE_SECURITY` reliably fires on ACL changes made through the Win32 API layer | ReadDirectoryChangesW Monitoring | If an attacker uses direct NTFS syscalls (e.g., `NtSetSecurityObject`), `ReadDirectoryChangesW` may not fire. This is a known limitation documented in `docs/SECURITY_ARCHITECTURE.md` (THREAT-022). The 60s polling backstop mitigates. |
| A2 | The `Authenticated Users` SID (S-1-5-11) is the correct target for the Deny ACE | ACE Canonical Order | If the deployment uses a different identity model (e.g., only specific AD groups), the Deny ACE may be ineffective. The DLP-Admin group SID is resolved at startup and cached per D-12. |
| A3 | `walkdir` 2.5.0 will be added as a dependency for subtree traversal | Subtree ACE Application | If the planner chooses `std::fs::read_dir` instead, manual junction/symlink handling is required. Either approach works; `walkdir` is safer. |
| A4 | The agent's existing `agent.db` SQLite file (at `C:\ProgramData\DLP\agent.db`) is the correct location for the `protected_paths_staging` table | Two-Phase Staged Update | If the agent DB path changes, the staging table init must follow. Currently `init_agent_db()` in `service.rs` hardcodes this path. |
| A5 | DPAPI master keys are retained indefinitely by Windows (per Microsoft docs) | DPAPI Recovery | If Windows ever purges old master keys, the restore-from-backup flow becomes the only recovery path. The runbook documents both. |

---

## Open Questions

1. **ReadDirectoryChangesW buffer sizing for high-volume paths**
   - What we know: A 4 KB buffer is standard. `ERROR_NOTIFY_ENUM_DIR` (1022) occurs on overflow.
   - What's unclear: Whether 4 KB is sufficient for T3/T4 roots with heavy file activity (e.g., build outputs, temp directories).
   - Recommendation: Start with 4 KB and monitor for overflow events in telemetry. Increase to 16 KB if overflow rate > 0.1%.

2. **Subtree repair performance on deeply nested directories**
   - What we know: The 10,000-file limit prevents runaway walks.
   - What's unclear: Whether a single `SetFileSecurityW` call on a directory with `CONTAINER_INHERIT_ACE` propagates to all children, or if explicit per-file ACLs are required for the tripwire to be effective.
   - Recommendation: Test on a deeply nested directory tree. If inheritance alone is insufficient (e.g., files with `SE_DACL_PROTECTED`), the repair must walk all children.

3. **DLP-Admin AD group SID resolution at startup**
   - What we know: The group SID is resolved from AD at agent startup and cached (D-12).
   - What's unclear: The exact AD attribute or LDAP query to resolve the DLP-Admin group SID.
   - Recommendation: Use the existing `AdClient` in `dlp-agent` to query the group by name (e.g., "DLP-Admins") and cache the SID. Fall back to SYSTEM-only Allow ACE if AD is unreachable.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain | Build | Yes | 1.94.1 | -- |
| Windows SDK | Win32 API bindings | Yes | 10.0.26100 | -- |
| Windows 11 Pro | Runtime target | Yes | 10.0.26200 | -- |
| SQLite (bundled) | rusqlite | Yes | 3.46 | -- |
| DPAPI | KEK protection | Yes | OS built-in | re-init-from-env-vars |

**Missing dependencies with no fallback:** none
**Missing dependencies with fallback:** none

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `tokio::test` for async |
| Config file | None -- see Wave 0 |
| Quick run command | `cargo test -p dlp-agent dacl` (filter by module name) |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DACL-01 | Tripwire writer applies Deny ACE to protected path | unit | `cargo test -p dlp-agent dacl_tripwire` | No -- Wave 0 |
| DACL-01 | 60 KB ACL guard rejects oversized ACLs | unit | `cargo test -p dlp-agent dacl_tripwire` | No -- Wave 0 |
| DACL-02 | Repair watcher detects ACL tamper and restores | integration | `cargo test -p dlp-agent dacl_watcher` | No -- Wave 0 |
| DACL-02 | 60s polling backstop catches missed events | integration | `cargo test -p dlp-agent dacl_watcher` | No -- Wave 0 |
| DACL-03 | Admin API CRUD for protected paths | unit | `cargo test -p dlp-server protected_paths` | No -- Wave 0 |
| DACL-03 | Agent config sync includes protected paths | unit | `cargo test -p dlp-agent config` | No -- Wave 0 |
| DACL-04 | Staging row suppresses tamper alert on removal | integration | `cargo test -p dlp-agent dacl_staging` | No -- Wave 0 |
| DACL-04 | GC removes expired staging rows after 5 min | integration | `cargo test -p dlp-agent dacl_staging` | No -- Wave 0 |
| DACL-05 | DPAPI recovery runbook exists and is readable | doc | `test -f docs/operations/dpapi-recovery.md` | No -- Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-agent dacl_tripwire` (quick filter)
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `dlp-agent/src/dacl_tripwire.rs` -- module creation + unit tests for `build_deny_authusers_dacl`
- [ ] `dlp-agent/src/dacl_repair_watcher.rs` -- module creation + mock watcher tests
- [ ] `dlp-agent/src/dacl_staging.rs` -- module creation + SQLite table tests
- [ ] `dlp-server/src/db/repositories/protected_paths.rs` -- repository + CRUD tests
- [ ] `dlp-common/src/audit.rs` -- add `DaclTamperDetected` and `DaclTripwireTooLarge` variants
- [ ] `docs/operations/dpapi-recovery.md` -- runbook creation

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | -- |
| V3 Session Management | No | -- |
| V4 Access Control | Yes | NTFS DACL + explicit Deny ACE for Authenticated Users |
| V5 Input Validation | Yes | Path validation (absolute NTFS path), ACL size guard (60 KB) |
| V6 Cryptography | Yes | DPAPI for KEK protection (Phase 47); recovery runbook for key loss |
| V7 Error Handling | Yes | `thiserror` error types; no panic on ACL failure |
| V8 Data Protection | Yes | SDDL snapshots stored in agent SQLite; no secrets in code |
| V10 Malicious Code | Yes | Repair watcher detects tampering; two-phase updates prevent alert fatigue |

### Known Threat Patterns for NTFS DACL Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Direct NTFS syscall bypass (NtSetSecurityObject) | Tampering | Polling backstop catches changes that ReadDirectoryChangesW misses; documented in SECURITY_ARCHITECTURE.md THREAT-022 |
| ACL inheritance breakage (icacls /inheritance:r) | Tampering | Repair restores canonical snapshot; polling backstop scans recursively |
| Operator-initiated removal false-positive | Denial of Service | Two-phase staged update suppresses spurious tamper alerts |
| Pathological ACL ( > 60 KB ) | Denial of Service | 60 KB guard rejects operation; emits audit event for operator review |
| DPAPI master key loss | Information Disclosure | Recovery runbook documents re-init and restore-from-backup flows |
| Race condition between staging and watcher | Elevation of Privilege | Staging table checked before tamper alert emission |

---

## Sources

### Primary (HIGH confidence)
- `dlp-agent/src/protection.rs` -- Raw ACL buffer construction pattern (`build_deny_everyone_dacl`)
- `dlp-agent/src/wfp_manager.rs` -- `WfpManager` lifecycle pattern (`new`/`register`/`unregister`)
- `dlp-agent/src/process_watcher.rs` -- crossbeam channel + dedicated OS thread pattern
- `dlp-agent/src/device_controller.rs` -- `SetFileSecurityW` + SDDL conversion patterns
- `dlp-agent/src/audit_emitter.rs` -- `GetNamedSecurityInfoW` + `ConvertSidToStringSidW` pattern
- `dlp-agent/src/ipc/pipe_security.rs` -- SDDL to SECURITY_DESCRIPTOR conversion
- `dlp-agent/src/service.rs` -- `RunLoopContext` subsystem collection; config poll loop
- `dlp-server/src/db/mod.rs` -- `init_tables()` + `run_migrations()` patterns
- `dlp-server/src/db/repositories/allowlist.rs` -- Repository CRUD pattern
- `dlp-server/src/admin_api.rs` -- axum route registration pattern
- `dlp-server/src/policy_store.rs` -- In-memory cache pattern
- `dlp-common/src/audit.rs` -- `AuditEvent` + `EventType` patterns
- `dlp-common/src/crypto/dpapi.rs` -- DPAPI protect/unprotect patterns
- `dlp-server/src/crypto/mod.rs` -- `SecretCrypto` + envelope patterns
- `.planning/phases/47-secrets-encryption-at-rest/47-RESEARCH.md` -- DPAPI failure modes, recovery context

### Secondary (MEDIUM confidence)
- Microsoft Learn: `ReadDirectoryChangesW` documentation -- buffer sizing, `FILE_NOTIFY_CHANGE_SECURITY` filter
- MS-DTYP 2.4.5 -- ACL evaluation order (Deny-before-Allow, Explicit-before-Inherited)
- walkdir 2.5.0 documentation -- junction/symlink handling

### Tertiary (LOW confidence)
- Windows DPAPI master key retention behavior -- Microsoft docs state old keys are retained indefinitely, but this is not programmatically verifiable

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all core dependencies already in workspace, verified via `cargo info` and `slopcheck`
- Architecture: HIGH -- existing patterns (WfpManager, process_watcher, device_controller) provide solid foundation
- Pitfalls: MEDIUM -- some edge cases (buffer overflow, inheritance breakage) are theoretical until tested on real workloads

**Research date:** 2026-05-22
**Valid until:** 2026-06-22 (30 days for stable Windows APIs)
