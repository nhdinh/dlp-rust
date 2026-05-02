# Phase 35: Disk Allowlist Persistence - Context

**Gathered:** 2026-05-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Agent persists the disk allowlist to `agent-config.toml` and loads it back across restarts. Covers DISK-03 only. The allowlist established here feeds Phase 36 enforcement (runtime I/O blocking) and eventually Phase 37 (server-side registry sync).

**In scope:**
- Add `disk_allowlist: Vec<DiskIdentity>` field to `AgentConfig` struct
- Load TOML allowlist at startup into `DiskEnumerator.instance_id_map` (pre-populated before live enumeration)
- After disk enumeration succeeds, merge live disks with TOML entries and write the updated allowlist via `AgentConfig::save()`
- Pass `Arc<RwLock<AgentConfig>>` to the enumeration task for atomic read-modify-write

**Out of scope:**
- Runtime I/O blocking based on allowlist (Phase 36)
- WM_DEVICECHANGE persistence of newly arrived disks (Phase 36)
- Server-side disk registry (Phase 37)
- Admin TUI for disk registry (Phase 38)
- Admin removal of disks from allowlist (Phase 37/38)
- Re-writing TOML after Phase 34 encryption re-checks (in-memory only)

</domain>

<decisions>
## Implementation Decisions

### Write trigger and timing
- **D-01:** The allowlist is written to `agent-config.toml` **after disk enumeration succeeds** — this is the only write trigger for Phase 35. Encryption fields are `None` at this point (Phase 34 runs after enumeration; Phase 35 does not wait for it).
- **D-02:** On restart, the agent loads the TOML allowlist first, then enumerates live disks, merges, and writes the updated TOML **immediately** if the merged list differs from the prior TOML (i.e., new disks were added). No defer-to-shutdown; if the agent crashes after enumeration, new disks are already persisted.
- **D-03:** TOML write uses the existing `AgentConfig::save()` method — no dedicated allowlist writer. Phase 35 adds `pub disk_allowlist: Vec<DiskIdentity>` to `AgentConfig`; the existing save path serializes it as `[[disk_allowlist]]` automatically.
- **D-04:** `AgentConfig` is wrapped as `Arc<RwLock<AgentConfig>>` and passed to the enumeration task. The task acquires a write lock, updates `disk_allowlist`, then calls `save()`. This mirrors the existing `parking_lot::RwLock` pattern used throughout the agent for shared state.
- **D-05:** Phase 34's 6-hour periodic encryption re-check does **not** trigger a TOML re-write. The TOML is an enumeration identity snapshot; encryption status is authoritative in the in-memory `DiskEnumerator` and audit events. Admin views current encryption status via audit events, not the TOML file.

### Disconnected disk policy
- **D-06:** Disks that are in the TOML allowlist but absent from the current enumeration (physically disconnected) are **kept** in the in-memory allowlist and in TOML. The allowlist is additive — admin must explicitly remove disks (Phase 37/38). If the disk reappears, Phase 36 finds it already allowlisted.
- **D-07:** When a disk is found by both TOML load and live enumeration (same `instance_id`), **live enumeration wins**. The live `DiskIdentity` replaces the TOML snapshot in-memory. This ensures `drive_letter`, `is_boot_disk`, `model` are always current. Only disconnected-only entries keep their TOML values.

### Encryption fields persistence
- **D-08:** The full `DiskIdentity` struct is persisted to TOML — including `encryption_status`, `encryption_method`, `encryption_checked_at`. The existing `#[serde(skip_serializing_if = "Option::is_none")]` attributes on all three fields mean they are silently absent from TOML when `None` (clean for first-run records that haven't been through Phase 34 yet).
- **D-09:** TOML is **not** re-written after Phase 34's startup encryption check. The TOML snapshot after enumeration will have `encryption_status = None` for all disks. Phase 34 populates encryption fields in memory; those values live in the running `DiskEnumerator` and are emitted via `DiskDiscovery` audit events. This avoids coupling Phase 34's re-check cadence to TOML I/O.

### In-memory allowlist cache design
- **D-10:** `DiskEnumerator.instance_id_map` (existing `RwLock<HashMap<String, DiskIdentity>>`) **is** the allowlist. No new `DiskAllowlist` singleton is introduced. Phase 36 calls `get_disk_enumerator().disk_for_instance_id(id)` to check allowlist membership.
- **D-11:** At agent startup, TOML allowlist entries are loaded into `instance_id_map` **before** live enumeration runs. Disconnected disks pre-populate the map so they remain allowlisted even if this session's enumeration doesn't find them.
- **D-12:** `enumeration_complete` is set to `true` **only after live enumeration succeeds** — not after the TOML pre-load. Phase 36 enforcement waits on `enumeration_complete` before enforcing, ensuring it uses live data and not a potentially stale TOML snapshot. Pre-loading TOML is a warm-up step, not a readiness signal.
- **D-13:** One unified map. TOML-loaded entries start in `instance_id_map`; live enumeration updates entries for present disks in-place; absent-but-allowlisted entries remain as loaded from TOML. Phase 36 sees a single map with both live and absent allowlisted disks.

### Claude's Discretion
- Exact field name in `AgentConfig`: `disk_allowlist` (matches the `[[disk_allowlist]]` TOML section name)
- Whether to add a `load_disk_allowlist(path)` helper on `AgentConfig` or inline the TOML pre-load in `spawn_disk_enumeration_task` (recommended: inline in the task, similar to how `_agent_config_path` stub is already there)
- Write ordering within the enumeration task: update `instance_id_map` first, then write TOML (recommended: write TOML while holding the `AgentConfig` write lock; release before signaling `enumeration_complete`)
- Error handling on TOML write failure: log with `tracing::error!`, do NOT fail enumeration (the in-memory state is authoritative; TOML write failure is non-fatal for the running agent)
- Whether `discovered_disks: RwLock<Vec<DiskIdentity>>` is also updated with TOML-pre-loaded entries (recommended: yes, keep `discovered_disks` and `instance_id_map` in sync as they are today)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements and Roadmap
- `.planning/ROADMAP.md` — Phase 35 goal, success criteria, depends-on Phase 33
- `.planning/REQUIREMENTS.md` — DISK-03 requirement definition; deferred DISK-F1..F4
- `.planning/PROJECT.md` — Architecture, tech stack, key design decisions

### Prior Phase Context (patterns and data models)
- `.planning/phases/33-disk-enumeration/33-CONTEXT.md` — `DiskIdentity` schema, `DiskEnumerator` pattern, `spawn_disk_enumeration_task` stub with `_agent_config_path` parameter already present, `AgentConfig` TOML pattern, D-07 (preserve-and-append semantics)
- `.planning/phases/34-bitlocker-verification/34-CONTEXT.md` — Phase 34 encryption fields on `DiskIdentity` (D-05..D-08), `EncryptionChecker` module, `DiskEnumerator` mutation pattern (D-20), why TOML is not re-written after encryption checks (this phase extends D-20 to also exclude re-writes from Phase 34)

### Key Source Files (read before touching)
- `dlp-agent/src/config.rs` — `AgentConfig` struct (add `disk_allowlist` field), `AgentConfig::save()` method, `AgentConfig::load()` method, `DEFAULT_CONFIG_PATH`, `effective_config_path()`. Note: `AgentConfig` is currently not wrapped in `Arc<RwLock<...>>`; Phase 35 introduces that wrapping at service startup.
- `dlp-agent/src/detection/disk.rs` — `DiskEnumerator` struct and fields (`instance_id_map`, `drive_letter_map`, `discovered_disks`, `enumeration_complete`), `spawn_disk_enumeration_task` function (add `_agent_config_path` parameter use here), `get_disk_enumerator()` / `set_disk_enumerator()` global static pattern.
- `dlp-agent/src/service.rs` — Service startup; where `AgentConfig` is currently constructed and where `Arc<RwLock<AgentConfig>>` wrapping should be introduced; where `spawn_disk_enumeration_task` is called.
- `dlp-common/src/disk.rs` — `DiskIdentity` struct with all current fields including Phase 34 additions (`encryption_status`, `encryption_method`, `encryption_checked_at`).

### TOML Format Reference
- Phase 33 specifics showed the target TOML shape — `[[disk_allowlist]]` array of tables, one entry per disk. Phase 35 makes this live:
  ```toml
  [[disk_allowlist]]
  instance_id = "PCIIDE\\IDECHANNEL\\4&1234&0&0"
  bus_type = "sata"
  model = "WDC WD10EZEX-00BN5A0"
  drive_letter = "C"
  is_boot_disk = true
  # encryption_status, encryption_method, encryption_checked_at omitted if None
  ```

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `AgentConfig::save()` (`dlp-agent/src/config.rs:262`) — Writes the full struct as TOML via `toml::to_string`. Phase 35 adds `disk_allowlist` field; serialization is automatic.
- `AgentConfig::load()` (`dlp-agent/src/config.rs:176`) — Reads and deserializes TOML with graceful fallback to `Default`. Adding `disk_allowlist` with `#[serde(default)]` means old TOML files without the section load cleanly.
- `spawn_disk_enumeration_task` (`dlp-agent/src/detection/disk.rs:151`) — Has a `_agent_config_path: Option<String>` stub parameter with the comment "Phase 35 will use this." The Phase 35 implementation replaces this stub with actual allowlist load/save logic.
- `DiskEnumerator.instance_id_map` (`dlp-agent/src/detection/disk.rs:50`) — Already the lookup map for Phase 36. Phase 35 pre-populates it from TOML before enumeration runs.
- `parking_lot::RwLock` pattern — Already used in `DiskEnumerator` for all shared state. `AgentConfig` wrapping follows the same pattern.

### Established Patterns
- `#[serde(default)]` on new `AgentConfig` fields — ensures backwards-compatible TOML loading when the `[disk_allowlist]` section is absent (first-run or old config file).
- `OnceLock<Arc<...>>` for service-scope singletons — pattern for `DiskEnumerator`. `AgentConfig` will become `Arc<RwLock<AgentConfig>>` but is NOT a global singleton (passed explicitly through the call chain).
- `tracing::error!` for non-fatal I/O failures — never `panic!` or `unwrap()` on TOML write failure.

### Integration Points
- `dlp-agent/src/service.rs` — Wrap `AgentConfig` in `Arc<RwLock<AgentConfig>>` at startup. Pass the `Arc` clone to `spawn_disk_enumeration_task`.
- `dlp-agent/src/detection/disk.rs::spawn_disk_enumeration_task` — Change `_agent_config_path: Option<String>` parameter to `agent_config: Arc<RwLock<AgentConfig>>`. At task start: read lock → extract `disk_allowlist` → pre-populate `instance_id_map` + `discovered_disks`. After successful enumeration: write lock → update `disk_allowlist` with merged list → call `save()`.
- Phase 36 enforcement will call `get_disk_enumerator().disk_for_instance_id(id)` — no API changes needed in `DiskEnumerator` for Phase 36 to work; the map is already there.

### Merge Algorithm (pseudocode)
```
startup:
  toml_disks = agent_config.disk_allowlist  // Vec<DiskIdentity> from TOML
  pre-populate instance_id_map and discovered_disks from toml_disks

enumeration:
  live_disks = enumerate_fixed_disks()
  merged = HashMap::from toml_disks by instance_id  // start with TOML (keeps absent disks)
  for disk in live_disks:
    merged.insert(disk.instance_id.clone(), disk)   // live wins for present disks
  updated_list = merged.into_values().collect()

  update DiskEnumerator (instance_id_map, drive_letter_map, discovered_disks)
  update agent_config.disk_allowlist = updated_list
  agent_config.save(path)
  set enumeration_complete = true
```

</code_context>

<specifics>
## Specific Requirements

### AgentConfig addition
```rust
/// Phase 35 disk allowlist — persisted across restarts.
///
/// Loaded from `[[disk_allowlist]]` TOML array of tables.
/// Each entry is a `DiskIdentity` with `instance_id` as canonical key.
/// When the section is absent (first run or old config), defaults to empty.
#[serde(default)]
pub disk_allowlist: Vec<DiskIdentity>,
```

### spawn_disk_enumeration_task signature change
```rust
// Before (Phase 33/34):
pub fn spawn_disk_enumeration_task(
    runtime_handle: tokio::runtime::Handle,
    audit_ctx: crate::audit_emitter::EmitContext,
    _agent_config_path: Option<String>,   // stub
)

// After (Phase 35):
pub fn spawn_disk_enumeration_task(
    runtime_handle: tokio::runtime::Handle,
    audit_ctx: crate::audit_emitter::EmitContext,
    agent_config: Arc<parking_lot::RwLock<AgentConfig>>,
    config_path: PathBuf,
)
```

### TOML representation after Phase 35 (stable machine, second restart)
```toml
# ... other AgentConfig fields ...

[[disk_allowlist]]
instance_id = "PCIIDE\\IDECHANNEL\\4&1234&0&0"
bus_type = "sata"
model = "WDC WD10EZEX-00BN5A0"
drive_letter = "C"
is_boot_disk = true
# encryption_status absent (None) — Phase 34 not yet run on this entry

[[disk_allowlist]]
instance_id = "USB\\VID_1234&PID_5678\\001"
bus_type = "usb"
model = "USB External Drive"
drive_letter = "E"
is_boot_disk = false
# No encryption fields — Phase 34 hasn't checked yet

[[disk_allowlist]]
instance_id = "NVME\\GEN31X4\\5&ABC"
bus_type = "nvme"
model = "Samsung SSD 980 Pro"
is_boot_disk = false
# drive_letter absent (was disconnected at last enumeration — kept per D-06)
```

</specifics>

<deferred>
## Deferred Ideas

- **TOML re-write after Phase 34 encryption check** — rejected in discussion; encryption status is authoritative in memory and audit events. TOML is an identity snapshot.
- **Diff-gate on TOML write** — skip write if no new disks were added — rejected for simplicity; always write after enumeration (cost is minimal on fixed disk counts).
- **Separate `disk-allowlist.toml` file** — rejected; single `agent-config.toml` with `AgentConfig::save()` is cleaner and reuses existing I/O path.
- **`DiskAllowlist` new singleton** — rejected; `DiskEnumerator.instance_id_map` already serves this role, no need for a parallel data structure.
- **`absent = true` flag on disconnected disk TOML entries** — rejected; keeping entries as-is is sufficient, and a new field adds test-matrix complexity without enforcement benefit.
- **Admin removal of disks from allowlist (Phase 35)** — out of scope; that's Phase 37/38 (server-side registry + TUI).

</deferred>

---

*Phase: 35-disk-allowlist-persistence*
*Context gathered: 2026-05-03*
