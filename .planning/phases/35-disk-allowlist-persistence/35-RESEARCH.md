# Phase 35: Disk Allowlist Persistence - Research

**Researched:** 2026-05-03
**Domain:** Rust TOML persistence, parking_lot RwLock/Mutex, serde derive, AgentConfig extension
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**D-01:** Allowlist is written to `agent-config.toml` after disk enumeration succeeds. Only write trigger in Phase 35.

**D-02:** On restart: load TOML allowlist first, enumerate live disks, merge, write TOML immediately if merged list differs from prior TOML. No defer-to-shutdown.

**D-03:** TOML write uses existing `AgentConfig::save()`. Phase 35 adds `pub disk_allowlist: Vec<DiskIdentity>` to `AgentConfig`.

**D-04:** `AgentConfig` wrapped as `Arc<RwLock<AgentConfig>>`, passed to enumeration task. Task acquires write lock, updates `disk_allowlist`, calls `save()`. Mirrors `parking_lot::RwLock` pattern.

**D-05:** Phase 34's 6-hour periodic encryption re-check does NOT trigger a TOML re-write.

**D-06:** Disks in TOML allowlist but absent from current enumeration (disconnected) are kept in both in-memory allowlist and TOML. Allowlist is additive.

**D-07:** When a disk is found in both TOML and live enumeration (same `instance_id`), live enumeration wins. Live `DiskIdentity` replaces TOML snapshot in-memory.

**D-08:** Full `DiskIdentity` struct is persisted to TOML including encryption fields. `#[serde(skip_serializing_if = "Option::is_none")]` means absent when `None`.

**D-09:** TOML is NOT re-written after Phase 34's startup encryption check.

**D-10:** `DiskEnumerator.instance_id_map` IS the allowlist. No new `DiskAllowlist` singleton.

**D-11:** At startup, TOML allowlist entries are loaded into `instance_id_map` BEFORE live enumeration runs.

**D-12:** `enumeration_complete` is set to `true` ONLY after live enumeration succeeds — not after TOML pre-load.

**D-13:** One unified map. TOML-loaded entries start in `instance_id_map`; live enumeration updates entries for present disks in-place; absent-but-allowlisted entries remain.

### Claude's Discretion

- Exact field name in `AgentConfig`: `disk_allowlist`
- Whether to add a `load_disk_allowlist(path)` helper or inline TOML pre-load in `spawn_disk_enumeration_task` (recommended: inline)
- Write ordering: update `instance_id_map` first, then write TOML while holding `AgentConfig` write lock; release before signaling `enumeration_complete`
- Error handling on TOML write failure: `tracing::error!`, do NOT fail enumeration
- Whether `discovered_disks: RwLock<Vec<DiskIdentity>>` is also updated with TOML-pre-loaded entries (recommended: yes)

### Deferred Ideas (OUT OF SCOPE)

- TOML re-write after Phase 34 encryption check
- Diff-gate on TOML write (skip write if no new disks)
- Separate `disk-allowlist.toml` file
- `DiskAllowlist` new singleton
- `absent = true` flag on disconnected disk TOML entries
- Admin removal of disks from allowlist (Phase 37/38)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DISK-03 | Agent persists disk allowlist to `agent-config.toml` with device instance ID as canonical key; drive letter is informational only | Add `disk_allowlist: Vec<DiskIdentity>` to `AgentConfig`; use existing `AgentConfig::save()` path; TOML serializes `[[disk_allowlist]]` array of tables automatically via serde |
</phase_requirements>

---

## Summary

Phase 35 is a focused persistence wiring task. The data model (`DiskIdentity`), the TOML serialization infrastructure (`AgentConfig::save()` / `AgentConfig::load()`), and the in-memory registry (`DiskEnumerator.instance_id_map`) all already exist from Phases 33 and 34. The work is purely connective: add one field to `AgentConfig`, change the signature of `spawn_disk_enumeration_task` to accept the config instead of a path stub, implement the pre-load + merge + save sequence inside the enumeration task, and thread the `Arc<RwLock<AgentConfig>>` from `service.rs`.

The most important architectural finding is a **discrepancy between CONTEXT.md D-04 and the actual service.rs code**: `service.rs` currently wraps `AgentConfig` in `Arc<parking_lot::Mutex<AgentConfig>>` (not `RwLock`) for the config poll loop at line 541. Phase 35 must introduce a separate `Arc<parking_lot::RwLock<AgentConfig>>` for disk enumeration, or reuse the existing `Mutex` wrapper. The recommendation is to introduce the `RwLock` wrapper as a new binding, since the disk enumeration task is write-once (no readers competing during enumeration), and `RwLock` is already the pattern inside `DiskEnumerator`. The existing `config_arc: Arc<Mutex<AgentConfig>>` for the config poll loop remains unchanged.

**Primary recommendation:** Add `disk_allowlist: Vec<DiskIdentity>` to `AgentConfig` with `#[serde(default)]`, change `spawn_disk_enumeration_task` to accept `Arc<parking_lot::RwLock<AgentConfig>>` + `PathBuf`, implement the pre-load/merge/save algorithm inside the task, and create the `Arc<RwLock<AgentConfig>>` in `service.rs` from `agent_config.clone()` before both it and `config_arc` are constructed.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| TOML deserialization of allowlist on startup | `dlp-agent` (config.rs load path) | — | `AgentConfig::load()` already handles this; `#[serde(default)]` ensures backwards compat |
| Allowlist pre-population before enumeration | `dlp-agent` (disk.rs task) | — | Task owns `DiskEnumerator` writes; pre-load runs at task start before live scan |
| Merge algorithm (live wins over TOML) | `dlp-agent` (disk.rs task) | — | Task holds both TOML data and live enumeration result; single code site |
| TOML serialization / write after enumeration | `dlp-agent` (config.rs AgentConfig::save) | disk.rs (caller) | `save()` is the canonical write path; disk.rs calls it inside the write lock |
| Disconnected disk retention | `dlp-agent` (disk.rs merge) | — | Merge starts from TOML map so absent disks survive to the output list |
| Phase 36 allowlist lookup | `dlp-agent` (disk.rs DiskEnumerator) | — | `disk_for_instance_id()` already exists; no new API needed |

---

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `toml` | 0.8 [VERIFIED: Cargo.toml] | TOML serialize/deserialize for `AgentConfig` | Already in `dlp-agent` dependencies; `toml::to_string` + `toml::from_str` |
| `serde` | 1.x [VERIFIED: workspace Cargo.toml] | Derive `Serialize`/`Deserialize` for `AgentConfig` and `DiskIdentity` | Already derived on both structs |
| `parking_lot` | 0.12 [VERIFIED: workspace Cargo.toml] | `RwLock<T>` for `AgentConfig` wrapper | Already used throughout `DiskEnumerator` |
| `anyhow` | 1.x [VERIFIED: workspace Cargo.toml] | Error context on TOML write failure | Already used in `AgentConfig::save()` |
| `tracing` | 0.1 [VERIFIED: workspace Cargo.toml] | `tracing::error!` for non-fatal write failures | Project standard per CLAUDE.md |

### No New Dependencies

Phase 35 requires **zero new crate dependencies**. All required crates are already present in `dlp-agent/Cargo.toml`.

---

## Architecture Patterns

### System Architecture Diagram

```
service.rs startup
    |
    +--> AgentConfig::load_default()
    |       reads agent-config.toml
    |       deserializes [[disk_allowlist]] -> Vec<DiskIdentity>
    |       (empty Vec on first run -- #[serde(default)])
    |
    +--> Arc<RwLock<AgentConfig>> created (new, separate from config_arc)
    |
    +--> spawn_disk_enumeration_task(handle, audit_ctx, agent_config_arc, config_path)
            |
            +-- TOML pre-load phase (before live enumeration)
            |       read lock -> extract disk_allowlist
            |       write DiskEnumerator.instance_id_map  (TOML entries)
            |       write DiskEnumerator.discovered_disks (TOML entries)
            |       enumeration_complete remains false
            |
            +-- Live enumeration (with retry x3)
            |       enumerate_fixed_disks() -> Vec<DiskIdentity>
            |       mark boot disk
            |
            +-- Merge algorithm
            |       merged = HashMap::from(toml_disks by instance_id)
            |       for disk in live_disks { merged.insert(disk.instance_id, disk) }
            |       updated_list = merged.into_values().collect()
            |
            +-- Write to DiskEnumerator
            |       write lock on all 4 DiskEnumerator fields
            |       *discovered = updated_list
            |       drive_map rebuilt, instance_map rebuilt
            |
            +-- Write to TOML (non-fatal)
            |       write lock on AgentConfig
            |       cfg.disk_allowlist = updated_list
            |       cfg.save(config_path)  -- tracing::error! on failure, continue
            |       release write lock
            |
            +-- enumeration_complete = true
            |
            +-- emit_disk_discovery audit event
```

### Key Lock Ordering

To avoid deadlock, locks are acquired and released in strict order:
1. `DiskEnumerator` write locks (all four fields under a single conceptual write)
2. `AgentConfig` write lock (taken after DiskEnumerator writes complete)

Never hold both simultaneously. The DiskEnumerator update finishes before the AgentConfig lock is acquired.

### Recommended Project Structure

No new files. Changes are confined to:
```
dlp-agent/src/
    config.rs          -- add disk_allowlist field to AgentConfig
    detection/disk.rs  -- change spawn_disk_enumeration_task signature + implement pre-load/merge/save
    service.rs         -- construct Arc<RwLock<AgentConfig>>, pass to spawn_disk_enumeration_task
```

### Pattern 1: `#[serde(default)]` Field Addition for Backwards Compatibility

**What:** Adding a new field to a serde struct with `#[serde(default)]` ensures existing TOML files (pre-Phase-35) that lack the `[[disk_allowlist]]` section still deserialize successfully, defaulting to an empty `Vec`.

**When to use:** Every new field added to `AgentConfig` to ensure forward/backward TOML compatibility.

**Example:**
```rust
// Source: existing AgentConfig pattern (dlp-agent/src/config.rs)
// The same pattern is used for monitored_paths, excluded_paths, encryption, etc.
#[serde(default)]
pub disk_allowlist: Vec<DiskIdentity>,
```

`DiskIdentity` already has `#[serde(default)]` at the struct level and `#[serde(skip_serializing_if = "Option::is_none")]` on all optional fields. This means:
- TOML entries without encryption fields (`encryption_status`, `encryption_method`, `encryption_checked_at`) load cleanly with `None` values — no migration needed.
- TOML entries missing `drive_letter` (disconnected disk) load cleanly with `drive_letter: None`.

### Pattern 2: TOML Array of Tables (`[[section]]`)

**What:** `toml::to_string` serializes `Vec<T>` fields as TOML array-of-tables sections when `T` is a struct. The field name in `AgentConfig` becomes the TOML section header.

**When to use:** Whenever a list of structs needs to be persisted to TOML.

**Example — resulting TOML:**
```toml
# Source: CONTEXT.md §Specific Requirements

[[disk_allowlist]]
instance_id = "PCIIDE\\IDECHANNEL\\4&1234&0&0"
bus_type = "sata"
model = "WDC WD10EZEX-00BN5A0"
drive_letter = "C"
is_boot_disk = true
# encryption fields absent (None) -- #[serde(skip_serializing_if = "Option::is_none")]

[[disk_allowlist]]
instance_id = "NVME\\GEN31X4\\5&ABC"
bus_type = "nvme"
model = "Samsung SSD 980 Pro"
is_boot_disk = false
# drive_letter absent -- disconnected disk, kept per D-06
```

**Note on TOML boolean serialization:** `is_boot_disk = true/false` serializes and deserializes correctly via serde for `bool` fields with no special annotation required. [VERIFIED: existing `AgentConfig` roundtrip tests pass]

### Pattern 3: Merge Algorithm (Live Wins over TOML)

**What:** Start the merged result from the TOML snapshot (so disconnected disks survive), then overwrite with live enumeration results for any disk whose `instance_id` is found in the live scan.

**When to use:** D-06 (keep disconnected) + D-07 (live wins for present disks).

**Example:**
```rust
// Source: CONTEXT.md §Merge Algorithm (pseudocode)
// Collect TOML entries into a HashMap keyed by instance_id.
// HashMap::from_iter is O(n) -- no repeated allocation.
let mut merged: HashMap<String, DiskIdentity> = toml_disks
    .into_iter()
    .map(|d| (d.instance_id.clone(), d))
    .collect();

// Live enumeration overwrites present disks (D-07 -- live wins).
for disk in &live_disks {
    merged.insert(disk.instance_id.clone(), disk.clone());
}

// Values in arbitrary HashMap order -- sort by instance_id for stable TOML output.
let mut updated_list: Vec<DiskIdentity> = merged.into_values().collect();
updated_list.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
```

**Sorting note:** CONTEXT.md does not specify sort order. Stable sort-by-instance_id is recommended for deterministic TOML diffs across restarts (easier to audit). This is Claude's Discretion.

### Pattern 4: Arc<RwLock<AgentConfig>> Construction in service.rs

**What:** The enumeration task needs a shared, mutable `AgentConfig` reference to write `disk_allowlist` and call `save()`. This is a new `Arc<RwLock<AgentConfig>>` binding, separate from the existing `config_arc: Arc<Mutex<AgentConfig>>` used by the config poll loop.

**Critical constraint:** `agent_config` is consumed by `InterceptionEngine::with_config(agent_config)` at line 583 of `service.rs`. The `Arc<RwLock<AgentConfig>>` must be created from `agent_config.clone()` BEFORE the `with_config` call (or from `config_arc.lock().clone()` — but the former is simpler).

**Example:**
```rust
// Source: VERIFIED in service.rs (lines 364, 541, 583)
// agent_config: AgentConfig is loaded once at line 364.

// Existing: config poll loop wrapper (Mutex, unchanged)
let config_arc = Arc::new(parking_lot::Mutex::new(agent_config.clone()));  // line 541

// New: disk enumeration wrapper (RwLock, per D-04)
// Must be created BEFORE agent_config is moved into with_config().
let disk_config_arc = Arc::new(parking_lot::RwLock::new(agent_config.clone()));
let config_path = std::path::PathBuf::from(crate::config::AgentConfig::effective_config_path());

// ...later...
crate::detection::disk::spawn_disk_enumeration_task(
    tokio::runtime::Handle::current(),
    audit_ctx.clone(),
    Arc::clone(&disk_config_arc),
    config_path,
);
```

### Anti-Patterns to Avoid

- **Holding `AgentConfig` write lock while also holding `DiskEnumerator` write locks:** Creates a potential deadlock if any other code path acquires them in opposite order. Always release `DiskEnumerator` locks before acquiring the `AgentConfig` lock.
- **Setting `enumeration_complete = true` before the TOML write:** The TOML write is non-fatal and must not gate the readiness signal. Set `enumeration_complete` after the TOML save attempt (success or failure). Phase 36 enforcement then observes both the updated `instance_id_map` and the persisted allowlist.
- **Failing enumeration on TOML write failure:** TOML write failure is non-fatal. In-memory state is authoritative. Log with `tracing::error!` and continue.
- **Using `.unwrap()` on TOML write path:** Per CLAUDE.md §9.4, never use `.unwrap()` in library code. Use `if let Err(e) = cfg.save(&path) { tracing::error!(...) }`.
- **Skipping `discovered_disks` sync when pre-loading TOML:** Both `discovered_disks` and `instance_id_map` must be kept in sync (CONTEXT.md Claude's Discretion note). Pre-load must update both.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| TOML serialization of `Vec<DiskIdentity>` | Custom TOML writer | `toml::to_string` via `AgentConfig::save()` | Already handles the full struct; `[[disk_allowlist]]` array-of-tables is automatic |
| TOML deserialization from `[[disk_allowlist]]` | Custom TOML parser | `toml::from_str` via `AgentConfig::load()` | Already handles backwards compat; `#[serde(default)]` covers missing section |
| Thread-safe shared config | Manual atomic operations | `parking_lot::RwLock` | Already used throughout `DiskEnumerator`; proven pattern in this codebase |
| Merge logic for disconnected disks | Complex state machine | `HashMap` overwrite (live wins) | Simple O(n) merge; see Pattern 3 above |

**Key insight:** This phase has zero new infrastructure. All persistence, concurrency, and error-handling primitives are already present and used in adjacent code.

---

## Common Pitfalls

### Pitfall 1: Forgetting `config_arc` vs `disk_config_arc` Are Independent Copies

**What goes wrong:** Agent loads config, wraps in `Arc<Mutex<>>` for config poll loop, and later the config poll loop updates `monitored_paths` — but `disk_config_arc` never sees these updates because it was cloned independently at startup.

**Why it happens:** `AgentConfig` is `Clone`, and both wrappers are constructed from separate `.clone()` calls. They are not synchronized.

**How to avoid:** This is intentional and acceptable for Phase 35. The `disk_allowlist` field is only written once (at enumeration time) via `disk_config_arc`. The config poll loop never touches `disk_allowlist`. The two wrappers serve different subsystems.

**Warning signs:** If a future phase needs the config poll loop to push `disk_allowlist` changes from the server, this design will need revisiting. That is Phase 37 scope — ignore for now.

### Pitfall 2: `agent_config` Moved Before `disk_config_arc` Creation

**What goes wrong:** `InterceptionEngine::with_config(agent_config)` takes ownership of `agent_config` by value. If `disk_config_arc` is constructed after this line, it will not compile.

**Why it happens:** Rust's move semantics — once `agent_config` is moved, it cannot be borrowed or cloned.

**How to avoid:** Create `disk_config_arc = Arc::new(RwLock::new(agent_config.clone()))` BEFORE the `with_config(agent_config)` call on line 583 of `service.rs`. The correct ordering window is between line 541 (where `config_arc` is constructed) and line 583.

**Warning signs:** Compiler error `use of moved value: agent_config`.

### Pitfall 3: TOML Serialization of `char` (Drive Letter)

**What goes wrong:** `DiskIdentity.drive_letter` is `Option<char>`. The `toml` crate can serialize `char` as a single-character string, but round-trip behavior deserves verification.

**Why it happens:** TOML has no native `char` type; serde's TOML backend serializes `char` as a single-character string `"C"`. Deserialization back to `char` works if the field is a single ASCII character.

**How to avoid:** This is an existing concern inherited from Phase 33's `DiskIdentity` design. The existing `test_disk_identity_serde_round_trip` test in `dlp-common/src/disk.rs` passes (verified: all 8 disk detection tests pass). However, a TOML-specific roundtrip test for `drive_letter` should be added in Phase 35's test suite to confirm the TOML backend handles it correctly, not just the JSON backend. [ASSUMED — behavior verified for JSON; TOML-specific round-trip not yet tested]

**Warning signs:** `toml::from_str` returning a parse error or `None` for `drive_letter` after a save/load cycle.

### Pitfall 4: Lock Order Violation Between DiskEnumerator and AgentConfig

**What goes wrong:** Deadlock if code elsewhere acquires `AgentConfig` first and then tries to read `DiskEnumerator`, while the enumeration task holds a `DiskEnumerator` write lock and tries to acquire an `AgentConfig` write lock.

**Why it happens:** Two lock-ordered resources in different order across two code paths.

**How to avoid:** The merge/update flow in the enumeration task must (1) complete all DiskEnumerator writes, (2) release all DiskEnumerator write locks, then (3) acquire the AgentConfig write lock to update `disk_allowlist` and call `save()`. Never hold both simultaneously.

**Warning signs:** Agent hangs at startup after successful enumeration but before `enumeration_complete` is set.

### Pitfall 5: `DiskIdentity` Test Instantiation Requires All Fields

**What goes wrong:** `AgentConfig` constructor calls in existing tests enumerate all fields explicitly (e.g., `test_resolve_watch_paths_configured`). Adding `disk_allowlist` to `AgentConfig` will break these tests with a compile error: `missing field disk_allowlist`.

**Why it happens:** Rust's struct literal syntax requires all fields unless `..Default::default()` is used.

**How to avoid:** All existing `AgentConfig { ... }` struct literals in tests must be updated to add `disk_allowlist: Vec::new()` or use `..Default::default()`. There are at least 4 such call sites in `config.rs` tests (lines ~428-440, ~489-500, ~471-481, ~492-501 approximately). These are test-only breaks — no production code is affected.

**Warning signs:** Compiler errors on `cargo test -p dlp-agent --lib`.

---

## Code Examples

### Adding the Field to AgentConfig

```rust
// Source: CONTEXT.md §Specific Requirements + existing config.rs pattern
// File: dlp-agent/src/config.rs

// Required import at top of file:
use dlp_common::DiskIdentity;

// In AgentConfig struct, after the `encryption` field:
/// Disk allowlist persisted across agent restarts (Phase 35).
///
/// Loaded from `[[disk_allowlist]]` TOML array of tables.
/// Each entry is a [`DiskIdentity`] with `instance_id` as the canonical key.
/// When the section is absent (first run or pre-Phase-35 config), defaults to empty.
///
/// Phase 36 enforcement reads from `DiskEnumerator.instance_id_map`; this field
/// is the persistence backing for that map.
#[serde(default)]
pub disk_allowlist: Vec<DiskIdentity>,
```

### Updated spawn_disk_enumeration_task Signature

```rust
// Source: CONTEXT.md §Specific Requirements
// File: dlp-agent/src/detection/disk.rs

pub fn spawn_disk_enumeration_task(
    runtime_handle: tokio::runtime::Handle,
    audit_ctx: crate::audit_emitter::EmitContext,
    agent_config: Arc<parking_lot::RwLock<crate::config::AgentConfig>>,
    config_path: std::path::PathBuf,
) {
    // ...
}
```

### TOML Pre-Load (Inside Task, Before Live Enumeration)

```rust
// Source: CONTEXT.md §Merge Algorithm (pseudocode)
// File: dlp-agent/src/detection/disk.rs -- inside the spawned async block

// Pre-load TOML entries into DiskEnumerator before live enumeration.
let toml_disks: Vec<DiskIdentity> = {
    let cfg = agent_config.read();
    cfg.disk_allowlist.clone()
};

if !toml_disks.is_empty() {
    if let Some(enumerator) = get_disk_enumerator() {
        let mut discovered = enumerator.discovered_disks.write();
        let mut instance_map = enumerator.instance_id_map.write();
        *discovered = toml_disks.clone();
        for disk in &toml_disks {
            instance_map.insert(disk.instance_id.clone(), disk.clone());
        }
        // drive_letter_map intentionally not pre-populated:
        // disconnected disks have stale/absent drive letters; pre-populating
        // would make Phase 36 route I/O events to disconnected disks.
    }
    info!(count = toml_disks.len(), "pre-loaded disk allowlist from TOML");
}
// enumeration_complete remains false until live enumeration succeeds (D-12).
```

### Merge and Persist After Successful Enumeration

```rust
// Source: CONTEXT.md §Merge Algorithm (pseudocode)
// File: dlp-agent/src/detection/disk.rs -- inside the Ok(mut disks) arm

// --- Step 1: Mark boot disk ---
// (existing code, unchanged)

// --- Step 2: Merge live disks with TOML snapshot (D-06, D-07) ---
// Start from TOML entries so disconnected disks survive (D-06).
// Overwrite with live data for present disks (D-07 -- live wins).
let mut merged: HashMap<String, DiskIdentity> = toml_disks
    .into_iter()
    .map(|d| (d.instance_id.clone(), d))
    .collect();
for disk in &disks {
    merged.insert(disk.instance_id.clone(), disk.clone());
}
let mut updated_list: Vec<DiskIdentity> = merged.into_values().collect();
// Sort for deterministic TOML output and stable audit diffs.
updated_list.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));

// --- Step 3: Update DiskEnumerator (all locks released after this block) ---
if let Some(enumerator) = get_disk_enumerator() {
    let mut discovered = enumerator.discovered_disks.write();
    let mut drive_map = enumerator.drive_letter_map.write();
    let mut instance_map = enumerator.instance_id_map.write();
    let mut complete = enumerator.enumeration_complete.write();

    *discovered = updated_list.clone();
    drive_map.clear();
    instance_map.clear();
    for disk in &updated_list {
        if let Some(letter) = disk.drive_letter {
            drive_map.insert(letter, disk.clone());
        }
        instance_map.insert(disk.instance_id.clone(), disk.clone());
    }
    *complete = true;
    // All DiskEnumerator write locks released here (end of block).
}

// --- Step 4: Persist allowlist to TOML (non-fatal, AgentConfig lock independent) ---
{
    let mut cfg = agent_config.write();
    cfg.disk_allowlist = updated_list.clone();
    if let Err(e) = cfg.save(&config_path) {
        tracing::error!(
            error = %e,
            path = %config_path.display(),
            "failed to persist disk allowlist to TOML -- in-memory state remains authoritative"
        );
    }
    // AgentConfig write lock released here.
}

// --- Step 5: Emit audit event ---
emit_disk_discovery(&audit_ctx, &updated_list);
info!(disk_count = updated_list.len(), "fixed disk enumeration complete");
return;
```

---

## Runtime State Inventory

> This phase is not a rename/refactor/migration. No runtime state inventory required.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `toml` crate | `AgentConfig::save()` / `load()` | Yes [VERIFIED: Cargo.toml] | 0.8 | — |
| `parking_lot` crate | `Arc<RwLock<AgentConfig>>` | Yes [VERIFIED: workspace] | 0.12 | — |
| `tempfile` crate (dev) | New TOML roundtrip tests | Yes [VERIFIED: dlp-agent dev-dependencies] | 3.x | — |
| `serial_test` crate (dev) | Tests sharing global singletons | Yes [VERIFIED: dlp-agent dev-dependencies] | 3.x | — |

No missing dependencies. Phase 35 requires no new crates.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` + `cargo test` |
| Config file | None (built-in test runner) |
| Quick run command | `cargo test -p dlp-agent --lib -- detection::disk config 2>&1` |
| Full suite command | `cargo test -p dlp-agent --lib 2>&1` |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DISK-03 | `disk_allowlist` field added to `AgentConfig` with `#[serde(default)]`, TOML roundtrip succeeds | unit | `cargo test -p dlp-agent --lib -- config::tests::test_disk_allowlist` | No -- Wave 0 |
| DISK-03 | Old TOML without `[[disk_allowlist]]` deserializes to empty `Vec` (backwards compat) | unit | `cargo test -p dlp-agent --lib -- config::tests::test_disk_allowlist_backwards_compat` | No -- Wave 0 |
| DISK-03 | TOML pre-load populates `instance_id_map` before enumeration | unit | `cargo test -p dlp-agent --lib -- detection::disk::tests::test_pre_load_populates_instance_map` | No -- Wave 0 |
| DISK-03 | Merge: live disk wins over TOML for same `instance_id` | unit | `cargo test -p dlp-agent --lib -- detection::disk::tests::test_merge_live_wins` | No -- Wave 0 |
| DISK-03 | Merge: disconnected TOML disk retained in merged list (D-06) | unit | `cargo test -p dlp-agent --lib -- detection::disk::tests::test_merge_disconnected_retained` | No -- Wave 0 |
| DISK-03 | `enumeration_complete` not set by TOML pre-load (D-12) | unit | `cargo test -p dlp-agent --lib -- detection::disk::tests::test_enumeration_complete_not_set_on_preload` | No -- Wave 0 |
| DISK-03 | TOML write failure is non-fatal (enumeration succeeds despite save error) | unit | `cargo test -p dlp-agent --lib -- detection::disk::tests::test_toml_write_failure_non_fatal` | No -- Wave 0 |
| DISK-03 | `drive_letter` char round-trips through TOML (not just JSON) | unit | `cargo test -p dlp-agent --lib -- config::tests::test_disk_allowlist_drive_letter_toml_roundtrip` | No -- Wave 0 |
| DISK-03 | Existing `AgentConfig` struct literal tests updated with `disk_allowlist` field | unit | `cargo test -p dlp-agent --lib -- config 2>&1` | Yes, must be updated |

### Sampling Rate

- **Per task commit:** `cargo test -p dlp-agent --lib -- detection::disk config`
- **Per wave merge:** `cargo test -p dlp-agent --lib`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `dlp-agent/src/config.rs` test block -- add `test_disk_allowlist_backwards_compat`, `test_disk_allowlist_toml_roundtrip`, `test_disk_allowlist_drive_letter_toml_roundtrip`
- [ ] `dlp-agent/src/detection/disk.rs` test block -- add `test_pre_load_populates_instance_map`, `test_merge_live_wins`, `test_merge_disconnected_retained`, `test_enumeration_complete_not_set_on_preload`, `test_toml_write_failure_non_fatal`
- [ ] Update all existing `AgentConfig { ... }` struct literals in `config.rs` tests to add `disk_allowlist: Vec::new()` (or `..Default::default()`)

---

## Security Domain

> `security_enforcement` is not explicitly set to false in config.json — treated as enabled.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Not applicable to local file persistence |
| V3 Session Management | No | No session state involved |
| V4 Access Control | Partial | File path `C:\ProgramData\DLP\agent-config.toml` is system-only; `AgentConfig::save()` uses `std::fs::write` without explicit ACL setting — relies on OS DACL inherited from `C:\ProgramData\DLP\` (agent runs as SYSTEM) |
| V5 Input Validation | Yes | TOML deserialization via serde validates field types; `instance_id` is a raw string with no injection risk (used as HashMap key, not in SQL/OS calls) |
| V6 Cryptography | No | Allowlist contains identity metadata only; no secrets persisted |

### Known Threat Patterns for This Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Tampering with `agent-config.toml` to inject false disk entries | Tampering | File ACL on `C:\ProgramData\DLP\` restricts write to SYSTEM/admin only; agent is hardened via `harden_agent_process()` in `service.rs` |
| `instance_id` path traversal or injection | Tampering | `instance_id` is used as a HashMap key and TOML string only; not used in filesystem or OS calls in Phase 35 |
| TOML parse error on malformed `disk_allowlist` entry | DoS (availability) | `AgentConfig::load()` falls back to `Default` on parse failure (`warn!` + return); agent continues without allowlist rather than crashing |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `char` serializes and deserializes correctly through the `toml` 0.8 backend for single ASCII drive letters | Common Pitfalls (Pitfall 3) | TOML roundtrip loses `drive_letter`; drive letters would be `None` after a restart; Phase 36 drive-letter lookups would fail. Low risk -- toml 0.8 handles single-char strings. Mitigated by Wave 0 test. |
| A2 | Sorting `updated_list` by `instance_id` is acceptable (CONTEXT.md does not specify order) | Code Examples | No functional risk; only TOML output order. If admin tools diff the file, a stable sort is strictly better. |

**If this table is empty:** All other claims in this research were verified against source code or project documents.

---

## Open Questions

1. **`config_arc` (Mutex) vs `disk_config_arc` (RwLock) — should they share a single lock?**
   - What we know: Both are constructed from `agent_config.clone()` and are independent copies. The config poll loop writes `monitored_paths`/`heartbeat_interval_secs`/`offline_cache_enabled`/`ldap_config`/`excluded_paths` via `config_arc`. Phase 35 writes `disk_allowlist` via `disk_config_arc`.
   - What's unclear: Could a single `Arc<RwLock<AgentConfig>>` serve both purposes, replacing `config_arc`?
   - Recommendation: Keep them separate for Phase 35 to minimize scope. A refactor to unify them belongs in a future maintenance phase when the config struct grows further. The two wrappers never contend because they touch disjoint fields.

2. **TOML write: should the existing `config_arc` be used instead of a new `disk_config_arc`?**
   - What we know: `config_arc` is `Arc<parking_lot::Mutex<AgentConfig>>`, used exclusively by the config poll loop. CONTEXT.md D-04 says `Arc<parking_lot::RwLock<AgentConfig>>`.
   - What's unclear: Whether passing `config_arc` (Mutex) to the enumeration task (which expects RwLock per D-04) would be a cleaner design.
   - Recommendation: Introduce `disk_config_arc: Arc<RwLock<AgentConfig>>` as a separate binding. The type difference matters — `RwLock` signals "multiple readers (future enforcement) / one writer (enumeration)". Introducing `Mutex` here would be a regression in expressiveness.

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `_agent_config_path: Option<String>` stub in `spawn_disk_enumeration_task` | `agent_config: Arc<RwLock<AgentConfig>>` + `config_path: PathBuf` | Phase 35 (now) | Enables actual allowlist persistence; Phase 33 intentionally left a stub |
| `AgentConfig` without `disk_allowlist` | `AgentConfig` with `disk_allowlist: Vec<DiskIdentity>` | Phase 35 (now) | Backwards-compatible via `#[serde(default)]` |

---

## Sources

### Primary (HIGH confidence)

- `dlp-agent/src/config.rs` [VERIFIED: read directly] -- `AgentConfig` struct, `save()`, `load()`, `effective_config_path()`
- `dlp-agent/src/detection/disk.rs` [VERIFIED: read directly] -- `DiskEnumerator`, `spawn_disk_enumeration_task`, `set_disk_enumerator`
- `dlp-agent/src/service.rs` [VERIFIED: read directly] -- startup sequence, `config_arc` construction, `spawn_disk_enumeration_task` call site
- `dlp-common/src/disk.rs` [VERIFIED: read directly] -- `DiskIdentity` struct, all serde annotations
- `dlp-agent/Cargo.toml` [VERIFIED: read directly] -- `toml = "0.8"`, `parking_lot`, `tempfile`, `serial_test` dev-deps
- `Cargo.toml` (workspace) [VERIFIED: read directly] -- `parking_lot = "0.12"`, `serde`, `anyhow`, `tracing` versions
- `.planning/phases/35-disk-allowlist-persistence/35-CONTEXT.md` [VERIFIED: read directly] -- all decisions D-01 through D-13, merge algorithm pseudocode, signature specs

### Secondary (MEDIUM confidence)

- `cargo test -p dlp-agent --lib -- detection::disk config` [VERIFIED: run in session] -- all 8 disk tests + 29 config/server_client tests pass; confirms no existing `disk_allowlist` field

### Tertiary (LOW confidence)

- `toml` crate `char` round-trip behavior (Pitfall 3) [ASSUMED] -- not explicitly verified in this session for TOML backend; JSON backend confirmed by existing tests.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all dependencies verified in Cargo.toml files
- Architecture: HIGH -- based on direct code reading of all 4 key source files
- Pitfalls: HIGH -- derived from direct code analysis (Pitfalls 1-4) and known Rust semantics (Pitfall 5)
- Test gaps: HIGH -- verified by running existing test suite; all new tests are Wave 0 gaps

**Research date:** 2026-05-03
**Valid until:** 2026-06-03 (stable Rust ecosystem, no fast-moving dependencies)
