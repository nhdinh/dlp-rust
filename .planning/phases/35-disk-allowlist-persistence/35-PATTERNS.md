# Phase 35: Disk Allowlist Persistence - Pattern Map

**Mapped:** 2026-05-03
**Files analyzed:** 3 modified files (no new files)
**Analogs found:** 3 / 3 (all modifications are intra-file extensions of existing patterns)

---

## File Classification

| Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---------------|------|-----------|----------------|---------------|
| `dlp-agent/src/config.rs` | config / model | batch (TOML I/O) | itself — `EncryptionConfig` field addition pattern (lines 81-91, 147-153) | exact |
| `dlp-agent/src/detection/disk.rs` | service / background task | batch (pre-load + merge + persist) | itself — existing `spawn_disk_enumeration_task` DiskEnumerator write block (lines 151-229) | exact |
| `dlp-agent/src/service.rs` | startup wiring | request-response | itself — `config_arc` construction at line 541 and `spawn_disk_enumeration_task` call at lines 630-634 | exact |

---

## Pattern Assignments

### `dlp-agent/src/config.rs` (config field addition)

**Analog:** Same file — `EncryptionConfig` field and `encryption` field on `AgentConfig`.

**Field addition pattern** (`config.rs` lines 81-91 and 147-153):
```rust
// Existing pattern for adding a serde-compatible, backwards-compatible field:
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EncryptionConfig {
    #[serde(default)]
    pub recheck_interval_secs: Option<u64>,
}

// ...in AgentConfig struct body (lines 147-153):
/// Phase 34 BitLocker verification settings (D-11).
///
/// When the `[encryption]` section is absent, defaults are applied at
/// use site via [`AgentConfig::resolved_recheck_interval`].
#[serde(default)]
pub encryption: EncryptionConfig,
```

**New field to add** (after `encryption` field, ~line 163):
```rust
/// Disk allowlist persisted across agent restarts (Phase 35).
///
/// Loaded from `[[disk_allowlist]]` TOML array of tables.
/// Each entry is a [`DiskIdentity`] with `instance_id` as the canonical key.
/// When the section is absent (first run or pre-Phase-35 config), defaults to empty.
///
/// Phase 36 enforcement reads from `DiskEnumerator.instance_id_map`; this field
/// is the persistence backing for that map.
#[serde(default)]
pub disk_allowlist: Vec<dlp_common::DiskIdentity>,
```

**Import addition** (at top of file, after existing imports ~line 49-53):
```rust
// No new import needed if using the full path `dlp_common::DiskIdentity`.
// Alternatively add: use dlp_common::DiskIdentity;
// The existing crate already uses dlp_common types (see ldap_config field line 158).
```

**Test struct literal update pattern** (`config.rs` lines 426-436, 461-471, 489-498):
```rust
// All AgentConfig { ... } struct literals in tests must add the new field.
// Pattern: either add the field explicitly or use ..Default::default() spread.

// Explicit (used in test_resolve_watch_paths_configured, lines 426-436):
AgentConfig {
    server_url: None,
    monitored_paths: vec![r"C:\Data\".to_string()],
    excluded_paths: Vec::new(),
    heartbeat_interval_secs: None,
    offline_cache_enabled: None,
    log_level: None,
    encryption: EncryptionConfig::default(),
    ldap_config: None,
    machine_name: None,
    disk_allowlist: Vec::new(),   // <-- add this line to ALL such literals
}

// Spread pattern (used in test_resolved_log_level_known_values, line 543):
AgentConfig {
    log_level: Some(input.to_string()),
    ..Default::default()
    // disk_allowlist: Vec::new() is implicitly covered by Default::default()
}
```

**TOML roundtrip test pattern** (`config.rs` lines 458-485):
```rust
// Copy from test_agent_config_save_roundtrip.  Add disk_allowlist assertions.
#[test]
fn test_disk_allowlist_toml_roundtrip() {
    use dlp_common::{BusType, DiskIdentity};
    let original = AgentConfig {
        disk_allowlist: vec![DiskIdentity {
            instance_id: "PCIIDE\\IDECHANNEL\\4&1234".to_string(),
            bus_type: BusType::Sata,
            model: "WDC WD10EZEX-00BN5A0".to_string(),
            drive_letter: Some('C'),
            is_boot_disk: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    let tmp_path = std::env::temp_dir().join("test_disk_allowlist_roundtrip.toml");
    original.save(&tmp_path).expect("save should succeed");
    let loaded = AgentConfig::load(&tmp_path);
    let _ = std::fs::remove_file(&tmp_path);
    assert_eq!(loaded.disk_allowlist.len(), 1);
    assert_eq!(loaded.disk_allowlist[0].instance_id, "PCIIDE\\IDECHANNEL\\4&1234");
    assert_eq!(loaded.disk_allowlist[0].drive_letter, Some('C'));
}
```

---

### `dlp-agent/src/detection/disk.rs` (task signature + pre-load + merge + persist)

**Analog:** Same file — existing `spawn_disk_enumeration_task` and its DiskEnumerator write block (lines 151-229).

**Import additions** (at top of file, after existing imports ~lines 25-32):
```rust
// Add to existing import block:
use std::path::PathBuf;
use crate::config::AgentConfig;
// parking_lot::RwLock is already imported via `use parking_lot::RwLock;` (line 26).
// std::sync::Arc is already imported (line 28).
// std::collections::HashMap is already imported (line 27).
```

**Signature change pattern** (lines 151-155):
```rust
// BEFORE (Phase 33/34 stub):
pub fn spawn_disk_enumeration_task(
    runtime_handle: tokio::runtime::Handle,
    audit_ctx: crate::audit_emitter::EmitContext,
    _agent_config_path: Option<String>,   // stub — unused
)

// AFTER (Phase 35):
pub fn spawn_disk_enumeration_task(
    runtime_handle: tokio::runtime::Handle,
    audit_ctx: crate::audit_emitter::EmitContext,
    agent_config: Arc<parking_lot::RwLock<AgentConfig>>,
    config_path: PathBuf,
)
```

**TOML pre-load pattern** (insert inside `runtime_handle.spawn(async move { ... })`, before the retry loop at line 157):
```rust
// Pre-load TOML allowlist entries into DiskEnumerator before live enumeration (D-11).
// Use a read lock — does not block other readers; extract the Vec and release immediately.
let toml_disks: Vec<dlp_common::DiskIdentity> = {
    let cfg = agent_config.read();
    cfg.disk_allowlist.clone()
};

if !toml_disks.is_empty() {
    if let Some(enumerator) = get_disk_enumerator() {
        // Acquire write locks on both maps that Phase 36 reads.
        let mut discovered = enumerator.discovered_disks.write();
        let mut instance_map = enumerator.instance_id_map.write();
        *discovered = toml_disks.clone();
        for disk in &toml_disks {
            instance_map.insert(disk.instance_id.clone(), disk.clone());
        }
        // drive_letter_map intentionally NOT pre-populated:
        // disconnected disks have stale/absent drive letters; pre-populating
        // would make Phase 36 route I/O events to disconnected disks.
    }
    info!(count = toml_disks.len(), "pre-loaded disk allowlist from TOML");
}
// enumeration_complete remains false until live enumeration succeeds (D-12).
```

**Merge + DiskEnumerator update pattern** (replaces the existing write block at lines 183-199):
```rust
// --- Step 2: Merge live disks with TOML snapshot (D-06, D-07) ---
// Start from TOML entries so disconnected disks survive (D-06).
// Overwrite with live data for present disks (D-07 -- live wins).
let mut merged: HashMap<String, dlp_common::DiskIdentity> = toml_disks
    .into_iter()
    .map(|d| (d.instance_id.clone(), d))
    .collect();
for disk in &disks {
    merged.insert(disk.instance_id.clone(), disk.clone());
}
let mut updated_list: Vec<dlp_common::DiskIdentity> = merged.into_values().collect();
// Sort for deterministic TOML output and stable audit diffs (Claude's Discretion).
updated_list.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));

// --- Step 3: Update DiskEnumerator (all locks released after this block) ---
// Pattern mirrors lines 183-199 of the existing code exactly.
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

// --- Step 4: Persist allowlist to TOML (non-fatal, separate lock from DiskEnumerator) ---
// CRITICAL LOCK ORDER: DiskEnumerator locks MUST be released before acquiring AgentConfig
// write lock to avoid deadlock (RESEARCH.md §"Key Lock Ordering").
{
    let mut cfg = agent_config.write();
    cfg.disk_allowlist = updated_list.clone();
    if let Err(e) = cfg.save(&config_path) {
        // Non-fatal: in-memory state is authoritative. Log and continue.
        // Pattern: tracing::error! for non-fatal I/O failures (CLAUDE.md §9.1).
        tracing::error!(
            error = %e,
            path = %config_path.display(),
            "failed to persist disk allowlist to TOML -- in-memory state remains authoritative"
        );
    }
    // AgentConfig write lock released here.
}

// --- Step 5: Emit audit event and return ---
emit_disk_discovery(&audit_ctx, &updated_list);
info!(disk_count = updated_list.len(), "fixed disk enumeration complete");
return;
```

**Error handling pattern** (matches existing `tracing::error!` calls, e.g., line 224):
```rust
// Non-fatal errors: log with tracing::error!, continue execution.
// Never panic!, never unwrap() on TOML write path.
if let Err(e) = cfg.save(&config_path) {
    tracing::error!(error = %e, path = %config_path.display(), "...");
}
// Note: `error = %e` uses Display formatting per existing pattern (line 224 uses `error = %e`).
```

**Test pattern for merge logic** (copy from `test_disk_enumerator_update_and_query` at lines 302-370):
```rust
// New test: test_merge_live_wins
// Arrange: toml_disks contains one entry, live_disks contains same instance_id with updated drive_letter.
// Act: run merge algorithm.
// Assert: merged list has 1 entry with live drive_letter.

// New test: test_merge_disconnected_retained
// Arrange: toml_disks has 2 entries, live_disks has 1 (the other is disconnected).
// Act: run merge.
// Assert: merged list has 2 entries; disconnected entry keeps its TOML values.
```

---

### `dlp-agent/src/service.rs` (startup wiring)

**Analog:** Same file — `config_arc` construction pattern at line 541, `spawn_disk_enumeration_task` call at lines 630-634.

**Arc<RwLock<AgentConfig>> construction pattern** (insert after line 541, before `recheck_interval` at line 582):
```rust
// Existing: config poll loop wrapper (Mutex, unchanged -- line 541):
let config_arc = Arc::new(parking_lot::Mutex::new(agent_config.clone()));

// New: disk enumeration wrapper (RwLock per D-04).
// MUST be created BEFORE agent_config is moved into with_config() at line 583.
// The window is between line 541 and line 583.
let disk_config_arc = Arc::new(parking_lot::RwLock::new(agent_config.clone()));
let config_path = std::path::PathBuf::from(crate::config::AgentConfig::effective_config_path());
```

**spawn_disk_enumeration_task call site update** (lines 630-634):
```rust
// BEFORE:
crate::detection::disk::spawn_disk_enumeration_task(
    tokio::runtime::Handle::current(),
    audit_ctx.clone(),
    None, // Phase 35 will pass the allowlist TOML path here
);

// AFTER:
crate::detection::disk::spawn_disk_enumeration_task(
    tokio::runtime::Handle::current(),
    audit_ctx.clone(),
    Arc::clone(&disk_config_arc),
    config_path,
);
```

---

## Shared Patterns

### `parking_lot::RwLock` Write Lock Block
**Source:** `dlp-agent/src/detection/disk.rs` lines 183-199
**Apply to:** DiskEnumerator write block in disk.rs (Phase 35 extends the existing block)
```rust
// Pattern: acquire multiple write guards in a scoped block; all release at end of block.
// This prevents accidental lock extension across unrelated operations.
if let Some(enumerator) = get_disk_enumerator() {
    let mut discovered = enumerator.discovered_disks.write();
    let mut drive_map = enumerator.drive_letter_map.write();
    let mut instance_map = enumerator.instance_id_map.write();
    let mut complete = enumerator.enumeration_complete.write();
    // ... mutations ...
    *complete = true;
    // All locks dropped here at end of `if let` block.
}
```

### `#[serde(default)]` Backwards-Compatible Field Addition
**Source:** `dlp-agent/src/config.rs` lines 89, 108, 115, 123, 129, 134, 152, 157
**Apply to:** New `disk_allowlist` field in `AgentConfig`
```rust
// Pattern: every new AgentConfig field uses #[serde(default)] so old TOML files
// without the field still deserialize to a valid struct.
#[serde(default)]
pub some_new_field: SomeType,
```

### Non-Fatal I/O Error Logging
**Source:** `dlp-agent/src/detection/disk.rs` lines 207-215 (warn on retry), lines 221-228 (error on final failure)
**Apply to:** TOML write failure in disk.rs
```rust
// Pattern: tracing::error! for non-fatal failures; never panic!, never unwrap().
// Structured fields use `field = %value` (Display) or `field = ?value` (Debug).
tracing::error!(
    error = %e,
    path = %config_path.display(),
    "descriptive message -- consequence for operator"
);
```

### `AgentConfig::save()` Call Pattern
**Source:** `dlp-agent/src/config.rs` lines 262-266
**Apply to:** TOML write in disk.rs enumeration task
```rust
// AgentConfig::save() takes &Path, returns anyhow::Result<()>.
// Always wrap in if let Err(e) = ... to handle non-fatally.
pub fn save(&self, path: &Path) -> anyhow::Result<()> {
    let toml_str = toml::to_string(self).context("failed to serialize AgentConfig to TOML")?;
    std::fs::write(path, toml_str)
        .with_context(|| format!("failed to write config to {}", path.display()))?;
    Ok(())
}
```

### `Arc::clone` for Task Argument Passing
**Source:** `dlp-agent/src/service.rs` lines 570-571, 628-629
**Apply to:** Passing `disk_config_arc` to `spawn_disk_enumeration_task`
```rust
// Pattern: Arc::clone at the call site makes ownership transfer explicit.
// The spawned task owns its clone; the caller retains the original Arc.
crate::detection::disk::set_disk_enumerator(Arc::clone(&disk_enumerator));
// Phase 35 follows same pattern:
// spawn_disk_enumeration_task(..., Arc::clone(&disk_config_arc), config_path);
```

---

## No Analog Found

No files in this phase lack a codebase analog. All three files being modified already contain the core patterns being extended.

---

## Affected Test Call Sites

The following existing test struct literals in `config.rs` will require `disk_allowlist: Vec::new()` to be added (compile-time breakage after field addition):

| Test function | Approximate lines | Fix required |
|---------------|-------------------|-------------|
| `test_resolve_watch_paths_configured` | 425-439 | Add `disk_allowlist: Vec::new()` |
| `test_agent_config_save_roundtrip` | 458-485 | Add `disk_allowlist: Vec::new()` to `original` and `expected` |
| `test_agent_config_save_preserves_server_url` | 487-511 | Add `disk_allowlist: Vec::new()` |

Structs using `..Default::default()` spread (e.g., `test_resolved_log_level_known_values` line 543) are automatically safe — `Default` will supply `Vec::new()`.

---

## Metadata

**Analog search scope:** `dlp-agent/src/config.rs`, `dlp-agent/src/detection/disk.rs`, `dlp-agent/src/service.rs`, `dlp-common/src/disk.rs`
**Files scanned:** 4
**Pattern extraction date:** 2026-05-03
