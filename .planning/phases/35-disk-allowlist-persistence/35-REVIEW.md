---
phase: 35-disk-allowlist-persistence
reviewed: 2026-05-03T00:00:00Z
depth: standard
files_reviewed: 4
files_reviewed_list:
  - dlp-agent/src/config.rs
  - dlp-agent/src/detection/disk.rs
  - dlp-agent/src/service.rs
  - dlp-agent/src/detection/encryption.rs
findings:
  critical: 2
  warning: 4
  info: 2
  total: 8
status: issues_found
---

# Phase 35: Code Review Report

**Reviewed:** 2026-05-03
**Depth:** standard
**Files Reviewed:** 4
**Status:** issues_found

## Summary

Phase 35 adds `disk_allowlist: Vec<DiskIdentity>` to `AgentConfig`, TOML pre-load/merge/persist
logic in `spawn_disk_enumeration_task`, and `Arc<RwLock<AgentConfig>>` + `PathBuf` wiring in
`service.rs`. The `encryption.rs` file contains only `cargo fmt` whitespace adjustments; no
logic was changed and no findings apply to it.

Two critical issues were found: a dangling singleton reference in `acquire_instance_mutex` that
silently provides no single-instance enforcement, and a dual-config-clone design in `service.rs`
that causes the `config_poll_loop`'s server-pushed updates to never reach `disk_config_arc`,
breaking any Phase 36/37 enforcement that reads `disk_allowlist` from that arc. Four warnings
cover unsafe `impl` redundancy, pre-load lock ordering, a clone count concern, and a missing
test for the cross-arc divergence. Two info items flag a leftover TODO comment in `disk.rs` and
the test-suite breakage caused by the Phase 35 struct field addition.

---

## Critical Issues

### CR-01: `acquire_instance_mutex` creates a temporary mutex that is immediately dropped — provides zero enforcement

**File:** `dlp-agent/src/service.rs:992`

**Issue:** `std::sync::Mutex::new(())` constructs a brand-new anonymous mutex on the stack on
every call. Calling `.try_lock()` on a freshly constructed mutex always succeeds; it does not
check whether another process holds any mutex. The guard returned by `try_lock` is bound to `_guard`
in the `Ok` arm, but because the match arm has no block, `_guard` lives until the end of the
`match` expression — i.e. it is dropped immediately. After the function returns, the mutex is
destroyed entirely. A second service instance calling the same function creates its own
independent mutex and also "succeeds". This means the single-instance enforcement does not work
at all.

The actual mechanism for named cross-process mutexes on Windows is
`CreateMutexW` / `OpenMutexW` with a well-known name (e.g., `"Global\\DlpAgentMutex"`).
The resulting `HANDLE` must be stored in a `static` or returned so it stays alive for the
process lifetime.

**Fix:**
```rust
// In service.rs: replace acquire_instance_mutex with a Windows named mutex approach.
// Store the handle in a static so it lives for the process lifetime.

use std::sync::OnceLock;
#[cfg(windows)]
use windows::Win32::System::Threading::{CreateMutexW, MUTEX_ALL_ACCESS};
#[cfg(windows)]
use windows::core::PCWSTR;

static INSTANCE_MUTEX: OnceLock<windows::Win32::Foundation::HANDLE> = OnceLock::new();

#[cfg(windows)]
fn acquire_instance_mutex() {
    let name: Vec<u16> = "Global\\DlpAgentSingleInstance"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
        CreateMutexW(None, true, PCWSTR(name.as_ptr()))
    };
    match handle {
        Ok(h) => {
            // GetLastError() == ERROR_ALREADY_EXISTS means another instance owns the mutex.
            if windows::Win32::Foundation::GetLastError()
                == windows::Win32::Foundation::ERROR_ALREADY_EXISTS
            {
                error!(service_name = SERVICE_NAME, "another instance is already running -- exiting");
                std::process::exit(1);
            }
            let _ = INSTANCE_MUTEX.set(h);
            info!(service_name = SERVICE_NAME, "single-instance mutex acquired");
        }
        Err(e) => {
            warn!(error = %e, "could not create single-instance mutex -- continuing");
        }
    }
}
```

---

### CR-02: Two independent `AgentConfig` clones in `run_loop` diverge immediately — `config_poll_loop` updates never reach `disk_config_arc`

**File:** `dlp-agent/src/service.rs:541-552`

**Issue:** `run_loop` clones `agent_config` twice:

```rust
// line 541
let config_arc = Arc::new(parking_lot::Mutex::new(agent_config.clone()));
// line 552
let disk_config_arc = Arc::new(parking_lot::RwLock::new(agent_config.clone()));
```

`config_poll_loop` receives `Arc::clone(&config_arc)` (line 582) and writes server-pushed
updates (heartbeat interval, offline cache, monitored paths, LDAP config, excluded paths)
exclusively into `config_arc`. `disk_config_arc` is a completely independent clone; it receives
updates only from `spawn_disk_enumeration_task`, which writes `disk_allowlist`.

Any Phase 36/37 or future code that reads `disk_config_arc` for fields updated by the poll loop
(e.g., a future `ldap_config` or `monitored_paths` check) will see the startup snapshot forever.
More concretely: if `disk_allowlist` were ever merged with a server-pushed payload, the merge
would operate on the stale clone.

The deeper issue is that there is no documented invariant specifying which arc is authoritative
for which fields, making the split ownership invisible to future maintainers.

**Fix:** Use a single `Arc<parking_lot::RwLock<AgentConfig>>` and adapt `config_poll_loop` to
accept `RwLock` instead of `Mutex`:

```rust
// Replace both lines 541-552 with one authoritative arc.
let config_arc = Arc::new(parking_lot::RwLock::new(agent_config.clone()));

// Pass the same arc to both subsystems:
// config_poll_loop:
let config_for_poll = Arc::clone(&config_arc);
// spawn_disk_enumeration_task:
crate::detection::disk::spawn_disk_enumeration_task(
    tokio::runtime::Handle::current(),
    audit_ctx.clone(),
    Arc::clone(&config_arc),   // same arc
    config_path.clone(),
);
```

Update `config_poll_loop`'s signature from `Arc<parking_lot::Mutex<AgentConfig>>` to
`Arc<parking_lot::RwLock<AgentConfig>>` and change `.lock()` to `.write()` inside it.
The function only writes during the update block; the rest of the time it reads
`heartbeat_interval_secs` which is also safe under `RwLock`.

---

## Warnings

### WR-01: Unnecessary `unsafe impl Send + Sync` for `DiskEnumerator` — the impls are already derived automatically

**File:** `dlp-agent/src/detection/disk.rs:107-108`

**Issue:** `DiskEnumerator` contains only `parking_lot::RwLock<T>` fields where `T: Send + Sync`
(`Vec<DiskIdentity>`, `HashMap<char, DiskIdentity>`, `HashMap<String, DiskIdentity>`, `bool`).
`parking_lot::RwLock<T>` implements `Send + Sync` when `T: Send`. All field types satisfy this.
The compiler derives `Send + Sync` for `DiskEnumerator` automatically; the explicit `unsafe impl`
blocks are redundant.

Redundant `unsafe impl` statements are a code quality concern because they suppress the compiler's
auto-derived safety check. If a non-`Send` field were added in a future patch, the compiler would
silently accept it instead of emitting an error, potentially introducing a data race.

**Fix:**
```rust
// Remove both unsafe impl blocks entirely:
// unsafe impl Send for DiskEnumerator {}  <-- delete
// unsafe impl Sync for DiskEnumerator {}  <-- delete
// The compiler generates correct impls from the field types.
```

---

### WR-02: Pre-load block acquires `discovered_disks` and `instance_id_map` write locks simultaneously while `drive_letter_map` and `enumeration_complete` are left unlocked — creates a window where partial state is visible to concurrent readers

**File:** `dlp-agent/src/detection/disk.rs:186-191`

**Issue:** The pre-load block acquires two write locks at the same time (`discovered_disks` +
`instance_id_map`) but leaves `drive_letter_map` and `enumeration_complete` in their initial
empty/false state. Concurrent readers (e.g., from the `encryption.rs` background task polling
`is_ready()` in a 250ms loop) will see `discovered_disks` populated but `enumeration_complete`
still `false`, which is the intended D-12 behavior. However, they can also observe
`disk_for_instance_id` returning entries from `instance_id_map` while `all_disks()` and
`disk_for_drive_letter` return inconsistent results until Step 3 completes.

In Step 3 (success path), all four write locks are acquired in the order:
`discovered_disks` → `drive_letter_map` → `instance_id_map` → `enumeration_complete`.
In the pre-load block the order is `discovered_disks` → `instance_id_map` (no `drive_letter_map`
or `complete`). There is no risk of deadlock between the two blocks because they run sequentially
in the same async task, but a concurrent reader between pre-load and Step 3 sees `instance_id_map`
populated while `drive_letter_map` is empty — an inconsistency that could confuse Phase 36
enforcement if it queries both maps.

**Fix:** Document the observable window explicitly, or pre-load all three maps atomically (still
leaving `complete` false per D-12):

```rust
let mut discovered = enumerator.discovered_disks.write();
let mut instance_map = enumerator.instance_id_map.write();
let mut drive_map = enumerator.drive_letter_map.write(); // add this
*discovered = toml_disks.clone();
for disk in &toml_disks {
    instance_map.insert(disk.instance_id.clone(), disk.clone());
    // Intentionally pre-populate with stale drive letters from TOML.
    // Step 3 will clear and re-populate with live letters on success.
    // Stale entries are preferable to the current asymmetry.
    if let Some(letter) = disk.drive_letter {
        drive_map.insert(letter, disk.clone());
    }
}
// Note: enumeration_complete stays false per D-12.
```

---

### WR-03: `updated_list` is cloned three times consecutively in the success path — unnecessary allocation

**File:** `dlp-agent/src/detection/disk.rs:251-282`

**Issue:** After building `updated_list`, it is cloned three times in close succession:

- Line 251: `*discovered = updated_list.clone();` (writes into DiskEnumerator)
- Line 270: `cfg.disk_allowlist = updated_list.clone();` (writes into AgentConfig)
- Line 282: `emit_disk_discovery(&audit_ctx, &updated_list);` (passes by reference — no clone)

The third use is by reference and correct. The first two clones are necessary because
`updated_list` must remain available for both. However, the order can be rearranged so one
clone is avoided by moving `updated_list` into `cfg.disk_allowlist` after the DiskEnumerator
block is done:

**Fix:**
```rust
// Inside the DiskEnumerator block (Step 3):
*discovered = updated_list.clone(); // still needs a clone here
// ... rest of Step 3 ...

// Step 4: move updated_list into cfg (no second clone needed):
{
    let mut cfg = agent_config.write();
    cfg.disk_allowlist = updated_list; // move, not clone
    if let Err(e) = cfg.save(&config_path) { ... }
}

// Step 5: emit uses the now-moved value — use `discovered` instead:
emit_disk_discovery(&audit_ctx, &enumerator.discovered_disks.read());
```

This avoids one full `Vec<DiskIdentity>` clone (each entry includes `String` fields) on every
successful enumeration cycle.

---

### WR-04: No test verifies that `config_poll_loop` updates are visible through `disk_config_arc` — the dual-clone divergence (CR-02) is untested

**File:** `dlp-agent/src/service.rs:541-584`

**Issue:** There is no test that exercises `config_poll_loop` writing a field and then reads it
back through `disk_config_arc`. Given that the two arcs are independent clones, a test would
immediately fail with a field mismatch — but because no such test exists, the divergence
(identified in CR-02) is invisible to the test suite.

**Fix:** Add an integration-level unit test for the `run_loop` config wiring, or at minimum add
a compile-time assertion that both subsystems receive the same `Arc` instance (using
`Arc::ptr_eq`). Until CR-02 is resolved, a test asserting the two arcs are the same object would
serve as a regression guard.

---

## Info

### IN-01: `test_resolve_watch_paths_configured` and `test_config_clone_and_eq` in `tests/comprehensive.rs` fail to compile after Phase 35 added `disk_allowlist`

**File:** `dlp-agent/tests/comprehensive.rs:354,375`

**Issue:** Both tests construct `AgentConfig` via struct literal but omit the new `disk_allowlist`
field. The compiler emits `error[E0063]: missing field 'disk_allowlist'`. The unit tests in
`config.rs` pass because they use `..Default::default()` spread syntax, but the integration tests
in `tests/comprehensive.rs` use exhaustive struct literals that were not updated when the new
field was added.

This causes `cargo test --tests` (which runs integration tests) to fail to compile, even though
`cargo test --lib` succeeds.

**Fix:** Add `disk_allowlist: Vec::new()` to both struct literals in `tests/comprehensive.rs`,
or switch them to use `..Default::default()`:
```rust
let config = AgentConfig {
    monitored_paths: vec![...],
    disk_allowlist: Vec::new(), // add this
    ..Default::default()
};
```

---

### IN-02: `spawn_disk_enumeration_task` logs the pre-load info message outside the `if let Some(enumerator)` block — log fires even when the global is not set

**File:** `dlp-agent/src/detection/disk.rs:193-197`

**Issue:** The `info!(count = toml_disks.len(), "pre-loaded disk allowlist from TOML")` log on
line 193 is placed after the `if let Some(enumerator)` block, not inside it. If
`get_disk_enumerator()` returns `None` (i.e., `set_disk_enumerator` was never called before
`spawn_disk_enumeration_task`), the log still fires, claiming disks were pre-loaded when in fact
they were silently dropped. This is a misleading diagnostic.

**Fix:**
```rust
if let Some(enumerator) = get_disk_enumerator() {
    let mut discovered = enumerator.discovered_disks.write();
    let mut instance_map = enumerator.instance_id_map.write();
    *discovered = toml_disks.clone();
    for disk in &toml_disks {
        instance_map.insert(disk.instance_id.clone(), disk.clone());
    }
    // Move log inside the block so it only fires on success:
    info!(count = toml_disks.len(), "pre-loaded disk allowlist from TOML");
} else {
    warn!("DiskEnumerator not set -- TOML pre-load skipped");
}
```

---

_Reviewed: 2026-05-03_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
