---
phase: 36-disk-enforcement
fixed_at: 2026-05-04T00:00:00Z
review_path: .planning/phases/36-disk-enforcement/36-REVIEW.md
iteration: 1
findings_in_scope: 10
fixed: 10
skipped: 0
status: all_fixed
---

# Phase 36: Code Review Fix Report

**Fixed at:** 2026-05-04T00:00:00Z
**Source review:** .planning/phases/36-disk-enforcement/36-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 10 (4 Critical + 6 Warning)
- Fixed: 10
- Skipped: 0

## Fixed Issues

### CR-01: TOCTOU Race Between Snapshot Read and Write-Lock Insert in `on_disk_arrival_inner`

**Files modified:** `dlp-agent/src/detection/disk.rs`
**Commit:** `924e7f8`
**Applied fix:** Removed the stale `existing_letters: HashSet<char>` snapshot that was taken under a read lock and then used as a guard for a later write-lock insertion. Replaced with an atomic `contains_key` check inside the write lock itself, so the check-and-insert cannot race. Also removed the now-unused `HashSet` import.

---

### CR-02: Use-After-Destroy of HWND in `unregister_device_watcher`

**Files modified:** `dlp-agent/src/detection/device_watcher.rs`
**Commit:** `b10cbef`
**Applied fix:** Removed the explicit `DestroyWindow(hwnd)` call after `thread.join()`. The message loop destroys the window via the WM_CLOSE -> DefWindowProcW -> DestroyWindow -> WM_DESTROY chain before the thread exits. The second call was undefined behavior in Win32. Added a comment explaining why the call must not be present.

---

### CR-03: SMTP Password Stored and Transmitted as Plain `String`

**Files modified:** `dlp-server/src/alert_router.rs`, `dlp-server/Cargo.toml`, `Cargo.toml`
**Commit:** `936228b`
**Applied fix:** Added `secrecy = "0.8"` to the workspace and dlp-server dependencies. Changed `SmtpConfig.password` from `String` to `SecretString`. Changed `AlertRouterConfigRow.smtp_password` from `String` to `SecretString`. Replaced `#[derive(Debug)]` on both structs with manual `Debug` implementations that redact the password field with `"[REDACTED]"`. Updated the `Credentials::new` call site to use `expose_secret().to_string()`. Updated all test construction sites to use `SecretString::new("...".into())` and updated the assertion to use `expose_secret()`.

---

### CR-04: Dead `disk_to_identity` Write-Path — Fallback Is Silently Never Populated

**Files modified:** `dlp-agent/src/detection/usb.rs`
**Commit:** `84c1f8b`
**Applied fix:** Deleted the `disk_to_identity: RwLock<HashMap<String, DeviceIdentity>>` field from `UsbDetector` and its doc comment. Deleted the two orphan tests (`test_disk_to_identity_populated_on_arrival`, `test_disk_to_identity_removal_fallback`) that only tested map insert/retrieve on the dead field and exercised no production logic.

---

### WR-01: `spawn_disk_enumeration_task` Holds Multiple `DiskEnumerator` Write Locks Simultaneously

**Files modified:** `dlp-agent/src/detection/disk.rs`
**Commit:** `ee2bd50`
**Applied fix:** Split the single block holding four simultaneous write locks into four sequential scoped blocks, each acquiring, mutating, and immediately dropping one lock. `enumeration_complete` is set last so enforcement exits the fail-closed window only after all maps are fully populated.

---

### WR-02: `on_usb_device_arrival` Drive-Letter Assignment Is Racy and Wrong

**Files modified:** `dlp-agent/src/detection/usb.rs`
**Commit:** `747e03c`
**Applied fix:** Removed the A..=Z `Path::exists` heuristic scan. Made `pending_identity` the sole path for all USB device arrivals. The `handle_volume_event` path — which receives the kernel-assigned drive letter from the `GUID_DEVINTERFACE_VOLUME` notification — is already implemented and correctly correlates drive letters; the heuristic scan was a dangerous bypass of that path.

---

### WR-03: `with_policy` Stores Empty `policy_id` — Produces Misleading Audit Records

**Files modified:** `dlp-agent/src/interception/mod.rs`
**Commit:** `c377677`
**Applied fix:** Replaced both `with_policy(String::new(), "...")` call chains for USB and disk enforcement audit events with direct field assignment: `audit_event.policy_name = Some("...")` leaving `policy_id` as `None`. SIEM rules testing `policy_id IS NOT NULL` will no longer classify these enforcement events as matched-policy events.

---

### WR-04: `acquire_instance_mutex` Does Not Actually Prevent a Second Instance

**Files modified:** `dlp-agent/src/service.rs`
**Commit:** `22f238e`
**Applied fix:** Replaced the local `std::sync::Mutex` (which was created and dropped in the same stack frame, providing no cross-process protection) with a Windows named mutex via `CreateMutexW("Global\DlpAgentSingleInstance")`. On `ERROR_ALREADY_EXISTS` (183) the process calls `std::process::exit(1)`. The returned `HANDLE` is stored in `_instance_mutex` at the call site so it remains live for the service lifetime. Added a `#[cfg(not(windows))]` no-op stub for non-Windows targets.

---

### WR-05: `send_webhook` Silently Ignores Non-2xx HTTP Responses

**Files modified:** `dlp-server/src/alert_router.rs`
**Commit:** `6c7516a`
**Applied fix:** Added `.error_for_status()?` after `.send().await?`. This converts non-2xx responses into `reqwest::Error` which maps to `AlertError::Webhook` via the existing `#[from]` derive. Updated the docstring to remove the incorrect "Non-2xx treated as silent successes" claim.

---

### WR-06: `DiskEnforcer::check` Calls `should_notify` for the Fail-Closed Path When Drive Letter Is `'?'`

**Files modified:** `dlp-agent/src/disk_enforcer.rs`
**Commit:** `1827a51`
**Applied fix:** Both fail-closed early-return paths (enumerator absent and enumeration incomplete) now use `drive_letter_from_path(path)` directly (returning `Option<char>`). When the result is `None` (UNC, empty, malformed path), `notify` is set to `false` and `should_notify` is not called, so the `'?'` sentinel is never inserted into the per-letter cooldown map. When a valid letter is resolved, `should_notify` is called normally.

---

_Fixed: 2026-05-04T00:00:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
