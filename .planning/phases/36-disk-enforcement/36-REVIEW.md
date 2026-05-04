---
phase: 36-disk-enforcement
reviewed: 2026-05-04T00:00:00Z
depth: standard
files_reviewed: 10
files_reviewed_list:
  - dlp-agent/src/detection/device_watcher.rs
  - dlp-agent/src/detection/disk.rs
  - dlp-agent/src/detection/mod.rs
  - dlp-agent/src/detection/usb.rs
  - dlp-agent/src/disk_enforcer.rs
  - dlp-agent/src/interception/mod.rs
  - dlp-agent/src/lib.rs
  - dlp-agent/src/service.rs
  - dlp-common/src/audit.rs
  - dlp-server/src/alert_router.rs
findings:
  critical: 4
  warning: 6
  info: 4
  total: 14
status: issues_found
---

# Phase 36: Code Review Report

**Reviewed:** 2026-05-04T00:00:00Z
**Depth:** standard
**Files Reviewed:** 10
**Status:** issues_found

## Summary

Phase 36 implements fixed-disk allowlist enforcement: a `DiskEnforcer` that intercepts write-path file actions, a `DiskEnumerator` that maintains an in-memory registry of known fixed disks, and a refactored `device_watcher` that dispatches WM_DEVICECHANGE events for disks, USB volumes, and USB devices. The overall architecture is sound and the fail-closed semantics (D-06) are correctly implemented. However, several correctness and security issues require resolution before shipping.

The most serious issues are: (1) a classic TOCTOU race in `on_disk_arrival_inner` between the snapshot read and the write-lock insertion that can silently produce incorrect entries in the live `drive_letter_map`; (2) a HWND-lifetime use-after-free window in `unregister_device_watcher` where `DestroyWindow` is called after the message loop has already processed `WM_DESTROY` via `PostMessageW(WM_CLOSE)`; (3) the `SMTP password` field is stored and cloned as a plain `String` rather than a `secrecy`-protected type, violating the project security standard; and (4) the `disk_to_identity` map on `UsbDetector` is populated in tests but has no production write-path, meaning the fallback it was designed to provide is silently dead code.

---

## Critical Issues

### CR-01: TOCTOU Race Between Snapshot Read and Write-Lock Insert in `on_disk_arrival_inner`

**File:** `dlp-agent/src/detection/disk.rs:434-454`

**Issue:** `on_disk_arrival_inner` takes a snapshot of the existing `drive_letter_map` keys under a read lock, releases the lock, then acquires a write lock per disk to insert new entries. Between the snapshot and the per-disk write-lock acquisition, another thread (e.g., a concurrent call triggered by a rapid unplug-replug) can insert the same drive letter with a *different* `DiskIdentity`. The existence check (`existing_letters.contains(&letter)`) is then stale, and two entries for the same drive letter race to be written — the final winner is non-deterministic. This corrupts the `drive_letter_map` with an entry whose `DiskIdentity` may belong to the earlier disk, causing enforcement to pass or block based on the wrong disk's identity.

```rust
// Vulnerable pattern: snapshot is stale by the time the write lock fires
let existing_letters: HashSet<char> =
    enumerator.drive_letter_map.read().keys().copied().collect();

for disk in live_disks {
    let Some(letter) = disk.drive_letter else { continue; };
    if existing_letters.contains(&letter) {    // stale check
        continue;
    }
    {
        let mut map = enumerator.drive_letter_map.write();  // no re-check inside lock
        map.insert(letter, disk.clone());
    }
    // ...
}
```

**Fix:** Re-check inside the write lock using the entry API so the check-and-insert is atomic:

```rust
for disk in live_disks {
    let Some(letter) = disk.drive_letter else { continue; };
    let mut map = enumerator.drive_letter_map.write();
    // `entry().or_insert` is atomic under the write lock — no TOCTOU gap.
    if map.contains_key(&letter) {
        continue;
    }
    map.insert(letter, disk.clone());
    // Drop the write lock before the audit emission below.
    drop(map);
    // ... allowlist check and audit emission
}
```

---

### CR-02: Use-After-Destroy of HWND in `unregister_device_watcher`

**File:** `dlp-agent/src/detection/device_watcher.rs:463-493`

**Issue:** `unregister_device_watcher` posts `WM_CLOSE` to the message-only window, waits for the watcher thread to join (which means the thread's `GetMessageW` loop has exited), and then calls `DestroyWindow` on the same HWND. However, the watcher thread's `WM_DESTROY` handler calls `PostQuitMessage(0)`, which means the window is destroyed by the message loop itself (`WM_DESTROY` is dispatched via `DispatchMessageW` after `WM_CLOSE` triggers default processing that calls `DestroyWindow` internally). The explicit `DestroyWindow` call at line 489 is therefore called on a window that has already been destroyed, which is undefined behavior in Win32 and can cause a crash or handle recycling attack where a different window now owns that HWND value.

```rust
// WM_CLOSE -> DefWindowProcW -> DestroyWindow -> WM_DESTROY -> PostQuitMessage
// Thread exits. Then:
unsafe {
    let _ = DestroyWindow(hwnd);  // HWND is already destroyed!
}
```

**Fix:** Remove the second `DestroyWindow` call at the end of `unregister_device_watcher`. The window is destroyed by the Win32 message loop when it processes `WM_CLOSE` through `DefWindowProcW`. The subsequent `thread.join()` guarantees the destruction has completed before the function returns.

```rust
pub fn unregister_device_watcher(hwnd: HWND, thread: std::thread::JoinHandle<()>) {
    // Unregister device notifications
    if let Some((h_vol, h_usb, h_disk)) = NOTIFY_HANDLES.lock().take() {
        unsafe {
            let _ = UnregisterDeviceNotification(HDEVNOTIFY(h_vol as *mut _));
            let _ = UnregisterDeviceNotification(HDEVNOTIFY(h_usb as *mut _));
            let _ = UnregisterDeviceNotification(HDEVNOTIFY(h_disk as *mut _));
        }
    }

    unsafe {
        let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
    }

    if let Err(e) = thread.join() {
        warn!("device-watcher thread panicked: {:?}", e);
    }
    // Do NOT call DestroyWindow here — the window is already destroyed by
    // the message loop processing WM_CLOSE -> DefWindowProcW -> DestroyWindow.
    info!("device watcher unregistered");
}
```

---

### CR-03: SMTP Password Stored and Transmitted as Plain `String` — Violates Security Standard

**File:** `dlp-server/src/alert_router.rs:41` and `:63`

**Issue:** `SmtpConfig.password` is a plain `String`. It is loaded from the database into `AlertRouterConfigRow.smtp_password` (also `String`), cloned multiple times, and passed directly to `lettre::Credentials::new`. The project CLAUDE.md section 9.13 mandates: "Use `secrecy` crate for sensitive data types." A plain `String` is logged by the default `Debug` derive, will appear in crash dumps, and can be captured by memory inspection tools. Any `tracing::debug!` on `SmtpConfig` (which derives `Debug`) will print the password in plaintext to the log file.

```rust
// SmtpConfig derives Debug — password prints in plaintext:
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub password: String,   // plaintext in debug output
    ...
}

// AlertRouterConfigRow also derives Debug:
#[derive(Debug, Clone)]
struct AlertRouterConfigRow {
    smtp_password: String,  // plaintext in debug output
    ...
}
```

**Fix:** Wrap the password field in `secrecy::SecretString` in both structs. Replace `Debug` derive on `SmtpConfig` with a manual implementation that redacts the password field. Update the `Credentials::new` call to expose the secret via `expose_secret()`.

```rust
use secrecy::{ExposeSecret, SecretString};

pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: SecretString,  // protected
    pub from: String,
    pub to: Vec<String>,
}

// In send_email:
let creds = Credentials::new(
    config.username.clone(),
    config.password.expose_secret().to_string(),
);
```

---

### CR-04: Dead `disk_to_identity` Write-Path — Fallback Is Silently Never Populated

**File:** `dlp-agent/src/detection/usb.rs:76-77`

**Issue:** `UsbDetector` exposes a `disk_to_identity: RwLock<HashMap<String, DeviceIdentity>>` field documented as "Map from disk device instance ID to USB identity for removal lookup when the PnP tree walk fails." However, no production code path ever writes to this map. The old write site (which populated it during USB disk arrival) was removed in a prior refactor but the read/fallback path that was supposed to consult it during removal was never wired to `on_usb_device_removal`. Only tests insert into `disk_to_identity`. When the PnP tree walk fails at removal time and `device_identities` has no matching entry, the fallback silently fails to find the identity — meaning no `restore_volume_acl` or `enable_usb_device` call is made for that device. This is a functional correctness failure: disconnected ReadOnly-tier or Blocked-tier devices are not restored when removed.

**Fix:** Either wire the `disk_to_identity` map into `on_usb_device_arrival` (populate it) and `on_usb_device_removal` (consult it as a fallback), or delete the dead field and its documentation entirely if the fallback path is out of scope. Do not leave a documented fallback that silently does nothing.

```rust
// In on_usb_device_removal, add fallback after the device_identities lookup:
if letter_opt.is_none() {
    // Fallback: consult disk_to_identity for removal context when PnP tree
    // has already expelled the device from device_identities.
    if let Some(identity) = detector.disk_to_identity.read().get(device_path).cloned() {
        // apply restore_volume_acl / enable_usb_device as needed
    }
}
```

---

## Warnings

### WR-01: `spawn_disk_enumeration_task` Holds Multiple `DiskEnumerator` Write Locks Simultaneously — Potential Deadlock Risk

**File:** `dlp-agent/src/detection/disk.rs:247-263`

**Issue:** Inside the async task, the code acquires four write locks on the same `DiskEnumerator` simultaneously and holds all four for the entire update block:

```rust
let mut discovered = enumerator.discovered_disks.write();
let mut drive_map = enumerator.drive_letter_map.write();
let mut instance_map = enumerator.instance_id_map.write();
let mut complete = enumerator.enumeration_complete.write();
```

`parking_lot::RwLock` does not reenter, so acquiring a second `write()` on the same lock from the same thread while holding the first would deadlock. This is safe today because these are four distinct `RwLock` instances. However, the pattern is fragile: if a future refactor consolidates the state (e.g., wraps everything in one `RwLock<DiskState>`), or if any code between the lock acquisitions tries to re-acquire an already-held lock transitively, this silently deadlocks. The comment "All DiskEnumerator write locks MUST be released before the AgentConfig write lock is acquired" documents lock-order discipline for DiskEnumerator vs. AgentConfig, but not within DiskEnumerator itself.

**Fix:** Acquire each lock, mutate, and release individually (using scoped blocks) to minimize lock hold times and make ordering explicit:

```rust
{
    *enumerator.discovered_disks.write() = updated_list.clone();
}
{
    let mut drive_map = enumerator.drive_letter_map.write();
    drive_map.clear();
    for disk in &updated_list {
        if let Some(letter) = disk.drive_letter {
            drive_map.insert(letter, disk.clone());
        }
    }
}
{
    let mut instance_map = enumerator.instance_id_map.write();
    instance_map.clear();
    for disk in &updated_list {
        instance_map.insert(disk.instance_id.clone(), disk.clone());
    }
}
*enumerator.enumeration_complete.write() = true;
```

---

### WR-02: `on_usb_device_arrival` Drive-Letter Assignment Is Racy and Wrong

**File:** `dlp-agent/src/detection/usb.rs:473-507`

**Issue:** `on_usb_device_arrival` heuristically assigns a drive letter by scanning A..=Z for a path that exists on disk and is not already in `device_identities`. This is fundamentally incorrect: it assigns the first drive letter whose root path exists regardless of whether that drive is the newly arrived USB device. On a system with multiple external drives, or with a pre-existing fixed disk on the same letter, this scan can mis-assign the identity of USB device X to the letter belonging to pre-existing drive Y. The assigned letter is then used for `apply_tier_enforcement(letter, &identity)`, which may silently set the wrong volume read-only or disable an already-present device.

Additionally, calling `std::path::Path::new(...).exists()` in a Win32 message callback thread (which must remain fast and non-blocking) can trigger a file-system hit that stalls the message loop.

**Fix:** Correlate the USB device identity to the correct drive letter via the PnP parent/child relationship (SetupDiGetDeviceProperty on the disk's parent composite device) rather than scanning drive roots. If the platform API is unavailable, park the identity in `pending_identity` and resolve it when the corresponding `GUID_DEVINTERFACE_VOLUME` arrives (this path already exists but is only taken when no drive letter is found — the heuristic scan should be removed, making the pending-identity path the primary path).

---

### WR-03: `with_policy` on Disk Block Audit Events Stores Empty `policy_id` — Produces Misleading Audit Records

**File:** `dlp-agent/src/interception/mod.rs:189-191`

**Issue:** When `DiskEnforcer` blocks a write, the audit event is built with:

```rust
.with_policy(
    String::new(),
    "Disk enforcement: unregistered fixed disk".to_string(),
)
```

`with_policy` unconditionally sets `policy_id = Some(String::new())`. The `AuditEvent` struct stores it as `Option<String>` with `skip_serializing_if = "Option::is_none"`. An empty-string `Some("")` is not `None`, so the JSON will contain `"policy_id":""` — an empty string that SIEM rules looking for `policy_id IS NOT NULL` will incorrectly classify as having a matched policy. The same pattern appears for USB enforcement at line 109-112.

**Fix:** Pass `None` directly rather than routing through `with_policy` when there is no applicable policy ID:

```rust
// Instead of .with_policy(String::new(), "...")
// set fields directly or add a named constructor:
audit_event.policy_id = None;
audit_event.policy_name = Some("Disk enforcement: unregistered fixed disk".to_string());
```

Or modify `with_policy` to accept `Option<String>` for the policy_id parameter and skip setting it when `None`.

---

### WR-04: `acquire_instance_mutex` Does Not Actually Prevent a Second Instance

**File:** `dlp-agent/src/service.rs:1005-1018`

**Issue:** `acquire_instance_mutex` creates a `std::sync::Mutex::new(())` locally on the stack and immediately calls `try_lock()` on it. Because the mutex is local, it is dropped at the end of the function and releases the lock immediately — no other process or thread can see it, and the lock provides zero cross-instance protection. This is a no-op function. An attacker or misconfiguration can start multiple DLP agent instances simultaneously.

```rust
fn acquire_instance_mutex() {
    match std::sync::Mutex::new(()).try_lock() {  // local mutex, dropped instantly
        Ok(_guard) => info!("single-instance mutex acquired"),
        Err(_) => info!("previous instance detected — SCM serialises starts"),
    }
}
```

The `Err` branch is also unreachable: `try_lock` on a freshly-created mutex always succeeds.

**Fix:** Use a Windows named mutex (via `CreateMutexW` with a well-known name) or a file-based lock in a well-known path. The `single-instance-mutex` crate provides a cross-platform implementation.

```rust
fn acquire_instance_mutex() -> windows::core::Result<windows::Win32::Foundation::HANDLE> {
    let name: Vec<u16> = "Global\\DlpAgentSingleInstance\0"
        .encode_utf16()
        .collect();
    // SAFETY: name is null-terminated, valid for duration of service
    let handle = unsafe {
        windows::Win32::System::Threading::CreateMutexW(
            None,
            true,
            windows::core::PCWSTR(name.as_ptr()),
        )?
    };
    // ERROR_ALREADY_EXISTS (183) means another instance holds the mutex
    if windows::Win32::Foundation::GetLastError() ==
       windows::Win32::Foundation::WIN32_ERROR(183) {
        error!("another DLP agent instance is already running — aborting");
        std::process::exit(1);
    }
    Ok(handle)
}
```

---

### WR-05: `send_webhook` Silently Ignores Non-2xx HTTP Responses

**File:** `dlp-server/src/alert_router.rs:391-406`

**Issue:** `send_webhook` calls `.send().await?` and discards the `Response`. Non-2xx responses (e.g., 404 Not Found, 500 Internal Server Error, 403 Forbidden from a webhook endpoint) are treated as success. The function docstring acknowledges this: "Non-2xx responses are treated as silent successes at this layer." A webhook endpoint that is misconfigured or down will return a non-2xx status, and the alert delivery will silently fail with no log entry at `warn` level. For a security audit trail system, silent alert delivery failures are a security gap.

**Fix:** Check the response status and propagate non-2xx as an error:

```rust
async fn send_webhook(&self, config: &WebhookConfig, event: &AuditEvent) -> Result<(), AlertError> {
    let response = self
        .client
        .post(&config.url)
        .header("Content-Type", "application/json")
        .json(event)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        return Err(AlertError::Webhook(
            reqwest::Error::from(/* construct from status */
                response.error_for_status().unwrap_err()
            )
        ));
    }

    tracing::info!("sent webhook alert");
    Ok(())
}
```

Or use `response.error_for_status()?` directly:

```rust
let _ = self.client.post(&config.url)
    .header("Content-Type", "application/json")
    .json(event)
    .send()
    .await?
    .error_for_status()?;
```

---

### WR-06: `DiskEnforcer::check` Calls `should_notify` for the Fail-Closed Path When Drive Letter Is `'?'`

**File:** `dlp-agent/src/disk_enforcer.rs:143-153`

**Issue:** When `get_disk_enumerator()` returns `None` (startup window, enumerator not yet installed), `drive_letter_from_path(path)` is called and may return `None` for UNC or malformed paths. The fallback `unwrap_or('?')` assigns the sentinel letter `'?'`. This sentinel is then passed to `should_notify('?')`, which inserts `'?'` into the `last_toast` cooldown map and arms a 30-second cooldown keyed to `'?'`. All subsequent fail-closed blocks during the enumerator-absent window for *any* path that fails drive extraction (UNC, empty, malformed) will share this single cooldown slot, suppressing toast notifications after the first. The user is not notified of repeated blocks against different paths.

```rust
let letter = drive_letter_from_path(path).unwrap_or('?');
// ...
notify: self.should_notify(letter),  // '?' shared across all unresolved paths
```

**Fix:** When the drive letter cannot be resolved, generate the block result with `notify: false` (the user cannot act on a path-less notification) and do not insert into the cooldown map, OR use the full path as the cooldown key.

---

## Info

### IN-01: TODO Comment Left in Production Code — `send_email` SMTP Transport Caching

**File:** `dlp-server/src/alert_router.rs:325`

**Issue:** A `// TODO(followup): cache SMTP transport keyed by config hash.` comment violates project rule 9.14 ("NEVER commit commented-out code; delete it") and CLAUDE.md section 9.14 which prohibits TODO comments in committed code. Additionally a lengthy block comment starting at line 319 duplicates a pre-existing review finding.

**Fix:** Remove the TODO comment. File a `bd` issue for the SMTP transport caching work if it needs tracking.

---

### IN-02: `with_policy` Builder Method Always Sets `policy_id` to `Some(...)` Even for Empty Strings

**File:** `dlp-common/src/audit.rs:254-258`

**Issue:** The `with_policy` builder sets `self.policy_id = Some(policy_id)` unconditionally. When called with `String::new()` (as done in the disk and USB enforcement paths), this stores `Some("")`, which serializes as `"policy_id":""`. Downstream SIEM/audit consumers that test `policy_id IS NOT NULL` or `policy_id != ""` will need to handle both representations. This is an API design issue that creates implicit contract ambiguity.

**Fix:** Change `with_policy` to skip setting `policy_id` when the string is empty:

```rust
pub fn with_policy(mut self, policy_id: String, policy_name: String) -> Self {
    self.policy_id = if policy_id.is_empty() { None } else { Some(policy_id) };
    self.policy_name = if policy_name.is_empty() { None } else { Some(policy_name) };
    self
}
```

---

### IN-03: `DiskEnumerator` Has Unnecessary `unsafe impl Send` and `unsafe impl Sync`

**File:** `dlp-agent/src/detection/disk.rs:108-109`

**Issue:** The manual `unsafe impl Send for DiskEnumerator` and `unsafe impl Sync for DiskEnumerator` are unnecessary. `DiskEnumerator` contains only `RwLock<T>` fields where all `T` types (`Vec<DiskIdentity>`, `HashMap<char, DiskIdentity>`, etc.) are themselves `Send + Sync`. `parking_lot::RwLock<T>` is already `Send + Sync` when `T: Send + Sync`, so the compiler would derive these bounds automatically. The manual `unsafe impl` bypasses the compiler's safety check without adding any correctness guarantee, which violates the project rule 9.10: "NEVER use `unsafe` unless absolutely necessary."

**Fix:** Remove the `unsafe impl Send for DiskEnumerator` and `unsafe impl Sync for DiskEnumerator` blocks and let the compiler derive them automatically. Add `#[derive(Debug)]` if it doesn't prevent auto-derivation.

---

### IN-04: `extract_disk_instance_id` Docstring Example Does Not Match Implementation Output

**File:** `dlp-agent/src/detection/device_watcher.rs:156-165`

**Issue:** The docstring example shows:

```
Input:  \\?\USBSTOR#Disk#1234#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
Output: USBSTOR\Disk\1234
```

The test at line 502 uses `#Disk&Ven_Kingston#1234#` (with `Disk&Ven_Kingston` as one segment), but the docstring uses `#Disk#1234#` (with `Disk` as one segment and `1234` as another). Both are plausible real Windows device paths. The ambiguity is minor but docstring examples should match test inputs exactly to serve as reliable reference material. The current mismatch could mislead callers about the expected segment format.

**Fix:** Update the docstring example to exactly match the primary test case at line 502:

```rust
/// # Examples
///
/// ```
/// use dlp_agent::detection::device_watcher::extract_disk_instance_id;
/// let input = r"\\?\USBSTOR#Disk&Ven_Kingston#1234#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
/// let id = extract_disk_instance_id(input);
/// assert_eq!(id, r"USBSTOR\Disk&Ven_Kingston\1234");
/// ```
```

---

_Reviewed: 2026-05-04T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
