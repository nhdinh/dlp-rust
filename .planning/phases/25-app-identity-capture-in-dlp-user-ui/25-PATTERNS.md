# Phase 25: App Identity Capture in dlp-user-ui - Pattern Map

**Mapped:** 2026-04-22
**Files analyzed:** 5 (2 new, 3 modified)
**Analogs found:** 5 / 5

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `dlp-user-ui/src/detection/mod.rs` | module-declaration | — | `dlp-agent/src/detection/mod.rs` | exact |
| `dlp-user-ui/src/detection/app_identity.rs` | service (Win32 resolver + cache) | request-response | `dlp-agent/src/detection/usb.rs` (OnceLock statics, Win32 unsafe callbacks, `#[cfg(windows)]`) | role-match |
| `dlp-user-ui/src/clipboard_monitor.rs` | service (message loop) | event-driven | itself (existing Win32 PeekMessageW loop) | exact (modify-in-place) |
| `dlp-user-ui/src/ipc/pipe3.rs` | IPC client | request-response | itself (existing `send_clipboard_alert`) | exact (signature extension) |
| `dlp-user-ui/Cargo.toml` | config | — | itself (existing `windows` features list lines 32-53) | exact (additive) |

---

## Pattern Assignments

### `dlp-user-ui/src/detection/mod.rs` (new module declaration)

**Analog:** `dlp-agent/src/detection/mod.rs` (lines 1-12)

**Pattern to replicate exactly** — module-level doc comment naming the sub-module, then one `pub mod` declaration:

```rust
//! App identity resolution for the DLP UI process.
//!
//! - [`app_identity`] — Win32 process identity capture and Authenticode verification.

pub mod app_identity;
```

Note: `dlp-agent/src/detection/mod.rs` also re-exports public types with `pub use`. Do the same if `AppIdentityResolver` or other public types are added. For Phase 25 the public API surface is only free functions (`resolve_app_identity`, `verify_and_cache`), so re-exports are optional.

---

### `dlp-user-ui/src/detection/app_identity.rs` (new Win32 resolver + cache)

**Analog:** `dlp-agent/src/detection/usb.rs`

#### Imports pattern (usb.rs lines 31-55 — gate all Win32 imports under `#[cfg(windows)]`)

```rust
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use dlp_common::{AppIdentity, AppTrustTier, SignatureState};
use tracing::{debug, warn};

#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HWND};
#[cfg(windows)]
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;
#[cfg(windows)]
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_UI_NONE, WTD_STATEACTION_VERIFY, WTD_STATEACTION_CLOSE,
    WTD_REVOCATION_CHECK_NONE,
};
```

**Key rule (from usb.rs):** Every Win32 use-statement is `#[cfg(windows)]`. Platform-agnostic items (cache type, `AppIdentity` construction logic) are NOT gated, so tests compile on all platforms.

#### OnceLock static pattern (usb.rs lines 233-251 — the real OnceLock usage in this codebase)

```rust
// usb.rs:233-235 — the exact OnceLock pattern used in this codebase:
static REGISTRY_CACHE: std::sync::OnceLock<
    std::sync::Arc<crate::device_registry::DeviceRegistryCache>,
> = std::sync::OnceLock::new();
```

For app_identity.rs, mirror this verbatim with the Authenticode cache type:

```rust
// Process-wide Authenticode result cache.
// Key: absolute image path (String). Value: (publisher_cn: String, SignatureState).
// Populated once per unique path per process lifetime (D-06 — no TTL).
//
// Rust note: OnceLock<T> lazily initialises a static on first access (stable since 1.70).
// Using std::sync::Mutex (not parking_lot) — no contention on the single-threaded
// clipboard monitor; std::sync is simpler and avoids import confusion.
static AUTHENTICODE_CACHE: OnceLock<Mutex<HashMap<String, (String, SignatureState)>>> =
    OnceLock::new();

fn authenticode_cache() -> &'static Mutex<HashMap<String, (String, SignatureState)>> {
    AUTHENTICODE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}
```

**Note:** `usb.rs` uses `std::sync::OnceLock` with the full path. `app_identity.rs` should `use std::sync::{Mutex, OnceLock}` at the top per the codebase's import-organisation convention (stdlib first).

#### `#[cfg(windows)]` on free functions with Win32 bodies (usb.rs lines 295-372, 633-761)

```rust
// usb.rs:295 — pattern: cfg-gate entire function when its body contains Win32 calls
#[cfg(windows)]
unsafe extern "system" fn usb_wndproc(...) -> LRESULT { ... }

#[cfg(windows)]
pub fn register_usb_notifications(detector: &'static UsbDetector) -> windows::core::Result<(HWND, ...)> { ... }
```

Apply the same to app_identity.rs: `hwnd_to_image_path`, `run_wintrust`, `extract_publisher` are all `#[cfg(windows)]`. `resolve_app_identity`, `verify_and_cache`, and `build_app_identity_from_path` can be ungated if their signatures use only `dlp-common` types — but they must guard the Win32 call sites internally with `#[cfg(windows)]` branches.

#### Error handling pattern (usb.rs lines 520-527 — early return `String::new()` on Win32 failure)

```rust
// usb.rs:520-527 — Win32 call fails: return empty/default, never panic
let hdev = match hdev {
    Ok(h) => h,
    Err(_) => return String::new(),
};
```

Mirror this in `hwnd_to_image_path`: Win32 failures return `None`, never `unwrap`. Match the usb.rs convention of not logging at the call site (log at the caller with `warn!` if the None causes a fallback).

#### Process-path resolution pattern (RESEARCH.md Pattern 3 — mirrors usb.rs's read_dbcc_name approach for Win32 string buffers)

```rust
// Pattern from usb.rs:391-397 — null-terminated UTF-16 buffer read:
let mut buf = [0u16; 1024];
let mut size = buf.len() as u32;
let result = unsafe {
    QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, windows::core::PWSTR(buf.as_mut_ptr()), &mut size)
};
unsafe { let _ = CloseHandle(handle); };
result.ok()?;
// size is updated to the number of characters written (excluding NUL).
Some(String::from_utf16_lossy(&buf[..size as usize]))
```

The `from_utf16_lossy(&buf[..size as usize])` idiom is the same pattern usb.rs uses for `read_dbcc_name`.

#### `unsafe extern "system"` callback signature (clipboard_monitor.rs lines 231-238 — the exact callback form already in dlp-user-ui)

```rust
// clipboard_monitor.rs:231-238 — existing unsafe extern "system" fn in this crate:
unsafe extern "system" fn wndproc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    windows::Win32::UI::WindowsAndMessaging::DefWindowProcW(hwnd, msg, wparam, lparam)
}
```

The `foreground_event_proc` callback in app_identity.rs follows the same `unsafe extern "system"` ABI and the same convention of accessing statics directly (no captured environment, since `extern "system"` callbacks cannot capture).

#### Test pattern (usb.rs lines 840-1054 — inline `#[cfg(test)]` module with Arrange-Act-Assert)

```rust
// usb.rs:840-843 — test module structure:
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authenticode_cache_hit() {
        // Arrange: pre-seed cache with known entry
        // Act: call verify_and_cache twice for same path
        // Assert: second call returns cached result (WinVerifyTrust not called again)
    }
}
```

Tests that exercise cache behaviour (D-05: unbounded) and D-02 (intra-app copy) do not require live Win32 calls — seed the cache directly and test the pure logic. Tests for `hwnd_to_image_path` that need a real process use `std::process::id()` + `GetCurrentProcess()`.

---

### `dlp-user-ui/src/clipboard_monitor.rs` (modify: add SetWinEventHook + FOREGROUND_SLOT + GetClipboardOwner)

**Analog:** itself (lines 1-238) — modify-in-place with three targeted insertions.

#### Insertion point 1: FOREGROUND_SLOT static (after existing imports, before `const PREVIEW_MAX`)

**Pattern from:** `dlp-agent/src/detection/usb.rs:225-235` — process-wide static with `parking_lot::Mutex<Option<&'static T>>`. For the foreground slot, use `AtomicUsize` (simpler, no lock needed — same thread reads and writes).

```rust
// After line 14 (existing AtomicBool import) — add:
use std::sync::atomic::{AtomicUsize, Ordering};

// After line 20 (const PREVIEW_MAX) — add the slot static:
// Process-wide foreground HWND slot. Updated by the WinEvent hook callback
// on every EVENT_SYSTEM_FOREGROUND. Read-and-cleared in the WM_CLIPBOARDUPDATE branch.
// 0 = no previous foreground window captured.
// HWND is *mut c_void (pointer-sized), which fits safely in usize on 64-bit Windows.
static FOREGROUND_SLOT: AtomicUsize = AtomicUsize::new(0);
```

#### Insertion point 2: SetWinEventHook registration in `run_monitor` (after line 100 — after `AddClipboardFormatListener` succeeds)

**Pattern from:** usb.rs lines 654-760 — register hook after window creation succeeds, store handle for teardown, unhook before function returns.

```rust
// After line 100 (debug!("clipboard format listener registered")):
use windows::Win32::UI::Accessibility::{
    SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK,
    WINEVENT_OUTOFCONTEXT, WINEVENT_SKIPOWNPROCESS, EVENT_SYSTEM_FOREGROUND,
};

// Register out-of-context WinEvent hook for foreground-window tracking (D-01).
// CRITICAL: must be registered on the same thread that owns the message loop
// (this thread). WINEVENT_OUTOFCONTEXT means no DLL injection — callback runs
// in this thread's message queue. WINEVENT_SKIPOWNPROCESS prevents the DLP UI
// itself from being recorded as the destination (Pitfall 6).
let winevent_hook: HWINEVENTHOOK = unsafe {
    SetWinEventHook(
        EVENT_SYSTEM_FOREGROUND,
        EVENT_SYSTEM_FOREGROUND,
        None,                         // hmodWinEventProc = None for OUTOFCONTEXT
        Some(foreground_event_proc),
        0,                            // all processes
        0,                            // all threads
        WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
    )
};
```

And after the `loop { ... }` block ends (after existing line 137 `RemoveClipboardFormatListener`):

```rust
// Teardown — must happen on the same thread as SetWinEventHook (this thread).
// Mirrors the RemoveClipboardFormatListener call directly above.
let _ = unsafe { UnhookWinEvent(winevent_hook) };
```

#### Insertion point 3: WM_CLIPBOARDUPDATE branch (replace line 125)

**Exact lines to replace** (`clipboard_monitor.rs:124-126`):

```rust
// BEFORE (lines 124-126):
if msg.message == WM_CLIPBOARDUPDATE {
    handle_clipboard_change(session_id, &mut last_hash);
}

// AFTER — add GetClipboardOwner capture before handle_clipboard_change:
if msg.message == WM_CLIPBOARDUPDATE {
    // Capture source identity NOW — source process may exit within milliseconds.
    // GetClipboardOwner returns NULL when clipboard was written without an owner
    // (legitimate: some automation tools clear ownership). NULL -> None (D-08).
    let source_hwnd: Option<windows::Win32::Foundation::HWND> = unsafe {
        let h = windows::Win32::System::DataExchange::GetClipboardOwner();
        if h.is_invalid() { None } else { Some(h) }
    };

    // Read and clear the foreground slot atomically (swap-to-zero).
    // Use swap, not load, so the slot cannot persist across multiple clipboard events.
    let dest_raw = FOREGROUND_SLOT.swap(0, Ordering::Relaxed);
    let dest_hwnd: Option<windows::Win32::Foundation::HWND> = if dest_raw != 0 {
        Some(windows::Win32::Foundation::HWND(dest_raw as *mut _))
    } else {
        None
    };

    handle_clipboard_change(session_id, &mut last_hash, source_hwnd, dest_hwnd);
}
```

#### New function: `foreground_event_proc` (add after existing `wndproc` at line 231)

**Pattern from:** `clipboard_monitor.rs:231-238` (existing `unsafe extern "system"` callback form):

```rust
/// WinEvent callback for `EVENT_SYSTEM_FOREGROUND`.
///
/// Runs on the clipboard-monitor thread's message dispatch (WINEVENT_OUTOFCONTEXT).
/// Stores the newly-foreground window in `FOREGROUND_SLOT` so the next
/// `WM_CLIPBOARDUPDATE` can read it as the destination application (D-01).
///
/// # Safety
///
/// This is an `extern "system"` callback registered with `SetWinEventHook`.
/// The OS guarantees the arguments are valid for the duration of the call.
#[cfg(windows)]
unsafe extern "system" fn foreground_event_proc(
    _hook: windows::Win32::UI::Accessibility::HWINEVENTHOOK,
    _event: u32,
    hwnd: windows::Win32::Foundation::HWND,
    _id_object: i32,
    _id_child: i32,
    _event_thread: u32,
    _event_time: u32,
) {
    // HWND is *mut c_void — cast to usize for atomic storage.
    // .0 accesses the raw pointer field (standard windows-rs pattern).
    FOREGROUND_SLOT.store(hwnd.0 as usize, Ordering::Relaxed);
}
```

#### `handle_clipboard_change` signature change (line 146)

**Existing signature** (line 146):

```rust
fn handle_clipboard_change(session_id: u32, last_hash: &mut u64) {
```

**New signature** — add two HWND parameters, resolve identities before calling `classify_and_alert`:

```rust
fn handle_clipboard_change(
    session_id: u32,
    last_hash: &mut u64,
    source_hwnd: Option<windows::Win32::Foundation::HWND>,
    dest_hwnd: Option<windows::Win32::Foundation::HWND>,
) {
```

Inside, resolve identities via `crate::detection::app_identity::resolve_app_identity` and pass them to `classify_and_alert`. Pattern for the resolve call mirrors the cache lookup pattern from usb.rs.

#### `classify_and_alert` signature change (line 194)

**Existing signature** (line 194):

```rust
pub fn classify_and_alert(session_id: u32, text: &str) -> Option<&'static str> {
```

**New signature** (RESEARCH.md verified):

```rust
pub fn classify_and_alert(
    session_id: u32,
    text: &str,
    source_identity: Option<dlp_common::AppIdentity>,
    dest_identity: Option<dlp_common::AppIdentity>,
) -> Option<&'static str> {
```

Pass `source_identity` and `dest_identity` through to `crate::ipc::pipe3::send_clipboard_alert` (replacing the two `None` literals).

---

### `dlp-user-ui/src/ipc/pipe3.rs` (modify: extend `send_clipboard_alert` signature)

**Analog:** itself (lines 77-105).

**Existing signature** (lines 77-82):

```rust
pub fn send_clipboard_alert(
    session_id: u32,
    classification: &str,
    preview: &str,
    text_length: usize,
) -> Result<()> {
```

**New signature** — add two `Option<AppIdentity>` parameters:

```rust
pub fn send_clipboard_alert(
    session_id: u32,
    classification: &str,
    preview: &str,
    text_length: usize,
    source_application: Option<dlp_common::AppIdentity>,
    destination_application: Option<dlp_common::AppIdentity>,
) -> Result<()> {
```

**Lines 91-93** (the two `None` literals to replace):

```rust
// BEFORE:
source_application: None,
destination_application: None,

// AFTER — pass through parameters directly:
source_application,
destination_application,
```

**Import to add** at the top of pipe3.rs (after line 5):

```rust
use dlp_common::AppIdentity;
```

Note: `messages.rs` already imports `dlp_common::AppIdentity` (line 7) — the import in pipe3.rs is a separate file and needs its own use declaration.

---

### `dlp-user-ui/Cargo.toml` (modify: add two windows feature flags)

**Analog:** itself (lines 32-53 — existing `windows` features list).

**Lines to add** inside the existing `features = [...]` block (after line 52 `"Win32_UI_WindowsAndMessaging"`):

```toml
"Win32_Security_WinTrust",      # WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO
"Win32_UI_Accessibility",       # SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK, EVENT_SYSTEM_FOREGROUND
```

**Already present — no changes needed:**
- `Win32_Security_Cryptography` (line 38) — needed for `CertGetNameStringW` publisher extraction
- `Win32_System_Threading` (line 44) — `OpenProcess`, `QueryFullProcessImageNameW`
- `Win32_UI_WindowsAndMessaging` (line 52) — `GetClipboardOwner`, `GetWindowThreadProcessId`

---

## Shared Patterns

### `unsafe extern "system"` callbacks
**Source:** `dlp-user-ui/src/clipboard_monitor.rs` lines 231-238 (existing `wndproc`) and `dlp-agent/src/detection/usb.rs` lines 295-372 (`usb_wndproc`)
**Apply to:** `foreground_event_proc` in `app_identity.rs` (or `clipboard_monitor.rs` — planner's choice per discretion)

The pattern: `unsafe extern "system" fn name(args...) -> ReturnType { /* access process-wide statics only, no captured environment */ }`. Gate with `#[cfg(windows)]`.

### `#[cfg(windows)]` gating
**Source:** `dlp-agent/src/detection/usb.rs` — all Win32 `use` statements and all functions with Win32 call sites are individually gated.
**Apply to:** All new Win32-calling code in `app_identity.rs` and `clipboard_monitor.rs`. Non-Win32 logic (cache operations, `AppIdentity` struct construction, trust-tier mapping) is NOT gated, allowing non-Windows test compilation.

### OnceLock static accessor pattern
**Source:** `dlp-agent/src/detection/usb.rs` lines 233-235 (`REGISTRY_CACHE`) and 244-245 (`REGISTRY_RUNTIME_HANDLE`)
**Apply to:** `AUTHENTICODE_CACHE` static in `app_identity.rs`

Pattern:
```rust
static FOO: std::sync::OnceLock<T> = std::sync::OnceLock::new();
// accessor (optional helper):
fn foo() -> &'static T { FOO.get_or_init(|| ...) }
```

### tracing log levels
**Source:** `dlp-user-ui/src/clipboard_monitor.rs` lines 37-43 (`warn!`, `info!`, `debug!`) and `dlp-agent/src/detection/usb.rs` lines 104-106 (`info!`, `debug!`)
**Apply to:** All new functions in `app_identity.rs`

Convention: `debug!` for cache hits, `warn!` for Win32 resolution failures (not `error!` — identity resolution failure is expected for elevated processes), `info!` for first-time Authenticode verification of a new binary.

### `String::from_utf16_lossy` for Win32 wide-string buffers
**Source:** `dlp-agent/src/detection/usb.rs` lines 392-397 (`read_dbcc_name`) and `dlp-user-ui/src/clipboard_monitor.rs` line 61 (class name encoding)
**Apply to:** `hwnd_to_image_path` in `app_identity.rs` when converting `QueryFullProcessImageNameW` output.

---

## lib.rs Change (not listed in scope but required for compilation)

**File:** `dlp-user-ui/src/lib.rs` (lines 7-11 — the existing module list)

**Change:** Add `pub mod detection;` (or `mod detection;` if internal) after line 9 (`pub mod clipboard_monitor;`).

**Pattern:** Mirror `dlp-agent/src/lib.rs` which includes `detection` as a module. The planner must include this in the plan; it is a one-line change but a hard compile dependency.

---

## No Analog Found

None — all files have close codebase analogs.

---

## Metadata

**Analog search scope:** `dlp-user-ui/src/`, `dlp-agent/src/`, `dlp-common/src/`
**Files scanned:** 9 source files read in full; 1 Cargo.toml
**Pattern extraction date:** 2026-04-22
