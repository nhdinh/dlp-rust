# Phase 25: App Identity Capture in dlp-user-ui — Research

**Researched:** 2026-04-22
**Domain:** Win32 process identity, Authenticode verification, WinEvent hooks, Tokio async bridge
**Confidence:** HIGH (codebase-verified + official MSDN docs); MEDIUM (publisher extraction pipeline)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Destination identity via `SetWinEventHook(EVENT_SYSTEM_FOREGROUND)` — single previous-foreground HWND slot, updated on every focus change, cleared after each `WM_CLIPBOARDUPDATE` is processed.
- **D-02:** Intra-app copy → destination = same `AppIdentity` as source (not `None`). Explicitly modeled.
- **D-03:** Source via `GetClipboardOwner` called synchronously inside `WM_CLIPBOARDUPDATE` handler before returning to message loop.
- **D-04:** Cache: `OnceLock<Mutex<HashMap<String, (String, SignatureState)>>>` — same pattern as `REGISTRY_CACHE` in Phase 24. Keyed by absolute image path.
- **D-05:** Unbounded `HashMap`, no eviction (≤200 unique paths per session in practice).
- **D-06:** No TTL — `WinVerifyTrust` runs once per unique path per process start.
- **D-07:** Trust tier derived purely from `SignatureState`: `Valid`→`Trusted`, `Invalid`/`NotSigned`→`Untrusted`, `Unknown`→`Unknown`.
- **D-08:** Resolution failures:
  - `GetClipboardOwner` returns NULL → `source_application = None`
  - Owner HWND found but path fails → `Some(AppIdentity { image_path: "", publisher: "", trust_tier: Unknown, signature_state: Unknown })`
  - Destination slot empty → `destination_application = None`
  - Dest HWND found but path fails → same `Some(AppIdentity)` with all-Unknown fields

### Claude's Discretion

- Exact `SetWinEventHook` registration and teardown lifecycle (thread vs process scope)
- `spawn_blocking` task structure for the WinVerifyTrust → cache-lookup → AppIdentity construction pipeline
- Whether the foreground slot is an `AtomicUsize` (HWND as usize) or `Mutex<Option<HWND>>`

### Deferred Ideas (OUT OF SCOPE)

- Publisher allowlist (admin-managed trusted publishers list) — Phase 28
- Right-click paste detection (WH_KEYBOARD_LL for Ctrl+V)
- TTL-based Authenticode cache invalidation for revoked certificates
- APP-07: UWP app identity via AUMID
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| APP-01 | Destination process image path and publisher captured at paste time via `GetForegroundWindow` → `GetWindowThreadProcessId` → `QueryFullProcessImageNameW` in `dlp-user-ui` | D-01: SetWinEventHook previous-foreground slot pattern; Win32_System_Threading already in Cargo.toml |
| APP-02 | Source process identity captured at clipboard-change time via `GetClipboardOwner` called synchronously inside `WM_CLIPBOARDUPDATE` handler | D-03: current clipboard_monitor.rs:124 is the injection point; synchronous before sleep branch |
| APP-05 | Audit events include `source_application` and `destination_application` fields on clipboard block | Fields already in `Pipe3UiMsg::ClipboardAlert` (messages.rs:101-104); populating them satisfies APP-05 automatically |
| APP-06 | Authenticode via `WinVerifyTrust` with per-path cache, non-blocking | D-04: OnceLock cache; `Win32_Security_WinTrust` feature flag needed; spawn_blocking pipeline documented below |
</phase_requirements>

---

## Summary

Phase 25 populates `source_application` and `destination_application` in `ClipboardAlert` — both fields are already declared in `dlp-user-ui/src/ipc/messages.rs:101-104` as `Option<AppIdentity>` and are transmitted to the agent as `None` today. The phase introduces two new Win32 mechanisms: a `SetWinEventHook(EVENT_SYSTEM_FOREGROUND)` hook to track the previous-foreground window (destination), and a synchronous `GetClipboardOwner` call at `WM_CLIPBOARDUPDATE` time (source). Publisher verification via `WinVerifyTrust` is routed through `tokio::task::spawn_blocking` with a process-wide `OnceLock<Mutex<HashMap>>` cache to avoid blocking the message pump on CRL network calls.

The codebase structure makes this phase self-contained: all types (`AppIdentity`, `AppTrustTier`, `SignatureState`) are finalized in `dlp-common::endpoint`, all message structs are already wired (`Pipe3UiMsg::ClipboardAlert`), and the only files that need modification are `dlp-user-ui/src/clipboard_monitor.rs` (two integration points) and `dlp-user-ui/src/ipc/pipe3.rs` (the two `None` literals at line 92-93). One new source file — `dlp-user-ui/src/detection/app_identity.rs` — holds the Win32 resolution and verification logic.

The single highest-risk item is the thread-affinity requirement for `SetWinEventHook`: the hook callback is delivered on the same thread that called `SetWinEventHook`, and that thread must have a running message loop. The clipboard monitor thread satisfies both conditions (it creates a message-only HWND and runs its own `PeekMessageW` loop), making it the correct registration site. No additional thread is needed.

**Primary recommendation:** Register `SetWinEventHook` immediately after `AddClipboardFormatListener` in `run_monitor`. Store the previous-foreground HWND in an `AtomicUsize` (HWND as usize, `0` = no slot). Capture `GetClipboardOwner` synchronously in the `WM_CLIPBOARDUPDATE` branch before calling `handle_clipboard_change`. Pass source HWND and foreground HWND into `classify_and_alert` as parameters; the function spawns a blocking task for verification and passes `AppIdentity` into `send_clipboard_alert`.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Source identity capture (GetClipboardOwner) | UI Process (user session) | — | Must run in user session; session-0 agent cannot access user clipboard |
| Destination identity capture (SetWinEventHook) | UI Process (user session) | — | GetForegroundWindow and WinEvents are per-session; session-0 sees no foreground |
| Authenticode verification (WinVerifyTrust) | UI Process (user session) | — | File path must be verifiable from user-session context |
| AppIdentity transport to agent | IPC (Pipe 3) | — | Already established; ClipboardAlert already has the fields |
| Audit event population | Agent (dlp-agent) | — | Agent reconstructs AuditEvent from ClipboardAlert fields |

---

## Standard Stack

### Core (all already in dlp-user-ui/Cargo.toml — no new crates needed)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `windows` crate | 0.58 (current) | All Win32 API bindings | Already used throughout |
| `tokio` | workspace | Async runtime + `spawn_blocking` | Already the async runtime |
| `parking_lot` | workspace | `Mutex` for Authenticode cache | Already used; faster than `std::sync::Mutex` |
| `dlp-common` | path | `AppIdentity`, `AppTrustTier`, `SignatureState` types | Already a dependency; types finalized in Phase 22 |

### New Windows Feature Flags Required

```toml
# dlp-user-ui/Cargo.toml — add to the `windows` features list:
"Win32_Security_WinTrust",      # WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO
"Win32_UI_Accessibility",       # SetWinEventHook, UnhookWinEvent, WINEVENTPROC, EVENT_SYSTEM_FOREGROUND
"Win32_System_Threading",       # Already present — OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION
"Win32_UI_WindowsAndMessaging", # Already present — GetClipboardOwner, GetWindowThreadProcessId
```

**Already present (no action):** `Win32_Security_Cryptography` is already listed — needed for `CertGetNameStringW` (publisher extraction).

**Not needed for Phase 25:** `Win32_UI_Shell_PropertiesSystem` (UWP AUMID) is deferred.

[VERIFIED: dlp-user-ui/Cargo.toml — existing features list; Win32_Security_WinTrust and Win32_UI_Accessibility are the only additions needed]

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `Win32_UI_Accessibility` + `SetWinEventHook` | `WH_CBT` + `SetWindowsHookEx` | CBT hooks require a DLL for cross-process injection; SetWinEventHook with WINEVENT_OUTOFCONTEXT runs in-process with no DLL |
| `AtomicUsize` for foreground slot | `Mutex<Option<HWND>>` | Both work since hook and message handlers run on the same thread — no actual contention. AtomicUsize is simpler and avoids lock overhead. |
| `OnceLock<Mutex<HashMap>>` cache | `Arc<RwLock<HashMap>>` | OnceLock matches the Phase 24 REGISTRY_CACHE pattern; no Arc needed since the static is accessible from any thread including spawn_blocking threads |

---

## Architecture Patterns

### System Architecture Diagram

```
[Clipboard system]
     |
     | WM_CLIPBOARDUPDATE (message delivered to clipboard-monitor thread)
     v
[clipboard_monitor::run_monitor loop]
     |
     |---> [1] GetClipboardOwner (SYNCHRONOUS — before sleep branch)
     |          |
     |          +---> HWND -> GetWindowThreadProcessId -> OpenProcess(QUERY_LIMITED) -> QueryFullProcessImageNameW
     |          |     capture: (source_hwnd, source_pid, source_path_string)
     |          |
     |     [2] read FOREGROUND_SLOT.load (AtomicUsize)
     |          capture: dest_hwnd (may be 0)
     |          FOREGROUND_SLOT.store(0) — clear slot after read
     |
     |---> handle_clipboard_change(session_id, last_hash, source_hwnd, dest_hwnd)
               |
               | [if T2+] classify_and_alert(session_id, text, source_path, dest_path)
                         |
                         | tokio::task::spawn_blocking {
                         |   verify_and_cache(source_path) -> AppIdentity
                         |   verify_and_cache(dest_path)   -> AppIdentity
                         |   send_clipboard_alert(session_id, tier, preview, len, Some(src), Some(dst))
                         | }
                         |
                         v
               [Pipe 3: ClipboardAlert with source_application + destination_application populated]
                         |
                         v
               [dlp-agent: deserializes ClipboardAlert, evaluates policy, writes AuditEvent]

[Any foreground change in the OS (user switches windows)]
     |
     | EVENT_SYSTEM_FOREGROUND (delivered by WinEvent subsystem to clipboard-monitor thread message loop)
     v
[winevent_proc callback (out-of-context, same thread)]
     |
     +---> FOREGROUND_SLOT.store(hwnd as usize)  -- record the just-activated window as future destination
```

### Recommended Project Structure

```
dlp-user-ui/src/
├── detection/
│   └── app_identity.rs     # NEW — resolve_app_identity(), verify_and_cache(), AUTHENTICODE_CACHE
├── clipboard_monitor.rs    # MODIFY — SetWinEventHook registration, GetClipboardOwner capture, FOREGROUND_SLOT
├── ipc/
│   └── pipe3.rs            # MODIFY — replace None, None with resolved AppIdentity values
└── (all other files unchanged)
```

---

### Pattern 1: SetWinEventHook Registration and Teardown

**What:** Register an out-of-context WinEvent hook for `EVENT_SYSTEM_FOREGROUND` on the clipboard-monitor thread immediately after `AddClipboardFormatListener`. The hook callback updates a thread-accessible `AtomicUsize` with the newly-activated HWND.

**Critical thread-affinity rule (VERIFIED: MSDN SetWinEventHook docs):**
- The callback is delivered on the **same thread** that called `SetWinEventHook`.
- That thread **must have a message loop** — and the clipboard-monitor thread already does.
- `WINEVENT_OUTOFCONTEXT` means: no DLL injection, callback runs out-of-process in our own thread's message queue. This is what we want.
- `WINEVENT_SKIPOWNPROCESS` prevents self-notification — not strictly needed but good hygiene.

```rust
// Source: MSDN SetWinEventHook, verified against windows-rs 0.58 API surface
use windows::Win32::UI::Accessibility::{SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK};
use windows::Win32::UI::Accessibility::{
    WINEVENT_OUTOFCONTEXT, WINEVENT_SKIPOWNPROCESS,
    EVENT_SYSTEM_FOREGROUND,
};

// Process-wide atomic HWND slot — 0 means "no previous foreground window captured yet".
// HWND is a *mut c_void (pointer-sized), which fits in usize on both 32-bit and 64-bit.
// Rust note: AtomicUsize has no overhead over a raw usize on x86-64 for single-writer scenarios.
static FOREGROUND_SLOT: AtomicUsize = AtomicUsize::new(0);

// Register inside run_monitor, after AddClipboardFormatListener succeeds:
let hook: HWINEVENTHOOK = unsafe {
    SetWinEventHook(
        EVENT_SYSTEM_FOREGROUND,  // eventMin
        EVENT_SYSTEM_FOREGROUND,  // eventMax (same event)
        None,                     // hmodWinEventProc = None for OUTOFCONTEXT
        Some(foreground_event_proc), // the callback
        0,                        // idProcess = 0 (all processes)
        0,                        // idThread = 0 (all threads)
        WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
    )
};
// Teardown — after breaking out of the message loop:
let _ = unsafe { UnhookWinEvent(hook) };

/// WinEvent callback — runs on the clipboard-monitor thread's message dispatch.
/// Stores the newly-foreground HWND so the next WM_CLIPBOARDUPDATE can read it as "destination".
unsafe extern "system" fn foreground_event_proc(
    _hook: HWINEVENTHOOK,
    _event: u32,
    hwnd: HWND,
    _id_object: i32,
    _id_child: i32,
    _event_thread: u32,
    _event_time: u32,
) {
    // Store as usize — HWND is *mut c_void, which is usize-wide on all Windows targets.
    FOREGROUND_SLOT.store(hwnd.0 as usize, Ordering::Relaxed);
}
```

**Teardown lifecycle:** Call `UnhookWinEvent(hook)` after the `loop { ... }` exits in `run_monitor`. The hook lives for the duration of the clipboard monitor thread — same as the `RemoveClipboardFormatListener` call that already happens there.

[VERIFIED: MSDN SetWinEventHook — thread affinity, WINEVENT_OUTOFCONTEXT, callback signature, teardown via UnhookWinEvent]

---

### Pattern 2: Synchronous Source Identity Capture at WM_CLIPBOARDUPDATE

**What:** At `WM_CLIPBOARDUPDATE` time, call `GetClipboardOwner` before entering `handle_clipboard_change`. This is the only safe window — the source process may exit within milliseconds.

**Why synchronous matters:** The current `PeekMessageW` loop has a 100ms sleep on the idle branch. `WM_CLIPBOARDUPDATE` is checked before the sleep in the `if has_msg.as_bool()` branch, so if we call `GetClipboardOwner` here we are already synchronous. No structural change to the polling loop is needed. [VERIFIED: clipboard_monitor.rs:123-126]

```rust
// Inside the WM_CLIPBOARDUPDATE branch in run_monitor (clipboard_monitor.rs:124):
if msg.message == WM_CLIPBOARDUPDATE {
    // Capture source identity BEFORE handle_clipboard_change — source window may close any moment.
    let source_hwnd: Option<HWND> = unsafe {
        // GetClipboardOwner returns NULL if no owner (e.g., clipboard written by system or cleared).
        let h = windows::Win32::System::DataExchange::GetClipboardOwner();
        if h.is_invalid() { None } else { Some(h) }
    };

    // Read and clear the foreground slot atomically.
    let dest_raw = FOREGROUND_SLOT.swap(0, Ordering::Relaxed);
    let dest_hwnd: Option<HWND> = if dest_raw != 0 {
        Some(HWND(dest_raw as *mut _))
    } else {
        None
    };

    handle_clipboard_change(session_id, &mut last_hash, source_hwnd, dest_hwnd);
}
```

[VERIFIED: clipboard_monitor.rs lines 106-135 — the if/else structure, PeekMessageW branch, WM_CLIPBOARDUPDATE check]

---

### Pattern 3: HWND to Image Path Resolution

**What:** Given an HWND, resolve to a full NT image path. `GetWindowThreadProcessId` extracts the PID; `OpenProcess` opens a handle with minimum rights; `QueryFullProcessImageNameW` returns the full path.

```rust
// Source: windows-rs API surface — Win32_System_Threading (already enabled in Cargo.toml)
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_NAME_WIN32,
};
use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;
use windows::Win32::Foundation::{CloseHandle, HWND};

/// Resolves an HWND to its full Win32 image path.
///
/// Returns `None` if the process has already exited or if the caller lacks
/// `PROCESS_QUERY_LIMITED_INFORMATION` rights (elevated target process).
///
/// # Safety
/// Safe to call — all unsafe operations are contained.
fn hwnd_to_image_path(hwnd: HWND) -> Option<String> {
    let mut pid: u32 = 0;
    // GetWindowThreadProcessId returns the thread ID; pid is an out parameter.
    // Returns 0 on failure (dead HWND).
    let _tid = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    if pid == 0 {
        return None;
    }

    // PROCESS_QUERY_LIMITED_INFORMATION works on all processes including elevated ones
    // (unlike PROCESS_QUERY_INFORMATION which fails on higher-integrity processes).
    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?
    };

    let mut buf = [0u16; 1024];
    let mut size = buf.len() as u32;
    // PROCESS_NAME_WIN32 = 0 — returns the Win32 path (e.g. C:\Windows\notepad.exe).
    // PROCESS_NAME_NATIVE = 1 — returns NT device path (e.g. \Device\HarddiskVolume3\...).
    let result = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, windows::core::PWSTR(buf.as_mut_ptr()), &mut size)
    };
    unsafe { let _ = CloseHandle(handle); };

    result.ok()?;
    // size is updated to the number of characters written (excluding the NUL).
    Some(String::from_utf16_lossy(&buf[..size as usize]))
}
```

[VERIFIED: STACK.md Capability 1 — PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW confirmed in Win32_System_Threading]

---

### Pattern 4: Authenticode Verification + Publisher Extraction Pipeline

**What:** `WinVerifyTrust` verifies the signature. Publisher extraction requires walking the certificate chain via WinCrypt APIs (`CryptQueryObject` → `CryptMsgGetParam` → `CertFindCertificateInStore` → `CertGetNameStringW`). This is a multi-step, potentially-network-bound operation — always run in `spawn_blocking`.

**Two-phase approach (D-04):**
1. Cache lookup by image path (holds `Mutex` lock briefly, O(1))
2. If miss: run `WinVerifyTrust` + publisher extraction in the same `spawn_blocking` closure, then insert into cache

```rust
// Process-wide Authenticode result cache.
// Key: absolute image path (String).
// Value: (publisher_cn: String, signature_state: SignatureState).
// Populated once per unique path per process lifetime (D-06 — no TTL).
//
// Using std::sync::OnceLock (stable since Rust 1.70) — same pattern as REGISTRY_CACHE in Phase 24.
// Rust note: OnceLock<T> allows lazy initialization of a static — get_or_init runs the closure
// only on the first call; all subsequent calls return a reference to the same value.
static AUTHENTICODE_CACHE: OnceLock<Mutex<HashMap<String, (String, SignatureState)>>> =
    OnceLock::new();

fn authenticode_cache() -> &'static Mutex<HashMap<String, (String, SignatureState)>> {
    AUTHENTICODE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Verify and cache Authenticode result for a given image path.
///
/// Must be called from inside `tokio::task::spawn_blocking` — `WinVerifyTrust`
/// may block on CRL/OCSP network calls (PITFALL-A4).
///
/// # Returns
///
/// `(publisher, SignatureState)` — publisher is empty string when signature is absent or invalid.
fn verify_and_cache(image_path: &str) -> (String, SignatureState) {
    // Fast path: check cache first (brief lock, O(1)).
    {
        let cache = authenticode_cache().lock().expect("authenticode cache lock");
        if let Some(entry) = cache.get(image_path) {
            return entry.clone();
        }
    } // lock released here

    // Slow path: run WinVerifyTrust (may block on CRL check).
    let result = run_wintrust(image_path);

    // Insert into cache (second lock acquisition — OK, this is in spawn_blocking).
    authenticode_cache()
        .lock()
        .expect("authenticode cache lock")
        .insert(image_path.to_string(), result.clone());

    result
}
```

**WinVerifyTrust call structure (Phase 25 recommended flags):**

```rust
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_UI_NONE, WTD_STATEACTION_VERIFY, WTD_STATEACTION_CLOSE,
    WTD_REVOCATION_CHECK_NONE,  // Avoids CRL network blocking on hot path
};

// WinVerifyTrust return codes:
// 0 (S_OK)              → valid Authenticode signature
// 0x800B0100 (TRUST_E_NOSIGNATURE) → no signature or signature not found
// 0x800B0101 (CERT_E_EXPIRED) → certificate expired
// 0x80096004 (TRUST_E_BAD_LENGTH) → signature data corrupted
// All other negative values → verification failed for various reasons
```

**CRITICAL flag note (PITFALL-A4):** Use `WTD_REVOCATION_CHECK_NONE` on the primary clipboard path (D-06: no TTL re-verification). This avoids the 5-30 second CRL network hang documented in PITFALL-A4. The tradeoff is that a freshly-revoked certificate will not be caught until the process restarts — acceptable per D-06.

**Publisher extraction sequence (VERIFIED: MSDN "Get information from Authenticode Signed Executables" KB323809):**

The three-step chain: `CryptQueryObject` (opens the PE's embedded PKCS#7 blob) → `CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM)` (gets the signer info) → `CertFindCertificateInStore` (finds the cert in the store) → `CertGetNameStringW(CERT_NAME_SIMPLE_DISPLAY_TYPE)` (extracts the Subject CN as the publisher string).

`CryptQueryObject` and `CertGetNameStringW` are in `Win32_Security_Cryptography` which is already enabled in `dlp-user-ui/Cargo.toml`. [VERIFIED: Cargo.toml line 39]

[VERIFIED: PITFALLS.md PITFALL-A4 — WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT / WTD_CACHE_ONLY_URL_RETRIEVAL documented as mitigations; MSDN KB323809 for publisher extraction sequence]

---

### Pattern 5: spawn_blocking Pipeline (Async Bridge)

**What:** The clipboard monitor runs on a dedicated OS thread (not Tokio), but `dlp-user-ui` uses Tokio as the async runtime (iced feature `"tokio"` is enabled). The `send_clipboard_alert` call in `classify_and_alert` is currently synchronous. For Phase 25, the call that includes verification must become async — or verification must run synchronously in the clipboard monitor thread with a blocking call into a Tokio-aware spawn point.

**The correct pattern (matching pipe1.rs and pipe2.rs):**

Looking at `dlp-user-ui/src/ipc/pipe1.rs:77`:
```rust
tokio::task::spawn_blocking(move || client_loop(handle.into_inner(), session_id))
    .await
    .map_err(|e| anyhow::anyhow!("join error: {}", e))?
```

The clipboard monitor thread is **not** an async task — it is a plain OS thread spawned with `std::thread::Builder`. It cannot call `.await`. The pattern must be:

**Option A (recommended): Blocking spawn from the OS thread using `Handle::spawn_blocking`.**

The Tokio runtime handle can be captured before spawning the clipboard monitor thread and passed in. Then from the OS thread:

```rust
// In run_monitor: call verify_and_cache synchronously inside a spawn_blocking
// by obtaining the current-thread runtime handle before crossing into the OS thread.
// Rust note: tokio::runtime::Handle::current() works on any thread as long as a Tokio
// runtime is active — even non-async OS threads.
let rt_handle = tokio::runtime::Handle::current();

// Later, when building the AppIdentity:
let source_identity = if let Some(path) = source_path {
    // block_on is valid on a non-async thread; block_in_place would be wrong here
    // since we are not inside an async context.
    rt_handle.block_on(tokio::task::spawn_blocking(move || {
        let (publisher, sig_state) = verify_and_cache(&path);
        build_app_identity(path, publisher, sig_state)
    })).ok().flatten()
} else {
    None
};
```

**Option B (simpler): Run verify_and_cache directly in the clipboard monitor thread.**

Since `verify_and_cache` is a pure synchronous function with a cache, and since the `WTD_REVOCATION_CHECK_NONE` flag avoids network calls, it is safe to run it directly on the clipboard-monitor thread for Phase 25. The risk of blocking is eliminated by the revocation-check flag. This is simpler and avoids the `Handle::current()` complexity.

**Recommendation:** Use Option B for Phase 25. The cache makes subsequent calls ~0ms. The first call for a given binary may take 10-50ms (disk read, certificate parse, no network). This is acceptable on the clipboard monitor thread. Document that enabling revocation checks in a future hardening phase will require moving this to a background task.

[VERIFIED: clipboard_monitor.rs thread model — `std::thread::Builder::new().spawn(...)`, not a tokio::spawn; pipe1.rs:77 shows the spawn_blocking pattern for OS threads]

---

### Pattern 6: Final AppIdentity Construction

```rust
/// Builds an `AppIdentity` from a resolved image path.
///
/// Runs `WinVerifyTrust` and publisher extraction (or returns from cache).
/// Safe to call from non-async OS threads when `WTD_REVOCATION_CHECK_NONE` is set.
fn build_app_identity_from_path(image_path: String) -> AppIdentity {
    let (publisher, signature_state) = verify_and_cache(&image_path);
    let trust_tier = match signature_state {
        SignatureState::Valid => AppTrustTier::Trusted,
        SignatureState::Invalid | SignatureState::NotSigned => AppTrustTier::Untrusted,
        SignatureState::Unknown => AppTrustTier::Unknown,
    };
    AppIdentity { image_path, publisher, trust_tier, signature_state }
}

/// Resolves an HWND to a full `AppIdentity` per D-08 failure semantics.
///
/// - HWND resolves to path: runs Authenticode, returns `Some(AppIdentity)`.
/// - HWND is dead / path fails: returns `Some(AppIdentity::default())` (all-Unknown fields).
/// - HWND is None (no owner / no slot): returns `None`.
fn resolve_app_identity(hwnd: Option<HWND>) -> Option<AppIdentity> {
    let hwnd = hwnd?;  // None → source/dest is None (D-08)
    match hwnd_to_image_path(hwnd) {
        Some(path) => Some(build_app_identity_from_path(path)),
        None => Some(AppIdentity::default()),  // D-08: path resolution failed → all-Unknown
    }
}
```

**Intra-app copy (D-02):** When the `dest_hwnd` from the `FOREGROUND_SLOT` matches the same PID as the source HWND, set `destination_application = source_application.clone()`. Implementation: compare PIDs via `GetWindowThreadProcessId` before doing two full resolution calls.

[VERIFIED: dlp-common/src/endpoint.rs — AppIdentity derives Default; AppTrustTier::default() = Unknown, SignatureState::default() = Unknown]

---

### Anti-Patterns to Avoid

- **Never call `GetClipboardOwner` in `handle_clipboard_change` or `classify_and_alert`** — by the time those functions run, the source window may have closed. Capture the HWND at the `WM_CLIPBOARDUPDATE` branch, before the sleep. [PITFALL-A1]
- **Never call `WinVerifyTrust` with default `WINTRUST_DATA` flags on the message pump thread** — default flags include CRL checking which can block 5-30 seconds. Always use `WTD_REVOCATION_CHECK_NONE` unless on a dedicated background thread. [PITFALL-A4]
- **Never register `SetWinEventHook` from a thread without a message loop** — the callback will never fire. The clipboard-monitor thread already has a message loop. [VERIFIED: MSDN SetWinEventHook Remarks]
- **Never use `WINEVENT_INCONTEXT`** — requires DLL injection and a handle to the DLL (`hmodWinEventProc`). `WINEVENT_OUTOFCONTEXT` is the correct choice for an in-process callback.
- **Never call `UnhookWinEvent` from a different thread than `SetWinEventHook`** — behavior is undefined. Teardown must happen in `run_monitor` on the clipboard-monitor thread.
- **Never skip updating the `FOREGROUND_SLOT` on the `None` path** — always read-and-clear with `swap(0)`, not `load`. Otherwise the slot persists across multiple clipboard events and the wrong destination is reported.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Authenticode signature verification | Custom PE parser + cert chain walker | `WinVerifyTrust` | Handles all signature formats, revocation, time-stamping — edge cases are deep |
| Publisher CN extraction | Custom ASN.1 decoder | `CryptQueryObject` + `CertGetNameStringW` | ASN.1 is complex; DER vs BER, nested structures, encoding variants |
| Process path resolution | `/proc`-style reading or registry walks | `QueryFullProcessImageNameW` | Only Win32 API handles all process types including sandboxed/UWP hosts |
| WinEvent hook registration | Manual `SetWindowsHookEx` + DLL | `SetWinEventHook(WINEVENT_OUTOFCONTEXT)` | No DLL required; delivered on-thread; no injection complexity |

**Key insight:** The Win32 Authenticode API surface appears simple (`WinVerifyTrust` = one function call) but publisher extraction from the cert chain is a 5-step WinCrypt sequence that is trivially wrong if hand-rolled (wrong cert in multi-signer chains, missing nested signer info for counter-signatures, etc.).

---

## Common Pitfalls

### Pitfall 1: Dead HWND from GetClipboardOwner (PITFALL-A1)

**What goes wrong:** `GetClipboardOwner` returns a valid-looking HWND that is already destroyed by the time `GetWindowThreadProcessId` is called — PID returns 0, identity is lost.

**Why it happens:** Short-lived source processes (script automation, context-menu handlers) exit within milliseconds of setting clipboard data.

**How to avoid:** Call `GetClipboardOwner` at the earliest possible moment — the `WM_CLIPBOARDUPDATE` message dispatch branch, before `handle_clipboard_change`. The current code already checks `msg.message == WM_CLIPBOARDUPDATE` at line 124 before any sleep.

**Warning signs:** `GetWindowThreadProcessId` returning `pid = 0` on a non-null HWND — this indicates a dead window.

---

### Pitfall 2: WinVerifyTrust Network Block (PITFALL-A4)

**What goes wrong:** `WinVerifyTrust` performs CRL/OCSP revocation check over the network. On a machine with a slow proxy or no internet, this blocks for 5-30 seconds — freezing the clipboard monitor thread.

**Why it happens:** Default `WINTRUST_DATA.fdwRevocationChecks` includes revocation checking.

**How to avoid:** Set `WTD_REVOCATION_CHECK_NONE` for Phase 25. Per D-06, no TTL re-verification is needed per session.

**Warning signs:** UI freezing for seconds after copying text in offline/restricted-network environments.

---

### Pitfall 3: Hook Callback Not Firing (Thread Affinity Violation)

**What goes wrong:** `SetWinEventHook` is called successfully (returns non-null handle) but the `foreground_event_proc` callback is never invoked.

**Why it happens:** The thread that registered the hook does not have a running message loop at the time the event fires, OR the hook was registered from a temporary thread that exited.

**How to avoid:** Always register from the clipboard-monitor thread, inside `run_monitor`, after the message-only HWND is created and the `PeekMessageW` loop is running. Never register from `main` or from a tokio task.

**Warning signs:** `FOREGROUND_SLOT` always reads 0 in `WM_CLIPBOARDUPDATE` handler.

---

### Pitfall 4: HWND Cast Safety

**What goes wrong:** `HWND` is `*mut c_void` in windows-rs 0.58. Casting to `usize` and storing in `AtomicUsize` is correct on 64-bit Windows (both are 8 bytes) but the cast requires care to avoid alignment issues.

**How to avoid:** Use `hwnd.0 as usize` when storing (`.0` accesses the raw pointer field), and `HWND(dest_raw as *mut core::ffi::c_void)` when reconstructing. This is the standard pattern in the windows-rs ecosystem.

[VERIFIED: clipboard_monitor.rs uses `HWND(-3_isize as *mut _)` showing the same pointer-to-HWND cast pattern]

---

### Pitfall 5: Mutex Reentrance in Authenticode Cache

**What goes wrong:** `verify_and_cache` releases the cache lock between the read check and the write insert (two separate lock acquisitions). If two clipboard events race simultaneously, both may call `WinVerifyTrust` for the same path and both insert (last writer wins). This is safe (both produce the same result) but wastes one call.

**Why acceptable for Phase 25:** The clipboard monitor is single-threaded (one thread, one `WM_CLIPBOARDUPDATE` at a time). There is no actual race. The double-check idiom is only needed if `verify_and_cache` is called from multiple threads — which spawn_blocking could enable in a future phase. Document the invariant.

---

### Pitfall 6: FOREGROUND_SLOT Captures Own Window

**What goes wrong:** When `dlp-user-ui` itself becomes the foreground window (e.g., it shows a dialog), `EVENT_SYSTEM_FOREGROUND` fires and stores the UI process's HWND in `FOREGROUND_SLOT`. The next clipboard event then reports the DLP UI process as the destination.

**How to avoid:** Use `WINEVENT_SKIPOWNPROCESS` in the `SetWinEventHook` flags. This prevents the hook from receiving events generated by the DLP UI process's own threads. [VERIFIED: MSDN SetWinEventHook — WINEVENT_SKIPOWNPROCESS flag]

---

## Runtime State Inventory

This is a greenfield modification phase — no rename/refactor. No runtime state beyond in-process caches.

**Nothing found in any category:** The `AUTHENTICODE_CACHE` and `FOREGROUND_SLOT` are process-local statics initialized at first use. They have no persistence across process restarts. No data migration required.

---

## Code Examples

### Verified: OnceLock pattern from dlp-agent/src/device_registry.rs

The Phase 24 `DeviceRegistryCache` uses `parking_lot::RwLock<HashMap>` as a struct field with `Arc<Self>`. Phase 25's Authenticode cache uses a **process-wide static** `OnceLock<Mutex<HashMap>>` instead — simpler since no Arc is needed (static is accessible from everywhere):

```rust
// Directly analogous to REGISTRY_CACHE pattern from device_registry.rs.
// Rust note: OnceLock<T> is a lazily-initialized static value — safe to access
// from any thread without an Arc because the 'static lifetime covers the entire process.
use std::sync::{Mutex, OnceLock};
use std::collections::HashMap;
use dlp_common::{SignatureState};

static AUTHENTICODE_CACHE: OnceLock<Mutex<HashMap<String, (String, SignatureState)>>> =
    OnceLock::new();

fn authenticode_cache() -> &'static Mutex<HashMap<String, (String, SignatureState)>> {
    AUTHENTICODE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}
```

[VERIFIED: dlp-agent/src/device_registry.rs — DeviceRegistryCache pattern; dlp-user-ui uses std::sync::Mutex (not parking_lot) in existing code]

### Verified: classify_and_alert signature (must change)

Current signature (clipboard_monitor.rs:194):
```rust
pub fn classify_and_alert(session_id: u32, text: &str) -> Option<&'static str>
```

Phase 25 new signature (add identity parameters):
```rust
pub fn classify_and_alert(
    session_id: u32,
    text: &str,
    source_identity: Option<AppIdentity>,
    dest_identity: Option<AppIdentity>,
) -> Option<&'static str>
```

The existing integration tests that call `classify_and_alert` directly will need to be updated to pass `None, None` for the new parameters.

[VERIFIED: clipboard_monitor.rs:194-227 — current signature; tests call this function directly]

### Verified: send_clipboard_alert signature (must change)

Current (pipe3.rs:77-82):
```rust
pub fn send_clipboard_alert(
    session_id: u32,
    classification: &str,
    preview: &str,
    text_length: usize,
) -> Result<()>
```

Phase 25 new signature:
```rust
pub fn send_clipboard_alert(
    session_id: u32,
    classification: &str,
    preview: &str,
    text_length: usize,
    source_application: Option<AppIdentity>,
    destination_application: Option<AppIdentity>,
) -> Result<()>
```

[VERIFIED: pipe3.rs:77-105 — current signature and None placeholder comments at lines 92-93]

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `GetForegroundWindow` at paste time | `SetWinEventHook(EVENT_SYSTEM_FOREGROUND)` previous-slot | Phase 25 D-01 | Captures destination even before the paste keystroke |
| No publisher verification | `WinVerifyTrust` + WinCrypt chain walk | Phase 25 APP-06 | Prevents renamed-binary bypass |
| `source_application: None, destination_application: None` | Populated `AppIdentity` structs | Phase 25 | Enables policy evaluation and audit enrichment in Phases 26+ |

**Deprecated/outdated:**
- `GetForegroundWindow` for destination detection: returns the window with focus at the moment of the call, which is unreliable — the user may already have switched away by the time the DLP code runs. Replaced by the event-hook slot approach.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `WTD_REVOCATION_CHECK_NONE` is the correct constant name in windows-rs 0.58 `Win32_Security_WinTrust` | Pattern 4 | Would fail to compile; rename to correct constant |
| A2 | `WinVerifyTrust` with `WTD_REVOCATION_CHECK_NONE` completes in < 500ms on local disk reads | Pattern 4 | If slower, message pump may lag; move to spawn_blocking per Option A |
| A3 | Publisher CN is always in `CERT_NAME_SIMPLE_DISPLAY_TYPE` field of the leaf certificate | Pattern 4 (publisher extraction) | Some signing setups put publisher in intermediate cert; may need `CERT_NAME_FRIENDLY_DISPLAY_TYPE` fallback |

---

## Open Questions

1. **`parking_lot::Mutex` vs `std::sync::Mutex` for AUTHENTICODE_CACHE**
   - What we know: `dlp-user-ui` has `parking_lot` in Cargo.toml; existing code uses it for other shared state
   - What's unclear: Whether `parking_lot::Mutex` works correctly in a `OnceLock` static (it should — no difference from `std::sync::Mutex` in this context)
   - Recommendation: Use `std::sync::Mutex` for the OnceLock static (simpler, no import confusion) since the clipboard monitor thread has no contention

2. **Intra-app copy PID comparison timing**
   - What we know: D-02 requires dest = source identity for intra-app copy
   - What's unclear: Whether to compare PIDs before or after resolving identities (comparing after wastes a second `verify_and_cache` call for the same path)
   - Recommendation: Compare source and dest HWNDs' PIDs first; if equal, call `resolve_app_identity` once and `clone()` the result for dest

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `Win32_Security_WinTrust` feature | WinVerifyTrust | ✓ (add to Cargo.toml) | windows 0.58 | — |
| `Win32_UI_Accessibility` feature | SetWinEventHook | ✓ (add to Cargo.toml) | windows 0.58 | — |
| `Win32_Security_Cryptography` feature | CertGetNameStringW | ✓ (already in Cargo.toml) | windows 0.58 | — |
| `OnceLock` | AUTHENTICODE_CACHE | ✓ | Rust 1.70+ (stable since 1.70) | — |

[VERIFIED: dlp-user-ui/Cargo.toml — Win32_Security_Cryptography at line 38, Win32_Security at line 37]

---

## Validation Architecture

`workflow.nyquist_validation` is not explicitly set to `false` in config.json — validation section is included.

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `cargo test` (built-in) |
| Config file | `serial_test` crate in dev-dependencies (for clipboard + env-var state isolation) |
| Quick run command | `cargo test -p dlp-user-ui -- --test-thread=1` |
| Full suite command | `cargo test --workspace -- --test-threads=1` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| APP-02 | `GetClipboardOwner` captured synchronously at WM_CLIPBOARDUPDATE | Unit (mock HWND) | `cargo test -p dlp-user-ui test_source_identity_captured` | ❌ Wave 0 |
| APP-01 | Destination HWND from FOREGROUND_SLOT populated at WM_CLIPBOARDUPDATE | Unit (mock AtomicUsize slot) | `cargo test -p dlp-user-ui test_dest_identity_from_slot` | ❌ Wave 0 |
| APP-06 | Authenticode cache: first call runs WinVerifyTrust, second call is a cache hit | Unit (spy on verify_and_cache) | `cargo test -p dlp-user-ui test_authenticode_cache_hit` | ❌ Wave 0 |
| D-02 | Intra-app copy: dest == source identity (same PID) | Unit | `cargo test -p dlp-user-ui test_intraapp_copy_dest_equals_source` | ❌ Wave 0 |
| D-08 | NULL GetClipboardOwner → source = None | Unit | `cargo test -p dlp-user-ui test_null_clipboard_owner_gives_none` | ❌ Wave 0 |
| D-08 | Dead HWND (pid=0) → Some(AppIdentity::default()) | Unit | `cargo test -p dlp-user-ui test_dead_hwnd_gives_unknown_identity` | ❌ Wave 0 |
| APP-05 | ClipboardAlert wire format includes source/dest with non-empty image_path | Integration (mock pipe3 server) | `cargo test -p dlp-user-ui -- clipboard_alert_includes_identity` | ❌ Wave 0 |
| APP-06 SC-5 | Renamed binary still returns correct publisher (path-keyed, not name-keyed) | Unit (two paths, same binary) | `cargo test -p dlp-user-ui test_renamed_binary_cache_miss` | ❌ Wave 0 |

### Testing Strategy: Mocking Win32 Calls

Because `GetClipboardOwner`, `QueryFullProcessImageNameW`, and `WinVerifyTrust` require a live Windows session with real process handles, unit tests must either:

1. **Extract the logic into testable pure functions** — `resolve_app_identity(hwnd)` is hard to unit test (needs a live HWND). Instead, extract `image_path_to_app_identity(path: String)` as a pure function that takes a path string and calls `verify_and_cache`. This is fully testable with any real path on the test machine.

2. **Test the cache behavior with known paths** — Use `std::env::current_exe()` (the test binary itself) as a test path. It is guaranteed to exist. `WinVerifyTrust` on an unsigned Rust test binary returns `TRUST_E_NOSIGNATURE` → `SignatureState::NotSigned` → `AppTrustTier::Untrusted`. This is a deterministic outcome.

3. **Test the slot logic with atomic primitives** — `FOREGROUND_SLOT.store(12345, Relaxed)` then simulate a `WM_CLIPBOARDUPDATE` branch reading and clearing the slot. No Win32 calls needed.

4. **Test the D-02 intra-app branch** — Use two fake HWNDs with the same PID (mock `hwnd_to_image_path` by making the function injectable or by using a test cfg flag).

### Sampling Rate

- **Per task commit:** `cargo test -p dlp-user-ui -- --test-threads=1`
- **Per wave merge:** `cargo test --workspace -- --test-threads=1`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `dlp-user-ui/src/detection/app_identity.rs` — new module with `resolve_app_identity`, `verify_and_cache`, `AUTHENTICODE_CACHE`; unit tests inline
- [ ] `dlp-user-ui/src/detection/mod.rs` — new module file declaring `pub mod app_identity`
- [ ] Update `dlp-user-ui/src/lib.rs` — add `mod detection;`
- [ ] Update existing `classify_and_alert` tests — pass `None, None` for new identity parameters

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | yes | Default-deny on `AppTrustTier::Unknown` (D-07); no allowlisting of Unknown |
| V5 Input Validation | yes | Image path is system-provided (QueryFullProcessImageNameW output) — treat as untrusted; validate UTF-16 conversion |
| V6 Cryptography | yes | WinVerifyTrust — never hand-roll; use OS Authenticode stack |

### Known Threat Patterns for This Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Binary rename bypass (copy signed.exe to bypass_app.exe) | Spoofing | WinVerifyTrust keyed by file path — verifies actual file contents, not name |
| Process path injection (malicious DLL loaded into legitimate process) | Tampering | Out of scope for Phase 25; detected by EDR at a lower layer |
| Clipboard owner HWND spoofing (crafted HWND pointing to attacker process) | Spoofing | Impossible — HWND is OS-assigned, not user-controlled; attacker cannot control GetClipboardOwner return value |
| Cache poisoning (inject fake cache entry via race) | Tampering | Single-threaded clipboard monitor eliminates race; Mutex protects multi-thread case |
| CRL bypass (revoked cert not checked) | Elevation of Privilege | Accepted per D-06 (no TTL, revocation deferred); documented in Assumptions Log A2 |

---

## Sources

### Primary (HIGH confidence)
- `dlp-user-ui/src/clipboard_monitor.rs` — existing message loop structure, injection points at lines 124-125
- `dlp-user-ui/src/ipc/pipe3.rs:92-93` — None placeholders to replace
- `dlp-user-ui/src/ipc/messages.rs:101-104` — ClipboardAlert fields already declared
- `dlp-common/src/endpoint.rs` — AppIdentity, AppTrustTier, SignatureState fully defined
- `dlp-agent/src/device_registry.rs` — OnceLock cache pattern (DeviceRegistryCache)
- `dlp-user-ui/Cargo.toml` — existing windows feature flags
- MSDN `SetWinEventHook` (learn.microsoft.com) — thread affinity rules, WINEVENT_OUTOFCONTEXT semantics, callback signature
- `.planning/research/PITFALLS.md` — PITFALL-A1 (clipboard race), PITFALL-A4 (WinVerifyTrust block)
- `.planning/research/STACK.md` — Capability 1 (process identity APIs), Capability 2 (WinVerifyTrust feature flag)

### Secondary (MEDIUM confidence)
- MSDN KB323809 "Get information from Authenticode Signed Executables" — CryptQueryObject → CertGetNameStringW publisher extraction sequence
- windows-docs-rs WinVerifyTrust entry — confirmed module path `windows::Win32::Security::WinTrust`
- windows-docs-rs SetWinEventHook entry — confirmed module path `windows::Win32::UI::Accessibility`, WINEVENTPROC signature

### Tertiary (LOW confidence)
- A3 assumption: publisher CN location in `CERT_NAME_SIMPLE_DISPLAY_TYPE` — based on training knowledge of Windows cert API conventions, not verified against live cert chain output in this session

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all feature flags traced to existing Cargo.toml or verified module paths
- Architecture: HIGH — patterns derived directly from existing codebase (clipboard_monitor.rs, pipe3.rs, device_registry.rs)
- SetWinEventHook lifecycle: HIGH — MSDN docs verified for thread affinity rules
- WinVerifyTrust publisher extraction: MEDIUM — multi-step WinCrypt sequence confirmed by KB323809, exact constant names (WTD_REVOCATION_CHECK_NONE) need compile-time verification
- Pitfalls: HIGH — all drawn from existing PITFALLS.md research plus MSDN confirmation

**Research date:** 2026-04-22
**Valid until:** 2026-05-22 (stable Win32 API surface — low churn risk)
