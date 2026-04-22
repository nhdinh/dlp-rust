---
phase: 25-app-identity-capture-in-dlp-user-ui
plan: "02"
subsystem: dlp-user-ui/clipboard_monitor
tags: [win32, winevent, app-identity, spawn-blocking, sc3, foreground-slot, clipboard-monitor]
dependency_graph:
  requires:
    - dlp-user-ui::detection::app_identity (Plan 01 — resolve_app_identity, hwnd_to_pid, AUTHENTICODE_CACHE)
    - dlp-common::endpoint (AppIdentity, AppTrustTier, SignatureState)
    - tokio::runtime::Handle (SC-3 spawn_blocking wiring)
  provides:
    - dlp-user-ui::clipboard_monitor::FOREGROUND_SLOT (AtomicUsize destination-identity slot)
    - dlp-user-ui::clipboard_monitor::foreground_event_proc (WinEvent callback)
    - dlp-user-ui::clipboard_monitor::classify_and_alert (updated 4-param signature)
  affects:
    - dlp-user-ui::ipc::pipe3 (Plan 03 will extend send_clipboard_alert to accept identities)
tech_stack:
  added:
    - Win32_UI_WindowsAndMessaging::EVENT_SYSTEM_FOREGROUND (foreground window change events)
    - Win32_UI_WindowsAndMessaging::WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS (hook flags)
    - Win32_UI_Accessibility::SetWinEventHook / UnhookWinEvent (hook registration/teardown)
    - Win32_System_DataExchange::GetClipboardOwner (source HWND capture at clipboard event)
    - tokio::task::spawn_blocking (SC-3 — offload WinVerifyTrust disk I/O off Tokio executor)
    - tokio::runtime::Handle::current() (captured on async thread, moved into std::thread closure)
  patterns:
    - AtomicUsize foreground slot — write in WinEvent callback, read-and-clear via swap(0) at event time
    - usize-as-HWND Send boundary crossing — HWND is *mut c_void (not Send); cast to usize for spawn_blocking, reconstruct inside closure
    - D-02 intra-app copy optimization — source_pid == dest_pid -> clone source identity, skip second WinVerifyTrust
    - SC-3 rt_handle.block_on(spawn_blocking(...)) — drives blocking future to completion on std::thread without executor re-entrancy
key_files:
  modified:
    - dlp-user-ui/src/clipboard_monitor.rs (FOREGROUND_SLOT, foreground_event_proc, SetWinEventHook, GetClipboardOwner, spawn_blocking, updated signatures)
    - dlp-user-ui/src/detection/app_identity.rs (remove #![allow(dead_code)], gate resolve_app_identity_from_path under #[cfg(test)])
    - dlp-user-ui/tests/clipboard_integration.rs (update classify_and_alert calls to 4-param signature with None, None)
decisions:
  - "WINEVENT_OUTOFCONTEXT and WINEVENT_SKIPOWNPROCESS live in Win32::UI::WindowsAndMessaging, not Win32::UI::Accessibility — windows-rs 0.58 placement differs from MSDN module grouping"
  - "GetClipboardOwner returns windows_core::Result<HWND> in windows-rs 0.58 — use .ok() to convert to Option<HWND>"
  - "HWND is *mut c_void (not Send) — must cast to usize before spawn_blocking boundary, reconstruct inside closure; this is safe because usize is Copy+Send and the value is only used for Win32 API calls inside the blocking thread"
  - "resolve_app_identity_from_path gated #[cfg(test)] — it was a test-only helper; removing #![allow(dead_code)] and keeping it public without cfg(test) would fail clippy -D warnings"
  - "Tasks 1 and 2 committed atomically — Task 1 added FOREGROUND_SLOT/foreground_event_proc; Task 2 wired SetWinEventHook, spawn_blocking, and updated signatures; the two form one coherent change set"
metrics:
  duration_seconds: 1200
  completed_date: "2026-04-22"
  tasks_completed: 2
  tasks_total: 2
  files_created: 0
  files_modified: 3
  tests_added: 5
  tests_passing: 23
---

# Phase 25 Plan 02: SetWinEventHook Foreground Tracking + Identity Wiring Summary

Win32 foreground-window tracking slot wired into clipboard_monitor — `FOREGROUND_SLOT` AtomicUsize captures destination HWND on every `EVENT_SYSTEM_FOREGROUND` event; `GetClipboardOwner` captures source HWND synchronously at `WM_CLIPBOARDUPDATE`; both resolved via `spawn_blocking`-wrapped `resolve_app_identity` calls (SC-3). `classify_and_alert` now carries `Option<AppIdentity>` for both source and destination.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | FOREGROUND_SLOT static + foreground_event_proc callback | 2cca0ff | clipboard_monitor.rs (static + callback + tests) |
| 2 | SetWinEventHook wiring + spawn_blocking identity resolution + updated signatures | 2cca0ff | clipboard_monitor.rs (full wiring), app_identity.rs (dead_code cleanup), clipboard_integration.rs (signature updates) |

## What Was Built

### `FOREGROUND_SLOT: AtomicUsize` static
Declared before `PREVIEW_MAX`. Written by `foreground_event_proc` on every `EVENT_SYSTEM_FOREGROUND` event via `store(hwnd.0 as usize, Ordering::Relaxed)`. Read-and-cleared by the `WM_CLIPBOARDUPDATE` handler via `swap(0, Ordering::Relaxed)` — atomic read-and-reset in one operation.

### `foreground_event_proc` WinEvent callback
`unsafe extern "system"` function registered via `SetWinEventHook`. Stores the incoming `HWND` as `usize` into `FOREGROUND_SLOT`. Gated `#[cfg(windows)]`. Delivered on the clipboard-monitor thread (same thread as `SetWinEventHook` registration) so `Relaxed` ordering suffices.

### `SetWinEventHook` registration in `run_monitor`
Registered immediately after `AddClipboardFormatListener`. Flags: `WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS` (both from `Win32::UI::WindowsAndMessaging`). Tracks `EVENT_SYSTEM_FOREGROUND` for all processes/threads except dlp-user-ui itself (T-25-04 mitigation). `UnhookWinEvent` called after the message loop exits on the same thread (required by Win32 thread affinity contract).

### `rt_handle` capture + SC-3 `spawn_blocking` wiring
`tokio::runtime::Handle::current()` captured before `std::thread::Builder::new().spawn(...)` on the async caller's thread. Moved into the clipboard-monitor thread closure. In `handle_clipboard_change`, both `resolve_app_identity` calls are wrapped in `rt_handle.block_on(tokio::task::spawn_blocking(...))`. Because `HWND` is `*mut c_void` (not `Send`), each HWND is cast to `usize` before the closure boundary and reconstructed as `HWND(raw as *mut c_void)` inside the closure.

### D-02 intra-app copy optimization
If `source_pid == dest_pid` (and both non-zero), `dest_identity = source_identity.clone()`. This avoids a second `WinVerifyTrust` call for the same executable. The cache in Plan 01 would also prevent the redundant I/O, but the PID comparison avoids even the cache lookup + hash map overhead.

### Updated `classify_and_alert` signature
Now accepts `source_identity: Option<AppIdentity>` and `dest_identity: Option<AppIdentity>` as parameters 3 and 4. The identities are received but suppressed with `let _ = (source_identity, dest_identity)` until Plan 03 extends `send_clipboard_alert`. Existing integration tests updated to pass `None, None`.

## Test Results

```
running 15 tests (unit — lib)
test clipboard_monitor::tests::test_foreground_slot_store_and_swap ... ok
test clipboard_monitor::tests::test_foreground_slot_empty_gives_zero ... ok
test clipboard_monitor::tests::test_classify_and_alert_with_none_identities_returns_tier_for_sensitive ... ok
test clipboard_monitor::tests::test_classify_and_alert_with_none_identities_returns_none_for_t1 ... ok
test clipboard_monitor::tests::test_intraapp_copy_dest_equals_source_identity ... ok
test detection::app_identity::tests::* ... ok (10 tests)
test result: ok. 15 passed; 0 failed

running 8 tests (integration — clipboard_integration)
test test_confidential_triggers_t3_alert ... ok
test test_credit_card_triggers_t4_alert ... ok
test test_duplicate_deduplicated ... ok
test test_empty_clipboard_ignored ... ok
test test_internal_triggers_t2_alert ... ok
test test_non_text_clipboard_ignored ... ok
test test_ordinary_text_no_alert ... ok
test test_ssn_triggers_t4_alert ... ok
test result: ok. 8 passed; 0 failed
```

## Verification

```
cargo build -p dlp-user-ui                                 PASS
cargo clippy -p dlp-user-ui -- -D warnings                 PASS (clean)
cargo test -p dlp-user-ui -- --test-threads=1              PASS (23/23)
grep -c FOREGROUND_SLOT clipboard_monitor.rs               10 (>= 3 required)
grep SetWinEventHook clipboard_monitor.rs                  MATCH
grep UnhookWinEvent clipboard_monitor.rs                   MATCH
grep GetClipboardOwner clipboard_monitor.rs                MATCH
grep -c spawn_blocking clipboard_monitor.rs                5 (>= 2 required, SC-3 satisfied)
grep rt_handle clipboard_monitor.rs                        MATCH (capture + pass-through)
grep "source_identity.*Option.*AppIdentity" clipboard_monitor.rs  MATCH (classify_and_alert signature)
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] WINEVENT_OUTOFCONTEXT / WINEVENT_SKIPOWNPROCESS wrong module**
- **Found during:** cargo build Task 2
- **Issue:** Plan action imported these constants from `Win32::UI::Accessibility`. In windows-rs 0.58 they live in `Win32::UI::WindowsAndMessaging`.
- **Fix:** Moved `WINEVENT_OUTOFCONTEXT` and `WINEVENT_SKIPOWNPROCESS` to the `Win32::UI::WindowsAndMessaging` use block; kept only `SetWinEventHook` and `UnhookWinEvent` in the `Win32::UI::Accessibility` use.
- **Files modified:** `dlp-user-ui/src/clipboard_monitor.rs`
- **Commit:** 2cca0ff

**2. [Rule 1 - Bug] GetClipboardOwner returns Result<HWND>, not HWND**
- **Found during:** cargo build Task 2
- **Issue:** Plan action used `.is_invalid()` on the return value. `GetClipboardOwner` returns `windows_core::Result<HWND>` in windows-rs 0.58 — `is_invalid()` does not exist on `Result<T,E>`.
- **Fix:** Replaced with `GetClipboardOwner().ok()` which converts `Ok(hwnd)` to `Some(hwnd)` and `Err(_)` (NULL return) to `None`.
- **Files modified:** `dlp-user-ui/src/clipboard_monitor.rs`
- **Commit:** 2cca0ff

**3. [Rule 1 - Bug] HWND is not Send — cannot move directly into spawn_blocking closure**
- **Found during:** cargo build Task 2
- **Issue:** `HWND` is `*mut c_void` which does not implement `Send`. `tokio::task::spawn_blocking` requires `F: Send + 'static`. Plan action moved `HWND` directly into closures.
- **Fix:** Cast `hwnd.0 as usize` before each closure boundary (usize is `Copy + Send`). Reconstruct `HWND(raw as *mut core::ffi::c_void)` inside the closure. Safety: the usize is only used for Win32 API calls within the blocking thread; no aliasing or lifetime concerns.
- **Files modified:** `dlp-user-ui/src/clipboard_monitor.rs`
- **Commit:** 2cca0ff

**4. [Rule 1 - Bug] clippy redundant closure warning**
- **Found during:** cargo clippy Task 2
- **Issue:** `.map(|sh| crate::detection::app_identity::hwnd_to_pid(sh))` triggers `clippy::redundant_closure`.
- **Fix:** Replaced with `.map(crate::detection::app_identity::hwnd_to_pid)`.
- **Files modified:** `dlp-user-ui/src/clipboard_monitor.rs`
- **Commit:** 2cca0ff

**5. [Rule 1 - Bug] Integration tests broke on updated classify_and_alert signature**
- **Found during:** cargo test Task 2
- **Issue:** `dlp-user-ui/tests/clipboard_integration.rs` had 9 call sites using the 2-param `classify_and_alert(session_id, text)` signature.
- **Fix:** Updated all 9 call sites to pass `None, None` for the new identity parameters.
- **Files modified:** `dlp-user-ui/tests/clipboard_integration.rs`
- **Commit:** 2cca0ff

**6. [Rule 2 - Missing critical functionality] Remove #![allow(dead_code)] from app_identity.rs**
- **Found during:** cargo clippy Task 2 — after removing the allow, `resolve_app_identity_from_path` (test-only helper) triggered dead_code warning
- **Issue:** `resolve_app_identity_from_path` was only ever used inside `#[cfg(test)]` blocks in app_identity.rs. Without the module-level allow, clippy -D warnings rejected it.
- **Fix:** Gated `resolve_app_identity_from_path` under `#[cfg(test)]`. All production code paths use `resolve_app_identity` (HWND-based) directly.
- **Files modified:** `dlp-user-ui/src/detection/app_identity.rs`
- **Commit:** 2cca0ff

## Known Stubs

- `classify_and_alert` receives `source_identity` and `dest_identity` but suppresses them with `let _ = (source_identity, dest_identity)`. This is intentional — Plan 03 (25-03-PLAN.md) extends `send_clipboard_alert` to accept identity parameters. The data is fully resolved and available; only the forwarding to pipe3 is deferred.

## Threat Flags

No new threat surface beyond what is documented in the plan's `<threat_model>`. All four STRIDE threats addressed:
- T-25-01 (binary rename bypass): inherited from Plan 01, cache keyed by absolute path
- T-25-02 (WinVerifyTrust network block): inherited from Plan 01 WTD_REVOKE_NONE; additionally protected by spawn_blocking offload
- T-25-04 (DLP UI own window as destination): WINEVENT_SKIPOWNPROCESS prevents foreground_event_proc from firing on dlp-user-ui's own windows
- T-25-05 (dead-HWND race in source capture): GetClipboardOwner called synchronously at WM_CLIPBOARDUPDATE dispatch — earliest possible moment

## Self-Check: PASSED

- `dlp-user-ui/src/clipboard_monitor.rs` modified: CONFIRMED (277 insertions)
- `dlp-user-ui/src/detection/app_identity.rs` modified: CONFIRMED (#![allow(dead_code)] removed, resolve_app_identity_from_path gated)
- `dlp-user-ui/tests/clipboard_integration.rs` modified: CONFIRMED (9 call sites updated)
- Commit 2cca0ff exists: CONFIRMED
- `cargo test -p dlp-user-ui -- --test-threads=1`: 23/23 PASS
- `cargo clippy -p dlp-user-ui -- -D warnings`: CLEAN
- `grep -c FOREGROUND_SLOT clipboard_monitor.rs`: 10 (>= 3)
- `grep SetWinEventHook clipboard_monitor.rs`: MATCH
- `grep UnhookWinEvent clipboard_monitor.rs`: MATCH
- `grep GetClipboardOwner clipboard_monitor.rs`: MATCH
- `grep -c spawn_blocking clipboard_monitor.rs`: 5 (>= 2, SC-3 satisfied)
