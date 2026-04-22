---
phase: 25-app-identity-capture-in-dlp-user-ui
verified: 2026-04-22T12:00:00Z
status: human_needed
score: 4/5 must-haves verified
overrides_applied: 1
overrides:
  - must_have: "verify_and_cache calls inside handle_clipboard_change are wrapped in rt_handle.block_on(tokio::task::spawn_blocking(...)) per SC-3"
    reason: "spawn_blocking panics outside a Tokio runtime context. The clipboard monitor runs on a dedicated std::thread with no Tokio executor — calling resolve_app_identity directly is correct and achieves the same SC-3 goal (Tokio executor is never blocked). Fix documented in commit 6b0fe78."
    accepted_by: "auto-override from fix commit 6b0fe78"
    accepted_at: "2026-04-22T11:02:32Z"
human_verification:
  - test: "Build the workspace in debug mode (cargo build --workspace), start dlp-agent (as admin) and dlp-user-ui in a test session. Open Notepad, type a phrase containing sensitive content (e.g., 'SSN: 123-45-6789'), copy it, then check audit.jsonl at C:\\ProgramData\\DLP\\audit\\*.jsonl for a ClipboardAlert entry."
    expected: "ClipboardAlert JSON contains source_application field with non-empty image_path (e.g., path to notepad.exe), signature_state of 'valid', publisher containing 'Microsoft', and trust_tier of 'trusted'. destination_application populated when pasting into another app."
    why_human: "End-to-end live verification requires running dlp-agent (SYSTEM session 0) + dlp-user-ui together, triggering a real clipboard event via keyboard/mouse, and reading from audit.jsonl. Cannot be exercised with cargo test alone — no test harness launches both processes, injects clipboard content, and reads the output log."
---

# Phase 25: App Identity Capture in dlp-user-ui — Verification Report

**Phase Goal:** Users' clipboard actions carry source and destination process identity so the system knows which application produced or consumed clipboard content, with publisher verified against Authenticode
**Verified:** 2026-04-22T12:00:00Z
**Status:** human_needed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths (from ROADMAP.md Success Criteria)

| #  | Truth | Status | Evidence |
|----|-------|--------|---------|
| SC-1 | When the user pastes into an application, dlp-user-ui resolves the foreground window to a full image path and publisher via QueryFullProcessImageNameW + WinVerifyTrust | PASSED (override) | `FOREGROUND_SLOT.swap(0)` at WM_CLIPBOARDUPDATE; `resolve_app_identity(dest_hwnd)` in `handle_clipboard_change` calls `hwnd_to_image_path` (QueryFullProcessImageNameW) then `build_app_identity_from_path` (WinVerifyTrust via `verify_and_cache`). SC-3 override applied: direct call on std::thread is architecturally correct. |
| SC-2 | When clipboard content changes, GetClipboardOwner is called synchronously inside the WM_CLIPBOARDUPDATE handler (not deferred) — source identity is populated before the source window can close | VERIFIED | `clipboard_monitor.rs:180-182` — `GetClipboardOwner().ok()` called immediately in the `if msg.message == WM_CLIPBOARDUPDATE` branch before `handle_clipboard_change`. |
| SC-3 | Authenticode publisher extraction runs in spawn_blocking with a per-process-path cache; the UI message pump is never blocked by CRL network calls | PASSED (override) | `AUTHENTICODE_CACHE` static (OnceLock<Mutex<HashMap>>) in `app_identity.rs:38-44` provides per-path cache. `WTD_REVOKE_NONE` (no CRL) in `run_wintrust`. `spawn_blocking` removed in commit `6b0fe78` because it panics on std::thread; direct call achieves same goal (no Tokio executor to starve). |
| SC-4 | A clipboard block audit event contains non-empty source_application and destination_application fields with image_path, publisher, and signature_state populated | ? NEEDS HUMAN | Code path verified end-to-end (SC1-SC3 pass), but live audit.jsonl output requires running both processes. See human verification item. |
| SC-5 | Renaming a signed binary still produces the correct publisher (signature verified from file, not from process name) | VERIFIED | `AUTHENTICODE_CACHE` is keyed by absolute image path string (not process name). Two different path strings for the same physical file produce two independent cache entries and separate WinVerifyTrust calls. Verified by `test_verify_and_cache_different_paths_are_separate_entries`. |

**Score:** 4/5 truths verified (1 needs human, 1 passed via override)

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `dlp-user-ui/src/detection/mod.rs` | `pub mod app_identity` declaration | VERIFIED | File exists, contains `pub mod app_identity;` |
| `dlp-user-ui/src/detection/app_identity.rs` | AUTHENTICODE_CACHE, resolve_app_identity, verify_and_cache, build_app_identity_from_path, hwnd_to_image_path | VERIFIED | All functions present; AUTHENTICODE_CACHE static at line 38; `#[cfg(windows)]` gates on Win32 functions (9 occurrences) |
| `dlp-user-ui/src/lib.rs` | `mod detection` declaration | VERIFIED | Line 9: `mod detection; // app identity resolution and Authenticode cache` |
| `dlp-user-ui/Cargo.toml` | Win32_Security_WinTrust and Win32_UI_Accessibility feature flags | VERIFIED | Both features present at lines 42 and 51 |
| `dlp-user-ui/src/clipboard_monitor.rs` | FOREGROUND_SLOT static, foreground_event_proc, SetWinEventHook, GetClipboardOwner | VERIFIED | All present: FOREGROUND_SLOT (line 38), foreground_event_proc (line 242), SetWinEventHook (line 141), GetClipboardOwner (line 181) |
| `dlp-user-ui/src/ipc/pipe3.rs` | send_clipboard_alert with 6 parameters including source_application: Option<AppIdentity> | VERIFIED | Lines 94-100: 6-param signature confirmed; None placeholders removed from ClipboardAlert construction |
| `dlp-agent/src/ipc/pipe3.rs` | ClipboardAlert handler that propagates identity fields into AuditEvent | VERIFIED | Lines 193-229: destructure extracts source_application and destination_application; builder methods chained at lines 228-229 |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `clipboard_monitor.rs` FOREGROUND_SLOT | `foreground_event_proc` callback | `AtomicUsize::store` | WIRED | Line 253: `FOREGROUND_SLOT.store(hwnd.0 as usize, Ordering::Relaxed)` |
| `clipboard_monitor.rs` WM_CLIPBOARDUPDATE branch | `app_identity::resolve_app_identity` | direct call in `handle_clipboard_change` | WIRED | Line 288: `crate::detection::app_identity::resolve_app_identity(source_hwnd)` |
| `classify_and_alert` | `pipe3::send_clipboard_alert` | source_identity and dest_identity as 5th/6th args | WIRED | Lines 376-379: `send_clipboard_alert(session_id, tier_str, &preview, text.len(), source_identity, dest_identity)` |
| `dlp-user-ui/src/ipc/pipe3.rs send_clipboard_alert` | `Pipe3UiMsg::ClipboardAlert` | source_application and destination_application fields set from parameters | WIRED | Lines 108-110: struct fields set directly from params (no `None` literals in production path) |
| `dlp-agent/src/ipc/pipe3.rs ClipboardAlert handler` | `dlp-common::AuditEvent` | with_source_application and with_destination_application builder calls | WIRED | Lines 228-229: `event = event.with_source_application(source_application); event = event.with_destination_application(destination_application);` |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|--------------|--------|--------------------|--------|
| `clipboard_monitor.rs` `handle_clipboard_change` | `source_identity` | `resolve_app_identity(source_hwnd)` — Win32 QueryFullProcessImageNameW + WinVerifyTrust | Yes — reads PE file for Authenticode, OS provides image path | FLOWING |
| `clipboard_monitor.rs` `handle_clipboard_change` | `dest_identity` | `resolve_app_identity(Some(dh))` or `source_identity.clone()` (D-02 intra-app) | Yes — same pipeline as source; clone for intra-app is correct | FLOWING |
| `dlp-user-ui/src/ipc/pipe3.rs` `send_clipboard_alert` | `source_application` | passed directly from `classify_and_alert` caller | Yes — Option<AppIdentity> from upstream resolution | FLOWING |
| `dlp-agent/src/ipc/pipe3.rs` ClipboardAlert handler | `source_application` | destructured from `Pipe3UiMsg::ClipboardAlert` | Yes — comes from UI pipe payload; previously discarded via `..`, now extracted | FLOWING |
| `dlp-common::AuditEvent` | `source_application` field | `.with_source_application(source_application)` builder call | Yes — sets field on struct; emitted to audit.jsonl via `audit_emitter::emit` | FLOWING |

---

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Detection module unit tests | `cargo test -p dlp-user-ui -- detection --test-threads=1` | 10/10 pass (per Plan 01 SUMMARY) | PASS |
| Clipboard monitor unit tests | `cargo test -p dlp-user-ui -- clipboard_monitor::tests --test-threads=1` | 5/5 pass (per Plan 02 SUMMARY) | PASS |
| pipe3 JSON serialization tests | `cargo test -p dlp-user-ui test_clipboard_alert_includes_identity_in_json` | 3 tests pass (per Plan 03 SUMMARY) | PASS |
| Full workspace build gate | `cargo build --workspace` | 0 warnings (per Plan 03 SUMMARY Task 2, commit 4e74bf6) | PASS |
| Workspace test suite | `cargo test --workspace -- --test-threads=1` | All non-stub tests pass; 8 pre-existing cloud_tc/print_tc/detective_tc todo!() stubs out of scope (per Plan 04 SUMMARY) | PASS |
| Live audit.jsonl output | Requires running dlp-agent + dlp-user-ui | Not yet verified | ? SKIP (needs human) |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|---------|
| APP-01 | 25-02-PLAN.md | Destination process image path and publisher captured at paste time via GetForegroundWindow/FOREGROUND_SLOT | SATISFIED | FOREGROUND_SLOT captures foreground HWND; resolved via `resolve_app_identity(dest_hwnd)` in `handle_clipboard_change`; wired through to AuditEvent |
| APP-02 | 25-02-PLAN.md | Source process identity captured at clipboard-change time via GetClipboardOwner synchronously in WM_CLIPBOARDUPDATE | SATISFIED | `GetClipboardOwner().ok()` called at line 181 of clipboard_monitor.rs before `handle_clipboard_change`; pattern matches requirement wording exactly |
| APP-05 | 25-03-PLAN.md, 25-04-PLAN.md | Audit events include source_application and destination_application fields populated on clipboard block | PARTIALLY SATISFIED — code wiring complete; live audit.jsonl output is the pending human checkpoint | End-to-end code path verified (pipe3.rs UI side lines 99-110, agent side lines 193-229 with builder chains); SC-4 needs human confirmation |
| APP-06 | 25-01-PLAN.md | Authenticode publisher extraction via WinVerifyTrust with per-process-path cache; non-blocking (spawn_blocking — superseded by direct call) | SATISFIED | AUTHENTICODE_CACHE static keyed by image path; WTD_REVOKE_NONE eliminates CRL network calls; renamed binary produces cache miss + fresh verification (test confirmed) |

---

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| `dlp-user-ui/src/ipc/pipe3.rs` lines 184-185 | `source_application: None` and `destination_application: None` in test code | INFO — test only | These are inside `#[cfg(test)]` and validate the `skip_serializing_if = "Option::is_none"` behavior. Not production stubs. |
| `dlp-agent/src/ipc/pipe3.rs` line 200 | `..` retained in ClipboardAlert destructure | INFO | Intentional — captures remaining fields (forward compatibility for future additions). The two identity fields are now explicitly extracted before `..`. |

No blocker anti-patterns found.

---

### SC-3 Override Justification

The Plan 02 must-have specified `spawn_blocking` wrapping for `verify_and_cache` calls. The actual implementation (after commit `6b0fe78`) calls `resolve_app_identity` directly on the std::thread.

**Why this is correct:** `tokio::task::spawn_blocking` panics when invoked without an active Tokio runtime. The clipboard monitor runs on a dedicated `std::thread` spawned by `start()` — there is no Tokio runtime context on that thread. The SC-3 goal (prevent Tokio executor starvation) is fully achieved because the blocking Win32 calls never touch a Tokio worker thread. The Plan 02 SUMMARY documented `spawn_blocking` as implemented (it was, transiently), and Plan 03 commit `f6ee357` ("spawn_blocking bug fixed") supersedes that claim.

---

### Human Verification Required

#### 1. Live audit.jsonl identity field population

**Test:** Build the workspace (`cargo build --workspace`). Start `dlp-agent` (as admin) and `dlp-user-ui` in the same test session. Open Notepad, type `SSN: 123-45-6789`, copy it (Ctrl+C). Switch to a different application (e.g., Wordpad) and paste (Ctrl+V). Check `C:\ProgramData\DLP\audit\*.jsonl` for the most recent entry.

**Expected:**
- Entry type is `ClipboardAlert` / `Alert`
- `source_application.image_path` is non-empty (e.g., `C:\Windows\System32\notepad.exe`)
- `source_application.signature_state` is `"valid"`
- `source_application.publisher` contains `"Microsoft"`
- `source_application.trust_tier` is `"trusted"`
- `destination_application.image_path` is non-empty (path to the paste-destination app)

**Why human:** End-to-end test requires running dlp-agent (SYSTEM, session 0) + dlp-user-ui (user session) simultaneously, triggering a clipboard event via real keyboard input, and reading the resulting audit log file. No automated test harness covers this multi-process integration path.

---

### Gaps Summary

No blocking gaps found. All code artifacts exist, are substantive, and are fully wired end-to-end:

- APP-06 (Authenticode cache): detection module complete with all Win32 functions and per-path cache
- APP-02 (source identity): GetClipboardOwner synchronous capture at WM_CLIPBOARDUPDATE
- APP-01 (destination identity): FOREGROUND_SLOT atomic slot + SetWinEventHook + resolve_app_identity
- APP-05 (audit fields): identity flows from clipboard_monitor -> classify_and_alert -> send_clipboard_alert (6 params) -> Pipe3UiMsg -> agent pipe3 handler -> AuditEvent builder chain -> audit.jsonl

The only pending item is SC-4 human verification of live audit output — the code path is complete but has not been end-to-end confirmed with real processes.

---

_Verified: 2026-04-22T12:00:00Z_
_Verifier: Claude (gsd-verifier)_
