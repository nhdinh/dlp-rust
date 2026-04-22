---
phase: 25
slug: app-identity-capture-in-dlp-user-ui
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-22
---

# Phase 25 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (built-in) |
| **Config file** | none — existing infrastructure |
| **Quick run command** | `cargo test -p dlp-user-ui -- --test-threads=1` |
| **Full suite command** | `cargo test --workspace -- --test-threads=1` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-user-ui -- --test-threads=1`
- **After every plan wave:** Run `cargo test --workspace -- --test-threads=1`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 25-01-01 | 01 | 1 | APP-06 | Cache poisoning | Cache miss runs WinVerifyTrust; hit skips it | unit | `cargo test -p dlp-user-ui test_authenticode_cache_hit` | ❌ W0 | ⬜ pending |
| 25-01-02 | 01 | 1 | APP-06 | Binary rename bypass | Renamed binary = new cache miss + re-verify | unit | `cargo test -p dlp-user-ui test_renamed_binary_cache_miss` | ❌ W0 | ⬜ pending |
| 25-01-03 | 01 | 1 | APP-06 | — | Unsigned binary → NotSigned → Untrusted tier | unit | `cargo test -p dlp-user-ui test_unsigned_binary_untrusted` | ❌ W0 | ⬜ pending |
| 25-02-01 | 02 | 1 | APP-02 | Dead HWND race | NULL GetClipboardOwner → source = None | unit | `cargo test -p dlp-user-ui test_null_clipboard_owner_gives_none` | ❌ W0 | ⬜ pending |
| 25-02-02 | 02 | 1 | APP-02 | Dead HWND race | Dead HWND (pid=0) → Some(AppIdentity::default()) | unit | `cargo test -p dlp-user-ui test_dead_hwnd_gives_unknown_identity` | ❌ W0 | ⬜ pending |
| 25-02-03 | 02 | 1 | APP-01 | — | Foreground slot cleared after each clipboard event | unit | `cargo test -p dlp-user-ui test_foreground_slot_cleared_after_read` | ❌ W0 | ⬜ pending |
| 25-02-04 | 02 | 1 | APP-01/02 | — | Intra-app copy: dest == source identity (same PID) | unit | `cargo test -p dlp-user-ui test_intraapp_copy_dest_equals_source` | ❌ W0 | ⬜ pending |
| 25-03-01 | 03 | 2 | APP-05 | — | ClipboardAlert wire includes source/dest AppIdentity | unit | `cargo test -p dlp-user-ui test_clipboard_alert_includes_identity` | ❌ W0 | ⬜ pending |
| 25-03-02 | 03 | 2 | APP-05 | — | classify_and_alert passes identity to send_clipboard_alert | unit | `cargo test -p dlp-user-ui test_classify_and_alert_passes_identity` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `dlp-user-ui/src/detection/mod.rs` — new module file declaring `pub mod app_identity`
- [ ] `dlp-user-ui/src/detection/app_identity.rs` — stubs for `resolve_app_identity`, `verify_and_cache`, `AUTHENTICODE_CACHE`, `build_app_identity_from_path`, with inline `#[cfg(test)]` module containing all unit test stubs
- [ ] Update `dlp-user-ui/src/lib.rs` — add `mod detection;`
- [ ] Update existing `classify_and_alert` test helpers — pass `None, None` for new identity parameters

*Existing infrastructure covers test runner — no new test crate needed.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `WinVerifyTrust` returns correct `SignatureState` for a signed binary | APP-06 | Requires a signed executable on the test machine (e.g. `notepad.exe`) | Run test binary, check log output shows `SignatureState::Valid` and non-empty publisher for `C:\Windows\System32\notepad.exe` |
| `SetWinEventHook` fires on window switch | APP-01 (D-01) | Requires live Win32 session with focus changes | Launch dlp-user-ui, switch windows, copy text — verify ClipboardAlert includes destination `image_path` |
| `GetClipboardOwner` captured before source exits | APP-02 | Race condition testing requires a fast-exit source process | Use a script that copies to clipboard then exits immediately; verify source identity is populated in audit log |
