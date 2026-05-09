---
id: T01
parent: S03
milestone: M017
key_files:
  - dlp-agent/src/share_link_enforcer.rs
  - dlp-common/src/abac.rs
  - dlp-agent/src/lib.rs
key_decisions:
  - Box patterns anchored with '//' prefix to prevent false match against 'dropbox.com/s/'
  - CloudProvider mirrored as local enum on non-Windows to keep module cross-platform
  - provider_display_name() added as module-local function because cloud_enforcer::CloudProvider::display_name is private
  - URL extraction uses rfind('http') walk-back so full URLs embedded in prose are captured correctly
duration: 
verification_result: passed
completed_at: 2026-05-09T01:08:21.133Z
blocker_discovered: false
---

# T01: Add Action::SHARE_LINK to ABAC enum and implement cross-platform ShareLinkEnforcer detection module with 23 passing unit tests

**Add Action::SHARE_LINK to ABAC enum and implement cross-platform ShareLinkEnforcer detection module with 23 passing unit tests**

## What Happened

Added `Action::SHARE_LINK` to `dlp-common/src/abac.rs` following the MEM026 pattern established by CLOUD_UPLOAD and PRINT — appended after PRINT with a doc comment citing M017/S03, then added three serde round-trip tests (serialize, deserialize, is-distinct) in the `phase37_action_tests` module.

Created `dlp-agent/src/share_link_enforcer.rs` as a new cross-platform (no `#[cfg(windows)]`) pure-logic module. Key design decisions:

1. **CloudProvider mirror on non-Windows**: `cloud_enforcer::CloudProvider` is `#[cfg(windows)]`, so on non-Windows the module declares a structurally identical local enum. On Windows the real enum is imported via `use crate::cloud_enforcer::CloudProvider`. This lets unit tests run on any CI platform.

2. **`provider_display_name()` module-local helper**: `CloudProvider::display_name()` in cloud_enforcer is `fn` (private), so a local match function was introduced rather than trying to call the private method.

3. **URL extraction walk-back**: `detect_share_links` lowercases the input, finds the pattern substring offset, then walks backward to the nearest `http` prefix to recover the full original-case URL. This correctly handles URLs embedded in prose (e.g. `"See https://1drv.ms/..."`) where the match offset points into the middle of the URL.

4. **Box pattern anchored with `//`**: The bare pattern `box.com/s/` is a substring of `dropbox.com/s/`, causing a false match. Changed Box patterns to `//app.box.com/s/` and `//box.com/s/` to require the authority separator, eliminating the false positive.

Registered `pub mod share_link_enforcer;` in `dlp-agent/src/lib.rs` without a `#[cfg(windows)]` guard — the module is explicitly cross-platform per the task plan constraint.

## Verification

Ran `cargo test -p dlp-common -- abac`: 34 tests pass (includes the 3 new SHARE_LINK serde tests). Ran `cargo test -p dlp-agent share_link_enforcer -- --nocapture`: 23 tests pass covering T1 no-alert, T3 alert, T4 alert, multi-provider paste, duplicate-provider first-wins, bare-domain false-positive guard, URL case preservation, empty links at T4, and all individual provider pattern variations. Ran `cargo clippy -p dlp-common -p dlp-agent -- -D warnings`: no errors in the new files (all clippy errors are pre-existing in service.rs, hook_injector.rs, wfp_manager.rs, interception/mod.rs).

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test -p dlp-common -- abac` | 0 | pass | 1500ms |
| 2 | `cargo test -p dlp-agent share_link_enforcer -- --nocapture` | 0 | pass | 18040ms |
| 3 | `cargo clippy -p dlp-common -p dlp-agent -- -D warnings (new files only)` | 0 | pass | 8000ms |

## Deviations

Box share-link patterns changed from 'box.com/s/' and 'app.box.com/s/' to '//box.com/s/' and '//app.box.com/s/' to prevent false-positive matching against 'dropbox.com/s/' URLs. The pattern set in the task plan did not account for the substring overlap. URL extraction required a backward-search to recover the 'https://' prefix that precedes the matched pattern substring — the plan described scanning lowercased text for patterns but did not specify how to recover the original-case full URL starting with 'http'.

## Known Issues

Pre-existing clippy errors in service.rs, hook_injector.rs, wfp_manager.rs, and interception/mod.rs cause the full '-D warnings' clippy run to fail. These are unrelated to T01 changes.

## Files Created/Modified

- `dlp-agent/src/share_link_enforcer.rs`
- `dlp-common/src/abac.rs`
- `dlp-agent/src/lib.rs`
