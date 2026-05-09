# S03: Cloud Share Link Detection — Research

**Date:** 2026-05-09
**Scope:** Clipboard URL pattern matching + stricter ABAC context for sync-folder files (D012)

## Summary

S03 is a connector slice. The heavy infrastructure it needs already exists: `ClipboardListener` intercepts paste events in `dlp-agent/src/clipboard/listener.rs`, `CloudEnforcer` owns all four `CloudProvider` types and `resolve_sync_paths()` in `cloud_enforcer.rs`, and the ABAC `Action` enum in `dlp-common/src/abac.rs` is trivially extensible. What S03 adds is narrow: a share-link URL pattern matcher, a `ShareLinkEnforcer` that wraps the detection logic, and wiring into the clipboard pipeline so that `Alert` audit events fire for T3/T4 linked content.

The clipboard hook already runs in the user session (service-spawned UI process via `ui_spawner.rs`), so the share-link check happens in the right process. The `process_clipboard_text()` method in `ClipboardListener` is the natural insertion point — share-link detection runs there before the text is classified for content, and a detected link triggers its own audit path independently of content classification.

The "stricter ABAC policy for sync-folder files" mentioned in the milestone context is already partially delivered by S02: `CloudEnforcer::check()` now blocks T3/T4 writes to sync folders. S03 refines this only in the sense that clipboard share-link paste to an external application should also emit an `Alert`. No new ABAC policy engine changes are needed — the enforcer layer is sufficient.

## Recommendation

Build in two tasks:

1. **`share_link_enforcer.rs`** — pure logic module. Implement `detect_share_links(text) -> Vec<DetectedShareLink>` with per-provider URL patterns (no external deps; simple string matching is correct here). Add `ShareLinkEnforcer::check(links, classification) -> Option<ShareLinkAlertResult>` that returns `Some` for T3/T4. Add `Action::SHARE_LINK` to `dlp-common/src/abac.rs` with round-trip serde test per MEM026 convention.

2. **Clipboard wiring** — In `process_clipboard_text()`, after content classification, call `ShareLinkEnforcer::check()`. On `Some`, emit an `EventType::Alert` audit event with `Action::SHARE_LINK`. Service integration: construct `ShareLinkEnforcer` in `run_loop_init` (same pattern as `CloudEnforcer`), pass to `ClipboardListener` or to a new global context like `CLIPBOARD_EMIT_CONTEXT`. Add TC-34..TC-37 in `comprehensive.rs`.

Avoid: adding an HTTP fetch to validate URLs. Pattern matching on the URL string is enough — fetching would add latency to every paste and is blocked by enterprise proxies anyway.

## Implementation Landscape

### Key Files

- `dlp-agent/src/clipboard/listener.rs` — `process_clipboard_text()` at line 368 is the insertion point. Currently: classify → emit T2+ audit. S03 adds: classify → detect share links → emit share-link alert (if T3/T4 link) → emit content audit. `ClipboardEvent` struct (line 90) may need a `detected_share_links: Vec<DetectedShareLink>` field if downstream consumers need it, but audit emission can happen inline without changing the struct.
- `dlp-agent/src/clipboard/classifier.rs` — `ContentClassifier::classify()` is the existing pattern to follow for `detect_share_links()`. No changes needed to `classifier.rs`; share-link detection lives in a new module.
- `dlp-common/src/abac.rs` — Add `Action::SHARE_LINK` variant after `PRINT` (line 43). Follow MEM026: add a round-trip serde test. No other ABAC type changes required.
- `dlp-agent/src/cloud_enforcer.rs` — `CloudProvider` enum (line 33) is reused in `DetectedShareLink.provider`. Import only; no changes to `cloud_enforcer.rs` itself.
- `dlp-agent/src/service.rs` — Lines 873-874 init the clipboard emit context. If `ShareLinkEnforcer` needs runtime config, construct it here and store in `RunLoopContext`. If it's stateless (no config), construct it inline in `process_clipboard_text()` — it's cheap.
- `dlp-agent/tests/comprehensive.rs` — Add `mod share_link_tc` block after line 2624 with TC-34..TC-37.

### New File

- `dlp-agent/src/share_link_enforcer.rs` — New module (parallel to `cloud_enforcer.rs`). Contains:
  - `DetectedShareLink { provider: CloudProvider, url: String }` 
  - `detect_share_links(text: &str) -> Vec<DetectedShareLink>` — scans for URL substrings matching per-provider patterns
  - `ShareLinkAlertResult { provider: String, url: String, decision: Decision }` 
  - `ShareLinkEnforcer::check(links: &[DetectedShareLink], classification: Classification) -> Option<ShareLinkAlertResult>` — returns `Some` for T3/T4

### URL Patterns to Detect

| Provider | Pattern substrings |
|---|---|
| OneDrive | `1drv.ms/`, `onedrive.live.com/`, `sharepoint.com/` (shared links only — check for `/s/` or `?share=`) |
| Google Drive | `drive.google.com/drive/folders/`, `drive.google.com/file/d/`, `docs.google.com/` with sharing path |
| Dropbox | `dropbox.com/s/`, `dropbox.com/sh/`, `dropbox.com/scl/` |
| Box | `box.com/s/`, `app.box.com/s/` |

Simple substring matching on lowercased text is sufficient. A URL is "detected" if any of its known share-link substrings appear in the clipboard text. The first match per provider wins; a paste with two OneDrive links counts as one OneDrive detection.

### Build Order

1. **`dlp-common/src/abac.rs`** — Add `Action::SHARE_LINK` first. This unblocks the enforcer and tests that reference it.
2. **`dlp-agent/src/share_link_enforcer.rs`** — New module with pure detection logic. No Windows deps; fully unit-testable on any platform.
3. **`dlp-agent/src/clipboard/listener.rs`** — Wire `detect_share_links()` into `process_clipboard_text()`. Emit `EventType::Alert` with `Action::SHARE_LINK` for T3/T4 detected links.
4. **`dlp-agent/tests/comprehensive.rs`** — Add TC-34..TC-37.

### Verification Approach

```bash
# Unit tests for share_link_enforcer
cargo test -p dlp-agent share_link_enforcer

# Integration TC-34..TC-37
cargo test -p dlp-agent --test comprehensive -- share_link_tc

# Full build
cargo build --workspace

# Clippy
cargo clippy -p dlp-agent -p dlp-common -- -D warnings
```

Observable: TC-34 passes (T1 link → no alert), TC-35 passes (T3 link → alert), TC-36 passes (T4 link → alert), TC-37 passes (multiple providers in one paste → one alert per provider detected).

## Don't Hand-Roll

| Problem | Existing Solution | Why Use It |
|---------|------------------|------------|
| URL origin parsing | `to_origin()` in `dlp-agent/src/chrome/handler.rs` | Already parses `scheme://host` — usable if host-level matching is needed; but simple substring matching is cheaper and sufficient here |
| Cloud provider enum | `CloudProvider` in `cloud_enforcer.rs` | Reuse directly in `DetectedShareLink.provider` — avoids a parallel type |
| Audit emission | `emit_audit()` + `CLIPBOARD_EMIT_CONTEXT` in `listener.rs` | Already global and initialized; the share-link alert path uses the same `OnceLock` |

## Constraints

- `ClipboardListener` and its hook procedure run on a `std::thread`, not a tokio task — no `await` allowed inside `process_clipboard_text()`. All share-link detection must be synchronous.
- `CLIPBOARD_EMIT_CONTEXT` is a `OnceLock` — already set at service startup. Share-link audit events read from it without needing a new global.
- `CloudProvider` is defined in `cloud_enforcer.rs` (not in `dlp-common`) — import requires `use crate::cloud_enforcer::CloudProvider` in the new module. This is fine; both live in `dlp-agent`.
- MEM001: Clipboard monitoring runs in the user-session UI process, not in the SYSTEM service. The `ShareLinkEnforcer` must also live in that process — it does, since it's called from `ClipboardListener`.
- MEM026 convention: new `Action::SHARE_LINK` variant needs a serde round-trip test in `dlp-common/src/abac.rs`.

## Common Pitfalls

- **T1/T2 links should not alert** — The check is `classification >= T3`. A public OneDrive link (the file is classified T1) must not emit an alert. Classification comes from `ContentClassifier::classify(text)` applied to the full clipboard text, which may include the URL. URLs themselves won't trigger T3/T4 content patterns, but if the paste also contains SSN/CC numbers, classification will be T4 regardless of the link. That is correct behavior.
- **False positives from partial URL matches** — `dropbox.com` appears in login pages, error messages, etc. Anchor the match: require `dropbox.com/s/` or `dropbox.com/sh/` (share path prefix), not just the domain. The pattern table above uses share-specific paths to reduce false positives.
- **Multiple URLs in one paste** — A paste like "Here are two links: 1drv.ms/abc and dropbox.com/s/xyz" should emit two alert events (one per provider), or one combined event with both links. Easiest: emit one `Alert` per `DetectedShareLink` with the specific URL and provider — mirrors how `CloudEnforcer` emits per-file.
- **Empty `CLIPBOARD_EMIT_CONTEXT`** — The `OnceLock` is not set in unit tests. Guard with `.get()` (already the pattern in `listener.rs` line 399); tests exercise `ShareLinkEnforcer::check()` directly without needing the emit context.

## Open Risks

- The `ClipboardEvent` struct (line 90) does not carry detected share links. Downstream consumers of the `mpsc::Receiver<ClipboardEvent>` (if any) won't see link data. Currently no downstream consumer processes `ClipboardEvent` contents beyond the audit emission that already happens inline in `process_clipboard_text()`. Adding `detected_share_links` to the struct is optional for S03 — S05 can decide if it's needed for the end-to-end UAT.
