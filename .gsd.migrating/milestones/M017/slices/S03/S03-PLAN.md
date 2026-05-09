# S03: Cloud Share Link Detection

**Goal:** Detect cloud share links pasted to clipboard and emit Alert audit events for T3/T4 linked content. Adds Action::SHARE_LINK to the ABAC enum, a pure ShareLinkEnforcer detection module, and wires it into the existing ClipboardListener pipeline.
**Demo:** Copy a https://1drv.ms/... link to clipboard → alert emitted if the linked file is T3/T4. Sync-folder files get stricter ABAC policy applied.

## Must-Haves

- TC-34 passes (T1 link — no alert), TC-35 passes (T3 link — alert emitted), TC-36 passes (T4 link — alert emitted), TC-37 passes (multi-provider paste — one Alert per detected provider). Workspace build clean. Clippy passes with -D warnings on dlp-agent and dlp-common.

## Proof Level

- This slice proves: Contract — unit tests and in-process integration tests exercise the full detection-to-audit-emission path using the real ClipboardListener, real ShareLinkEnforcer, and real ABAC types. No live clipboard or external sync client required.

## Integration Closure

Upstream consumed: CloudProvider enum from cloud_enforcer.rs, CLIPBOARD_EMIT_CONTEXT OnceLock from listener.rs, emit_audit() from listener.rs, ContentClassifier::classify() output (Classification value). New wiring: share_link_enforcer module declared in dlp-agent/src/lib.rs; process_clipboard_text() calls detect_share_links() then ShareLinkEnforcer::check() after content classification. What remains: S05 UAT must run a live smoke test where a user copies a real OneDrive share link and verifies the Alert event reaches the SIEM.

## Verification

- Alert audit events carry provider name and URL (truncated) in the audit context. tracing::debug! logs each detected share link and its classification before the Alert check. tracing::trace! on T1/T2 links that pass without alerting. CLIPBOARD_EMIT_CONTEXT.get() guard already in place — missing context logs at WARN level (existing pattern from listener.rs line 399).

## Tasks

- [x] **T01: Implement ShareLinkEnforcer detection module and add Action::SHARE_LINK** `est:45m`
  Add the Action::SHARE_LINK ABAC variant to dlp-common/src/abac.rs following the MEM026 pattern (variant + two serde round-trip tests). Create dlp-agent/src/share_link_enforcer.rs as a new pure-logic module with no Windows dependencies.
  - Files: `dlp-common/src/abac.rs`, `dlp-agent/src/share_link_enforcer.rs`, `dlp-agent/src/lib.rs`
  - Verify: cargo test -p dlp-common -- abac && cargo test -p dlp-agent share_link_enforcer -- --nocapture && cargo clippy -p dlp-common -p dlp-agent -- -D warnings

- [x] **T02: Wire ShareLinkEnforcer into ClipboardListener and add TC-34..TC-37** `est:45m`
  Wire share-link detection into process_clipboard_text() in dlp-agent/src/clipboard/listener.rs, then add TC-34..TC-37 to dlp-agent/tests/comprehensive.rs.
  - Files: `dlp-agent/src/clipboard/listener.rs`, `dlp-agent/tests/comprehensive.rs`
  - Verify: cargo test -p dlp-agent --test comprehensive -- share_link_tc && cargo test -p dlp-agent --test comprehensive -- cloud_tc && cargo build --workspace && cargo clippy -p dlp-agent -- -D warnings

## Files Likely Touched

- dlp-common/src/abac.rs
- dlp-agent/src/share_link_enforcer.rs
- dlp-agent/src/lib.rs
- dlp-agent/src/clipboard/listener.rs
- dlp-agent/tests/comprehensive.rs
