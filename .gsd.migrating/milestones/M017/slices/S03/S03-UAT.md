# S03: Cloud Share Link Detection — UAT

**Milestone:** M017
**Written:** 2026-05-09T01:19:49.871Z

# S03: Cloud Share Link Detection — UAT

**Milestone:** M017
**Written:** 2026-05-09

## UAT Type

- UAT mode: artifact-driven
- Why this mode is sufficient: The slice plan specifies Contract-level proof — unit tests and in-process integration tests exercise the full detection-to-audit-emission path using real ClipboardListener, real ShareLinkEnforcer, and real ABAC types. No live clipboard or external sync client is required at this level. Live smoke testing is deferred to S05 UAT.

## Preconditions

- `cargo build --workspace` exits 0
- `cargo clippy -p dlp-agent -- -D warnings` exits 0
- The `dlp-agent/tests/comprehensive.rs` test suite is present with `share_link_tc` and `cloud_tc` modules

## Smoke Test

Run `cargo test -p dlp-agent --test comprehensive -- share_link_tc` — all 4 tests must pass without errors.

## Test Cases

### TC-34: T1 OneDrive link — no alert

1. Invoke `ShareLinkEnforcer::check()` with a OneDrive share URL (`https://1drv.ms/u/...`) and classification `T1`.
2. **Expected:** Result is `None` (no enforcement action). No Alert audit event is emitted.

### TC-35: T3 OneDrive link — alert emitted

1. Invoke `ShareLinkEnforcer::check()` with a OneDrive share URL and classification `T3`.
2. **Expected:** Result is `Some(EnforcerResult { action: SHARE_LINK, decision: Deny, ... })`. Alert audit event is emitted with `source_origin` containing the truncated share URL and `destination_origin` containing the provider display name.

### TC-36: T4 Dropbox link — alert emitted

1. Invoke `ShareLinkEnforcer::check()` with a Dropbox share URL (`https://www.dropbox.com/s/...`) and classification `T4`.
2. **Expected:** Result is `Some(EnforcerResult { action: SHARE_LINK, decision: Deny, ... })`. Alert audit event is emitted.

### TC-37: T3 clipboard text with two provider links — two results

1. Call `detect_share_links()` on a clipboard string containing both a OneDrive and a Google Drive share URL, both at T3.
2. **Expected:** Two separate enforcer results are returned, one per provider. Duplicate provider URLs yield only the first result (first-wins dedup).

## Edge Cases

### Bare domain false positive (Box vs Dropbox)

1. Pass a clipboard string containing only `https://www.dropbox.com/s/abc123` with no Box link.
2. **Expected:** Only a Dropbox result is returned. No Box result, because Box patterns are anchored with `//` to avoid substring match against `dropbox`.

### URL embedded in prose

1. Pass `"Please review: https://1drv.ms/u/abc123 before the meeting"` at classification T3.
2. **Expected:** The full `https://1drv.ms/u/abc123` URL is extracted and appears in the audit event `source_origin`.

### Empty link set at T4

1. Pass clipboard text with no cloud share URLs at T4 classification.
2. **Expected:** `detect_share_links()` returns an empty vec. No Alert is emitted.

### Missing emit context

1. Call `process_clipboard_text()` without a populated `CLIPBOARD_EMIT_CONTEXT` when a T3 link is detected.
2. **Expected:** A `WARN` log is emitted noting the missing context. No panic or crash.

## Failure Signals

- Any TC-34..TC-37 test failure indicates a regression in detection or audit emission logic.
- `cargo clippy -p dlp-agent -- -D warnings` non-zero exit indicates a new lint issue was introduced.
- Missing `source_origin` or `destination_origin` in emitted Alert events indicates the AuditEvent wiring regressed.

## Not Proven By This UAT

- Live clipboard interception on a running Windows system — deferred to S05 UAT
- Real OneDrive/Dropbox/GDrive/Box share link formats from production (only representative patterns tested)
- SIEM ingestion of SHARE_LINK Alert events — deferred to S05
- Classification of the linked file's actual content (only the link's presence and clipboard classification are checked here)
- Performance under high-frequency clipboard change events

## Notes for Tester

The share_link_enforcer module is cross-platform; all tests run on any OS. The Box pattern anchor (`//box.com/s/`) is intentional — do not remove the `//` prefix or Dropbox URLs will generate false Box alerts. The `source_origin` / `destination_origin` field reuse is a deliberate deferral of dedicated audit metadata fields to a later phase.
