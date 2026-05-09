---
estimated_steps: 18
estimated_files: 2
skills_used: []
---

# T02: Wire ShareLinkEnforcer into ClipboardListener and add TC-34..TC-37

Wire share-link detection into process_clipboard_text() in dlp-agent/src/clipboard/listener.rs, then add TC-34..TC-37 to dlp-agent/tests/comprehensive.rs.

In process_clipboard_text() (currently at line 368), after the existing classification call and before the existing audit emission block, insert:
1. Call `detect_share_links(text)` — gets Vec<DetectedShareLink>
2. If non-empty, call `ShareLinkEnforcer.check(&links, classification)`
3. If Some(results), for each result emit an Alert audit event: AuditEvent::new() with EventType::Alert and Action::SHARE_LINK, set audit_metadata fields for provider and truncated URL, then emit_audit(ctx, &mut alert_event) using the existing CLIPBOARD_EMIT_CONTEXT.get() guard pattern (lines 399-417 of listener.rs)
4. Log each detected link at tracing::debug! before the check, and log T1/T2 pass-throughs at tracing::trace!

ShareLinkEnforcer is stateless — construct it inline (zero-cost) rather than storing in RunLoopContext.

Do NOT change the ClipboardEvent struct or the downstream channel send — share-link detection is an inline side-effect of the listener, not a struct field.

In dlp-agent/tests/comprehensive.rs, add mod share_link_tc after the cloud_tc module (after line 2584). The four tests:
- TC-34: T1 classification + OneDrive share link in text → check() returns None, no alert path taken
- TC-35: T3 classification + OneDrive share link (1drv.ms/) → check() returns Some with one result, Decision::Deny
- TC-36: T4 classification + Dropbox share link (dropbox.com/s/) → check() returns Some, Decision::Deny  
- TC-37: T3 classification + two providers in paste (1drv.ms/ and dropbox.com/s/) → check() returns Some with two results, one per provider

These tests call detect_share_links() and ShareLinkEnforcer::check() directly — they do not spin up the clipboard listener or emit context.

Constraints:
- No await in process_clipboard_text() — it runs on a std::thread, not a tokio task
- CLIPBOARD_EMIT_CONTEXT.get() must guard the alert emission (same as existing audit emission)
- Import share_link_enforcer types via crate::share_link_enforcer in listener.rs

## Inputs

- `dlp-agent/src/share_link_enforcer.rs`
- `dlp-agent/src/clipboard/listener.rs`
- `dlp-agent/tests/comprehensive.rs`

## Expected Output

- `dlp-agent/src/clipboard/listener.rs`
- `dlp-agent/tests/comprehensive.rs`

## Verification

cargo test -p dlp-agent --test comprehensive -- share_link_tc && cargo test -p dlp-agent --test comprehensive -- cloud_tc && cargo build --workspace && cargo clippy -p dlp-agent -- -D warnings
