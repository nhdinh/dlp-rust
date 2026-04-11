# Phase 99 Plan: Clipboard Monitoring Integration Tests

## Summary

Add a full end-to-end integration test suite for the clipboard
monitoring feature. Uses real Win32 clipboard and a mock named-pipe
server on a unique per-run pipe name.

## Files to Modify

### Production code
- `dlp-user-ui/src/ipc/pipe3.rs` — read optional pipe name override via env var
- `dlp-user-ui/src/clipboard_monitor.rs` — expose a public helper to classify
  and emit a ClipboardAlert for a given text string (without needing a
  running message loop), enabling direct testing

### Tests
- `dlp-user-ui/tests/clipboard_integration.rs` — new integration test file

### Cargo
- `dlp-user-ui/Cargo.toml` — add `uuid` and `tempfile` to dev-dependencies

## Implementation Steps

### Step 1: Parameterize Pipe 3 pipe name

In `dlp-user-ui/src/ipc/pipe3.rs`:

```rust
const PIPE_NAME_DEFAULT: &str = r"\\.\pipe\DLPEventUI2Agent";

fn pipe_name() -> String {
    std::env::var("DLP_PIPE3_NAME")
        .unwrap_or_else(|_| PIPE_NAME_DEFAULT.to_string())
}
```

Replace the `PIPE_NAME` constant with a call to `pipe_name()` inside
`open_pipe()`.

### Step 2: Add test helper to clipboard_monitor.rs

Expose a public (crate-visible) function that performs the classify +
send-alert path without needing a message loop:

```rust
#[cfg(test)]
pub fn classify_and_alert_for_test(
    session_id: u32,
    text: &str,
) -> anyhow::Result<Option<&'static str>> {
    // Returns Some(tier) if an alert was sent, None if ignored.
    // Uses the same logic as handle_clipboard_change but without dedup.
}
```

Or simpler: move the logic from `handle_clipboard_change` into a
public helper `fn classify_text_and_send(session_id, text, last_hash)
-> Option<&'static str>` that the test can call directly.

### Step 3: Add dev-dependencies

In `dlp-user-ui/Cargo.toml`:

```toml
[dev-dependencies]
uuid = { workspace = true }
```

### Step 4: Create `dlp-user-ui/tests/clipboard_integration.rs`

**Structure:**

```rust
#![cfg(windows)]

//! End-to-end integration tests for clipboard monitoring.

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Test helpers
mod helpers {
    /// Starts a mock Pipe 3 named-pipe server on a unique name.
    /// Returns the pipe name + a receiver that yields messages.
    pub fn start_mock_pipe_server() -> (String, Arc<Mutex<Vec<String>>>) { ... }

    /// Writes text to the Windows clipboard.
    pub fn set_clipboard_text(text: &str) { ... }

    /// Clears the Windows clipboard.
    pub fn clear_clipboard() { ... }
}

#[test]
fn test_ssn_triggers_t4_alert() { ... }

#[test]
fn test_credit_card_triggers_t4_alert() { ... }

#[test]
fn test_confidential_triggers_t3_alert() { ... }

#[test]
fn test_internal_triggers_t2_alert() { ... }

#[test]
fn test_ordinary_text_no_alert() { ... }

#[test]
fn test_duplicate_deduplicated() { ... }

#[test]
fn test_empty_clipboard_ignored() { ... }

#[test]
fn test_non_text_clipboard_ignored() { ... }
```

**Mock pipe server approach:**

Use `windows::Win32::System::Pipes::CreateNamedPipeW` to create a
named pipe server. Accept one connection per test, read one frame,
parse the JSON, and store it in a `Mutex<Vec<String>>` for the test
to assert on.

```rust
fn start_mock_pipe_server() -> (String, Arc<Mutex<Vec<String>>>) {
    let name = format!(r"\\.\pipe\DLPEventUI2Agent-test-{}", Uuid::new_v4());
    let messages = Arc::new(Mutex::new(Vec::new()));
    let messages_clone = Arc::clone(&messages);
    let name_clone = name.clone();

    thread::spawn(move || {
        // Create server pipe
        // ConnectNamedPipe (blocking)
        // ReadFile for length-prefixed frame
        // Append JSON string to messages_clone
    });

    // Give the server a moment to start listening.
    thread::sleep(Duration::from_millis(100));
    (name, messages)
}
```

**Clipboard injection helpers:**

Use `OpenClipboard`, `EmptyClipboard`, `SetClipboardData(CF_UNICODETEXT)`,
`CloseClipboard` directly. Wrap the Unicode text in a GlobalAlloc
buffer.

**Each test flow:**

1. Save current clipboard state (for restoration)
2. `let (pipe_name, messages) = start_mock_pipe_server()`
3. `std::env::set_var("DLP_PIPE3_NAME", &pipe_name)`
4. `set_clipboard_text("SSN: 123-45-6789")`
5. Call `clipboard_monitor::classify_text_and_send(session_id, text, ...)`
   directly (bypasses the message loop)
6. Wait up to 500ms for the message to appear in `messages`
7. Assert the ClipboardAlert JSON contains `classification: "T4"`
8. Restore original clipboard state
9. `std::env::remove_var("DLP_PIPE3_NAME")`

**Cleanup / isolation:**

- Each test uses a unique pipe name (UUID).
- Tests MUST run sequentially (use `serial_test` crate or mark each
  test as `#[serial]`) because they share process-wide state
  (clipboard + env var). Add `serial_test = "3"` to dev-dependencies
  and `#[serial]` to each test.

### Step 5: Adjust dev-dependencies

Add to `dlp-user-ui/Cargo.toml`:

```toml
[dev-dependencies]
uuid = { workspace = true }
serial_test = "3"
```

### Step 6: Update CI (if applicable)

If a GitHub Actions workflow exists, ensure the Windows runner has
interactive desktop access. Clipboard APIs require `session >= 1`
with a window station. `windows-latest` runners typically work but
verify.

## Verification

```
cargo test --package dlp-user-ui --test clipboard_integration
cargo clippy --package dlp-user-ui --tests -- -D warnings
```

## UAT Criteria

- [ ] `dlp-user-ui/tests/clipboard_integration.rs` exists with 8 test cases
- [ ] Tests use `#[serial]` to prevent clipboard race conditions
- [ ] Each test uses a unique named pipe (UUID-suffixed)
- [ ] Pipe 3 pipe name can be overridden via `DLP_PIPE3_NAME` env var
- [ ] All 8 tests pass on a Windows machine with interactive desktop
- [ ] Clippy clean (package-level)
- [ ] Tests restore original clipboard state after running
- [ ] CI Windows runner configured to run these tests

## Risks

1. **Clipboard race conditions** — other apps may modify the clipboard
   during tests. Mitigation: `#[serial]` + short-lived test windows.
2. **Pipe server race** — the UI sender might connect before the
   server calls `ConnectNamedPipe`. Mitigation: 100ms warmup sleep
   after `start_mock_pipe_server`.
3. **CI interactive desktop** — headless Windows CI may fail clipboard
   access. Mitigation: verify `windows-latest` runner supports
   clipboard; if not, use `#[ignore]` and run locally.
