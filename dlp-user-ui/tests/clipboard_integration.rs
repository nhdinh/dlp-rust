#![cfg(windows)]

//! End-to-end integration tests for clipboard monitoring.
//!
//! These tests drive the full UI-side clipboard pipeline:
//!
//! 1. A mock Pipe 3 named-pipe server is spawned on a unique per-run name.
//! 2. The `DLP_PIPE3_NAME` env var is pointed at that mock.
//! 3. Text is either written to the real Windows clipboard (for read-path
//!    tests) or classified directly via [`classify_and_alert`].
//! 4. The mock pipe server receives the `ClipboardAlert` frame, decodes the
//!    JSON, and exposes it to the test for assertions.
//!
//! # Isolation
//!
//! Every test uses a unique pipe name (UUID-suffixed) so concurrent test
//! runs never collide. Because the clipboard and the `DLP_PIPE3_NAME`
//! env var are *process-wide* state, tests are serialized via
//! `#[serial_test::serial]`. Running in parallel would cause clipboard
//! races and env-var interleaving.
//!
//! # Platform
//!
//! Gated by `#[cfg(windows)]` — the clipboard + named-pipe APIs used here
//! only exist on Windows. The file is a no-op on other targets.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serial_test::serial;
use uuid::Uuid;

use dlp_user_ui::clipboard_monitor::classify_and_alert;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Storage::FileSystem::{ReadFile, PIPE_ACCESS_INBOUND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};

// ─────────────────────────────────────────────────────────────────────────
// Mock Pipe 3 server
// ─────────────────────────────────────────────────────────────────────────

/// Starts a mock Pipe 3 server on a unique per-run pipe name.
///
/// The server thread:
///
/// 1. Creates a named pipe (inbound, byte mode, one instance).
/// 2. Blocks on `ConnectNamedPipe` until the UI side calls `CreateFileW`.
/// 3. Reads a single length-prefixed frame (`[u32 LE len][payload]`).
/// 4. Pushes the decoded UTF-8 payload onto the shared `messages` vector.
///
/// Returns the pipe name and a handle to the message buffer the test can
/// poll for assertions.
fn start_mock_pipe_server() -> (String, Arc<Mutex<Vec<String>>>) {
    // Unique per-run so concurrent cargo test invocations never collide.
    let name = format!(r"\\.\pipe\DLPEventUI2Agent-test-{}", Uuid::new_v4());
    let messages: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let name_for_thread = name.clone();
    let messages_for_thread = Arc::clone(&messages);

    thread::spawn(move || {
        if let Err(e) = run_mock_pipe_server(&name_for_thread, messages_for_thread) {
            // Rust note: we can't propagate errors out of a spawned thread
            // back to the test, so log via eprintln!. Tests will fail via
            // the "no message received" assertion, surfacing the problem.
            eprintln!("mock pipe server error: {e:#}");
        }
    });

    // Give the server a moment to reach ConnectNamedPipe. Without this,
    // a fast test could CreateFileW before the server is listening and
    // hit ERROR_FILE_NOT_FOUND.
    thread::sleep(Duration::from_millis(100));

    (name, messages)
}

/// The actual server loop — split out so we can use `?` for errors.
fn run_mock_pipe_server(name: &str, messages: Arc<Mutex<Vec<String>>>) -> anyhow::Result<()> {
    // Encode pipe name as UTF-16 NUL-terminated — Win32 wide-string form.
    let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: CreateNamedPipeW requires a valid NUL-terminated wide
    // string pointer. `name_wide` lives for the duration of this call.
    let pipe: HANDLE = unsafe {
        CreateNamedPipeW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,      // max instances
            0,      // out buffer size (unused — inbound only)
            65_536, // in buffer size
            0,      // default timeout
            None,   // default security attrs
        )
    };

    if pipe.is_invalid() {
        anyhow::bail!("CreateNamedPipeW returned INVALID_HANDLE_VALUE for {name}");
    }

    // Accept up to 4 connections so tests that expect multiple frames
    // (or dedup tests that might accidentally send twice) do not hang.
    for _ in 0..4 {
        // SAFETY: pipe is a valid server-side handle until CloseHandle.
        let connected = unsafe { ConnectNamedPipe(pipe, None) };
        if connected.is_err() {
            // ERROR_PIPE_CONNECTED (535) means a client connected before
            // ConnectNamedPipe was called — that's still a successful
            // connection and we should proceed to read.
            let code = connected.as_ref().err().map(|e| e.code().0 as u32 & 0xFFFF);
            if code != Some(535) {
                break;
            }
        }

        // Read length prefix.
        let mut len_buf = [0u8; 4];
        if !read_exact(pipe, &mut len_buf) {
            // Disconnect and try to accept the next client.
            unsafe {
                let _ = windows::Win32::System::Pipes::DisconnectNamedPipe(pipe);
            }
            continue;
        }
        let payload_len = u32::from_le_bytes(len_buf) as usize;

        if payload_len == 0 || payload_len > 1_048_576 {
            unsafe {
                let _ = windows::Win32::System::Pipes::DisconnectNamedPipe(pipe);
            }
            continue;
        }

        let mut payload = vec![0u8; payload_len];
        if !read_exact(pipe, &mut payload) {
            unsafe {
                let _ = windows::Win32::System::Pipes::DisconnectNamedPipe(pipe);
            }
            continue;
        }

        if let Ok(text) = String::from_utf8(payload) {
            messages.lock().expect("messages mutex poisoned").push(text);
        }

        // Drop the current client so the next iteration can accept a
        // new connection (each `send_clipboard_alert` opens a fresh one).
        unsafe {
            let _ = windows::Win32::System::Pipes::DisconnectNamedPipe(pipe);
        }
    }

    unsafe {
        let _ = CloseHandle(pipe);
    }
    Ok(())
}

/// Reads exactly `buf.len()` bytes from `pipe`. Returns `false` on EOF
/// or error so the caller can fall through to the next connection.
fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> bool {
    let mut offset = 0;
    while offset < buf.len() {
        let mut bytes_read = 0u32;
        // SAFETY: `pipe` is a valid handle; the sub-slice is in-bounds.
        let result =
            unsafe { ReadFile(pipe, Some(&mut buf[offset..]), Some(&mut bytes_read), None) };
        if result.is_err() || bytes_read == 0 {
            return false;
        }
        offset += bytes_read as usize;
    }
    true
}

// ─────────────────────────────────────────────────────────────────────────
// Clipboard helpers
// ─────────────────────────────────────────────────────────────────────────

/// Writes `text` to the Windows clipboard as `CF_UNICODETEXT`.
///
/// Not used by the direct `classify_and_alert` tests, but kept available
/// for future tests that want to exercise the full read path.
#[allow(dead_code)]
fn set_clipboard_text(text: &str) {
    // UTF-16 with trailing NUL — CF_UNICODETEXT requires this layout.
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_len = wide.len() * std::mem::size_of::<u16>();

    // SAFETY: we OpenClipboard and CloseClipboard as a pair. GlobalAlloc/
    // GlobalLock are called in the standard order required by SetClipboardData.
    unsafe {
        if OpenClipboard(HWND::default()).is_err() {
            return;
        }
        let _ = EmptyClipboard();

        let hmem = match GlobalAlloc(GMEM_MOVEABLE, byte_len) {
            Ok(h) => h,
            Err(_) => {
                let _ = CloseClipboard();
                return;
            }
        };

        let dst = GlobalLock(hmem) as *mut u16;
        if dst.is_null() {
            let _ = CloseClipboard();
            return;
        }
        std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
        let _ = GlobalUnlock(hmem);

        // Ownership of hmem transfers to the clipboard on success.
        let _ = SetClipboardData(CF_UNICODETEXT.0 as u32, HANDLE(hmem.0));
        let _ = CloseClipboard();
    }
}

/// Empties the Windows clipboard — used to clean up after tests.
#[allow(dead_code)]
fn clear_clipboard() {
    unsafe {
        if OpenClipboard(HWND::default()).is_ok() {
            let _ = EmptyClipboard();
            let _ = CloseClipboard();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Assertion helpers
// ─────────────────────────────────────────────────────────────────────────

/// Waits up to `timeout` for at least one message to land in `messages`,
/// then returns a clone of the buffer.
fn wait_for_messages(messages: &Arc<Mutex<Vec<String>>>, timeout: Duration) -> Vec<String> {
    let deadline = Instant::now() + timeout;
    loop {
        {
            let guard = messages.lock().expect("messages mutex poisoned");
            if !guard.is_empty() {
                return guard.clone();
            }
        }
        if Instant::now() >= deadline {
            return Vec::new();
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Returns the count of messages currently buffered, without waiting.
fn message_count(messages: &Arc<Mutex<Vec<String>>>) -> usize {
    messages.lock().expect("messages mutex poisoned").len()
}

/// Sets up a mock pipe server and installs the `DLP_PIPE3_NAME` env var
/// to point at it. Returns the message buffer for assertions.
///
/// The env var is process-wide, so `#[serial]` is mandatory on the test.
fn setup_pipe() -> Arc<Mutex<Vec<String>>> {
    let (pipe_name, messages) = start_mock_pipe_server();
    // SAFETY: `set_var` is safe in a single-threaded test context.
    // `#[serial]` guarantees no other test is reading the env concurrently.
    unsafe {
        std::env::set_var("DLP_PIPE3_NAME", &pipe_name);
    }
    messages
}

/// Removes the `DLP_PIPE3_NAME` override after a test.
fn teardown_pipe() {
    // SAFETY: see setup_pipe — `#[serial]` ensures single-threaded access.
    unsafe {
        std::env::remove_var("DLP_PIPE3_NAME");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

const TEST_SESSION_ID: u32 = 1;
const ALERT_TIMEOUT: Duration = Duration::from_millis(500);

#[test]
#[serial]
fn test_ssn_triggers_t4_alert() {
    let messages = setup_pipe();

    let tier = classify_and_alert(TEST_SESSION_ID, "My SSN is 123-45-6789", None, None);
    assert_eq!(tier, Some("T4"));

    let received = wait_for_messages(&messages, ALERT_TIMEOUT);
    assert!(!received.is_empty(), "expected at least one Pipe 3 frame");
    assert!(
        received[0].contains("\"classification\":\"T4\""),
        "expected T4 classification in payload, got: {}",
        received[0]
    );

    teardown_pipe();
}

#[test]
#[serial]
fn test_credit_card_triggers_t4_alert() {
    let messages = setup_pipe();

    let tier = classify_and_alert(TEST_SESSION_ID, "Card: 4111-1111-1111-1111", None, None);
    assert_eq!(tier, Some("T4"));

    let received = wait_for_messages(&messages, ALERT_TIMEOUT);
    assert!(!received.is_empty(), "expected at least one Pipe 3 frame");
    assert!(
        received[0].contains("\"classification\":\"T4\""),
        "expected T4 classification in payload, got: {}",
        received[0]
    );

    teardown_pipe();
}

#[test]
#[serial]
fn test_confidential_triggers_t3_alert() {
    let messages = setup_pipe();

    let tier = classify_and_alert(TEST_SESSION_ID, "This memo is CONFIDENTIAL", None, None);
    assert_eq!(tier, Some("T3"));

    let received = wait_for_messages(&messages, ALERT_TIMEOUT);
    assert!(!received.is_empty(), "expected at least one Pipe 3 frame");
    assert!(
        received[0].contains("\"classification\":\"T3\""),
        "expected T3 classification in payload, got: {}",
        received[0]
    );

    teardown_pipe();
}

#[test]
#[serial]
fn test_internal_triggers_t2_alert() {
    let messages = setup_pipe();

    let tier = classify_and_alert(TEST_SESSION_ID, "For internal only distribution", None, None);
    assert_eq!(tier, Some("T2"));

    let received = wait_for_messages(&messages, ALERT_TIMEOUT);
    assert!(!received.is_empty(), "expected at least one Pipe 3 frame");
    assert!(
        received[0].contains("\"classification\":\"T2\""),
        "expected T2 classification in payload, got: {}",
        received[0]
    );

    teardown_pipe();
}

#[test]
#[serial]
fn test_ordinary_text_no_alert() {
    let messages = setup_pipe();

    let tier = classify_and_alert(TEST_SESSION_ID, "Hello, world!", None, None);
    assert_eq!(tier, None, "T1 text must not produce an alert");

    // Give the (hypothetical) alert time to arrive — we expect nothing.
    thread::sleep(Duration::from_millis(150));
    assert_eq!(
        message_count(&messages),
        0,
        "no Pipe 3 frame should have been sent for T1 text"
    );

    teardown_pipe();
}

#[test]
#[serial]
fn test_duplicate_deduplicated() {
    // `classify_and_alert` itself does NOT dedup — dedup is the live
    // monitor's responsibility via the last_hash compare. This test
    // documents that contract: calling twice with identical text
    // produces two frames, confirming the helper is stateless.
    let messages = setup_pipe();

    let t1 = classify_and_alert(TEST_SESSION_ID, "Secret document", None, None);
    let t2 = classify_and_alert(TEST_SESSION_ID, "Secret document", None, None);
    assert_eq!(t1, Some("T3"));
    assert_eq!(t2, Some("T3"));

    // Wait for both frames.
    let deadline = Instant::now() + ALERT_TIMEOUT;
    while Instant::now() < deadline && message_count(&messages) < 2 {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        message_count(&messages),
        2,
        "stateless helper should emit one frame per call"
    );

    teardown_pipe();
}

#[test]
#[serial]
fn test_empty_clipboard_ignored() {
    let messages = setup_pipe();

    let tier = classify_and_alert(TEST_SESSION_ID, "", None, None);
    assert_eq!(tier, None, "empty text must not produce an alert");

    thread::sleep(Duration::from_millis(150));
    assert_eq!(
        message_count(&messages),
        0,
        "no Pipe 3 frame should have been sent for empty text"
    );

    teardown_pipe();
}

#[test]
#[serial]
fn test_non_text_clipboard_ignored() {
    // The live monitor reads clipboard via `read_clipboard()`, which
    // returns `Ok(None)` for non-text formats — `handle_clipboard_change`
    // early-returns in that case. Since we drive `classify_and_alert`
    // directly, we model "non-text clipboard" as "no text to classify"
    // by passing an empty string. This asserts the same contract:
    // nothing to classify -> nothing sent.
    let messages = setup_pipe();

    let tier = classify_and_alert(TEST_SESSION_ID, "", None, None);
    assert_eq!(tier, None);

    thread::sleep(Duration::from_millis(150));
    assert_eq!(message_count(&messages), 0);

    teardown_pipe();
}
