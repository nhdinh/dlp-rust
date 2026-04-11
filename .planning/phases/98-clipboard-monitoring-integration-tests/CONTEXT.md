# Phase 99 Context: Clipboard Monitoring Integration Tests

## Purpose

Add integration tests for the clipboard monitoring feature (shipped in
commit 539d9e8, before GSD was set up). No test coverage currently
exists for the end-to-end flow.

## Decisions (locked)

### Scope
- **Full end-to-end**: UI clipboard monitor -> classifier -> Pipe 3 ->
  agent handler (mocked pipe server) -> verify message received.
- Uses real Win32 clipboard (OpenClipboard / SetClipboardData).

### Clipboard control
- **Real Win32 clipboard**. Tests inject text via the Windows clipboard
  API. Requires interactive desktop. Not headless-CI-friendly.

### Test location
- **`dlp-user-ui/tests/clipboard_integration.rs`** — single integration
  test file in the UI crate. Gated by `#[cfg(windows)]`.

### CI
- **Run all in CI on Windows runner** — tests are mandatory in the
  pipeline. No `#[ignore]` marker. Requires CI to provide an
  interactive-desktop Windows runner.

### Agent-side mock
- **Spawn real named pipe server in-test** on a unique pipe name per
  test run (e.g., `DLPEventUI2Agent-test-{uuid}`).
- Will need to parameterize the pipe name in `dlp-user-ui/src/ipc/pipe3.rs`
  (currently hardcoded as `\\.\pipe\DLPEventUI2Agent`) so tests can
  point at the mock pipe.

### Test cases (comprehensive, ~8 tests)
1. T4 SSN pattern triggers ClipboardAlert with classification="T4"
2. T4 credit card (16-digit) triggers alert
3. T3 "CONFIDENTIAL" keyword triggers alert
4. T2 "internal only" keyword triggers alert
5. T1 ordinary text does NOT trigger alert
6. Duplicate clipboard content triggers alert only once (dedup hash)
7. Non-text clipboard format (e.g., image) is ignored
8. Empty clipboard text is ignored

## New API requirements

`dlp-user-ui` needs a way to override the Pipe 3 pipe name for testing:
- Option A: env var `DLP_PIPE3_NAME` read by `send_clipboard_alert`
- Option B: new `send_clipboard_alert_to(pipe_name, ...)` function
  exposed publicly
- **Preferred: env var** — minimal code change, keeps test setup simple

## Files to touch

1. `dlp-user-ui/src/ipc/pipe3.rs` — read optional pipe name override
2. `dlp-user-ui/tests/clipboard_integration.rs` — new integration test file
3. `dlp-user-ui/Cargo.toml` — add `uuid` to dev-dependencies (for unique pipe names)

## Non-goals

- Testing the iced app event loop
- Testing the tray or notifications
- Testing on non-Windows platforms
- Testing with real dlp-agent running

## Acceptance criteria

- [ ] `dlp-user-ui/tests/clipboard_integration.rs` exists with 8 test cases
- [ ] All tests pass on Windows
- [ ] Tests use a unique per-run pipe name (no conflicts)
- [ ] Tests restore original clipboard state on completion
- [ ] `cargo test --package dlp-user-ui --test clipboard_integration` runs cleanly
- [ ] Per-package clippy clean
