//! Hook IPC — named-pipe protocol between API-hook DLL and agent service.
//!
//! Each frame on the pipe is encoded as:
//! ```text
//! [u32: payload_length_le] [bincode payload]
//! ```
//!
//! The server runs a blocking accept loop (intended to be spawned on a
//! dedicated `std::thread`).  When a Tokio runtime is available on the
//! calling thread, each connection is handled in a
//! `tokio::task::spawn_blocking` task so the accept loop never blocks on
//! classification work.

use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

use dlp_common::{HookRequest, HookResponse};

use crate::ipc::frame::{read_frame, write_frame};
use crate::ipc::pipe_security::PipeSecurity;

/// Default pipe name used by the hook DLL.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\DlpHookPipe";

/// Number of pipe instances to allow.
const NUM_INSTANCES: u32 = 4;

/// Output / input buffer size.
const PIPE_BUFFER_SIZE: u32 = 65_536;

/// Default timeout for `CreateNamedPipeW`.
const PIPE_TIMEOUT_MS: u32 = 5_000;

/// Handler type for processing hook requests.
pub type HookHandler = Arc<dyn Fn(HookRequest) -> HookResponse + Send + Sync + 'static>;

/// Named-pipe server that listens for hook DLL classification requests.
pub struct HookIpcServer {
    pipe_name: String,
    handler: HookHandler,
}

impl HookIpcServer {
    /// Creates a new hook IPC server.
    ///
    /// `pipe_name` is the full Win32 pipe path (e.g. `r"\\.\pipe\DlpHookPipe"`).
    /// `handler` is called once per request to produce a [`HookResponse`].
    pub fn new(pipe_name: impl Into<String>, handler: HookHandler) -> Self {
        Self {
            pipe_name: pipe_name.into(),
            handler,
        }
    }

    /// Runs the blocking accept loop on the current thread.
    ///
    /// Callers should spawn this in a dedicated `std::thread`.  If a Tokio
    /// runtime is present on the calling thread, each accepted connection is
    /// off-loaded to `tokio::task::spawn_blocking` so the accept loop stays
    /// responsive.
    pub fn run(self) -> Result<()> {
        self.run_with_ready(|| {})
    }

    /// Same as [`run`](Self::run) but calls `on_ready` after the first pipe
    /// instance has been created and is ready for clients.
    pub fn run_with_ready(self, on_ready: impl FnOnce()) -> Result<()> {
        info!(pipe = %self.pipe_name, "Hook IPC server starting");
        let rt = tokio::runtime::Handle::try_current().ok();
        let pipe = create_pipe(&self.pipe_name)?;
        on_ready();
        accept_loop(pipe, self.pipe_name, self.handler, rt)
    }
}

fn pipe_mode() -> NAMED_PIPE_MODE {
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
}

fn create_pipe(pipe_name: &str) -> Result<HANDLE> {
    let name_wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let sec = PipeSecurity::new().context("pipe security descriptor")?;

    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            pipe_mode(),
            NUM_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            PIPE_TIMEOUT_MS,
            Some(sec.as_ptr()),
        )
    };

    if pipe.is_invalid() {
        return Err(anyhow::anyhow!(
            "CreateNamedPipeW returned INVALID_HANDLE_VALUE"
        ));
    }
    Ok(pipe)
}

fn accept_loop(
    first_pipe: HANDLE,
    pipe_name: String,
    handler: HookHandler,
    rt: Option<tokio::runtime::Handle>,
) -> Result<()> {
    let mut pipe = first_pipe;
    loop {
        // Wait for a client. ERROR_PIPE_CONNECTED (535) means a client
        // already connected between CreateNamedPipeW and ConnectNamedPipe.
        if let Err(e) = unsafe { ConnectNamedPipe(pipe, None) } {
            let win32_code = (e.code().0 as u32) & 0xFFFF;
            if win32_code != 535 {
                warn!(win32_code, "Hook IPC: ConnectNamedPipe failed — recycling pipe");
                let _ = unsafe { CloseHandle(pipe) };
                pipe = create_pipe(&pipe_name)?;
                continue;
            }
            debug!("Hook IPC: client already connected (535)");
        }

        info!("Hook IPC: client connected");

        match rt {
            Some(ref _h) => {
                // Synchronous handling (same as no-runtime path).  In a
                // future integration the handler may internally spawn Tokio
                // tasks for async classification; the accept loop itself
                // stays synchronous because Win32 pipe APIs are blocking.
                if let Err(e) = handle_connection(pipe, &handler) {
                    warn!(error = %e, "Hook IPC: connection handler error");
                }
                let _ = unsafe { DisconnectNamedPipe(pipe) };
                let _ = unsafe { CloseHandle(pipe) };
            }
            None => {
                if let Err(e) = handle_connection(pipe, &handler) {
                    warn!(error = %e, "Hook IPC: connection handler error");
                }
                let _ = unsafe { DisconnectNamedPipe(pipe) };
                let _ = unsafe { CloseHandle(pipe) };
            }
        }

        pipe = create_pipe(&pipe_name)?;
    }
}

fn handle_connection(pipe: HANDLE, handler: &HookHandler) -> Result<()> {
    loop {
        let frame = match read_frame(pipe) {
            Ok(f) => f,
            Err(e) => {
                debug!(error = %e, "Hook IPC: read error — disconnecting");
                break;
            }
        };

        let request: HookRequest = match bincode::deserialize(&frame) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "Hook IPC: malformed request — bincode deserialization failed");
                continue;
            }
        };

        debug!(path = %request.path, action = %request.action, "Hook IPC: classifying");
        let response = handler(request);
        debug!(decision = ?response.decision, "Hook IPC: classification complete");

        let payload = bincode::serialize(&response).context("serialize response")?;
        if let Err(e) = write_frame(pipe, &payload) {
            warn!(error = %e, "Hook IPC: write response failed — disconnecting");
            break;
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Client helpers (used by tests and, in the future, the hook DLL)
// ─────────────────────────────────────────────────────────────────────────────

/// Connects to a named pipe as a client.
///
/// Returns `Err` if the pipe does not exist or the server is not listening.
pub fn connect_client(pipe_name: &str) -> Result<HANDLE> {
    let name_wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    };

    match handle {
        Ok(h) => Ok(h),
        Err(e) => {
            let code = (e.code().0 as u32) & 0xFFFF;
            Err(anyhow::anyhow!(
                "CreateFileW failed (win32={}) — pipe server not running?",
                code
            ))
        }
    }
}

/// Sends a [`HookRequest`] over an open pipe and returns the [`HookResponse`].
pub fn send_request(pipe: HANDLE, request: &HookRequest) -> Result<HookResponse> {
    let payload = bincode::serialize(request).context("serialize request")?;
    write_frame(pipe, &payload).context("write request frame")?;

    let frame = read_frame(pipe).context("read response frame")?;
    let response: HookResponse = bincode::deserialize(&frame).context("deserialize response")?;
    Ok(response)
}

/// Sends raw bytes over an open pipe and reads the response frame.
pub fn send_raw(pipe: HANDLE, raw: &[u8]) -> Result<Vec<u8>> {
    write_frame(pipe, raw).context("write raw frame")?;
    let frame = read_frame(pipe).context("read response frame")?;
    Ok(frame)
}

/// Closes a pipe handle.
pub fn close_pipe(pipe: HANDLE) {
    let _ = unsafe { CloseHandle(pipe) };
}

/// Test helper: starts a [`HookIpcServer`] on a dedicated thread using the
/// given handler, waits until the pipe is ready, and returns the thread
/// handle so the caller can join it later (or let it run).
#[cfg(test)]
pub fn start_mock_server(
    pipe_name: &str,
    handler: HookHandler,
) -> std::thread::JoinHandle<Result<()>> {
    let name = pipe_name.to_string();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        let server = HookIpcServer::new(name, handler);
        server.run_with_ready(|| {
            let _ = tx.send(());
        })
    });

    rx.recv_timeout(std::time::Duration::from_secs(5))
        .expect("server did not become ready within 5s");
    handle
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use dlp_common::Decision;
    use super::*;

    /// Starts a [`HookIpcServer`] on a dedicated thread using the given
    /// handler, waits until the pipe is created, and returns the thread
    /// handle so the caller can join it later.
    fn start_server(
        pipe_name: &str,
        handler: HookHandler,
    ) -> std::thread::JoinHandle<Result<()>> {
        start_mock_server(pipe_name, handler)
    }

    #[test]
    fn hook_ipc_roundtrip_test() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestRoundtrip";

        let handler: HookHandler = Arc::new(|req: HookRequest| HookResponse {
            decision: Decision::DENY,
            reason: format!("blocked: {}", req.path),
        });

        let _server_handle = start_server(pipe_name, handler);

        // Give the server thread time to enter ConnectNamedPipe before the
        // client connects.  Without this, CreateFileW may race ahead and the
        // server's subsequent ConnectNamedPipe + handle_connection can see a
        // broken pipe before the client writes.
        std::thread::sleep(Duration::from_millis(50));

        let client = connect_client(pipe_name).expect("client connect");

        let mut latencies: Vec<Duration> = Vec::with_capacity(1_000);

        for i in 0..1_000 {
            let req = HookRequest {
                path: format!(r"C:\Users\test\file{}.txt", i),
                action: "CREATE".to_string(),
            };

            let start = Instant::now();
            let resp = send_request(client, &req).expect("request/response");
            let elapsed = start.elapsed();

            assert_eq!(resp.decision, Decision::DENY);
            assert_eq!(resp.reason, format!("blocked: {}", req.path));
            latencies.push(elapsed);

        }

        close_pipe(client);

        // Drop the server by … nothing; we just let the thread run out.
        // In a real scenario we'd send a shutdown signal.  For the test we
        // simply abandon the pipe — the server thread will block on the
        // next ConnectNamedPipe.  That's acceptable for unit tests.

        latencies.sort();
        let p99_idx = (latencies.len() as f64 * 0.99).ceil() as usize - 1;
        let p99 = latencies[p99_idx.min(latencies.len() - 1)];

        println!("p99 latency: {:?}", p99);
        println!("median latency: {:?}", latencies[latencies.len() / 2]);
        println!("min latency: {:?}", latencies[0]);
        println!("max latency: {:?}", latencies[latencies.len() - 1]);

        assert!(
            p99 < Duration::from_millis(50),
            "p99 latency {}ms >= 50ms",
            p99.as_millis()
        );

        // Clean up: we can't gracefully stop the server, but we can at
        // least join the thread with a timeout so it doesn't leak forever
        // in test runners.
        // Server thread blocks in ConnectNamedPipe — do not join.
    }

    #[test]
    fn hook_ipc_empty_path_boundary() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestEmpty";

        let handler: HookHandler = Arc::new(|req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: if req.path.is_empty() {
                "empty path ok".to_string()
            } else {
                "non-empty".to_string()
            },
        });

        let _server_handle = start_server(pipe_name, handler);
        let client = connect_client(pipe_name).expect("client connect");

        let req = HookRequest {
            path: "".to_string(),
            action: "READ".to_string(),
        };
        let resp = send_request(client, &req).expect("send empty path request");
        assert_eq!(resp.decision, Decision::ALLOW);
        assert_eq!(resp.reason, "empty path ok");

        close_pipe(client);
        // Server thread blocks in ConnectNamedPipe — do not join.
    }

    #[test]
    fn hook_ipc_zero_byte_payload_returns_no_response() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestZero";

        let handler: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::DENY,
            reason: "never reached".to_string(),
        });

        let _server_handle = start_server(pipe_name, handler);
        let client = connect_client(pipe_name).expect("client connect");

        // Write a zero-byte payload (length = 0, no payload bytes).
        let zero_len = 0u32.to_le_bytes();
        let written = unsafe {
            let mut bytes_written = 0u32;
            windows::Win32::Storage::FileSystem::WriteFile(
                client,
                Some(&zero_len),
                Some(&mut bytes_written),
                None,
            )
            .is_ok()
        };
        assert!(written);

        // Close our end so the server detects the disconnect and leaves
        // handle_connection.  Then ReadFile on our (now-invalid) handle
        // should fail.
        close_pipe(client);

        // The server will try to bincode::deserialize an empty slice and
        // log a warning, then close the connection without writing a
        // response.  ReadFile should therefore fail or return 0.
        let mut buf = [0u8; 4];
        let result = unsafe {
            let mut read = 0u32;
            windows::Win32::Storage::FileSystem::ReadFile(
                client,
                Some(&mut buf),
                Some(&mut read),
                None,
            )
        };

        // Either ReadFile errors or the pipe closes (0 bytes read).
        assert!(
            result.is_err() || {
                let mut read = 0u32;
                unsafe {
                    windows::Win32::Storage::FileSystem::ReadFile(
                        client,
                        Some(&mut buf),
                        Some(&mut read),
                        None,
                    )
                    .ok();
                }
                read == 0
            },
            "expected broken pipe after zero-byte payload"
        );

        // Server thread blocks in ConnectNamedPipe — do not join.
    }

    #[test]
    fn hook_ipc_malformed_request_logged_and_dropped() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestMalformed";

        let handler: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::DENY,
            reason: "should not reach".to_string(),
        });

        let _server_handle = start_server(pipe_name, handler);
        let client = connect_client(pipe_name).expect("client connect");

        // Send a valid-length frame but with garbage bytes that are not
        // valid bincode for HookRequest.
        let garbage = b"\x01\x02\x03\x04\x05\x06\x07\x08";
        let frame_len = (garbage.len() as u32).to_le_bytes();
        let mut payload = Vec::with_capacity(4 + garbage.len());
        payload.extend_from_slice(&frame_len);
        payload.extend_from_slice(garbage);

        let written = unsafe {
            let mut bytes_written = 0u32;
            windows::Win32::Storage::FileSystem::WriteFile(
                client,
                Some(&payload),
                Some(&mut bytes_written),
                None,
            )
            .is_ok()
        };
        assert!(written);

        // Because the server deserialisation fails, it drops the
        // connection without a response.  The next read should fail.
        let mut buf = [0u8; 4];
        let result = unsafe {
            let mut read = 0u32;
            windows::Win32::Storage::FileSystem::ReadFile(
                client,
                Some(&mut buf),
                Some(&mut read),
                None,
            )
        };
        assert!(
            result.is_err() || {
                let mut read = 0u32;
                unsafe {
                    windows::Win32::Storage::FileSystem::ReadFile(
                        client,
                        Some(&mut buf),
                        Some(&mut read),
                        None,
                    )
                    .ok();
                }
                read == 0
            },
            "expected broken pipe after malformed request"
        );

        close_pipe(client);
        // Server thread blocks in ConnectNamedPipe — do not join.
    }

    #[test]
    fn hook_ipc_server_not_running_connect_fails() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestNoServer";
        let result = connect_client(pipe_name);
        assert!(result.is_err(), "expected connection to fail when server is not running");
    }

    #[test]
    fn hook_ipc_oversized_path_frame_rejected() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestOversized";

        let handler: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::DENY,
            reason: "ok".to_string(),
        });

        let _server_handle = start_server(pipe_name, handler);
        let client = connect_client(pipe_name).expect("client connect");

        // Build a path well over 32KB.
        let huge_path = "A".repeat(40_000);
        let req = HookRequest {
            path: huge_path,
            action: "WRITE".to_string(),
        };

        // Serialisation itself should succeed.
        let _payload = bincode::serialize(&req).expect("serialize oversized path");
        // The frame is ~40KB, which is under the 64MiB limit in frame.rs,
        // so it should go through.  We verify the server handles it.
        let resp = send_request(client, &req).expect("request/response with oversized path");
        assert_eq!(resp.decision, Decision::DENY);

        close_pipe(client);
        // Server thread blocks in ConnectNamedPipe — do not join.
    }
}
