//! Named-pipe client for the hook DLL.
//!
//! Connects to `\\.\pipe\DlpHookPipe`, sends a [`HookRequest`] via
//! length-prefixed bincode framing, and returns the [`HookResponse`].
//! All errors are mapped to [`PipeError`] so the caller can fail-closed.

use std::cell::RefCell;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::{SetNamedPipeHandleState, PIPE_READMODE_MESSAGE};

use dlp_common::{HookRequest, HookResponse};

thread_local! {
    /// Pre-allocated 4 KiB buffer reused per thread for pipe serialization.
    ///
    /// Eliminates allocator pressure in the hot path.  The buffer is
    /// initialized with `with_capacity(4096)` and never shrinks — on each
    /// `send_request` the buffer is cleared and reused via
    /// `bincode::serialize_into`.
    pub static PIPE_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4096));
}

/// Errors that can occur during pipe communication.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum PipeError {
    /// The pipe server is not running or the pipe does not exist.
    ConnectionRefused,
    /// The request timed out waiting for a response.
    Timeout,
    /// The response was malformed (e.g. could not be decoded).
    Malformed,
    /// An unexpected Win32 error occurred.
    Win32(u32),
}

impl std::fmt::Display for PipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipeError::ConnectionRefused => write!(f, "pipe connection refused"),
            PipeError::Timeout => write!(f, "pipe request timed out"),
            PipeError::Malformed => write!(f, "malformed pipe response"),
            PipeError::Win32(c) => write!(f, "Win32 error {c}"),
        }
    }
}

impl std::error::Error for PipeError {}

/// Sends a classification request to the agent service over the named pipe.
///
/// # Fail-closed behaviour
///
/// Any error (connection refused, timeout, malformed response) is returned
/// as [`PipeError`] so the caller can treat it as a denial.
pub fn send_request(
    pipe_name: &str,
    request: &HookRequest,
    timeout_ms: u32,
) -> Result<HookResponse, PipeError> {
    let pipe = connect_pipe(pipe_name, timeout_ms)?;

    // Set pipe to message-read mode so frame boundaries are respected.
    unsafe {
        let mode = PIPE_READMODE_MESSAGE;
        let _ = SetNamedPipeHandleState(pipe, Some(&mode), None, None);
    }

    // Serialize into thread-local buffer.
    PIPE_BUFFER.with(|buf| {
        let mut buffer = buf.borrow_mut();
        buffer.clear();

        if bincode::serialize_into(&mut *buffer, request).is_err() {
            let _ = unsafe { CloseHandle(pipe) };
            return Err(PipeError::Malformed);
        }

        if let Err(e) = write_frame(pipe, &buffer) {
            let _ = unsafe { CloseHandle(pipe) };
            return Err(e);
        }

        // Read response into a fresh Vec (response size is unknown).
        let frame = match read_frame(pipe, timeout_ms) {
            Ok(f) => f,
            Err(e) => {
                let _ = unsafe { CloseHandle(pipe) };
                return Err(e);
            }
        };

        let _ = unsafe { CloseHandle(pipe) };

        match bincode::deserialize(&frame) {
            Ok(resp) => Ok(resp),
            Err(_) => Err(PipeError::Malformed),
        }
    })
}

/// Sends raw bytes over the pipe and returns the raw response bytes.
///
/// This is used for handle-based classification where the request type
/// is [`HandleHookRequest`] rather than [`HookRequest`].
pub fn send_raw_request(
    pipe_name: &str,
    payload: &[u8],
    timeout_ms: u32,
) -> Result<Vec<u8>, PipeError> {
    let pipe = connect_pipe(pipe_name, timeout_ms)?;
    unsafe {
        let mode = PIPE_READMODE_MESSAGE;
        let _ = SetNamedPipeHandleState(pipe, Some(&mode), None, None);
    }
    if let Err(e) = write_frame(pipe, payload) {
        let _ = unsafe { CloseHandle(pipe) };
        return Err(e);
    }
    let frame = match read_frame(pipe, timeout_ms) {
        Ok(f) => f,
        Err(e) => {
            let _ = unsafe { CloseHandle(pipe) };
            return Err(e);
        }
    };
    let _ = unsafe { CloseHandle(pipe) };
    Ok(frame)
}

/// Fire-and-send helper for bypass alerts that does not wait for a response.
///
/// Connects to the named pipe, writes the payload with length-prefix framing,
/// and immediately closes the handle. No read is performed, avoiding deadlock
/// with the agent (per REVIEW-H-02).
///
/// # Arguments
///
/// * `pipe_name` — The named pipe path (e.g., `r"\\.\pipe\DlpHookPipe"`).
/// * `payload` — The raw bytes to send (already serialized).
///
/// # Returns
///
/// `Ok(())` if the payload was written successfully, or [`PipeError`] on failure.
///
/// # Errors
///
/// Returns `PipeError::ConnectionRefused` if the pipe does not exist.
/// Returns `PipeError::Win32(u32)` for unexpected Win32 errors.
pub fn send_raw_oneway(pipe_name: &str, payload: &[u8]) -> Result<(), PipeError> {
    // 50ms is a best-effort budget to avoid blocking the hooked thread.
    // The hook DLL runs in the hot path of file operations; alerts are
    // fire-and-send (no response wait), so a short timeout is acceptable.
    const CONNECT_TIMEOUT_MS: u32 = 50;
    let pipe = connect_pipe(pipe_name, CONNECT_TIMEOUT_MS)?;

    // Set pipe to message-read mode so frame boundaries are respected.
    unsafe {
        let mode = PIPE_READMODE_MESSAGE;
        if let Err(e) = SetNamedPipeHandleState(pipe, Some(&mode), None, None) {
            let _ = CloseHandle(pipe);
            return Err(PipeError::Win32((e.code().0 as u32) & 0xFFFF));
        }
    }

    if let Err(e) = write_frame(pipe, payload) {
        let _ = unsafe { CloseHandle(pipe) };
        return Err(e);
    }

    // Best-effort flush before close to reduce truncation risk under load.
    let _ = unsafe { FlushFileBuffers(pipe) };
    let _ = unsafe { CloseHandle(pipe) };
    Ok(())
}

/// Connects to a named pipe, retrying up to `timeout_ms`.
fn connect_pipe(pipe_name: &str, timeout_ms: u32) -> Result<HANDLE, PipeError> {
    let name_wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let start = std::time::Instant::now();
    let deadline = std::time::Duration::from_millis(timeout_ms as u64);

    loop {
        let handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR::from_raw(name_wide.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        };

        match handle {
            Ok(h) if h != INVALID_HANDLE_VALUE => return Ok(h),
            Ok(_) => return Err(PipeError::ConnectionRefused),
            Err(e) => {
                let code = (e.code().0 as u32) & 0xFFFF;
                // ERROR_FILE_NOT_FOUND (2) — server hasn't created the pipe yet.
                if code == 2 {
                    if start.elapsed() >= deadline {
                        return Err(PipeError::ConnectionRefused);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                return Err(PipeError::Win32(code));
            }
        }
    }
}

/// Writes a length-prefixed frame.
fn write_frame(pipe: HANDLE, payload: &[u8]) -> Result<(), PipeError> {
    let len_bytes = (payload.len() as u32).to_le_bytes();
    write_all(pipe, &len_bytes)?;
    write_all(pipe, payload)?;
    Ok(())
}

/// Reads a length-prefixed frame.
fn read_frame(pipe: HANDLE, _timeout_ms: u32) -> Result<Vec<u8>, PipeError> {
    let mut len_buf = [0u8; 4];
    read_exact(pipe, &mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;

    const MAX_PAYLOAD: usize = 67_108_864; // 64 MiB
    if len > MAX_PAYLOAD {
        return Err(PipeError::Malformed);
    }

    let mut payload = vec![0u8; len];
    read_exact(pipe, &mut payload)?;
    Ok(payload)
}

fn write_all(pipe: HANDLE, buf: &[u8]) -> Result<(), PipeError> {
    let mut remaining = buf.len();
    while remaining > 0 {
        let offset = buf.len() - remaining;
        let slice_len = remaining.min(65536);
        let mut written = 0u32;
        let result = unsafe {
            WriteFile(
                pipe,
                Some(&buf[offset..offset + slice_len]),
                Some(&mut written),
                None,
            )
        };
        if result.is_err() || written == 0 {
            return Err(PipeError::ConnectionRefused);
        }
        remaining -= written as usize;
    }
    Ok(())
}

fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> Result<(), PipeError> {
    let mut remaining = buf.len();
    while remaining > 0 {
        let offset = buf.len() - remaining;
        let slice_len = remaining.min(65536);
        let mut read = 0u32;
        let result = unsafe {
            ReadFile(
                pipe,
                Some(&mut buf[offset..offset + slice_len]),
                Some(&mut read),
                None,
            )
        };
        if result.is_err() {
            return Err(PipeError::ConnectionRefused);
        }
        if read == 0 {
            return Err(PipeError::Malformed);
        }
        remaining -= read as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_error_display() {
        assert_eq!(PipeError::Timeout.to_string(), "pipe request timed out");
        assert_eq!(PipeError::Malformed.to_string(), "malformed pipe response");
        assert_eq!(
            PipeError::ConnectionRefused.to_string(),
            "pipe connection refused"
        );
    }

    #[test]
    fn pipe_error_roundtrip() {
        // Verify PipeError implements Error + Display.
        let err: Box<dyn std::error::Error> = Box::new(PipeError::Timeout);
        assert!(err.to_string().contains("timed out"));
    }

    #[test]
    fn thread_local_buffer_reused() {
        PIPE_BUFFER.with(|buf| {
            let mut buffer = buf.borrow_mut();
            buffer.clear();
            buffer.extend_from_slice(b"test");
            assert_eq!(buffer.len(), 4);
            assert!(buffer.capacity() >= 4096);
        });
        PIPE_BUFFER.with(|buf| {
            let buffer = buf.borrow();
            assert!(buffer.capacity() >= 4096);
        });
    }

    #[test]
    fn thread_local_buffer_is_thread_local() {
        use std::sync::Arc;
        use std::thread;

        let cap1 = Arc::new(std::sync::Mutex::new(0usize));
        let cap2 = cap1.clone();

        thread::spawn(move || {
            PIPE_BUFFER.with(|buf| {
                let mut b = buf.borrow_mut();
                b.extend_from_slice(b"thread2");
                *cap2.lock().unwrap() = b.capacity();
            });
        })
        .join()
        .unwrap();

        PIPE_BUFFER.with(|buf| {
            let b = buf.borrow();
            assert_eq!(b.len(), 0);
            assert!(b.capacity() >= 4096);
        });

        assert!(*cap1.lock().unwrap() >= 4096);
    }

    #[test]
    fn test_send_raw_oneway_returns_err_on_connection_refused() {
        // A non-existent pipe should return ConnectionRefused.
        let result = send_raw_oneway(r"\\.\pipe\NonExistentPipeForTesting", b"test");
        assert_eq!(result, Err(PipeError::ConnectionRefused));
    }

    #[test]
    fn test_send_raw_oneway_signature_no_read_timeout() {
        // Verify the function signature does NOT include a timeout_ms parameter
        // for reading (since there is no read). The connection timeout is hardcoded.
        // This is a compile-time check — if the signature changes, this test breaks.
        let f: fn(&str, &[u8]) -> Result<(), PipeError> = send_raw_oneway;
        let _ = f;
    }
}
