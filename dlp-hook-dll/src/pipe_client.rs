//! Named-pipe client for the hook DLL.
//!
//! Connects to `\\.\pipe\DlpHookPipe`, sends a [`HookRequest`] via
//! length-prefixed bincode framing, and returns the [`HookResponse`].
//! All errors are mapped to [`PipeError`] so the caller can fail-closed.

use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::{SetNamedPipeHandleState, PIPE_READMODE_MESSAGE};

use dlp_common::{HookRequest, HookResponse};

/// Default pipe name used by the hook DLL.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\DlpHookPipe";

/// Errors that can occur during pipe communication.
#[derive(Debug, Clone, PartialEq)]
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

    // Serialize and send.
    let payload = match bincode::serialize(request) {
        Ok(p) => p,
        Err(_) => {
            let _ = unsafe { CloseHandle(pipe) };
            return Err(PipeError::Malformed);
        }
    };

    if let Err(e) = write_frame(pipe, &payload) {
        let _ = unsafe { CloseHandle(pipe) };
        return Err(e);
    }

    // Read response.
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
                (FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0) as u32,
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
                eprintln!("[connect_pipe] CreateFileW failed with code={}", code);
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
}
