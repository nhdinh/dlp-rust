//! Length-prefixed protobuf frame helpers for Chrome Content Analysis IPC.
//!
//! Each frame is encoded as:
//! ```text
//! [u32: payload_length_le] [protobuf payload bytes]
//! ```
//!
//! The payload is a protobuf-encoded message (not JSON).

use anyhow::{Context, Result};

#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile};

/// Maximum allowed protobuf payload size (4 MiB).
///
/// Prevents a misbehaving client from exhausting agent memory via a
/// forged length prefix.  Chrome's Content Analysis SDK uses a 4 KiB
/// buffer; 4 MiB is three orders of magnitude larger and safe.
const MAX_PAYLOAD: usize = 4 * 1024 * 1024;

/// Reads a single length-prefixed protobuf frame from a pipe handle.
///
/// # Errors
///
/// Returns an error if the pipe is broken, the frame header cannot be
/// read, the declared payload exceeds [`MAX_PAYLOAD`], or fewer bytes
/// than declared are received.
#[cfg(windows)]
pub fn read_frame(pipe: HANDLE) -> Result<Vec<u8>> {
    let mut length_buf = [0u8; 4];
    read_exact(pipe, &mut length_buf).context("read frame length")?;

    let payload_len = u32::from_le_bytes(length_buf) as usize;

    if payload_len > MAX_PAYLOAD {
        return Err(anyhow::anyhow!(
            "frame payload too large: {} bytes (max {} MiB)",
            payload_len,
            MAX_PAYLOAD / (1024 * 1024)
        ));
    }

    let mut payload = vec![0u8; payload_len];
    read_exact(pipe, &mut payload).context("read frame payload")?;
    Ok(payload)
}

/// Writes a length-prefixed protobuf frame to a pipe handle.
///
/// # Errors
///
/// Returns an error if the pipe is broken or the write is partial.
#[cfg(windows)]
pub fn write_frame(pipe: HANDLE, payload: &[u8]) -> Result<()> {
    let length_buf = (payload.len() as u32).to_le_bytes();
    write_all(pipe, &length_buf).context("write frame length")?;
    write_all(pipe, payload).context("write frame payload")?;
    flush(pipe).context("flush frame")?;
    Ok(())
}

/// Like [`std::io::Read::read_exact`] but for Win32 [`HANDLE`].
#[cfg(windows)]
fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> Result<()> {
    let mut remaining = buf.len();

    while remaining > 0 {
        let slice_len = remaining.min(65536);
        let offset = buf.len() - remaining;
        let mut bytes_read = 0u32;

        let result = unsafe {
            ReadFile(
                pipe,
                Some(&mut buf[offset..offset + slice_len]),
                Some(&mut bytes_read),
                None,
            )
        };

        if result.is_err() {
            return Err(anyhow::anyhow!(
                "ReadFile returned an error ({} bytes read before failure)",
                buf.len() - remaining
            ));
        }

        if bytes_read == 0 {
            return Err(anyhow::anyhow!(
                "pipe closed prematurely ({} bytes read, {} expected)",
                buf.len() - remaining,
                buf.len()
            ));
        }

        remaining -= bytes_read as usize;
    }

    Ok(())
}

/// Like [`std::io::Write::write_all`] but for Win32 [`HANDLE`].
#[cfg(windows)]
fn write_all(pipe: HANDLE, buf: &[u8]) -> Result<()> {
    let mut remaining = buf.len();

    while remaining > 0 {
        let mut bytes_written = 0u32;
        let slice_len = buf.len() - remaining;

        let result = unsafe {
            WriteFile(
                pipe,
                Some(&buf[slice_len..]),
                Some(&mut bytes_written),
                None,
            )
        };

        if result.is_err() {
            return Err(anyhow::anyhow!(
                "WriteFile returned an error ({} bytes written before failure)",
                buf.len() - remaining
            ));
        }

        if bytes_written == 0 {
            return Err(anyhow::anyhow!(
                "pipe closed during write ({} bytes written, {} expected)",
                buf.len() - remaining,
                buf.len()
            ));
        }

        remaining -= bytes_written as usize;
    }

    Ok(())
}

/// Flushes write buffers for a pipe handle.
#[cfg(windows)]
fn flush(pipe: HANDLE) -> Result<()> {
    unsafe { FlushFileBuffers(pipe).map_err(|e| anyhow::anyhow!("FlushFileBuffers failed: {}", e)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_payload_is_4_mib() {
        assert_eq!(MAX_PAYLOAD, 4 * 1024 * 1024);
    }
}
