//! Length-prefixed JSON frame helpers for named-pipe IPC (T-32).
//!
//! Each frame on every pipe is encoded as:
//! ```text
//! [u32: payload_length_le] [payload_bytes]
//! ```
//!
//! The payload is a UTF-8 JSON document — exactly what `serde_json` produces.

use anyhow::{Context, Result};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile};

/// Reads a single length-prefixed frame from a pipe handle.
//
// # Errors
// Returns an error if the pipe is broken, the frame header cannot be read,
// or fewer bytes than declared are received.
pub fn read_frame(pipe: HANDLE) -> Result<Vec<u8>> {
    let mut length_buf = [0u8; 4];
    read_exact(pipe, &mut length_buf).context("read frame length")?;

    let payload_len = u32::from_le_bytes(length_buf) as usize;

    // Guard against degenerate frames (64 MiB max — prevents a misbehaving
    // client from exhausting memory).
    const MAX_PAYLOAD: usize = 67_108_864;
    if payload_len > MAX_PAYLOAD {
        return Err(anyhow::anyhow!(
            "frame payload too large: {} bytes (max 64 MiB)",
            payload_len
        ));
    }

    let mut payload = vec![0u8; payload_len];
    read_exact(pipe, &mut payload).context("read frame payload")?;
    Ok(payload)
}

/// Writes a length-prefixed frame to a pipe handle.
//
// # Errors
// Returns an error if the pipe is broken or the write is partial.
pub fn write_frame(pipe: HANDLE, payload: &[u8]) -> Result<()> {
    let length_buf = (payload.len() as u32).to_le_bytes();
    write_all(pipe, &length_buf).context("write frame length")?;
    write_all(pipe, payload).context("write frame payload")?;

    // Flush so the client receives data before we wait for the next message.
    flush(pipe).context("flush frame")?;

    Ok(())
}

/// Like [`std::io::Read::read_exact`] but for Win32 [`HANDLE`].
fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> Result<()> {
    let mut remaining = buf.len();

    while remaining > 0 {
        let slice_len = remaining.min(65536);
        let offset = buf.len() - remaining;
        let mut bytes_read = 0u32;

        // windows-rs 0.58 ReadFile: lpbuffer: Option<&mut [u8]>
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
fn write_all(pipe: HANDLE, buf: &[u8]) -> Result<()> {
    let mut remaining = buf.len();

    while remaining > 0 {
        let mut bytes_written = 0u32;
        let slice_len = buf.len() - remaining;

        // windows-rs 0.58 WriteFile: lpbuffer: Option<&[u8]>
        let result = unsafe {
            WriteFile(
                pipe,
                Some(&buf[..slice_len]),
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
fn flush(pipe: HANDLE) -> Result<()> {
    unsafe { FlushFileBuffers(pipe).map_err(|e| anyhow::anyhow!("FlushFileBuffers failed: {}", e)) }
}
