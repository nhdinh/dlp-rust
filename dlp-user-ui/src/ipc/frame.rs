//! Length-prefix JSON frame I/O for named pipes.
//!
//! Frame format: `[u32:LE payload length][json payload]`
//! Maximum payload: 64 MiB.

use anyhow::Result;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile};

/// Reads exactly `buf.len()` bytes from the pipe.
fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> Result<()> {
    let mut remaining = buf.len();
    while remaining > 0 {
        let slice_len = remaining.min(65536);
        let offset = buf.len() - remaining;
        let mut bytes_read = 0u32;

        // ReadFile requires Option<&mut [u8]> — slice_len must fit in usize.
        let result = unsafe {
            ReadFile(
                pipe,
                Some(&mut buf[offset..offset + slice_len]),
                Some(&mut bytes_read),
                None,
            )
        };

        if let Err(e) = result {
            let hresult = e.code().0 as u32;
            let win32 = hresult & 0xFFFF;
            return Err(anyhow::anyhow!("ReadFile failed: win32={win32} ({e})"));
        }

        if bytes_read == 0 {
            return Err(anyhow::anyhow!("pipe disconnected"));
        }

        remaining -= bytes_read as usize;
    }
    Ok(())
}

/// Reads a length-prefix JSON frame from the pipe.
pub fn read_frame(pipe: HANDLE) -> Result<Vec<u8>> {
    let mut length_buf = [0u8; 4];
    read_exact(pipe, &mut length_buf)?;

    let payload_len = u32::from_le_bytes(length_buf) as usize;

    const MAX_PAYLOAD: usize = 67_108_864; // 64 MiB
    if payload_len > MAX_PAYLOAD {
        return Err(anyhow::anyhow!(
            "frame payload {} exceeds maximum {}",
            payload_len,
            MAX_PAYLOAD
        ));
    }

    let mut payload = vec![0u8; payload_len];
    read_exact(pipe, &mut payload)?;
    Ok(payload)
}

/// Writes a length-prefix JSON frame to the pipe.
pub fn write_frame(pipe: HANDLE, payload: &[u8]) -> Result<()> {
    let length = (payload.len() as u32).to_le_bytes();

    // WriteFile takes Option<&[u8]>, so pass the length prefix as a slice.
    unsafe {
        WriteFile(pipe, Some(&length), None, None)
            .map_err(|_| anyhow::anyhow!("WriteFile (length prefix) failed"))?;
    }

    unsafe {
        WriteFile(pipe, Some(payload), None, None)
            .map_err(|_| anyhow::anyhow!("WriteFile (payload) failed"))
    }
}

/// Flushes the pipe send buffer.
#[allow(dead_code)]
pub fn flush(pipe: HANDLE) -> Result<()> {
    unsafe { FlushFileBuffers(pipe).map_err(|e| anyhow::anyhow!("FlushFileBuffers failed: {e}")) }
}

/// Closes a pipe handle.
#[allow(dead_code)]
pub fn close_pipe(pipe: HANDLE) {
    unsafe {
        let _ = CloseHandle(pipe);
    }
}
