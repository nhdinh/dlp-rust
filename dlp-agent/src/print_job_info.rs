//! Win32 print job info wrappers (M017 T02).
//!
//! Provides safe Rust wrappers around `OpenPrinterW`, `GetJobW`, and `SetJobW`
//! for querying and cancelling print jobs.
//!
//! ## Safety
//!
//! - `PrinterHandle` calls `ClosePrinter` on drop.
//! - All wide-string conversions are null-terminated before passing to Win32.
//! - `GetJobW` uses the two-call pattern (size probe + buffer allocation).
//!
//! ## Elevation
//!
//! `OpenPrinterW` with `PRINTER_ACCESS_ADMINISTER` requires SYSTEM or
//! administrative privileges. The DLP agent runs as SYSTEM, so this is
//! satisfied in production. Tests do not call real spooler APIs.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use anyhow::{Context, Result};
use tracing::debug;

use windows::core::PCWSTR;
use windows::Win32::Graphics::Printing::{
    ClosePrinter, GetJobW, OpenPrinterW, SetJobW, JOB_CONTROL_DELETE, JOB_INFO_2W,
    JOB_STATUS_PRINTING, PRINTER_ACCESS_ADMINISTER, PRINTER_DEFAULTSW, PRINTER_HANDLE,
};
use windows::Win32::Foundation::GetLastError;

/// Owned handle to a printer — calls `ClosePrinter` on drop.
pub struct PrinterHandle {
    handle: PRINTER_HANDLE,
}

impl PrinterHandle {
    /// Returns the raw `PRINTER_HANDLE` for use with Win32 APIs.
    pub fn raw(&self) -> PRINTER_HANDLE {
        self.handle
    }
}

impl Drop for PrinterHandle {
    fn drop(&mut self) {
        // SAFETY: handle is a valid printer handle returned by OpenPrinterW.
        let _ = unsafe { ClosePrinter(self.handle) };
    }
}

/// Information about a print job extracted from `JOB_INFO_2W`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobInfo {
    /// Spooler job ID.
    pub job_id: u32,
    /// Document name (e.g., "Microsoft Word - Document1").
    pub document_name: String,
    /// User name that submitted the job.
    pub user_name: String,
    /// Job status bitmask (`JOB_STATUS_*`).
    pub status: u32,
    /// Data type (e.g., "RAW", "XPS_PASS", "NT EMF 1.008").
    pub datatype: String,
    /// Total pages reported by the driver.
    pub pages: u32,
}

/// Opens a printer with administrative access.
///
/// # Errors
///
/// Returns an error if `OpenPrinterW` fails (e.g., printer not found,
/// insufficient privileges).
pub fn open_printer(name: &str) -> Result<PrinterHandle> {
    let name_wide: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let defaults = PRINTER_DEFAULTSW {
        pDatatype: windows::core::PWSTR::null(),
        pDevMode: std::ptr::null_mut(),
        DesiredAccess: PRINTER_ACCESS_ADMINISTER,
    };

    let mut handle = PRINTER_HANDLE::default();

    // SAFETY: name_wide is a valid null-terminated wide string; defaults is a
    // stack-local struct valid for the call duration.
    unsafe {
        OpenPrinterW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            &mut handle,
            Some(&defaults),
        )
        .with_context(|| {
            let err = GetLastError();
            format!("OpenPrinterW failed for '{}' (last error: {:?})", name, err)
        })?;
    }

    debug!(printer = %name, "opened printer with administer access");
    Ok(PrinterHandle { handle })
}

/// Queries job information (level 2) for the given job ID.
///
/// # Errors
///
/// Returns an error if `GetJobW` fails (e.g., job does not exist).
pub fn get_job_info(handle: &PrinterHandle, job_id: u32) -> Result<JobInfo> {
    let mut needed: u32 = 0;

    // First call: probe for required buffer size.
    // SAFETY: valid printer handle; pcbNeeded points to a local variable.
    let ok = unsafe {
        GetJobW(
            handle.raw(),
            job_id,
            2,
            None,
            &mut needed,
        )
    };

    if !ok.as_bool() && needed == 0 {
        let err = unsafe { GetLastError() };
        anyhow::bail!("GetJobW size probe failed for job {} (last error: {:?})", job_id, err);
    }

    let mut buf: Vec<u8> = vec![0; needed as usize];

    // Second call: fetch actual data.
    // SAFETY: buf is sized to `needed` bytes; pcbNeeded points to a local variable.
    let ok = unsafe {
        GetJobW(
            handle.raw(),
            job_id,
            2,
            Some(&mut buf),
            &mut needed,
        )
    };

    if !ok.as_bool() {
        let err = unsafe { GetLastError() };
        anyhow::bail!("GetJobW failed for job {} (last error: {:?})", job_id, err);
    }

    // SAFETY: GetJobW succeeded and wrote a valid JOB_INFO_2W at the start of buf.
    let job = unsafe { &*(buf.as_ptr() as *const JOB_INFO_2W) };

    let document_name = pwstr_to_string(job.pDocument);
    let user_name = pwstr_to_string(job.pUserName);
    let datatype = pwstr_to_string(job.pDatatype);

    debug!(job_id, document = %document_name, user = %user_name, "queried job info");

    Ok(JobInfo {
        job_id: job.JobId,
        document_name,
        user_name,
        status: job.Status,
        datatype,
        pages: job.TotalPages,
    })
}

/// Cancels a print job by sending `JOB_CONTROL_DELETE`.
///
/// # Errors
///
/// Returns an error if `SetJobW` fails (e.g., job already completed).
pub fn cancel_job(handle: &PrinterHandle, job_id: u32) -> Result<()> {
    // SAFETY: valid printer handle; level 0 and pJob None mean we only send a command.
    let ok = unsafe {
        SetJobW(handle.raw(), job_id, 0, None, JOB_CONTROL_DELETE)
    };

    if !ok.as_bool() {
        let err = unsafe { GetLastError() };
        anyhow::bail!(
            "SetJobW(JOB_CONTROL_DELETE) failed for job {} (last error: {:?})",
            job_id,
            err
        );
    }

    debug!(job_id, "cancelled print job");
    Ok(())
}

/// Returns `true` if the job status indicates it is currently printing.
#[must_use]
pub fn is_job_printing(status: u32) -> bool {
    (status & JOB_STATUS_PRINTING) != 0
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Converts a `PWSTR` to a Rust `String`, returning empty on null.
fn pwstr_to_string(ptr: windows::core::PWSTR) -> String {
    if ptr.0.is_null() {
        return String::new();
    }
    // SAFETY: we assume the pointer is valid and null-terminated (Win32 guarantees
    // this for the string fields inside a successfully-fetched JOB_INFO_2W).
    unsafe {
        let len = (0..)
            .take_while(|&i| *ptr.0.offset(i) != 0)
            .count();
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr.0, len))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_info_default_construction() {
        let info = JobInfo {
            job_id: 42,
            document_name: "test.docx".to_string(),
            user_name: "jsmith".to_string(),
            status: 0,
            datatype: "XPS_PASS".to_string(),
            pages: 3,
        };
        assert_eq!(info.job_id, 42);
        assert_eq!(info.document_name, "test.docx");
        assert_eq!(info.user_name, "jsmith");
        assert_eq!(info.status, 0);
        assert_eq!(info.datatype, "XPS_PASS");
        assert_eq!(info.pages, 3);
    }

    #[test]
    fn job_info_clone_equality() {
        let info = JobInfo {
            job_id: 1,
            document_name: "a".to_string(),
            user_name: "b".to_string(),
            status: 0,
            datatype: "RAW".to_string(),
            pages: 0,
        };
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    #[test]
    fn is_job_printing_with_zero_status() {
        assert!(!is_job_printing(0));
    }

    #[test]
    fn is_job_printing_with_printing_bit() {
        assert!(is_job_printing(JOB_STATUS_PRINTING));
    }

    #[test]
    fn is_job_printing_with_mixed_bits() {
        assert!(is_job_printing(JOB_STATUS_PRINTING | 0x04));
        assert!(!is_job_printing(0x04));
    }

    #[test]
    fn pwstr_to_string_null() {
        let s = pwstr_to_string(windows::core::PWSTR::null());
        assert_eq!(s, "");
    }
}
