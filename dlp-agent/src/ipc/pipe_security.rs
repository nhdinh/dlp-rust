//! Named-pipe security descriptor for Agent-to-UI IPC.
//!
//! Creates a `SECURITY_ATTRIBUTES` that grants Authenticated Users
//! read/write access to the pipe, allowing the dlp-user-ui process
//! (running as the interactive user) to connect to pipes owned by the
//! dlp-agent service (running as SYSTEM).
//!
//! Uses an SDDL string to define the DACL, which is simpler and more
//! reliable than building ACL entries manually.

use windows::core::PCWSTR;
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

/// SDDL string granting:
/// - `(A;;GRGW;;;AU)` — Allow Generic Read + Generic Write to
///   Authenticated Users
/// - `(A;;GA;;;SY)` — Allow Generic All to SYSTEM
/// - `(A;;GA;;;BA)` — Allow Generic All to Built-in Administrators
///
/// This lets the interactive-user UI process connect to SYSTEM-owned
/// pipes while preserving full control for SYSTEM and Administrators.
const PIPE_SDDL: &str = "D:(A;;GRGW;;;AU)(A;;GA;;;SY)(A;;GA;;;BA)\0";

/// A self-contained pipe security context that owns the security
/// descriptor buffer.
///
/// The `SECURITY_ATTRIBUTES` returned by [`as_ptr`](Self::as_ptr) is
/// valid for the lifetime of this struct.  Drop it only after
/// `CreateNamedPipeW` returns.
pub struct PipeSecurity {
    /// The raw SD pointer allocated by
    /// `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
    /// Must be freed with `LocalFree`.
    sd_ptr: PSECURITY_DESCRIPTOR,
    /// The `SECURITY_ATTRIBUTES` struct pointing to `sd_ptr`.
    sa: SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    /// Builds a `SECURITY_ATTRIBUTES` that allows Authenticated Users
    /// to read and write the pipe.
    ///
    /// # Returns
    ///
    /// A `PipeSecurity` whose [`as_ptr`](Self::as_ptr) can be passed
    /// to `CreateNamedPipeW`.
    ///
    /// # Errors
    ///
    /// Returns an error if the SDDL conversion fails.
    pub fn new() -> anyhow::Result<Self> {
        let sddl_wide: Vec<u16> = PIPE_SDDL.encode_utf16().collect();

        let mut sd_ptr = PSECURITY_DESCRIPTOR::default();

        // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW
        // parses a well-known SDDL string and allocates the SD via
        // LocalAlloc.  We free it in Drop.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR::from_raw(sddl_wide.as_ptr()),
                1, // SDDL_REVISION_1
                &mut sd_ptr,
                None,
            )
            .map_err(|e| anyhow::anyhow!("SDDL security descriptor creation failed: {e}"))?;
        }

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd_ptr.0,
            bInheritHandle: false.into(),
        };

        Ok(Self { sd_ptr, sa })
    }

    /// Returns a pointer to the `SECURITY_ATTRIBUTES`.
    ///
    /// Valid for the lifetime of this `PipeSecurity` instance.
    pub fn as_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        &self.sa
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.sd_ptr.0.is_null() {
            // SAFETY: sd_ptr was allocated by
            // ConvertStringSecurityDescriptorToSecurityDescriptorW
            // via LocalAlloc.
            unsafe {
                let _ = windows::Win32::Foundation::LocalFree(Some(
                    windows::Win32::Foundation::HLOCAL(self.sd_ptr.0),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipe_security_creates_successfully() {
        let sec = PipeSecurity::new();
        assert!(sec.is_ok(), "PipeSecurity::new() should succeed");
    }

    #[test]
    fn test_pipe_security_as_ptr_non_null() {
        let sec = PipeSecurity::new().unwrap();
        assert!(!sec.as_ptr().is_null());
    }
}
