//! Windows DPAPI (Data Protection API) bindings, machine-scoped.
//!
//! Uses `CryptProtectData` / `CryptUnprotectData` with `CRYPTPROTECT_LOCAL_MACHINE`
//! flag so data is bound to the machine (not user profile). This is required because
//! dlp-agent runs as SYSTEM service.
//!
//! Pitfall: DPAPI data is lost on machine rebuild (expected per D-06/D-07).

#![cfg(windows)]

use thiserror::Error;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
};

/// Errors that can occur during DPAPI operations.
#[derive(Debug, Error)]
pub enum DpapiError {
    /// `CryptProtectData` returned a failure HRESULT.
    #[error("DPAPI protect failed: HRESULT {hresult:#010x}")]
    Protect { hresult: u32 },
    /// `CryptUnprotectData` returned a failure HRESULT.
    #[error("DPAPI unprotect failed: HRESULT {hresult:#010x}")]
    Unprotect { hresult: u32 },
    /// DPAPI is not available on this platform (non-Windows builds).
    #[error("DPAPI not available on this platform")]
    NotAvailable,
}

#[cfg(windows)]
impl From<windows::core::Error> for DpapiError {
    fn from(e: windows::core::Error) -> Self {
        Self::Protect {
            hresult: e.code().0 as u32,
        }
    }
}

/// Encrypt plaintext with DPAPI using LocalMachine scope.
///
/// On non-Windows, returns `Err(DpapiError::NotAvailable)`.
///
/// # Errors
///
/// Returns `DpapiError::Protect` when `CryptProtectData` fails.
///
/// # Safety
///
/// The unsafe block is required for the FFI call into `CryptProtectData`.
/// Invariants preserved:
///
/// 1. `input` points to `plaintext`'s heap-allocated bytes for the duration
///    of the call (`plaintext` lives for the entire function body).
/// 2. `output.pbData` is freed via `LocalFree` after we have copied the
///    bytes out, satisfying the Win32 ownership contract.
#[cfg(windows)]
pub fn dpapi_protect_machine(plaintext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    // SAFETY: CryptProtectData reads the input blob and writes the output blob.
    // The output buffer is allocated by the function and must be freed via
    // LocalFree. CRYPTPROTECT_LOCAL_MACHINE (0x4) binds the blob to the machine
    // rather than the calling user — required so a service running as SYSTEM
    // can decrypt after reboot.
    unsafe {
        CryptProtectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        )
        .map_err(|e| DpapiError::Protect {
            hresult: e.code().0 as u32,
        })?;

        let ciphertext =
            std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut _)));
        Ok(ciphertext)
    }
}

#[cfg(not(windows))]
pub fn dpapi_protect_machine(_plaintext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    Err(DpapiError::NotAvailable)
}

/// Decrypt DPAPI-protected data.
///
/// On non-Windows, returns `Err(DpapiError::NotAvailable)`.
///
/// # Errors
///
/// Returns `DpapiError::Unprotect` when `CryptUnprotectData` fails.
///
/// # Safety
///
/// See `dpapi_protect_machine`'s safety section — the same invariants apply,
/// inverted (we now read the output buffer that the OS allocates).
#[cfg(windows)]
pub fn dpapi_unprotect_machine(protected: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    // SAFETY: CryptUnprotectData reads the input blob and writes the output blob.
    // The output buffer is allocated by the function and must be freed via LocalFree.
    unsafe {
        CryptUnprotectData(&input, None, None, None, None, 0, &mut output).map_err(|e| {
            DpapiError::Unprotect {
                hresult: e.code().0 as u32,
            }
        })?;

        let plaintext =
            std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut _)));
        Ok(plaintext)
    }
}

#[cfg(not(windows))]
pub fn dpapi_unprotect_machine(_protected: &[u8]) -> Result<Vec<u8>, DpapiError> {
    Err(DpapiError::NotAvailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn dpapi_round_trip() {
        let plaintext = b"hello, dpapi world!";
        let protected = dpapi_protect_machine(plaintext).expect("protect should succeed");
        assert!(!protected.is_empty());
        assert_ne!(protected, plaintext.to_vec());

        let decrypted = dpapi_unprotect_machine(&protected).expect("unprotect should succeed");
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    #[cfg(windows)]
    fn dpapi_corrupt_data_fails() {
        let mut protected = dpapi_protect_machine(b"test").expect("protect should succeed");
        // Corrupt the last byte
        let last = protected.len() - 1;
        protected[last] = protected[last].wrapping_add(1);

        let result = dpapi_unprotect_machine(&protected);
        assert!(result.is_err(), "unprotect of corrupt data must fail");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unprotect failed"),
            "error should mention unprotect failure; got: {err_msg}"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn dpapi_not_available_on_non_windows() {
        let result = dpapi_protect_machine(b"test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not available"));
    }
}
