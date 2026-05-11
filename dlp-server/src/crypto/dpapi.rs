//! Windows DPAPI (Data Protection API) bindings, machine-scoped.
//!
//! The server runs (in production) as a Windows Service under LocalSystem or
//! a managed service account. The master seed for the KEK must survive
//! reboots and remain decryptable across service-identity rotations. Hence
//! we set the `CRYPTPROTECT_LOCAL_MACHINE` flag (0x4) on the protect side,
//! binding the wrapped blob to the **machine** (DPAPI_SYSTEM LSA secret)
//! rather than to a user profile.
//!
//! Reference implementations:
//! - `dlp-agent/src/password_stop.rs:760-781` — user-scope unprotect
//! - `dlp-user-ui/src/dialogs/stop_password.rs:239-265` — user-scope protect
//!
//! This module adds the `CRYPTPROTECT_LOCAL_MACHINE` flag the agent omits.
//!
//! ## Threat model summary
//!
//! With `CRYPTPROTECT_LOCAL_MACHINE`, encryption does **not** protect
//! against a local administrator on the same machine — they can decrypt via
//! any process. The SQLite file ACL (SYSTEM-only) is the on-box access
//! boundary. This module protects against offline file-system theft and
//! SQLite copy-to-other-machine attacks; see `47-RESEARCH.md §B.1`.

#![cfg(windows)]

use crate::crypto::error::{CryptoError, DpapiError};

use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
};

/// Encrypts `plaintext` with DPAPI under the `CRYPTPROTECT_LOCAL_MACHINE`
/// scope.
///
/// The resulting opaque blob can be persisted (e.g., as the
/// `secret_kek_history.master_seed_dpapi` column) and decrypted by any
/// process on the same machine via [`dpapi_unprotect`].
///
/// # Errors
///
/// Returns [`CryptoError::DpapiProtectFailed`] when `CryptProtectData`
/// returns a non-success HRESULT. The plaintext is never logged or included
/// in the error.
///
/// # Safety
///
/// The unsafe block is required for the FFI call into `CryptProtectData`.
/// Invariants preserved:
///
/// 1. `input` points to `plaintext`'s heap-allocated bytes for the duration
///    of the call (`plaintext` lives for the entire function body).
/// 2. `output.pbData` is freed via `LocalFree` after we have copied the
///    bytes out, satisfying the Win32 ownership contract documented at
///    <https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata>.
/// 3. The `pbData` field of `CRYPT_INTEGER_BLOB` is declared `*mut u8` even
///    though the call only reads from `input` — this matches the
///    `dlp-agent` reference pattern and is sound because the underlying
///    slice is borrowed immutably for the duration of the FFI call.
pub fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
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
        .map_err(|e| CryptoError::DpapiProtectFailed {
            source: DpapiError::from(e),
        })?;

        let ciphertext = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData as *mut _));
        Ok(ciphertext)
    }
}

/// Decrypts a DPAPI-wrapped blob previously produced by [`dpapi_protect`].
///
/// The unprotect side does not need the `CRYPTPROTECT_LOCAL_MACHINE` flag —
/// scope is encoded in the wrapped blob itself.
///
/// # Errors
///
/// Returns [`CryptoError::DpapiUnprotectFailed`] when the wrapped blob was
/// produced on a different machine, the LSA `DPAPI_SYSTEM` secret has
/// rotated and the master key file is missing, or the blob is corrupted.
/// Plaintext content is never logged.
///
/// # Safety
///
/// See [`dpapi_protect`]'s safety section — the same invariants apply,
/// inverted (we now read the output buffer that the OS allocates).
pub fn dpapi_unprotect(protected: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    // SAFETY: CryptUnprotectData reads the input blob and writes the output blob.
    // The output buffer is allocated by the function and must be freed via
    // LocalFree.
    unsafe {
        CryptUnprotectData(&input, None, None, None, None, 0, &mut output).map_err(|e| {
            CryptoError::DpapiUnprotectFailed {
                source: DpapiError::from(e),
            }
        })?;

        let plaintext = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData as *mut _));
        Ok(plaintext)
    }
}

/// Newtype around a DPAPI-protected blob. Exposed so future tasks (47-02
/// repository, 47-06 migration) can take a strongly-typed argument instead
/// of a naked `Vec<u8>`, preventing accidental confusion with cleartext.
#[derive(Debug, Clone)]
pub struct MachineSecret(pub Vec<u8>);

impl MachineSecret {
    /// Wrap an existing DPAPI-protected blob (e.g., one read from the
    /// `secret_kek_history.master_seed_dpapi` column).
    pub fn from_protected_blob(blob: Vec<u8>) -> Self {
        Self(blob)
    }

    /// Borrow the underlying bytes for passing to [`dpapi_unprotect`].
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
