//! SMB impersonation resolution (T-12).
//!
//! Resolves the effective user identity from the current thread's impersonation
//! token or from a process token.  Used by the interception engine to attach
//! a real user SID to every file action event.
//!
//! ## Impersonation flow
//!
//! ```text
//! File system operation
//!   -> interception layer hooks (PreWrite, PreCreate, …)
//!   -> ImpersonateSelf (get caller's token)
//!   -> QueryTokenInformation(TokenUser)  → SID + name
//!   -> RevertToSelf
//!   -> forward event with resolved user identity
//! ```

use anyhow::Result;
use tracing::{debug, warn};

use crate::prelude::Subject;

/// A resolved Windows identity with SID, username, and primary group.
#[derive(Debug, Clone)]
pub struct WindowsIdentity {
    /// The user's security identifier (e.g., "S-1-5-21-123456789-...").
    pub sid: String,
    /// The user's display name (e.g., "jsmith").
    pub username: String,
    /// The SID of the user's primary group.
    pub primary_group: Option<String>,
}

impl WindowsIdentity {
    /// Converts this identity into an ABAC [`Subject`].
    ///
    /// Groups are fetched via a separate AD lookup (not included here).
    pub fn to_subject(&self) -> Subject {
        Subject {
            user_sid: self.sid.clone(),
            user_name: self.username.clone(),
            groups: Vec::new(),
            device_trust: dlp_common::DeviceTrust::Unknown,
            network_location: dlp_common::NetworkLocation::Unknown,
        }
    }
}

/// Errors that can occur during identity resolution.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("no impersonation token available")]
    NoToken,

    #[error("token user query failed: {0}")]
    TokenQueryFailed(String),

    #[error("could not convert SID to string: {0}")]
    SidToString(String),

    #[error("could not look up account name: {0}")]
    AccountLookup(String),

    #[error("revert to self failed: {0}")]
    RevertFailed(String),
}

/// The identity resolver for file operation interception.
///
/// Uses `ImpersonateSelf` / `RevertToSelf` for the caller's token when
/// called from within a hooked operation, and `OpenProcessToken` as a
/// fallback when called outside an impersonation context.
pub struct IdentityResolver {
    /// Cache of SID → username lookups.  SID strings are the keys.
    sid_cache: std::collections::HashMap<String, Option<String>>,
}

impl IdentityResolver {
    /// Constructs a new resolver with an empty cache.
    pub fn new() -> Self {
        Self {
            sid_cache: std::collections::HashMap::new(),
        }
    }

    /// Resolves the effective identity of the calling thread.
    ///
    /// First attempts `ImpersonateSelf` + token query; falls back to
    /// `OpenProcessToken(GetCurrentProcess)` if no impersonation token
    /// is available.
    pub fn resolve_caller_identity(&mut self) -> Result<WindowsIdentity, IdentityError> {
        // Try the thread's impersonation token first.
        if let Some(identity) = self.resolve_from_thread_token() {
            return Ok(identity);
        }

        // Fall back to the process token (usually SYSTEM or the service account).
        self.resolve_from_process_token()
    }

    /// Looks up the account name for a SID, using the cache.
    pub fn lookup_account_name(&mut self, sid: &str) -> Option<String> {
        if let Some(cached) = self.sid_cache.get(sid) {
            return cached.clone();
        }

        let name = Self::_lookup_account_name_impl(sid);
        self.sid_cache.insert(sid.to_owned(), name.clone());
        name
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// Attempts impersonation via `ImpersonateSelf`, queries the token, then reverts.
    fn resolve_from_thread_token(&mut self) -> Option<WindowsIdentity> {
        use windows::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};

        // Begin impersonation.
        // SAFETY: ImpersonateSelf with SecurityImpersonation level is safe on any thread.
        if unsafe { ImpersonateSelf(SecurityImpersonation) }.is_err() {
            debug!("ImpersonateSelf failed — not in an impersonation context");
            return None;
        }

        let result = self.query_own_token();
        // Always revert regardless of query result.
        if unsafe { RevertToSelf() }.is_err() {
            warn!("RevertToSelf failed after successful ImpersonateSelf");
        }

        result
    }

    /// Queries the current thread's effective token (after `ImpersonateSelf`).
    fn query_own_token(&mut self) -> Option<WindowsIdentity> {
        use windows::Win32::Security::TOKEN_QUERY;
        use windows::Win32::System::Threading::OpenThreadToken;

        // SAFETY: thread token is valid for the duration of this function
        // (RevertToSelf is called by the caller after this returns).
        let token = unsafe {
            let mut handle = windows::Win32::Foundation::HANDLE::default();
            let opened = OpenThreadToken(get_current_thread(), TOKEN_QUERY, false, &mut handle);
            if opened.is_ok() {
                Some(handle)
            } else {
                None
            }
        };

        let token = token?;
        let identity = self.query_token_user(token);
        close_handle(token);
        identity
    }

    /// Falls back to the current process's token.
    fn resolve_from_process_token(&mut self) -> Result<WindowsIdentity, IdentityError> {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Threading::{
            GetCurrentProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
        };

        let process = unsafe { GetCurrentProcess() };

        // SAFETY: process handle is a pseudo-handle, valid for the caller's lifetime.
        let mut handle = HANDLE::default();
        unsafe {
            // Cast PROCESS_QUERY_INFORMATION (u32) to TOKEN_ACCESS_MASK (newtype u32).
            OpenProcessToken(
                process,
                windows::Win32::Security::TOKEN_ACCESS_MASK(PROCESS_QUERY_INFORMATION.0),
                &mut handle,
            )
            .map_err(|e| IdentityError::TokenQueryFailed(format!("{e:?}")))?;
        }

        let result = self.query_token_user(handle);
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };

        result.ok_or_else(|| IdentityError::TokenQueryFailed("query failed".to_string()))
    }

    /// Queries `TokenUser` from a valid token handle and converts it to a [`WindowsIdentity`].
    fn query_token_user(
        &mut self,
        token: windows::Win32::Foundation::HANDLE,
    ) -> Option<WindowsIdentity> {
        use windows::Win32::Security::{GetTokenInformation, TokenUser};

        const BUF_SIZE: usize = 512;

        let mut buf = vec![0u8; BUF_SIZE];
        let mut returned = 0u32;

        // SAFETY: token is a valid open handle; buf is valid for writes.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut _),
                BUF_SIZE as u32,
                &mut returned,
            )
        };

        if ok.is_err() {
            return None;
        }

        // The first entry in the returned buffer is a SID_AND_ATTRIBUTES.
        let sid_ptr = unsafe { *(buf.as_ptr() as *const *const std::ffi::c_void) };
        if sid_ptr.is_null() {
            return None;
        }

        // Convert the raw SID pointer to a string using ConvertStringSidToSidW.
        // SAFETY: sid_ptr points to a SID allocated within the token buffer.
        let sid_str = Self::_sid_to_string(sid_ptr)?;

        let username = self
            .lookup_account_name(&sid_str)
            .unwrap_or_else(|| sid_str.clone());

        Some(WindowsIdentity {
            sid: sid_str,
            username,
            primary_group: None,
        })
    }

    /// Converts a raw `PSID` pointer to a string via `ConvertSidToStringSidW`.
    ///
    /// The windows-rs 0.58 bindings take exactly 2 arguments (sid, *mut PWSTR)
    /// with no size-returning variant.  A fixed 512-char buffer covers all
    /// valid SID string representations (max ~180 chars per MSDN).
    fn _sid_to_string(sid_ptr: *const std::ffi::c_void) -> Option<String> {
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;

        let psid = windows::Win32::Security::PSID(sid_ptr as *mut _);

        // Allocate a buffer large enough for any SID string representation.
        let mut buf = vec![0u16; 512];

        // SAFETY: buf is valid for writes; psid is a valid SID from the token buffer.
        let ok = unsafe {
            ConvertSidToStringSidW(psid, &mut windows::core::PWSTR(buf.as_mut_ptr())).is_ok()
        };

        if !ok {
            return None;
        }

        // SAFETY: ConvertSidToStringSidW wrote a null-terminated UTF-16 string.
        let result = String::from_utf16_lossy(&buf)
            .trim_end_matches('\0')
            .to_string();
        // Note: ConvertSidToStringSidW allocates via LocalAlloc internally, but
        // since we provided the buffer, no LocalFree is needed here.
        Some(result)
    }

    /// Looks up the account name for a SID string using `LookupAccountSidW`.
    fn _lookup_account_name_impl(sid_str: &str) -> Option<String> {
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows::Win32::Security::{LookupAccountSidW, PSID};

        // Convert the SID string to a SID via `ConvertStringSidToSidW`.
        let sid_wide: Vec<u16> = sid_str.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psid_ptr: PSID = PSID::default();

        // SAFETY: sid_wide is a valid null-terminated wide string.
        if unsafe {
            ConvertStringSidToSidW(
                windows::core::PCWSTR::from_raw(sid_wide.as_ptr()),
                &mut psid_ptr,
            )
        }
        .is_err()
        {
            return None;
        }

        let mut name_buf = vec![0u16; 256];
        let mut domain_buf = vec![0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let mut domain_len = domain_buf.len() as u32;
        let mut use_ = windows::Win32::Security::SID_NAME_USE(0);

        // SAFETY: psid_ptr is a valid SID from ConvertStringSidToSidW; buffers are valid.
        let ok = unsafe {
            LookupAccountSidW(
                None,
                psid_ptr,
                windows::core::PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                windows::core::PWSTR(domain_buf.as_mut_ptr()),
                &mut domain_len,
                &mut use_,
            )
        };

        // Free the SID allocated by ConvertStringSidToSidW.
        // SAFETY: psid_ptr was allocated by ConvertStringSidToSidW and has not been freed.
        let _ = unsafe { LocalFree(HLOCAL(psid_ptr.0)) };

        if ok.is_ok() && name_len > 0 {
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            Some(name)
        } else {
            None
        }
    }
}

impl Default for IdentityResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows API helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a pseudo-handle for the current thread.
fn get_current_thread() -> windows::Win32::Foundation::HANDLE {
    // SAFETY: GetCurrentThread returns a pseudo-handle valid for the calling thread.
    unsafe { windows::Win32::System::Threading::GetCurrentThread() }
}

/// Closes a Windows handle.
fn close_handle(handle: windows::Win32::Foundation::HANDLE) {
    // SAFETY: handle is a valid open handle we received from OpenThreadToken/OpenProcessToken.
    let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_resolver_default() {
        let resolver = IdentityResolver::new();
        assert!(resolver.sid_cache.is_empty());
    }

    #[test]
    fn test_windows_identity_to_subject() {
        let identity = WindowsIdentity {
            sid: "S-1-5-21-123".to_string(),
            username: "jsmith".to_string(),
            primary_group: None,
        };
        let subject = identity.to_subject();
        assert_eq!(subject.user_sid, "S-1-5-21-123");
        assert_eq!(subject.user_name, "jsmith");
        assert!(subject.groups.is_empty());
    }
}
