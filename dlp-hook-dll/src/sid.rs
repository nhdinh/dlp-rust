use std::ptr;

use windows::core::PSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows::Win32::Security::Authorization::ConvertSidToStringSidA;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Sentinel SID returned when the current process token cannot be resolved.
///
/// "S-1-0-0" is the Windows NULL SID; it is never a real user and makes
/// attribution failures explicit in diagnostic snapshots and audit events.
const FALLBACK_SID: &str = "S-1-0-0";

/// Retrieves the current process user's SID as a string.
///
/// Returns a Windows SID string (e.g., "S-1-5-21-...") on success.
/// On failure, returns the NULL SID ("S-1-0-0") and logs the failure reason
/// via OutputDebugStringW so operators can diagnose attribution problems.
///
/// # Safety
///
/// This function uses `unsafe` blocks to call Win32 APIs. All raw pointers
/// are valid because they are derived from properly allocated buffers and
/// handles are checked before use.
pub fn get_current_user_sid() -> String {
    unsafe {
        // 1. Open the current process token with TOKEN_QUERY access.
        let mut token_handle: HANDLE = HANDLE(ptr::null_mut());
        let result = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle);
        if result.is_err() {
            crate::debug_log("[dlp-hook] get_current_user_sid: OpenProcessToken failed, falling back to NULL SID\0");
            return FALLBACK_SID.to_string();
        }

        // 2. Determine the required buffer size for TOKEN_USER.
        let mut return_length: u32 = 0;
        let _ = GetTokenInformation(token_handle, TokenUser, None, 0, &mut return_length);

        // The first call is expected to fail with ERROR_INSUFFICIENT_BUFFER;
        // return_length now holds the required size.
        if return_length == 0 {
            crate::debug_log("[dlp-hook] get_current_user_sid: GetTokenInformation returned zero buffer size, falling back to NULL SID\0");
            let _ = CloseHandle(token_handle);
            return FALLBACK_SID.to_string();
        }

        // 3. Allocate a buffer of the required size and call again.
        let mut buffer: Vec<u8> = vec![0; return_length as usize];
        let result = GetTokenInformation(
            token_handle,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        );

        if result.is_err() {
            crate::debug_log("[dlp-hook] get_current_user_sid: GetTokenInformation failed, falling back to NULL SID\0");
            let _ = CloseHandle(token_handle);
            return FALLBACK_SID.to_string();
        }

        // 4. Cast the buffer to PTOKEN_USER and read the SID pointer.
        // SAFETY: buffer is large enough (verified by GetTokenInformation success).
        let token_user = buffer.as_ptr() as *const TOKEN_USER;
        let sid = (*token_user).User.Sid;

        if sid.0.is_null() {
            crate::debug_log("[dlp-hook] get_current_user_sid: SID pointer is null, falling back to NULL SID\0");
            let _ = CloseHandle(token_handle);
            return FALLBACK_SID.to_string();
        }

        // 5. Convert the SID to a string.
        let mut string_sid_ptr: windows::core::PSTR = PSTR(ptr::null_mut());
        let result = ConvertSidToStringSidA(sid, &mut string_sid_ptr);

        let sid_string = if result.is_ok() && !string_sid_ptr.0.is_null() {
            // SAFETY: ConvertSidToStringSidA guarantees a valid null-terminated C string on success.
            // We verify the pointer is non-null before creating CStr as defense-in-depth.
            let cstr = std::ffi::CStr::from_ptr(string_sid_ptr.0 as *const i8);
            cstr.to_string_lossy().into_owned()
        } else {
            crate::debug_log("[dlp-hook] get_current_user_sid: ConvertSidToStringSidA failed, falling back to NULL SID\0");
            FALLBACK_SID.to_string()
        };

        // 6. Free the allocated string and close the token handle.
        if !string_sid_ptr.0.is_null() {
            let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                string_sid_ptr.0 as *mut _,
            )));
        }
        let _ = CloseHandle(token_handle);

        sid_string
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_current_user_sid_returns_non_empty() {
        let sid = get_current_user_sid();
        assert!(!sid.is_empty(), "SID should not be empty");
        assert!(
            sid.starts_with("S-1-"),
            "SID should start with S-1-: got {}",
            sid
        );
    }

    #[test]
    fn test_get_current_user_sid_fallback_format() {
        // On non-Windows or if the API fails, the fallback is the NULL SID
        // "S-1-0-0". We verify the format is valid by checking the prefix.
        let sid = get_current_user_sid();
        // The SID must match the standard Windows SID format.
        assert!(
            sid.starts_with("S-1-"),
            "SID must be a valid Windows SID string: got {}",
            sid
        );
    }
}
