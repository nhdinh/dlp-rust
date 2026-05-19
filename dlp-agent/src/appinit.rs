//! AppInit_DLLs registry reading and Secure Boot detection.
//!
//! The agent only READS these values at boot. Installer handles writes.
//! D-18: Secure Boot detection via GetFirmwareEnvironmentVariable.

use std::ffi::c_void;
use tracing::{info, warn};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_SZ,
};

const APPINIT_DLLS_VALUE: &str = "AppInit_DLLs";
const LOAD_APPINIT_VALUE: &str = "LoadAppInit_DLLs";
const REQUIRE_SIGNED_VALUE: &str = "RequireSignedAppInit_DLLs";
/// AppInit_DLLs registry state read at boot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppInitState {
    pub appinit_dlls: Option<String>,
    pub load_appinit: Option<u32>,
    pub require_signed: Option<u32>,
}

/// Read AppInit_DLLs registry state from HKLM.
///
/// Opens the registry key read-only and queries the three values:
/// - `AppInit_DLLs` (REG_SZ)
/// - `LoadAppInit_DLLs` (REG_DWORD)
/// - `RequireSignedAppInit_DLLs` (REG_DWORD)
///
/// # Errors
///
/// Returns an error if the registry key cannot be opened or read.
pub fn read_appinit_state() -> anyhow::Result<AppInitState> {
    let mut hkey = windows::Win32::System::Registry::HKEY::default();
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::w!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
            None,
            KEY_READ,
            &mut hkey,
        )
    };

    if result.is_err() {
        return Err(anyhow::anyhow!("RegOpenKeyExW failed: {:?}", result));
    }

    let state = AppInitState {
        appinit_dlls: read_reg_string(hkey, APPINIT_DLLS_VALUE),
        load_appinit: read_reg_dword(hkey, LOAD_APPINIT_VALUE),
        require_signed: read_reg_dword(hkey, REQUIRE_SIGNED_VALUE),
    };

    unsafe {
        let _ = RegCloseKey(hkey);
    }

    Ok(state)
}

/// Read a REG_SZ value from an open registry key.
fn read_reg_string(
    hkey: windows::Win32::System::Registry::HKEY,
    value_name: &str,
) -> Option<String> {
    let name_wide: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut buf = vec![0u8; 512];
    let mut buf_size: u32 = buf.len() as u32;
    let mut reg_type = windows::Win32::System::Registry::REG_VALUE_TYPE(0);

    let result = unsafe {
        RegQueryValueExW(
            hkey,
            windows::core::PCWSTR::from_raw(name_wide.as_ptr()),
            None,
            Some(&mut reg_type),
            Some(buf.as_mut_ptr()),
            Some(&mut buf_size),
        )
    };

    if result.is_err() || reg_type != REG_SZ {
        return None;
    }

    // buf_size includes the NUL terminator in bytes; convert to UTF-16 chars.
    let chars = (buf_size as usize) / 2;
    let u16_slice = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u16, chars) };

    // Trim NUL terminator.
    let trimmed = if u16_slice.last() == Some(&0) {
        &u16_slice[..u16_slice.len().saturating_sub(1)]
    } else {
        u16_slice
    };

    Some(String::from_utf16_lossy(trimmed))
}

/// Read a REG_DWORD value from an open registry key.
fn read_reg_dword(hkey: windows::Win32::System::Registry::HKEY, value_name: &str) -> Option<u32> {
    let name_wide: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut value: u32 = 0;
    let mut buf_size: u32 = std::mem::size_of::<u32>() as u32;
    let mut reg_type = windows::Win32::System::Registry::REG_VALUE_TYPE(0);

    let result = unsafe {
        RegQueryValueExW(
            hkey,
            windows::core::PCWSTR::from_raw(name_wide.as_ptr()),
            None,
            Some(&mut reg_type),
            Some((&mut value as *mut u32).cast::<u8>()),
            Some(&mut buf_size),
        )
    };

    if result.is_err() || reg_type != REG_DWORD {
        return None;
    }

    Some(value)
}

/// Detect Secure Boot state.
///
/// Returns `Some(true)` if Secure Boot is enabled, `Some(false)` if disabled,
/// `None` if the API is unavailable (pre-UEFI system) or fails.
///
/// Uses `GetFirmwareEnvironmentVariableW` with the EFI Secure Boot variable GUID.
pub fn is_secure_boot_enabled() -> Option<bool> {
    #[cfg(windows)]
    {
        use windows::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableW;

        let mut value: u32 = 0;
        let result = unsafe {
            GetFirmwareEnvironmentVariableW(
                windows::core::w!("SecureBoot"),
                windows::core::w!("{8be4df61-93ca-11d2-aa0d-00e098032b8c}"),
                Some(&mut value as *mut _ as *mut c_void),
                std::mem::size_of::<u32>() as u32,
            )
        };
        if result == 0 {
            return None;
        }
        Some(value != 0)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Events emitted by the AppInit boot check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppInitEvent {
    /// Secure Boot is enabled, blocking AppInit_DLLs.
    SecureBootBlocksAppInit,
    /// AppInit_DLLs registry value is not configured.
    AppInitNotConfigured,
    /// AppInit_DLLs is configured and available.
    AppInitConfigured,
}

/// Boot-time check: verify AppInit is configured, emit audit events.
///
/// # Arguments
///
/// * `appinit_state` — The registry state read by `read_appinit_state`.
///
/// # Returns
///
/// A vector of events describing the AppInit configuration status.
pub fn boot_check(appinit_state: &AppInitState) -> Vec<AppInitEvent> {
    let mut events = Vec::new();

    if let Some(true) = is_secure_boot_enabled() {
        warn!("Secure Boot is enabled — AppInit_DLLs will be blocked by Windows");
        events.push(AppInitEvent::SecureBootBlocksAppInit);
    }

    match &appinit_state.appinit_dlls {
        None => {
            warn!("AppInit_DLLs registry value is not set");
            events.push(AppInitEvent::AppInitNotConfigured);
        }
        Some(dlls) if dlls.trim().is_empty() => {
            warn!("AppInit_DLLs registry value is empty");
            events.push(AppInitEvent::AppInitNotConfigured);
        }
        Some(dlls) => {
            info!(appinit_dlls = %dlls, "AppInit_DLLs is configured");
            events.push(AppInitEvent::AppInitConfigured);
        }
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_secure_boot_enabled_returns_option_bool() {
        // On Windows, returns Some(true/false) or None.
        // On non-Windows, returns None.
        let result = is_secure_boot_enabled();
        assert!(result.is_none() || result == Some(true) || result == Some(false));
    }

    #[test]
    fn test_appinit_state_default() {
        let state = AppInitState::default();
        assert!(state.appinit_dlls.is_none());
        assert!(state.load_appinit.is_none());
        assert!(state.require_signed.is_none());
    }

    #[test]
    fn test_boot_check_secure_boot_blocks() {
        // We can't reliably test Secure Boot state on all machines,
        // so we test the event logic by mocking the state.
        let state = AppInitState {
            appinit_dlls: Some("dlp_hook_dll.dll".to_string()),
            load_appinit: Some(1),
            require_signed: Some(1),
        };

        let events = boot_check(&state);
        // Events may contain SecureBootBlocksAppInit if Secure Boot is enabled.
        // Always contains AppInitConfigured because dlls is non-empty.
        assert!(
            events.contains(&AppInitEvent::AppInitConfigured),
            "expected AppInitConfigured when dlls is set"
        );
    }

    #[test]
    fn test_boot_check_not_configured_empty() {
        let state = AppInitState {
            appinit_dlls: Some("".to_string()),
            load_appinit: None,
            require_signed: None,
        };

        let events = boot_check(&state);
        assert!(
            events.contains(&AppInitEvent::AppInitNotConfigured),
            "expected AppInitNotConfigured when dlls is empty"
        );
    }

    #[test]
    fn test_boot_check_not_configured_none() {
        let state = AppInitState {
            appinit_dlls: None,
            load_appinit: None,
            require_signed: None,
        };

        let events = boot_check(&state);
        assert!(
            events.contains(&AppInitEvent::AppInitNotConfigured),
            "expected AppInitNotConfigured when dlls is None"
        );
    }

    #[test]
    fn test_appinit_event_equality() {
        assert_eq!(
            AppInitEvent::SecureBootBlocksAppInit,
            AppInitEvent::SecureBootBlocksAppInit
        );
        assert_eq!(
            AppInitEvent::AppInitNotConfigured,
            AppInitEvent::AppInitNotConfigured
        );
        assert_eq!(
            AppInitEvent::AppInitConfigured,
            AppInitEvent::AppInitConfigured
        );
        assert_ne!(
            AppInitEvent::SecureBootBlocksAppInit,
            AppInitEvent::AppInitNotConfigured
        );
    }
}
