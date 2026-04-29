//! Chrome Content Analysis agent HKLM self-registration.
//!
//! Writes the pipe name to the registry so Chrome discovers the agent on
//! startup.  Registration is idempotent — safe to write on every service
//! startup.  Failures are logged but never block service start.

use anyhow::Result;
use tracing::{info, warn};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_WRITE,
    REG_OPTION_NON_VOLATILE, REG_SZ,
};

/// Registry subkey path for Chrome third-party CAS agents.
///
/// This path may need adjustment based on the exact Chrome Enterprise
/// version.  See 29-RESEARCH.md Assumption A1 for discussion.
const REG_KEY_PATH: &str = r"SOFTWARE\Google\Chrome\3rdparty\cas_agents";

/// Registry value name that stores the pipe name.
const REG_VALUE_NAME: &str = "pipe_name";

/// The pipe name Chrome should connect to.
const PIPE_NAME: &str = r"\\.\pipe\brcm_chrm_cas";

/// Registers this agent as a Chrome Content Analysis agent in HKLM.
///
/// If the `DLP_SKIP_CHROME_REG` environment variable is set to `"1"`,
/// registration is skipped (used in tests to avoid requiring elevated
/// privileges).
///
/// # Errors
///
/// Returns `Ok(())` even if the registry write fails — service startup
/// must never be blocked by a registration failure.
#[cfg(windows)]
pub fn register_agent() -> Result<()> {
    if std::env::var("DLP_SKIP_CHROME_REG").is_ok_and(|v| v == "1") {
        info!("Chrome registry registration skipped (DLP_SKIP_CHROME_REG=1)");
        return Ok(());
    }

    unsafe {
        let subkey_wide: Vec<u16> =
            REG_KEY_PATH.encode_utf16().chain(std::iter::once(0)).collect();
        let name_wide: Vec<u16> =
            REG_VALUE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let value_wide: Vec<u16> =
            PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let value_bytes: &[u8] =
            std::slice::from_raw_parts(value_wide.as_ptr().cast(), value_wide.len() * 2);

        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let result = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(subkey_wide.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );
        if result.is_err() {
            warn!(
                "RegCreateKeyExW failed for HKLM\\{}: {:?} — continuing without registration",
                REG_KEY_PATH, result
            );
            return Ok(());
        }

        let result = RegSetValueExW(
            hkey,
            PCWSTR::from_raw(name_wide.as_ptr()),
            0,
            REG_SZ,
            Some(value_bytes),
        );
        let _ = RegCloseKey(hkey);

        if result.is_err() {
            warn!(
                "RegSetValueExW failed for Chrome pipe name: {:?} — continuing without registration",
                result
            );
            return Ok(());
        }
    }

    info!("Chrome Content Analysis agent registered in HKLM");
    Ok(())
}

#[cfg(not(windows))]
pub fn register_agent() -> Result<()> {
    // No-op on non-Windows platforms (tests).
    Ok(())
}
