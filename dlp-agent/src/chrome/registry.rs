//! Chrome Enterprise Connector registry helpers.
//!
//! Manages the Windows registry keys that Chrome uses to discover the
//! Content Analysis agent pipe name and configuration.

#[cfg(windows)]
use anyhow::{Context, Result};

#[cfg(windows)]
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegSetValueExW,
};

#[cfg(windows)]
use windows::core::PCWSTR;

/// Registry path where Chrome Enterprise Connector settings are stored.
#[cfg(windows)]
const CHROME_ENTERPRISE_KEY: &str =
    r"SOFTWARE\Policies\Google\Chrome\ContentAnalysis\Default";

/// Enables the Chrome Enterprise Content Analysis connector.
///
/// Writes the `Enabled` DWORD (1) and `PipeName` string to the Chrome
/// policy registry key so Chrome knows to connect to the agent pipe.
///
/// # Errors
///
/// Returns an error if the registry key cannot be created or the values
/// cannot be written.
#[cfg(windows)]
pub fn enable_connector(pipe_name: &str) -> Result<()> {
    let key_path: Vec<u16> = CHROME_ENTERPRISE_KEY
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut hkey = HKEY::default();

    unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(key_path.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .ok()
        .context("create Chrome Enterprise registry key")?;

        // Write Enabled = 1 (DWORD)
        let enabled: u32 = 1;
        let enabled_name: Vec<u16> = "Enabled".encode_utf16().chain(std::iter::once(0)).collect();
        RegSetValueExW(
            hkey,
            PCWSTR::from_raw(enabled_name.as_ptr()),
            0,
            windows::Win32::System::Registry::REG_DWORD,
            Some(&enabled.to_le_bytes()),
        )
        .ok()
        .context("write Enabled registry value")?;

        // Write PipeName (REG_SZ)
        let pipe_name_wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
        let pipe_name_bytes: &[u8] =
            std::slice::from_raw_parts(pipe_name_wide.as_ptr().cast(), pipe_name_wide.len() * 2);
        let pipe_name_reg: Vec<u16> = "PipeName".encode_utf16().chain(std::iter::once(0)).collect();
        RegSetValueExW(
            hkey,
            PCWSTR::from_raw(pipe_name_reg.as_ptr()),
            0,
            REG_SZ,
            Some(pipe_name_bytes),
        )
        .ok()
        .context("write PipeName registry value")?;

        let _ = RegCloseKey(hkey);
    }

    Ok(())
}

/// Disables the Chrome Enterprise Content Analysis connector.
///
/// Writes `Enabled` = 0 to the Chrome policy registry key.
#[cfg(windows)]
pub fn disable_connector() -> Result<()> {
    let key_path: Vec<u16> = CHROME_ENTERPRISE_KEY
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut hkey = HKEY::default();

    unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(key_path.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .ok()
        .context("open Chrome Enterprise registry key")?;

        let enabled: u32 = 0;
        let enabled_name: Vec<u16> = "Enabled".encode_utf16().chain(std::iter::once(0)).collect();
        RegSetValueExW(
            hkey,
            PCWSTR::from_raw(enabled_name.as_ptr()),
            0,
            windows::Win32::System::Registry::REG_DWORD,
            Some(&enabled.to_le_bytes()),
        )
        .ok()
        .context("write Enabled=0 registry value")?;

        let _ = RegCloseKey(hkey);
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn enable_connector(_pipe_name: &str) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn disable_connector() -> anyhow::Result<()> {
    Ok(())
}
