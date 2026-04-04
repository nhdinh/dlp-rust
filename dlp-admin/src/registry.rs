//! Windows registry read/write utilities.

use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
    REG_VALUE_TYPE,
};
use windows::core::PCWSTR;

/// Registry path under HKLM where the dlp-admin bcrypt hash is stored.
pub const REG_KEY_PATH: &str = r"SOFTWARE\DLP\Agent\Credentials";

/// Name of the registry value holding the bcrypt hash.
pub const REG_VALUE_NAME: &str = "DLPAuthHash";

/// Reads a REG_SZ string value from `HKLM\{subkey}\{name}`.
pub fn read_registry_string(subkey: &str, name: &str) -> anyhow::Result<String> {
    unsafe {
        let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        let mut hkey = HKEY::default();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(subkey_wide.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );
        if status.is_err() {
            anyhow::bail!(
                "RegOpenKeyExW failed to open HKLM\\{subkey}: {status:?}"
            );
        }

        // Query size first.
        let mut data_size = 0u32;
        let mut value_type = REG_VALUE_TYPE::default();
        let _ = RegQueryValueExW(
            hkey,
            PCWSTR::from_raw(name_wide.as_ptr()),
            None,
            Some(std::ptr::null_mut()),
            None,
            Some(&mut data_size),
        );

        if data_size == 0 {
            let _ = RegCloseKey(hkey);
            return Ok(String::new());
        }

        let mut data = vec![0u8; data_size as usize];
        let status = RegQueryValueExW(
            hkey,
            PCWSTR::from_raw(name_wide.as_ptr()),
            None,
            Some(&mut value_type),
            Some(data.as_mut_ptr()),
            Some(&mut data_size),
        );
        let _ = RegCloseKey(hkey);

        if status.is_err() {
            anyhow::bail!(
                "RegQueryValueExW failed to read '{name}': {status:?}"
            );
        }

        if value_type.0 != REG_SZ.0 {
            anyhow::bail!(
                "Unexpected registry type {} for '{name}' (expected REG_SZ)",
                value_type.0
            );
        }

        // REG_SZ is UTF-16 LE, null-terminated.
        let wide: &[u16] =
            std::slice::from_raw_parts(data.as_ptr() as *const u16, (data_size as usize) / 2);
        Ok(String::from_utf16_lossy(wide)
            .trim_end_matches('\0')
            .to_string())
    }
}

/// Writes a REG_SZ string value to `HKLM\{subkey}\{name}`, creating the key
/// if it does not exist.
pub fn write_registry_string(subkey: &str, name: &str, value: &str) -> anyhow::Result<()> {
    unsafe {
        let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let value_wide: Vec<u16> = value
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let value_bytes: *const u8 = value_wide.as_ptr().cast();
        let value_bytes: &[u8] =
            std::slice::from_raw_parts(value_bytes, value_wide.len() * 2);

        let mut hkey = HKEY::default();
        let status = RegCreateKeyExW(
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
        if status.is_err() {
            anyhow::bail!(
                "RegCreateKeyExW failed to create/open HKLM\\{subkey}: {status:?}"
            );
        }

        let status = RegSetValueExW(
            hkey,
            PCWSTR::from_raw(name_wide.as_ptr()),
            0,
            REG_SZ,
            Some(value_bytes),
        );
        let _ = RegCloseKey(hkey);

        if status.is_err() {
            anyhow::bail!("RegSetValueExW failed to set '{name}': {status:?}");
        }

        Ok(())
    }
}
