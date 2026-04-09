//! Self-registration of the DLP Server bind address in the Windows
//! registry.
//!
//! On startup the server writes its resolved `BIND_ADDR` to:
//!
//! ```text
//! HKLM\SOFTWARE\DLP\Server\BindAddr
//! ```
//!
//! On shutdown (normal exit) it clears the value so stale addresses
//! are never left behind. The `dlp-admin-cli` reads this key to
//! auto-detect the server without manual configuration.

use tracing::{debug, info, warn};

/// Registry key path.
const REG_KEY: &str = r"SOFTWARE\DLP\Server";

/// Registry value name.
const REG_VALUE: &str = "BindAddr";

/// Writes the bind address to the registry.
///
/// Best-effort: logs a warning on failure but never panics or returns
/// an error, because the server must start even if registry access is
/// unavailable (e.g., running as a non-admin user in development).
///
/// # Arguments
///
/// * `addr` - The socket address the server is listening on.
pub fn register(addr: &std::net::SocketAddr) {
    let addr_str = addr.to_string();
    match write_reg(REG_KEY, REG_VALUE, &addr_str) {
        Ok(()) => info!(
            addr = %addr_str,
            "Registered BIND_ADDR in registry \
             (HKLM\\{REG_KEY}\\{REG_VALUE})"
        ),
        Err(e) => warn!(
            addr = %addr_str,
            error = %e,
            "Failed to register BIND_ADDR in registry \
             (non-fatal, CLI auto-detect may not work)"
        ),
    }
}

/// Clears the bind address from the registry.
///
/// Called on graceful shutdown so the CLI does not connect to a stale
/// address after the server stops.
pub fn unregister() {
    match delete_reg(REG_KEY, REG_VALUE) {
        Ok(()) => debug!(
            "Cleared BIND_ADDR from registry \
             (HKLM\\{REG_KEY}\\{REG_VALUE})"
        ),
        Err(e) => debug!(
            error = %e,
            "Failed to clear BIND_ADDR from registry (non-fatal)"
        ),
    }
}

// ---- Win32 registry helpers (Windows only) ------------------------------

#[cfg(windows)]
fn write_reg(
    subkey: &str,
    name: &str,
    value: &str,
) -> anyhow::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY,
        HKEY_LOCAL_MACHINE, KEY_WRITE, REG_OPTION_NON_VOLATILE,
        REG_SZ,
    };

    unsafe {
        let subkey_wide: Vec<u16> = subkey
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let name_wide: Vec<u16> = name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let value_wide: Vec<u16> = value
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let value_bytes = std::slice::from_raw_parts(
            value_wide.as_ptr().cast::<u8>(),
            value_wide.len() * 2,
        );

        let mut hkey = HKEY::default();
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(subkey_wide.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .ok()
        .map_err(|e| anyhow::anyhow!("RegCreateKeyExW: {e}"))?;

        let result = RegSetValueExW(
            hkey,
            PCWSTR::from_raw(name_wide.as_ptr()),
            0,
            REG_SZ,
            Some(value_bytes),
        );
        let _ = RegCloseKey(hkey);

        result
            .ok()
            .map_err(|e| anyhow::anyhow!("RegSetValueExW: {e}"))
    }
}

#[cfg(windows)]
fn delete_reg(
    subkey: &str,
    name: &str,
) -> anyhow::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, HKEY,
        HKEY_LOCAL_MACHINE, KEY_WRITE,
    };

    unsafe {
        let subkey_wide: Vec<u16> = subkey
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let name_wide: Vec<u16> = name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut hkey = HKEY::default();
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(subkey_wide.as_ptr()),
            0,
            KEY_WRITE,
            &mut hkey,
        )
        .ok()
        .map_err(|e| anyhow::anyhow!("RegOpenKeyExW: {e}"))?;

        let result = RegDeleteValueW(
            hkey,
            PCWSTR::from_raw(name_wide.as_ptr()),
        );
        let _ = RegCloseKey(hkey);

        result
            .ok()
            .map_err(|e| anyhow::anyhow!("RegDeleteValueW: {e}"))
    }
}

// ---- Non-Windows stubs --------------------------------------------------

#[cfg(not(windows))]
fn write_reg(
    _subkey: &str,
    _name: &str,
    _value: &str,
) -> anyhow::Result<()> {
    Ok(()) // No-op on non-Windows.
}

#[cfg(not(windows))]
fn delete_reg(
    _subkey: &str,
    _name: &str,
) -> anyhow::Result<()> {
    Ok(()) // No-op on non-Windows.
}
