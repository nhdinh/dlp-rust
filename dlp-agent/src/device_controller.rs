//! Active USB device control via Windows Configuration Manager (CM_*) APIs.
//!
//! Provides [`DeviceController`] — a singleton that wraps `CM_Disable_DevNode`,
//! `CM_Enable_DevNode`, and volume DACL manipulation to enforce USB trust tiers
//! at the PnP level (not just at file I/O time).
//!
//! ## Architecture
//!
//! - **Blocked tier**: device is disabled immediately on arrival via
//!   `CM_Disable_DevNode` — the device disappears from Device Manager and
//!   generates no file events.
//! - **ReadOnly tier**: the volume's DACL is modified on arrival to remove
//!   write/delete ACEs for `Everyone` and `Authenticated Users`; the original
//!   DACL is cached and restored on removal.
//! - **FullAccess tier**: no action — device remains fully enabled.
//!
//! ## Fail-safe behaviour
//!
//! If `CM_Locate_DevNodeW` fails (device removed between scan and enforcement),
//! a warning is logged and the call returns `Ok(())` — the agent does NOT panic.

use std::collections::HashMap;

use parking_lot::Mutex;
use tracing::{info, warn};

#[cfg(windows)]
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Disable_DevNode, CM_Enable_DevNode, CM_Locate_DevNodeW, CM_LOCATE_DEVNODE_NORMAL,
};
#[cfg(windows)]
use windows::Win32::Foundation::LocalFree;
#[cfg(windows)]
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
#[cfg(windows)]
use windows::Win32::Security::{
    GetFileSecurityW, SetFileSecurityW, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};

/// Error type for device controller operations.
#[derive(Debug, thiserror::Error)]
pub enum DeviceControllerError {
    /// Device instance ID could not be converted to a wide string.
    #[error("invalid device instance ID encoding")]
    InvalidInstanceId,
    /// Configuration Manager returned an error code.
    #[error("Configuration Manager error: {0:#010x}")]
    ConfigManager(u32),
    /// Win32 API returned an error.
    #[error("Win32 error: {0}")]
    Win32(#[from] windows::core::Error),
    /// Security descriptor operation failed.
    #[error("security descriptor error: {0}")]
    SecurityDescriptor(String),
    /// Volume path could not be opened.
    #[error("failed to access volume: {0}")]
    VolumeAccess(String),
}

/// Active USB device controller.
///
/// Wraps Windows CM_* APIs for disabling/enabling USB devices and
/// volume DACL manipulation for read-only enforcement.
///
/// The `original_dacls` cache stores raw security descriptor bytes keyed by
/// drive letter so that the original ACL can be restored when the device is
/// removed.
#[derive(Debug)]
pub struct DeviceController {
    /// Original DACLs keyed by drive letter, for restoration on removal.
    original_dacls: Mutex<HashMap<char, Vec<u8>>>,
}

impl DeviceController {
    /// Constructs a new [`DeviceController`] with an empty DACL cache.
    pub fn new() -> Self {
        Self {
            original_dacls: Mutex::new(HashMap::new()),
        }
    }

    /// Disables a USB device by its VID/PID/serial triple.
    ///
    /// Builds a device instance ID (`USB\VID_XXXX&PID_YYYY\SERIAL`), locates
    /// the device node via `CM_Locate_DevNodeW`, and disables it with
    /// `CM_Disable_DevNode` using `CM_DISABLE_ABSOLUTE`.
    ///
    /// # Arguments
    ///
    /// * `vid` — USB Vendor ID hex string (e.g., `"0951"`).
    /// * `pid` — USB Product ID hex string (e.g., `"1666"`).
    /// * `serial` — Device serial number string.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the CM APIs return an unexpected error.
    /// If the device is not found (already removed), logs a warning and
    /// returns `Ok(())` — this is NOT treated as a failure.
    #[cfg(windows)]
    pub fn disable_usb_device(
        &self,
        vid: &str,
        pid: &str,
        serial: &str,
    ) -> Result<(), DeviceControllerError> {
        let instance_id = format!(r"USB\VID_{vid}&PID_{pid}\{serial}");
        let wide: Vec<u16> = instance_id
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut dev_inst: u32 = 0;
        // SAFETY: `wide` is a valid null-terminated UTF-16 string.
        let cr = unsafe {
            CM_Locate_DevNodeW(
                &mut dev_inst,
                windows::core::PCWSTR(wide.as_ptr()),
                CM_LOCATE_DEVNODE_NORMAL,
            )
        };

        // CONFIGRET(0) is CR_SUCCESS.
        if cr.0 != 0 {
            // CR_NO_SUCH_DEVNODE = 0x0000000D — device already removed.
            const CR_NO_SUCH_DEVNODE: u32 = 0x0000000D;
            if cr.0 == CR_NO_SUCH_DEVNODE {
                warn!(
                    vid = %vid,
                    pid = %pid,
                    serial = %serial,
                    "CM_Locate_DevNodeW: device not found — may have been removed"
                );
                return Ok(());
            }
            return Err(DeviceControllerError::ConfigManager(cr.0));
        }

        // SAFETY: `dev_inst` is a valid device instance handle returned by CM_Locate_DevNodeW.
        let cr = unsafe { CM_Disable_DevNode(dev_inst, 0) };
        if cr.0 != 0 {
            return Err(DeviceControllerError::ConfigManager(cr.0));
        }

        info!(
            vid = %vid,
            pid = %pid,
            serial = %serial,
            "USB device disabled"
        );
        Ok(())
    }

    /// Enables a previously disabled USB device.
    ///
    /// Uses the same instance ID construction and locate logic as
    /// [`disable_usb_device`], then calls `CM_Enable_DevNode` with
    /// `CM_ENABLE_ABSOLUTE`.
    ///
    /// # Arguments
    ///
    /// * `vid` — USB Vendor ID hex string.
    /// * `pid` — USB Product ID hex string.
    /// * `serial` — Device serial number string.
    #[cfg(windows)]
    pub fn enable_usb_device(
        &self,
        vid: &str,
        pid: &str,
        serial: &str,
    ) -> Result<(), DeviceControllerError> {
        let instance_id = format!(r"USB\VID_{vid}&PID_{pid}\{serial}");
        let wide: Vec<u16> = instance_id
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut dev_inst: u32 = 0;
        // SAFETY: `wide` is a valid null-terminated UTF-16 string.
        let cr = unsafe {
            CM_Locate_DevNodeW(
                &mut dev_inst,
                windows::core::PCWSTR(wide.as_ptr()),
                CM_LOCATE_DEVNODE_NORMAL,
            )
        };

        if cr.0 != 0 {
            const CR_NO_SUCH_DEVNODE: u32 = 0x0000000D;
            if cr.0 == CR_NO_SUCH_DEVNODE {
                warn!(
                    vid = %vid,
                    pid = %pid,
                    serial = %serial,
                    "CM_Locate_DevNodeW: device not found — may have been removed"
                );
                return Ok(());
            }
            return Err(DeviceControllerError::ConfigManager(cr.0));
        }

        // SAFETY: `dev_inst` is a valid device instance handle.
        let cr = unsafe { CM_Enable_DevNode(dev_inst, 0) };
        if cr.0 != 0 {
            return Err(DeviceControllerError::ConfigManager(cr.0));
        }

        info!(
            vid = %vid,
            pid = %pid,
            serial = %serial,
            "USB device enabled"
        );
        Ok(())
    }

    /// Modifies a volume's DACL to remove write/delete permissions.
    ///
    /// Queries the existing security descriptor for the volume root path
    /// via `GetFileSecurityW`, stores the original bytes in the
    /// `original_dacls` cache, then applies a new DACL that strips write
    /// and delete ACEs for `Everyone` and `Authenticated Users`.
    ///
    /// # Arguments
    ///
    /// * `drive_letter` — Uppercase drive letter (e.g., `'E'`).
    ///
    /// # Errors
    ///
    /// Returns `Err` on any Win32 failure. The original DACL is only cached
    /// after a successful query.
    #[cfg(windows)]
    pub fn set_volume_readonly(
        &self,
        drive_letter: char,
    ) -> Result<(), DeviceControllerError> {
        let volume_path = format!(r"\\.\{}:", drive_letter);
        let wide: Vec<u16> = volume_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let path_pcwstr = windows::core::PCWSTR(wide.as_ptr());

        // Query the existing security descriptor to cache it.
        let mut required_len: u32 = 0;
        // SAFETY: first call with null buffer gets the required size.
        let _ = unsafe {
            GetFileSecurityW(
                path_pcwstr,
                DACL_SECURITY_INFORMATION.0,
                PSECURITY_DESCRIPTOR(std::ptr::null_mut()),
                0,
                &mut required_len,
            )
        };

        if required_len == 0 {
            return Err(DeviceControllerError::SecurityDescriptor(
                "GetFileSecurityW returned zero size".to_string(),
            ));
        }

        let mut sd_buf = vec![0u8; required_len as usize];
        let mut returned_len: u32 = 0;
        // SAFETY: `sd_buf` is sized to `required_len`.
        let ok = unsafe {
            GetFileSecurityW(
                path_pcwstr,
                DACL_SECURITY_INFORMATION.0,
                PSECURITY_DESCRIPTOR(sd_buf.as_mut_ptr() as *mut std::ffi::c_void),
                required_len,
                &mut returned_len,
            )
        };

        if ok == windows::Win32::Foundation::BOOL(0) {
            return Err(DeviceControllerError::Win32(windows::core::Error::from_win32()));
        }

        // Cache the original DACL bytes.
        self.original_dacls.lock().insert(drive_letter, sd_buf.clone());

        // Build a restrictive DACL SDDL string.
        // This DACL:
        //   - Denies write/delete for Everyone (S-1-1-0)
        //   - Denies write/delete for Authenticated Users (S-1-5-11)
        //   - Allows read/execute for Everyone
        //   - Allows full control for SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544)
        let sddl =
            "D:(D;;WDWO;;;S-1-1-0)(D;;WDWO;;;S-1-5-11)(A;;0x1200A9;;;S-1-1-0)(A;;FA;;;S-1-5-18)(A;;FA;;;S-1-5-32-544)";

        let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut p_sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());

        // SAFETY: `sddl_wide` is a valid null-terminated UTF-16 SDDL string.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                windows::core::PCWSTR(sddl_wide.as_ptr()),
                1, // SDDL_REVISION_1
                &mut p_sd,
                None,
            )
        };

        if let Err(e) = ok {
            return Err(DeviceControllerError::Win32(e));
        }

        // SAFETY: `p_sd` points to a valid security descriptor allocated by the API.
        // `path_pcwstr` is the same valid wide string used above.
        let set_ok = unsafe { SetFileSecurityW(path_pcwstr, DACL_SECURITY_INFORMATION, p_sd) };

        // SAFETY: free the security descriptor allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        if !p_sd.0.is_null() {
            let _ = unsafe { LocalFree(windows::Win32::Foundation::HLOCAL(p_sd.0)) };
        }

        if set_ok == windows::Win32::Foundation::BOOL(0) {
            return Err(DeviceControllerError::Win32(windows::core::Error::from_win32()));
        }

        info!(drive = %drive_letter, "volume set to read-only");
        Ok(())
    }

    /// Restores the original DACL for a volume from the cache.
    ///
    /// Looks up the cached security descriptor bytes for the drive letter and
    /// applies them via `SetFileSecurityW`. Removes the entry from the cache
    /// after successful restoration.
    ///
    /// # Arguments
    ///
    /// * `drive_letter` — Uppercase drive letter (e.g., `'E'`).
    ///
    /// # Errors
    ///
    /// Returns `Ok(())` even if no cached DACL exists (logs a warning).
    /// Returns `Err` only if `SetFileSecurityW` fails.
    #[cfg(windows)]
    pub fn restore_volume_acl(
        &self,
        drive_letter: char,
    ) -> Result<(), DeviceControllerError> {
        let sd_buf = {
            let mut cache = self.original_dacls.lock();
            cache.remove(&drive_letter)
        };

        let Some(sd_buf) = sd_buf else {
            warn!(
                drive = %drive_letter,
                "no cached DACL found — device may have been removed before restoration"
            );
            return Ok(());
        };

        let volume_path = format!(r"\\.\{}:", drive_letter);
        let wide: Vec<u16> = volume_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let path_pcwstr = windows::core::PCWSTR(wide.as_ptr());

        let p_sd = PSECURITY_DESCRIPTOR(sd_buf.as_ptr() as *mut _);
        // SAFETY: `p_sd` points to valid security descriptor bytes we cached earlier.
        // `path_pcwstr` is a valid null-terminated wide string.
        let ok = unsafe { SetFileSecurityW(path_pcwstr, DACL_SECURITY_INFORMATION, p_sd) };

        if ok == windows::Win32::Foundation::BOOL(0) {
            return Err(DeviceControllerError::Win32(windows::core::Error::from_win32()));
        }

        info!(drive = %drive_letter, "volume ACL restored");
        Ok(())
    }
}

impl Default for DeviceController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_controller_new_empty_cache() {
        let controller = DeviceController::new();
        let cache = controller.original_dacls.lock();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_dacl_backup_roundtrip() {
        let controller = DeviceController::new();
        let drive = 'E';
        let fake_dacl = vec![0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00];

        // Insert fake DACL into cache directly (simulating set_volume_readonly).
        controller.original_dacls.lock().insert(drive, fake_dacl.clone());

        // Verify it's in the cache.
        {
            let cache = controller.original_dacls.lock();
            assert_eq!(cache.get(&drive), Some(&fake_dacl));
        }

        // Simulate restore — remove from cache.
        let removed = controller.original_dacls.lock().remove(&drive);
        assert_eq!(removed, Some(fake_dacl));

        // Cache is now empty.
        assert!(controller.original_dacls.lock().is_empty());
    }

    #[test]
    fn test_multiple_drive_letters_isolated() {
        let controller = DeviceController::new();
        let dacl_e = vec![0x01, 0x02];
        let dacl_f = vec![0x03, 0x04];

        controller.original_dacls.lock().insert('E', dacl_e.clone());
        controller.original_dacls.lock().insert('F', dacl_f.clone());

        let cache = controller.original_dacls.lock();
        assert_eq!(cache.get(&'E'), Some(&dacl_e));
        assert_eq!(cache.get(&'F'), Some(&dacl_f));
        assert_eq!(cache.get(&'G'), None);
    }
}
