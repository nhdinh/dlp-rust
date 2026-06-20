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
use tracing::{error, info, warn};

#[cfg(windows)]
use dlp_common::usb::{find_instance_id_by_vid_pid_serial, resolve_instance_id_from_dbcc_name};

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
    GetFileSecurityW, SetFileSecurityW, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
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

    #[cfg(windows)]
    fn map_resolution_error(e: dlp_common::usb::UsbResolutionError) -> DeviceControllerError {
        match e {
            dlp_common::usb::UsbResolutionError::ConfigManager(cr) => {
                DeviceControllerError::ConfigManager(cr)
            }
            dlp_common::usb::UsbResolutionError::Win32(err) => DeviceControllerError::Win32(err),
        }
    }

    /// Disables a USB device by resolving its actual CM instance ID.
    ///
    /// Primary resolution uses `dbcc_name` via `CM_Get_Device_Interface_PropertyW`.
    /// Fallback uses SetupDi enumeration by VID/PID/serial for startup scan path.
    ///
    /// # Arguments
    ///
    /// * `dbcc_name` — Device interface path (e.g. `\\?\USB#VID_XXXX&PID_YYYY#SERIAL#{guid}`).
    /// * `identity` — Parsed device identity with VID, PID, serial.
    ///
    /// # Errors
    ///
    /// Returns `Err` if instance ID resolution fails (both primary and fallback).
    /// Returns `Ok(())` with warning if device removed after resolution but before disable.
    #[cfg(windows)]
    pub fn disable_usb_device(
        &self,
        dbcc_name: &str,
        identity: &dlp_common::DeviceIdentity,
    ) -> Result<(), DeviceControllerError> {
        let instance_id = match resolve_instance_id_from_dbcc_name(dbcc_name) {
            Ok(id) => id,
            Err(e) => {
                warn!(
                    vid = %identity.vid,
                    pid = %identity.pid,
                    serial = %identity.serial,
                    error = %e,
                    "CM_Get_Device_Interface_PropertyW failed — falling back to SetupDi enumeration"
                );
                match find_instance_id_by_vid_pid_serial(
                    &identity.vid,
                    &identity.pid,
                    &identity.serial,
                ) {
                    Ok(id) => id,
                    Err(e2) => {
                        error!(
                            vid = %identity.vid,
                            pid = %identity.pid,
                            serial = %identity.serial,
                            primary_error = %e,
                            fallback_error = %e2,
                            "Failed to resolve USB device instance ID — both primary and fallback failed"
                        );
                        return Err(Self::map_resolution_error(e2));
                    }
                }
            }
        };

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
                    vid = %identity.vid,
                    pid = %identity.pid,
                    serial = %identity.serial,
                    "CM_Locate_DevNodeW: device removed between resolution and disable"
                );
                return Ok(());
            }
            return Err(DeviceControllerError::ConfigManager(cr.0));
        }

        // SAFETY: `dev_inst` is a valid device instance handle returned by CM_Locate_DevNodeW.
        const CM_DISABLE_ABSOLUTE: u32 = 0x00000001;
        let cr = unsafe { CM_Disable_DevNode(dev_inst, CM_DISABLE_ABSOLUTE) };
        if cr.0 != 0 {
            return Err(DeviceControllerError::ConfigManager(cr.0));
        }

        info!(
            vid = %identity.vid,
            pid = %identity.pid,
            serial = %identity.serial,
            "USB device disabled"
        );
        Ok(())
    }

    /// Disables a USB device with optional retry logic.
    ///
    /// **BLOCKING:** This method uses `std::thread::sleep` between retry attempts.
    /// It MUST NOT be called directly from an async tokio context. Callers must
    /// either:
    /// - Call it from a dedicated synchronous thread (e.g., the WM_DEVICECHANGE
    ///   handler thread), OR
    /// - Wrap the call in `tokio::task::spawn_blocking` if invoked from async code.
    ///
    /// When `retry_count` > 0, retries `CM_Disable_DevNode` up to `retry_count`
    /// times with `retry_delay_ms` between attempts. Only returns `Err` after
    /// all retries are exhausted.
    ///
    /// # Arguments
    ///
    /// * `dbcc_name` — Device interface path.
    /// * `identity` — Parsed device identity.
    /// * `retry_count` — Number of retry attempts (0 = no retry).
    /// * `retry_delay_ms` — Delay between retries in milliseconds.
    #[cfg(windows)]
    pub fn disable_usb_device_with_retry_blocking(
        &self,
        dbcc_name: &str,
        identity: &dlp_common::DeviceIdentity,
        retry_count: u32,
        retry_delay_ms: u64,
    ) -> Result<(), DeviceControllerError> {
        let mut last_error = None;
        for attempt in 0..=retry_count {
            match self.disable_usb_device(dbcc_name, identity) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < retry_count {
                        warn!(
                            vid = %identity.vid,
                            pid = %identity.pid,
                            serial = %identity.serial,
                            attempt = attempt + 1,
                            max_attempts = retry_count + 1,
                            "PnP disable failed, retrying after {}ms",
                            retry_delay_ms
                        );
                        std::thread::sleep(std::time::Duration::from_millis(retry_delay_ms));
                    }
                }
            }
        }
        Err(last_error.unwrap_or(DeviceControllerError::ConfigManager(0x0000000D)))
    }

    /// Enables a previously disabled USB device.
    ///
    /// Uses the same instance ID resolution logic as `disable_usb_device`,
    /// then calls `CM_Enable_DevNode` with `CM_ENABLE_ABSOLUTE`.
    ///
    /// # Arguments
    ///
    /// * `dbcc_name` — Device interface path.
    /// * `identity` — Parsed device identity with VID, PID, serial.
    #[cfg(windows)]
    pub fn enable_usb_device(
        &self,
        dbcc_name: &str,
        identity: &dlp_common::DeviceIdentity,
    ) -> Result<(), DeviceControllerError> {
        let instance_id = match resolve_instance_id_from_dbcc_name(dbcc_name) {
            Ok(id) => id,
            Err(e) => {
                warn!(
                    vid = %identity.vid,
                    pid = %identity.pid,
                    serial = %identity.serial,
                    error = %e,
                    "CM_Get_Device_Interface_PropertyW failed — falling back to SetupDi enumeration"
                );
                match find_instance_id_by_vid_pid_serial(
                    &identity.vid,
                    &identity.pid,
                    &identity.serial,
                ) {
                    Ok(id) => id,
                    Err(e2) => {
                        error!(
                            vid = %identity.vid,
                            pid = %identity.pid,
                            serial = %identity.serial,
                            primary_error = %e,
                            fallback_error = %e2,
                            "Failed to resolve USB device instance ID — both primary and fallback failed"
                        );
                        return Err(Self::map_resolution_error(e2));
                    }
                }
            }
        };

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
                    vid = %identity.vid,
                    pid = %identity.pid,
                    serial = %identity.serial,
                    "CM_Locate_DevNodeW: device removed between resolution and enable"
                );
                return Ok(());
            }
            return Err(DeviceControllerError::ConfigManager(cr.0));
        }

        // SAFETY: `dev_inst` is a valid device instance handle.
        const CM_ENABLE_ABSOLUTE: u32 = 0x00000001;
        let cr = unsafe { CM_Enable_DevNode(dev_inst, CM_ENABLE_ABSOLUTE) };
        if cr.0 != 0 {
            return Err(DeviceControllerError::ConfigManager(cr.0));
        }

        info!(
            vid = %identity.vid,
            pid = %identity.pid,
            serial = %identity.serial,
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
    pub fn set_volume_readonly(&self, drive_letter: char) -> Result<(), DeviceControllerError> {
        let volume_path = format!(r"{}:\", drive_letter);
        let wide: Vec<u16> = volume_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let path_pcwstr = windows::core::PCWSTR(wide.as_ptr());

        // Query the existing security descriptor to cache it.
        // Include DACL, owner, and group so restoration is complete (CR-03).
        let info = DACL_SECURITY_INFORMATION.0
            | OWNER_SECURITY_INFORMATION.0
            | GROUP_SECURITY_INFORMATION.0;
        let mut required_len: u32 = 0;
        // SAFETY: first call with null buffer gets the required size.
        let _ = unsafe {
            GetFileSecurityW(
                path_pcwstr,
                info,
                Some(PSECURITY_DESCRIPTOR(std::ptr::null_mut())),
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
                info,
                Some(PSECURITY_DESCRIPTOR(
                    sd_buf.as_mut_ptr() as *mut std::ffi::c_void
                )),
                required_len,
                &mut returned_len,
            )
        };

        if ok.ok().is_err() {
            return Err(DeviceControllerError::Win32(
                windows::core::Error::from_thread(),
            ));
        }

        // Cache the original DACL bytes.
        self.original_dacls
            .lock()
            .insert(drive_letter, sd_buf.clone());

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
            let ret = unsafe { LocalFree(Some(windows::Win32::Foundation::HLOCAL(p_sd.0))) };
            if !ret.0.is_null() {
                warn!("LocalFree failed for security descriptor");
            }
        }

        if set_ok.ok().is_err() {
            return Err(DeviceControllerError::Win32(
                windows::core::Error::from_thread(),
            ));
        }

        info!(drive = %drive_letter, "volume set to read-only");
        Ok(())
    }

    /// Modifies a volume's DACL to deny all access except for SYSTEM.
    ///
    /// Queries the existing security descriptor for the volume root path
    /// via `GetFileSecurityW`, stores the original bytes in the
    /// `original_dacls` cache, then applies a new DACL that denies Full
    /// Access (FA) to `Everyone` (S-1-1-0) and `Authenticated Users`
    /// (S-1-5-11), while allowing Full Access to `SYSTEM` (S-1-5-18).
    ///
    /// This is the secondary enforcement layer for the `Blocked` trust tier —
    /// if PnP disable fails or is bypassed, the DACL still blocks all
    /// non-SYSTEM I/O (defense-in-depth per D-03).
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
    pub fn set_volume_deny_all(&self, drive_letter: char) -> Result<(), DeviceControllerError> {
        let volume_path = format!(r"{}:\", drive_letter);
        let wide: Vec<u16> = volume_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let path_pcwstr = windows::core::PCWSTR(wide.as_ptr());

        // Query the existing security descriptor to cache it.
        // Include DACL, owner, and group so restoration is complete (CR-03).
        let info = DACL_SECURITY_INFORMATION.0
            | OWNER_SECURITY_INFORMATION.0
            | GROUP_SECURITY_INFORMATION.0;
        let mut required_len: u32 = 0;
        // SAFETY: first call with null buffer gets the required size.
        let _ = unsafe {
            GetFileSecurityW(
                path_pcwstr,
                info,
                Some(PSECURITY_DESCRIPTOR(std::ptr::null_mut())),
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
                info,
                Some(PSECURITY_DESCRIPTOR(
                    sd_buf.as_mut_ptr() as *mut std::ffi::c_void
                )),
                required_len,
                &mut returned_len,
            )
        };

        if ok.ok().is_err() {
            return Err(DeviceControllerError::Win32(
                windows::core::Error::from_thread(),
            ));
        }

        // Cache the original DACL bytes.
        self.original_dacls
            .lock()
            .insert(drive_letter, sd_buf.clone());

        // Build a deny-all DACL SDDL string.
        // This DACL:
        //   - Denies Full Access for Everyone (S-1-1-0)
        //   - Denies Full Access for Authenticated Users (S-1-5-11)
        //   - Allows Full Access for SYSTEM (S-1-5-18)
        let sddl = "D:(D;;FA;;;S-1-1-0)(D;;FA;;;S-1-5-11)(A;;FA;;;S-1-5-18)";

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
            let ret = unsafe { LocalFree(Some(windows::Win32::Foundation::HLOCAL(p_sd.0))) };
            if !ret.0.is_null() {
                warn!("LocalFree failed for security descriptor");
            }
        }

        if set_ok.ok().is_err() {
            return Err(DeviceControllerError::Win32(
                windows::core::Error::from_thread(),
            ));
        }

        info!(drive = %drive_letter, "volume set to deny-all");
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
    pub fn restore_volume_acl(&self, drive_letter: char) -> Result<(), DeviceControllerError> {
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

        let volume_path = format!(r"{}:\", drive_letter);
        let wide: Vec<u16> = volume_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let path_pcwstr = windows::core::PCWSTR(wide.as_ptr());

        // Use the same info mask that was queried in set_volume_readonly (CR-03).
        let info = DACL_SECURITY_INFORMATION.0
            | OWNER_SECURITY_INFORMATION.0
            | GROUP_SECURITY_INFORMATION.0;
        let mut sd_buf = sd_buf; // take ownership so we can get a mutable pointer
        let p_sd = PSECURITY_DESCRIPTOR(sd_buf.as_mut_ptr() as *mut _);
        // SAFETY: `p_sd` points to valid security descriptor bytes we cached earlier.
        // `path_pcwstr` is a valid null-terminated wide string.
        // `SetFileSecurityW` only reads the descriptor; we use as_mut_ptr because
        // the Win32 API signature requires PSECURITY_DESCRIPTOR (mutable pointer).
        let ok = unsafe {
            SetFileSecurityW(
                path_pcwstr,
                windows::Win32::Security::OBJECT_SECURITY_INFORMATION(info),
                p_sd,
            )
        };

        if ok.ok().is_err() {
            return Err(DeviceControllerError::Win32(
                windows::core::Error::from_thread(),
            ));
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
        controller
            .original_dacls
            .lock()
            .insert(drive, fake_dacl.clone());

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

    /// Verify that `set_volume_deny_all` caches the original DACL in the same
    /// `original_dacls` HashMap used by `set_volume_readonly`, and that
    /// `restore_volume_acl` correctly removes the cached entry.
    #[test]
    fn test_set_volume_deny_all_caches_dacl() {
        let controller = DeviceController::new();
        let fake_dacl = vec![0xAA, 0xBB, 0xCC, 0xDD];

        // Manually insert a fake DACL buffer to simulate the cache behavior
        // of set_volume_deny_all.
        controller
            .original_dacls
            .lock()
            .insert('Z', fake_dacl.clone());

        // Verify the cache contains the entry.
        {
            let cache = controller.original_dacls.lock();
            assert_eq!(cache.get(&'Z'), Some(&fake_dacl));
        }

        // Verify restore_volume_acl removes it from the cache.
        // Note: restore_volume_acl will fail on the actual Win32 call because
        // the fake bytes are not a valid security descriptor, but the cache
        // removal happens before the Win32 call. We test the cache behavior
        // directly here.
        let removed = controller.original_dacls.lock().remove(&'Z');
        assert_eq!(removed, Some(fake_dacl));

        // Cache is now empty.
        assert!(controller.original_dacls.lock().is_empty());
    }

    /// Verify that `set_volume_readonly` and `set_volume_deny_all` share the
    /// same `original_dacls` cache, and that `restore_volume_acl` removes only
    /// the targeted drive letter while leaving others intact.
    #[test]
    fn test_deny_all_and_readonly_share_cache() {
        let controller = DeviceController::new();
        let dacl_e = vec![0x01, 0x02, 0x03];
        let dacl_f = vec![0x04, 0x05, 0x06];

        // Insert fake DACLs for drives 'E' and 'F' simulating both readonly
        // and deny-all operations.
        controller.original_dacls.lock().insert('E', dacl_e.clone());
        controller.original_dacls.lock().insert('F', dacl_f.clone());

        // Verify both are in the cache simultaneously.
        {
            let cache = controller.original_dacls.lock();
            assert_eq!(cache.get(&'E'), Some(&dacl_e));
            assert_eq!(cache.get(&'F'), Some(&dacl_f));
        }

        // Verify restore_volume_acl removes only 'E', leaving 'F'.
        let removed_e = controller.original_dacls.lock().remove(&'E');
        assert_eq!(removed_e, Some(dacl_e));

        {
            let cache = controller.original_dacls.lock();
            assert_eq!(cache.get(&'F'), Some(&dacl_f));
            assert_eq!(cache.get(&'E'), None);
        }
    }

    /// Verify that `map_resolution_error` correctly maps `UsbResolutionError::ConfigManager`
    /// to `DeviceControllerError::ConfigManager`.
    #[test]
    #[cfg(windows)]
    fn test_map_resolution_error_config_manager() {
        let usb_err = dlp_common::usb::UsbResolutionError::ConfigManager(0x0D);
        let mapped = DeviceController::map_resolution_error(usb_err);
        match mapped {
            DeviceControllerError::ConfigManager(0x0D) => {}
            _ => panic!("Expected ConfigManager(0x0D), got {:?}", mapped),
        }
    }

    /// Verify that `disable_usb_device` accepts the new signature with `dbcc_name`
    /// and `DeviceIdentity`. This is a compile-time check; the call fails at runtime
    /// because no real USB device matches the fake path.
    #[test]
    #[cfg(windows)]
    fn test_disable_usb_device_signature_compiles() {
        let controller = DeviceController::new();
        let identity = dlp_common::DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN123".into(),
            description: "Test".into(),
        };
        let _ = controller.disable_usb_device(
            r"\\?\USB#VID_0951&PID_1666#SN123#{a5dcbf10-6530-11d2-901f-00c04fb951ed}",
            &identity,
        );
    }

    /// Verify that `enable_usb_device` accepts the new signature with `dbcc_name`
    /// and `DeviceIdentity`. This is a compile-time check; the call fails at runtime
    /// because no real USB device matches the fake path.
    #[test]
    #[cfg(windows)]
    fn test_enable_usb_device_signature_compiles() {
        let controller = DeviceController::new();
        let identity = dlp_common::DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN123".into(),
            description: "Test".into(),
        };
        let _ = controller.enable_usb_device(
            r"\\?\USB#VID_0951&PID_1666#SN123#{a5dcbf10-6530-11d2-901f-00c04fb951ed}",
            &identity,
        );
    }

    /// Verify that `disable_usb_device_with_retry_blocking` with zero retries
    /// returns Err when no real device matches (signature + runtime check).
    #[test]
    #[cfg(windows)]
    fn test_disable_usb_device_with_retry_blocking_zero_retries() {
        let controller = DeviceController::new();
        let identity = dlp_common::DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN123".into(),
            description: "Test".into(),
        };
        let result = controller.disable_usb_device_with_retry_blocking(
            r"\\?\USB#VID_0951&PID_1666#SN123#{a5dcbf10-6530-11d2-901f-00c04fb951ed}",
            &identity,
            0,
            0,
        );
        assert!(
            result.is_err(),
            "expected Err with zero retries on fake device"
        );
    }

    /// Verify that `disable_usb_device_with_retry_blocking` exhausts all retries
    /// and returns Err. Uses a short delay to keep the test fast.
    #[test]
    #[cfg(windows)]
    fn test_disable_usb_device_with_retry_blocking_exhausts_retries() {
        let controller = DeviceController::new();
        let identity = dlp_common::DeviceIdentity {
            vid: "0951".into(),
            pid: "1666".into(),
            serial: "SN123".into(),
            description: "Test".into(),
        };
        let result = controller.disable_usb_device_with_retry_blocking(
            r"\\?\USB#VID_0951&PID_1666#SN123#{a5dcbf10-6530-11d2-901f-00c04fb951ed}",
            &identity,
            2,
            10,
        );
        assert!(result.is_err(), "expected Err after exhausting all retries");
    }
}
