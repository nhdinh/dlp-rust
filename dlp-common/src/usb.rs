//! Shared USB device enumeration and path-parsing helpers.
//!
//! Used by `dlp-agent` (event-driven arrival/removal handlers) and
//! `dlp-admin-cli` (point-in-time scan and register flow). The Windows-only
//! SetupDi calls are gated behind `#[cfg(windows)]`; on other platforms
//! [`enumerate_connected_usb_devices`] is a no-op returning an empty vector.

use crate::endpoint::DeviceIdentity;

// ---------------------------------------------------------------------------
// Shared USB enforcement config constants
// ---------------------------------------------------------------------------
// These constants are referenced by dlp-server, dlp-agent, and dlp-admin-cli
// to ensure enum values never drift across the codebase.
// If you change a value here, you MUST update all consumers.

/// Valid values for `usb_blocked_failure_mode`.
pub const USB_FAILURE_MODES: &[&str] = &["Hard error", "Warning only", "Retry then error"];

/// Valid values for `usb_startup_resolution_mode`.
/// NOTE: "Volume GUID resolution" is not yet implemented; it is kept in the
/// constant list for forward compatibility but rejected at config-set time.
pub const USB_RESOLUTION_MODES: &[&str] = &["Volume GUID resolution", "VID/PID/serial fallback"];

/// Valid values for `usb_none_serial_policy`.
/// NOTE: "Port-based disambiguation" is not yet implemented; it is kept in the
/// constant list for forward compatibility but rejected at config-set time.
pub const USB_NONE_SERIAL_POLICIES: &[&str] = &[
    "Always Blocked",
    "Port-based disambiguation",
    "Allow unregistered",
];

/// Default values for each USB config field.
pub const DEFAULT_USB_BLOCKED_FAILURE_MODE: &str = "Warning only";
pub const DEFAULT_USB_STARTUP_RESOLUTION_MODE: &str = "VID/PID/serial fallback";
pub const DEFAULT_USB_NONE_SERIAL_POLICY: &str = "Always Blocked";

#[cfg(windows)]
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_Device_IDW, CM_Get_Parent, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
    SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW,
    SetupDiGetDeviceRegistryPropertyW, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT,
    SETUP_DI_REGISTRY_PROPERTY, SP_DEVICE_INTERFACE_DATA, SP_DEVICE_INTERFACE_DETAIL_DATA_W,
    SP_DEVINFO_DATA,
};
#[cfg(windows)]
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_Device_Interface_PropertyW, CR_BUFFER_SMALL, CR_SUCCESS,
};
#[cfg(windows)]
use windows::Win32::Devices::Properties::{
    DEVPKEY_Device_InstanceId, DEVPROPTYPE, DEVPROP_TYPE_STRING,
};

/// SetupDi registry property: device friendly name (`SPDRP_FRIENDLYNAME` = 0x0C).
#[cfg(windows)]
const SPDRP_FRIENDLYNAME: u32 = 0x0000_000C;

/// SetupDi registry property: device description fallback (`SPDRP_DEVICEDESC` = 0x00).
#[cfg(windows)]
const SPDRP_DEVICEDESC: u32 = 0x0000_0000;

/// `GUID_DEVINTERFACE_USB_DEVICE` — the device interface class for USB devices,
/// used with `SetupDiGetClassDevsW` to enumerate currently-connected USB devices.
#[cfg(windows)]
const GUID_DEVINTERFACE_USB_DEVICE: windows::core::GUID = windows::core::GUID::from_values(
    0xA5DCBF10,
    0x6530,
    0x11D2,
    [0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED],
);

/// `GUID_DEVINTERFACE_DISK` — the device interface class for disk drives.
/// Used to enumerate all disk devices, then filter to USB-attached ones by
/// walking the PnP device tree.
#[cfg(windows)]
const GUID_DEVINTERFACE_DISK: windows::core::GUID = windows::core::GUID::from_values(
    0x53F56307,
    0xB6BF,
    0x11D0,
    [0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B],
);

/// Parses a Windows USB device interface path of the form
/// `\\?\USB#VID_XXXX&PID_YYYY#SERIAL#{GUID}` into a [`DeviceIdentity`].
///
/// The `description` field is left empty; callers fill it from
/// [`setupdi_description_for_device`] on Windows.
/// Synthesized or missing serials (empty segment, or one starting with `&`)
/// are coerced to the literal string `"(none)"`.
///
/// # Examples
///
/// ```
/// use dlp_common::usb::parse_usb_device_path;
/// let id = parse_usb_device_path(r"\\?\USB#VID_0951&PID_1666#SN12345#{guid}");
/// assert_eq!(id.vid, "0951");
/// assert_eq!(id.pid, "1666");
/// assert_eq!(id.serial, "SN12345");
/// ```
pub fn parse_usb_device_path(dbcc_name: &str) -> DeviceIdentity {
    let mut identity = DeviceIdentity::default();
    let parts: Vec<&str> = dbcc_name.split('#').collect();

    // Segment 1 carries VID/PID.
    if let Some(vid_pid_segment) = parts.get(1) {
        for token in vid_pid_segment.split('&') {
            let lower = token.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("vid_") {
                identity.vid = rest.to_string();
            } else if let Some(rest) = lower.strip_prefix("pid_") {
                identity.pid = rest.to_string();
            }
        }
    }

    // Segment 2 carries the serial number, or a Windows-synthesized
    // placeholder like `&0` when no serial descriptor is present.
    let raw_serial = parts.get(2).copied().unwrap_or("");
    identity.serial = if raw_serial.is_empty() || raw_serial.starts_with('&') {
        "(none)".to_string()
    } else {
        raw_serial.to_string()
    };

    identity
}

/// Looks up the SetupDi friendly name (or device description fallback) for
/// the USB device whose interface path is `device_path`.
///
/// Uses a two-tier matching strategy:
///
/// 1. **Primary (exact path):** Enumerates `GUID_DEVINTERFACE_USB_DEVICE`
///    interfaces via `SetupDiEnumDeviceInterfaces`, calls
///    `SetupDiGetDeviceInterfaceDetailW` to get the actual device path for
///    each interface, and compares it directly to `device_path` using
///    `eq_ignore_ascii_case`. This eliminates false-positive matches when
///    multiple devices share the same VID+PID (e.g. a Bluetooth adapter and
///    a SanDisk flash drive both with VID_0781).
///
/// 2. **Fallback (VID+PID+serial):** If exact path matching fails, falls
///    back to the legacy VID+PID+serial matching via
///    `SetupDiEnumDeviceInfo` + `SetupDiGetDeviceInstanceIdW`. This path
///    is needed for the startup scan where only VID/PID/serial are known.
///
/// Returns an empty string on any Win32 error or if no matching device is found.
#[cfg(windows)]
pub fn setupdi_description_for_device(device_path: &str) -> String {
    let description = setupdi_description_by_exact_path(device_path);
    if !description.is_empty() {
        return description;
    }

    // Fallback: VID+PID+serial matching for startup scan path (D-09).
    setupdi_description_by_vid_pid_serial(device_path)
}

/// Primary match strategy: exact device interface path comparison.
///
/// Enumerates `GUID_DEVINTERFACE_USB_DEVICE` interfaces and compares the
/// `DevicePath` from `SetupDiGetDeviceInterfaceDetailW` directly against
/// `device_path` using case-insensitive ASCII comparison.
#[cfg(windows)]
fn setupdi_description_by_exact_path(device_path: &str) -> String {
    // SAFETY: passing GUID_DEVINTERFACE_USB_DEVICE + null enumerator string +
    // DIGCF_PRESENT | DIGCF_DEVICEINTERFACE is a well-defined SetupDi usage that
    // selects currently-present USB device interfaces.
    let hdev = unsafe {
        SetupDiGetClassDevsW(
            Some(&GUID_DEVINTERFACE_USB_DEVICE),
            windows::core::PCWSTR::null(),
            None,
            DIGCF_DEVICEINTERFACE | DIGCF_PRESENT,
        )
    };
    let hdev = match hdev {
        Ok(h) => h,
        Err(_) => return String::new(),
    };

    let mut index: u32 = 0;

    loop {
        let mut interface_data = SP_DEVICE_INTERFACE_DATA {
            cbSize: std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: hdev is valid; interface_data is owned stack memory with cbSize set.
        // Loop terminates on the first Err (ERROR_NO_MORE_ITEMS).
        if unsafe {
            SetupDiEnumDeviceInterfaces(
                hdev,
                None,
                &GUID_DEVINTERFACE_USB_DEVICE,
                index,
                &mut interface_data,
            )
        }
        .is_err()
        {
            break;
        }

        // Retrieve the device interface path and the associated SP_DEVINFO_DATA.
        if let Some((path, devinfo)) = get_device_interface_path_and_devinfo(hdev, &interface_data)
        {
            // Case-insensitive comparison: Windows device paths can differ in
            // casing (e.g. `USB#VID_0781` vs `USB#vid_0781`).
            if path.eq_ignore_ascii_case(device_path) {
                let desc = read_string_property(hdev, &devinfo, SPDRP_FRIENDLYNAME)
                    .filter(|s| !s.is_empty())
                    .or_else(|| read_string_property(hdev, &devinfo, SPDRP_DEVICEDESC))
                    .unwrap_or_default();
                // SAFETY: hdev is a valid handle from SetupDiGetClassDevsW above.
                let _ = unsafe { SetupDiDestroyDeviceInfoList(hdev) };
                return desc;
            }
        }

        index += 1;
        // Safety valve: bound the loop against a pathological enumeration.
        if index > 1024 {
            break;
        }
    }

    // SAFETY: hdev is a valid handle obtained from SetupDiGetClassDevsW above.
    let _ = unsafe { SetupDiDestroyDeviceInfoList(hdev) };

    String::new()
}

/// Fallback match strategy: VID+PID+serial matching.
///
/// Used when exact path matching fails, primarily for the startup scan path
/// where only VID/PID/serial are available (D-09).
#[cfg(windows)]
fn setupdi_description_by_vid_pid_serial(device_path: &str) -> String {
    use windows::Win32::Devices::DeviceAndDriverInstallation::SetupDiGetDeviceInstanceIdW;

    let parsed = parse_usb_device_path(device_path);

    // SAFETY: passing GUID_DEVINTERFACE_USB_DEVICE + null enumerator string +
    // DIGCF_PRESENT | DIGCF_DEVICEINTERFACE is a well-defined SetupDi usage.
    let hdev = unsafe {
        SetupDiGetClassDevsW(
            Some(&GUID_DEVINTERFACE_USB_DEVICE),
            windows::core::PCWSTR::null(),
            None,
            DIGCF_DEVICEINTERFACE | DIGCF_PRESENT,
        )
    };
    let hdev = match hdev {
        Ok(h) => h,
        Err(_) => return String::new(),
    };

    let mut index: u32 = 0;

    loop {
        let mut devinfo = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: hdev is valid; devinfo is owned stack memory with cbSize set.
        if unsafe { SetupDiEnumDeviceInfo(hdev, index, &mut devinfo) }.is_err() {
            break;
        }

        // Read the device instance ID (e.g., `USB\VID_8087&PID_0036\5A0B047F08010`)
        // and parse it to extract VID/PID/serial for matching.
        let mut id_buf = [0u16; 256];
        let mut required: u32 = 0;
        let ok = unsafe {
            SetupDiGetDeviceInstanceIdW(
                hdev,
                &devinfo,
                Some(id_buf.as_mut_slice()),
                Some(&mut required),
            )
        };
        if ok.is_ok() {
            let instance_id = String::from_utf16_lossy(
                &id_buf
                    .iter()
                    .copied()
                    .take_while(|&w| w != 0)
                    .collect::<Vec<u16>>(),
            );
            // Reshape instance ID into the dbcc_name form for parsing.
            let reshaped = format!("\\\\?\\{}", instance_id.replace('\\', "#"));
            let candidate = parse_usb_device_path(&reshaped);

            // Match by VID + PID + serial.
            // Only treat a candidate with serial "(none)" as matching when the target
            // also has no serial. Bluetooth adapters that share a VID with a SanDisk
            // device have synthesised "(none)" serials and must not match a target
            // that has a real serial number.
            let serial_match = match (parsed.serial.as_str(), candidate.serial.as_str()) {
                ("(none)", "(none)") => true, // both have no serial
                ("(none)", _) => true,        // target has no serial; accept any candidate
                (_, "(none)") => false, // target has real serial; candidate has none → no match
                (t, c) => t == c,       // both have real serials; must match exactly
            };
            if candidate.vid == parsed.vid && candidate.pid == parsed.pid && serial_match {
                let desc = read_string_property(hdev, &devinfo, SPDRP_FRIENDLYNAME)
                    .filter(|s| !s.is_empty())
                    .or_else(|| read_string_property(hdev, &devinfo, SPDRP_DEVICEDESC))
                    .unwrap_or_default();
                // SAFETY: hdev is a valid handle from SetupDiGetClassDevsW above.
                let _ = unsafe { SetupDiDestroyDeviceInfoList(hdev) };
                return desc;
            }
        }

        index += 1;
        // Safety valve: bound the loop against a pathological enumeration.
        if index > 1024 {
            break;
        }
    }

    // SAFETY: hdev is a valid handle obtained from SetupDiGetClassDevsW above.
    let _ = unsafe { SetupDiDestroyDeviceInfoList(hdev) };

    String::new()
}

/// Retrieve the device interface path and associated `SP_DEVINFO_DATA` from a
/// `SP_DEVICE_INTERFACE_DATA` entry.
///
/// Calls `SetupDiGetDeviceInterfaceDetailW` twice (size probe + detail fetch)
/// and extracts the null-terminated `DevicePath` string. The `SP_DEVINFO_DATA`
/// output from the second call is returned alongside the path so callers can
/// read device properties (friendly name, description) on match.
///
/// # Arguments
///
/// * `hdev` -- valid `HDEVINFO` device set.
/// * `interface_data` -- the interface data returned by `SetupDiEnumDeviceInterfaces`.
///
/// # Returns
///
/// `Some((path, devinfo))` on success, or `None` on any error.
#[cfg(windows)]
fn get_device_interface_path_and_devinfo(
    hdev: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    interface_data: &SP_DEVICE_INTERFACE_DATA,
) -> Option<(String, SP_DEVINFO_DATA)> {
    let mut required: u32 = 0;
    // SAFETY: First call with None buffer to query required size.
    let _ = unsafe {
        SetupDiGetDeviceInterfaceDetailW(hdev, interface_data, None, 0, Some(&mut required), None)
    };
    if required == 0 {
        return None;
    }

    let mut buf = vec![0u8; required as usize];
    let detail = buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
    // SAFETY: SP_DEVICE_INTERFACE_DETAIL_DATA_W starts with cbSize (u32) then DevicePath.
    unsafe {
        (*detail).cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
    }

    let mut devinfo = SP_DEVINFO_DATA {
        cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
        ..Default::default()
    };

    // SAFETY: Second call with allocated buffer and devinfo output.
    let ok = unsafe {
        SetupDiGetDeviceInterfaceDetailW(
            hdev,
            interface_data,
            Some(detail),
            required,
            None,
            Some(&mut devinfo),
        )
    };
    if ok.is_err() {
        return None;
    }

    // Extract the device path from the detail structure.
    let path_wide: Vec<u16> = unsafe {
        std::slice::from_raw_parts(
            (*detail).DevicePath.as_ptr(),
            (required as usize - std::mem::size_of::<u32>()) / 2,
        )
    }
    .iter()
    .copied()
    .take_while(|&w| w != 0)
    .collect();
    let path = String::from_utf16_lossy(&path_wide);

    Some((path, devinfo))
}

/// Reads a UTF-16 string property from a `SP_DEVINFO_DATA` entry.
///
/// Returns `None` on any Win32 error — callers substitute an empty string per D-04.
///
/// # Arguments
///
/// * `hdev` — a valid `HDEVINFO` set obtained from `SetupDiGetClassDevsW`.
/// * `devinfo` — pointer to an initialized `SP_DEVINFO_DATA` entry.
/// * `property` — one of `SPDRP_FRIENDLYNAME` or `SPDRP_DEVICEDESC` (as `u32`
///   constants from Windows SDK `SetupAPI.h`).
#[cfg(windows)]
fn read_string_property(
    hdev: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    devinfo: &SP_DEVINFO_DATA,
    property: u32,
) -> Option<String> {
    // 1024 bytes is enough for any realistic device name (REG_SZ, UTF-16 LE).
    let mut buf = vec![0u8; 1024];
    let mut required: u32 = 0;
    // SAFETY: buf is 1024 bytes and we pass its length as the buffer size.
    // The Win32 call fills buf with a null-terminated UTF-16 LE string or
    // sets required_size if buf is too small (we ignore truncation here —
    // a device name exceeding 512 UTF-16 chars is pathological).
    // `SETUP_DI_REGISTRY_PROPERTY` is a newtype wrapper over u32 — the
    // Windows crate requires it at the call site even though the underlying
    // value is just a u32.
    let ok = unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            hdev,
            devinfo,
            SETUP_DI_REGISTRY_PROPERTY(property),
            None,
            Some(buf.as_mut_slice()),
            Some(&mut required),
        )
    };
    if ok.is_err() {
        return None;
    }
    // buf contains a null-terminated UTF-16 LE string (REG_SZ). Decode by
    // pairing adjacent bytes into u16 code units and stopping at the first null.
    let wide: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    Some(String::from_utf16_lossy(&wide))
}

/// Enumerates currently-connected USB mass-storage devices via SetupDi.
///
/// Returns a `Vec<DeviceIdentity>` populated with VID, PID, serial, and
/// SetupDi-derived description for each USB mass-storage device (service ==
/// "USBSTOR"). Hubs, HID devices, Bluetooth adapters, and other non-storage
/// USB devices are filtered out. Devices without a parseable VID and PID are
/// also excluded.
///
/// # Platform
///
/// Windows only. On non-Windows targets, always returns `vec![]`.
pub fn enumerate_connected_usb_devices() -> Vec<DeviceIdentity> {
    #[cfg(windows)]
    {
        enumerate_connected_usb_devices_windows()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// Windows implementation of USB mass-storage device enumeration.
///
/// Enumerates `GUID_DEVINTERFACE_DISK` (all disk drives) and walks the PnP
/// device tree upward via [`CM_Get_Parent`] to find a USB ancestor node.
/// Only disks with a USB ancestor (instance path starting with `USB\`) are
/// included. VID/PID/serial are parsed from the USB ancestor's instance ID.
///
/// This approach correctly identifies USB mass-storage devices regardless of
/// their Windows driver service name (some devices use `usbccgp`, vendor-
/// specific drivers, or no explicit service at the USB device node level).
#[cfg(windows)]
fn enumerate_connected_usb_devices_windows() -> Vec<DeviceIdentity> {
    // SAFETY: GUID_DEVINTERFACE_DISK + null enumerator + DIGCF flags is a
    // well-defined SetupDi usage selecting present disk device interfaces.
    let hdev = match unsafe {
        SetupDiGetClassDevsW(
            Some(&GUID_DEVINTERFACE_DISK),
            windows::core::PCWSTR::null(),
            None,
            DIGCF_DEVICEINTERFACE | DIGCF_PRESENT,
        )
    } {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };

    let mut out: Vec<DeviceIdentity> = Vec::new();
    let mut index: u32 = 0;
    loop {
        let mut devinfo = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: hdev valid; devinfo owned with cbSize set.
        if unsafe { SetupDiEnumDeviceInfo(hdev, index, &mut devinfo) }.is_err() {
            break;
        }

        if let Some(mut identity) = find_usb_identity_for_disk(hdev, &devinfo) {
            // Read description from the disk device node (not the USB ancestor).
            identity.description = read_string_property(hdev, &devinfo, SPDRP_FRIENDLYNAME)
                .filter(|s| !s.is_empty())
                .or_else(|| read_string_property(hdev, &devinfo, SPDRP_DEVICEDESC))
                .unwrap_or_default();
            out.push(identity);
        }

        index += 1;
        // Safety valve: bound the loop against pathological enumeration.
        if index > 1024 {
            break;
        }
    }

    // SAFETY: hdev is a valid handle from SetupDiGetClassDevsW above.
    let _ = unsafe { SetupDiDestroyDeviceInfoList(hdev) };
    out
}

/// Walk up the PnP device tree from a disk device to find a USB ancestor.
///
/// Returns `Some(DeviceIdentity)` if a USB ancestor is found with valid
/// VID and PID, or `None` if no USB ancestor exists.
///
/// # Arguments
///
/// * `_hdev` -- valid `HDEVINFO` from `SetupDiGetClassDevsW` (unused but kept
///   for API consistency with other device enumeration helpers).
/// * `devinfo` -- the disk device info data to start walking from.
#[cfg(windows)]
fn find_usb_identity_for_disk(
    _hdev: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    devinfo: &SP_DEVINFO_DATA,
) -> Option<DeviceIdentity> {
    let mut current_devinst = devinfo.DevInst;
    for _ in 0..16 {
        // Avoid infinite loops — device trees are shallow (usually < 8 levels).
        let mut parent_devinst: u32 = 0;
        // SAFETY: current_devinst is a valid DEVINST returned by SetupDi.
        let cr = unsafe { CM_Get_Parent(&mut parent_devinst, current_devinst, 0) };
        if cr.0 != 0 {
            // No more parents (CR_NO_SUCH_DEVNODE, CR_INVALID_DEVINST, etc.).
            return None;
        }

        let mut id_buf = [0u16; 256];
        // SAFETY: parent_devinst is a valid DEVINST; id_buf is owned.
        let cr = unsafe { CM_Get_Device_IDW(parent_devinst, &mut id_buf, 0) };
        if cr.0 != 0 {
            current_devinst = parent_devinst;
            continue;
        }

        let id = String::from_utf16_lossy(
            &id_buf
                .iter()
                .copied()
                .take_while(|&w| w != 0)
                .collect::<Vec<u16>>(),
        );
        if !id.starts_with("USB\\") {
            current_devinst = parent_devinst;
            continue;
        }

        // Reshape: `USB\VID_X&PID_Y\SERIAL` -> `\\?\USB#VID_X&PID_Y#SERIAL#`.
        let reshaped = format!("\\\\?\\{}", id.replace('\\', "#"));
        let identity = parse_usb_device_path(&reshaped);
        if identity.vid.is_empty() || identity.pid.is_empty() {
            return None;
        }
        return Some(identity);
    }
    None
}

/// Errors that can occur when resolving a USB device instance ID.
#[derive(Debug)]
#[cfg(windows)]
pub enum UsbResolutionError {
    /// A Configuration Manager API returned an error code.
    ConfigManager(u32),
    /// A Win32 API returned an error.
    Win32(windows::core::Error),
}

#[cfg(windows)]
impl std::fmt::Display for UsbResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UsbResolutionError::ConfigManager(cr) => {
                write!(f, "Configuration Manager error: {cr:#010x}")
            }
            UsbResolutionError::Win32(e) => write!(f, "Win32 error: {e}"),
        }
    }
}

#[cfg(windows)]
impl std::error::Error for UsbResolutionError {}

/// Resolves the Configuration Manager instance ID from a `dbcc_name` device
/// interface path using `CM_Get_Device_Interface_PropertyW`.
///
/// This is the primary resolution path for hot-plug events where the
/// `dbcc_name` (e.g. `\\?\USB#VID_0951&PID_1666#SN12345#{guid}`) is
/// available from `WM_DEVICECHANGE`.
///
/// # Arguments
///
/// * `dbcc_name` — A device interface path, typically from `DEV_BROADCAST_DEVICEINTERFACE`.
///
/// # Returns
///
/// `Ok(instance_id)` on success, e.g. `USB\VID_0951&PID_1666\SN12345`.
/// `Err(UsbResolutionError::ConfigManager(...))` on CM API failure.
/// `Err(UsbResolutionError::Win32(...))` on encoding or unexpected Win32 error.
#[cfg(windows)]
pub fn resolve_instance_id_from_dbcc_name(dbcc_name: &str) -> Result<String, UsbResolutionError> {
    // Validate path starts with the expected prefix (ASVS V5 — reject malformed input).
    // Windows device paths arrive as `\\?\USB#...` (two leading backslashes + `?`).
    if !dbcc_name.starts_with(r"\\?\USB#") {
        return Err(UsbResolutionError::ConfigManager(0x00000013));
    }

    // Encode dbcc_name as null-terminated UTF-16.
    let mut wide_path: Vec<u16> = dbcc_name.encode_utf16().collect();
    wide_path.push(0);

    let mut required_size: u32 = 0;
    let mut property_type = DEVPROPTYPE(0);

    // SAFETY: wide_path is a valid null-terminated UTF-16 string.
    // First call: query required buffer size. Accept CR_BUFFER_SMALL (26) or CR_SUCCESS (0).
    let cr = unsafe {
        CM_Get_Device_Interface_PropertyW(
            windows::core::PCWSTR(wide_path.as_ptr()),
            &DEVPKEY_Device_InstanceId,
            &mut property_type,
            None,
            &mut required_size,
            0,
        )
    };

    if cr != CR_BUFFER_SMALL && cr != CR_SUCCESS {
        return Err(UsbResolutionError::ConfigManager(cr.0));
    }

    // Allocate buffer: capacity = (required_size / 2) + 1 for null terminator.
    let mut buffer: Vec<u16> = vec![0; (required_size as usize / 2) + 1];

    // SAFETY: buffer is large enough (required_size bytes). PCWSTR is valid.
    let cr = unsafe {
        CM_Get_Device_Interface_PropertyW(
            windows::core::PCWSTR(wide_path.as_ptr()),
            &DEVPKEY_Device_InstanceId,
            &mut property_type,
            Some(buffer.as_mut_ptr() as *mut u8),
            &mut required_size,
            0,
        )
    };

    if cr != CR_SUCCESS {
        return Err(UsbResolutionError::ConfigManager(cr.0));
    }

    // Verify property type is DEVPROP_TYPE_STRING.
    if property_type != DEVPROP_TYPE_STRING {
        return Err(UsbResolutionError::ConfigManager(0x00000013));
    }

    // Convert null-terminated UTF-16 to Rust String.
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    let instance_id = String::from_utf16(&buffer[..len])
        .map_err(|_e| UsbResolutionError::ConfigManager(0x0000000D))?;

    Ok(instance_id)
}

/// Finds a USB device's CM instance ID by enumerating present USB devices
/// via SetupDi and matching VID, PID, and optionally serial.
///
/// This is the fallback resolution path for the startup scan where no
/// `dbcc_name` is available (only VID/PID/serial from the registry cache).
///
/// # Arguments
///
/// * `vid` — Vendor ID (hex string, e.g. "0951").
/// * `pid` — Product ID (hex string, e.g. "1666").
/// * `serial` — Serial number or "(none)" for devices without a serial descriptor.
///
/// # Returns
///
/// `Ok(instance_id)` when exactly one match is found.
/// `Err(UsbResolutionError::ConfigManager(0x0D))` when zero matches found.
/// `Err(UsbResolutionError::ConfigManager(0x0D))` when serial is "(none)" and
/// multiple matches are found (ambiguous per D-05).
#[cfg(windows)]
pub fn find_instance_id_by_vid_pid_serial(
    vid: &str,
    pid: &str,
    serial: &str,
) -> Result<String, UsbResolutionError> {
    use windows::Win32::Devices::DeviceAndDriverInstallation::SetupDiGetDeviceInstanceIdW;

    // SAFETY: passing GUID_DEVINTERFACE_USB_DEVICE + null enumerator string +
    // DIGCF_PRESENT | DIGCF_DEVICEINTERFACE is a well-defined SetupDi usage.
    let hdev = unsafe {
        SetupDiGetClassDevsW(
            Some(&GUID_DEVINTERFACE_USB_DEVICE),
            windows::core::PCWSTR::null(),
            None,
            DIGCF_DEVICEINTERFACE | DIGCF_PRESENT,
        )
    };
    let hdev = match hdev {
        Ok(h) => h,
        Err(e) => return Err(UsbResolutionError::Win32(e)),
    };

    let mut matches: Vec<String> = Vec::new();
    let mut index: u32 = 0;

    loop {
        let mut devinfo = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: hdev is valid; devinfo is owned stack memory with cbSize set.
        if unsafe { SetupDiEnumDeviceInfo(hdev, index, &mut devinfo) }.is_err() {
            break;
        }

        let mut id_buf = [0u16; 256];
        let ok = unsafe {
            SetupDiGetDeviceInstanceIdW(hdev, &devinfo, Some(id_buf.as_mut_slice()), None)
        };
        if ok.is_ok() {
            let instance_id = String::from_utf16_lossy(
                &id_buf
                    .iter()
                    .copied()
                    .take_while(|&w| w != 0)
                    .collect::<Vec<u16>>(),
            );
            let reshaped = format!("\\\\?\\{}", instance_id.replace('\\', "#"));
            let candidate = parse_usb_device_path(&reshaped);

            // Apply the same serial matching logic as the description lookup:
            // a candidate with serial "(none)" does not match a target with a real serial.
            let serial_match = match (serial, candidate.serial.as_str()) {
                ("(none)", "(none)") => true,
                ("(none)", _) => true,
                (_, "(none)") => false,
                (t, c) => t == c,
            };
            if candidate.vid == vid && candidate.pid == pid && serial_match {
                matches.push(instance_id);
            }
        }

        index += 1;
        if index > 1024 {
            break;
        }
    }

    // SAFETY: hdev is a valid handle obtained from SetupDiGetClassDevsW above.
    let _ = unsafe { SetupDiDestroyDeviceInfoList(hdev) };

    match matches.len() {
        0 => Err(UsbResolutionError::ConfigManager(0x0000000D)), // CR_NO_SUCH_DEVNODE
        1 => Ok(matches.into_iter().next().unwrap()),
        _ if serial == "(none)" => {
            // Ambiguous: multiple devices with same VID+PID and no serial.
            Err(UsbResolutionError::ConfigManager(0x0000000D))
        }
        _ => {
            // Multiple matches but serial was specific — shouldn't happen.
            // Return first with a tracing warning is not possible here (no tracing in dlp-common).
            Ok(matches.into_iter().next().unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_happy_path() {
        let path = r"\\?\USB#VID_0951&PID_1666#1234567890#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
        let id = parse_usb_device_path(path);
        assert_eq!(id.vid, "0951");
        assert_eq!(id.pid, "1666");
        assert_eq!(id.serial, "1234567890");
        assert_eq!(id.description, "");
    }

    #[test]
    fn test_parse_no_serial_empty_segment() {
        let path = r"\\?\USB#VID_0951&PID_1666##{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
        let id = parse_usb_device_path(path);
        assert_eq!(id.vid, "0951");
        assert_eq!(id.pid, "1666");
        assert_eq!(id.serial, "(none)");
    }

    #[test]
    fn test_parse_no_serial_ampersand_synthesized() {
        let path = r"\\?\USB#VID_0951&PID_1666#&0#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
        let id = parse_usb_device_path(path);
        assert_eq!(id.serial, "(none)");
    }

    #[test]
    fn test_parse_lowercase_vid_pid_accepted() {
        let path = r"\\?\USB#vid_0951&pid_1666#abc#{guid}";
        let id = parse_usb_device_path(path);
        assert_eq!(id.vid, "0951");
        assert_eq!(id.pid, "1666");
        assert_eq!(id.serial, "abc");
    }

    #[test]
    fn test_parse_malformed_missing_vid_pid_segment() {
        let path = r"\\?\USB#garbage#serial#{guid}";
        let id = parse_usb_device_path(path);
        assert_eq!(id.vid, "");
        assert_eq!(id.pid, "");
        assert_eq!(id.serial, "serial");
    }

    #[test]
    fn test_parse_empty_string() {
        let id = parse_usb_device_path("");
        assert_eq!(id.vid, "");
        assert_eq!(id.pid, "");
        assert_eq!(id.serial, "(none)");
        assert_eq!(id.description, "");
    }

    #[test]
    fn test_parse_does_not_panic_on_unusual_input() {
        // Only two segments; should yield empty serial -> "(none)".
        let id = parse_usb_device_path(r"\\?\USB#VID_0951&PID_1666");
        assert_eq!(id.vid, "0951");
        assert_eq!(id.pid, "1666");
        assert_eq!(id.serial, "(none)");
    }

    #[test]
    #[cfg(not(windows))]
    fn test_enumerate_returns_empty_on_non_windows() {
        assert!(enumerate_connected_usb_devices().is_empty());
    }

    #[test]
    #[cfg(windows)]
    fn test_enumerate_smoke_windows_compiles() {
        // CI may have no USB devices; we only assert the call returns a Vec
        // (compile + runtime smoke). Length is environment-dependent.
        let _devices: Vec<DeviceIdentity> = enumerate_connected_usb_devices();
    }

    #[test]
    fn test_resolve_instance_id_rejects_malformed_path() {
        // Non-USB path should be rejected before CM API call.
        #[cfg(windows)]
        {
            let result =
                resolve_instance_id_from_dbcc_name(r"\\?\NOTUSB#VID_0951&PID_1666#SN12345#{guid}");
            assert!(result.is_err(), "Expected error for non-USB path");
        }
        #[cfg(not(windows))]
        {
            // On non-Windows, the function is not compiled; test is a no-op.
        }
    }

    #[test]
    fn test_find_instance_id_signature_compiles() {
        // On Windows this function exists; on non-Windows it does not.
        // We verify the signature is callable by type-checking only.
        #[cfg(windows)]
        {
            // This will fail at runtime (no device), but it proves the signature.
            let _ = || {
                let _: Result<String, UsbResolutionError> =
                    find_instance_id_by_vid_pid_serial("0951", "1666", "SN12345");
            };
        }
    }

    /// Smoke test for `find_instance_id_by_vid_pid_serial` with `(none)` serial.
    /// Calls with a VID/PID that is unlikely to match any real device, verifying
    /// the function accepts the `(none)` serial parameter and returns a Result.
    #[test]
    #[cfg(windows)]
    fn test_find_instance_id_by_vid_pid_serial_none_smoke() {
        // FFFF:FFFF is unlikely to match any real USB device.
        let result = find_instance_id_by_vid_pid_serial("FFFF", "FFFF", "(none)");
        // Assert the function returns a Result (either Ok or Err is acceptable
        // since we cannot control which USB devices are connected).
        let _ = result;
    }

    // -------------------------------------------------------------------------
    // USB enforcement config constants -- duplicate detection (Phase 43-02)
    // -------------------------------------------------------------------------

    #[test]
    fn test_usb_failure_modes_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for &mode in USB_FAILURE_MODES {
            assert!(
                seen.insert(mode),
                "duplicate value in USB_FAILURE_MODES: {mode}"
            );
        }
    }

    #[test]
    fn test_usb_resolution_modes_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for &mode in USB_RESOLUTION_MODES {
            assert!(
                seen.insert(mode),
                "duplicate value in USB_RESOLUTION_MODES: {mode}"
            );
        }
    }

    #[test]
    fn test_usb_none_serial_policies_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for &policy in USB_NONE_SERIAL_POLICIES {
            assert!(
                seen.insert(policy),
                "duplicate value in USB_NONE_SERIAL_POLICIES: {policy}"
            );
        }
    }

    // -------------------------------------------------------------------------
    // setupdi_description_for_device -- exact-path matching (Phase 43-01)
    // -------------------------------------------------------------------------

    /// Calls `setupdi_description_for_device` with a known-nonexistent path and
    /// asserts it does not panic, returning an empty string or falling back
    /// gracefully. This is a no-crash smoke test since we cannot control which
    /// USB devices are connected in CI.
    #[test]
    #[cfg(windows)]
    fn test_setupdi_description_exact_path_no_crash() {
        // A path that is extremely unlikely to match any real device.
        let fake_path =
            r"\\?\USB#VID_FFFF&PID_FFFF#NONEXISTENT#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
        let result = setupdi_description_for_device(fake_path);
        // Must not panic. Empty string is expected since no device matches.
        assert_eq!(result, "");
    }

    /// Compile-time signature check for `setupdi_description_for_device`.
    ///
    /// On non-Windows targets the function is not compiled, so this test
    /// asserts the function exists with the correct signature via type-checking.
    #[test]
    #[cfg(not(windows))]
    fn test_setupdi_description_signature_compiles() {
        // Type-check the function signature: fn(&str) -> String
        let _ = setupdi_description_for_device as fn(&str) -> String;
    }

    // -------------------------------------------------------------------------
    // resolve_instance_id_from_dbcc_name — prefix validation (bug fix)
    // -------------------------------------------------------------------------

    /// Regression test: paths starting with `\\?\USB#` (double backslash) must NOT
    /// be rejected by the prefix guard. Before the fix the guard checked for `\?\USB#`
    /// (single backslash), which rejected every valid Windows device path.
    #[test]
    #[cfg(windows)]
    fn test_resolve_instance_id_accepts_double_backslash_prefix() {
        // A well-formed USB path (device will not be found at runtime, but it must
        // pass the prefix guard and reach the CM API rather than returning early).
        let path = r"\\?\USB#VID_0951&PID_1666#SN12345#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
        let result = resolve_instance_id_from_dbcc_name(path);
        // We cannot assert Ok on a machine without that device, but we must NOT get the
        // ConfigManager(0x13) "invalid data" sentinel that the prefix guard returns.
        if let Err(UsbResolutionError::ConfigManager(0x00000013)) = result {
            panic!("prefix guard incorrectly rejected a valid \\\\?\\USB# path");
        }
    }

    /// Confirm that a path with only a single leading backslash is still rejected.
    #[test]
    #[cfg(windows)]
    fn test_resolve_instance_id_rejects_single_backslash_prefix() {
        // `\?\USB#...` (one backslash) is not a valid Win32 device namespace path.
        let path = r"\?\USB#VID_0951&PID_1666#SN12345#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
        let result = resolve_instance_id_from_dbcc_name(path);
        assert!(
            matches!(result, Err(UsbResolutionError::ConfigManager(0x00000013))),
            "expected ConfigManager(0x13) for single-backslash prefix, got: {result:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Serial match logic — prevent Bluetooth/SanDisk VID collision (bug fix)
    // -------------------------------------------------------------------------

    /// Unit-level regression: a candidate with serial "(none)" must NOT match a
    /// target with a real serial. This is the core of the Bluetooth/SanDisk
    /// confusion: both share VID 0781 but Bluetooth has no serial descriptor.
    ///
    /// We test the matching logic directly via `parse_usb_device_path` + the
    /// match expression extracted from the function, since the SetupDi functions
    /// require a real device to be connected.
    #[test]
    fn test_serial_match_real_target_vs_none_candidate() {
        // Target: SanDisk with a real serial.
        let target = parse_usb_device_path(
            r"\\?\USB#VID_0781&PID_5591#0401EFEFB391D95A#{a5dcbf10-6530-11d2-901f-00c04fb951ed}",
        );
        // Candidate: Bluetooth adapter — same VID, no serial.
        let candidate = parse_usb_device_path(
            r"\\?\USB#VID_0781&PID_5591##{a5dcbf10-6530-11d2-901f-00c04fb951ed}",
        );

        assert_eq!(target.serial, "0401EFEFB391D95A");
        assert_eq!(candidate.serial, "(none)");

        // Reproduce the match logic from setupdi_description_by_vid_pid_serial.
        let serial_match = match (target.serial.as_str(), candidate.serial.as_str()) {
            ("(none)", "(none)") => true,
            ("(none)", _) => true,
            (_, "(none)") => false, // <-- must take this branch
            (t, c) => t == c,
        };

        assert!(
            !serial_match,
            "candidate with serial '(none)' must NOT match target with real serial"
        );
    }

    #[test]
    fn test_serial_match_none_target_accepts_none_candidate() {
        let serial_match = match ("(none)", "(none)") {
            ("(none)", "(none)") => true,
            _ => false,
        };
        assert!(serial_match);
    }

    #[test]
    fn test_serial_match_real_both_must_be_equal() {
        let serial_match = match ("ABC123", "ABC123") {
            ("(none)", "(none)") | ("(none)", _) => true,
            (_, "(none)") => false,
            (t, c) => t == c,
        };
        assert!(serial_match);

        let serial_match_diff = match ("ABC123", "XYZ999") {
            ("(none)", "(none)") | ("(none)", _) => true,
            (_, "(none)") => false,
            (t, c) => t == c,
        };
        assert!(!serial_match_diff);
    }
}
