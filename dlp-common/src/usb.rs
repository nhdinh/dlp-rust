//! Shared USB device enumeration and path-parsing helpers.
//!
//! Used by `dlp-agent` (event-driven arrival/removal handlers) and
//! `dlp-admin-cli` (point-in-time scan and register flow). The Windows-only
//! SetupDi calls are gated behind `#[cfg(windows)]`; on other platforms
//! [`enumerate_connected_usb_devices`] is a no-op returning an empty vector.

use crate::endpoint::DeviceIdentity;

#[cfg(windows)]
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiGetDeviceRegistryPropertyW, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT,
    SETUP_DI_REGISTRY_PROPERTY, SP_DEVINFO_DATA,
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
/// Enumerates `GUID_DEVINTERFACE_USB_DEVICE` interfaces currently present and
/// returns the description whose VID/PID substring matches the parsed VID/PID
/// from `device_path`. Falls back to the first non-empty description seen if
/// no VID/PID match is found.
///
/// Returns an empty string on any Win32 error or if no description is available.
#[cfg(windows)]
pub fn setupdi_description_for_device(device_path: &str) -> String {
    let parsed = parse_usb_device_path(device_path);

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

    let mut first_description = String::new();
    let mut matching_description = String::new();
    let mut index: u32 = 0;

    loop {
        let mut devinfo = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: hdev is valid; devinfo is owned stack memory with cbSize set.
        // Loop terminates on the first Err (ERROR_NO_MORE_ITEMS).
        if unsafe { SetupDiEnumDeviceInfo(hdev, index, &mut devinfo) }.is_err() {
            break;
        }

        let desc = read_string_property(hdev, &devinfo, SPDRP_FRIENDLYNAME)
            .filter(|s| !s.is_empty())
            .or_else(|| read_string_property(hdev, &devinfo, SPDRP_DEVICEDESC))
            .unwrap_or_default();

        if !desc.is_empty() {
            if first_description.is_empty() {
                first_description = desc.clone();
            }
            let upper = desc.to_ascii_uppercase();
            // Prefer a description whose text mentions the device's VID or PID
            // (e.g., "VID_0951" or "PID_1666") — the 4-hex-digit substrings are
            // unique enough to pick the right device in most cases.
            if (!parsed.vid.is_empty()
                && upper.contains(&format!("VID_{}", parsed.vid.to_ascii_uppercase())))
                || (!parsed.pid.is_empty()
                    && upper.contains(&format!("PID_{}", parsed.pid.to_ascii_uppercase())))
            {
                matching_description = desc;
                break;
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

    if !matching_description.is_empty() {
        matching_description
    } else {
        first_description
    }
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
/// SetupDi-derived description for each device. Devices without a parseable
/// VID and PID (hubs, root hubs, HID-only devices) are filtered out.
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

/// Windows implementation of USB device enumeration. Mirrors the agent's
/// existing SetupDi loop pattern (see `setupdi_description_for_device`).
#[cfg(windows)]
fn enumerate_connected_usb_devices_windows() -> Vec<DeviceIdentity> {
    use windows::Win32::Devices::DeviceAndDriverInstallation::SetupDiGetDeviceInstanceIdW;

    // SAFETY: GUID_DEVINTERFACE_USB_DEVICE + null enumerator + DIGCF flags is
    // a well-defined SetupDi usage selecting present USB device interfaces.
    let hdev = match unsafe {
        SetupDiGetClassDevsW(
            Some(&GUID_DEVINTERFACE_USB_DEVICE),
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

        // Read the device instance ID (e.g., `USB\VID_0951&PID_1666\1234567890`)
        // and reshape it into the dbcc_name form `\\?\USB#VID_0951&PID_1666#1234567890#`
        // so parse_usb_device_path's `#`-split logic applies. Easiest: read
        // instance id, replace '\\' with '#', prepend "\\\\?\\".
        let mut id_buf = [0u16; 256];
        let mut required: u32 = 0;
        // SAFETY: id_buf is owned and sized; required is a valid u32 ptr.
        let ok = unsafe {
            SetupDiGetDeviceInstanceIdW(
                hdev,
                &devinfo,
                Some(id_buf.as_mut_slice()),
                Some(&mut required),
            )
        };
        if ok.is_ok() {
            let instance_id: String = id_buf
                .iter()
                .take_while(|&&w| w != 0)
                .map(|&w| w as u8 as char)
                .collect();
            // Reshape: `USB\VID_X&PID_Y\SERIAL` -> `\\?\USB#VID_X&PID_Y#SERIAL#`.
            let reshaped = format!("\\\\?\\{}", instance_id.replace('\\', "#"));
            let mut identity = parse_usb_device_path(&reshaped);
            // Filter: drop devices without a parseable VID+PID (hubs, etc.).
            if !identity.vid.is_empty() && !identity.pid.is_empty() {
                identity.description = setupdi_description_for_device(&reshaped);
                out.push(identity);
            }
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
}
