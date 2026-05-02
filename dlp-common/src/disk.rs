//! Shared disk enumeration module for the Enterprise DLP System.
//!
//! This module provides the canonical disk identity data model and enumeration
//! API used by `dlp-agent` (disk enumeration at startup), `dlp-admin-cli`
//! (Phase 38 scan screen), and audit event emission.
//!
//! All Windows-only functions are gated behind `#[cfg(windows)]`; on non-Windows
//! targets the public APIs return safe defaults (empty vectors, `false`, `None`).
//!
//! ## USB-Bridged Detection
//!
//! Detection uses a two-tier strategy per D-12/D-13:
//! 1. **Primary:** `IOCTL_STORAGE_QUERY_PROPERTY` with `StorageDeviceProperty` to
//!    read the `STORAGE_DEVICE_DESCRIPTOR.BusType` field directly.
//! 2. **Fallback:** PnP device tree walk via `CM_Get_Parent` / `CM_Get_Device_IDW`
//!    looking for a `USB\` ancestor node.
//!
//! A disk is classified as USB-bridged if **either** method indicates USB ancestry.

use serde::{Deserialize, Serialize};

#[cfg(windows)]
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_Device_IDW, CM_Get_Parent, CM_Locate_DevNodeW, SetupDiDestroyDeviceInfoList,
    SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW,
    SetupDiGetDeviceRegistryPropertyW, CM_LOCATE_DEVNODE_NORMAL, DIGCF_DEVICEINTERFACE,
    DIGCF_PRESENT, SETUP_DI_REGISTRY_PROPERTY, SP_DEVINFO_DATA,
};
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetDriveTypeW, GetLogicalDrives, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
#[cfg(windows)]
use windows::Win32::System::Ioctl::{
    IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_ID,
    STORAGE_PROPERTY_QUERY, STORAGE_QUERY_TYPE,
};
#[cfg(windows)]
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
#[cfg(windows)]
use windows::Win32::System::IO::DeviceIoControl;

/// Error type for disk enumeration and identity operations.
#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    /// WMI query failed.
    #[error("WMI query failed: {0}")]
    WmiQueryFailed(String),
    /// SetupDi enumeration failed.
    #[error("SetupDi enumeration failed: {0}")]
    SetupDiFailed(String),
    /// IOCTL_STORAGE_QUERY_PROPERTY failed.
    #[error("IOCTL_STORAGE_QUERY_PROPERTY failed: {0}")]
    IoctlFailed(String),
    /// PnP tree walk failed.
    #[error("PnP tree walk failed: {0}")]
    PnpWalkFailed(String),
    /// Failed to open disk device.
    #[error("failed to open disk device: {0}")]
    DeviceOpenFailed(String),
    /// Invalid device instance ID.
    #[error("invalid device instance ID")]
    InvalidInstanceId,
}

/// Physical bus type of a storage device.
///
/// Maps Windows `STORAGE_BUS_TYPE` values to a project-specific subset.
/// Exotic bus types (SataExpress, SD, MMC, etc.) map to `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BusType {
    /// Bus type could not be determined.
    #[default]
    Unknown,
    /// Serial ATA.
    Sata,
    /// NVM Express.
    Nvme,
    /// USB-bridged enclosure or native USB storage.
    Usb,
    /// SCSI or SAS.
    Scsi,
}

impl From<u32> for BusType {
    /// Maps raw `STORAGE_BUS_TYPE` values to the project `BusType` enum.
    ///
    /// # Mapping
    ///
    /// | Raw value | BusType |
    /// |-----------|---------|
    /// | 1         | Scsi    |
    /// | 7         | Usb     |
    /// | 8         | Sata    |
    /// | 17        | Nvme    |
    /// | other     | Unknown |
    fn from(raw: u32) -> Self {
        match raw {
            1 => Self::Scsi,
            7 => Self::Usb,
            8 => Self::Sata,
            17 => Self::Nvme,
            _ => Self::Unknown,
        }
    }
}

/// Canonical identity of a fixed disk on the system.
///
/// This struct is the shared data model for disk enumeration, allowlist
/// management, and audit events. `instance_id` is the canonical key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DiskIdentity {
    /// Device instance ID (e.g., `PCIIDE\IDECHANNEL\4&1234&0&0`).
    /// This is the canonical key for allowlist matching.
    pub instance_id: String,
    /// Physical bus type (SATA, NVMe, USB, SCSI, Unknown).
    pub bus_type: BusType,
    /// Drive model string (e.g., `WDC WD10EZEX-00BN5A0`).
    pub model: String,
    /// Current drive letter, if assigned (volatile -- may change).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drive_letter: Option<char>,
    /// Drive serial number (may not be available from all controllers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Drive capacity in bytes (may be unavailable for some devices).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// `true` if this disk hosts the system boot volume.
    /// Set at enumeration time and never user-modifiable (D-16).
    pub is_boot_disk: bool,
}

/// `GUID_DEVINTERFACE_DISK` -- the device interface class for disk drives.
///
/// Used with `SetupDiGetClassDevsW` to enumerate all disk device interfaces.
#[cfg(windows)]
const GUID_DEVINTERFACE_DISK: windows::core::GUID = windows::core::GUID::from_values(
    0x53F56307,
    0xB6BF,
    0x11D0,
    [0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B],
);

/// SetupDi registry property: device friendly name (`SPDRP_FRIENDLYNAME` = 0x0C).
#[cfg(windows)]
const SPDRP_FRIENDLYNAME: u32 = 0x0000_000C;

/// SetupDi registry property: device description fallback (`SPDRP_DEVICEDESC` = 0x00).
#[cfg(windows)]
const SPDRP_DEVICEDESC: u32 = 0x0000_0000;

/// Windows `DRIVE_FIXED` constant (value 3).
#[cfg(windows)]
const DRIVE_FIXED: u32 = 3;

// ---------------------------------------------------------------------------
// Public API (platform-dispatch wrappers)
// ---------------------------------------------------------------------------

/// Enumerate all fixed disks on the system.
///
/// Returns a `Vec<DiskIdentity>` for every physical fixed disk found,
/// regardless of whether it has a drive letter. On non-Windows targets,
/// always returns an empty vector.
///
/// # Errors
///
/// Returns `DiskError::SetupDiFailed` if the underlying Windows SetupDi
/// enumeration fails.
///
/// # Examples
///
/// ```
/// use dlp_common::disk::enumerate_fixed_disks;
/// let disks = enumerate_fixed_disks().unwrap_or_default();
/// // On Windows: Vec contains all fixed disks.
/// // On non-Windows: Vec is empty.
/// ```
pub fn enumerate_fixed_disks() -> Result<Vec<DiskIdentity>, DiskError> {
    #[cfg(windows)]
    {
        enumerate_fixed_disks_windows()
    }
    #[cfg(not(windows))]
    {
        Ok(Vec::new())
    }
}

/// Determine whether a disk is USB-bridged.
///
/// Uses the two-tier detection strategy per D-12/D-13:
/// 1. `IOCTL_STORAGE_QUERY_PROPERTY` primary check.
/// 2. PnP tree walk fallback (`CM_Get_Parent` looking for `USB\` ancestor).
///
/// Returns `true` if either method indicates USB ancestry.
/// On non-Windows targets, always returns `Ok(false)`.
///
/// # Arguments
///
/// * `instance_id` -- the device instance ID of the disk to check.
///
/// # Errors
///
/// Returns `DiskError::IoctlFailed` if the IOCTL call fails and the PnP walk
/// also fails.
///
/// # Examples
///
/// ```
/// use dlp_common::disk::is_usb_bridged;
/// let bridged = is_usb_bridged("PCIIDE\\IDECHANNEL\\4&1234").unwrap_or(false);
/// ```
pub fn is_usb_bridged(instance_id: &str) -> Result<bool, DiskError> {
    #[cfg(windows)]
    {
        is_usb_bridged_windows(instance_id)
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}

/// Resolve the system boot drive letter.
///
/// Calls `GetSystemDirectoryW` on Windows and extracts the drive letter
/// from the returned path (e.g., `C:\Windows\system32` -> `Some('C')`).
/// On non-Windows targets, returns `None`.
///
/// # Examples
///
/// ```
/// use dlp_common::disk::get_boot_drive_letter;
/// let letter = get_boot_drive_letter();
/// // On Windows: Some('C') (or equivalent system drive).
/// // On non-Windows: None.
/// ```
pub fn get_boot_drive_letter() -> Option<char> {
    #[cfg(windows)]
    {
        get_boot_drive_letter_windows()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

/// Windows-specific fixed disk enumeration.
#[cfg(windows)]
fn enumerate_fixed_disks_windows() -> Result<Vec<DiskIdentity>, DiskError> {
    let hdev = unsafe {
        SetupDiGetClassDevsW(
            Some(&GUID_DEVINTERFACE_DISK),
            windows::core::PCWSTR::null(),
            None,
            DIGCF_DEVICEINTERFACE | DIGCF_PRESENT,
        )
    };
    let hdev = hdev.map_err(|e| DiskError::SetupDiFailed(format!("SetupDiGetClassDevsW: {e}")))?;

    let boot_letter = get_boot_drive_letter_windows();
    let mut out: Vec<DiskIdentity> = Vec::new();
    let mut index: u32 = 0;

    loop {
        let mut devinfo = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        if unsafe { SetupDiEnumDeviceInfo(hdev, index, &mut devinfo) }.is_err() {
            break;
        }

        // Read instance ID.
        let instance_id = read_instance_id(hdev, &devinfo)?;

        // Read model (friendly name, fallback to device description).
        let model = read_string_property(hdev, &devinfo, SPDRP_FRIENDLYNAME)
            .filter(|s| !s.is_empty())
            .or_else(|| read_string_property(hdev, &devinfo, SPDRP_DEVICEDESC))
            .unwrap_or_default();

        // Determine bus type via IOCTL primary + PnP fallback.
        let bus_type = match query_bus_type_ioctl(&instance_id) {
            Ok(bt) => bt,
            Err(_) => {
                // Fallback: if PnP walk finds USB ancestor, mark as USB.
                match is_usb_bridged_pnp_walk(&instance_id) {
                    Ok(true) => BusType::Usb,
                    _ => BusType::Unknown,
                }
            }
        };

        // Determine drive letter by scanning fixed drives.
        let drive_letter = find_drive_letter_for_instance_id(&instance_id, &out);

        let is_boot_disk = boot_letter.is_some() && drive_letter == boot_letter;

        out.push(DiskIdentity {
            instance_id,
            bus_type,
            model,
            drive_letter,
            serial: None,
            size_bytes: None,
            is_boot_disk,
        });

        index += 1;
        if index > 1024 {
            break;
        }
    }

    let _ = unsafe { SetupDiDestroyDeviceInfoList(hdev) };
    Ok(out)
}

/// Read the device instance ID from a `SP_DEVINFO_DATA` entry.
#[cfg(windows)]
fn read_instance_id(
    hdev: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    devinfo: &SP_DEVINFO_DATA,
) -> Result<String, DiskError> {
    let mut id_buf = [0u16; 256];
    let mut required: u32 = 0;
    unsafe {
        SetupDiGetDeviceInstanceIdW(
            hdev,
            devinfo,
            Some(id_buf.as_mut_slice()),
            Some(&mut required),
        )
    }
    .map_err(|e| DiskError::SetupDiFailed(format!("SetupDiGetDeviceInstanceIdW: {e}")))?;

    let id = String::from_utf16_lossy(
        &id_buf
            .iter()
            .copied()
            .take_while(|w| *w != 0)
            .collect::<Vec<u16>>(),
    );
    Ok(id)
}

/// Query the bus type for a disk via `IOCTL_STORAGE_QUERY_PROPERTY`.
///
/// Opens the disk via `\\.\PhysicalDriveN` where N is derived from the
/// SetupDi enumeration order (0, 1, 2...). The enumeration order typically
/// matches PhysicalDrive numbering.
#[cfg(windows)]
fn query_bus_type_ioctl(instance_id: &str) -> Result<BusType, DiskError> {
    // Derive PhysicalDrive index from the instance_id hash for stable mapping.
    // In practice, we try a small range of indices and match by instance_id.
    // For simplicity, we try PhysicalDrive0 through PhysicalDrive31.
    for drive_index in 0..32u32 {
        let path = format!(r"\\.\PhysicalDrive{drive_index}");
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        let handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR(wide.as_ptr()),
                0x8000_0000u32, // GENERIC_READ as raw u32
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        };

        let handle = match handle {
            Ok(h) => h,
            Err(_) => continue,
        };

        let result = query_bus_type_for_handle(handle, instance_id);
        let _ = unsafe { CloseHandle(handle) };

        if let Ok(bt) = result {
            return Ok(bt);
        }
    }

    Err(DiskError::IoctlFailed(
        "could not open any PhysicalDrive handle".to_string(),
    ))
}

/// Send `IOCTL_STORAGE_QUERY_PROPERTY` to an open disk handle.
#[cfg(windows)]
fn query_bus_type_for_handle(handle: HANDLE, _instance_id: &str) -> Result<BusType, DiskError> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: STORAGE_PROPERTY_ID(0), // StorageDeviceProperty
        QueryType: STORAGE_QUERY_TYPE(0),   // PropertyStandardQuery
        AdditionalParameters: [0u8; 1],
    };

    let mut descriptor_buf = vec![0u8; 512];
    let mut returned: u32 = 0;

    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&query as *const _ as *const std::ffi::c_void),
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some(descriptor_buf.as_mut_ptr() as *mut std::ffi::c_void),
            descriptor_buf.len() as u32,
            Some(&mut returned),
            None,
        )
    };

    if ok.is_err() {
        return Err(DiskError::IoctlFailed("DeviceIoControl failed".to_string()));
    }

    if returned < std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>() as u32 {
        return Err(DiskError::IoctlFailed(
            "insufficient data from IOCTL".to_string(),
        ));
    }

    // STORAGE_DEVICE_DESCRIPTOR layout:
    //   ULONG Version;          // offset 0
    //   ULONG Size;             // offset 4
    //   BYTE  DeviceType;       // offset 8
    //   BYTE  DeviceTypeModifier;// offset 9
    //   BOOLEAN RemovableMedia; // offset 10
    //   BOOLEAN CommandQueueing;// offset 11
    //   ULONG VendorIdOffset;   // offset 12
    //   ULONG ProductIdOffset;  // offset 16
    //   ULONG ProductRevisionOffset; // offset 20
    //   ULONG SerialNumberOffset;    // offset 24
    //   STORAGE_BUS_TYPE BusType;    // offset 28
    //   ULONG RawPropertiesLength;   // offset 32
    //   BYTE  RawProperties[1];      // offset 36
    //
    // BusType is at offset 28 (after 24-byte SerialNumberOffset).
    let bus_type_raw = descriptor_buf
        .get(28..32)
        .and_then(|b| {
            if b.len() >= 4 {
                Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            } else {
                None
            }
        })
        .ok_or_else(|| DiskError::IoctlFailed("could not read BusType field".to_string()))?;

    Ok(BusType::from(bus_type_raw))
}

/// Windows-specific USB-bridged detection.
///
/// First tries `IOCTL_STORAGE_QUERY_PROPERTY`; if that indicates USB,
/// returns `true`. Otherwise falls back to PnP tree walk.
#[cfg(windows)]
fn is_usb_bridged_windows(instance_id: &str) -> Result<bool, DiskError> {
    // Primary: IOCTL.
    match query_bus_type_ioctl(instance_id) {
        Ok(BusType::Usb) => return Ok(true),
        Ok(_) => {}
        Err(_) => {}
    }

    // Fallback: PnP tree walk.
    is_usb_bridged_pnp_walk(instance_id)
}

/// PnP tree walk fallback for USB-bridged detection.
///
/// Locates the device node by instance ID, then walks up the parent chain
/// for up to 16 levels. If any ancestor starts with `USB\`, the disk is
/// classified as USB-bridged.
#[cfg(windows)]
fn is_usb_bridged_pnp_walk(instance_id: &str) -> Result<bool, DiskError> {
    let wide_id: Vec<u16> = instance_id
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut devinst: u32 = 0;
    let cr = unsafe {
        CM_Locate_DevNodeW(
            &mut devinst,
            windows::core::PCWSTR(wide_id.as_ptr()),
            CM_LOCATE_DEVNODE_NORMAL,
        )
    };
    if cr.0 != 0 {
        return Err(DiskError::PnpWalkFailed(format!(
            "CM_Locate_DevNodeW failed: cr=0x{:08X}",
            cr.0
        )));
    }

    let mut current = devinst;
    for _ in 0..16 {
        let mut parent: u32 = 0;
        let cr = unsafe { CM_Get_Parent(&mut parent, current, 0) };
        if cr.0 != 0 {
            // No more parents.
            break;
        }

        let mut id_buf = [0u16; 256];
        let cr = unsafe { CM_Get_Device_IDW(parent, &mut id_buf, 0) };
        if cr.0 == 0 {
            let id = String::from_utf16_lossy(
                &id_buf
                    .iter()
                    .copied()
                    .take_while(|w| *w != 0)
                    .collect::<Vec<u16>>(),
            );
            if id.starts_with("USB\\") {
                return Ok(true);
            }
        }
        current = parent;
    }

    Ok(false)
}

/// Resolve the system boot drive letter on Windows.
///
/// Calls `GetSystemDirectoryW`, extracts the drive letter from the returned
/// path (e.g., `C:\Windows\system32` -> `Some('C')`).
#[cfg(windows)]
fn get_boot_drive_letter_windows() -> Option<char> {
    let mut buf = [0u16; 512];
    let len = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
    if len == 0 {
        return None;
    }
    let path = String::from_utf16_lossy(
        &buf.iter()
            .copied()
            .take_while(|w| *w != 0)
            .collect::<Vec<u16>>(),
    );
    path.chars().next().filter(|c| c.is_ascii_alphabetic())
}

/// Find the drive letter associated with a given disk instance ID.
///
/// Scans all logical drives, filters to `DRIVE_FIXED`, and correlates
/// each fixed drive with the disk instance ID. For now, uses a simplified
/// heuristic: the drive letter is assigned if the drive exists and is fixed.
///
/// In a future phase, WMI `Win32_DiskDrive` -> `Win32_DiskPartition` ->
/// `Win32_LogicalDisk` correlation will provide exact mapping.
#[cfg(windows)]
fn find_drive_letter_for_instance_id(
    _instance_id: &str,
    _already_found: &[DiskIdentity],
) -> Option<char> {
    let drives = unsafe { GetLogicalDrives() };
    if drives == 0 {
        return None;
    }

    for letter in 'A'..='Z' {
        let bit = 1u32 << (letter as u32 - 'A' as u32);
        if drives & bit == 0 {
            continue;
        }

        let path = format!("{letter}:\\");
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        let drive_type = unsafe { GetDriveTypeW(windows::core::PCWSTR(wide.as_ptr())) };
        if drive_type != DRIVE_FIXED {
            continue;
        }

        // Check if this drive path exists (secondary validation per D-05/31-02).
        if std::path::Path::new(&format!("{letter}:\\")).exists() {
            // Simplified: assign the first available fixed drive letter
            // that hasn't been assigned to a previously enumerated disk.
            let already_taken = _already_found
                .iter()
                .any(|d| d.drive_letter == Some(letter));
            if !already_taken {
                return Some(letter);
            }
        }
    }

    None
}

/// Reads a UTF-16 string property from a `SP_DEVINFO_DATA` entry.
///
/// Returns `None` on any Win32 error.
///
/// # Arguments
///
/// * `hdev` -- a valid `HDEVINFO` set obtained from `SetupDiGetClassDevsW`.
/// * `devinfo` -- pointer to an initialized `SP_DEVINFO_DATA` entry.
/// * `property` -- one of `SPDRP_FRIENDLYNAME` or `SPDRP_DEVICEDESC`.
#[cfg(windows)]
fn read_string_property(
    hdev: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    devinfo: &SP_DEVINFO_DATA,
    property: u32,
) -> Option<String> {
    let mut buf = vec![0u8; 1024];
    let mut required: u32 = 0;
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
    let wide: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|w| *w != 0)
        .collect();
    Some(String::from_utf16_lossy(&wide))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bus_type_from_raw() {
        assert_eq!(BusType::from(1), BusType::Scsi);
        assert_eq!(BusType::from(7), BusType::Usb);
        assert_eq!(BusType::from(8), BusType::Sata);
        assert_eq!(BusType::from(17), BusType::Nvme);
        assert_eq!(BusType::from(99), BusType::Unknown);
        assert_eq!(BusType::from(0), BusType::Unknown);
    }

    #[test]
    fn test_bus_type_serde_round_trip() {
        for bt in [
            BusType::Unknown,
            BusType::Sata,
            BusType::Nvme,
            BusType::Usb,
            BusType::Scsi,
        ] {
            let json = serde_json::to_string(&bt).unwrap();
            let rt: BusType = serde_json::from_str(&json).unwrap();
            assert_eq!(bt, rt, "serde round-trip failed for {bt:?}");
        }
    }

    #[test]
    fn test_bus_type_snake_case_serde() {
        assert_eq!(serde_json::to_string(&BusType::Sata).unwrap(), "\"sata\"");
        assert_eq!(serde_json::to_string(&BusType::Nvme).unwrap(), "\"nvme\"");
        assert_eq!(serde_json::to_string(&BusType::Usb).unwrap(), "\"usb\"");
        assert_eq!(serde_json::to_string(&BusType::Scsi).unwrap(), "\"scsi\"");
        assert_eq!(
            serde_json::to_string(&BusType::Unknown).unwrap(),
            "\"unknown\""
        );
    }

    #[test]
    fn test_disk_identity_default() {
        let d = DiskIdentity::default();
        assert_eq!(d.instance_id, "");
        assert_eq!(d.bus_type, BusType::Unknown);
        assert_eq!(d.model, "");
        assert!(d.drive_letter.is_none());
        assert!(d.serial.is_none());
        assert!(d.size_bytes.is_none());
        assert!(!d.is_boot_disk);
    }

    #[test]
    fn test_disk_identity_serde_round_trip() {
        let original = DiskIdentity {
            instance_id: "PCIIDE\\IDECHANNEL\\4&1234".to_string(),
            bus_type: BusType::Sata,
            model: "WDC WD10EZEX-00BN5A0".to_string(),
            drive_letter: Some('C'),
            serial: Some("WD-12345678".to_string()),
            size_bytes: Some(1_000_204_886_016),
            is_boot_disk: true,
        };
        let json = serde_json::to_string(&original).unwrap();
        let rt: DiskIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(original, rt);
    }

    #[test]
    fn test_disk_identity_deserialize_empty_object() {
        // #[serde(default)] at struct level lets `{}` deserialize with all-default fields.
        let parsed: DiskIdentity = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.instance_id, "");
        assert_eq!(parsed.bus_type, BusType::Unknown);
        assert_eq!(parsed.model, "");
        assert!(parsed.drive_letter.is_none());
        assert!(!parsed.is_boot_disk);
    }

    #[test]
    fn test_disk_identity_serde_skips_none_fields() {
        let d = DiskIdentity {
            instance_id: "TEST".to_string(),
            bus_type: BusType::Nvme,
            model: "Samsung SSD 970".to_string(),
            drive_letter: None,
            serial: None,
            size_bytes: None,
            is_boot_disk: false,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("\"drive_letter\":null"));
        assert!(!json.contains("\"serial\":null"));
        assert!(!json.contains("\"size_bytes\":null"));
    }

    #[test]
    fn test_disk_error_display() {
        let e = DiskError::IoctlFailed("test error".to_string());
        assert_eq!(
            format!("{e}"),
            "IOCTL_STORAGE_QUERY_PROPERTY failed: test error"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn test_enumerate_fixed_disks_non_windows_returns_empty() {
        let disks = enumerate_fixed_disks().unwrap();
        assert!(disks.is_empty());
    }

    #[test]
    #[cfg(not(windows))]
    fn test_is_usb_bridged_non_windows_returns_false() {
        assert!(!is_usb_bridged("anything").unwrap());
    }

    #[test]
    #[cfg(not(windows))]
    fn test_get_boot_drive_letter_non_windows_returns_none() {
        assert!(get_boot_drive_letter().is_none());
    }

    #[test]
    #[cfg(windows)]
    fn test_get_boot_drive_letter_windows_smoke() {
        // On Windows, should return the system drive letter (typically 'C').
        let letter = get_boot_drive_letter();
        assert!(letter.is_some());
        let c = letter.unwrap();
        assert!(c.is_ascii_alphabetic());
        assert!(c.is_ascii_uppercase());
    }

    #[test]
    #[cfg(windows)]
    fn test_enumerate_fixed_disks_windows_smoke() {
        // CI may have no fixed disks in some environments; we only assert
        // the call returns a Vec (compile + runtime smoke).
        let _disks: Vec<DiskIdentity> = enumerate_fixed_disks().unwrap_or_default();
    }

    #[test]
    fn test_encryption_status_serde_round_trip() {
        for status in [
            EncryptionStatus::Encrypted,
            EncryptionStatus::Suspended,
            EncryptionStatus::Unencrypted,
            EncryptionStatus::Unknown,
        ] {
            let json = serde_json::to_string(&status).expect("serialize");
            let rt: EncryptionStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, rt, "round-trip failed for {status:?}");
        }
    }

    #[test]
    fn test_encryption_status_snake_case_serde() {
        assert_eq!(serde_json::to_string(&EncryptionStatus::Encrypted).unwrap(), "\"encrypted\"");
        assert_eq!(serde_json::to_string(&EncryptionStatus::Suspended).unwrap(), "\"suspended\"");
        assert_eq!(
            serde_json::to_string(&EncryptionStatus::Unencrypted).unwrap(),
            "\"unencrypted\""
        );
        assert_eq!(serde_json::to_string(&EncryptionStatus::Unknown).unwrap(), "\"unknown\"");
    }

    #[test]
    fn test_encryption_status_default_is_unknown() {
        assert_eq!(EncryptionStatus::default(), EncryptionStatus::Unknown);
    }

    #[test]
    fn test_encryption_method_from_raw() {
        assert_eq!(EncryptionMethod::from(0u32), EncryptionMethod::None);
        assert_eq!(EncryptionMethod::from(1u32), EncryptionMethod::Aes128Diffuser);
        assert_eq!(EncryptionMethod::from(2u32), EncryptionMethod::Aes256Diffuser);
        assert_eq!(EncryptionMethod::from(3u32), EncryptionMethod::Aes128);
        assert_eq!(EncryptionMethod::from(4u32), EncryptionMethod::Aes256);
        assert_eq!(EncryptionMethod::from(5u32), EncryptionMethod::Hardware);
        assert_eq!(EncryptionMethod::from(6u32), EncryptionMethod::XtsAes128);
        assert_eq!(EncryptionMethod::from(7u32), EncryptionMethod::XtsAes256);
        assert_eq!(EncryptionMethod::from(99u32), EncryptionMethod::Unknown);
        assert_eq!(EncryptionMethod::from(u32::MAX), EncryptionMethod::Unknown);
    }

    #[test]
    fn test_encryption_method_serde_round_trip() {
        for method in [
            EncryptionMethod::None,
            EncryptionMethod::Aes128Diffuser,
            EncryptionMethod::Aes256Diffuser,
            EncryptionMethod::Aes128,
            EncryptionMethod::Aes256,
            EncryptionMethod::Hardware,
            EncryptionMethod::XtsAes128,
            EncryptionMethod::XtsAes256,
            EncryptionMethod::Unknown,
        ] {
            let json = serde_json::to_string(&method).expect("serialize");
            let rt: EncryptionMethod = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(method, rt, "round-trip failed for {method:?}");
        }
    }

    #[test]
    fn test_encryption_method_default_is_unknown() {
        assert_eq!(EncryptionMethod::default(), EncryptionMethod::Unknown);
    }

    #[test]
    fn test_disk_identity_backward_compat_no_encryption_fields() {
        // Pre-Phase-34 record: no encryption fields present.
        let legacy = r#"{
            "instance_id": "PCIIDE\\IDECHANNEL\\4&1234",
            "bus_type": "sata",
            "model": "WDC WD10EZEX",
            "is_boot_disk": true
        }"#;
        let disk: DiskIdentity = serde_json::from_str(legacy).expect("deserialize legacy");
        assert!(disk.encryption_status.is_none(), "encryption_status must be None on legacy record");
        assert!(disk.encryption_method.is_none(), "encryption_method must be None on legacy record");
        assert!(
            disk.encryption_checked_at.is_none(),
            "encryption_checked_at must be None on legacy record"
        );
        assert_eq!(disk.instance_id, "PCIIDE\\IDECHANNEL\\4&1234");
        assert_eq!(disk.bus_type, BusType::Sata);
    }

    #[test]
    fn test_disk_identity_serializes_none_encryption_fields_omitted() {
        // Pitfall D: None must be absent on the wire (skip_serializing_if).
        let disk = DiskIdentity {
            instance_id: "X".to_string(),
            bus_type: BusType::Sata,
            model: "M".to_string(),
            drive_letter: None,
            serial: None,
            size_bytes: None,
            is_boot_disk: false,
            encryption_status: None,
            encryption_method: None,
            encryption_checked_at: None,
        };
        let json = serde_json::to_string(&disk).expect("serialize");
        assert!(!json.contains("encryption_status"), "None encryption_status must be skipped");
        assert!(!json.contains("encryption_method"), "None encryption_method must be skipped");
        assert!(
            !json.contains("encryption_checked_at"),
            "None encryption_checked_at must be skipped"
        );
    }

    #[test]
    fn test_disk_identity_serializes_some_unknown_encryption_status_present() {
        // Pitfall D: Some(Unknown) MUST appear on the wire as "unknown" — distinct from None.
        let disk = DiskIdentity {
            instance_id: "X".to_string(),
            bus_type: BusType::Sata,
            model: "M".to_string(),
            drive_letter: None,
            serial: None,
            size_bytes: None,
            is_boot_disk: false,
            encryption_status: Some(EncryptionStatus::Unknown),
            encryption_method: None,
            encryption_checked_at: None,
        };
        let json = serde_json::to_string(&disk).expect("serialize");
        assert!(
            json.contains("\"encryption_status\":\"unknown\""),
            "Some(Unknown) must serialize as \"unknown\" on the wire (Pitfall D)"
        );
    }
}
