//! WFP manager — registers a sublayer and per-process egress block filters.
//!
//! This is a defense-in-depth layer: if the API hook DLL is bypassed via a
//! direct syscall, the WFP filter still blocks outbound HTTPS (TCP/443) from
//! the sync client process.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr::null_mut;

use parking_lot::Mutex;
use tracing::{info, warn};
use uuid::Uuid;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::wfp_ffi::*;

/// Manages a WFP engine session, sublayer, and per-PID block filters.
pub struct WfpManager {
    engine: Mutex<Option<HANDLE>>,
    sublayer_key: GUID,
    filters: Mutex<HashMap<u32, u64>>,
}

impl WfpManager {
    /// Open the WFP engine (requires elevation).
    pub fn new() -> Result<Self, WfpError> {
        let mut handle = HANDLE(null_mut());
        let session = unsafe { std::mem::zeroed::<FWPM_SESSION0>() };
        let result =
            unsafe { FwpmEngineOpen0(PCWSTR::null(), 0, None, Some(&session), &mut handle) };
        if result != 0 {
            return Err(WfpError::EngineUnavailable(result));
        }
        info!("WFP engine opened");
        Ok(Self {
            engine: Mutex::new(Some(handle)),
            sublayer_key: GUID::from_u128(Uuid::new_v4().as_u128()),
            filters: Mutex::new(HashMap::new()),
        })
    }

    /// Register our sublayer inside the WFP engine.
    pub fn register(&self) -> Result<(), WfpError> {
        let engine = *self.engine.lock();
        let engine_handle = engine.ok_or(WfpError::EngineNotOpen)?;

        let name_wide = wide_string("DlpWfpSubLayer");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: self.sublayer_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_wide.as_ptr() as *mut _),
                description: PWSTR::null(),
            },
            flags: 0,
            providerKey: null_mut(),
            providerData: unsafe { std::mem::zeroed() },
            weight: 0x100,
        };

        let result = unsafe { FwpmSubLayerAdd0(engine_handle, &sublayer, None) };
        if result != 0 {
            return Err(WfpError::SubLayerAddFailed(result));
        }
        info!(sublayer_key = ?self.sublayer_key, "WFP sublayer registered");
        Ok(())
    }

    /// Remove the sublayer and close the engine.
    pub fn unregister(&self) -> Result<(), WfpError> {
        let mut engine = self.engine.lock();
        let engine_handle = engine.ok_or(WfpError::EngineNotOpen)?;

        // Remove all filters first.
        let filters = std::mem::take(&mut *self.filters.lock());
        for (pid, filter_id) in filters {
            let result = unsafe { FwpmFilterDeleteById0(engine_handle, filter_id) };
            if result != 0 {
                warn!(
                    pid,
                    filter_id, result, "failed to delete filter during unregister"
                );
            }
        }

        let result = unsafe { FwpmSubLayerDeleteByKey0(engine_handle, &self.sublayer_key) };
        if result != 0 {
            warn!(result, "failed to delete sublayer during unregister");
        }

        if let Some(handle) = engine.take() {
            unsafe { FwpmEngineClose0(handle) };
            info!("WFP engine closed");
        }
        Ok(())
    }

    /// Add a WFP filter that blocks outbound TCP/443 for `pid`.
    pub fn add_process_block(&self, pid: u32) -> Result<(), WfpError> {
        if pid == 0 {
            return Err(WfpError::PidResolveFailed {
                pid,
                detail: "PID 0 is invalid".into(),
            });
        }

        let mut filters = self.filters.lock();
        if filters.contains_key(&pid) {
            return Err(WfpError::PidResolveFailed {
                pid,
                detail: "PID already blocked".into(),
            });
        }

        let engine = *self.engine.lock();
        let engine = engine.ok_or(WfpError::EngineNotOpen)?;
        let image_path = Self::pid_to_image_path(pid)?;
        let app_id = Self::path_to_app_id(&image_path)?;

        let filter_key = GUID::from_u128(Uuid::new_v4().as_u128());
        let name_wide = wide_string(&format!("DlpBlockPid{pid}"));

        let display_data = FWPM_DISPLAY_DATA0 {
            name: PWSTR(name_wide.as_ptr() as *mut _),
            description: PWSTR::null(),
        };

        // Condition 1: ALE_APP_ID == app_id
        let cond_app_id = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: &*app_id as *const _ as *mut _,
                },
            },
        };

        // Condition 2: IP_PROTOCOL == TCP
        let cond_proto = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint8: IPPROTO_TCP.0 as u8,
                },
            },
        };

        // Condition 3: IP_REMOTE_PORT == 443
        let cond_port = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: 443 },
            },
        };

        let conditions = [cond_app_id, cond_proto, cond_port];

        let action = FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            Anonymous: FWPM_ACTION0_0::default(),
        };

        let filter = FWPM_FILTER0 {
            filterKey: filter_key,
            displayData: display_data,
            flags: FWPM_FILTER_FLAGS(0), // transient
            providerKey: null_mut(),
            providerData: unsafe { std::mem::zeroed() },
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: self.sublayer_key,
            weight: FWP_VALUE0::default(),
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_ptr() as *mut _,
            action,
            ..Default::default()
        };

        let mut filter_id: u64 = 0;
        let result = unsafe { FwpmFilterAdd0(engine, &filter, None, Some(&mut filter_id)) };
        if result != 0 {
            return Err(WfpError::FilterAddFailed(result));
        }

        info!(pid, filter_id, "WFP block filter added");
        filters.insert(pid, filter_id);
        Ok(())
    }

    /// Remove the WFP filter for `pid`.
    pub fn remove_process_block(&self, pid: u32) -> Result<(), WfpError> {
        let mut filters = self.filters.lock();
        let filter_id = filters
            .remove(&pid)
            .ok_or_else(|| WfpError::PidResolveFailed {
                pid,
                detail: "PID not blocked".into(),
            })?;

        let engine = *self.engine.lock();
        let engine = engine.ok_or(WfpError::EngineNotOpen)?;
        let result = unsafe { FwpmFilterDeleteById0(engine, filter_id) };
        if result != 0 {
            return Err(WfpError::FilterDeleteFailed(result));
        }

        info!(pid, filter_id, "WFP block filter removed");
        Ok(())
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    fn pid_to_image_path(pid: u32) -> Result<String, WfpError> {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| {
                WfpError::PidResolveFailed {
                    pid,
                    detail: format!("OpenProcess: {e}"),
                }
            })?;
            let mut buf = [0u16; 1024];
            let mut size = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(
                h,
                PROCESS_NAME_FORMAT(0),
                PWSTR(buf.as_mut_ptr()),
                &mut size,
            );
            let _ = CloseHandle(h);
            ok.map_err(|e| WfpError::PidResolveFailed {
                pid,
                detail: format!("QueryFullProcessImageNameW: {e}"),
            })?;
            Ok(OsString::from_wide(&buf[..size as usize])
                .to_string_lossy()
                .into_owned())
        }
    }

    fn path_to_app_id(path: &str) -> Result<AppIdBlob, WfpError> {
        let wide: Vec<u16> = std::ffi::OsString::from(path)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut blob: *mut FWP_BYTE_BLOB = null_mut();
        let result =
            unsafe { FwpmGetAppIdFromFileName0(PCWSTR::from_raw(wide.as_ptr()), &mut blob) };
        if result != 0 {
            return Err(WfpError::PidResolveFailed {
                pid: 0,
                detail: format!("FwpmGetAppIdFromFileName0: {result}"),
            });
        }
        Ok(AppIdBlob(blob))
    }
}

fn wide_string(s: &str) -> Vec<u16> {
    std::ffi::OsString::from(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

/// RAII wrapper for an app-id blob allocated by `FwpmGetAppIdFromFileName0`.
struct AppIdBlob(*mut FWP_BYTE_BLOB);

impl std::ops::Deref for AppIdBlob {
    type Target = FWP_BYTE_BLOB;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.0 }
    }
}

impl Drop for AppIdBlob {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FwpmFreeMemory0(&mut self.0 as *mut _ as *mut *mut std::ffi::c_void) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn try_manager() -> Option<WfpManager> {
        match WfpManager::new() {
            Ok(m) => Some(m),
            Err(WfpError::EngineUnavailable(code)) => {
                eprintln!("Skipping WFP test: engine unavailable (code {code})");
                None
            }
            Err(e) => panic!("unexpected WFP error: {e}"),
        }
    }

    #[test]
    fn test_register_unregister() {
        let Some(manager) = try_manager() else { return };
        manager.register().unwrap();
        manager.unregister().unwrap();
    }

    #[test]
    fn test_add_remove_block() {
        let Some(manager) = try_manager() else { return };
        manager.register().unwrap();

        let pid = std::process::id();
        manager.add_process_block(pid).unwrap();

        // Verify filter exists via FwpmFilterGetById0.
        let engine = (*manager.engine.lock()).unwrap();
        let filter_id = manager.filters.lock()[&pid];
        let mut filter_ptr = std::ptr::null_mut();
        let result = unsafe { FwpmFilterGetById0(engine, filter_id, &mut filter_ptr) };
        assert_eq!(result, 0, "filter should exist in engine");
        if !filter_ptr.is_null() {
            unsafe { FwpmFreeMemory0(&mut filter_ptr as *mut _ as *mut *mut std::ffi::c_void) };
        }

        manager.remove_process_block(pid).unwrap();
        manager.unregister().unwrap();
    }

    #[test]
    fn test_block_invalid_pid() {
        let Some(manager) = try_manager() else { return };
        manager.register().unwrap();
        let result = manager.add_process_block(0);
        assert!(result.is_err(), "PID 0 should be rejected");
        manager.unregister().unwrap();
    }

    #[test]
    fn test_remove_nonexistent_pid() {
        let Some(manager) = try_manager() else { return };
        manager.register().unwrap();
        let result = manager.remove_process_block(999_999);
        assert!(result.is_err(), "removing unblocked PID should fail");
        manager.unregister().unwrap();
    }

    #[test]
    fn test_double_block_same_pid() {
        let Some(manager) = try_manager() else { return };
        manager.register().unwrap();
        let pid = std::process::id();
        manager.add_process_block(pid).unwrap();
        let result = manager.add_process_block(pid);
        assert!(result.is_err(), "double-block should fail");
        manager.remove_process_block(pid).unwrap();
        manager.unregister().unwrap();
    }
}
