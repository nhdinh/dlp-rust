//! Minimal FFI wrapper around Windows Filtering Platform (WFP) APIs.
//!
//! The `windows` crate's `Win32_NetworkManagement_WindowsFilteringPlatform`
//! feature provides the raw bindings; this module re-exports the subset we
//! need and defines a project-specific error type.

pub use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0,
    FwpmFilterGetById0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FWPM_ACTION0, FWPM_ACTION0_0,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAGS,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_SESSION0, FWPM_SUBLAYER0,
    FWP_ACTION_BLOCK, FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_DATA_TYPE, FWP_MATCH_EQUAL,
    FWP_MATCH_TYPE, FWP_UINT16, FWP_UINT8, FWP_VALUE0, FWP_VALUE0_0,
};

pub use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_PORT,
};

pub use windows::Win32::Networking::WinSock::IPPROTO_TCP;

/// Errors returned by WFP operations.
#[derive(Debug, thiserror::Error)]
pub enum WfpError {
    #[error("WFP engine unavailable or open failed: {0}")]
    EngineUnavailable(u32),

    #[error("failed to add WFP filter: {0}")]
    FilterAddFailed(u32),

    #[error("failed to delete WFP filter: {0}")]
    FilterDeleteFailed(u32),

    #[error("failed to add WFP sublayer: {0}")]
    SubLayerAddFailed(u32),

    #[error("failed to delete WFP sublayer: {0}")]
    SubLayerDeleteFailed(u32),

    #[error("failed to resolve PID {pid}: {detail}")]
    PidResolveFailed { pid: u32, detail: String },

    #[error("WFP engine not open")]
    EngineNotOpen,
}
