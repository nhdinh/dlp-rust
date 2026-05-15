//! IPC types shared between the hook DLL and the agent service.

use serde::{Deserialize, Serialize};

/// Request sent by the hook DLL to the agent for classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookRequest {
    pub path: String,
    pub action: String,
}

/// Response returned by the agent to the hook DLL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookResponse {
    pub decision: crate::Decision,
    pub reason: String,
}

/// Request sent by the hook DLL to the agent for handle-based classification.
///
/// The agent resolves the path from its internal handle tracker.
/// `handle_value` is `u64` (not `usize`) to avoid architecture ambiguity
/// when a 32-bit hook DLL talks to a 64-bit agent service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandleHookRequest {
    /// The raw HANDLE value cast to u64 for cross-architecture safety.
    pub handle_value: u64,
    /// The operation being performed (e.g., "WRITE", "SET_INFO").
    pub action: String,
    /// The PID of the process making the request.
    pub pid: u32,
}
