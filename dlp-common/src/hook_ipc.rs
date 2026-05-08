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
