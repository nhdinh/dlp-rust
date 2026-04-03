//! Process DACL hardening — denies process termination and memory manipulation
//! to non-privileged users (T-37).
//!
//! ## Threat model
//!
//! Even if an attacker obtains code execution under a standard user account,
//! they must not be able to:
//! - Terminate the DLP Agent or UI process.
//! - Inject a thread into either process.
//! - Read or write the address space of either process.
//!
//! ## Implementation status
//!
//! This module is **stubbed** in the current build due to windows-rs 0.58 API
//! surface limitations (`SID` byte layout, `TRUSTEE_W` construction, and
//! `SetSecurityInfo`/`SetEntriesInAclW` calling conventions require
//! non-trivial unsafe conversions).  The wiring to the call sites is correct;
//! the hardening is a no-op until the implementation is completed.
//!
//! ## Roadmap
//!
//! - Fix `harden_process` using raw `PSID` pointer casts and `SID` byte layout
//! - Verify `ACL` allocation lifetime with `SetEntriesInAclW` + `LocalFree`
//! - Add integration test that calls `harden_ui_process` and confirms DACL state

use tracing::warn;

/// Applies a hardening DACL to the current (agent) process.
///
/// Called once during service startup.
///
/// # Status
///
/// Stubbed — returns immediately. Fix `harden_process` to enable.
pub fn harden_agent_process() {
    let pid = std::process::id();
    warn!(
        pid = pid,
        "process DACL hardening is stubbed — not yet functional"
    );
}

/// Applies a hardening DACL to a UI process handle.
///
/// Called from [`crate::ui_spawner`] immediately after `CreateProcessAsUserW`
/// succeeds.
///
/// # Status
///
/// Stubbed — returns immediately. Fix `harden_process` to enable.
pub fn harden_ui_process(_h: windows::Win32::Foundation::HANDLE, session_id: u32) {
    warn!(
        session_id = session_id,
        "UI process DACL hardening is stubbed — not yet functional"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The full implementation below is temporarily disabled pending resolution
// of windows-rs 0.58 API surface issues (SID byte layout, PSID pointer
// casting, and ACL lifetime management).  To re-enable, delete the stub
// above and uncomment the implementation below.
// ─────────────────────────────────────────────────────────────────────────────

// fn harden_current_process() -> anyhow::Result<()> {
//     // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no cleanup.
//     let self_handle = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
//     harden_process(self_handle)
// }
//
// fn harden_process(h: windows::Win32::Foundation::HANDLE) -> anyhow::Result<()> {
//     use windows::Win32::Security::Authorization::{
//         BuildTrusteeWithSidW, NO_MULTIPLE_TRUSTEE,
//     };
//     use windows::Win32::Security::{
//         ACL, DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED, SE_OBJECT_TYPE,
//         EXPLICIT_ACCESS_W, SetEntriesInAclW, SetSecurityInfo, ACCESS_MODE, ACE_FLAGS,
//         TRUSTEE_W,
//     };
//
//     unsafe {
//         // ── Build TRUSTEE_W structs using the SID builder helper ────────
//         let auth_users_sid = build_authenticated_users_sid()?;
//         let mut auth_trustee: TRUSTEE_W = std::mem::zeroed();
//         BuildTrusteeWithSidW(&mut auth_trustee, Some(&auth_users_sid));
//         // ... etc.
//     }
// }
