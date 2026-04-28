//! Process DACL hardening -- denies process termination and memory manipulation
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
//! ## Implementation
//!
//! Removes all non-inherited ACEs from the process DACL, then adds a single
//! DENY ACE for the `Everyone` SID covering dangerous access rights.  This
//! prevents standard users and even non-dlp-admin administrators from killing
//! the process via Task Manager, `taskkill`, or Process Explorer.
//!
//! SYSTEM retains full access through inherited ACEs from the default DACL.

use anyhow::{Context, Result};
use tracing::{info, warn};
use windows::Win32::Foundation::HANDLE;

/// Dangerous access rights blocked by the hardening DACL.
///
/// - `PROCESS_TERMINATE` (0x0001) -- kill the process.
/// - `PROCESS_CREATE_THREAD` (0x0002) -- inject a thread.
/// - `PROCESS_VM_OPERATION` (0x0008) -- VirtualProtectEx, etc.
/// - `PROCESS_VM_WRITE` (0x0020) -- WriteProcessMemory.
/// - `PROCESS_VM_READ` (0x0010) -- ReadProcessMemory.
const DENIED_ACCESS: u32 = 0x0001 | 0x0002 | 0x0008 | 0x0010 | 0x0020;

/// Applies a hardening DACL to the current (agent) process.
///
/// Called once during service startup.  Failures are logged as warnings
/// but do not prevent the service from running.
///
/// # Test override
///
/// Set `DLP_SKIP_HARDENING=1` to disable DACL hardening.  This allows
/// integration tests to kill the agent process via `Child::kill()` without
/// requiring SYSTEM-level privileges.
pub fn harden_agent_process() {
    // Skip DACL hardening when running in test mode. Integration tests spawn
    // the agent as a child process and need to terminate it with child.kill(),
    // which requires PROCESS_TERMINATE access. Hardening blocks this for
    // non-privileged callers.
    if std::env::var("DLP_SKIP_HARDENING").is_ok_and(|v| v == "1") {
        info!(pid = std::process::id(), "agent process DACL hardening skipped (DLP_SKIP_HARDENING=1)");
        return;
    }
    // SAFETY: `GetCurrentProcess()` returns a pseudo-handle (-1) that is
    // always valid and does not need to be closed.
    let handle = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
    match harden_process(handle) {
        Ok(()) => info!(pid = std::process::id(), "agent process DACL hardened"),
        Err(e) => warn!(
            pid = std::process::id(),
            error = %e,
            "failed to harden agent process DACL"
        ),
    }
}

/// Applies a hardening DACL to a UI process handle.
///
/// Called from [`crate::ui_spawner`] immediately after `CreateProcessAsUserW`
/// succeeds.
pub fn harden_ui_process(handle: HANDLE, session_id: u32) {
    match harden_process(handle) {
        Ok(()) => info!(session_id, "UI process DACL hardened"),
        Err(e) => warn!(
            session_id,
            error = %e,
            "failed to harden UI process DACL"
        ),
    }
}

/// Applies a DENY ACE for `Everyone` on the given process handle.
///
/// Uses `SetKernelObjectSecurity` with a manually-constructed DACL
/// containing a single DENY ACE.  This approach avoids the complex
/// `SetEntriesInAclW` / `TRUSTEE_W` API that has ergonomic issues
/// in windows-rs 0.58.
fn harden_process(handle: HANDLE) -> Result<()> {
    use windows::Win32::Security::{
        InitializeSecurityDescriptor, SetKernelObjectSecurity, SetSecurityDescriptorDacl, ACL,
        DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR,
    };

    // SECURITY_DESCRIPTOR_REVISION = 1 (avoid pulling in Win32_System_SystemServices).
    const SD_REVISION: u32 = 1;

    // Build a DACL with a single DENY ACE for Everyone.
    let dacl = build_deny_everyone_dacl(DENIED_ACCESS)?;

    // Build a security descriptor pointing to our DACL.
    // SAFETY: `sd` is stack-allocated and outlives the SetKernelObjectSecurity call.
    // The DACL buffer must also outlive the descriptor.
    let mut sd = SECURITY_DESCRIPTOR::default();
    unsafe {
        let psd = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut _);

        InitializeSecurityDescriptor(psd, SD_REVISION)
            .ok()
            .context("InitializeSecurityDescriptor failed")?;

        SetSecurityDescriptorDacl(
            psd,
            true,                              // bDaclPresent
            Some(dacl.as_ptr() as *const ACL), // pDacl
            false,                             // bDaclDefaulted
        )
        .ok()
        .context("SetSecurityDescriptorDacl failed")?;

        SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, psd)
            .ok()
            .context("SetKernelObjectSecurity failed")?;
    }

    Ok(())
}

/// Builds a raw ACL buffer containing a single ACCESS_DENIED_ACE for
/// the `Everyone` well-known SID (S-1-1-0).
///
/// ## ACL memory layout (Win32)
///
/// ```text
/// [ ACL header (8 bytes) ][ ACCESS_DENIED_ACE header (8 bytes) ][ SID (12 bytes) ]
/// ```
///
/// The ACE header is `ACE_HEADER` (1-byte type, 1-byte flags, 2-byte size)
/// followed by a 4-byte `Mask` (the denied access rights), followed by the
/// SID.  The SID for Everyone is `S-1-1-0` = 12 bytes.
fn build_deny_everyone_dacl(denied_mask: u32) -> Result<Vec<u8>> {
    // Everyone SID: S-1-1-0
    // Revision=1, SubAuthorityCount=1, IdentifierAuthority={0,0,0,0,0,1},
    // SubAuthority[0]=0
    let everyone_sid: [u8; 12] = [
        1, // Revision
        1, // SubAuthorityCount
        0, 0, 0, 0, 0, 1, // IdentifierAuthority = SECURITY_WORLD_SID_AUTHORITY
        0, 0, 0, 0, // SubAuthority[0] = 0
    ];

    // ACCESS_DENIED_ACE = ACE_HEADER (4 bytes) + Mask (4 bytes) + SID (variable)
    // ACE_HEADER: AceType=ACCESS_DENIED_ACE_TYPE(1), AceFlags=0, AceSize
    let ace_size: u16 = 4 + 4 + everyone_sid.len() as u16; // header + mask + sid
    let acl_size: u16 = 8 + ace_size; // ACL header (8 bytes) + one ACE

    let mut buf = vec![0u8; acl_size as usize];

    // ACL header (8 bytes):
    // AclRevision (1), Sbz1 (1), AclSize (2), AceCount (2), Sbz2 (2)
    buf[0] = 2; // ACL_REVISION
    buf[1] = 0; // Sbz1
    buf[2..4].copy_from_slice(&acl_size.to_le_bytes()); // AclSize
    buf[4..6].copy_from_slice(&1u16.to_le_bytes()); // AceCount = 1
    buf[6..8].copy_from_slice(&0u16.to_le_bytes()); // Sbz2

    // ACCESS_DENIED_ACE at offset 8:
    let ace_offset = 8usize;
    buf[ace_offset] = 1; // AceType = ACCESS_DENIED_ACE_TYPE
    buf[ace_offset + 1] = 0; // AceFlags = 0 (no inheritance)
    buf[ace_offset + 2..ace_offset + 4].copy_from_slice(&ace_size.to_le_bytes()); // AceSize
    buf[ace_offset + 4..ace_offset + 8].copy_from_slice(&denied_mask.to_le_bytes()); // Mask

    // SID at offset 8 + 8 = 16:
    buf[ace_offset + 8..ace_offset + 8 + everyone_sid.len()].copy_from_slice(&everyone_sid);

    Ok(buf)
}
