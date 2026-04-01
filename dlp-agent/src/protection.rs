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
//! This is enforced by placing a deny-only ACE for `Authenticated Users` on both
//! process handles immediately after they are created.  The DLP Admin (member
//! of the local `Administrators` group) has an explicit `Allow` entry and is
//! therefore unaffected.
//!
//! ## Technical note
//!
//! `PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
//! PROCESS_VM_READ | PROCESS_VM_WRITE` are denied on the process object itself.
//! This requires `SeSecurityPrivilege` to set a DACL on a protected process,
//! which is held automatically by LocalSystem (the service runs as LocalSystem
//! by default).

use tracing::{error, info};

/// Denies terminate / thread-create / VM operations for Authenticated Users.
const DENY_MASK: u32 = windows::Win32::System::Threading::PROCESS_TERMINATE
    | windows::Win32::System::Threading::PROCESS_CREATE_THREAD
    | windows::Win32::System::Threading::PROCESS_VM_OPERATION
    | windows::Win32::System::Threading::PROCESS_VM_READ
    | windows::Win32::System::Threading::PROCESS_VM_WRITE;

/// Grants full access to LocalSystem and Builtin\Administrators.
const ALLOW_MASK: u32 = windows::Win32::System::Threading::PROCESS_ALL_ACCESS;

/// Applies a hardening DACL to the current (agent) process.
///
/// Called once during service startup.
pub fn harden_agent_process() {
    let pid = std::process::id();
    if let Err(e) = harden_current_process() {
        error!(pid, error = %e, "Failed to harden agent process DACL");
    } else {
        info!(pid, "Agent process DACL hardened");
    }
}

/// Applies a hardening DACL to a UI process handle.
///
/// Called from [`crate::ui_spawner`] immediately after `CreateProcessAsUserW`
/// succeeds.
pub fn harden_ui_process(h: windows::Win32::Foundation::HANDLE, session_id: u32) {
    if let Err(e) = harden_process(h) {
        error!(session_id, error = %e, "Failed to harden UI process DACL");
    } else {
        info!(session_id, "UI process DACL hardened");
    }
}

// ─────────────────────────────────────────────────────────────────────────────

fn harden_current_process() -> anyhow::Result<()> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let self_handle = GetCurrentProcess();
    harden_process(self_handle)
}

fn harden_process(h: windows::Win32::Foundation::HANDLE) -> anyhow::Result<()> {
    use windows::Win32::Security::{
        ACE_FLAGS, ACL_REVISION, DACL_PROTECTED,
        INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE,
        SetEntriesInAclW, SetSecurityInfo,
        EXPLICIT_ACCESS_W, GET_ACCESS, ACCESS_MODE,
        TRUSTEE_W, TRUSTEE_FORM, TRUSTEE_TYPE,
        SE_KERNEL_OBJECT, SET_SECURITY_INFORMATION,
    };
    use windows::Win32::Security::Authorization::NO_MULTIPLE_TRUSTEE;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, TOKEN_QUERY};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, PSID};

    unsafe {
        // Open our own process token (needed to prove we're LocalSystem).
        let mut token: HANDLE = HANDLE::default();
        let self_proc = GetCurrentProcess();
        let ok = OpenProcessToken(self_proc, TOKEN_QUERY(0x0008), &mut token);
        if ok.is_err() {
            return Err(anyhow::anyhow!("OpenProcessToken failed"));
        }
        let _ = CloseHandle(token);

        // ── Build SIDs ────────────────────────────────────────────────────────

        // Authenticated Users: S-1-5-11
        let auth_users_sid = build_authenticated_users_sid()?;
        let auth_ptr = auth_users_sid.as_ptr() as *mut _;

        // LocalSystem (S-1-5-18)
        let localsystem_sid = build_localsystem_sid()?;
        let ls_ptr = localsystem_sid.as_ptr() as *mut _;

        // Builtin\Administrators (S-1-5-32-544)
        let admins_sid = build_admins_sid()?;
        let admin_ptr = admins_sid.as_ptr() as *mut _;

        // ── Build explicit ACEs ──────────────────────────────────────────────

        let deny_explicit = EXPLICIT_ACCESS_W {
            grfAccessPermissions: DENY_MASK,
            grfAccessMode: ACCESS_MODE(3i32), // DENY_ACCESS
            grfInheritance: OBJECT_INHERIT_ACE.0 | INHERIT_ONLY_ACE.0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_FORM(0i32), // TRUSTEE_IS_SID
                TrusteeType: TRUSTEE_TYPE(0i32), // TRUSTEE_IS_UNKNOWN
                ptstrName: auth_ptr,
            },
        };

        let allow_ls_explicit = EXPLICIT_ACCESS_W {
            grfAccessPermissions: ALLOW_MASK,
            grfAccessMode: ACCESS_MODE(1i32), // GRANT_ACCESS
            grfInheritance: OBJECT_INHERIT_ACE.0 | INHERIT_ONLY_ACE.0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_FORM(0i32),
                TrusteeType: TRUSTEE_TYPE(0i32),
                ptstrName: ls_ptr,
            },
        };

        let allow_admin_explicit = EXPLICIT_ACCESS_W {
            grfAccessPermissions: ALLOW_MASK,
            grfAccessMode: ACCESS_MODE(1i32),
            grfInheritance: OBJECT_INHERIT_ACE.0 | INHERIT_ONLY_ACE.0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_FORM(0i32),
                TrusteeType: TRUSTEE_TYPE(0i32),
                ptstrName: admin_ptr,
            },
        };

        // ── Build DACL ────────────────────────────────────────────────────────

        let entries = [deny_explicit, allow_ls_explicit, allow_admin_explicit];
        let mut acl: Option<&mut windows::Win32::Security::ACL> = None;

        let result = SetEntriesInAclW(Some(&entries), None, &mut acl);
        if result != windows::Win32::Foundation::WIN32_ERROR(0) {
            return Err(anyhow::anyhow!(
                "SetEntriesInAclW failed: {}",
                result.0
            ));
        }

        // ── Apply DACL to process ─────────────────────────────────────────────

        let set_result = SetSecurityInfo(
            h,
            SE_KERNEL_OBJECT,
            DACL_PROTECTED | SET_SECURITY_INFORMATION,
            None,
            None,
            acl,
            None,
        );

        if set_result != windows::Win32::Foundation::WIN32_ERROR(0) {
            return Err(anyhow::anyhow!(
                "SetSecurityInfo failed: {}",
                set_result.0
            ));
        }

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// Builds the SID for the Authenticated Users well-known group (S-1-5-11).
///
/// SID structure: revision(1) + authority(6, BE) + sub_count(1) + sub_auths(4 each)
/// S-1-5-11: revision=1, authority=5, sub_count=1, sub_auth=[11]
fn build_authenticated_users_sid() -> anyhow::Result<Vec<u8>> {
    build_sid(1, 5, &[11])
}

/// Builds the SID for the LocalSystem account (S-1-5-18).
fn build_localsystem_sid() -> anyhow::Result<Vec<u8>> {
    build_sid(1, 5, &[18])
}

/// Builds the SID for Builtin\Administrators (S-1-5-32-544).
fn build_admins_sid() -> anyhow::Result<Vec<u8>> {
    build_sid(1, 5, &[32, 544])
}

/// Constructs a SID byte vector for a given authority and sub-authorities.
fn build_sid(revision: u8, authority: u8, sub_authorities: &[u32]) -> anyhow::Result<Vec<u8>> {
    // Authenticated Users: authority=5 (NT AUTHORITY), sub=[11]
    // Layout: revision(1) + authority(6 big-endian) + sub_count(1) + sub_auths(4 each LE)
    let total_size = 1 + 6 + 1 + (sub_authorities.len() * 4);
    let mut sid = vec![0u8; total_size];

    sid[0] = revision;
    // Identifier authority — 6 bytes, bytes 1-6, big-endian from the authority byte
    // The NT authority is 5, encoded big-endian into bytes 1-6 (top 48 bits)
    sid[1] = 0; // bytes 1-5 are zero for authority 5 (it fits in the last byte)
    sid[2] = 0;
    sid[3] = 0;
    sid[4] = 0;
    sid[5] = 0;
    sid[6] = authority; // byte 6 = low byte of big-endian = 5
    sid[7] = sub_authorities.len() as u8;

    for (i, &sub) in sub_authorities.iter().enumerate() {
        let offset = 8 + i * 4;
        sid[offset..offset + 4].copy_from_slice(&sub.to_le_bytes());
    }

    // Validate: the authority byte at sid[6] must be non-zero when top 5 bytes are zero
    if sid[1..7].iter().all(|&b| b == 0) && sid[6] == 0 {
        return Err(anyhow::anyhow!("Invalid SID: zero authority"));
    }

    Ok(sid)
}
