//! Per-session user identity resolution for the DLP agent.
//!
//! When the agent runs as a Windows Service (SYSTEM), file events from the
//! `notify` crate carry no process/user information — every event appears as
//! SYSTEM (S-1-5-18).  This module resolves the *actual* interactive user by:
//!
//! 1. Maintaining a map of active session IDs to their resolved user identities
//!    (populated via Win32 token queries on session logon).
//! 2. Matching file paths against user profile directories
//!    (e.g., `C:\Users\jsmith\...` -> session for `jsmith`).
//! 3. Falling back to a single-user heuristic when the path is ambiguous.
//!
//! ## Integration
//!
//! The [`SessionIdentityMap`] should be created once at agent startup and
//! shared via `Arc`.  Call [`SessionIdentityMap::add_session`] when a new
//! interactive session is detected and [`SessionIdentityMap::remove_session`]
//! on logoff.  Use [`SessionIdentityMap::resolve_for_path`] in the file
//! interception pipeline to tag each event with the correct user.

use std::collections::HashMap;
use std::sync::Arc;

use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

/// Global session identity map, shared across the agent's subsystems.
///
/// Initialised once during service startup via [`init_global`] and accessed
/// by the session monitor, interception pipeline, and audit emitter.
static GLOBAL_MAP: OnceCell<Arc<SessionIdentityMap>> = OnceCell::new();

/// Stores a reference to the global session identity map.
///
/// Called once during service or console startup.  Subsequent calls are
/// no-ops (the first value wins).
///
/// # Arguments
///
/// * `map` - The shared identity map to install as the global instance.
pub fn init_global(map: Arc<SessionIdentityMap>) {
    let _ = GLOBAL_MAP.set(map);
}

/// Returns the global session identity map, if initialised.
///
/// Returns `None` before [`init_global`] has been called.
pub fn global_map() -> Option<Arc<SessionIdentityMap>> {
    GLOBAL_MAP.get().cloned()
}

/// SID string returned when no interactive user can be resolved.
const SYSTEM_SID: &str = "S-1-5-18";

/// Username returned when no interactive user can be resolved.
const SYSTEM_NAME: &str = "SYSTEM";

/// The `C:\Users\` prefix used for path-based identity resolution.
/// Stored as lowercase for case-insensitive comparison.
const USERS_PREFIX: &str = r"c:\users\";

/// A resolved user identity for an interactive Windows session.
#[derive(Debug, Clone, PartialEq)]
pub struct UserIdentity {
    /// The user's security identifier (e.g., "S-1-5-21-...").
    pub sid: String,
    /// The user's account name (e.g., "jsmith").
    pub name: String,
}

/// Errors that can occur during session identity resolution.
#[derive(Debug, thiserror::Error)]
pub enum SessionIdentityError {
    /// The session ID refers to session 0, which has no interactive user.
    #[error("session 0 is reserved for SYSTEM services")]
    SessionZero,

    /// Failed to obtain the user token for the session.
    #[error("WTSQueryUserToken failed for session {session_id}: {reason}")]
    TokenQueryFailed {
        /// The session ID that was queried.
        session_id: u32,
        /// Description of the underlying Win32 error.
        reason: String,
    },

    /// Failed to query token information.
    #[error("GetTokenInformation failed: {0}")]
    TokenInfoFailed(String),

    /// Failed to convert a SID to its string representation.
    #[error("ConvertSidToStringSidW failed: {0}")]
    SidConversionFailed(String),

    /// Failed to look up the account name for a SID.
    #[error("LookupAccountSidW failed: {0}")]
    AccountLookupFailed(String),

    /// Failed to open the process token.
    #[error("OpenProcessToken failed: {0}")]
    ProcessTokenFailed(String),
}

/// Thread-safe map from session IDs to resolved user identities.
///
/// Internally uses a [`parking_lot::RwLock`] so readers never block each other.
/// Also maintains a reverse map from lowercase username to session ID for
/// efficient path-based lookups.
///
/// # Examples
///
/// ```no_run
/// use dlp_agent::session_identity::SessionIdentityMap;
///
/// let map = SessionIdentityMap::new();
/// // Called when session monitor detects a new interactive session:
/// map.add_session(2);
/// // Called from the file interception pipeline:
/// let (sid, name) = map.resolve_for_path(r"C:\Users\jsmith\Documents\report.docx");
/// ```
#[derive(Debug)]
pub struct SessionIdentityMap {
    /// Forward map: session_id -> UserIdentity.
    pub sessions: RwLock<HashMap<u32, UserIdentity>>,
    /// Reverse map: lowercase username -> session_id for path lookups.
    pub username_to_session: RwLock<HashMap<String, u32>>,
}

impl SessionIdentityMap {
    /// Creates a new, empty session identity map.
    ///
    /// # Returns
    ///
    /// An empty `SessionIdentityMap` ready to accept session registrations.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            username_to_session: RwLock::new(HashMap::new()),
        }
    }

    /// Resolves and registers the user identity for an interactive session.
    ///
    /// Queries the session's user token via Win32 APIs to obtain the SID and
    /// account name, then stores them for later path-based resolution.
    ///
    /// Session 0 is silently skipped (it hosts SYSTEM services, not
    /// interactive users).
    ///
    /// # Arguments
    ///
    /// * `session_id` - The Windows session ID to resolve (from
    ///   `WTSEnumerateSessionsW`).
    ///
    /// # Errors
    ///
    /// Returns [`SessionIdentityError`] if the Win32 token query chain fails.
    /// The map is left unchanged on error.
    pub fn add_session(&self, session_id: u32) -> Result<(), SessionIdentityError> {
        if session_id == 0 {
            debug!("Skipping session 0 (SYSTEM services)");
            return Err(SessionIdentityError::SessionZero);
        }

        let identity = query_session_user(session_id)?;

        info!(
            session_id,
            sid = %identity.sid,
            name = %identity.name,
            "Registered session identity"
        );

        let lower_name = identity.name.to_lowercase();
        self.sessions.write().insert(session_id, identity);
        self.username_to_session
            .write()
            .insert(lower_name, session_id);

        Ok(())
    }

    /// Removes a session from both the forward and reverse maps.
    ///
    /// Called when a user logs off. If the session ID is not present,
    /// this is a no-op.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The Windows session ID to remove.
    pub fn remove_session(&self, session_id: u32) {
        let removed = self.sessions.write().remove(&session_id);
        if let Some(identity) = removed {
            let lower_name = identity.name.to_lowercase();
            // Only remove the reverse entry if it still points to this session
            // (guards against a user with two sessions where one logs off).
            let mut reverse = self.username_to_session.write();
            if reverse.get(&lower_name) == Some(&session_id) {
                reverse.remove(&lower_name);
            }
            info!(
                session_id,
                name = %identity.name,
                "Removed session identity"
            );
        }
    }

    /// Resolves the user identity for a file path.
    ///
    /// Uses a three-tier strategy:
    ///
    /// 1. **Path heuristic** -- if the path starts with `C:\Users\<name>\`,
    ///    look up `<name>` in the reverse username map.
    /// 2. **Single-user heuristic** -- if exactly one interactive session is
    ///    registered, assume that user performed the operation.
    /// 3. **Fallback** -- return the SYSTEM identity (`S-1-5-18`).
    ///
    /// # Arguments
    ///
    /// * `path` - The file path from the `notify` event.
    ///
    /// # Returns
    ///
    /// A `(sid, username)` tuple.  Never fails — always returns at least the
    /// SYSTEM fallback.
    pub fn resolve_for_path(&self, path: &str) -> (String, String) {
        // Tier 1: extract username from the path.
        if let Some(profile_name) = extract_profile_username(path) {
            let lower = profile_name.to_lowercase();
            let reverse = self.username_to_session.read();
            if let Some(&sid) = reverse.get(&lower) {
                let sessions = self.sessions.read();
                if let Some(identity) = sessions.get(&sid) {
                    debug!(
                        path,
                        resolved_user = %identity.name,
                        "Path-based identity resolution"
                    );
                    return (identity.sid.clone(), identity.name.clone());
                }
            }
        }

        // Tier 2: single-user heuristic.
        let sessions = self.sessions.read();
        if sessions.len() == 1 {
            // SAFETY of .values().next(): we just checked len() == 1.
            let identity = sessions
                .values()
                .next()
                .expect("len == 1 guarantees at least one entry");
            debug!(
                path,
                resolved_user = %identity.name,
                "Single-user heuristic resolution"
            );
            return (identity.sid.clone(), identity.name.clone());
        }

        // Tier 3: fallback to SYSTEM.
        debug!(
            path,
            "No interactive user resolved — falling back to SYSTEM"
        );
        (SYSTEM_SID.to_owned(), SYSTEM_NAME.to_owned())
    }

    /// Returns the number of registered sessions (for diagnostics).
    ///
    /// # Returns
    ///
    /// The count of sessions currently in the map.
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }
}

impl Default for SessionIdentityMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Extracts the username component from a `C:\Users\<name>\...` path.
///
/// The match is case-insensitive.  Returns `None` if the path does not
/// follow the user-profile directory convention.
///
/// # Arguments
///
/// * `path` - A Windows file path.
///
/// # Returns
///
/// The profile directory name (original casing) if the path matches, or
/// `None` otherwise.
fn extract_profile_username(path: &str) -> Option<&str> {
    // Normalise path separators: convert forward slashes to backslashes for
    // consistent matching (some libraries produce forward-slash paths).
    // We compare against a lowercase copy to be case-insensitive.
    let lower = path.to_lowercase();
    let lower = lower.replace('/', r"\");

    if !lower.starts_with(USERS_PREFIX) {
        return None;
    }

    // The username sits between `C:\Users\` and the next backslash.
    let after_prefix = &path[USERS_PREFIX.len()..];
    // Find the end of the username component.
    let end = after_prefix
        .find('\\')
        .or_else(|| after_prefix.find('/'))
        .unwrap_or(after_prefix.len());

    let name = &after_prefix[..end];
    if name.is_empty() {
        return None;
    }

    Some(name)
}

// ---------------------------------------------------------------------------
// Win32 API wrappers (only compiled on Windows)
// ---------------------------------------------------------------------------

/// Queries the user identity for a given session via Win32 token APIs.
///
/// # Arguments
///
/// * `session_id` - The interactive session to query.
///
/// # Returns
///
/// The resolved [`UserIdentity`] containing the SID string and username.
///
/// # Errors
///
/// Returns [`SessionIdentityError`] if any step of the Win32 API chain fails.
#[cfg(windows)]
fn query_session_user(session_id: u32) -> Result<UserIdentity, SessionIdentityError> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;

    // Step 1: obtain the session's primary token.
    let mut token = HANDLE::default();

    // SAFETY: WTSQueryUserToken is safe to call with a valid session ID;
    // it writes a token handle that we must close.
    unsafe {
        WTSQueryUserToken(session_id, &mut token).map_err(|e| {
            SessionIdentityError::TokenQueryFailed {
                session_id,
                reason: format!("{e}"),
            }
        })?;
    }

    // Ensure the token handle is closed on all exit paths.
    // `scopeguard` would be ideal, but a manual approach avoids the dep.
    let result = query_token_identity(token);

    // SAFETY: token is a valid handle returned by WTSQueryUserToken.
    unsafe {
        let _ = CloseHandle(token);
    }

    result
}

/// Stub for non-Windows platforms (allows the module to compile in tests on
/// any OS, though the Win32 calls are gated behind `#[cfg(windows)]`).
#[cfg(not(windows))]
fn query_session_user(_session_id: u32) -> Result<UserIdentity, SessionIdentityError> {
    Err(SessionIdentityError::TokenInfoFailed(
        "Win32 APIs unavailable on this platform".to_owned(),
    ))
}

/// Extracts the SID and username from an open token handle.
///
/// # Arguments
///
/// * `token` - A valid token handle with `TOKEN_QUERY` access.
///
/// # Returns
///
/// The resolved [`UserIdentity`].
///
/// # Errors
///
/// Returns [`SessionIdentityError`] on any Win32 failure.
#[cfg(windows)]
fn query_token_identity(
    token: windows::Win32::Foundation::HANDLE,
) -> Result<UserIdentity, SessionIdentityError> {
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};

    // First call: determine the required buffer size.
    let mut needed: u32 = 0;
    // SAFETY: passing None/0 to get the required size is the documented
    // two-call pattern for GetTokenInformation.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };

    if needed == 0 {
        return Err(SessionIdentityError::TokenInfoFailed(
            "GetTokenInformation returned zero size".to_owned(),
        ));
    }

    // Second call: fill the buffer.
    let mut buf = vec![0u8; needed as usize];
    // SAFETY: buf is sized to `needed` bytes as reported by the first call.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
        .map_err(|e| SessionIdentityError::TokenInfoFailed(format!("{e}")))?;
    }

    // The buffer starts with a TOKEN_USER struct whose first field is a
    // SID_AND_ATTRIBUTES containing the user SID pointer.
    // SAFETY: GetTokenInformation succeeded and wrote a valid TOKEN_USER.
    let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let psid = token_user.User.Sid;

    let sid_string = sid_to_string(psid)?;
    let username = lookup_account_name(psid)?;

    Ok(UserIdentity {
        sid: sid_string,
        name: username,
    })
}

/// Converts a `PSID` to its string representation (e.g., "S-1-5-21-...").
///
/// # Arguments
///
/// * `psid` - A valid SID pointer from a token query.
///
/// # Returns
///
/// The SID as a `String`.
///
/// # Errors
///
/// Returns [`SessionIdentityError::SidConversionFailed`] on Win32 failure.
#[cfg(windows)]
fn sid_to_string(psid: windows::Win32::Security::PSID) -> Result<String, SessionIdentityError> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;

    let mut sid_pwstr = PWSTR::null();

    // SAFETY: psid is a valid SID from GetTokenInformation.
    // ConvertSidToStringSidW allocates memory via LocalAlloc that we must free.
    unsafe {
        ConvertSidToStringSidW(psid, &mut sid_pwstr)
            .map_err(|e| SessionIdentityError::SidConversionFailed(format!("{e}")))?;
    }

    // Read the null-terminated wide string.
    // SAFETY: ConvertSidToStringSidW wrote a valid null-terminated UTF-16 string.
    let result = unsafe { sid_pwstr.to_string() }.map_err(|e| {
        SessionIdentityError::SidConversionFailed(format!("UTF-16 decode error: {e}"))
    })?;

    // Free the buffer allocated by ConvertSidToStringSidW.
    // SAFETY: sid_pwstr was allocated by ConvertSidToStringSidW.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid_pwstr.0.cast())));
    }

    Ok(result)
}

/// Looks up the account name for a SID via `LookupAccountSidW`.
///
/// Uses the standard two-call pattern: first call to determine buffer sizes,
/// second call to fill the buffers.
///
/// # Arguments
///
/// * `psid` - A valid SID pointer.
///
/// # Returns
///
/// The account name as a `String`.
///
/// # Errors
///
/// Returns [`SessionIdentityError::AccountLookupFailed`] on Win32 failure.
#[cfg(windows)]
fn lookup_account_name(
    psid: windows::Win32::Security::PSID,
) -> Result<String, SessionIdentityError> {
    use windows::core::PWSTR;
    use windows::Win32::Security::{LookupAccountSidW, SID_NAME_USE};

    let mut name_len: u32 = 0;
    let mut domain_len: u32 = 0;
    let mut sid_type = SID_NAME_USE(0);

    // First call: get required buffer sizes.
    // SAFETY: passing null buffers with zero lengths is the documented pattern.
    let _ = unsafe {
        LookupAccountSidW(
            None,
            psid,
            Some(PWSTR::null()),
            &mut name_len,
            Some(PWSTR::null()),
            &mut domain_len,
            &mut sid_type,
        )
    };

    if name_len == 0 {
        return Err(SessionIdentityError::AccountLookupFailed(
            "LookupAccountSidW returned zero name length".to_owned(),
        ));
    }

    // Second call: fill the buffers.
    let mut name_buf = vec![0u16; name_len as usize];
    let mut domain_buf = vec![0u16; domain_len as usize];

    // SAFETY: buffers are sized per the first call's output.
    unsafe {
        LookupAccountSidW(
            None,
            psid,
            Some(PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain_buf.as_mut_ptr())),
            &mut domain_len,
            &mut sid_type,
        )
        .map_err(|e| SessionIdentityError::AccountLookupFailed(format!("{e}")))?;
    }

    // name_len now contains the length *excluding* the null terminator.
    let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    Ok(name)
}

/// Resolves the identity of the current process's user.
///
/// Intended for **console mode** (non-service) operation where the agent runs
/// under the logged-in user's account rather than SYSTEM.
///
/// # Returns
///
/// A `(sid_string, username)` tuple.  Falls back to the `USERNAME` environment
/// variable with a stub SID if the Win32 calls fail.
///
/// # Errors
///
/// Returns [`SessionIdentityError`] if all resolution strategies fail.
/// In practice, the env-var fallback makes total failure unlikely.
#[cfg(windows)]
pub fn resolve_console_user() -> (String, String) {
    match resolve_console_user_inner() {
        Ok(identity) => {
            info!(
                sid = %identity.sid,
                name = %identity.name,
                "Console user resolved"
            );
            (identity.sid, identity.name)
        }
        Err(e) => {
            warn!(
                error = %e,
                "Failed to resolve console user via token -- \
                 falling back to env"
            );
            fallback_from_env()
        }
    }
}

/// Non-Windows stub for [`resolve_console_user`].
#[cfg(not(windows))]
pub fn resolve_console_user() -> (String, String) {
    fallback_from_env()
}

/// Inner implementation for [`resolve_console_user`] that can propagate errors.
#[cfg(windows)]
fn resolve_console_user_inner() -> Result<UserIdentity, SessionIdentityError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();

    // SAFETY: GetCurrentProcess returns a pseudo-handle; OpenProcessToken
    // with TOKEN_QUERY is a read-only operation.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| SessionIdentityError::ProcessTokenFailed(format!("{e}")))?;
    }

    let result = query_token_identity(token);

    // SAFETY: token is a valid handle from OpenProcessToken.
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(token);
    }

    result
}

/// Fallback identity resolution via the `USERNAME` environment variable.
///
/// Returns a stub SID (`S-1-5-0-0`) paired with the env-var username, or
/// the SYSTEM identity if the variable is unset.
fn fallback_from_env() -> (String, String) {
    match std::env::var("USERNAME") {
        Ok(name) if !name.is_empty() => {
            debug!(
                name = %name,
                "Using USERNAME env var as fallback identity"
            );
            // Stub SID signals that this was not resolved from a real token.
            ("S-1-5-0-0".to_owned(), name)
        }
        _ => {
            warn!("USERNAME env var not set -- defaulting to SYSTEM");
            (SYSTEM_SID.to_owned(), SYSTEM_NAME.to_owned())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Path extraction tests -----------------------------------------------

    #[test]
    fn test_resolve_user_profile_path() {
        let map = SessionIdentityMap::new();

        // Pre-populate the map with a known session.
        map.sessions.write().insert(
            2,
            UserIdentity {
                sid: "S-1-5-21-999".to_owned(),
                name: "jsmith".to_owned(),
            },
        );
        map.username_to_session
            .write()
            .insert("jsmith".to_owned(), 2);

        let (sid, name) = map.resolve_for_path(r"C:\Users\jsmith\Documents\file.txt");
        assert_eq!(sid, "S-1-5-21-999");
        assert_eq!(name, "jsmith");
    }

    #[test]
    fn test_resolve_non_user_path() {
        let map = SessionIdentityMap::new();

        // With no sessions registered, any path falls back to SYSTEM.
        let (sid, name) = map.resolve_for_path(r"C:\Data\report.txt");
        assert_eq!(sid, SYSTEM_SID);
        assert_eq!(name, SYSTEM_NAME);
    }

    #[test]
    fn test_resolve_case_insensitive() {
        let map = SessionIdentityMap::new();

        map.sessions.write().insert(
            3,
            UserIdentity {
                sid: "S-1-5-21-888".to_owned(),
                name: "JSmith".to_owned(),
            },
        );
        map.username_to_session
            .write()
            .insert("jsmith".to_owned(), 3);

        // Mixed-case path should still resolve.
        let (sid, name) = map.resolve_for_path(r"C:\users\JSmith\Desktop\notes.txt");
        assert_eq!(sid, "S-1-5-21-888");
        assert_eq!(name, "JSmith");
    }

    #[test]
    fn test_add_remove_session() {
        let map = SessionIdentityMap::new();

        // Directly insert (bypassing Win32 APIs for unit testing).
        let identity = UserIdentity {
            sid: "S-1-5-21-100".to_owned(),
            name: "testuser".to_owned(),
        };
        map.sessions.write().insert(5, identity.clone());
        map.username_to_session
            .write()
            .insert("testuser".to_owned(), 5);

        assert_eq!(map.session_count(), 1);
        assert_eq!(map.sessions.read().get(&5), Some(&identity),);

        // Remove and verify cleanup.
        map.remove_session(5);
        assert_eq!(map.session_count(), 0);
        assert!(map.username_to_session.read().get("testuser").is_none());
    }

    #[test]
    fn test_session_zero_rejected() {
        let map = SessionIdentityMap::new();
        let result = map.add_session(0);
        assert!(result.is_err());
        assert!(matches!(result, Err(SessionIdentityError::SessionZero)));
    }

    #[test]
    fn test_single_user_heuristic() {
        let map = SessionIdentityMap::new();

        // One session registered, but path is NOT under that user's profile.
        map.sessions.write().insert(
            7,
            UserIdentity {
                sid: "S-1-5-21-777".to_owned(),
                name: "alice".to_owned(),
            },
        );
        map.username_to_session
            .write()
            .insert("alice".to_owned(), 7);

        // Path under a shared directory, not a user profile.
        let (sid, name) = map.resolve_for_path(r"D:\Shared\budget.xlsx");
        assert_eq!(sid, "S-1-5-21-777");
        assert_eq!(name, "alice");
    }

    #[test]
    fn test_multiple_sessions_non_profile_path_falls_back() {
        let map = SessionIdentityMap::new();

        // Two sessions registered.
        map.sessions.write().insert(
            2,
            UserIdentity {
                sid: "S-1-5-21-111".to_owned(),
                name: "alice".to_owned(),
            },
        );
        map.sessions.write().insert(
            3,
            UserIdentity {
                sid: "S-1-5-21-222".to_owned(),
                name: "bob".to_owned(),
            },
        );

        // Non-profile path with multiple sessions -> SYSTEM fallback.
        let (sid, name) = map.resolve_for_path(r"D:\Shared\report.pdf");
        assert_eq!(sid, SYSTEM_SID);
        assert_eq!(name, SYSTEM_NAME);
    }

    #[test]
    fn test_extract_profile_username_basic() {
        assert_eq!(
            extract_profile_username(r"C:\Users\jsmith\Documents\f.txt"),
            Some("jsmith"),
        );
    }

    #[test]
    fn test_extract_profile_username_case_insensitive() {
        assert_eq!(
            extract_profile_username(r"c:\users\Admin\Desktop"),
            Some("Admin"),
        );
    }

    #[test]
    fn test_extract_profile_username_no_match() {
        assert_eq!(extract_profile_username(r"D:\Data\file.txt"), None,);
    }

    #[test]
    fn test_extract_profile_username_forward_slash() {
        assert_eq!(
            extract_profile_username("C:/Users/jdoe/file.txt"),
            Some("jdoe"),
        );
    }

    #[test]
    fn test_extract_profile_username_bare_users() {
        // Just `C:\Users\` with nothing after it.
        assert_eq!(extract_profile_username(r"C:\Users\"), None,);
    }

    #[test]
    fn test_fallback_from_env() {
        // This test exercises the env-var fallback. The exact result depends
        // on the environment, but it should never panic.
        let (sid, name) = fallback_from_env();
        assert!(!sid.is_empty());
        assert!(!name.is_empty());
    }

    #[test]
    fn test_remove_nonexistent_session_is_noop() {
        let map = SessionIdentityMap::new();
        // Should not panic.
        map.remove_session(999);
        assert_eq!(map.session_count(), 0);
    }
}
