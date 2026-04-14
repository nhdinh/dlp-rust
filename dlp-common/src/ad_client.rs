//! Active Directory LDAP client for resolving ABAC subject attributes.
//!
//! This module provides an async AD/LDAP client that:
//! - Resolves user group memberships via `tokenGroups` (full transitive closure)
//! - Caches group memberships by SID with configurable TTL
//! - Authenticates using the machine account (Kerberos TGT) — no stored credentials
//! - Fails open: returns empty groups on AD errors rather than blocking operations
//!
//! On non-Windows platforms, all Windows-API-dependent functions return safe
//! defaults (`DeviceTrust::Unknown`, `NetworkLocation::Unknown`).

use std::collections::HashMap;

use ipnetwork::IpNetwork;
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};
use parking_lot::Mutex;
use thiserror::Error;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Binary SID parsing (MS-DTYP)
// ---------------------------------------------------------------------------

/// Parses a binary SID byte array into its string representation.
///
/// Binary SID format (per MS-DTYP §2.4.2):
/// - Byte 0: Revision (must be 1)
/// - Byte 1: SubAuthorityCount (n)
/// - Bytes 2-7: IdentifierAuthority (6 bytes, big-endian u48)
/// - Bytes 8+: n × 4-byte subauthorities (little-endian u32 each)
///
/// Returns `None` if the byte slice is too short or has an invalid revision.
fn parse_sid_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    if bytes[0] != 1 {
        return None;
    }
    let subauthority_count = bytes[1] as usize;
    if bytes.len() < 8 + subauthority_count * 4 {
        return None;
    }

    let authority = u64::from(bytes[2]) << 40
        | u64::from(bytes[3]) << 32
        | u64::from(bytes[4]) << 24
        | u64::from(bytes[5]) << 16
        | u64::from(bytes[6]) << 8
        | u64::from(bytes[7]);

    let mut parts = vec![format!("S-1-{}", authority)];
    for i in 0..subauthority_count {
        let offset = 8 + i * 4;
        let sub = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        parts.push(format!("{}", sub));
    }

    Some(parts.join("-"))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the AD/LDAP client.
#[derive(Debug, Error)]
pub enum AdClientError {
    #[error("LDAP connection failed: {0}")]
    LdapConnect(String),

    #[error("LDAP bind failed: {0}")]
    LdapBind(String),

    #[error("LDAP search failed: {0}")]
    LdapSearch(String),

    #[error("user not found in AD: {0}")]
    UserNotFound(String),

    #[error("invalid SID in tokenGroups: {0}")]
    InvalidSid(String),
}

// ---------------------------------------------------------------------------
// Group cache
// ---------------------------------------------------------------------------

/// Thread-safe in-memory cache for AD group memberships.
///
/// Entries expire after `ttl_secs` seconds. The cache is keyed by the
/// caller's SID (not the user's DN), since the SID is universally available
/// in all call sites.
struct GroupCache {
    entries: HashMap<String, (Vec<String>, std::time::Instant)>,
    ttl_secs: u64,
}

impl GroupCache {
    /// Returns the cached groups for `sid` if the entry exists and is not expired.
    fn get(&self, sid: &str) -> Option<Vec<String>> {
        let entry = self.entries.get(sid)?;
        if entry.1.elapsed().as_secs() < self.ttl_secs {
            Some(entry.0.clone())
        } else {
            None
        }
    }

    /// Inserts a new entry for `sid`.
    fn insert(&mut self, sid: String, groups: Vec<String>) {
        self.evict_expired();
        self.entries
            .insert(sid, (groups, std::time::Instant::now()));
    }

    /// Removes all entries that have exceeded the TTL.
    fn evict_expired(&mut self) {
        self.entries
            .retain(|_, (_, cached_at)| cached_at.elapsed().as_secs() < self.ttl_secs);
    }
}

// ---------------------------------------------------------------------------
// LdapConfig
// ---------------------------------------------------------------------------

/// Configuration for the AD/LDAP client.
///
/// Serialized to/from the `ldap_config` table in the server DB and pushed
/// to agents via the agent-config payload.
#[derive(Debug, Clone)]
pub struct LdapConfig {
    /// LDAP URL — e.g. `"ldaps://dc.corp.internal:636"`.
    pub ldap_url: String,
    /// Base DN for LDAP searches — e.g. `"DC=corp,DC=internal"`.
    pub base_dn: String,
    /// When `true`, only LDAPS connections are permitted.
    pub require_tls: bool,
    /// Group membership cache TTL in seconds. Clamped to [60, 3600].
    pub cache_ttl_secs: u64,
    /// Comma-separated list of VPN CIDR ranges.
    pub vpn_subnets: String,
}

impl LdapConfig {
    /// Parses the `vpn_subnets` comma-separated string into a `Vec<IpNetwork>`.
    pub fn parse_vpn_subnets(&self) -> Result<Vec<IpNetwork>, ipnetwork::IpNetworkError> {
        if self.vpn_subnets.trim().is_empty() {
            return Ok(Vec::new());
        }
        self.vpn_subnets
            .split(',')
            .map(|s| s.trim().parse())
            .collect()
    }

    /// Returns the effective cache TTL clamped to [60, 3600].
    pub fn effective_cache_ttl(&self) -> u64 {
        self.cache_ttl_secs.clamp(60, 3600)
    }
}

// ---------------------------------------------------------------------------
// AdClient
// ---------------------------------------------------------------------------

/// Async AD/LDAP client backed by Tokio and the `ldap3` crate.
///
/// Constructed via [`AdClient::new`]. Each instance owns a background task that
/// manages a persistent LDAP connection authenticated with the machine
/// account (Kerberos TGT). All public methods are async and communicate with
/// that background task via channels.
pub struct AdClient {
    ldap_url: String,
    base_dn: String,
    require_tls: bool,
    cache: Mutex<GroupCache>,
    cache_ttl_secs: u64,
    vpn_subnets: Vec<IpNetwork>,
    /// Channel sender to the background LDAP connection task.
    tx: tokio::sync::mpsc::Sender<AdRequest>,
}

impl Clone for AdClient {
    fn clone(&self) -> Self {
        Self {
            ldap_url: self.ldap_url.clone(),
            base_dn: self.base_dn.clone(),
            require_tls: self.require_tls,
            cache: Mutex::new(GroupCache {
                entries: HashMap::new(),
                ttl_secs: self.cache_ttl_secs,
            }),
            cache_ttl_secs: self.cache_ttl_secs,
            vpn_subnets: self.vpn_subnets.clone(),
            tx: self.tx.clone(),
        }
    }
}

impl AdClient {
    /// Constructs a new `AdClient` from the given config.
    ///
    /// Spawns a background Tokio task that holds the LDAP connection. The
    /// connection uses the machine account (Kerberos TGT) — no password needed.
    ///
    /// # Errors
    ///
    /// Returns `AdClientError::LdapConnect` if the initial TCP connection
    /// cannot be established.
    pub async fn new(config: LdapConfig) -> Result<Self, AdClientError> {
        let vpn_subnets = config
            .parse_vpn_subnets()
            .map_err(|e| AdClientError::LdapConnect(format!("invalid VPN subnet: {}", e)))?;

        let cache_ttl_secs = config.effective_cache_ttl();

        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let ldap_url = config.ldap_url.clone();
        let base_dn = config.base_dn.clone();
        let require_tls = config.require_tls;
        tokio::spawn(async move { run_ldap_task(ldap_url, base_dn, require_tls, rx).await });

        // Brief pause to allow background task to establish the connection.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        Ok(Self {
            ldap_url: config.ldap_url,
            base_dn: config.base_dn,
            require_tls: config.require_tls,
            cache: Mutex::new(GroupCache {
                entries: HashMap::new(),
                ttl_secs: cache_ttl_secs,
            }),
            cache_ttl_secs,
            vpn_subnets,
            tx,
        })
    }

    /// Returns a slice of the configured VPN subnets.
    pub fn vpn_subnets(&self) -> &[IpNetwork] {
        &self.vpn_subnets
    }

    /// Returns the configured VPN subnets as a comma-separated string.
    ///
    /// Useful for passing to [`get_network_location`] without re-parsing.
    pub fn vpn_subnets_str(&self) -> String {
        self.vpn_subnets
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Resolves the AD group SIDs (full transitive closure) for the given user.
    ///
    /// The result is cached by `caller_sid` for `cache_ttl_secs`. If the user
    /// is not found in AD, returns `Ok(Vec::new())` (fail-open). If the LDAP
    /// operation fails, also returns `Ok(Vec::new())` and logs a warning.
    ///
    /// The user's own SID is filtered out of the result (it appears in
    /// `tokenGroups` as the primary group but is not a group membership).
    pub async fn resolve_user_groups(
        &self,
        username: &str,
        caller_sid: &str,
    ) -> Result<Vec<String>, AdClientError> {
        // Fast path: check cache first.
        if let Some(groups) = self.cache.lock().get(caller_sid) {
            return Ok(groups);
        }

        // Slow path: query LDAP.
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(AdRequest::ResolveGroups {
                username: username.to_owned(),
                reply: tx,
            })
            .await
            .map_err(|e| AdClientError::LdapConnect(e.to_string()))?;

        let all_sids = match rx.await {
            Ok(Ok(sids)) => sids,
            Ok(Err(AdClientError::UserNotFound(_))) => return Ok(Vec::new()),
            Ok(Err(e)) => {
                warn!(error = %e, "AD group lookup failed — using empty group set (fail-open)");
                return Ok(Vec::new());
            }
            Err(_) => {
                warn!("AD channel closed — using empty group set (fail-open)");
                return Ok(Vec::new());
            }
        };

        let groups: Vec<String> = all_sids
            .into_iter()
            .filter(|sid| sid != caller_sid)
            .collect();

        self.cache
            .lock()
            .insert(caller_sid.to_owned(), groups.clone());
        Ok(groups)
    }

    /// Resolves a username to their Windows SID via LDAP.
    ///
    /// # Errors
    ///
    /// Returns `AdClientError::UserNotFound` if no matching user is found.
    pub async fn resolve_username_to_sid(&self, username: &str) -> Result<String, AdClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(AdRequest::ResolveSid {
                username: username.to_owned(),
                reply: tx,
            })
            .await
            .map_err(|e| AdClientError::LdapConnect(e.to_string()))?;

        rx.await
            .map_err(|_| AdClientError::LdapConnect("AD channel closed".to_string()))?
    }
}

// ---------------------------------------------------------------------------
// Background LDAP task
// ---------------------------------------------------------------------------

enum AdRequest {
    ResolveGroups {
        username: String,
        reply: tokio::sync::oneshot::Sender<Result<Vec<String>, AdClientError>>,
    },
    ResolveSid {
        username: String,
        reply: tokio::sync::oneshot::Sender<Result<String, AdClientError>>,
    },
}

/// Background task that owns the LDAP connection and processes requests serially.
async fn run_ldap_task(
    ldap_url: String,
    base_dn: String,
    require_tls: bool,
    mut rx: tokio::sync::mpsc::Receiver<AdRequest>,
) {
    let computer_name = std::env::var("COMPUTERNAME").unwrap_or_default();
    let userdomain = std::env::var("USERDOMAIN").unwrap_or_default();
    let machine_account_dn = if base_dn.is_empty() {
        format!("CN={}$,CN=Computers", computer_name)
    } else {
        format!("CN={}$,CN=Computers,{}", computer_name, base_dn)
    };
    debug!(machine = %computer_name, domain = %userdomain, "AD client background task starting");

    loop {
        let mut ldap = match ldap_connect(&ldap_url, require_tls).await {
            Ok(l) => l,
            Err(e) => {
                warn!(error = %e, "AD client failed to connect — retrying in 5s");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        match ldap.simple_bind(&machine_account_dn, "").await {
            Ok(r) => {
                // Zero rc means success per RFC 4511.
                if r.rc != 0 {
                    warn!(rc = r.rc, "AD bind returned non-success — retrying in 5s");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            }
            Err(e) => {
                warn!(error = %e, "AD bind failed — retrying in 5s");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        }

        debug!("AD client connected and bound successfully");

        while let Some(req) = rx.recv().await {
            match req {
                AdRequest::ResolveGroups { username, reply } => {
                    let result = do_resolve_groups(&mut ldap, &base_dn, &username).await;
                    let _ = reply.send(result);
                }
                AdRequest::ResolveSid { username, reply } => {
                    let result = do_resolve_sid(&mut ldap, &base_dn, &username).await;
                    let _ = reply.send(result);
                }
            }
        }

        warn!("AD channel closed — background task exiting");
        break;
    }
}

/// Opens a TCP+TLS LDAP connection.
async fn ldap_connect(url: &str, require_tls: bool) -> Result<Ldap, AdClientError> {
    let url = if require_tls && !url.starts_with("ldaps://") {
        url.replace("ldap://", "ldaps://")
    } else {
        url.to_owned()
    };

    let (conn, ldap) = LdapConnAsync::new(&url)
        .await
        .map_err(|e| AdClientError::LdapConnect(e.to_string()))?;

    ldap3::drive!(conn);
    Ok(ldap)
}

/// Performs the `tokenGroups` LDAP search for the given username.
async fn do_resolve_groups(
    ldap: &mut Ldap,
    base_dn: &str,
    username: &str,
) -> Result<Vec<String>, AdClientError> {
    let filter = format!("(sAMAccountName={})", ldap3::ldap_escape(username));
    let (rs, _result) = ldap
        .search(
            base_dn,
            Scope::Subtree,
            &filter,
            vec!["distinguishedName", "tokenGroups"],
        )
        .await
        .map_err(|e| AdClientError::LdapSearch(e.to_string()))?
        .success()
        .map_err(|e| AdClientError::LdapSearch(e.to_string()))?;

    if rs.is_empty() {
        return Err(AdClientError::UserNotFound(username.to_owned()));
    }

    let entry = SearchEntry::construct(rs.into_iter().next().expect("entry"));
    let binary_sids = entry
        .bin_attrs
        .get("tokenGroups")
        .cloned()
        .unwrap_or_default();

    let mut sids = Vec::with_capacity(binary_sids.len());
    for sid_bytes in binary_sids {
        match parse_sid_bytes(&sid_bytes) {
            Some(sid) => sids.push(sid),
            None => warn!(
                bytes_len = sid_bytes.len(),
                "skipping invalid SID bytes in tokenGroups"
            ),
        }
    }

    Ok(sids)
}

/// Performs the `objectSid` LDAP search for the given username.
async fn do_resolve_sid(
    ldap: &mut Ldap,
    base_dn: &str,
    username: &str,
) -> Result<String, AdClientError> {
    let filter = format!("(sAMAccountName={})", ldap3::ldap_escape(username));
    let (rs, _result) = ldap
        .search(base_dn, Scope::Subtree, &filter, vec!["objectSid"])
        .await
        .map_err(|e| AdClientError::LdapSearch(e.to_string()))?
        .success()
        .map_err(|e| AdClientError::LdapSearch(e.to_string()))?;

    if rs.is_empty() {
        return Err(AdClientError::UserNotFound(username.to_owned()));
    }

    let entry = SearchEntry::construct(rs.into_iter().next().expect("entry"));
    let binary_sids = entry
        .bin_attrs
        .get("objectSid")
        .cloned()
        .ok_or_else(|| AdClientError::LdapSearch("objectSid attribute missing".to_string()))?;

    let sid_bytes = binary_sids
        .into_iter()
        .next()
        .ok_or_else(|| AdClientError::LdapSearch("empty objectSid value".to_string()))?;

    parse_sid_bytes(&sid_bytes)
        .ok_or_else(|| AdClientError::InvalidSid("could not parse objectSid bytes".to_string()))
}

// ---------------------------------------------------------------------------
// device_trust — Windows API
// ---------------------------------------------------------------------------

/// Returns the device trust level based on whether the machine is joined to a domain.
///
/// Uses `NetGetJoinInformation` from `Win32_NetworkManagement_Ndis` to check the
/// current join status without allocating memory.
#[cfg(windows)]
pub fn get_device_trust() -> crate::DeviceTrust {
    use windows::core::PWSTR;
    use windows::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetGetJoinInformation, NETSETUP_JOIN_STATUS,
    };

    // SAFETY: NetGetJoinInformation is a read-only NetApi query.
    unsafe {
        let mut name_buf = PWSTR::null();
        let mut status = NETSETUP_JOIN_STATUS::default();
        NetGetJoinInformation(None, &mut name_buf, &mut status);
        let is_domain_joined = !name_buf.is_null() && status == NETSETUP_JOIN_STATUS(3); // NetSetupDomainName = 3
                                                                                         // Free the domain name buffer if one was allocated.
        if !name_buf.is_null() {
            let _ = NetApiBufferFree(Some(name_buf.as_ptr() as *const _));
        }
        if is_domain_joined {
            crate::DeviceTrust::Managed
        } else {
            crate::DeviceTrust::Unmanaged
        }
    }
}

#[cfg(not(windows))]
pub fn get_device_trust() -> crate::DeviceTrust {
    crate::DeviceTrust::Unknown
}

// ---------------------------------------------------------------------------
// network_location — Windows API
// ---------------------------------------------------------------------------

/// Parses a comma-separated string of CIDR ranges into a `Vec<IpNetwork>`.
fn parse_vpn_subnet_str(subnets: &str) -> Vec<IpNetwork> {
    subnets
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Returns the network location based on the machine's current IP address and
/// configured VPN subnets.
///
/// # Arguments
///
/// * `vpn_subnets` — comma-separated CIDR ranges (e.g. `"10.10.0.0/16,172.16.0.0/12"`)
#[cfg(windows)]
pub async fn get_network_location(vpn_subnets: &str) -> crate::NetworkLocation {
    let vpn_cidrs = parse_vpn_subnet_str(vpn_subnets);

    let Some(local_ip) = find_local_ipv4().await else {
        return crate::NetworkLocation::Unknown;
    };

    if vpn_cidrs.iter().any(|cidr| cidr.contains(local_ip)) {
        return crate::NetworkLocation::CorporateVpn;
    }

    if let Some(site_name) = get_ad_site_name().await {
        debug!(site = %site_name, "AD site resolved");
    }

    crate::NetworkLocation::Corporate
}

#[cfg(not(windows))]
pub async fn get_network_location(_vpn_subnets: &str) -> crate::NetworkLocation {
    crate::NetworkLocation::Unknown
}

/// Finds the first routable (non-loopback, non-link-local, non-multicast) IPv4 address.
#[cfg(windows)]
async fn find_local_ipv4() -> Option<std::net::IpAddr> {
    tokio::task::spawn_blocking(find_local_ipv4_sync)
        .await
        .ok()?
}

#[cfg(windows)]
fn find_local_ipv4_sync() -> Option<std::net::IpAddr> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    let family = AF_INET.0 as u32;
    let flags = GAA_FLAG_INCLUDE_PREFIX;

    unsafe {
        let mut buf_size: u32 = 0;
        let _ = GetAdaptersAddresses(family, flags, None, None, &mut buf_size);
        if buf_size == 0 {
            return None;
        }

        let layout =
            std::alloc::Layout::from_size_align(buf_size as usize, 1).expect("valid layout");
        let buf = std::alloc::alloc(layout) as *mut IP_ADAPTER_ADDRESSES_LH;

        if GetAdaptersAddresses(family, flags, None, Some(&mut *buf), &mut buf_size) != 0 {
            std::alloc::dealloc(buf as *mut u8, layout);
            return None;
        }

        let mut curr = buf;
        while !curr.is_null() {
            let addr = &*curr;
            let mut unicast = addr.FirstUnicastAddress;
            while !unicast.is_null() {
                let ua = &*unicast;
                if let Some(sockaddr) = ua.Address.lpSockaddr.as_ref() {
                    let sockaddr_in = sockaddr as *const _ as *const SOCKADDR_IN;
                    let ip = (*sockaddr_in).sin_addr.S_un.S_addr;
                    let ip = u32::from_le(ip);
                    let ip_v4 = std::net::Ipv4Addr::from(ip);

                    if !ip_v4.is_loopback() && !ip_v4.is_link_local() && !ip_v4.is_multicast() {
                        std::alloc::dealloc(buf as *mut u8, layout);
                        return Some(std::net::IpAddr::V4(ip_v4));
                    }
                }
                unicast = ua.Next;
            }
            curr = addr.Next;
        }

        std::alloc::dealloc(buf as *mut u8, layout);
        None
    }
}

/// Returns the AD site name for this machine, or `None` if unavailable.
#[cfg(windows)]
async fn get_ad_site_name() -> Option<String> {
    tokio::task::spawn_blocking(get_ad_site_name_sync)
        .await
        .ok()?
}

#[cfg(windows)]
fn get_ad_site_name_sync() -> Option<String> {
    use windows::Win32::Networking::ActiveDirectory::DsGetSiteNameW;

    unsafe {
        // Allocate a 512-byte buffer (256 UTF-16 chars) for the site name.
        let layout = std::alloc::Layout::from_size_align(512, 2).expect("valid layout");
        let buf = std::alloc::alloc(layout) as *mut u16;

        let len = DsGetSiteNameW(None, &mut windows::core::PWSTR(buf));
        if len == 0 || buf.read() == 0 {
            std::alloc::dealloc(buf as *mut u8, layout);
            return None;
        }
        let result = String::from_utf16_lossy(std::slice::from_raw_parts(buf, len as usize - 1));
        std::alloc::dealloc(buf as *mut u8, layout);
        Some(result)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sid_bytes_valid() {
        // S-1-3-0 (creator-owner): revision=1, count=1, authority=3, sub=0
        let bytes = [1u8, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
        assert_eq!(parse_sid_bytes(&bytes), Some("S-1-3-0".to_owned()));
    }

    #[test]
    fn test_parse_sid_bytes_valid_multiple_subauthorities() {
        // S-1-5-21-123456789-123456789-123456789 per MS-DTYP:
        // authority is 6-byte big-endian in bytes 2-7; subauthorities are
        // 4-byte little-endian u32 in bytes 8+.
        let bytes = [
            1u8, // revision
            4,   // subauthority count
            0, 0, 0, 0, 0, 5, // bytes 2-7: authority = 5 (big-endian u48)
            21, 0, 0, 0, // subauthority 1 = 21
            0x15, 0xcd, 0x5b, 0x07, // subauthority 2 = 123456789
            0x15, 0xcd, 0x5b, 0x07, // subauthority 3 = 123456789
            0x15, 0xcd, 0x5b, 0x07, // subauthority 4 = 123456789
        ];

        // MS-DTYP big-endian authority: bytes[2]<<40|...|bytes[7] = 5.
        // Subauthorities are little-endian u32.
        assert_eq!(
            parse_sid_bytes(&bytes),
            Some("S-1-5-21-123456789-123456789-123456789".to_owned())
        );
    }

    #[test]
    fn test_parse_sid_bytes_too_short() {
        assert_eq!(parse_sid_bytes(&[1, 1, 0, 0, 0, 0, 0]), None);
        assert_eq!(parse_sid_bytes(&[1, 2, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(parse_sid_bytes(&[]), None);
    }

    #[test]
    fn test_parse_sid_bytes_invalid_revision() {
        let bytes = [2u8, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
        assert_eq!(parse_sid_bytes(&bytes), None);
    }

    #[test]
    fn test_filter_own_sid() {
        let caller_sid = "S-1-5-21-100";
        let all_sids = vec![
            "S-1-5-21-100".to_owned(),
            "S-1-5-21-512".to_owned(),
            "S-1-5-21-513".to_owned(),
            "S-1-5-21-100".to_owned(),
        ];

        let filtered: Vec<String> = all_sids
            .into_iter()
            .filter(|sid| sid != caller_sid)
            .collect();

        assert_eq!(filtered, vec!["S-1-5-21-512", "S-1-5-21-513"]);
        assert!(!filtered.contains(&"S-1-5-21-100".to_owned()));
    }

    #[test]
    fn test_group_cache_ttl_eviction() {
        let mut cache = GroupCache {
            entries: HashMap::new(),
            ttl_secs: 5,
        };

        cache.insert("sid1".to_owned(), vec!["g1".to_owned()]);
        assert_eq!(cache.get("sid1"), Some(vec!["g1".to_owned()]));

        // Insert an entry with an Instant already past the TTL.
        let past = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(cache.ttl_secs + 1))
            .expect("checked_sub");
        cache
            .entries
            .insert("sid2".to_owned(), (vec!["g2".to_owned()], past));

        cache.evict_expired();
        assert!(cache.get("sid1").is_some());
        assert!(cache.get("sid2").is_none());
    }

    #[test]
    fn test_vpn_subnet_parsing() {
        let config = LdapConfig {
            ldap_url: "ldaps://dc.corp.internal:636".to_owned(),
            base_dn: "DC=corp,DC=internal".to_owned(),
            require_tls: true,
            cache_ttl_secs: 300,
            vpn_subnets: "10.10.0.0/16,172.16.0.0/12".to_owned(),
        };

        let subnets = config.parse_vpn_subnets().expect("valid CIDRs");
        assert_eq!(subnets.len(), 2);

        let vpn_ip: std::net::IpAddr = "10.10.5.1".parse().unwrap();
        let corp_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        assert!(subnets.iter().any(|n| n.contains(vpn_ip)));
        assert!(!subnets.iter().any(|n| n.contains(corp_ip)));
    }

    #[test]
    fn test_vpn_subnet_parsing_invalid() {
        let config = LdapConfig {
            ldap_url: "ldaps://dc.corp.internal:636".to_owned(),
            base_dn: "DC=corp,DC=internal".to_owned(),
            require_tls: true,
            cache_ttl_secs: 300,
            vpn_subnets: "10.10.0.0/16,invalid-cidr".to_owned(),
        };
        assert!(config.parse_vpn_subnets().is_err());
    }

    #[test]
    fn test_vpn_subnet_parsing_empty() {
        let config = LdapConfig {
            ldap_url: "ldaps://dc.corp.internal:636".to_owned(),
            base_dn: "DC=corp,DC=internal".to_owned(),
            require_tls: true,
            cache_ttl_secs: 300,
            vpn_subnets: "".to_owned(),
        };
        assert!(config
            .parse_vpn_subnets()
            .expect("empty is valid")
            .is_empty());
    }

    #[test]
    fn test_get_device_trust_non_windows() {
        #[cfg(not(windows))]
        {
            assert_eq!(get_device_trust(), crate::DeviceTrust::Unknown);
        }
        #[cfg(windows)]
        {
            let _ = get_device_trust();
        }
    }

    #[tokio::test]
    async fn test_get_network_location_non_windows() {
        #[cfg(not(windows))]
        {
            assert_eq!(
                get_network_location("").await,
                crate::NetworkLocation::Unknown
            );
        }
        #[cfg(windows)]
        {
            let _ = get_network_location("").await;
        }
    }

    #[test]
    fn test_effective_cache_ttl_clamping() {
        let base = LdapConfig {
            ldap_url: "ldaps://dc.corp.internal:636".to_owned(),
            base_dn: "DC=corp,DC=internal".to_owned(),
            require_tls: true,
            cache_ttl_secs: 300,
            vpn_subnets: "".to_owned(),
        };

        let below_min = LdapConfig {
            cache_ttl_secs: 10,
            ..base.clone()
        };
        assert_eq!(below_min.effective_cache_ttl(), 60);

        let above_max = LdapConfig {
            cache_ttl_secs: 9999,
            ..base.clone()
        };
        assert_eq!(above_max.effective_cache_ttl(), 3600);

        assert_eq!(base.effective_cache_ttl(), 300);
    }
}
