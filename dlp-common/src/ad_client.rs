//! Active Directory / LDAP client for ABAC attribute resolution (Phase 7).
//!
//! Full implementation delivered in Plan 01 of Phase 7. This stub provides
//! enough types for `dlp-server` (Plan 02) to compile without depending on the
//! ad_client logic itself.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Re-exports from abac (dlp-common)
// ---------------------------------------------------------------------------
pub use crate::abac::{DeviceTrust, NetworkLocation};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// LDAP connection configuration persisted in `dlp-server`'s SQLite DB
/// and pushed to agents via the agent-config endpoint.
///
/// Mirrors the columns of the `ldap_config` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LdapConfig {
    /// LDAP URL, e.g. `ldaps://dc.corp.internal:636`.
    pub ldap_url: String,
    /// Search base DN, e.g. `DC=corp,DC=internal`.
    pub base_dn: String,
    /// Whether LDAPS/TLS is required (plaintext connections are rejected when true).
    pub require_tls: bool,
    /// Group membership cache TTL in seconds (min 60, max 3600, default 300).
    pub cache_ttl_secs: u64,
    /// Comma-separated VPN subnet CIDRs for location detection.
    pub vpn_subnets: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during AD/LDAP operations.
#[derive(Debug, Error)]
pub enum AdClientError {
    #[error("LDAP connection failed: {0}")]
    Connection(String),

    #[error("LDAP bind failed: {0}")]
    Bind(String),

    #[error("LDAP search failed: {0}")]
    Search(String),

    #[error("user not found in AD: {0}")]
    UserNotFound(String),

    #[error("invalid SID data: {0}")]
    InvalidSid(String),

    #[error("Windows API error: {0}")]
    WindowsApi(String),

    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Group cache
// ---------------------------------------------------------------------------

/// TTL cache for resolved group memberships keyed by caller's SID.
#[derive(Debug)]
struct GroupCache {
    /// SID → (group SIDs, expiry instant).
    entries: std::collections::HashMap<String, (Vec<String>, std::time::Instant)>,
    ttl: Duration,
}

impl Default for GroupCache {
    fn default() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            ttl: Duration::from_secs(300),
        }
    }
}

impl GroupCache {
    fn new(ttl_secs: u64) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            ttl: Duration::from_secs(ttl_secs.max(1)),
        }
    }

    fn get(&self, sid: &str) -> Option<Vec<String>> {
        let entry = self.entries.get(sid)?;
        if entry.1.elapsed() < self.ttl {
            Some(entry.0.clone())
        } else {
            None
        }
    }

    fn insert(&mut self, sid: String, groups: Vec<String>) {
        self.entries.insert(sid, (groups, std::time::Instant::now()));
    }

    fn evict_expired(&mut self) {
        self.entries.retain(|_, (_, inst)| inst.elapsed() < self.ttl);
    }
}

// ---------------------------------------------------------------------------
// AdClient
// ---------------------------------------------------------------------------

/// AD/LDAP client backed by an `ldap3` connection pool.
///
/// Provides ABAC attribute resolution by querying Active Directory for:
/// - User group memberships (via `tokenGroups`)
/// - Device trust level (via `NetIsPartOfDomain` — local API, no network)
/// - Network location (via AD site + VPN subnet detection)
#[derive(Clone)]
pub struct AdClient {
    config: LdapConfig,
}

impl AdClient {
    /// Constructs an `AdClient` from the given LDAP configuration.
    ///
    /// Does NOT connect immediately — connections are established lazily
    /// on first use.
    pub fn new(config: LdapConfig) -> Self {
        let cache_ttl_secs = config.cache_ttl_secs.max(60).min(3600);
        let _ = GroupCache::new(cache_ttl_secs);
        Self { config }
    }

    /// Returns the configured LDAP URL.
    #[inline]
    pub fn ldap_url(&self) -> &str {
        &self.config.ldap_url
    }

    /// Returns the configured search base DN.
    #[inline]
    pub fn base_dn(&self) -> &str {
        &self.config.base_dn
    }

    /// Returns the configured VPN subnets string.
    #[inline]
    pub fn vpn_subnets(&self) -> &str {
        &self.config.vpn_subnets
    }
}

// ---------------------------------------------------------------------------
// Stub implementations (replaced by full implementation in Plan 01)
// ---------------------------------------------------------------------------

/// Resolves the local machine's device trust level.
///
/// Full implementation uses `NetIsPartOfDomain()` Win32 API.
/// Stub always returns `Unknown`.
pub fn get_device_trust() -> DeviceTrust {
    DeviceTrust::Unknown
}

/// Resolves the local machine's network location.
///
/// Full implementation uses AD site lookup + VPN subnet matching.
/// Stub always returns `Unknown`.
pub async fn get_network_location(_vpn_subnets: &[ipnetwork::IpNetwork]) -> NetworkLocation {
    NetworkLocation::Unknown
}
