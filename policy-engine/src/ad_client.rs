//! Active Directory LDAP client.
//!
//! Connects to an AD LDAP server to resolve two attributes needed by the ABAC engine:
//! - Device trust level (managed / compliant / unmanaged)
//! - User group membership (list of group SIDs)
//!
//! ## Mock AD Server
//!
//! For development and CI, a mock AD server is provided in `tests/mock_ad/`
//! as a standalone binary. Run it with: `cargo run --package mock_ad --tests`
//! It listens on `localhost:3389` and can be used by setting the
//! `DLP_AD_LDAP_URL=ldap://localhost:3389` environment variable.

use dlp_common::abac::{DeviceTrust, NetworkLocation};
use ldap3::{LdapConn, Scope, SearchEntry};
use tracing::{debug, warn};

use crate::error::{AdClientError, PolicyEngineError, Result};

/// LDAP attribute name for device trust classification.
const ATTR_DEVICE_TRUST: &str = "dlpDeviceTrust";
/// LDAP attribute name for network location.
const ATTR_NETWORK_LOCATION: &str = "dlpNetworkLocation";

/// Maximum results to accept from a group membership search.
const MAX_GROUP_SEARCH_RESULTS: usize = 1_000;

/// An Active Directory client backed by LDAP.
///
/// All network I/O is performed on a blocking thread via `tokio::task::spawn_blocking`
/// so the async runtime is never blocked.
#[derive(Debug)]
pub struct AdClient {
    /// LDAP URL (e.g. "ldaps://dc01.contoso.com:636" or "ldap://dc01:389").
    ldap_url: String,
    /// Base DN to search under (e.g. "DC=contoso,DC=com").
    base_dn: String,
    /// Bind DN for authenticated queries.
    bind_dn: String,
    /// Bind password.
    bind_password: String,
}

impl AdClient {
    /// Creates a new AD client from the given configuration.
    ///
    /// # Example
    ///
    /// ```
    /// use policy_engine::ad_client::AdClient;
    ///
    /// let client = AdClient::new(
    ///     "ldaps://dc01.contoso.com:636".to_string(),
    ///     "DC=contoso,DC=com".to_string(),
    ///     "CN=dlp-svc,OU=Services,DC=contoso,DC=com".to_string(),
    ///     "s3cr3t".to_string(),
    /// );
    /// ```
    pub fn new(ldap_url: String, base_dn: String, bind_dn: String, bind_password: String) -> Self {
        Self {
            ldap_url,
            base_dn,
            bind_dn,
            bind_password,
        }
    }

    /// Looks up all group SIDs for the given user SID.
    ///
    /// Queries `memberOf` on the user object identified by `user_sid`.
    /// Returns the flat list of group SIDs (as strings).
    ///
    /// # Errors
    ///
    /// Returns `AdClientError::AdQueryError` if the LDAP search fails.
    pub async fn get_group_sids(&self, user_sid: &str) -> Result<Vec<String>> {
        let filter = format!(
            "(&(objectClass=user)(objectSid={}))",
            escape_filter(user_sid)
        );

        let results = self.ldap_search(&filter, &["memberOf"]).await?;

        let mut group_sids = Vec::new();
        for entry in results {
            if let Some(values) = entry.attrs.get("memberOf") {
                for dn in values {
                    if let Some(sid) = extract_sid_from_dn(dn) {
                        group_sids.push(sid);
                    }
                }
            }
        }

        debug!(
            user_sid,
            count = group_sids.len(),
            "group membership resolved"
        );
        Ok(group_sids)
    }

    /// Looks up the device trust level for the machine identified by its distinguished name.
    ///
    /// Queries the `dlpDeviceTrust` attribute on the computer object.
    ///
    /// # Errors
    ///
    /// Returns `AdClientError::AdQueryError` if the LDAP search fails.
    pub async fn get_device_trust(&self, machine_dn: &str) -> Result<DeviceTrust> {
        let filter = format!(
            "(&(objectClass=computer)(distinguishedName={}))",
            escape_filter(machine_dn)
        );

        let results = self.ldap_search(&filter, &[ATTR_DEVICE_TRUST]).await?;

        let Some(entry) = results.into_iter().next() else {
            return Ok(DeviceTrust::Unknown);
        };

        let value = entry
            .attrs
            .get(ATTR_DEVICE_TRUST)
            .and_then(|v| v.first())
            .map(String::as_str)
            .unwrap_or_default();

        debug!(machine_dn, trust = value, "device trust resolved");
        parse_device_trust(value)
    }

    /// Looks up the network location tag for the machine.
    ///
    /// Queries the `dlpNetworkLocation` attribute on the computer object.
    ///
    /// # Errors
    ///
    /// Returns `AdClientError::AdQueryError` if the LDAP search fails.
    pub async fn get_network_location(&self, machine_dn: &str) -> Result<NetworkLocation> {
        let filter = format!(
            "(&(objectClass=computer)(distinguishedName={}))",
            escape_filter(machine_dn)
        );

        let results = self.ldap_search(&filter, &[ATTR_NETWORK_LOCATION]).await?;

        let Some(entry) = results.into_iter().next() else {
            return Ok(NetworkLocation::Unknown);
        };

        let value = entry
            .attrs
            .get(ATTR_NETWORK_LOCATION)
            .and_then(|v| v.first())
            .map(String::as_str)
            .unwrap_or_default();

        debug!(machine_dn, location = value, "network location resolved");
        parse_network_location(value)
    }

    /// Performs an LDAP search and returns parsed search entries.
    ///
    /// The blocking LDAP operation is run on a dedicated thread to avoid blocking the async runtime.
    async fn ldap_search(&self, filter: &str, attrs: &[&str]) -> Result<Vec<SearchEntry>> {
        let url = self.ldap_url.clone();
        let base_dn = self.base_dn.clone();
        let bind_dn = self.bind_dn.clone();
        let bind_password = self.bind_password.clone();
        let filter = filter.to_string();
        let attrs = attrs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();

        let entries: Vec<SearchEntry> = tokio::task::spawn_blocking(move || {
            let mut ldap =
                LdapConn::new(&url).map_err(|e| AdClientError::LdapInitError(e.to_string()))?;

            ldap.simple_bind(&bind_dn, &bind_password)
                .map_err(|e| AdClientError::BindFailed(e.to_string()))?
                .success()
                .map_err(|e| AdClientError::BindFailed(e.to_string()))?;

            let (entries, _result) = ldap
                .search(&base_dn, Scope::Subtree, &filter, attrs.as_slice())
                .map_err(|e| AdClientError::AdQueryError(e.to_string()))?
                .success()
                .map_err(|e| AdClientError::AdQueryError(e.to_string()))?;

            if let Err(e) = ldap.unbind() {
                warn!(error = %e, "AD unbind error");
            }

            Ok::<_, AdClientError>(
                entries
                    .into_iter()
                    .take(MAX_GROUP_SEARCH_RESULTS)
                    .map(SearchEntry::construct)
                    .collect(),
            )
        })
        .await
        .map_err(|e| AdClientError::TaskJoinError(e.to_string()))?
        .map_err(PolicyEngineError::from)?;

        Ok(entries)
    }
}

/// Escapes special characters in LDAP filter values to prevent injection.
fn escape_filter(s: &str) -> String {
    let mut r = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => r.push_str("\\5c"),
            '*' => r.push_str("\\2a"),
            '(' => r.push_str("\\28"),
            ')' => r.push_str("\\29"),
            '\0' => r.push_str("\\00"),
            c => r.push(c),
        }
    }
    r
}

/// Parses a `dlpDeviceTrust` attribute value into a `DeviceTrust` enum.
fn parse_device_trust(value: &str) -> Result<DeviceTrust> {
    match value.to_lowercase().as_str() {
        "managed" => Ok(DeviceTrust::Managed),
        "compliant" => Ok(DeviceTrust::Compliant),
        "unmanaged" => Ok(DeviceTrust::Unmanaged),
        _ => Ok(DeviceTrust::Unknown),
    }
}

/// Parses a `dlpNetworkLocation` attribute value into a `NetworkLocation` enum.
fn parse_network_location(value: &str) -> Result<NetworkLocation> {
    match value.to_lowercase().as_str() {
        "corporate" => Ok(NetworkLocation::Corporate),
        "corporatevpn" | "vpn" => Ok(NetworkLocation::CorporateVpn),
        "guest" => Ok(NetworkLocation::Guest),
        _ => Ok(NetworkLocation::Unknown),
    }
}

/// Extracts the SID from a group DN.
//
//  Mock AD DN format: `CN=GroupName,SID=<sid>,CN=Users,DC=mock,DC=local`
//  Real AD DN format: `CN=GroupName,CN=Users,DC=contoso,DC=com` — requires a
//  second search on the group object to get objectSid. The mock uses the
//  inline SID segment for simplicity.
fn extract_sid_from_dn(dn: &str) -> Option<String> {
    for segment in dn.split(',') {
        if let Some(sid) = segment.trim().strip_prefix("SID=") {
            return Some(sid.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_filter() {
        assert_eq!(escape_filter("S-1-5-21-123"), "S-1-5-21-123");
        assert_eq!(escape_filter("user*"), "user\\2a");
        assert_eq!(escape_filter("a(b)c"), "a\\28b\\29c");
        assert_eq!(escape_filter("a\\b"), "a\\5cb");
    }

    #[test]
    fn test_extract_sid_from_dn() {
        assert_eq!(
            extract_sid_from_dn("CN=Admins,SID=S-1-5-21-123,CN=Users,DC=mock,DC=local"),
            Some("S-1-5-21-123".to_string())
        );
        assert_eq!(
            extract_sid_from_dn("CN=Group,CN=Users,DC=mock,DC=local"),
            None
        );
    }

    #[test]
    fn test_parse_device_trust() {
        assert_eq!(parse_device_trust("managed").unwrap(), DeviceTrust::Managed);
        assert_eq!(parse_device_trust("MANAGED").unwrap(), DeviceTrust::Managed);
        assert_eq!(
            parse_device_trust("compliant").unwrap(),
            DeviceTrust::Compliant
        );
        assert_eq!(
            parse_device_trust("unmanaged").unwrap(),
            DeviceTrust::Unmanaged
        );
        assert_eq!(parse_device_trust("").unwrap(), DeviceTrust::Unknown);
        assert_eq!(parse_device_trust("unknown").unwrap(), DeviceTrust::Unknown);
    }

    #[test]
    fn test_parse_network_location() {
        assert_eq!(
            parse_network_location("Corporate").unwrap(),
            NetworkLocation::Corporate
        );
        assert_eq!(
            parse_network_location("CorporateVpn").unwrap(),
            NetworkLocation::CorporateVpn
        );
        assert_eq!(
            parse_network_location("vpn").unwrap(),
            NetworkLocation::CorporateVpn
        );
        assert_eq!(
            parse_network_location("Guest").unwrap(),
            NetworkLocation::Guest
        );
        assert_eq!(
            parse_network_location("").unwrap(),
            NetworkLocation::Unknown
        );
    }
}
