//! DLP Server auto-detection.
//!
//! Resolves the DLP Server URL when the CLI and server run on the same
//! machine.  Falls back to a compiled default if detection fails.
//!
//! ## Auto-detection strategy
//!
//! 1. Check `DLP_SERVER_URL` env var (explicit override / `--connect`).
//! 2. Read `BIND_ADDR` from the registry (same-machine deployment).
//! 3. Probe well-known local ports: 9090, 8443, 8080.
//! 4. Fall back to the compiled default (`http://127.0.0.1:9090`).

use tracing::{debug, info, warn};

use crate::registry;

/// Default DLP Server URL.
const DEFAULT_URL: &str = "http://127.0.0.1:9090";

/// Registry key path for DLP Server settings.
const ENGINE_REG_KEY: &str = r"SOFTWARE\DLP\PolicyEngine";

/// Registry value name for the bind address.
const BIND_ADDR_VALUE: &str = "BindAddr";

/// Well-known ports to probe when auto-detecting.
const PROBE_PORTS: &[u16] = &[9090, 8443, 8080];

/// Probe timeout per port.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1500);

/// Resolves the DLP Server URL using a multi-step strategy.
///
/// 1. `DLP_SERVER_URL` env var (explicit override, highest priority).
/// 2. `BIND_ADDR` from the Windows registry (same-machine deployment).
/// 3. Probe well-known local ports (9090, 8443, 8080).
/// 4. Compiled default (`http://127.0.0.1:9090`).
pub fn resolve_engine_url() -> String {
    // Step 1: explicit env var.
    if let Ok(url) = std::env::var("DLP_SERVER_URL") {
        if !url.is_empty() {
            info!(url = %url, "using DLP_SERVER_URL env var");
            return url;
        }
    }

    // Step 2: registry BIND_ADDR.
    if let Ok(addr) = registry::read_registry_string(ENGINE_REG_KEY, BIND_ADDR_VALUE) {
        if !addr.is_empty() {
            let url = addr_to_url(&addr);
            debug!(addr = %addr, url = %url, "read BIND_ADDR from registry");
            if probe_health(&url) {
                info!(url = %url, "auto-detected DLP Server from registry");
                return url;
            }
            warn!(url = %url, "registry BIND_ADDR set but server not responding");
        }
    }

    // Step 3: probe well-known local ports.
    for port in PROBE_PORTS {
        let url = format!("http://127.0.0.1:{port}");
        debug!(url = %url, "probing local port");
        if probe_health(&url) {
            info!(url = %url, "auto-detected DLP Server on port {port}");
            return url;
        }
    }

    // Step 4: fall back to default.
    debug!(url = %DEFAULT_URL, "using default server URL");
    DEFAULT_URL.to_string()
}

/// Converts a `host:port` bind address to an HTTP URL.
///
/// Uses `http://` for loopback addresses and `https://` for others.
pub fn addr_to_url(addr: &str) -> String {
    let scheme = if addr.starts_with("127.")
        || addr.starts_with("localhost")
        || addr.starts_with("0.0.0.0")
    {
        "http"
    } else {
        "https"
    };
    format!("{scheme}://{addr}")
}

/// Probes the `/health` endpoint of a DLP Server URL.
///
/// Returns `true` if the server responds with HTTP 200 within the timeout.
fn probe_health(base_url: &str) -> bool {
    let url = format!("{}/health", base_url.trim_end_matches('/'));

    let client = match reqwest::blocking::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    match client.get(&url).send() {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addr_to_url_loopback() {
        assert_eq!(addr_to_url("127.0.0.1:9090"), "http://127.0.0.1:9090");
    }

    #[test]
    fn test_addr_to_url_localhost() {
        assert_eq!(addr_to_url("localhost:9000"), "http://localhost:9000");
    }

    #[test]
    fn test_addr_to_url_any() {
        assert_eq!(addr_to_url("0.0.0.0:9090"), "http://0.0.0.0:9090");
    }

    #[test]
    fn test_addr_to_url_remote() {
        assert_eq!(addr_to_url("10.0.1.50:9090"), "https://10.0.1.50:9090");
    }

    #[test]
    fn test_probe_health_unreachable() {
        assert!(!probe_health("http://127.0.0.1:1"));
    }
}
