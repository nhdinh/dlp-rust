//! Policy Engine connection management.
//!
//! Provides auto-detection of the Policy Engine bind address when the CLI
//! and engine run on the same machine, plus commands to query and update
//! the configured `BIND_ADDR` in the Windows registry.
//!
//! ## Registry layout
//!
//! ```text
//! HKLM\SOFTWARE\DLP\PolicyEngine
//!   BindAddr  REG_SZ  "127.0.0.1:8443"
//! ```
//!
//! ## Auto-detection strategy
//!
//! 1. Check `DLP_POLICY_ENGINE_URL` env var (explicit override).
//! 2. Read `BIND_ADDR` from the registry (same-machine deployment).
//! 3. Probe well-known local ports: 8443, 9443, 8080.
//! 4. Fall back to the compiled default (`https://localhost:8443`).

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::registry;

/// Registry key path for Policy Engine settings.
const ENGINE_REG_KEY: &str = r"SOFTWARE\DLP\PolicyEngine";

/// Registry value name for the bind address.
const BIND_ADDR_VALUE: &str = "BindAddr";

/// Well-known ports to probe when auto-detecting.
const PROBE_PORTS: &[u16] = &[8443, 9443, 8080];

/// Probe timeout per port.
const PROBE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(1500);

// ─── Public commands ─────────────────────────────────────────────────────

/// Reads and prints the current BIND_ADDR from the registry.
///
/// # Errors
///
/// Returns an error if the registry key does not exist or cannot be read.
pub fn get_bind_addr() -> Result<()> {
    match registry::read_registry_string(ENGINE_REG_KEY, BIND_ADDR_VALUE) {
        Ok(addr) if !addr.is_empty() => {
            println!("Policy Engine BIND_ADDR: {addr}");
            println!("  (from HKLM\\{ENGINE_REG_KEY}\\{BIND_ADDR_VALUE})");
            Ok(())
        }
        Ok(_) => {
            println!("Policy Engine BIND_ADDR is not configured in the registry.");
            println!(
                "  Set it with: dlp-admin-cli engine set-bind-addr <host:port>"
            );
            Ok(())
        }
        Err(e) => {
            println!("Policy Engine BIND_ADDR is not configured.");
            println!(
                "  Registry key HKLM\\{ENGINE_REG_KEY} not found: {e}"
            );
            println!(
                "  Set it with: dlp-admin-cli engine set-bind-addr <host:port>"
            );
            Ok(())
        }
    }
}

/// Writes a new BIND_ADDR to the registry.
///
/// Validates the address format before writing.
///
/// # Arguments
///
/// * `addr` - The bind address in `host:port` format (e.g., `127.0.0.1:8443`).
///
/// # Errors
///
/// Returns an error if the address format is invalid or registry write fails.
pub fn set_bind_addr(addr: &str) -> Result<()> {
    // Validate the address format.
    addr.parse::<std::net::SocketAddr>()
        .with_context(|| format!("invalid address format: '{addr}' (expected host:port, e.g. 127.0.0.1:8443)"))?;

    registry::write_registry_string(ENGINE_REG_KEY, BIND_ADDR_VALUE, addr)
        .context("failed to write BIND_ADDR to registry (run as Administrator)")?;

    println!("Policy Engine BIND_ADDR set to: {addr}");
    println!("  (stored in HKLM\\{ENGINE_REG_KEY}\\{BIND_ADDR_VALUE})");
    println!("  Restart the Policy Engine for this to take effect.");
    Ok(())
}

// ─── Auto-detection ──────────────────────────────────────────────────────

/// Resolves the Policy Engine URL using a multi-step strategy.
///
/// 1. `DLP_POLICY_ENGINE_URL` env var (explicit override, highest priority).
/// 2. `BIND_ADDR` from the Windows registry (same-machine deployment).
/// 3. Probe well-known local ports (8443, 9443, 8080).
/// 4. Compiled default (`https://localhost:8443`).
///
/// # Returns
///
/// The resolved base URL (e.g., `http://127.0.0.1:8443`).
pub fn resolve_engine_url() -> String {
    // Step 1: explicit env var.
    if let Ok(url) = std::env::var("DLP_POLICY_ENGINE_URL") {
        if !url.is_empty() {
            info!(url = %url, "Using DLP_POLICY_ENGINE_URL env var");
            return url;
        }
    }

    // Step 2: registry BIND_ADDR.
    if let Ok(addr) = registry::read_registry_string(
        ENGINE_REG_KEY,
        BIND_ADDR_VALUE,
    ) {
        if !addr.is_empty() {
            let url = addr_to_url(&addr);
            debug!(addr = %addr, url = %url, "Read BIND_ADDR from registry");
            // Probe to confirm the engine is actually listening.
            if probe_health(&url) {
                info!(
                    url = %url,
                    "Auto-detected Policy Engine from registry BIND_ADDR"
                );
                return url;
            }
            warn!(
                url = %url,
                "Registry BIND_ADDR set but engine not responding"
            );
        }
    }

    // Step 3: probe well-known local ports.
    for port in PROBE_PORTS {
        let url = format!("http://127.0.0.1:{port}");
        debug!(url = %url, "Probing local port");
        if probe_health(&url) {
            info!(
                url = %url,
                "Auto-detected Policy Engine on local port {port}"
            );
            return url;
        }
    }

    // Step 4: fall back to default.
    let default = crate::DEFAULT_ENGINE_URL.to_string();
    debug!(url = %default, "Using default engine URL");
    default
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

/// Probes the `/health` endpoint of a Policy Engine URL.
///
/// Returns `true` if the engine responds with HTTP 200 within the timeout.
fn probe_health(base_url: &str) -> bool {
    let url = format!("{}/health", base_url.trim_end_matches('/'));

    // Use a blocking reqwest client since this runs before the async
    // runtime is started.
    let client = match reqwest::blocking::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    match client.get(&url).send() {
        Ok(resp) => {
            let ok = resp.status().is_success();
            if ok {
                debug!(url = %url, "Health probe succeeded");
            }
            ok
        }
        Err(e) => {
            debug!(url = %url, error = %e, "Health probe failed");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addr_to_url_loopback() {
        assert_eq!(
            addr_to_url("127.0.0.1:8443"),
            "http://127.0.0.1:8443"
        );
    }

    #[test]
    fn test_addr_to_url_localhost() {
        assert_eq!(
            addr_to_url("localhost:9000"),
            "http://localhost:9000"
        );
    }

    #[test]
    fn test_addr_to_url_any() {
        assert_eq!(
            addr_to_url("0.0.0.0:8443"),
            "http://0.0.0.0:8443"
        );
    }

    #[test]
    fn test_addr_to_url_remote() {
        assert_eq!(
            addr_to_url("10.0.1.50:8443"),
            "https://10.0.1.50:8443"
        );
    }

    #[test]
    fn test_probe_health_unreachable() {
        // Port 1 is almost certainly not listening.
        assert!(!probe_health("http://127.0.0.1:1"));
    }
}
