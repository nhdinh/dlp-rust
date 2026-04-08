//! `dlp-admin-cli.exe` — DLP system administration CLI.
//!
//! ## Security notes
//!
//! - `set-password` requires Administrator privileges (HKLM write).
//! - Policy management commands require a configured Policy Engine URL.
//!
//! ## Commands
//!
//! ```text
//! dlp-admin-cli.exe set-password                      Set/update dlp-admin password
//! dlp-admin-cli.exe verify-password                   Verify password hash
//! dlp-admin-cli.exe policy list                       List all policies
//! dlp-admin-cli.exe policy get <id>                   Get a policy by ID
//! dlp-admin-cli.exe policy create <file>              Create from JSON
//! dlp-admin-cli.exe policy update <id> <file>         Update from JSON
//! dlp-admin-cli.exe policy delete <id>                Delete a policy
//! dlp-admin-cli.exe engine get-bind-addr              Show BIND_ADDR
//! dlp-admin-cli.exe engine set-bind-addr <host:port>  Set BIND_ADDR
//! dlp-admin-cli.exe status                            Check engine health
//! ```

mod client;
mod engine;
mod password;
mod policy;
mod registry;
mod ui;

use anyhow::Result;
use std::env;
use tracing::error;

const DEFAULT_ENGINE_URL: &str = "https://localhost:8443";

fn main() {
    // Initialize tracing — log level controlled by RUST_LOG env var.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args: Vec<String> = env::args().collect();

    // Parse --connect <addr:port> from anywhere in the args and set it
    // as DLP_POLICY_ENGINE_URL so resolve_engine_url() picks it up.
    let args = extract_connect_flag(args);

    let rc = run(&args);

    if let Err(e) = rc {
        error!("{e}");
        std::process::exit(1);
    }
}

/// Extracts `--connect <addr:port>` from the argument list.
///
/// If found, sets `DLP_POLICY_ENGINE_URL` so that
/// [`engine::resolve_engine_url`] uses it as the highest-priority
/// source.  Returns the remaining arguments with the flag removed.
fn extract_connect_flag(mut args: Vec<String>) -> Vec<String> {
    if let Some(pos) = args.iter().position(|a| a == "--connect") {
        if let Some(addr) = args.get(pos + 1).cloned() {
            // Normalise: if it looks like host:port, prepend http(s).
            let url = if addr.starts_with("http://")
                || addr.starts_with("https://")
            {
                addr
            } else {
                engine::addr_to_url(&addr)
            };
            env::set_var("DLP_POLICY_ENGINE_URL", &url);
            // Remove --connect and the value from the arg list.
            args.remove(pos + 1);
            args.remove(pos);
        }
    }
    args
}

fn run(args: &[String]) -> Result<()> {
    match args.get(1).map(|s| s.as_str()) {
        // ── Password management ──────────────────────────────────────────────
        Some("set-password") => password::set_password(),
        Some("verify-password") => password::verify_password(),

        // ── Policy management ──────────────────────────────────────────────────
        Some("policy") => match args.get(2).map(|s| s.as_str()) {
            Some("list") => policy::list(),
            Some("get") => {
                let id = args.get(3).ok_or_else(|| {
                    anyhow::anyhow!("Usage: dlp-admin-cli policy get <policy-id>")
                })?;
                policy::get(id)
            }
            Some("create") => {
                let file = args.get(3).ok_or_else(|| {
                    anyhow::anyhow!("Usage: dlp-admin-cli policy create <file.json>")
                })?;
                policy::create_from_file(file)
            }
            Some("update") => {
                let id = args.get(3).ok_or_else(|| {
                    anyhow::anyhow!("Usage: dlp-admin-cli policy update <policy-id> <file.json>")
                })?;
                let file = args.get(4).ok_or_else(|| {
                    anyhow::anyhow!("Usage: dlp-admin-cli policy update <policy-id> <file.json>")
                })?;
                policy::update_from_file(id, file)
            }
            Some("delete") => {
                let id = args.get(3).ok_or_else(|| {
                    anyhow::anyhow!("Usage: dlp-admin-cli policy delete <policy-id>")
                })?;
                policy::delete(id)
            }
            Some(cmd) => {
                anyhow::bail!(
                    "Unknown policy subcommand: {cmd}\n\
                     Valid: list, get, create, update, delete"
                );
            }
            None => {
                anyhow::bail!(
                    "Usage: dlp-admin-cli policy <list|get|create|update|delete> [args]"
                );
            }
        },

        // ── Engine configuration ─────────────────────────────────────────────
        Some("engine") => match args.get(2).map(|s| s.as_str()) {
            Some("get-bind-addr") => engine::get_bind_addr(),
            Some("set-bind-addr") => {
                let addr = args.get(3).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Usage: dlp-admin-cli engine set-bind-addr <host:port>"
                    )
                })?;
                engine::set_bind_addr(addr)
            }
            Some(cmd) => {
                anyhow::bail!(
                    "Unknown engine subcommand: {cmd}\n\
                     Valid: get-bind-addr, set-bind-addr"
                );
            }
            None => {
                anyhow::bail!(
                    "Usage: dlp-admin-cli engine <get-bind-addr|set-bind-addr> [args]"
                );
            }
        },

        // ── System status ─────────────────────────────────────────────────────
        Some("status") => {
            let url = engine::resolve_engine_url();
            println!("Connecting to: {url}");
            client::block_on(status(&url))
        }

        // ── Interactive TUI ──────────────────────────────────────────────────
        Some("interactive") | Some("ui") => {
            ui::run();
            Ok(())
        }

        // ── Help ─────────────────────────────────────────────────────────────
        _ => {
            print_help(args.first().map(|s| s.as_str()).unwrap_or("dlp-admin-cli"));
            Ok(())
        }
    }
}

fn print_help(name: &str) {
    eprintln!(
        r#"dlp-admin-cli -- DLP system administration CLI

USAGE:
    {name} <command> [arguments]

PASSWORD MANAGEMENT:
    {name} set-password                      Set or update the dlp-admin password
    {name} verify-password                   Verify a password against the stored hash

POLICY MANAGEMENT:
    {name} policy list                       List all policies
    {name} policy get <id>                   Get a policy by ID
    {name} policy create <file.json>         Create a policy from JSON
    {name} policy update <id> <file.json>    Update a policy from JSON
    {name} policy delete <id>                Delete a policy

ENGINE CONFIGURATION:
    {name} engine get-bind-addr              Show configured BIND_ADDR
    {name} engine set-bind-addr <host:port>  Set BIND_ADDR (requires admin)

SYSTEM:
    {name} status                            Check Policy Engine health
    {name} interactive                       Interactive TUI (menu-driven)

GLOBAL OPTIONS:
    --connect <host:port>                    Connect to a specific engine address

CONNECTION AUTO-DETECTION:
    The CLI automatically finds the Policy Engine when running on the same
    machine. Resolution order:
      1. DLP_POLICY_ENGINE_URL env var (explicit override)
      2. BIND_ADDR from registry (HKLM\SOFTWARE\DLP\PolicyEngine)
      3. Probe local ports: 8443, 9443, 8080
      4. Default: {DEFAULT_ENGINE_URL}

ENVIRONMENT VARIABLES:
    DLP_POLICY_ENGINE_URL   Policy Engine URL (overrides auto-detection)
    DLP_ENGINE_CERT_PATH    Path to client certificate (mTLS)
    DLP_ENGINE_KEY_PATH     Path to client key (mTLS)
    DLP_ENGINE_CA_PATH      Path to CA certificate (default: system trust store)
    RUST_LOG                Tracing log level (default: info)
"#
    );
}

// ─── Status command ───────────────────────────────────────────────────────────

async fn status(base_url: &str) -> Result<()> {
    use reqwest::Client;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let health_url = format!("{}/health", base_url.trim_end_matches('/'));
    let ready_url = format!("{}/ready", base_url.trim_end_matches('/'));

    // Check /health
    match client.get(&health_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("[OK]   Policy Engine health: {}", health_url);
        }
        Ok(resp) => {
            anyhow::bail!(
                "[FAIL] Policy Engine health returned {}: {}",
                resp.status(),
                health_url
            );
        }
        Err(e) => {
            anyhow::bail!(
                "[FAIL] Cannot connect to Policy Engine at {}: {e}",
                health_url
            );
        }
    }

    // Check /ready
    match client.get(&ready_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("[OK]   Policy Engine ready:  {}", ready_url);
        }
        Ok(resp) => {
            println!(
                "[WARN] Policy Engine not ready ({}): {}",
                resp.status().as_u16(),
                ready_url
            );
        }
        Err(e) => {
            println!("[WARN] Policy Engine readiness check failed: {e}");
        }
    }

    Ok(())
}
