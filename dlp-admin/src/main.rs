//! `dlp-admin.exe` — DLP system administration CLI.
//!
//! ## Security notes
//!
//! - `set-password` requires Administrator privileges (HKLM write).
//! - Policy management commands require a configured Policy Engine URL.
//!
//! ## Commands
//!
//! ```text
//! dlp-admin.exe set-password              Set or update the dlp-admin password
//! dlp-admin.exe verify-password           Verify a password against the stored hash
//! dlp-admin.exe policy list              List all policies
//! dlp-admin.exe policy get <id>         Get a policy by ID
//! dlp-admin.exe policy create <file>    Create a policy from JSON
//! dlp-admin.exe policy update <id> <file>  Update a policy from JSON
//! dlp-admin.exe policy delete <id>       Delete a policy
//! dlp-admin.exe status                   Check Policy Engine health
//! ```

mod client;
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
    let rc = run(&args);

    if let Err(e) = rc {
        error!("{e}");
        std::process::exit(1);
    }
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
                    anyhow::anyhow!("Usage: dlp-admin policy get <policy-id>")
                })?;
                policy::get(id)
            }
            Some("create") => {
                let file = args.get(3).ok_or_else(|| {
                    anyhow::anyhow!("Usage: dlp-admin policy create <file.json>")
                })?;
                policy::create_from_file(file)
            }
            Some("update") => {
                let id = args.get(3).ok_or_else(|| {
                    anyhow::anyhow!("Usage: dlp-admin policy update <policy-id> <file.json>")
                })?;
                let file = args.get(4).ok_or_else(|| {
                    anyhow::anyhow!("Usage: dlp-admin policy update <policy-id> <file.json>")
                })?;
                policy::update_from_file(id, file)
            }
            Some("delete") => {
                let id = args.get(3).ok_or_else(|| {
                    anyhow::anyhow!("Usage: dlp-admin policy delete <policy-id>")
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
                    "Usage: dlp-admin policy <list|get|create|update|delete> [args]"
                );
            }
        },

        // ── System status ─────────────────────────────────────────────────────
        Some("status") => {
            let url = env::var("DLP_POLICY_ENGINE_URL")
                .unwrap_or_else(|_| DEFAULT_ENGINE_URL.to_string());
            client::block_on(status(&url))
        }

        // ── Interactive TUI ──────────────────────────────────────────────────
        Some("interactive") | Some("ui") => {
            ui::run();
            Ok(())
        }

        // ── Help ─────────────────────────────────────────────────────────────
        _ => {
            print_help(args.first().map(|s| s.as_str()).unwrap_or("dlp-admin"));
            Ok(())
        }
    }
}

fn print_help(name: &str) {
    eprintln!(
        r#"dlp-admin — DLP system administration CLI

USAGE:
    {name} <command> [arguments]

PASSWORD MANAGEMENT:
    {name} set-password          Set or update the dlp-admin password
    {name} verify-password       Verify a password against the stored hash

POLICY MANAGEMENT:
    {name} policy list                       List all policies
    {name} policy get <id>                    Get a policy by ID
    {name} policy create <file.json>          Create a policy from JSON
    {name} policy update <id> <file.json>    Update a policy from JSON
    {name} policy delete <id>                Delete a policy

SYSTEM:
    {name} status                           Check Policy Engine health
    {name} interactive                       Interactive TUI (menu-driven)

ENVIRONMENT VARIABLES:
    DLP_POLICY_ENGINE_URL   Policy Engine URL (default: {DEFAULT_ENGINE_URL})
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
