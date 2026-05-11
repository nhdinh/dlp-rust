//! `dlp-admin-cli` — Interactive DLP system administration TUI.
//!
//! Connects to `dlp-server`, authenticates, and presents a navigable
//! menu for managing policies, agent passwords, and system status.
//!
//! ## Usage
//!
//! ```text
//! dlp-admin-cli.exe [OPTIONS]
//!
//! OPTIONS:
//!   --connect <host:port>    DLP Server address (auto-detected if omitted)
//!   --help                   Show this help message
//! ```

mod app;
mod client;
mod engine;
mod event;
mod login;
mod registry;
mod screens;
mod tui;

use anyhow::Result;

/// Non-interactive admin operations exposed alongside the default TUI.
///
/// The TUI runs when no subcommand is supplied. A subcommand triggers a
/// scripted flow: login -> single REST call -> exit. The subcommand
/// surface is intentionally minimal — admin policy CRUD remains in the
/// TUI; this entry point exists for one-shot operations that an operator
/// might want to script or document in a runbook (Phase 47 Task 47-08).
enum Subcommand {
    /// `dlp-admin-cli rotate-secrets [--force-while-running]`
    RotateSecrets { force_while_running: bool },
    /// `dlp-admin-cli maintenance enter`
    MaintenanceEnter,
    /// `dlp-admin-cli maintenance exit`
    MaintenanceExit,
}

/// Parses the first positional argument (after the binary name and any
/// known global flags) into a [`Subcommand`].
///
/// Returns `Ok(None)` when no subcommand was supplied — the caller
/// should fall through to the default TUI entry point. Returns
/// `Err(msg)` when the subcommand is recognised but malformed (so we
/// can print a tailored help line instead of silently dropping the
/// user into the TUI).
fn parse_subcommand(args: &[String]) -> Result<Option<Subcommand>, String> {
    // Skip args we've already consumed (binary path + the
    // --connect <addr> pair, which lives anywhere on the line).
    let mut filtered: Vec<&String> = args.iter().skip(1).collect();
    let mut i = 0;
    while i < filtered.len() {
        if filtered[i] == "--connect" {
            // Drop --connect and its value.
            if i + 1 < filtered.len() {
                filtered.drain(i..=i + 1);
            } else {
                filtered.remove(i);
            }
        } else {
            i += 1;
        }
    }

    let first = match filtered.first() {
        Some(s) => s.as_str(),
        None => return Ok(None),
    };
    match first {
        "rotate-secrets" => {
            let force_while_running = filtered
                .iter()
                .any(|s| s.as_str() == "--force-while-running");
            Ok(Some(Subcommand::RotateSecrets {
                force_while_running,
            }))
        }
        "maintenance" => match filtered.get(1).map(|s| s.as_str()) {
            Some("enter") => Ok(Some(Subcommand::MaintenanceEnter)),
            Some("exit") => Ok(Some(Subcommand::MaintenanceExit)),
            Some(other) => Err(format!(
                "unknown maintenance subcommand: '{other}' (expected 'enter' or 'exit')"
            )),
            None => Err("maintenance subcommand requires 'enter' or 'exit'".to_string()),
        },
        _ => Ok(None),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help(args.first().map(|s| s.as_str()).unwrap_or("dlp-admin-cli"));
        return;
    }

    // Parse --connect <host:port> and set DLP_SERVER_URL env var.
    extract_connect_flag(&args);

    // Detect non-interactive subcommands (rotate-secrets, maintenance ...).
    // When one is present we bypass the TUI entirely and run a scripted
    // login -> REST-call -> exit flow.
    match parse_subcommand(&args) {
        Ok(Some(sub)) => {
            if let Err(e) = run_subcommand(sub) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            return;
        }
        Ok(None) => {} // fall through to TUI
        Err(msg) => {
            eprintln!("Error: {msg}");
            std::process::exit(2);
        }
    }

    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

/// Scripted entry point for non-interactive subcommands.
///
/// Builds the HTTP client, performs the line-based login flow (re-using
/// [`login::run`] so the password prompt is identical to the TUI's),
/// and dispatches to the relevant client method. Prints a one-line
/// human-readable summary on success.
fn run_subcommand(sub: Subcommand) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = login::run(&rt)?;
    match sub {
        Subcommand::RotateSecrets {
            force_while_running,
        } => {
            let report = rt.block_on(client.rotate_secrets(force_while_running))?;
            println!(
                "Rotated KEK from v{} to v{} - {} secrets re-encrypted across {} tables. \
                 Old key retired and retained in secret_kek_history for delayed-rollback decrypts.",
                report.old_version,
                report.new_version,
                report.rows_reencrypted,
                report.tables_rotated.len()
            );
            if !report.tables_rotated.is_empty() {
                println!("Tables rotated:");
                for t in &report.tables_rotated {
                    println!("  - {t}");
                }
            }
        }
        Subcommand::MaintenanceEnter => {
            rt.block_on(client.maintenance_enter())?;
            println!(
                "Maintenance mode ENABLED. The rotate-secrets endpoint will accept calls \
                 without --force-while-running until you run `dlp-admin-cli maintenance exit`."
            );
        }
        Subcommand::MaintenanceExit => {
            rt.block_on(client.maintenance_exit())?;
            println!("Maintenance mode DISABLED.");
        }
    }
    Ok(())
}

fn run() -> Result<()> {
    // Defensive: ensure raw mode is off in case a previous run crashed.
    let _ = crossterm::terminal::disable_raw_mode();

    // Install a panic hook so a crash inside the TUI still restores
    // the terminal (otherwise the user's shell becomes unusable).
    tui::install_panic_hook();

    // Build a tokio runtime (reused for all async calls).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    // Pre-TUI: health check + login (line-based I/O).
    let client = login::run(&rt)?;

    // Enter the ratatui TUI.
    let mut terminal = tui::setup()?;
    let result = run_tui(&mut terminal, client, rt);

    // Always restore the terminal, even on error.
    tui::restore(&mut terminal)?;

    result
}

/// Runs the main TUI event loop.
fn run_tui(
    terminal: &mut tui::Tui,
    client: client::EngineClient,
    rt: tokio::runtime::Runtime,
) -> Result<()> {
    let mut app = app::App::new(client, rt);

    loop {
        terminal.draw(|frame| screens::draw(&app, frame))?;

        if let Some(evt) = event::poll()? {
            screens::handle_event(&mut app, evt);
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

/// Extracts `--connect <host:port>` from the argument list and sets
/// `DLP_SERVER_URL` so that [`engine::resolve_engine_url`] picks it up.
fn extract_connect_flag(args: &[String]) {
    if let Some(pos) = args.iter().position(|a| a == "--connect") {
        if let Some(addr) = args.get(pos + 1) {
            let url = if addr.starts_with("http://") || addr.starts_with("https://") {
                addr.clone()
            } else {
                engine::addr_to_url(addr)
            };
            std::env::set_var("DLP_SERVER_URL", &url);
        }
    }
}

fn print_help(name: &str) {
    eprintln!(
        r#"dlp-admin-cli -- Interactive DLP administration TUI

USAGE:
    {name} [OPTIONS] [SUBCOMMAND]

SUBCOMMANDS (non-interactive, Phase 47 Task 47-08):
    rotate-secrets [--force-while-running]
        Rotate the KEK and re-encrypt every populated secret column.
        Requires `maintenance enter` first unless --force-while-running.
    maintenance enter
        Flip system_kv.maintenance_mode to "1" so rotate-secrets runs
        without --force-while-running.
    maintenance exit
        Flip system_kv.maintenance_mode back to "0".

OPTIONS:
    --connect <host:port>    DLP Server address (auto-detected if omitted)
    --help                   Show this help message

When no subcommand is given, the tool launches an interactive TUI for:
  - Agent password management
  - Policy CRUD operations
  - System status and agent monitoring

NAVIGATION (TUI):
    Up/Down     Navigate menus
    Enter       Select / confirm
    Esc         Go back / cancel
    Q           Quit (from main menu)

CONNECTION AUTO-DETECTION:
    If --connect is not specified, the CLI auto-detects the server:
      1. DLP_SERVER_URL env var
      2. BIND_ADDR from registry (HKLM\SOFTWARE\DLP\PolicyEngine)
      3. Probe local ports: 9090, 8443, 8080
      4. Default: http://127.0.0.1:9090
"#
    );
}
