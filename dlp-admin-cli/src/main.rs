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

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help(args.first().map(|s| s.as_str()).unwrap_or("dlp-admin-cli"));
        return;
    }

    // Parse --connect <host:port> and set DLP_SERVER_URL env var.
    extract_connect_flag(&args);

    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
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
    {name} [OPTIONS]

OPTIONS:
    --connect <host:port>    DLP Server address (auto-detected if omitted)
    --help                   Show this help message

The tool connects to dlp-server, authenticates with admin credentials,
and presents a navigable menu for:
  - Agent password management
  - Policy CRUD operations
  - System status and agent monitoring

NAVIGATION:
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
