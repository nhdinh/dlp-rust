//! Pre-TUI login flow.
//!
//! Runs before the ratatui alternate screen is entered.  Uses simple
//! line-based I/O with crossterm for password masking.

use std::io::Write;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal;

use crate::client::EngineClient;

/// Maximum number of login attempts before giving up.
const MAX_ATTEMPTS: u32 = 3;

/// Runs the full pre-TUI login sequence:
///
/// 1. Build the HTTP client (auto-detect or `--connect` override).
/// 2. Health-check the server.
/// 3. Prompt for username + password (up to 3 attempts).
/// 4. Return the authenticated client.
pub fn run(rt: &tokio::runtime::Runtime) -> Result<EngineClient> {
    let mut client = EngineClient::from_env()?;
    let base_url = client.base_url().to_string();

    println!("Connecting to dlp-server at {base_url}...");
    rt.block_on(client.check_health())?;
    println!("Server is healthy.\n");

    for attempt in 1..=MAX_ATTEMPTS {
        let username = prompt_line("Username: ")?;
        let password = prompt_password("Password: ")?;

        match rt.block_on(client.login(&username, &password)) {
            Ok(()) => {
                println!("Authenticated as '{username}'.\n");
                return Ok(client);
            }
            Err(e) => {
                eprintln!("Login failed: {e}");
                if attempt < MAX_ATTEMPTS {
                    eprintln!(
                        "Attempt {attempt}/{MAX_ATTEMPTS}. Try again.\n"
                    );
                }
            }
        }
    }

    anyhow::bail!("maximum login attempts exceeded")
}

/// Reads a line of text from stdin (with echo).
fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Reads a password from stdin with crossterm raw mode (masked with `*`).
fn prompt_password(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;

    terminal::enable_raw_mode()?;
    let result = read_masked_input();
    terminal::disable_raw_mode()?;

    // Print a newline after the masked input.
    println!();

    result
}

/// Reads characters in raw mode, echoing `*` for each, until Enter.
fn read_masked_input() -> Result<String> {
    let mut input = String::new();
    loop {
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Enter => break,
                KeyCode::Backspace => {
                    if input.pop().is_some() {
                        // Erase the last `*` on screen.
                        print!("\x08 \x08");
                        std::io::stdout().flush()?;
                    }
                }
                KeyCode::Char(c) => {
                    input.push(c);
                    print!("*");
                    std::io::stdout().flush()?;
                }
                KeyCode::Esc => {
                    anyhow::bail!("login cancelled");
                }
                _ => {}
            }
        }
    }
    Ok(input)
}
