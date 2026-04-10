//! Terminal setup and teardown for the ratatui TUI.
//!
//! Enters crossterm raw mode and alternate screen on setup; restores
//! the original terminal state on teardown.  A panic hook guarantees
//! cleanup even on unexpected crashes.

use std::io::{self, Stdout};

use anyhow::Result;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

/// The concrete terminal type used throughout the application.
pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Installs a panic hook that restores the terminal before printing
/// the panic message.  Without this, a panic inside the TUI leaves
/// the terminal in raw mode and the user cannot type.
pub fn install_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // Best-effort restore — ignore errors since we are already panicking.
        let _ = disable_raw_mode();
        let _ = crossterm::execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(panic_info);
    }));
}

/// Enters raw mode and the alternate screen, returning a ready terminal.
pub fn setup() -> Result<Tui> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

/// Restores the terminal to its original state.
///
/// Must be called before the process exits (normal or error path).
pub fn restore(terminal: &mut Tui) -> Result<()> {
    disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
