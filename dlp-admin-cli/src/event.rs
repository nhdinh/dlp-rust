//! Crossterm event polling.
//!
//! Thin wrapper around `crossterm::event` that converts raw terminal
//! events into the [`AppEvent`] enum consumed by the main loop.

use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyEvent};

/// Events consumed by the main TUI loop.
pub enum AppEvent {
    /// A keyboard event.
    Key(KeyEvent),
    /// A periodic tick (used for status-bar auto-clear, etc.).
    Tick,
}

/// Polls for the next event with a 250 ms timeout.
///
/// Returns `Ok(None)` if no event arrived within the timeout.
pub fn poll() -> Result<Option<AppEvent>> {
    if event::poll(Duration::from_millis(250))? {
        if let Event::Key(key) = event::read()? {
            return Ok(Some(AppEvent::Key(key)));
        }
    }
    Ok(Some(AppEvent::Tick))
}
