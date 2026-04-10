//! TUI screen rendering and event handling.

mod dispatch;
mod render;

pub use dispatch::handle_event;
pub use render::draw;
