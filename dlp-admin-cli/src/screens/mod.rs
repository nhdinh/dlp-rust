//! TUI screen rendering and event handling.

pub mod allowlist;
mod approvals;
mod cloud_config;
mod dispatch;
mod labels;
mod print_config;
mod render;
mod syslog_config;
mod usb_enforcement;

pub use dispatch::handle_event;
pub use render::draw;
