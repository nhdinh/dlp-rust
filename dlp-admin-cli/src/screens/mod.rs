//! TUI screen rendering and event handling.

pub mod allowlist;
mod approvals;
pub mod audit_integrity;
mod bypass_alerts;
mod cloud_config;
mod diagnostic_list;
mod dispatch;
mod labels;
mod print_config;
mod protected_paths;
mod render;
mod self_health_dashboard;
mod syslog_config;
mod usb_enforcement;

pub use dispatch::handle_event;
pub use render::draw;
