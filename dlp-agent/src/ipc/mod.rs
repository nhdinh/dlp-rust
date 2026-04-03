//! Named-pipe IPC servers (T-31–T-34).
//!
//! Three named pipes connect the DLP Agent service to the UI process:
//!
//! | Pipe | Name                     | Direction   | Purpose                            |
//! |------|--------------------------|-------------|------------------------------------|
//! | P1   | `\\.\pipe\DLPCommand`   | Bidirectional | BLOCK_NOTIFY, OVERRIDE_REQUEST, CLIPBOARD_READ, PASSWORD_DIALOG |
//! | P2   | `\\.\pipe\DLPEventAgent2UI` | Agent → UI | TOAST, STATUS_UPDATE, HEALTH_PING, UI_RESPAWN, UI_CLOSING_SEQUENCE |
//! | P3   | `\\.\pipe\DLPEventUI2Agent` | UI → Agent | HEALTH_PONG, UI_READY, UI_CLOSING |
//!
//! All pipes use JSON messages over a synchronous byte stream.
//! The `windows` crate's named-pipe APIs (`CreateNamedPipeW`, `ConnectNamedPipe`,
//! `ReadFile`, `WriteFile`) are used directly via `spawn_blocking` so they do not
//! block the async runtime.

pub mod frame;
pub mod messages;
pub mod pipe1;
pub mod pipe2;
pub mod pipe3;
pub mod pipe_security;
pub mod server;

pub use server::start_all;
