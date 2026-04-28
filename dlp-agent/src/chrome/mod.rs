//! Chrome Enterprise Content Analysis Agent module.
//!
//! Implements the Chrome Content Analysis SDK protocol over a named pipe.
//! Chrome sends protobuf-framed scan requests; the agent evaluates origin
//! trust and returns allow/block verdicts.

pub mod cache;
pub mod frame;
pub mod handler;
pub mod proto;

#[cfg(windows)]
pub mod registry;
