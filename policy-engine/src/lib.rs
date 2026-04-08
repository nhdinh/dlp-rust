//! `policy-engine` — ABAC Policy Decision Point (PDP).
//!
//! This crate implements the Policy Engine: the central component responsible for
//! evaluating ABAC policy rules and returning enforcement decisions (ALLOW/DENY)
//! for file operation requests submitted by dlp-agents.
//!
//! ## Architecture
//!
//! - [`engine`] — ABAC evaluation engine (first-match policy evaluation)
//! - [`policy_store`] — JSON file persistence with hot-reload support
//! - [`ad_client`] — Active Directory LDAP integration
//! - [`http_server`] — HTTPS REST API for policy evaluation (Evaluate endpoint)
//! - [`rest_api`] — CRUD REST API for policy management
//! - [`error`] — Shared error types

pub mod ad_client;
pub mod bind_registry;
pub mod engine;
pub mod error;
pub mod http_server;
pub mod policy_store;
pub mod rest_api;

pub use engine::AbacEngine;
pub use error::{AppError, PolicyEngineError};
