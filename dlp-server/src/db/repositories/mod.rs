//! Repository modules -- one per database entity.
//!
//! All raw SQL is encapsulated within these modules. No `conn.execute()`
//! or `conn.query_row()` should appear outside `db/repositories/`.

pub mod admin_users;
pub mod agent_config;
pub mod agents;
pub mod alert_router_config;
pub mod audit_events;
pub mod credentials;
pub mod exceptions;
pub mod ldap_config;
pub mod policies;
pub mod siem_config;

pub use admin_users::AdminUserRepository;
pub use agent_config::AgentConfigRepository;
pub use agents::AgentRepository;
pub use alert_router_config::AlertRouterConfigRepository;
pub use audit_events::{AuditEventRepository, AuditEventRow};
pub use credentials::CredentialsRepository;
pub use exceptions::ExceptionRepository;
pub use ldap_config::LdapConfigRepository;
pub use policies::PolicyRepository;
pub use siem_config::SiemConfigRepository;
