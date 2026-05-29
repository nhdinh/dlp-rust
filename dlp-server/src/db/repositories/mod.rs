//! Repository modules -- one per database entity.
//!
//! All raw SQL is encapsulated within these modules. No `conn.execute()`
//! or `conn.query_row()` should appear outside `db/repositories/`.

pub mod admin_users;
pub mod agent_config;
pub mod agents;
pub mod alert_router_config;
pub mod allowlist;
pub mod approvals;
pub mod audit_events;
pub mod bypass_alerts;
pub mod credentials;
pub mod device_registry;
pub mod disk_registry;
pub mod exceptions;
pub mod jwt_secret;
pub mod labels;
pub mod ldap_config;
pub mod managed_origins;
pub mod policies;
pub mod protected_paths;
pub mod secret_kek;
pub mod siem_config;
pub mod syslog_config;
pub mod syslog_queue;
pub mod system_kv;

pub use admin_users::AdminUserRepository;
pub use agent_config::{AgentConfigOverrideRow, AgentConfigRepository, GlobalAgentConfigRow};
pub use agents::AgentRepository;
pub use alert_router_config::{AlertRouterConfigRepository, AlertRouterConfigRow};
pub use allowlist::{
    AllowlistAuditRepository, AllowlistAuditRow, AllowlistEntryRow, AllowlistRepository,
};
pub use approvals::{ApprovalRepository, ApprovalRow, ApprovalUpsertRow};
pub use audit_events::{AuditEventRepository, AuditEventRow};
pub use bypass_alerts::{
    BypassAlertFilter, BypassAlertInsertRow, BypassAlertRow, BypassAlertsRepository,
};
pub use credentials::CredentialsRepository;
pub use device_registry::{DeviceRegistryRepository, DeviceRegistryRow};
pub use disk_registry::{DiskRegistryRepository, DiskRegistryRow};
pub use exceptions::ExceptionRepository;
pub use ldap_config::{LdapConfigRepository, LdapConfigRow};
pub use managed_origins::{ManagedOriginRow, ManagedOriginsRepository};
pub use policies::{PolicyRepository, PolicyRow, PolicyUpdateRow};
pub use protected_paths::{ProtectedPathAceRow, ProtectedPathRow, ProtectedPathsRepository};
pub use siem_config::{SiemConfigRepository, SiemConfigRow};
pub use syslog_config::{
    validate_facility_code, validate_severity, SyslogConfigRepository, SyslogConfigRow,
};
pub use syslog_queue::{QueuedEvent, SyslogQueueRepository};
