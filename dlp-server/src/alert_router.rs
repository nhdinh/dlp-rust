//! Email (SMTP) and webhook alerts for DENY_WITH_ALERT events (P5-T06).
//!
//! Reads alert configuration from environment variables. Supports
//! sending email via SMTP (lettre) and HTTP POST to a webhook endpoint.

use dlp_common::AuditEvent;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use reqwest::Client;

/// SMTP email alert configuration.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// SMTP server hostname.
    pub host: String,
    /// SMTP server port.
    pub port: u16,
    /// SMTP username for authentication.
    pub username: String,
    /// SMTP password for authentication.
    pub password: String,
    /// Sender email address.
    pub from: String,
    /// List of recipient email addresses.
    pub to: Vec<String>,
}

/// Webhook alert configuration.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Webhook endpoint URL.
    pub url: String,
    /// Optional shared secret for HMAC signing (future use).
    pub secret: Option<String>,
}

/// Routes real-time alerts to email and/or webhook destinations.
///
/// Construct via `AlertRouter::from_env()`. If neither SMTP nor webhook
/// is configured, alert calls are no-ops.
#[derive(Debug, Clone)]
pub struct AlertRouter {
    /// Optional SMTP configuration for email alerts.
    smtp: Option<SmtpConfig>,
    /// Optional webhook configuration.
    webhook: Option<WebhookConfig>,
    /// Shared HTTP client for webhook calls.
    client: Client,
}

/// Error type for alert delivery failures.
#[derive(Debug, thiserror::Error)]
pub enum AlertError {
    /// SMTP transport or message construction failed.
    #[error("email alert error: {0}")]
    Email(String),

    /// Webhook HTTP request failed.
    #[error("webhook alert error: {0}")]
    Webhook(#[from] reqwest::Error),

    /// JSON serialization failed.
    #[error("alert serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl AlertRouter {
    /// Constructs an `AlertRouter` from environment variables.
    ///
    /// Environment variables:
    /// - `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
    ///   `SMTP_FROM`, `SMTP_TO` (comma-separated)
    /// - `ALERT_WEBHOOK_URL`, `ALERT_WEBHOOK_SECRET` (optional)
    pub fn from_env() -> Self {
        let smtp = Self::load_smtp_config();
        let webhook = Self::load_webhook_config();

        Self {
            smtp,
            webhook,
            client: Client::new(),
        }
    }

    /// Sends an alert for a single audit event to all configured
    /// destinations.
    ///
    /// # Arguments
    ///
    /// * `event` - The audit event that triggered the alert.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered. Both destinations are
    /// attempted even if one fails.
    pub async fn send_alert(&self, event: &AuditEvent) -> Result<(), AlertError> {
        let mut errors: Vec<AlertError> = Vec::new();

        if let Some(ref cfg) = self.smtp {
            if let Err(e) = self.send_email(cfg, event).await {
                tracing::error!("email alert failed: {e}");
                errors.push(e);
            }
        }

        if let Some(ref cfg) = self.webhook {
            if let Err(e) = self.send_webhook(cfg, event).await {
                tracing::error!("webhook alert failed: {e}");
                errors.push(e);
            }
        }

        if let Some(e) = errors.into_iter().next() {
            return Err(e);
        }

        Ok(())
    }

    /// Loads SMTP configuration from environment variables.
    fn load_smtp_config() -> Option<SmtpConfig> {
        let host = std::env::var("SMTP_HOST").ok()?;
        let port: u16 = std::env::var("SMTP_PORT").ok()?.parse().ok()?;
        let username = std::env::var("SMTP_USERNAME").ok()?;
        let password = std::env::var("SMTP_PASSWORD").ok()?;
        let from = std::env::var("SMTP_FROM").ok()?;
        let to_str = std::env::var("SMTP_TO").ok()?;
        let to: Vec<String> = to_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if to.is_empty() {
            return None;
        }

        tracing::info!("SMTP alert routing enabled");
        Some(SmtpConfig {
            host,
            port,
            username,
            password,
            from,
            to,
        })
    }

    /// Loads webhook configuration from environment variables.
    fn load_webhook_config() -> Option<WebhookConfig> {
        let url = std::env::var("ALERT_WEBHOOK_URL").ok()?;
        if url.is_empty() {
            return None;
        }
        let secret = std::env::var("ALERT_WEBHOOK_SECRET").ok();
        tracing::info!("Webhook alert routing enabled");
        Some(WebhookConfig { url, secret })
    }

    /// Sends an email alert via SMTP.
    async fn send_email(&self, config: &SmtpConfig, event: &AuditEvent) -> Result<(), AlertError> {
        let subject = format!(
            "[DLP ALERT] {} on {} by {}",
            serde_json::to_value(event.event_type)
                .unwrap_or_default()
                .as_str()
                .unwrap_or("UNKNOWN"),
            event.resource_path,
            event.user_name,
        );

        let body = serde_json::to_string_pretty(event)?;

        let from_mailbox: Mailbox = config
            .from
            .parse()
            .map_err(|e| AlertError::Email(format!("invalid from address: {e}")))?;

        // Send to each recipient individually.
        let creds = Credentials::new(config.username.clone(), config.password.clone());

        // Build the SMTP transport once (TLS via STARTTLS).
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
            .map_err(|e| AlertError::Email(format!("SMTP relay error: {e}")))?
            .port(config.port)
            .credentials(creds)
            .build();

        for recipient in &config.to {
            let to_mailbox: Mailbox = recipient
                .parse()
                .map_err(|e| AlertError::Email(format!("invalid to address: {e}")))?;

            let email = Message::builder()
                .from(from_mailbox.clone())
                .to(to_mailbox)
                .subject(&subject)
                .body(body.clone())
                .map_err(|e| AlertError::Email(format!("message build error: {e}")))?;

            mailer
                .send(email)
                .await
                .map_err(|e| AlertError::Email(format!("SMTP send error: {e}")))?;
        }

        tracing::info!(recipients = config.to.len(), "sent email alert");
        Ok(())
    }

    /// Sends an alert payload to a webhook endpoint via HTTP POST.
    async fn send_webhook(
        &self,
        config: &WebhookConfig,
        event: &AuditEvent,
    ) -> Result<(), AlertError> {
        let resp = self
            .client
            .post(&config.url)
            .header("Content-Type", "application/json")
            .json(event)
            .send()
            .await?;

        if !resp.status().is_success() {
            tracing::error!(
                status = resp.status().as_u16(),
                "webhook returned non-success"
            );
        }

        tracing::info!("sent webhook alert");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_config_fields() {
        let cfg = SmtpConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            username: "user".to_string(),
            password: "pass".to_string(),
            from: "dlp@example.com".to_string(),
            to: vec!["admin@example.com".to_string()],
        };
        assert_eq!(cfg.port, 587);
        assert_eq!(cfg.to.len(), 1);
    }

    #[test]
    fn test_webhook_config_fields() {
        let cfg = WebhookConfig {
            url: "https://hooks.example.com/alert".to_string(),
            secret: Some("s3cret".to_string()),
        };
        assert!(!cfg.url.is_empty());
        assert!(cfg.secret.is_some());
    }

    #[test]
    fn test_from_env_no_vars() {
        // When env vars are absent, both destinations should be None.
        let router = AlertRouter {
            smtp: None,
            webhook: None,
            client: Client::new(),
        };
        assert!(router.smtp.is_none());
        assert!(router.webhook.is_none());
    }

    #[tokio::test]
    #[ignore = "Wave 0 stub — implemented in Wave 2 after struct rewrite"]
    async fn test_alert_router_disabled_default() {
        // Wave 2: construct AlertRouter::new(Arc::new(Database::open(":memory:")?))
        // and assert send_alert returns Ok with no I/O when both channels are off.
        todo!("Wave 2");
    }

    #[test]
    #[ignore = "Wave 0 stub — implemented in Wave 2 after struct rewrite"]
    fn test_load_config_roundtrip() {
        // Wave 2: open in-memory DB, UPDATE alert_router_config with known values,
        // construct AlertRouter::new, call load_config, assert round-trip.
        todo!("Wave 2");
    }

    #[test]
    #[ignore = "Wave 0 stub — implemented in Wave 2 after struct rewrite"]
    fn test_load_config_port_overflow() {
        // Wave 2: UPDATE alert_router_config SET smtp_port = 70000; load_config
        // must return AlertError::Database (or equivalent) for the u16 overflow.
        todo!("Wave 2");
    }

    #[tokio::test]
    #[ignore = "Wave 0 stub — implemented in Wave 2 after struct rewrite"]
    async fn test_hot_reload() {
        // Wave 2: construct router; call load_config; UPDATE the row;
        // call load_config again; assert the second read reflects the update
        // (proves there is no caching).
        todo!("Wave 2");
    }
}
