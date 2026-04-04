//! Policy management commands — CRUD operations via the Policy Engine REST API.

use anyhow::{Context, Result};

use crate::client;
use crate::client::EngineClient;

/// Load and parse a JSON policy file.
fn load_policy_file(path: &str) -> Result<dlp_common::abac::Policy> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read policy file '{}'", path))?;
    serde_json::from_str(&content)
        .with_context(|| format!("'{}' is not valid JSON matching the policy schema", path))
}

/// Pretty-print a single policy.
fn print_policy(policy: &dlp_common::abac::Policy) {
    println!("  {:-^60}", "");
    println!("  ID       : {}", policy.id);
    println!("  Name     : {}", policy.name);
    if let Some(desc) = &policy.description {
        println!("  Desc     : {}", desc);
    }
    println!("  Priority : {}", policy.priority);
    println!("  Enabled  : {}", policy.enabled);
    println!("  Version  : {}", policy.version);
    println!("  Action   : {:?}", policy.action);
    println!("  Conditions ({}):", policy.conditions.len());
    for cond in &policy.conditions {
        println!("    - {:?}", cond);
    }
    println!("  {:-^60}", "");
}

/// `dlp-admin policy list` — list all policies.
pub fn list() -> Result<()> {
    let engine = EngineClient::from_env()?;
    let policies = client::block_on(engine.get::<Vec<dlp_common::abac::Policy>>("/policies"))?;

    if policies.is_empty() {
        println!("No policies defined.");
        return Ok(());
    }

    println!("{} policy(s) found:\n", policies.len());
    for p in &policies {
        let status = if p.enabled { "[ENABLED] " } else { "[DISABLED]" };
        println!("{} {}  (v{}, priority {})", status, p.id, p.version, p.priority);
        println!("   Name: {}", p.name);
        if let Some(desc) = &p.description {
            let preview = if desc.len() > 70 {
                format!("{}...", &desc[..70])
            } else {
                desc.clone()
            };
            println!("   {}", preview);
        }
        println!();
    }
    Ok(())
}

/// `dlp-admin policy get <id>` — retrieve a single policy by ID.
pub fn get(id: &str) -> Result<()> {
    let engine = EngineClient::from_env()?;
    let policy = client::block_on(
        engine.get::<dlp_common::abac::Policy>(&format!("/policies/{id}"))
    )?;
    println!("Policy '{}':\n", id);
    print_policy(&policy);
    Ok(())
}

/// `dlp-admin policy create <file>` — create a policy from a JSON file.
pub fn create_from_file(file: &str) -> Result<()> {
    let policy: dlp_common::abac::Policy = load_policy_file(file)?;

    let engine = EngineClient::from_env()?;
    let created = client::block_on(
        engine.post::<dlp_common::abac::Policy, _>("/policies", &policy)
    )?;

    println!("Policy '{}' created (v{}).", created.id, created.version);
    Ok(())
}

/// `dlp-admin policy update <id> <file>` — update an existing policy from a JSON file.
pub fn update_from_file(id: &str, file: &str) -> Result<()> {
    let policy: dlp_common::abac::Policy = load_policy_file(file)?;

    let engine = EngineClient::from_env()?;
    let updated = client::block_on(
        engine.put::<dlp_common::abac::Policy, _>(&format!("/policies/{id}"), &policy)
    )?;

    println!("Policy '{}' updated (now v{}).", updated.id, updated.version);
    Ok(())
}

/// `dlp-admin policy delete <id>` — delete a policy by ID.
pub fn delete(id: &str) -> Result<()> {
    let engine = EngineClient::from_env()?;
    client::block_on(engine.delete(&format!("/policies/{id}")))?;
    println!("Policy '{}' deleted.", id);
    Ok(())
}
