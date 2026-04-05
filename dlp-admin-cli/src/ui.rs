//! Interactive TUI for dlp-admin-cli.
//
//! Uses the standard Windows console API — no external TUI crate required.

use std::io::{self, Write};

use crate::client;

/// A menu item rendered in the interactive UI.
struct MenuItem {
    label: &'static str,
    description: &'static str,
}

/// Draws a full-screen console menu and returns the 1-based index of the selected item.
fn interactive_menu(_title: &str, items: &[MenuItem]) -> io::Result<usize> {
    loop {
        print!("\x1B[2J\x1B[H"); // clear screen
        print!("\x1B[3J");        // clear scrollback
        io::stdout().flush()?;

        println!("╔══════════════════════════════════════════════════════════╗");
        println!("║           dlp-admin-cli — Interactive Mode                 ║");
        println!("╚══════════════════════════════════════════════════════════╝");
        println!();

        for (i, item) in items.iter().enumerate() {
            println!("  [{}] {}", i + 1, item.label);
            println!("      {}", item.description);
            println!();
        }

        println!("  [0] Exit");
        println!();
        print!("Select an option [0-{}]: ", items.len());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        match input.parse::<usize>() {
            Ok(0) => {
                println!("Goodbye.");
                std::process::exit(0);
            }
            Ok(n) if n >= 1 && n <= items.len() => {
                return Ok(n - 1);
            }
            _ => {
                eprintln!("Invalid choice. Press Enter to try again...");
                let _ = io::stdin().read_line(&mut String::new());
            }
        }
    }
}

/// Formats an optional field for display, replacing None with a placeholder.
fn opt_field(label: &str, value: &Option<String>) {
    match value {
        Some(v) => println!("  {:.<15} {}", label, v),
        None => println!("  {:.<15} (none)", label),
    }
}

/// Formats a bool field as YES/NO.
fn bool_field(label: &str, value: bool) {
    println!("  {:.<15} {}", label, if value { "YES" } else { "NO" });
}

/// Prints an error and waits for Enter.
fn pause_on_error(msg: &str) {
    eprintln!("\nError: {}\nPress Enter to continue...", msg);
    let _ = io::stdin().read_line(&mut String::new());
}

/// Prints a success message and waits for Enter.
fn pause(msg: &str) {
    println!("\n{msg}\nPress Enter to continue...");
    let _ = io::stdin().read_line(&mut String::new());
}

/// Reads a non-empty line from stdin.
fn read_line(prompt: &str) -> Option<String> {
    print!("{}", prompt);
    io::stdout().flush().ok()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok()?;
    let s = s.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// ─── Sub-actions ────────────────────────────────────────────────────────────
fn change_password() {
    print!("Current password: ");
    io::stdout().flush().ok();
    let _current = rpassword::read_password().ok();
    // Verify first
    let stored = match crate::registry::read_registry_string(
        crate::registry::REG_KEY_PATH,
        crate::registry::REG_VALUE_NAME,
    ) {
        Ok(s) => s,
        Err(_) => {
            pause_on_error("No password is currently set. Run 'set-password' first.");
            return;
        }
    };

    if let Some(ref pw) = _current {
        let _cost = pw.strip_prefix("$2")
            .and_then(|s| s.split('$').nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(12);
        if bcrypt::verify(pw, &stored).unwrap_or(false) {
            // current password verified
        } else {
            pause_on_error("Current password is incorrect.");
            return;
        }
    }

    print!("New password: ");
    io::stdout().flush().ok();
    let new1 = match rpassword::read_password().ok() {
        Some(s) if !s.is_empty() => s,
        _ => {
            pause_on_error("Password cannot be empty.");
            return;
        }
    };
    print!("Confirm new password: ");
    io::stdout().flush().ok();
    let new2 = match rpassword::read_password().ok() {
        Some(s) => s,
        _ => {
            pause_on_error("Password cannot be empty.");
            return;
        }
    };

    if new1 != new2 {
        pause_on_error("Passwords do not match.");
        return;
    }

    match bcrypt::hash(&new1, 12) {
        Ok(hash) => {
            if let Err(e) = crate::registry::write_registry_string(
                crate::registry::REG_KEY_PATH,
                crate::registry::REG_VALUE_NAME,
                &hash,
            ) {
                pause_on_error(&format!("Failed to save password: {e}"));
            } else {
                pause("Password changed successfully.");
            }
        }
        Err(e) => pause_on_error(&format!("bcrypt error: {e}")),
    }
}

fn check_engine_status() {
    use crate::client::EngineClient;

    let base_url = std::env::var("DLP_POLICY_ENGINE_URL")
        .unwrap_or_else(|_| "https://localhost:8443".to_string());

    let client = match EngineClient::from_env() {
        Ok(c) => c,
        Err(e) => {
            pause_on_error(&format!("Failed to build HTTP client: {e}"));
            return;
        }
    };

    print!("\x1B[2J\x1B[H");
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║           Policy Engine — Connection Status               ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Base URL: {}", base_url);
    println!();

    // Health check
    match client::block_on(
        client.get::<serde_json::Value>(&format!("{}/health", base_url.trim_end_matches('/')))
    ) {
        Ok(_) => println!("  [OK]   /health  — engine is healthy"),
        Err(e) => println!("  [FAIL] /health  — {e}"),
    }

    // Ready check
    match client::block_on(
        client.get::<serde_json::Value>(&format!("{}/ready", base_url.trim_end_matches('/')))
    ) {
        Ok(_) => println!("  [OK]   /ready  — engine is ready"),
        Err(e) => println!("  [WARN] /ready  — {e}"),
    }

    println!();
    pause("");
}

fn list_policies_ui() {
    use crate::client::EngineClient;

    let client = match EngineClient::from_env() {
        Ok(c) => c,
        Err(e) => {
            pause_on_error(&format!("Failed to build HTTP client: {e}"));
            return;
        }
    };

    let policies = match client::block_on(
        client.get::<Vec<dlp_common::abac::Policy>>("/policies")
    ) {
        Ok(p) => p,
        Err(e) => {
            pause_on_error(&format!("Failed to list policies: {e}"));
            return;
        }
    };

    print!("\x1B[2J\x1B[H");
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║                    Policy List                             ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    if policies.is_empty() {
        println!("  No policies defined.");
    } else {
        for (i, p) in policies.iter().enumerate() {
            let status = if p.enabled { "ENABLED " } else { "DISABLED" };
            println!("  [{}] {}  v{}", i + 1, p.id, p.version);
            println!("      {}  (priority {}, {})", p.name, p.priority, status);
            println!();
        }
    }

    pause("");
}

fn get_policy_ui() {
    let id = match read_line("Policy ID: ") {
        Some(s) => s,
        None => {
            pause_on_error("Policy ID cannot be empty.");
            return;
        }
    };

    use crate::client::EngineClient;
    let client = match EngineClient::from_env() {
        Ok(c) => c,
        Err(e) => {
            pause_on_error(&format!("Failed to build HTTP client: {e}"));
            return;
        }
    };

    let policy = match client::block_on(
        client.get::<dlp_common::abac::Policy>(&format!("/policies/{id}"))
    ) {
        Ok(p) => p,
        Err(e) => {
            pause_on_error(&format!("Policy not found or error: {e}"));
            return;
        }
    };

    print!("\x1B[2J\x1B[H");
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║                    Policy Detail                           ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  {:.<15} {}", "ID", policy.id);
    println!("  {:.<15} {}", "Name", policy.name);
    opt_field("Description", &policy.description);
    println!("  {:.<15} {}", "Priority", policy.priority);
    bool_field("Enabled", policy.enabled);
    println!("  {:.<15} {}", "Version", policy.version);
    println!("  {:.<15} {:?}", "Action", policy.action);
    println!("  {:.<15} {} condition(s)", "Conditions", policy.conditions.len());
    for cond in &policy.conditions {
        println!("    - {:?}", cond);
    }
    println!();
    pause("");
}

fn create_policy_ui() {
    let path = match read_line("Path to policy JSON file: ") {
        Some(s) => s,
        None => {
            pause_on_error("Path cannot be empty.");
            return;
        }
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            pause_on_error(&format!("Failed to read file: {e}"));
            return;
        }
    };

    let policy: dlp_common::abac::Policy = match serde_json::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            pause_on_error(&format!("Invalid policy JSON: {e}"));
            return;
        }
    };

    use crate::client::EngineClient;
    let client = match EngineClient::from_env() {
        Ok(c) => c,
        Err(e) => {
            pause_on_error(&format!("Failed to build HTTP client: {e}"));
            return;
        }
    };

    match client::block_on(
        client.post::<dlp_common::abac::Policy, _>("/policies", &policy)
    ) {
        Ok(created) => {
            pause(&format!("Policy '{}' created successfully (v{}).", created.id, created.version));
        }
        Err(e) => {
            pause_on_error(&format!("Failed to create policy: {e}"));
        }
    }
}

fn update_policy_ui() {
    let id = match read_line("Policy ID to update: ") {
        Some(s) => s,
        None => {
            pause_on_error("Policy ID cannot be empty.");
            return;
        }
    };
    let path = match read_line("Path to updated policy JSON file: ") {
        Some(s) => s,
        None => {
            pause_on_error("Path cannot be empty.");
            return;
        }
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            pause_on_error(&format!("Failed to read file: {e}"));
            return;
        }
    };

    let policy: dlp_common::abac::Policy = match serde_json::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            pause_on_error(&format!("Invalid policy JSON: {e}"));
            return;
        }
    };

    use crate::client::EngineClient;
    let client = match EngineClient::from_env() {
        Ok(c) => c,
        Err(e) => {
            pause_on_error(&format!("Failed to build HTTP client: {e}"));
            return;
        }
    };

    match client::block_on(
        client.put::<dlp_common::abac::Policy, _>(&format!("/policies/{id}"), &policy)
    ) {
        Ok(updated) => {
            pause(&format!("Policy '{}' updated (now v{}).", updated.id, updated.version));
        }
        Err(e) => {
            pause_on_error(&format!("Failed to update policy: {e}"));
        }
    }
}

fn delete_policy_ui() {
    let id = match read_line("Policy ID to delete: ") {
        Some(s) => s,
        None => {
            pause_on_error("Policy ID cannot be empty.");
            return;
        }
    };

    print!("  Type '{}' to confirm deletion: ", id);
    io::stdout().flush().ok();
    let confirm = {
        let mut s = String::new();
        io::stdin().read_line(&mut s).ok();
        s.trim().to_string()
    };

    if confirm != id {
        println!("Deletion cancelled.");
        return;
    }

    use crate::client::EngineClient;
    let client = match EngineClient::from_env() {
        Ok(c) => c,
        Err(e) => {
            pause_on_error(&format!("Failed to build HTTP client: {e}"));
            return;
        }
    };

    match client::block_on(client.delete(&format!("/policies/{id}"))) {
        Ok(()) => {
            pause(&format!("Policy '{}' deleted.", id));
        }
        Err(e) => {
            pause_on_error(&format!("Failed to delete policy: {e}"));
        }
    }
}

/// ─── Main entry point ────────────────────────────────────────────────────────
/// Runs the interactive TUI menu loop.
pub fn run() {
    const MENU_ITEMS: &[MenuItem] = &[
        MenuItem {
            label: "Change Password",
            description: "Set or update the dlp-admin password (requires elevation)",
        },
        MenuItem {
            label: "Check Policy Engine Status",
            description: "Ping /health and /ready on the configured Policy Engine URL",
        },
        MenuItem {
            label: "List Policies",
            description: "List all policies from the Policy Engine",
        },
        MenuItem {
            label: "Get Policy",
            description: "View full details for a specific policy ID",
        },
        MenuItem {
            label: "Create Policy",
            description: "Create a new policy from a JSON file",
        },
        MenuItem {
            label: "Update Policy",
            description: "Update an existing policy from a JSON file",
        },
        MenuItem {
            label: "Delete Policy",
            description: "Delete a policy by ID",
        },
    ];

    loop {
        match interactive_menu("dlp-admin-cli — Main Menu", MENU_ITEMS) {
            Ok(0) => change_password(),
            Ok(1) => check_engine_status(),
            Ok(2) => list_policies_ui(),
            Ok(3) => get_policy_ui(),
            Ok(4) => create_policy_ui(),
            Ok(5) => update_policy_ui(),
            Ok(6) => delete_policy_ui(),
            Ok(_) => unreachable!(),
            Err(e) => {
                eprintln!("Console error: {e}");
                break;
            }
        }
    }
}
