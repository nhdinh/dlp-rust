//! Password management — set and verify the dlp-admin bcrypt hash in the registry.

use crate::registry::{read_registry_string, write_registry_string, REG_KEY_PATH, REG_VALUE_NAME};

/// Prompt-free helper: reads a password from stdin with echo disabled.
fn read_password(prompt: &str) -> anyhow::Result<String> {
    print!("{prompt}");
    std::io::Write::flush(&mut std::io::stdout())?;
    let pw = rpassword::read_password()?;
    if pw.is_empty() {
        anyhow::bail!("password cannot be empty");
    }
    Ok(pw)
}

/// Reads the stored bcrypt hash from the registry.
fn get_stored_hash() -> anyhow::Result<String> {
    let hash = read_registry_string(REG_KEY_PATH, REG_VALUE_NAME)?;
    if hash.is_empty() {
        anyhow::bail!(
            "No password is set. Run '{} set-password' first.",
            std::env::args_os().next().as_ref().map(|s| s.to_string_lossy()).unwrap_or_default()
        );
    }
    Ok(hash)
}

/// Reads the bcrypt cost from the stored hash, defaulting to 12.
fn get_cost(hash: &str) -> u32 {
    hash.strip_prefix("$2")
        .and_then(|s| s.split('$').nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(12)
}

/// `dlp-admin-cli set-password` — prompts for a new password (twice), hashes it with
/// bcrypt cost 12, and writes it to the registry under HKLM.
pub fn set_password() -> anyhow::Result<()> {
    let pw1 = read_password("New password: ")?;
    let pw2 = read_password("Confirm password: ")?;
    if pw1 != pw2 {
        anyhow::bail!("Passwords do not match — not saved.");
    }

    let cost = 12;
    let hash = bcrypt::hash(&pw1, cost)
        .map_err(|e| anyhow::anyhow!("bcrypt hash failed: {e}"))?;

    write_registry_string(REG_KEY_PATH, REG_VALUE_NAME, &hash)?;
    println!("Password set successfully.");
    Ok(())
}

/// `dlp-admin-cli verify-password` — prompts for a password and verifies it against
/// the stored bcrypt hash.
pub fn verify_password() -> anyhow::Result<()> {
    let stored_hash = get_stored_hash()?;
    let _cost = get_cost(&stored_hash);
    let candidate = read_password("Password: ")?;

    let ok = bcrypt::verify(&candidate, &stored_hash)
        .map_err(|e| anyhow::anyhow!("bcrypt verify failed: {e}"))?;

    if ok {
        println!("Password correct.");
    } else {
        anyhow::bail!("Incorrect password.");
    }
    Ok(())
}
