//! Independent hosts file configuration
//!
//! This module provides functions to ensure mcp.kodegen.ai is properly configured in /etc/hosts.
//! These functions are idempotent and can be run independently of other installation steps.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

const HOSTS_ENTRY: &str = "127.0.0.1 mcp.kodegen.ai";

/// Get platform-specific hosts file path
fn get_hosts_file_path() -> &'static Path {
    #[cfg(unix)]
    {
        Path::new("/etc/hosts")
    }

    #[cfg(windows)]
    {
        Path::new(r"C:\Windows\System32\drivers\etc\hosts")
    }
}

/// Check if the hosts file entry exists
pub fn hosts_entry_exists() -> bool {
    let hosts_path = get_hosts_file_path();

    match File::open(hosts_path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            reader
                .lines()
                .filter_map(Result::ok)
                .any(|line| line.contains(HOSTS_ENTRY))
        }
        Err(_) => false,
    }
}

/// Ensure the hosts file entry exists, adding it with sudo if needed
///
/// This function is idempotent - it checks first and only modifies if the entry is missing.
pub async fn ensure_hosts_configured() -> Result<bool> {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);

    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(stdout, "🔍 Checking /etc/hosts configuration...");
    let _ = stdout.reset();

    // Check if already configured
    if hosts_entry_exists() {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
        let _ = writeln!(stdout, "✓ mcp.kodegen.ai already configured in /etc/hosts");
        let _ = stdout.reset();
        return Ok(false); // No changes made
    }

    // Need to add entry - requires sudo
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)));
    let _ = writeln!(stdout, "⚠ mcp.kodegen.ai not found in /etc/hosts");
    let _ = stdout.reset();
    let _ = writeln!(stdout, "Adding entry (requires sudo)...\n");

    #[cfg(unix)]
    {
        // Create a simple script to add the hosts entry
        let script = r#"#!/bin/sh
set -e

echo 'Adding mcp.kodegen.ai to /etc/hosts...'
if ! grep -q '127.0.0.1 mcp.kodegen.ai' /etc/hosts 2>/dev/null; then
    echo '127.0.0.1 mcp.kodegen.ai' >> /etc/hosts
    echo 'Entry added successfully'
else
    echo 'Entry already exists'
fi
"#
        .to_string();

        // Write script to temp file
        let script_path = format!("/tmp/kodegen_hosts_setup_{}.sh", std::process::id());
        std::fs::write(&script_path, script)
            .context("Failed to write hosts setup script")?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms)?;
        }

        // Execute with sudo
        let status = Command::new("sudo")
            .arg("sh")
            .arg(&script_path)
            .status()
            .context("Failed to execute hosts setup script with sudo")?;

        // Clean up
        let _ = std::fs::remove_file(&script_path);

        if !status.success() {
            anyhow::bail!("Hosts file configuration failed");
        }

        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
        let _ = writeln!(stdout, "✓ mcp.kodegen.ai added to /etc/hosts");
        let _ = stdout.reset();

        Ok(true) // Changes made
    }

    #[cfg(not(unix))]
    {
        anyhow::bail!("Hosts file configuration not yet implemented for this platform");
    }
}
