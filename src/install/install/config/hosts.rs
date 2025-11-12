//! Hosts file management for Kodegen installation
//!
//! This module handles adding and removing Kodegen DNS entries in the system hosts file
//! with atomic operations and proper locking.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use log::info;

/// Check if a hosts file line contains the specified IP and hostname entry
/// 
/// Makes hosts file modification idempotent.
fn check_hosts_entry(line: &str, ip: &str, hostname: &str) -> bool {
    let trimmed = line.trim();

    // Skip comments and empty lines
    if trimmed.starts_with('#') || trimmed.is_empty() {
        return false;
    }

    // Split by whitespace (handles both spaces and tabs)
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 2 {
        return false;
    }

    // Check if IP matches and hostname matches (case insensitive for DNS)
    parts[0] == ip && parts[1..].iter().any(|h| h.eq_ignore_ascii_case(hostname))
}

/// Remove Kodegen block from hosts file content
fn remove_kodegen_block(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut new_lines = Vec::new();
    let mut in_kodegen_section = false;

    for line in lines {
        if line.trim() == "# Kodegen entries" {
            in_kodegen_section = true;
            continue;
        }
        if line.trim() == "# End Kodegen entries" {
            in_kodegen_section = false;
            continue;
        }
        if !in_kodegen_section {
            new_lines.push(line);
        }
    }

    new_lines.join("\n")
}

/// Write file atomically using temp file + rename pattern
fn write_hosts_file_atomic(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;

    // Create temp file in same directory as target (ensures same filesystem for atomic rename)
    let temp_path = path.with_extension("tmp");

    // Write to temp file with explicit sync
    {
        let mut file = fs::File::create(&temp_path)
            .with_context(|| format!("Failed to create temp file: {}", temp_path.display()))?;

        file.write_all(content.as_bytes())
            .context("Failed to write to temp file")?;

        file.sync_all()
            .context("Failed to sync temp file to disk")?;
    }

    // Atomically rename temp to target
    fs::rename(&temp_path, path)
        .with_context(|| format!("Failed to rename temp file to {}", path.display()))?;

    Ok(())
}

/// Add Kodegen host entries with lock-protected atomic modification
/// 
/// Used by uninstall.rs for structured hosts file management.
/// Install phase uses shell script version in main.rs for simplicity.
/// This Rust version provides flock-based locking and atomic block management.
#[allow(dead_code)]
#[cfg(unix)]
pub fn add_kodegen_host_entries() -> Result<()> {
    use nix::fcntl::{Flock, FlockArg};
    
    let hosts_file_path = get_hosts_file_path();  // /etc/hosts

    // Open file with read+write permissions to hold lock during operation
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&hosts_file_path)
        .context("Failed to open hosts file for locking")?;
    
    // Acquire exclusive lock - blocks until available
    // This makes the entire read-modify-write cycle atomic
    info!("Acquiring lock on {}", hosts_file_path.display());
    let _flock_guard = Flock::lock(lock_file, FlockArg::LockExclusive)
        .map_err(|(_, err)| anyhow::anyhow!("Failed to acquire exclusive lock on hosts file: {}", err))?;
    
    // ✅ LOCK ACQUIRED: Safe to read-modify-write
    info!("Lock acquired, reading hosts file");
    
    // Read existing hosts file (now protected by lock)
    let existing_content = 
        fs::read_to_string(&hosts_file_path)
            .context("Failed to read hosts file")?;
    
    // Check if the entry already exists
    let has_entry = existing_content
        .lines()
        .any(|line| check_hosts_entry(line, "127.0.0.1", "mcp.kodegen.ai"));
    
    if has_entry {
        info!("Entry 127.0.0.1 mcp.kodegen.ai already exists, skipping");
        // Lock auto-released when lock_file drops
        return Ok(());
    }
    
    // Remove any existing Kodegen block (idempotent)
    let cleaned_content = remove_kodegen_block(&existing_content);
    
    // Build new content with Kodegen block
    let mut new_content = cleaned_content;
    if !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    new_content.push('\n');
    new_content.push_str("# Kodegen entries\n");
    new_content.push_str("127.0.0.1 mcp.kodegen.ai\n");
    new_content.push_str("# End Kodegen entries\n");
    
    // Write atomically (temp + rename) - still protected by lock
    write_hosts_file_atomic(&hosts_file_path, &new_content)
        .context("Failed to write hosts file atomically")?;
    
    info!("Added Kodegen host entry to {}", hosts_file_path.display());
    
    // ✅ LOCK AUTO-RELEASED: lock_file drops here, flock() releases
    Ok(())
}

/// Windows implementation (unchanged - locking less critical on Windows)
#[cfg(windows)]
pub fn add_kodegen_host_entries() -> Result<()> {
    // Keep existing Windows implementation as-is
    // Windows installers rarely have concurrent /etc/hosts modifications
    let hosts_file_path = get_hosts_file_path();
    
    let existing_content = 
        fs::read_to_string(&hosts_file_path)
            .context("Failed to read hosts file")?;
    
    let has_entry = existing_content
        .lines()
        .any(|line| check_hosts_entry(line, "127.0.0.1", "mcp.kodegen.ai"));
    
    if has_entry {
        info!("Entry 127.0.0.1 mcp.kodegen.ai already exists, skipping");
        return Ok(());
    }
    
    let cleaned_content = remove_kodegen_block(&existing_content);
    let mut new_content = cleaned_content;
    if !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    new_content.push('\n');
    new_content.push_str("# Kodegen entries\n");
    new_content.push_str("127.0.0.1 mcp.kodegen.ai\n");
    new_content.push_str("# End Kodegen entries\n");
    
    write_hosts_file_atomic(&hosts_file_path, &new_content)
        .context("Failed to write hosts file atomically")?;
    
    info!("Added Kodegen host entry to {}", hosts_file_path.display());
    Ok(())
}

/// Get hosts file path with platform-specific logic
fn get_hosts_file_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/etc/hosts")
    }
    #[cfg(windows)]
    {
        PathBuf::from("C:\\Windows\\System32\\drivers\\etc\\hosts")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from("/etc/hosts")
    }
}

/// Remove Kodegen host entries with lock-protected atomic modification
#[cfg(unix)]
pub fn remove_kodegen_host_entries() -> Result<()> {
    use nix::fcntl::{Flock, FlockArg};
    
    let hosts_file_path = get_hosts_file_path();

    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&hosts_file_path)
        .context("Failed to open hosts file for locking")?;
    
    let _flock_guard = Flock::lock(lock_file, FlockArg::LockExclusive)
        .map_err(|(_, err)| anyhow::anyhow!("Failed to acquire exclusive lock on hosts file: {}", err))?;

    let existing_content =
        fs::read_to_string(&hosts_file_path)
            .context("Failed to read hosts file")?;

    if !existing_content.contains("# Kodegen entries") {
        info!("No Kodegen host entries found, skipping removal");
        return Ok(());
    }

    let mut new_content = remove_kodegen_block(&existing_content);
    if !new_content.is_empty() && !new_content.ends_with('\n') {
        new_content.push('\n');
    }

    write_hosts_file_atomic(&hosts_file_path, &new_content)
        .context("Failed to write hosts file atomically")?;

    info!("Removed Kodegen host entries from {}", hosts_file_path.display());
    Ok(())
}

#[cfg(windows)]
pub fn remove_kodegen_host_entries() -> Result<()> {
    let hosts_file_path = get_hosts_file_path();

    // Read existing hosts file
    let existing_content =
        fs::read_to_string(&hosts_file_path).context("Failed to read hosts file")?;

    // Check if Kodegen block exists
    if !existing_content.contains("# Kodegen entries") {
        info!("No Kodegen host entries found, skipping removal");
        return Ok(());
    }

    // Remove Kodegen block
    let mut new_content = remove_kodegen_block(&existing_content);

    // Ensure file ends with newline (POSIX standard)
    if !new_content.is_empty() && !new_content.ends_with('\n') {
        new_content.push('\n');
    }

    // Write atomically (temp + rename)
    write_hosts_file_atomic(&hosts_file_path, &new_content)
        .context("Failed to write hosts file atomically")?;

    info!(
        "Removed Kodegen host entries from {}",
        hosts_file_path.display()
    );
    Ok(())
}
