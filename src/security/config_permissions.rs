use anyhow::{Context, Result, bail};
use std::fs;
use std::path::Path;

/// Permission validation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PermissionMode {
    /// Reject on violation (default for production)
    #[default]
    Strict,
    /// Log warning but continue (development only)
    Warn,
    /// Skip all checks (CI/testing only - DANGEROUS)
    Ignore,
}

impl PermissionMode {
    /// Parse from string (for CLI/env var)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "strict" => Some(PermissionMode::Strict),
            "warn" => Some(PermissionMode::Warn),
            "ignore" => Some(PermissionMode::Ignore),
            _ => None,
        }
    }
}

/// Validate config file permissions (Unix implementation)
///
/// Security checks:
/// 1. Not a symlink (prevent symlink attacks)
/// 2. Not world-writable (mode & 0o002 == 0)
/// 3. Not group-writable by untrusted group
/// 4. Owned by root or current user
///
/// # Arguments
/// * `path` - Config file path
/// * `mode` - Permission validation mode
///
/// # Returns
/// * Ok(()) - Permissions are acceptable
/// * Err - Permissions are unsafe (if mode == Strict)
#[cfg(unix)]
pub fn validate_config_permissions(
    path: &Path,
    mode: PermissionMode,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use nix::unistd::{Uid, Gid, User, Group};
    
    if mode == PermissionMode::Ignore {
        log::debug!("Skipping config permission checks (ignore mode)");
        return Ok(());
    }
    
    // Get metadata without following symlinks (CRITICAL for security)
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Failed to read metadata for {}", path.display()))?;
    
    // ════════════════════════════════════════════════════════════════════
    // Check 1: Reject Symlinks (Symlink Attack Prevention)
    // ════════════════════════════════════════════════════════════════════
    
    if metadata.file_type().is_symlink() {
        let msg = format!(
            "Config file is a symlink: {}\n\
             \n\
             Symlinks are rejected to prevent symlink attacks where an attacker\n\
             creates a symlink to trick the daemon into reading/writing sensitive files.\n\
             \n\
             Fix: Use a real file instead:\n\
             $ rm {}\n\
             $ cp $(readlink {}) {}",
            path.display(),
            path.display(),
            path.display(),
            path.display()
        );
        return handle_violation(msg, mode);
    }
    
    // ════════════════════════════════════════════════════════════════════
    // Check 2: File Permission Bits
    // ════════════════════════════════════════════════════════════════════
    
    let permissions = metadata.permissions();
    let mode_bits = permissions.mode();
    
    // World-writable check (CWE-732: Incorrect Permission Assignment)
    if mode_bits & 0o002 != 0 {
        let msg = format!(
            "Config file is world-writable: {} (mode: {:o})\n\
             \n\
             This is a CRITICAL security vulnerability (CWE-732). Any user on the\n\
             system can modify the daemon configuration and execute arbitrary code\n\
             with daemon privileges.\n\
             \n\
             Fix: Remove write permissions for others:\n\
             $ chmod 644 {}\n\
             \n\
             Or for maximum security (owner-only):\n\
             $ chmod 600 {}",
            path.display(),
            mode_bits & 0o777,
            path.display(),
            path.display()
        );
        return handle_violation(msg, mode);
    }
    
    // Group-writable check (only allowed if group matches daemon's group)
    if mode_bits & 0o020 != 0 {
        let file_gid = Gid::from_raw(metadata.gid());
        let current_gid = Gid::current();
        
        if file_gid != current_gid {
            let file_group = Group::from_gid(file_gid)
                .ok()
                .flatten()
                .map(|g| g.name)
                .unwrap_or_else(|| format!("gid:{}", file_gid));
            let daemon_group = Group::from_gid(current_gid)
                .ok()
                .flatten()
                .map(|g| g.name)
                .unwrap_or_else(|| format!("gid:{}", current_gid));
            
            let msg = format!(
                "Config file is group-writable by untrusted group: {} (mode: {:o})\n\
                 \n\
                 File group: {}\n\
                 Daemon group: {}\n\
                 \n\
                 Group-write is only allowed if the file's group matches the daemon's\n\
                 group. This prevents users in other groups from modifying configs.\n\
                 \n\
                 Fix: Remove group write permissions:\n\
                 $ chmod 644 {}",
                path.display(),
                mode_bits & 0o777,
                file_group,
                daemon_group,
                path.display()
            );
            return handle_violation(msg, mode);
        }
    }
    
    // ════════════════════════════════════════════════════════════════════
    // Check 3: Owner Validation
    // ════════════════════════════════════════════════════════════════════
    
    let file_uid = Uid::from_raw(metadata.uid());
    let current_uid = Uid::current();
    let root_uid = Uid::from_raw(0);
    
    if file_uid != current_uid && file_uid != root_uid {
        let file_owner = User::from_uid(file_uid)
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_else(|| format!("uid:{}", file_uid));
        let current_user = User::from_uid(current_uid)
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_else(|| format!("uid:{}", current_uid));
        
        let msg = format!(
            "Config file is owned by untrusted user: {} (mode: {:o})\n\
             \n\
             File owner: {}\n\
             Current user: {}\n\
             \n\
             Config files must be owned by root or the daemon's user to prevent\n\
             unauthorized modification.\n\
             \n\
             Fix: Change ownership to current user or root:\n\
             $ sudo chown {} {}\n\
             $ sudo chown root:root {}",
            path.display(),
            mode_bits & 0o777,
            file_owner,
            current_user,
            current_user,
            path.display(),
            path.display()
        );
        return handle_violation(msg, mode);
    }
    
    // ════════════════════════════════════════════════════════════════════
    // Informational: Recommend Standard Permissions
    // ════════════════════════════════════════════════════════════════════
    
    let recommended_mode = mode_bits & 0o777;
    if recommended_mode != 0o600 && recommended_mode != 0o644 {
        log::warn!(
            "Config file has non-standard permissions: {} ({:o})\n\
             Recommended: 0600 (owner-only, most secure) or 0644 (owner-write, others-read)",
            path.display(),
            recommended_mode
        );
    }
    
    // Success - log validation details
    let file_owner = User::from_uid(file_uid)
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| format!("uid:{}", file_uid));
    let file_group = Group::from_gid(Gid::from_raw(metadata.gid()))
        .ok()
        .flatten()
        .map(|g| g.name)
        .unwrap_or_else(|| format!("gid:{}", metadata.gid()));
    
    log::info!(
        "Config file permissions validated: {} (mode: {:o}, owner: {}, group: {})",
        path.display(),
        mode_bits & 0o777,
        file_owner,
        file_group
    );
    
    Ok(())
}

/// Validate config file permissions (Windows implementation)
///
/// Security checks:
/// 1. Non-admin users don't have write access (ACL check)
/// 2. Not a UNC path (\\server\share\config.toml)
///
/// # Note
/// Windows ACL validation is complex. This implementation performs basic checks.
/// For production, consider using the `windows-acl` crate for comprehensive validation.
#[cfg(windows)]
pub fn validate_config_permissions(
    path: &Path,
    mode: PermissionMode,
) -> Result<()> {
    if mode == PermissionMode::Ignore {
        log::debug!("Skipping config permission checks (ignore mode)");
        return Ok(());
    }
    
    // ════════════════════════════════════════════════════════════════════
    // Check 1: Reject UNC Paths
    // ════════════════════════════════════════════════════════════════════
    
    let path_str = path.to_string_lossy();
    if path_str.starts_with("\\\\") || path_str.starts_with("//") {
        let msg = format!(
            "Config file is a UNC network path: {}\n\
             \n\
             Network paths are rejected because:\n\
             - Remote filesystem permissions are unreliable\n\
             - Network disruptions could affect daemon startup\n\
             - Increased attack surface via SMB vulnerabilities\n\
             \n\
             Fix: Copy config to local disk:\n\
             $ copy {} C:\\ProgramData\\kodegend\\kodegend.toml",
            path.display(),
            path.display()
        );
        return handle_violation(msg, mode);
    }
    
    // ════════════════════════════════════════════════════════════════════
    // Check 2: Basic Metadata Validation
    // ════════════════════════════════════════════════════════════════════
    
    let metadata = fs::metadata(path)
        .with_context(|| format!("Failed to read metadata for {}", path.display()))?;
    
    // Check if file is read-only at OS level (basic sanity check)
    if metadata.permissions().readonly() {
        log::warn!(
            "Config file is read-only: {}. This may prevent updates.",
            path.display()
        );
    }
    
    // ════════════════════════════════════════════════════════════════════
    // TODO: ACL Validation (Advanced)
    // ════════════════════════════════════════════════════════════════════
    
    // Full Windows ACL validation requires:
    // 1. GetNamedSecurityInfoW to retrieve DACL
    // 2. GetAce to enumerate ACL entries
    // 3. Check each ACE for non-admin write access
    //
    // Reference implementation in manager.rs:155-159 shows Windows API usage pattern.
    // For production, use windows-acl crate or implement comprehensive ACL enumeration.
    
    log::info!(
        "Config file permissions validated: {} (Windows - basic checks only)",
        path.display()
    );
    log::warn!(
        "Full ACL validation not implemented. Ensure config is in a secure location\n\
         (e.g., C:\\ProgramData\\kodegend\\) with admin-only write access."
    );
    
    Ok(())
}

/// Handle permission violation based on mode
fn handle_violation(msg: String, mode: PermissionMode) -> Result<()> {
    match mode {
        PermissionMode::Strict => {
            log::error!("{}", msg);
            bail!("{}", msg);
        }
        PermissionMode::Warn => {
            log::warn!("SECURITY WARNING: {}", msg);
            Ok(())
        }
        PermissionMode::Ignore => {
            Ok(())
        }
    }
}
