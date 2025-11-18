//! Systemd unit file generation and management.
//!
//! This module handles creation, configuration, and removal of systemd service
//! unit files with comprehensive security and performance settings.

use std::fs;
use std::path::{Path, PathBuf};

use super::InstallerError;
use super::file_ops::write_file_atomic;

// Pre-computed systemd unit template for zero allocation
const UNIT_TEMPLATE: &str = include_str!("../../../templates/systemd.service.template");

/// Systemd service configuration with zero-allocation patterns
#[derive(Clone)]
pub(super) struct SystemdConfig<'a> {
    pub service_name: &'a str,
    pub description: &'a str,
    pub binary_path: &'a str,
    pub args: &'a [String],
    pub env_vars: &'a [(String, String)],
    pub auto_restart: bool,
    pub wants_network: bool,
    pub user: Option<&'a str>,
    pub group: Option<&'a str>,
}

/// Create systemd unit file with comprehensive configuration in specified directory
pub(super) fn create_systemd_unit_with_dir(
    config: &SystemdConfig,
    unit_dir: &Path,
) -> Result<(), InstallerError> {
    let unit_content = generate_unit_content(config)?;

    // Determine unit file path
    let unit_path = unit_dir.join(format!("{}.service", config.service_name));

    // Create parent directory if it doesn't exist
    if let Some(parent) = unit_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            InstallerError::System(format!("Failed to create systemd directory: {}", e))
        })?;
    }

    // Write unit file atomically
    write_file_atomic(&unit_path, &unit_content)?;

    // Set appropriate permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&unit_path)
            .map_err(|e| {
                InstallerError::System(format!("Failed to get unit file metadata: {}", e))
            })?
            .permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&unit_path, perms).map_err(|e| {
            InstallerError::System(format!("Failed to set unit file permissions: {}", e))
        })?;
    }

    Ok(())
}

/// Generate systemd unit file content with zero allocation where possible
fn generate_unit_content(config: &SystemdConfig) -> Result<String, InstallerError> {
    let mut content = String::with_capacity(2048); // Pre-allocate for performance

    // [Unit] section
    content.push_str("[Unit]\n");
    content.push_str(&format!("Description={}\n", config.description));
    content.push_str("Documentation=https://github.com/kodegen/kodegen\n");

    if config.wants_network {
        content.push_str("Wants=network-online.target\n");
        content.push_str("After=network-online.target\n");
        content.push_str("Requires=network.target\n");
    }

    content.push_str("After=multi-user.target\n");
    content.push_str("DefaultDependencies=no\n");
    content.push('\n');

    // [Service] section
    content.push_str("[Service]\n");
    content.push_str("Type=notify\n"); // Use sd_notify for proper startup signaling
    content.push_str("NotifyAccess=main\n");

    // Build ExecStart command
    let exec_start = if config.args.is_empty() {
        format!("ExecStart={}\n", config.binary_path)
    } else {
        format!(
            "ExecStart={} {}\n",
            config.binary_path,
            config.args.join(" ")
        )
    };
    content.push_str(&exec_start);

    // Restart configuration
    if config.auto_restart {
        content.push_str("Restart=on-failure\n");
        content.push_str("RestartSec=5s\n");
        content.push_str("StartLimitInterval=60s\n");
        content.push_str("StartLimitBurst=3\n");
    } else {
        content.push_str("Restart=no\n");
    }

    // Environment variables
    for (key, value) in config.env_vars {
        content.push_str(&format!("Environment=\"{}={}\"\n", key, value));
    }

    // Security and sandboxing
    content.push_str("NoNewPrivileges=true\n");
    content.push_str("ProtectSystem=strict\n");
    content.push_str("ProtectHome=true\n");
    content.push_str("ProtectKernelTunables=true\n");
    content.push_str("ProtectControlGroups=true\n");
    content.push_str("RestrictSUIDSGID=true\n");
    content.push_str("RestrictRealtime=true\n");
    content.push_str("RestrictNamespaces=true\n");
    content.push_str("LockPersonality=true\n");
    content.push_str("MemoryDenyWriteExecute=true\n");

    // Allow specific directories for daemon operation
    content.push_str("ReadWritePaths=/var/log /var/lib /tmp\n");
    content.push_str("ReadOnlyPaths=/etc\n");

    // Resource limits
    content.push_str("LimitNOFILE=65536\n");
    content.push_str("LimitNPROC=4096\n");

    // User/Group configuration
    if let Some(user) = config.user {
        content.push_str(&format!("User={}\n", user));
    }
    if let Some(group) = config.group {
        content.push_str(&format!("Group={}\n", group));
    }

    // Logging
    content.push_str("StandardOutput=journal\n");
    content.push_str("StandardError=journal\n");
    content.push_str("SyslogIdentifier=kodegen\n");

    // Watchdog support
    content.push_str("WatchdogSec=30s\n");
    content.push('\n');

    // [Install] section
    content.push_str("[Install]\n");
    content.push_str("WantedBy=multi-user.target\n");

    Ok(content)
}

/// Remove systemd unit file
pub(super) fn remove_systemd_unit(service_name: &str) -> Result<(), InstallerError> {
    let unit_path = if unsafe { libc::getuid() } == 0 {
        PathBuf::from("/etc/systemd/system").join(format!("{}.service", service_name))
    } else {
        let home_dir = std::env::var("HOME").map_err(|_| {
            InstallerError::System("HOME environment variable not set".to_string())
        })?;
        PathBuf::from(home_dir)
            .join(".config/systemd/user")
            .join(format!("{}.service", service_name))
    };

    if unit_path.exists() {
        fs::remove_file(&unit_path).map_err(|e| {
            InstallerError::System(format!("Failed to remove unit file: {}", e))
        })?;
    }

    Ok(())
}
