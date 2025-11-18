//! Systemd drop-in configuration management.
//!
//! This module handles creation and cleanup of systemd drop-in configuration
//! files for advanced service features and resource management.

use std::fs;
use std::path::PathBuf;

use super::InstallerError;
use super::file_ops::write_file_atomic;
use super::unit::SystemdConfig;

/// Create systemd drop-in configuration for advanced features
pub(super) fn create_dropin_config(config: &SystemdConfig) -> Result<(), InstallerError> {
    let dropin_dir = if unsafe { libc::getuid() } == 0 {
        PathBuf::from("/etc/systemd/system").join(format!("{}.service.d", config.service_name))
    } else {
        let home_dir = std::env::var("HOME").map_err(|_| {
            InstallerError::System("HOME environment variable not set".to_string())
        })?;
        PathBuf::from(home_dir)
            .join(".config/systemd/user")
            .join(format!("{}.service.d", config.service_name))
    };

    // Create drop-in directory
    fs::create_dir_all(&dropin_dir).map_err(|e| {
        InstallerError::System(format!("Failed to create drop-in directory: {}", e))
    })?;

    // Create override configuration for advanced features
    let override_content = format!(
        r#"[Service]
# Resource management
MemoryMax=1G
CPUQuota=200%
TasksMax=1024

# Additional security
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

# Capability restrictions
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Process management
OOMScoreAdjust=-100
Nice=-5

# Service metadata
X-Kodegen-Service=true
X-Kodegen-Version={}
"#,
        env!("CARGO_PKG_VERSION")
    );

    let override_path = dropin_dir.join("10-kodegen.conf");
    write_file_atomic(&override_path, &override_content)?;

    Ok(())
}

/// Clean up drop-in configuration
pub(super) fn cleanup_dropin_config(service_name: &str) -> Result<(), InstallerError> {
    let dropin_dir = if unsafe { libc::getuid() } == 0 {
        PathBuf::from("/etc/systemd/system").join(format!("{}.service.d", service_name))
    } else {
        let home_dir = std::env::var("HOME").map_err(|_| {
            InstallerError::System("HOME environment variable not set".to_string())
        })?;
        PathBuf::from(home_dir)
            .join(".config/systemd/user")
            .join(format!("{}.service.d", service_name))
    };

    if dropin_dir.exists() {
        fs::remove_dir_all(&dropin_dir).map_err(|e| {
            InstallerError::System(format!("Failed to remove drop-in directory: {}", e))
        })?;
    }

    Ok(())
}
