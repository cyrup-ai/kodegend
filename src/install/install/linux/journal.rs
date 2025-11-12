//! Systemd journal integration.
//!
//! This module handles configuration of systemd journal for service logging,
//! including retention policies and compression settings.

use std::fs;
use std::path::PathBuf;

use super::InstallerError;
use super::file_ops::write_file_atomic;

/// Setup systemd journal integration for structured logging
pub(super) fn setup_journal_integration(service_name: &str) -> Result<(), InstallerError> {
    // Create journal configuration for the service
    let journal_config = format!(
        r#"# Systemd journal configuration for {}
[Journal]
MaxRetentionSec=7day
MaxFileSec=1day
Compress=yes
"#,
        service_name
    );

    let journal_config_dir = PathBuf::from("/etc/systemd/journald.conf.d");
    if journal_config_dir.exists() {
        let config_path = journal_config_dir.join(format!("{}.conf", service_name));
        write_file_atomic(&config_path, &journal_config)?;
    }

    Ok(())
}

/// Clean up journal integration
pub(super) fn cleanup_journal_integration(service_name: &str) -> Result<(), InstallerError> {
    let journal_config_dir = PathBuf::from("/etc/systemd/journald.conf.d");
    let config_path = journal_config_dir.join(format!("{}.conf", service_name));

    if config_path.exists() {
        fs::remove_file(&config_path).map_err(|e| {
            InstallerError::System(format!("Failed to remove journal config: {}", e))
        })?;
    }

    Ok(())
}
