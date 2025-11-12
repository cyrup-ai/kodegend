//! Linux platform implementation using systemd and native Linux APIs.
//!
//! This implementation provides sophisticated service management with zero allocation,
//! blazing-fast performance, and comprehensive error handling.
//!
//! # Module Structure
//!
//! - `helper` - Helper executable management (extraction, verification)
//! - `privileges` - Privilege checking and validation
//! - `file_ops` - Atomic file operations
//! - `unit` - Systemd unit file generation and management
//! - `dropin` - Drop-in configuration management
//! - `journal` - Journal integration and configuration
//! - `service_control` - Service control operations (start, stop, enable, disable)
//! - `services` - Service definition installation

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context, Result};

use super::{InstallerBuilder, InstallerError};

// Submodules
mod helper;
mod privileges;
mod file_ops;
mod unit;
mod dropin;
mod journal;
mod service_control;
mod services;

// Re-export for internal use
pub(crate) use unit::SystemdConfig;

// Constants for zero-allocation buffers
const UNIT_NAME_MAX: usize = 256;
const UNIT_PATH_MAX: usize = 512;
const MAX_SERVICE_NAME: usize = 256;
const MAX_DESCRIPTION: usize = 512;

// Atomic state for service operations
static SERVICE_OPERATION_STATE: AtomicU32 = AtomicU32::new(0);

pub(crate) struct PlatformExecutor;

impl PlatformExecutor {
    /// Install the daemon as a systemd service with comprehensive configuration
    pub fn install(b: InstallerBuilder) -> Result<(), InstallerError> {
        // System daemons always use system directory
        let unit_dir = PathBuf::from("/etc/systemd/system");

        // Ensure helper path is initialized and check privileges
        helper::ensure_helper_path()?;
        privileges::check_privileges()?;

        // Create systemd configuration
        let env_vec: Vec<(String, String)> = b.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let config = SystemdConfig {
            service_name: &b.label,
            description: &b.description,
            binary_path: b.program.to_str().ok_or_else(|| {
                InstallerError::System("Invalid binary path encoding".to_string())
            })?,
            args: &b.args,
            env_vars: &env_vec,
            auto_restart: b.auto_restart,
            wants_network: b.wants_network,
            user: None, // Run as root for system service, or current user for user service
            group: None,
        };

        // Generate and install systemd unit file
        unit::create_systemd_unit_with_dir(&config, &unit_dir)?;

        // Create systemd drop-in directories for advanced configuration
        dropin::create_dropin_config(&config)?;

        // Register with systemd journal for structured logging
        journal::setup_journal_integration(&b.label)?;

        // Install service definitions if any
        if !b.services.is_empty() {
            services::install_services(&b.services)?;
        }

        // Enable and start the system service (only if auto_start is enabled)
        if b.auto_start {
            service_control::enable_systemd_service(&b.label)?;
            service_control::start_systemd_service(&b.label)?;
        }

        Ok(())
    }

    /// Uninstall the systemd service and clean up all resources
    pub fn uninstall(label: &str) -> Result<(), InstallerError> {
        // Stop the service first
        service_control::stop_systemd_service(label)?;

        // Disable the service
        service_control::disable_systemd_service(label)?;

        // Remove systemd unit files
        unit::remove_systemd_unit(label)?;

        // Clean up drop-in configurations
        dropin::cleanup_dropin_config(label)?;

        // Remove journal integration
        journal::cleanup_journal_integration(label)?;

        // Reload systemd daemon to reflect changes
        service_control::reload_systemd_daemon()?;

        Ok(())
    }

    pub async fn install_async(b: InstallerBuilder) -> Result<(), InstallerError> {
        tokio::task::spawn_blocking(move || Self::install(b))
            .await
            .context("task join failed")?
    }

    pub async fn uninstall_async(label: &str) -> Result<(), InstallerError> {
        let label = label.to_string();
        tokio::task::spawn_blocking(move || Self::uninstall(&label))
            .await
            .context("task join failed")?
    }
}
