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

use anyhow::Result;

use super::{InstallerBuilder, InstallerError};

// Submodules
mod dropin;
mod file_ops;
mod helper;
mod journal;
mod privileges;
mod service_control;
mod services;
mod unit;

// Re-export for internal use
pub(crate) use unit::SystemdConfig;

pub(crate) struct PlatformExecutor;

impl PlatformExecutor {
    /// Install the daemon as a systemd service with comprehensive configuration
    pub fn install(b: InstallerBuilder) -> Result<(), InstallerError> {
        use crate::platform;
        
        // ═══════════════════════════════════════════════════════════════
        // STEP 1: Verify systemd is available
        // ═══════════════════════════════════════════════════════════════
        if !platform::is_systemd_available() {
            return Err(InstallerError::System(
                "systemd not detected on this system.\n\n\
                 This Linux system appears to use a different init system (OpenRC, runit, sysvinit, etc.).\n\
                 kodegend currently requires systemd for service management.\n\n\
                 Workarounds:\n\
                 1. Run kodegend manually: `kodegend daemon`\n\
                 2. Create init scripts for your init system manually\n\
                 3. Use kodegend in foreground mode for testing\n\n\
                 Detected init system check: /run/systemd/system does not exist"
                    .to_string()
            ));
        }
        
        // System daemons always use system directory
        let unit_dir = PathBuf::from("/etc/systemd/system");

        // Ensure helper path is initialized and check privileges
        helper::ensure_helper_path()?;
        privileges::check_privileges()?;

        // Create systemd configuration
        let env_vec: Vec<(String, String)> =
            b.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
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
            user: Some(&b.run_as_user),
            group: Some(&b.run_as_group),
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
}
