//! Windows platform implementation using Service Control Manager and native Windows APIs.
//!
//! This implementation provides sophisticated service management with zero allocation,
//! blazing-fast performance, and comprehensive error handling to match the macOS implementation.

use anyhow::Result;
use windows::Win32::System::Services::{OpenSCManagerW, SC_MANAGER_ALL_ACCESS};
use windows::core::PCWSTR;

use super::{InstallerBuilder, InstallerError};

mod handles;
pub(crate) mod paths;
pub(crate) mod privileges;
mod registry;
mod service_creation;
pub(crate) mod utils;

use handles::ScManagerHandle;
use privileges::{check_privileges, ensure_helper_path};
use registry::{
    cleanup_registry_entries, create_registry_entries, register_event_source,
    unregister_event_source,
};
use service_creation::{
    configure_delayed_start, configure_failure_actions, configure_service_description,
    configure_service_sid, create_service, install_services, open_service, start_service,
    stop_service,
};
// Re-export paths module for use in other modules
pub use paths::{hosts_file, install_dir, installer_data_dir, temp_cert_file};

#[allow(dead_code)]
pub(crate) struct PlatformExecutor;

impl ScManagerHandle {
    #[inline]
    fn new() -> Result<Self, InstallerError> {
        let handle =
            unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) }
            .map_err(|e| InstallerError::System(format!(
                "Failed to open Service Control Manager: {}", e
            )))?;

        if handle.is_invalid() {
            return Err(InstallerError::System(format!(
                "Failed to open Service Control Manager: {}",
                unsafe { windows::Win32::Foundation::GetLastError().0 }
            )));
        }

        Ok(Self(handle))
    }
}

#[allow(dead_code)]
impl PlatformExecutor {
    /// Install the daemon as a Windows service with comprehensive configuration
    pub fn install(b: InstallerBuilder) -> Result<(), InstallerError> {
        // Check if we have sufficient privileges
        check_privileges()?;

        // Create the service with full configuration
        let sc_manager = ScManagerHandle::new()?;
        let service = create_service(&sc_manager, &b)?;

        // Configure advanced service properties
        configure_service_description(&service, &b.description)?;
        configure_failure_actions(&service, b.auto_restart)?;
        configure_delayed_start(&service)?;
        configure_service_sid(&service)?;

        // Create registry entries for custom configuration
        create_registry_entries(&b)?;

        // Register Windows Event Log source
        register_event_source(&b.label)?;

        // Install service definitions if any
        if !b.services.is_empty() {
            install_services(&b.services)?;
        }

        // Start the service if requested
        if b.auto_start {
            start_service(&service)?;
        }

        Ok(())
    }

    /// Uninstall the Windows service and clean up all resources
    pub fn uninstall(label: &str) -> Result<(), InstallerError> {
        let sc_manager = ScManagerHandle::new()?;

        // Open the service
        let service = open_service(&sc_manager, label)?;

        // Stop the service first
        stop_service(&service)?;

        // Delete the service
        unsafe {
            windows::Win32::System::Services::DeleteService(service.handle())
                .map_err(|e| InstallerError::System(format!("Failed to delete service: {}", e)))?;
        }

        // Clean up registry entries
        cleanup_registry_entries(label)?;

        // Unregister event source
        unregister_event_source(label)?;

        Ok(())
    }
}
