//! Windows platform implementation using Service Control Manager and native Windows APIs.
//!
//! This implementation provides sophisticated service management with zero allocation,
//! blazing-fast performance, and comprehensive error handling to match the macOS implementation.

use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context, Result};
use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows::Win32::System::Services::{
    OpenSCManagerW, SC_MANAGER_ALL_ACCESS,
};
use windows::core::PCWSTR;

use super::{InstallerBuilder, InstallerError};

mod handles;
mod privileges;
mod registry;
mod service_creation;
mod utils;

use handles::{ScManagerHandle, ServiceHandle};
use privileges::{check_privileges, ensure_helper_path, HELPER_PATH, HELPER_EXTRACTION_LOCK};
use registry::{
    create_registry_entries, cleanup_registry_entries,
    register_event_source, unregister_event_source,
};
use service_creation::{
    create_service, configure_service_description, configure_failure_actions,
    configure_delayed_start, configure_service_sid,
    start_service, stop_service, open_service, install_services,
};
use utils::{str_to_wide, MAX_SERVICE_NAME};

pub(crate) struct PlatformExecutor;

// Atomic state for service operations
static SERVICE_OPERATION_STATE: AtomicU32 = AtomicU32::new(0);

impl ScManagerHandle {
    #[inline]
    fn new() -> Result<Self, InstallerError> {
        let handle =
            unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) };

        if handle.is_invalid() {
            return Err(InstallerError::System(format!(
                "Failed to open Service Control Manager: {}",
                unsafe { windows::Win32::Foundation::GetLastError().0 }
            )));
        }

        Ok(Self(handle))
    }
}

impl PlatformExecutor {
    /// Install the daemon as a Windows service with comprehensive configuration
    pub fn install(b: InstallerBuilder) -> Result<(), InstallerError> {
        // Ensure helper path is initialized
        ensure_helper_path()?;

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
