//! Windows Service Control Manager (SCM) integration for kodegend
//!
//! This module provides the Windows service dispatcher that allows kodegend to run
//! as a native Windows service. It handles:
//! - Service registration with SCM via service_dispatcher::start()
//! - Service control events (Stop, Pause, Continue, Interrogate)
//! - Status reporting throughout service lifecycle
//! - Integration with kodegend's ServiceManager and ServiceStateMachine

use anyhow::{Context, Result};
use crossbeam_channel::{bounded, Sender};
use log::{error, info, warn};
use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

use crate::lifecycle::ServiceLifecycle;
use crate::manager::ServiceManager;

/// Service name for SCM registration
const SERVICE_NAME: &str = "kodegend";

/// Define the Windows service entry point
/// This macro generates the FFI wrapper required by SCM
define_windows_service!(ffi_service_main, service_main);

/// Service main function - called by SCM when service starts
///
/// This function is invoked by the Service Control Manager when the service
/// is started. It runs in a separate thread created by SCM.
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!("kodegend service error: {}", e);
    }
}

/// Core service runtime implementation
///
/// This function:
/// 1. Registers the service control handler with SCM
/// 2. Reports service status changes to SCM
/// 3. Initializes and runs the ServiceManager
/// 4. Handles graceful shutdown on Stop events
fn run_service() -> Result<()> {
    // Create shutdown channel for coordinating service stop
    let (shutdown_tx, shutdown_rx) = bounded::<()>(1);

    // Shared state for service lifecycle
    let lifecycle = Arc::new(Mutex::new(ServiceLifecycle::Starting));

    // Register service control handler with SCM
    let status_handle = register_service_handler(shutdown_tx.clone(), lifecycle.clone())?;

    // Report service is starting
    report_service_status(
        &status_handle,
        ServiceState::StartPending,
        Duration::from_secs(3),
        0,
    )?;

    info!("kodegend Windows service starting...");

    // Initialize ServiceManager
    // The ServiceManager will spawn and manage all MCP server processes
    let service_manager = match ServiceManager::new() {
        Ok(mgr) => {
            info!("ServiceManager initialized successfully");
            mgr
        }
        Err(e) => {
            error!("Failed to initialize ServiceManager: {}", e);
            report_service_status(
                &status_handle,
                ServiceState::Stopped,
                Duration::from_secs(0),
                1,
            )?;
            return Err(e.into());
        }
    };

    // Update lifecycle state
    if let Ok(mut lc) = lifecycle.lock() {
        *lc = ServiceLifecycle::Running;
    }

    // Report service is running
    report_service_status(
        &status_handle,
        ServiceState::Running,
        Duration::from_secs(0),
        0,
    )?;

    info!("kodegend Windows service running");

    // Block until shutdown signal received
    if let Err(e) = shutdown_rx.recv() {
        warn!("Shutdown channel error: {}", e);
    }

    info!("kodegend Windows service stopping...");

    // Update lifecycle state
    if let Ok(mut lc) = lifecycle.lock() {
        *lc = ServiceLifecycle::Stopping;
    }

    // Report service is stopping
    report_service_status(
        &status_handle,
        ServiceState::StopPending,
        Duration::from_secs(5),
        0,
    )?;

    // Perform graceful shutdown of all MCP servers
    if let Err(e) = service_manager.shutdown() {
        error!("Error during ServiceManager shutdown: {}", e);
    }

    // Update lifecycle state
    if let Ok(mut lc) = lifecycle.lock() {
        *lc = ServiceLifecycle::Stopped;
    }

    // Report service stopped
    report_service_status(
        &status_handle,
        ServiceState::Stopped,
        Duration::from_secs(0),
        0,
    )?;

    info!("kodegend Windows service stopped");

    Ok(())
}

/// Register the service control handler with SCM
///
/// Returns a ServiceStatusHandle that can be used to report status changes
fn register_service_handler(
    shutdown_tx: Sender<()>,
    lifecycle: Arc<Mutex<ServiceLifecycle>>,
) -> Result<ServiceStatusHandle> {
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                info!("Received SERVICE_CONTROL_STOP event");

                // Update lifecycle state
                if let Ok(mut lc) = lifecycle.lock() {
                    *lc = ServiceLifecycle::Stopping;
                }

                // Signal shutdown to main service loop
                if let Err(e) = shutdown_tx.send(()) {
                    error!("Failed to send shutdown signal: {}", e);
                    return ServiceControlHandlerResult::Other(1);
                }

                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => {
                // SCM is requesting current status
                // We handle this by just returning NoError
                // The status is already up-to-date from our reports
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Pause => {
                // Pause not currently supported
                info!("Received SERVICE_CONTROL_PAUSE (not implemented)");
                ServiceControlHandlerResult::NotImplemented
            }
            ServiceControl::Continue => {
                // Continue not currently supported
                info!("Received SERVICE_CONTROL_CONTINUE (not implemented)");
                ServiceControlHandlerResult::NotImplemented
            }
            _ => {
                warn!("Received unsupported service control event: {:?}", control_event);
                ServiceControlHandlerResult::NotImplemented
            }
        }
    };

    service_control_handler::register(SERVICE_NAME, event_handler)
        .context("Failed to register service control handler")
}

/// Report service status to SCM
///
/// # Arguments
/// * `status_handle` - Handle for reporting status to SCM
/// * `current_state` - Current service state
/// * `wait_hint` - Estimated time for pending operations
/// * `exit_code` - Service exit code (0 for success)
fn report_service_status(
    status_handle: &ServiceStatusHandle,
    current_state: ServiceState,
    wait_hint: Duration,
    exit_code: u32,
) -> Result<()> {
    let controls_accepted = if current_state == ServiceState::Running {
        ServiceControlAccept::STOP
    } else {
        ServiceControlAccept::empty()
    };

    let status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted,
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    };

    status_handle
        .set_service_status(status)
        .context("Failed to set service status")
}

/// Public entry point for starting kodegend as a Windows service
///
/// This function should be called from main.rs when running in Windows service mode.
/// It invokes the service dispatcher which will call service_main() when SCM starts the service.
pub fn start_windows_service() -> Result<()> {
    info!("Starting kodegend as Windows service...");

    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("Failed to start service dispatcher")?;

    Ok(())
}
