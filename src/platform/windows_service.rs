//! Windows Service Control Manager (SCM) integration for kodegend
//!
//! This module provides the Windows service dispatcher that allows kodegend to run
//! as a native Windows service. It handles:
//! - Service registration with SCM via service_dispatcher::start()
//! - Service control events (Stop, Pause, Continue, Interrogate)
//! - Status reporting throughout service lifecycle
//! - Integration with kodegend's ServiceManager and ServiceStateMachine

use anyhow::{Context, Result};
use crossbeam_channel::{Sender, bounded};
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

use crate::state_machine::State as ServiceLifecycle;
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
/// This function implements the Windows service lifecycle:
/// 1. Creates tokio runtime for async operations
/// 2. Registers service control handler with SCM
/// 3. Reports service status changes to SCM with appropriate wait_hint values
/// 4. Initializes and runs ServiceManager in background task
/// 5. Blocks on shutdown signal from SCM
/// 6. Triggers graceful shutdown with 5-second timeout matching wait_hint
/// 7. Handles timeout by logging error (SCM will force-kill after 30s total)
/// 
/// # SCM Interaction Protocol
/// 
/// Windows SCM requires specific status reporting sequence:
/// - StartPending → Running: Must complete within wait_hint (3 seconds)
/// - StopPending → Stopped: Must complete within wait_hint (5 seconds)
/// - If wait_hint expires: SCM sends TerminateProcess (force-kill)
/// 
/// See: https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager
fn run_service() -> Result<()> {
    // Create shutdown channel for coordinating service stop
    // SCM sends stop events to control handler, which signals via this channel
    let (shutdown_tx, shutdown_rx) = bounded::<()>(1);

    // Shared state for service lifecycle tracking
    // Used by control handler to update state when SCM sends control events
    let lifecycle = Arc::new(Mutex::new(ServiceLifecycle::Starting));

    // Register service control handler with SCM
    // This handler receives SERVICE_CONTROL_STOP, PAUSE, etc. events
    let status_handle = register_service_handler(shutdown_tx.clone(), lifecycle.clone())?;

    // Report service is starting (3-second wait_hint for initialization)
    // SCM will wait up to 3 seconds for us to report Running status
    report_service_status(
        &status_handle,
        ServiceState::StartPending,
        Duration::from_secs(3),
        0,  // exit_code: 0 = success
    )?;

    info!("kodegend Windows service starting...");

    // Load configuration from standard Windows location
    // Platform-specific paths: C:\ProgramData\kodegend or %APPDATA%\kodegend
    let config_path = crate::platform::system_config_dir().join("kodegend.toml");
    
    // Load config with graceful fallback to defaults
    // If config file missing/corrupt, use default config to ensure service starts
    let config = if config_path.exists() {
        match crate::config::ServiceConfig::load_from_file(&config_path) {
            Ok(cfg) => {
                info!("Loaded configuration from: {}", config_path.display());
                cfg
            }
            Err(e) => {
                warn!("Failed to load config from {} ({}), using defaults", 
                    config_path.display(), e);
                crate::config::ServiceConfig::default()
            }
        }
    } else {
        info!("No config file at {}, using defaults", config_path.display());
        crate::config::ServiceConfig::default()
    };

    // Initialize ServiceManager with loaded config
    // This creates worker channels and prepares for service startup
    let service_manager = match ServiceManager::new(config) {
        Ok(mgr) => {
            info!("ServiceManager initialized successfully");
            mgr
        }
        Err(e) => {
            error!("Failed to initialize ServiceManager: {}", e);
            // Report failure to SCM with exit code 1
            report_service_status(
                &status_handle,
                ServiceState::Stopped,
                Duration::from_secs(0),
                1,  // exit_code: 1 = initialization failed
            )?;
            return Err(e);
        }
    };

    // Get ServiceManager's shutdown sender BEFORE moving it into the thread
    // This allows us to signal the manager to stop after receiving SCM stop event
    let mgr_shutdown_tx = service_manager.get_shutdown_sender();

    // Spawn ServiceManager::run() in a dedicated thread with its own runtime
    // We use std::thread instead of tokio::spawn because:
    // 1. run() consumes self (takes ownership)
    // 2. crossbeam's select! macro creates non-Send futures
    // 3. The SCM handler thread needs to remain responsive
    let run_handle = std::thread::spawn(move || {
        // Create runtime inside the thread to avoid Send requirements
        let thread_rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                error!("Failed to create runtime in manager thread: {}", e);
                return;
            }
        };

        thread_rt.block_on(async move {
            if let Err(e) = service_manager.run().await {
                error!("ServiceManager run() error: {}", e);
            }
        });
    });

    // Update lifecycle state to Running
    if let Ok(mut lc) = lifecycle.lock() {
        *lc = ServiceLifecycle::Running;
    }

    // Report service is running to SCM
    // wait_hint = 0 means we're in steady state (no pending operations)
    report_service_status(
        &status_handle,
        ServiceState::Running,
        Duration::from_secs(0),
        0,
    )?;

    info!("kodegend Windows service running");

    // Block until shutdown signal received from SCM
    // This keeps the service thread alive while ServiceManager runs in background
    // Control handler sends () on this channel when SCM sends SERVICE_CONTROL_STOP
    if let Err(e) = shutdown_rx.recv() {
        warn!("Shutdown channel error: {}", e);
    }

    info!("kodegend Windows service stopping...");

    // Update lifecycle state to Stopping
    if let Ok(mut lc) = lifecycle.lock() {
        *lc = ServiceLifecycle::Stopping;
    }

    // Report service is stopping with 5-second wait_hint
    // SCM will wait 5 seconds for us to report Stopped status
    // If we exceed 5 seconds, SCM may force-kill (but gives us until ~30s total)
    report_service_status(
        &status_handle,
        ServiceState::StopPending,
        Duration::from_secs(5),
        0,
    )?;

    // Send shutdown signal to ServiceManager via the cloned sender
    // This triggers the run() loop to break and begin cleanup
    info!("Sending shutdown signal to ServiceManager");
    if let Err(e) = mgr_shutdown_tx.send(()) {
        error!("Failed to send shutdown signal: {}", e);
    } else {
        info!("Shutdown signal sent successfully");
    }

    // Wait for manager thread to complete with 5-second timeout
    // Timeout MUST match wait_hint above to prevent SCM force-kill
    //
    // Shutdown sequence in run() loop:
    // 1. Receives shutdown signal on channel
    // 2. Breaks from select! loop
    // 3. Shuts down embedded HTTP servers
    // 4. Sends Shutdown to all workers
    // 5. Waits for worker termination
    // 6. run() returns
    //
    // We use a simple polling approach since std::thread::JoinHandle
    // doesn't have native timeout support
    let timeout_deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if run_handle.is_finished() {
            match run_handle.join() {
                Ok(()) => {
                    info!("ServiceManager shutdown completed successfully");
                }
                Err(_) => {
                    error!("ServiceManager thread panicked");
                }
            }
            break;
        }

        if std::time::Instant::now() >= timeout_deadline {
            error!("ServiceManager shutdown timed out after 5 seconds");
            error!("One or more MCP servers failed to stop gracefully");
            error!("Windows SCM may force-kill this process in ~25 seconds");
            // Note: We don't return error here - allow service to report Stopped
            // SCM will force-kill if we exceed the 30-second absolute deadline
            // Better to report Stopped cleanly than leave service in StopPending limbo
            break;
        }

        // Brief sleep to avoid busy-waiting
        std::thread::sleep(Duration::from_millis(50));
    }

    // Update lifecycle state to Stopped
    if let Ok(mut lc) = lifecycle.lock() {
        *lc = ServiceLifecycle::Stopped;
    }

    // Report service stopped to SCM
    // wait_hint = 0 means we're done (no more pending operations)
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
                warn!(
                    "Received unsupported service control event: {:?}",
                    control_event
                );
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
