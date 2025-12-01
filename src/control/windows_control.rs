//! Windows daemon control using Service Control Manager (SCM) API

use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use std::mem;
use tokio::time::{sleep, Duration};

use crate::constants::*;
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
    SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_CONTROL_STOP,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
    SERVICE_STOP, StartServiceW,
};
use windows::core::PCWSTR;

const SERVICE_NAME: &str = "kodegend";

// Windows error code constants for idempotency
const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;  // 0x420
const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;       // 0x426

/// RAII wrapper for SC_HANDLE (Service Control Manager handle)
struct ScManagerHandle(SC_HANDLE);

impl ScManagerHandle {
    fn new() -> Result<Self> {
        let handle =
            unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT.0) };

        if handle.is_invalid() {
            anyhow::bail!("Failed to open Service Control Manager");
        }

        Ok(ScManagerHandle(handle))
    }

    fn handle(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for ScManagerHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

/// RAII wrapper for SC_HANDLE (Service handle)
struct ServiceHandle(SC_HANDLE);

impl ServiceHandle {
    fn handle(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

/// Open a service with the specified access rights
fn open_service(sc_manager: &ScManagerHandle, access: u32) -> Result<ServiceHandle> {
    let service_name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();

    let handle =
        unsafe { OpenServiceW(sc_manager.handle(), PCWSTR(service_name.as_ptr()), access) };

    if handle.is_invalid() {
        anyhow::bail!("Failed to open service: {}", SERVICE_NAME);
    }

    Ok(ServiceHandle(handle))
}

/// Check if daemon is running via QueryServiceStatusEx
///
/// Returns: Ok(ServiceStatus) with PID information when running
///
/// Uses defense-in-depth strategy:
/// 1. Try Windows Service Control Manager (SCM) first (authoritative service manager)
/// 2. Fall back to PID file validation if SCM unavailable or fails
pub async fn check_status() -> Result<crate::daemon::ServiceStatus> {
    use crate::daemon::ServiceStatus;
    
    let result = tokio::task::spawn_blocking(|| {
        debug!("Checking daemon status via Windows SCM");
        
        let sc_manager = ScManagerHandle::new()
            .context("Failed to open Service Control Manager")?;

        debug!("Opening service '{}' for status query", SERVICE_NAME);
        let service = open_service(&sc_manager, SERVICE_QUERY_STATUS.0)
            .context("Failed to open service")?;

        let mut status: SERVICE_STATUS_PROCESS = unsafe { mem::zeroed() };
        let mut bytes_needed: u32 = 0;

        debug!("Querying service status via QueryServiceStatusEx");
        let query_result = unsafe {
            QueryServiceStatusEx(
                service.handle(),
                SC_STATUS_PROCESS_INFO,
                Some(&mut status as *mut _ as *mut u8),
                mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut bytes_needed,
            )
        };

        if let Err(e) = query_result {
            let error_code = unsafe { windows::Win32::Foundation::GetLastError() };
            error!("QueryServiceStatusEx failed for service '{}'", SERVICE_NAME);
            error!("Error code: {:?}", error_code);
            bail!("QueryServiceStatusEx failed: {}", e);
        }

        // Extract status from SERVICE_STATUS_PROCESS structure
        let service_status = match status.dwCurrentState {
            state if state == SERVICE_RUNNING.0 => {
                let pid = status.dwProcessId as crate::platform::ProcessId;
                info!("Daemon running with PID {} (verified by Windows SCM)", pid);
                ServiceStatus::Running { pid }
            }
            state if state == SERVICE_STOPPED.0 => {
                info!("Daemon is stopped (verified by Windows SCM)");
                ServiceStatus::Stopped
            }
            _ => {
                info!("Daemon is in non-running state: {} (verified by Windows SCM)", status.dwCurrentState);
                ServiceStatus::Stopped
            }
        };

        Ok(service_status)
    })
    .await
    .context("Failed to spawn blocking task for check_status")?;

    match result {
        Ok(status) => Ok(status),
        Err(e) => {
            // SCM query failed - use PID file fallback
            warn!("Windows SCM query failed ({}), using PID file fallback", e);
            let pid_file = crate::control::generic_control::pid_file_path();
            crate::daemon::get_service_status(&pid_file)
        }
    }
}

/// Start daemon via StartServiceW
///
/// Idempotent: Returns Ok(()) if service is already running
///
/// Uses two-layer defense:
/// - Layer 1: Check status before starting
/// - Layer 2: Handle ERROR_SERVICE_ALREADY_RUNNING from race conditions
pub async fn start_daemon() -> Result<()> {
    // Layer 1: Check if already running (fast path)
    if check_status().await? {
        debug!("Service already running - idempotent success");
        return Ok(());
    }
    
    // Layer 2: Attempt to start the service
    tokio::task::spawn_blocking(|| {
        debug!("Opening Service Control Manager for service start");
        let sc_manager =
            ScManagerHandle::new().context("Failed to open Service Control Manager for start")?;

        debug!("Opening service '{}' with SERVICE_START access", SERVICE_NAME);
        let service =
            open_service(&sc_manager, SERVICE_START.0).context("Failed to open service for start")?;

        debug!("Starting Windows service '{}' via StartServiceW", SERVICE_NAME);
        let result = unsafe { StartServiceW(service.handle(), None) };

        // Layer 3: Handle result and race conditions
        if let Err(e) = result {
            // Extract Win32 error code from HRESULT
            // HRESULT format for Win32 errors: 0x8007xxxx where xxxx is the error code
            // Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
            let hresult = e.code();
            let win32_error = hresult.0 as u32 & 0xFFFF;
            
            // ERROR_SERVICE_ALREADY_RUNNING means service started between our check and StartServiceW call
            // This is a race condition, not an error - return success for idempotency
            if win32_error == ERROR_SERVICE_ALREADY_RUNNING {
                debug!("Service already running (race condition) - idempotent success");
                return Ok(());
            }
            
            // Log failure details
            error!("StartServiceW failed for service '{}'", SERVICE_NAME);
            error!("Win32 error code: {}", win32_error);
            error!("HRESULT: 0x{:08X}", hresult.0);
            error!("Error message: {}", e.message());
            
            // Any other error is a genuine failure with comprehensive troubleshooting
            bail!(
                "Failed to start Windows service '{}'\n\
                 \n\
                 API Call: StartServiceW\n\
                 Win32 Error Code: {}\n\
                 HRESULT: 0x{:08X}\n\
                 Error: {}\n\
                 \n\
                 Troubleshooting:\n\
                 - Check service exists: sc query {}\n\
                 - Check service status: sc queryex {}\n\
                 - View event logs: Get-EventLog -LogName Application -Source {} -Newest 10\n\
                 - Check service config: sc qc {}\n\
                 - Verify permissions: Run as Administrator\n\
                 - Reinstall service: kodegend install (as Administrator)",
                SERVICE_NAME, win32_error, hresult.0, e.message(),
                SERVICE_NAME, SERVICE_NAME, SERVICE_NAME, SERVICE_NAME
            );
        }

        info!("Windows service '{}' started successfully", SERVICE_NAME);
        Ok(())
    })
    .await
    .context("Failed to spawn blocking task for start_daemon")?
}

/// Stop daemon via ControlService
///
/// Idempotent: Returns Ok(()) if service is already stopped
///
/// Uses two-layer defense:
/// - Layer 1: Check status before stopping
/// - Layer 2: Handle ERROR_SERVICE_NOT_ACTIVE from race conditions
pub async fn stop_daemon() -> Result<()> {
    // Layer 1: Check if already stopped (fast path)
    if !check_status().await? {
        debug!("Service already stopped - idempotent success");
        return Ok(());
    }
    
    // Layer 2: Attempt to stop the service
    tokio::task::spawn_blocking(|| {
        debug!("Opening Service Control Manager for service stop");
        let sc_manager =
            ScManagerHandle::new().context("Failed to open Service Control Manager for stop")?;

        debug!("Opening service '{}' with SERVICE_STOP access", SERVICE_NAME);
        let service =
            open_service(&sc_manager, SERVICE_STOP.0).context("Failed to open service for stop")?;

        let mut status: SERVICE_STATUS = unsafe { mem::zeroed() };

        debug!("Stopping Windows service '{}' via ControlService", SERVICE_NAME);
        let result = unsafe { ControlService(service.handle(), SERVICE_CONTROL_STOP, &mut status) };

        // Layer 3: Handle result and race conditions
        if let Err(e) = result {
            // Extract Win32 error code from HRESULT
            let hresult = e.code();
            let win32_error = hresult.0 as u32 & 0xFFFF;
            
            // ERROR_SERVICE_NOT_ACTIVE means service stopped between our check and ControlService call
            // This is a race condition, not an error - return success for idempotency
            if win32_error == ERROR_SERVICE_NOT_ACTIVE {
                debug!("Service already stopped (race condition) - idempotent success");
                return Ok(());
            }
            
            // Log failure details
            error!("ControlService failed for service '{}'", SERVICE_NAME);
            error!("Win32 error code: {}", win32_error);
            error!("HRESULT: 0x{:08X}", hresult.0);
            error!("Error message: {}", e.message());
            
            // Any other error is a genuine failure with comprehensive troubleshooting
            bail!(
                "Failed to stop Windows service '{}'\n\
                 \n\
                 API Call: ControlService(SERVICE_CONTROL_STOP)\n\
                 Win32 Error Code: {}\n\
                 HRESULT: 0x{:08X}\n\
                 Error: {}\n\
                 \n\
                 Troubleshooting:\n\
                 - Check service status: sc queryex {}\n\
                 - View event logs: Get-EventLog -LogName Application -Source {} -Newest 10\n\
                 - Force stop if needed: sc stop {}\n\
                 - Check for stuck processes: Get-Process | Where-Object {{$_.Name -like '*kodegend*'}}\n\
                 - Verify permissions: Run as Administrator",
                SERVICE_NAME, win32_error, hresult.0, e.message(),
                SERVICE_NAME, SERVICE_NAME, SERVICE_NAME
            );
        }

        info!("Windows service '{}' stopped successfully", SERVICE_NAME);
        Ok(())
    })
    .await
    .context("Failed to spawn blocking task for stop_daemon")?
}

/// Wait for daemon to fully stop (check_status returns false)
///
/// Uses exponential backoff pattern from autoconfig.rs for efficiency.
/// Polls check_status() until it returns false (stopped) or timeout expires.
///
/// # Arguments
/// * `timeout` - Maximum time to wait for daemon to stop
///
/// # Returns
/// * `Ok(())` if daemon stopped within timeout
/// * `Err()` if timeout expired or status check failed persistently
async fn wait_for_stopped(timeout: Duration) -> Result<()> {
    let start_time = std::time::Instant::now();
    let mut backoff_ms = BACKOFF_INITIAL_DELAY_MS;

    loop {
        // Check if already stopped
        match check_status().await {
            Ok(false) => return Ok(()), // Stopped successfully
            Ok(true) => {
                // Still running, continue waiting
                if start_time.elapsed() > timeout {
                    anyhow::bail!(
                        "Daemon did not stop within {:?}. Manual intervention may be required.",
                        timeout
                    );
                }

                // Exponential backoff sleep (1ms → 2ms → 4ms → ... → 100ms cap)
                sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(BACKOFF_MAX_DELAY_MS);
            }
            Err(e) => {
                // If check_status fails, we can't determine state
                // Log warning but continue - might be already stopped
                log::warn!("Failed to check daemon status during shutdown: {}", e);

                if start_time.elapsed() > timeout {
                    return Err(e).context(format!(
                        "Timeout waiting for daemon to stop ({:?}), and status check failed",
                        timeout
                    ));
                }

                sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(BACKOFF_MAX_DELAY_MS);
            }
        }
    }
}

/// Wait for daemon to become active (check_status returns true)
///
/// Uses exponential backoff pattern from autoconfig.rs for efficiency.
/// Polls check_status() until it returns true (running) or timeout expires.
///
/// # Arguments
/// * `timeout` - Maximum time to wait for daemon to become active
///
/// # Returns
/// * `Ok(())` if daemon became active within timeout
/// * `Err()` if timeout expired or status check failed persistently
async fn wait_for_active(timeout: Duration) -> Result<()> {
    let start_time = std::time::Instant::now();
    let mut backoff_ms = BACKOFF_INITIAL_DELAY_MS;

    loop {
        // Check if active
        match check_status().await {
            Ok(true) => return Ok(()), // Active successfully
            Ok(false) => {
                // Not running yet, continue waiting
                if start_time.elapsed() > timeout {
                    anyhow::bail!(
                        "Daemon did not become active within {:?}. Check logs for startup errors.",
                        timeout
                    );
                }

                // Exponential backoff sleep (1ms → 2ms → 4ms → ... → 100ms cap)
                sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(BACKOFF_MAX_DELAY_MS);
            }
            Err(e) => {
                // If check_status fails during startup, that's a problem
                if start_time.elapsed() > timeout {
                    anyhow::bail!(
                        "Daemon startup verification failed after {:?}: {}",
                        timeout,
                        e
                    );
                }

                sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(BACKOFF_MAX_DELAY_MS);
            }
        }
    }
}

/// Restart daemon (Windows doesn't have native restart - stop + start with verification)
pub async fn restart_daemon() -> Result<()> {
    info!("Restarting daemon (stop + verify + start + verify)");
    debug!("Windows service restart: executing stop-then-start sequence");

    // Stop the service
    debug!("Step 1: Stopping service");
    stop_daemon().await.context("Failed to stop daemon during restart")?;

    // Wait for service to fully stop (poll Service Control Manager)
    debug!("Step 2: Waiting for service to fully stop (timeout: {:?})", GRACEFUL_SHUTDOWN_TIMEOUT);
    wait_for_stopped(GRACEFUL_SHUTDOWN_TIMEOUT).await
        .context("Service did not stop cleanly within timeout")?;

    // Small delay to ensure resource cleanup (Windows-specific)
    debug!("Step 3: Waiting for resource cleanup (delay: {:?})", PORT_RELEASE_DELAY);
    sleep(PORT_RELEASE_DELAY).await;

    // Start the service
    debug!("Step 4: Starting service");
    start_daemon().await.context("Failed to start daemon after stop")?;

    // Verify startup succeeded
    debug!("Step 5: Verifying service became active (timeout: {:?})", STARTUP_VERIFICATION_TIMEOUT);
    wait_for_active(STARTUP_VERIFICATION_TIMEOUT).await
        .context("Service started but did not become active within timeout")?;

    info!("Windows service '{}' restarted successfully", SERVICE_NAME);
    Ok(())
}
