//! Windows daemon control using Service Control Manager (SCM) API

use anyhow::{Context, Result};
use std::mem;
use std::time::Duration;
use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
    StartServiceW, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
    SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP,
};

const SERVICE_NAME: &str = "kodegend";

/// RAII wrapper for SC_HANDLE (Service Control Manager handle)
struct ScManagerHandle(SC_HANDLE);

impl ScManagerHandle {
    fn new() -> Result<Self> {
        let handle = unsafe {
            OpenSCManagerW(
                PCWSTR::null(),
                PCWSTR::null(),
                SC_MANAGER_CONNECT.0,
            )
        };

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

    let handle = unsafe {
        OpenServiceW(
            sc_manager.handle(),
            PCWSTR(service_name.as_ptr()),
            access,
        )
    };

    if handle.is_invalid() {
        anyhow::bail!("Failed to open service: {}", SERVICE_NAME);
    }

    Ok(ServiceHandle(handle))
}

/// Check if daemon is running via QueryServiceStatusEx
///
/// Returns: Ok(true) if service is running, Ok(false) if stopped
pub fn check_status() -> Result<bool> {
    let sc_manager = ScManagerHandle::new()
        .context("Failed to open Service Control Manager for status check")?;

    let service = open_service(&sc_manager, SERVICE_QUERY_STATUS.0)
        .context("Failed to open service for status check")?;

    let mut status: SERVICE_STATUS_PROCESS = unsafe { mem::zeroed() };
    let mut bytes_needed: u32 = 0;

    let result = unsafe {
        QueryServiceStatusEx(
            service.handle(),
            SC_STATUS_PROCESS_INFO,
            Some(&mut status as *mut _ as *mut u8),
            mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        )
    };

    if result.is_err() {
        anyhow::bail!("Failed to query service status");
    }

    // SERVICE_RUNNING = 4, SERVICE_STOPPED = 1
    Ok(status.dwCurrentState == SERVICE_RUNNING.0)
}

/// Start daemon via StartServiceW
pub fn start_daemon() -> Result<()> {
    let sc_manager = ScManagerHandle::new()
        .context("Failed to open Service Control Manager for start")?;

    let service = open_service(&sc_manager, SERVICE_START.0)
        .context("Failed to open service for start")?;

    let result = unsafe {
        StartServiceW(service.handle(), None)
    };

    if result.is_err() {
        anyhow::bail!("Failed to start service");
    }

    Ok(())
}

/// Stop daemon via ControlService
pub fn stop_daemon() -> Result<()> {
    let sc_manager = ScManagerHandle::new()
        .context("Failed to open Service Control Manager for stop")?;

    let service = open_service(&sc_manager, SERVICE_STOP.0)
        .context("Failed to open service for stop")?;

    let mut status: SERVICE_STATUS = unsafe { mem::zeroed() };

    let result = unsafe {
        ControlService(service.handle(), SERVICE_CONTROL_STOP, &mut status)
    };

    if result.is_err() {
        anyhow::bail!("Failed to stop service");
    }

    Ok(())
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
fn wait_for_stopped(timeout: Duration) -> Result<()> {
    let start_time = std::time::Instant::now();
    let mut backoff_ms = 1;

    loop {
        // Check if already stopped
        match check_status() {
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
                std::thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms * 2).min(100);
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
                
                std::thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms * 2).min(100);
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
fn wait_for_active(timeout: Duration) -> Result<()> {
    let start_time = std::time::Instant::now();
    let mut backoff_ms = 1;

    loop {
        // Check if active
        match check_status() {
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
                std::thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms * 2).min(100);
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
                
                std::thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms * 2).min(100);
            }
        }
    }
}

/// Restart daemon (Windows doesn't have native restart - stop + start with verification)
pub fn restart_daemon() -> Result<()> {
    log::info!("Restarting daemon (stop + verify + start + verify)");
    
    // Stop the service
    stop_daemon()
        .context("Failed to stop daemon during restart")?;

    // Wait for service to fully stop (poll Service Control Manager)
    wait_for_stopped(Duration::from_secs(10))
        .context("Service did not stop cleanly within 10 seconds")?;

    // Small delay to ensure resource cleanup (Windows-specific)
    std::thread::sleep(Duration::from_millis(500));

    // Start the service
    start_daemon()
        .context("Failed to start daemon after stop")?;

    // Verify startup succeeded
    wait_for_active(Duration::from_secs(30))
        .context("Service started but did not become active within 30 seconds")?;

    log::info!("Daemon restarted successfully");
    Ok(())
}
