//! macOS daemon control using launchd (launchctl)

use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use tokio::process::Command;
use tokio::time::{sleep, Duration};

use crate::constants::*;

const SERVICE_LABEL: &str = "ai.kodegen.kodegend";
const PLIST_PATH: &str = "/Library/LaunchDaemons/kodegend.plist";

/// Check if daemon is running via launchctl list
///
/// Returns: Ok(ServiceStatus) with PID information when running
///
/// Uses defense-in-depth strategy:
/// 1. Try launchd/launchctl first (authoritative service manager)
/// 2. Fall back to PID file validation if launchctl unavailable or fails
pub async fn check_status() -> Result<crate::daemon::ServiceStatus> {
    use crate::daemon::ServiceStatus;
    
    let cmd_display = format!("launchctl list {}", SERVICE_LABEL);
    debug!("Checking daemon status: {}", cmd_display);
    
    let result = Command::new("launchctl")
        .args(["list", SERVICE_LABEL])
        .output()
        .await;
    
    match result {
        Ok(output) if output.status.success() => {
            // Service is loaded in launchd - parse PID from output
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            for line in stdout.lines() {
                if line.contains(SERVICE_LABEL) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(pid_str) = parts.first() {
                        if *pid_str == "-" {
                            // launchctl shows loaded but not running
                            info!("Daemon is loaded but not running (verified by launchd)");
                            return Ok(ServiceStatus::Stopped);
                        } else if let Ok(pid) = pid_str.parse::<crate::platform::ProcessId>() {
                            // PIDs match - daemon is genuinely running
                            info!("Daemon running with PID {} (verified by launchd)", pid);
                            return Ok(ServiceStatus::Running { pid });
                        } else {
                            // Failed to parse PID - fall back to PID file
                            warn!("Failed to parse PID '{}' from launchctl, using PID file fallback", pid_str);
                            let pid_file = crate::control::generic_control::pid_file_path();
                            return crate::daemon::get_service_status(&pid_file);
                        }
                    }
                }
            }
            
            // No matching line found - service might not be loaded properly
            info!("Service loaded but status unclear, checking PID file");
            let pid_file = crate::control::generic_control::pid_file_path();
            crate::daemon::get_service_status(&pid_file)
        }
        Ok(_output) => {
            // launchctl returned non-zero (service not loaded)
            info!("Service not loaded, checking PID file for stale entries");
            let pid_file = crate::control::generic_control::pid_file_path();
            crate::daemon::get_service_status(&pid_file)
        }
        Err(e) => {
            // launchctl command failed - use PID file fallback
            warn!("launchctl failed ({}), using PID file fallback", e);
            let pid_file = crate::control::generic_control::pid_file_path();
            crate::daemon::get_service_status(&pid_file)
        }
    }
}

/// Start daemon via launchctl
///
/// Idempotent: Returns Ok(()) if service is already running
///
/// Uses modern bootstrap + kickstart with legacy load fallback
pub async fn start_daemon() -> Result<()> {
    // Layer 1: Check if already running (fast path)
    let status = check_status().await?;
    
    if status.is_running() {
        debug!("Service already running - idempotent success");
        return Ok(());
    }
    
    // Handle cleanup cases before starting
    if status.needs_cleanup() {
        match status {
            crate::daemon::ServiceStatus::StaleFile { pid } => {
                warn!("Found stale PID file (PID: {}), will clean up and start", pid);
                // PID file will be overwritten when we start
            }
            crate::daemon::ServiceStatus::InvalidFile { error } => {
                warn!("Found invalid PID file ({}), will clean up and start", error);
                // PID file will be overwritten when we start
            }
            crate::daemon::ServiceStatus::Zombie { pid } => {
                warn!("Found zombie process (PID: {}), force killing before start", pid);
                // Use existing port_cleanup infrastructure to force kill zombie
                crate::service::port_cleanup::force_kill_process(pid as u32).await
                    .context("Failed to force kill zombie process")?;
                info!("Zombie process {} killed, proceeding with start", pid);
                // PID file will be overwritten when we start
            }
            _ => {} // Unreachable due to needs_cleanup() check
        }
    }
    
    // Layer 2: Start the service
    // Try modern bootstrap first (may fail if already loaded - that's OK)
    let bootstrap_cmd = format!("launchctl bootstrap system {}", PLIST_PATH);
    debug!("Executing: {}", bootstrap_cmd);
    
    let bootstrap_result = Command::new("launchctl")
        .args(["bootstrap", "system", PLIST_PATH])
        .output()
        .await;
    
    if let Ok(output) = bootstrap_result {
        if output.status.success() {
            debug!("Service bootstrapped successfully");
        } else {
            // Bootstrap failed - service might already be loaded
            debug!("Bootstrap failed (service may already be loaded): {}", 
                   String::from_utf8_lossy(&output.stderr));
        }
    }

    // Then kickstart to ensure it starts
    let kickstart_cmd = format!("launchctl kickstart {}", SERVICE_LABEL);
    debug!("Executing: {}", kickstart_cmd);
    
    let output = Command::new("launchctl")
        .args(["kickstart", SERVICE_LABEL])
        .output()
        .await
        .with_context(|| format!("Failed to execute: {}", kickstart_cmd))?;

    if !output.status.success() {
        debug!("Kickstart failed, trying legacy load command");
        
        // Fallback to legacy load command
        let load_cmd = format!("launchctl load -w {}", PLIST_PATH);
        warn!("launchctl kickstart failed, trying legacy load");
        debug!("Executing: {}", load_cmd);
        
        let load_output = Command::new("launchctl")
            .args(["load", "-w", PLIST_PATH])
            .output()
            .await
            .with_context(|| format!("Failed to execute: {}", load_cmd))?;

        if !load_output.status.success() {
            let stderr = String::from_utf8_lossy(&load_output.stderr);
            let exit_code = load_output.status.code();
            
            // Log failure details
            error!("Command failed: {}", load_cmd);
            error!("Exit code: {:?}", exit_code);
            error!("Stderr: {}", stderr);
            
            bail!(
                "Failed to start daemon via launchd\n\
                 \n\
                 Command: {}\n\
                 Exit code: {:?}\n\
                 Error: {}\n\
                 \n\
                 Troubleshooting:\n\
                 - Check if service is loaded: launchctl list | grep kodegend\n\
                 - Verify plist exists: ls -la {}\n\
                 - Check plist syntax: plutil -lint {}\n\
                 - View launch logs: log show --predicate 'process == \"kodegend\"' --last 5m\n\
                 - Reinstall service: kodegend install",
                load_cmd, exit_code, stderr, PLIST_PATH, PLIST_PATH
            );
        }
    }

    info!("Daemon started successfully via launchd");
    Ok(())
}

/// Stop daemon via launchctl
///
/// Idempotent: Returns Ok(()) if service is already stopped
///
/// Uses modern kill + bootout with legacy unload fallback
pub async fn stop_daemon() -> Result<()> {
    // Layer 1: Check if already stopped (fast path)
    let status = check_status().await?;
    
    // If not running, handle based on the specific status
    if !status.is_running() {
        match status {
            crate::daemon::ServiceStatus::Stopped => {
                debug!("Service already stopped - idempotent success");
                return Ok(());
            }
            crate::daemon::ServiceStatus::StaleFile { pid } => {
                debug!("Service already stopped (stale PID file: {})", pid);
                return Ok(());
            }
            crate::daemon::ServiceStatus::InvalidFile { error } => {
                debug!("Service already stopped (invalid PID file: {})", error);
                return Ok(());
            }
            crate::daemon::ServiceStatus::Zombie { pid } => {
                warn!("Found zombie process (PID: {}), force killing to clean up", pid);
                crate::service::port_cleanup::force_kill_process(pid as u32).await
                    .context("Failed to force kill zombie process")?;
                info!("Zombie process {} cleaned up", pid);
                return Ok(());
            }
            _ => {} // Unreachable - all non-running states handled above
        }
    }
    
    // Service is running, continue to stop the service
    
    // Layer 2: Stop the service
    // Try to kill the service first (graceful shutdown with SIGTERM)
    let kill_cmd = format!("launchctl kill SIGTERM {}", SERVICE_LABEL);
    debug!("Executing: {}", kill_cmd);
    
    let kill_result = Command::new("launchctl")
        .args(["kill", "SIGTERM", SERVICE_LABEL])
        .output()
        .await;
    
    if let Ok(output) = kill_result
        && output.status.success()
    {
        debug!("Sent SIGTERM to service");
    }

    // Give it a moment to shutdown gracefully
    sleep(POST_SIGTERM_DELAY).await;

    // Then bootout to unload it
    let bootout_cmd = format!("launchctl bootout system {}", PLIST_PATH);
    debug!("Executing: {}", bootout_cmd);
    
    let output = Command::new("launchctl")
        .args(["bootout", "system", PLIST_PATH])
        .output()
        .await
        .with_context(|| format!("Failed to execute: {}", bootout_cmd))?;

    if !output.status.success() {
        debug!("Bootout failed, trying legacy unload command");
        
        // Fallback to legacy unload
        let unload_cmd = format!("launchctl unload -w {}", PLIST_PATH);
        warn!("launchctl bootout failed, trying legacy unload");
        debug!("Executing: {}", unload_cmd);
        
        let unload_output = Command::new("launchctl")
            .args(["unload", "-w", PLIST_PATH])
            .output()
            .await
            .with_context(|| format!("Failed to execute: {}", unload_cmd))?;

        if !unload_output.status.success() {
            let stderr = String::from_utf8_lossy(&unload_output.stderr);
            let exit_code = unload_output.status.code();
            
            // Log failure details
            error!("Command failed: {}", unload_cmd);
            error!("Exit code: {:?}", exit_code);
            error!("Stderr: {}", stderr);
            
            bail!(
                "Failed to stop daemon via launchd\n\
                 \n\
                 Command: {}\n\
                 Exit code: {:?}\n\
                 Error: {}\n\
                 \n\
                 Troubleshooting:\n\
                 - Check if service is running: launchctl list | grep kodegend\n\
                 - View service logs: log show --predicate 'process == \"kodegend\"' --last 5m\n\
                 - Force remove if needed: sudo launchctl remove {}\n\
                 - Check for stuck processes: ps aux | grep kodegend\n\
                 - Verify plist exists: ls -la {}",
                unload_cmd, exit_code, stderr, SERVICE_LABEL, PLIST_PATH
            );
        }
    }

    info!("Daemon stopped successfully via launchd");
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
async fn wait_for_stopped(timeout: Duration) -> Result<()> {
    let start_time = std::time::Instant::now();
    let mut backoff_ms = BACKOFF_INITIAL_DELAY_MS;

    loop {
        // Check if already stopped
        match check_status().await {
            Ok(status) => {
                // If not running, we're done (either stopped cleanly or needs cleanup)
                if !status.is_running() {
                    // Handle zombie case specially - force kill it
                    if let crate::daemon::ServiceStatus::Zombie { pid } = status {
                        log::warn!("Daemon is zombie (PID: {}), force killing", pid);
                        crate::service::port_cleanup::force_kill_process(pid as u32).await
                            .context("Failed to force kill zombie during wait_for_stopped")?;
                    }
                    return Ok(()); // Stopped successfully (or cleaned up)
                }
                
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
            Ok(status) => {
                // If running, we're done
                if status.is_running() {
                    return Ok(()); // Active successfully
                }
                
                // Handle zombie case specially - force kill it before continuing
                if let crate::daemon::ServiceStatus::Zombie { pid } = status {
                    log::warn!("Found zombie process (PID: {}) while waiting for active, force killing", pid);
                    crate::service::port_cleanup::force_kill_process(pid as u32).await
                        .context("Failed to force kill zombie during wait_for_active")?;
                }
                
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

/// Restart daemon via launchctl
///
/// Uses kickstart -k (kill flag) with manual stop+start fallback that includes verification
pub async fn restart_daemon() -> Result<()> {
    // Try modern kickstart with -k (kill) flag which restarts the service
    let kickstart_cmd = format!("launchctl kickstart -k {}", SERVICE_LABEL);
    debug!("Executing: {}", kickstart_cmd);
    
    let output = Command::new("launchctl")
        .args(["kickstart", "-k", SERVICE_LABEL])
        .output()
        .await
        .with_context(|| format!("Failed to execute: {}", kickstart_cmd))?;

    if !output.status.success() {
        debug!("Kickstart -k failed, using manual stop+start fallback");
        
        // Fallback: manual stop + start with proper verification
        warn!("launchctl kickstart -k failed, using manual stop+start fallback");

        stop_daemon().await.context("Failed to stop daemon during restart")?;

        wait_for_stopped(GRACEFUL_SHUTDOWN_TIMEOUT).await
            .context("Daemon did not stop cleanly within timeout")?;

        // Small delay to ensure port release (launchd-specific timing)
        sleep(PORT_RELEASE_DELAY).await;

        start_daemon().await.context("Failed to start daemon after stop")?;

        wait_for_active(STARTUP_VERIFICATION_TIMEOUT).await
            .context("Daemon started but did not become active within timeout")?;

        info!("Daemon restarted successfully via fallback path");
    } else {
        info!("Daemon restarted successfully via launchctl kickstart -k");
    }

    Ok(())
}
