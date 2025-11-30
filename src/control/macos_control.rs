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
/// Returns: Ok(true) if service is loaded and running, Ok(false) otherwise
pub async fn check_status() -> Result<bool> {
    let cmd_display = format!("launchctl list {}", SERVICE_LABEL);
    
    // Log at DEBUG level - only visible with RUST_LOG=debug
    debug!("Executing: {}", cmd_display);
    
    let output = Command::new("launchctl")
        .args(["list", SERVICE_LABEL])
        .output()
        .await
        .with_context(|| format!("Failed to execute: {}", cmd_display))?;

    // launchctl list returns:
    // - Exit 0 if service is loaded (may be running or stopped)
    // - Exit 1 if service not found

    if !output.status.success() {
        info!("Daemon is not loaded");
        return Ok(false); // Service not loaded
    }

    // Parse output to check if PID exists
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Output format: "PID\tStatus\tLabel"
    // If PID is "-", service is loaded but not running
    // If PID is a number, service is running
    for line in stdout.lines() {
        if line.contains(SERVICE_LABEL) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(pid) = parts.first() {
                let is_running = *pid != "-";
                if is_running {
                    info!("Daemon is running");
                } else {
                    info!("Daemon is loaded but not running");
                }
                return Ok(is_running);
            }
        }
    }

    info!("Daemon is stopped");
    Ok(false)
}

/// Start daemon via launchctl
///
/// Idempotent: Returns Ok(()) if service is already running
///
/// Uses modern bootstrap + kickstart with legacy load fallback
pub async fn start_daemon() -> Result<()> {
    // Layer 1: Check if already running (fast path)
    if check_status().await? {
        debug!("Service already running - idempotent success");
        return Ok(());
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
    if !check_status().await? {
        debug!("Service already stopped - idempotent success");
        return Ok(());
    }
    
    // Layer 2: Stop the service
    // Try to kill the service first (graceful shutdown with SIGTERM)
    let kill_cmd = format!("launchctl kill SIGTERM {}", SERVICE_LABEL);
    debug!("Executing: {}", kill_cmd);
    
    let kill_result = Command::new("launchctl")
        .args(["kill", "SIGTERM", SERVICE_LABEL])
        .output()
        .await;
    
    if let Ok(output) = kill_result {
        if output.status.success() {
            debug!("Sent SIGTERM to service");
        }
    }

    // Give it a moment to shutdown gracefully
    sleep(Duration::from_millis(500)).await;

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
