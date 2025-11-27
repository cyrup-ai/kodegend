//! macOS daemon control using launchd (launchctl)

use anyhow::{Context, Result};
use std::process::Command;
use std::time::Duration;

const SERVICE_LABEL: &str = "ai.kodegen.kodegend";
const PLIST_PATH: &str = "/Library/LaunchDaemons/kodegend.plist";

/// Check if daemon is running via launchctl list
///
/// Returns: Ok(true) if service is loaded and running, Ok(false) otherwise
pub fn check_status() -> Result<bool> {
    let output = Command::new("launchctl")
        .args(["list", SERVICE_LABEL])
        .output()
        .context("Failed to execute launchctl list")?;

    // launchctl list returns:
    // - Exit 0 if service is loaded (may be running or stopped)
    // - Exit 1 if service not found
    
    if !output.status.success() {
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
                return Ok(*pid != "-");
            }
        }
    }

    Ok(false)
}

/// Start daemon via launchctl
///
/// Uses modern kickstart command with legacy load fallback
pub fn start_daemon() -> Result<()> {
    // Try modern bootstrap first (may fail if already loaded - that's OK)
    let _ = Command::new("launchctl")
        .args(["bootstrap", "system", PLIST_PATH])
        .output();

    // Then kickstart to ensure it starts
    let output = Command::new("launchctl")
        .args(["kickstart", SERVICE_LABEL])
        .output()
        .context("Failed to execute launchctl kickstart")?;

    if !output.status.success() {
        // Fallback to legacy load command
        let load_output = Command::new("launchctl")
            .args(["load", "-w", PLIST_PATH])
            .output()
            .context("Failed to execute launchctl load")?;

        if !load_output.status.success() {
            anyhow::bail!(
                "Failed to start daemon: {}",
                String::from_utf8_lossy(&load_output.stderr)
            );
        }
    }

    Ok(())
}

/// Stop daemon via launchctl
///
/// Uses modern kill + bootout with legacy unload fallback
pub fn stop_daemon() -> Result<()> {
    // Try to kill the service first (graceful shutdown)
    let _ = Command::new("launchctl")
        .args(["kill", "SIGTERM", SERVICE_LABEL])
        .output();

    // Give it a moment to shutdown gracefully
    std::thread::sleep(Duration::from_millis(500));

    // Then bootout
    let output = Command::new("launchctl")
        .args(["bootout", "system", PLIST_PATH])
        .output()
        .context("Failed to execute launchctl bootout")?;

    if !output.status.success() {
        // Fallback to legacy unload
        let unload_output = Command::new("launchctl")
            .args(["unload", "-w", PLIST_PATH])
            .output()
            .context("Failed to execute launchctl unload")?;

        if !unload_output.status.success() {
            anyhow::bail!(
                "Failed to stop daemon: {}",
                String::from_utf8_lossy(&unload_output.stderr)
            );
        }
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

/// Restart daemon via launchctl
///
/// Uses kickstart -k (kill flag) with manual stop+start fallback that includes verification
pub fn restart_daemon() -> Result<()> {
    // Try modern kickstart with -k (kill) flag which restarts the service
    let output = Command::new("launchctl")
        .args(["kickstart", "-k", SERVICE_LABEL])
        .output()
        .context("Failed to execute launchctl kickstart -k")?;

    if !output.status.success() {
        // Fallback: manual stop + start with proper verification
        log::warn!("launchctl kickstart -k failed, using manual stop+start fallback");
        
        stop_daemon()
            .context("Failed to stop daemon during restart")?;
        
        wait_for_stopped(Duration::from_secs(10))
            .context("Daemon did not stop cleanly within 10 seconds")?;
        
        // Small delay to ensure port release (launchd-specific timing)
        std::thread::sleep(Duration::from_millis(500));
        
        start_daemon()
            .context("Failed to start daemon after stop")?;
        
        wait_for_active(Duration::from_secs(30))
            .context("Daemon started but did not become active within 30 seconds")?;
        
        log::info!("Daemon restarted successfully via fallback path");
    }

    Ok(())
}
