//! Linux daemon control using systemd (systemctl)

use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use tokio::process::Command;

const SERVICE_NAME: &str = "kodegend";

/// Check if daemon is running via systemctl
///
/// Returns: Ok(ServiceStatus) with PID information when running
///
/// Uses defense-in-depth strategy:
/// 1. Try systemd/systemctl first (authoritative service manager)
/// 2. Fall back to PID file validation if systemd unavailable or fails
pub async fn check_status() -> Result<crate::daemon::ServiceStatus> {
    use crate::daemon::ServiceStatus;
    use crate::platform;
    
    // Attempt systemd check first
    if !platform::is_systemd_available() {
        warn!("systemd not available, using PID file fallback");
        let pid_file = crate::control::generic_control::pid_file_path();
        return crate::daemon::get_service_status(&pid_file);
    }
    
    let service_name = format!("{}.service", SERVICE_NAME);
    let args_active = if is_root() {
        vec!["is-active", &service_name]
    } else {
        vec!["--user", "is-active", &service_name]
    };
    
    let cmd_display = format!("systemctl {}", args_active.join(" "));
    debug!("Checking daemon status: {}", cmd_display);
    
    // Try systemctl is-active
    let result_active = Command::new("systemctl")
        .args(&args_active)
        .output()
        .await;
    
    match result_active {
        Ok(output) if output.status.success() => {
            // Service is active according to systemd - get detailed status with PID
            let args_status = if is_root() {
                vec!["status", &service_name]
            } else {
                vec!["--user", "status", &service_name]
            };

            let result_status = Command::new("systemctl")
                .args(&args_status)
                .output()
                .await;

            match result_status {
                Ok(status_output) => {
                    let stdout = String::from_utf8_lossy(&status_output.stdout);
                    
                    // Parse "Main PID: 12345 (kodegend)"
                    for line in stdout.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("Main PID:") {
                            let parts: Vec<&str> = trimmed.split_whitespace().collect();
                            if parts.len() >= 3 {
                                let pid_str = parts[2];
                                let pid_num = pid_str.split('(').next().unwrap_or(pid_str).trim();
                                
                                if let Ok(pid) = pid_num.parse::<crate::platform::ProcessId>() {
                                    info!("Daemon running with PID {} (verified by systemd)", pid);
                                    return Ok(ServiceStatus::Running { pid });
                                }
                            }
                        }
                    }
                    
                    // Could not parse PID from systemctl output - fall back to PID file
                    warn!("Failed to parse PID from systemctl output, using PID file fallback");
                    let pid_file = crate::control::generic_control::pid_file_path();
                    crate::daemon::get_service_status(&pid_file)
                }
                Err(e) => {
                    // systemctl status command failed - fall back to PID file
                    warn!("systemctl status failed ({}), using PID file fallback", e);
                    let pid_file = crate::control::generic_control::pid_file_path();
                    crate::daemon::get_service_status(&pid_file)
                }
            }
        }
        Ok(_output) => {
            // Service is not active according to systemd
            info!("Daemon is stopped (verified by systemd)");
            Ok(ServiceStatus::Stopped)
        }
        Err(e) => {
            // systemctl command failed completely - use PID file fallback
            warn!("systemctl failed ({}), using PID file fallback", e);
            let pid_file = crate::control::generic_control::pid_file_path();
            crate::daemon::get_service_status(&pid_file)
        }
    }
}

/// Start daemon via systemctl start
///
/// Idempotent: Returns Ok(()) if service is already running
pub async fn start_daemon() -> Result<()> {
    use crate::platform;
    
    if !platform::is_systemd_available() {
        bail!("systemd not available - cannot use systemctl commands");
    }
    
    // Layer 1: Check if already running (fast path)
    if check_status().await? {
        debug!("Service already running - idempotent success");
        return Ok(());
    }
    
    // Layer 2: Start the service
    let service_name = format!("{}.service", SERVICE_NAME);
    let args = if is_root() {
        vec!["start", &service_name]
    } else {
        vec!["--user", "start", &service_name]
    };
    
    // Format command for display
    let cmd_display = format!("systemctl {}", args.join(" "));
    
    // Log at DEBUG level - only visible with RUST_LOG=debug
    debug!("Executing: {}", cmd_display);

    let output = Command::new("systemctl")
        .args(&args)
        .output()
        .await
        .with_context(|| format!("Failed to execute: {}", cmd_display))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code();
        
        // Log failure details
        error!("Command failed: {}", cmd_display);
        error!("Exit code: {:?}", exit_code);
        error!("Stderr: {}", stderr);
        
        // Build comprehensive error message
        bail!(
            "Failed to start daemon via systemd\n\
             \n\
             Command: {}\n\
             Exit code: {:?}\n\
             Error: {}\n\
             \n\
             Troubleshooting:\n\
             - Verify service is installed: systemctl --user list-unit-files | grep kodegend\n\
             - Check service status: systemctl --user status kodegend\n\
             - View service logs: journalctl --user -u kodegend -n 50\n\
             - Reinstall service: kodegend install\n\
             \n\
             For system-wide service (requires root):\n\
             - sudo systemctl list-unit-files | grep kodegend\n\
             - sudo systemctl status kodegend\n\
             - sudo journalctl -u kodegend -n 50",
            cmd_display, exit_code, stderr
        );
    }

    info!("Daemon started successfully via systemctl");
    Ok(())
}

/// Stop daemon via systemctl stop
///
/// Idempotent: Returns Ok(()) if service is already stopped
pub async fn stop_daemon() -> Result<()> {
    use crate::platform;
    
    if !platform::is_systemd_available() {
        bail!("systemd not available - cannot use systemctl commands");
    }
    
    // Layer 1: Check if already stopped (fast path)
    if !check_status().await? {
        debug!("Service already stopped - idempotent success");
        return Ok(());
    }
    
    // Layer 2: Stop the service
    let service_name = format!("{}.service", SERVICE_NAME);
    let args = if is_root() {
        vec!["stop", &service_name]
    } else {
        vec!["--user", "stop", &service_name]
    };
    
    // Format command for display
    let cmd_display = format!("systemctl {}", args.join(" "));
    
    // Log at DEBUG level - only visible with RUST_LOG=debug
    debug!("Executing: {}", cmd_display);

    let output = Command::new("systemctl")
        .args(&args)
        .output()
        .await
        .with_context(|| format!("Failed to execute: {}", cmd_display))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code();
        
        // Log failure details
        error!("Command failed: {}", cmd_display);
        error!("Exit code: {:?}", exit_code);
        error!("Stderr: {}", stderr);
        
        // Build comprehensive error message
        bail!(
            "Failed to stop daemon via systemd\n\
             \n\
             Command: {}\n\
             Exit code: {:?}\n\
             Error: {}\n\
             \n\
             Troubleshooting:\n\
             - Check if service is running: systemctl --user status kodegend\n\
             - View recent logs: journalctl --user -u kodegend -n 50\n\
             - Force kill if needed: systemctl --user kill kodegend\n\
             - Check for stuck processes: ps aux | grep kodegend\n\
             \n\
             For system-wide service (requires root):\n\
             - sudo systemctl status kodegend\n\
             - sudo journalctl -u kodegend -n 50\n\
             - sudo systemctl kill kodegend",
            cmd_display, exit_code, stderr
        );
    }

    info!("Daemon stopped successfully via systemctl");
    Ok(())
}

/// Restart daemon via systemctl restart
pub async fn restart_daemon() -> Result<()> {
    use crate::platform;
    
    if !platform::is_systemd_available() {
        bail!("systemd not available - cannot use systemctl commands");
    }
    
    let service_name = format!("{}.service", SERVICE_NAME);
    let args = if is_root() {
        vec!["restart", &service_name]
    } else {
        vec!["--user", "restart", &service_name]
    };
    
    // Format command for display
    let cmd_display = format!("systemctl {}", args.join(" "));
    
    // Log at DEBUG level - only visible with RUST_LOG=debug
    debug!("Executing: {}", cmd_display);

    let output = Command::new("systemctl")
        .args(&args)
        .output()
        .await
        .with_context(|| format!("Failed to execute: {}", cmd_display))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code();
        
        // Log failure details
        error!("Command failed: {}", cmd_display);
        error!("Exit code: {:?}", exit_code);
        error!("Stderr: {}", stderr);
        
        // Build comprehensive error message
        bail!(
            "Failed to restart daemon via systemd\n\
             \n\
             Command: {}\n\
             Exit code: {:?}\n\
             Error: {}\n\
             \n\
             Troubleshooting:\n\
             - Check service status: systemctl --user status kodegend\n\
             - View service logs: journalctl --user -u kodegend -n 50\n\
             - Try manual restart: systemctl --user stop kodegend && systemctl --user start kodegend\n\
             - Reinstall service: kodegend install\n\
             \n\
             For system-wide service (requires root):\n\
             - sudo systemctl status kodegend\n\
             - sudo journalctl -u kodegend -n 50\n\
             - sudo systemctl stop kodegend && sudo systemctl start kodegend",
            cmd_display, exit_code, stderr
        );
    }

    info!("Daemon restarted successfully via systemctl");
    Ok(())
}

/// Check if running as root
#[inline]
fn is_root() -> bool {
    nix::unistd::getuid().is_root()
}
