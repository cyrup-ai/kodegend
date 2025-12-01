//! Generic Unix daemon control using PID files and POSIX signals
//!
//! This is a fallback implementation for Unix-like systems without
//! service manager integration (BSD systems, Solaris, etc.).
//!
//! ## Capabilities
//!
//! - ✅ Check daemon status via PID file and process existence
//! - ✅ Stop daemon via SIGTERM signal
//! - ❌ Cannot start daemon (no service manager to spawn process)
//! - ❌ Cannot restart daemon (requires start capability)
//!
//! ## Limitations
//!
//! - No service manager integration (no systemd/launchd/rc.d)
//! - Cannot spawn daemon process (manual startup required)
//! - No automatic restart on crashes
//! - No auto-start on boot
//! - Manual PID file management only
//!
//! For full daemon lifecycle management, use platform-specific implementations:
//! - macOS: [`macos_control`] (launchd via launchctl)
//! - Linux: [`linux_control`] (systemd via systemctl)
//! - Windows: [`windows_control`] (Service Control Manager)

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
use anyhow::{Context, Result, bail};
use std::path::PathBuf;

// Import existing platform utilities
use crate::platform;

/// Get PID file path using existing platform logic
///
/// Uses the same path resolution as the daemon itself:
/// - Root: /var/run/kodegend/kodegend.pid
/// - User: $XDG_RUNTIME_DIR/kodegend/kodegend.pid or ~/.local/state/kodegend/kodegend.pid
///
/// Reuses: config.rs::default_pid_file() logic
pub(crate) fn pid_file_path() -> PathBuf {
    let is_elevated = platform::is_elevated();
    platform::runtime_dir(is_elevated).join("kodegend.pid")
}

/// Read PID from the default PID file location
///
/// Convenience wrapper around [`daemon::read_pid_file()`] that automatically
/// uses the platform-appropriate PID file path.
///
/// This function:
/// 1. Gets the default PID file path via `pid_file_path()`
/// 2. Delegates to `daemon::read_pid_file()` for comprehensive validation
/// 3. Provides a helpful error message if the file doesn't exist
///
/// # Returns
/// * `Ok(i32)` - Successfully read and validated PID
/// * `Err` - PID file doesn't exist, is corrupted, or daemon not running
///
/// # Error Messages
///
/// If the PID file doesn't exist, provides actionable startup instructions:
/// - How to run kodegend manually in foreground
/// - How to use nohup for background execution
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn read_pid() -> Result<i32> {
    let path = pid_file_path();

    // Check if PID file exists first to provide helpful error message
    if !path.exists() {
        bail!(
            "Daemon not running (PID file does not exist: {})\n\
             \n\
             To start the daemon manually:\n\
             \n\
             kodegend run --foreground\n\
             \n\
             Or with nohup for background:\n\
             \n\
             nohup kodegend run --foreground > /var/log/kodegend.log 2>&1 &",
            path.display()
        );
    }

    // Delegate to the canonical implementation in daemon module
    // This provides comprehensive validation and rich error messages
    crate::daemon::read_pid_file(&path)
}

/// Check if daemon is running using PID file and process validation
///
/// Now returns rich ServiceStatus enum instead of boolean.
///
/// Returns:
/// - Ok(ServiceStatus) with detailed state information
/// - Err: System error (should be rare)
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub async fn check_status() -> Result<crate::daemon::ServiceStatus> {
    let path = pid_file_path();
    crate::daemon::get_service_status(&path)
}

/// Start daemon - NOT SUPPORTED
///
/// Generic implementation cannot start the daemon because there's no
/// service manager to spawn and supervise the process.
///
/// Returns: Error with instructions for manual startup
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub async fn start_daemon() -> Result<()> {
    bail!(
        "Starting the daemon is not supported on this platform.\n\
         \n\
         This platform lacks service manager integration (systemd/launchd/rc.d).\n\
         Kodegend cannot automatically spawn the daemon process.\n\
         \n\
         MANUAL STARTUP OPTIONS:\n\
         \n\
         1. Run in foreground mode:\n\
         \n\
            kodegend run --foreground\n\
         \n\
         2. Run in background with nohup:\n\
         \n\
            nohup kodegend run --foreground > /var/log/kodegend.log 2>&1 &\n\
         \n\
         3. Create a custom rc.d script for your platform:\n\
         \n\
            - FreeBSD: /usr/local/etc/rc.d/kodegend\n\
            - OpenBSD: /etc/rc.d/kodegend (use rcctl)\n\
            - NetBSD: /etc/rc.d/kodegend\n\
         \n\
         For automatic service management, request platform support:\n\
         https://github.com/kodegen-ai/kodegen/issues"
    );
}

/// Stop daemon by sending SIGTERM to PID
///
/// Algorithm:
/// 1. Read PID from PID file
/// 2. Send SIGTERM (signal 15) for graceful shutdown
/// 3. Return immediately (does not wait for termination)
///
/// The daemon's signal handler will:
/// - Receive SIGTERM
/// - Initiate graceful shutdown
/// - Clean up PID file via Drop trait
///
/// Returns:
/// - Ok(()): SIGTERM sent successfully
/// - Err: Cannot read PID file, or failed to send signal
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub async fn stop_daemon() -> Result<()> {
    let pid = read_pid().context("Cannot stop daemon: failed to read PID file")?;

    // Import signal types
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    // Send SIGTERM for graceful shutdown
    kill(Pid::from_raw(pid), Signal::SIGTERM).map_err(|e| {
        anyhow::anyhow!(
            "Failed to send SIGTERM to process {}: {}\n\
                 \n\
                 Possible causes:\n\
                 - Process already exited\n\
                 - Insufficient permissions (try sudo)\n\
                 - PID belongs to different user\n\
                 \n\
                 Try checking status: kodegend status",
            pid,
            e
        )
    })?;

    log::info!("Sent SIGTERM to kodegend daemon (PID: {})", pid);
    log::info!("Daemon will perform graceful shutdown and clean up PID file");

    Ok(())
}

/// Restart daemon - NOT SUPPORTED
///
/// Generic implementation cannot restart because start is not supported.
///
/// Returns: Error with instructions for manual restart
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub async fn restart_daemon() -> Result<()> {
    bail!(
        "Restarting the daemon is not supported on this platform.\n\
         \n\
         This platform lacks service manager integration (systemd/launchd/rc.d).\n\
         \n\
         MANUAL RESTART PROCEDURE:\n\
         \n\
         1. Stop the daemon:\n\
         \n\
            kodegend stop\n\
         \n\
         2. Wait for graceful shutdown (check status):\n\
         \n\
            kodegend status\n\
         \n\
         3. Start manually in foreground:\n\
         \n\
            kodegend run --foreground\n\
         \n\
         Or with nohup for background:\n\
         \n\
            nohup kodegend run --foreground > /var/log/kodegend.log 2>&1 &\n\
         \n\
         For automatic service management, request platform support:\n\
         https://github.com/kodegen-ai/kodegen/issues"
    );
}
