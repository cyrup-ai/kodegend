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

use anyhow::{Context, Result, bail};
use std::fs;
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
fn pid_file_path() -> PathBuf {
    let is_elevated = platform::is_elevated();
    platform::runtime_dir(is_elevated).join("kodegend.pid")
}

/// Read PID from PID file
///
/// Returns: PID as i32
/// Errors: File doesn't exist, can't read, or invalid PID format
fn read_pid() -> Result<i32> {
    let path = pid_file_path();
    
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
    
    let pid_str = fs::read_to_string(&path)
        .with_context(|| format!("Reading PID file: {}", path.display()))?;
    
    pid_str.trim()
        .parse::<i32>()
        .with_context(|| {
            format!(
                "Parsing PID from file {}: '{}' is not a valid process ID",
                path.display(),
                pid_str.trim()
            )
        })
}

/// Check if daemon is running using PID file and process validation
///
/// Algorithm:
/// 1. Check if PID file exists
/// 2. Read PID from file
/// 3. Validate process exists using kill(pid, 0)
///
/// Returns:
/// - Ok(true): Daemon is running
/// - Ok(false): Daemon is not running (no PID file or stale PID)
/// - Err: System error checking process status
pub fn check_status() -> Result<bool> {
    let path = pid_file_path();
    
    // No PID file = not running
    if !path.exists() {
        return Ok(false);
    }
    
    // Read PID from file
    let pid = match read_pid() {
        Ok(pid) => pid,
        Err(_) => {
            // Stale or corrupted PID file - treat as not running
            return Ok(false);
        }
    };
    
    // Reuse existing process checking logic
    // Uses POSIX kill(pid, 0) to check existence
    platform::is_process_running(pid)
        .map_err(|e| anyhow::anyhow!("Error checking process status: {}", e))
}

/// Start daemon - NOT SUPPORTED
///
/// Generic implementation cannot start the daemon because there's no
/// service manager to spawn and supervise the process.
///
/// Returns: Error with instructions for manual startup
pub fn start_daemon() -> Result<()> {
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
pub fn stop_daemon() -> Result<()> {
    let pid = read_pid()
        .context("Cannot stop daemon: failed to read PID file")?;
    
    // Import signal types
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    
    // Send SIGTERM for graceful shutdown
    kill(Pid::from_raw(pid), Signal::SIGTERM)
        .map_err(|e| {
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
pub fn restart_daemon() -> Result<()> {
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
