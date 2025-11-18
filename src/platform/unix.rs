//! Unix platform implementation (Linux, macOS, BSD)
//!
//! Preserves existing kodegend Unix behavior:
//! - Uses nix crate for system calls
//! - Fork-based daemonization (see daemon.rs)
//! - POSIX signals for process management
//! - XDG Base Directory Specification for paths

use std::path::PathBuf;
use nix::unistd::{Pid, getpid, geteuid};
use nix::sys::signal::kill;

/// Check if running as root (uid == 0)
///
/// Uses nix::unistd::geteuid() - same as existing config.rs logic
pub(super) fn platform_is_elevated() -> bool {
    geteuid().is_root()
}

/// Detect systemd or launchd service manager
///
/// Preserves existing logic from daemon.rs:15-33
pub(super) fn platform_running_under_service_manager() -> bool {
    // systemd sets INVOCATION_ID (daemon.rs:16)
    if std::env::var_os("INVOCATION_ID").is_some() {
        return true;
    }

    // macOS launchd detection (daemon.rs:32)
    if cfg!(target_os = "macos") {
        if std::env::var_os("LAUNCHED_BY_LAUNCHD").is_some()
            || std::env::var_os("XPC_SERVICE_NAME").is_some() {
            return true;
        }
    }

    false
}

/// Get current process PID
///
/// Uses nix::unistd::getpid()
pub(super) fn platform_current_process_id() -> i32 {
    getpid().as_raw()
}

/// Check if process is running using POSIX kill() with signal 0
///
/// Preserves exact logic from daemon.rs:83-108
///
/// Returns:
/// - Ok(true): Process exists (kill succeeded or EPERM)
/// - Ok(false): Process doesn't exist (ESRCH)
/// - Err: System error
pub(super) fn platform_is_process_running(pid: i32) -> Result<bool, std::io::Error> {
    match kill(Pid::from_raw(pid), None) {
        Ok(_) => Ok(true),  // Process exists and we can signal it
        Err(nix::errno::Errno::ESRCH) => Ok(false),  // No such process
        Err(nix::errno::Errno::EPERM) => Ok(true),   // Process exists but permission denied
        Err(e) => Err(std::io::Error::from_raw_os_error(e as i32)),
    }
}

/// System configuration directory: /etc/kodegend
pub(super) fn platform_system_config_dir() -> PathBuf {
    PathBuf::from("/etc/kodegend")
}

/// User configuration directory: ~/.config/kodegend
///
/// Follows XDG Base Directory Specification
pub(super) fn platform_user_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("kodegend")
}

/// Runtime directory for PID files and sockets
///
/// Elevated: /var/run/kodegend
/// User: $XDG_RUNTIME_DIR/kodegend or /tmp/kodegend-{uid}
pub(super) fn platform_runtime_dir(is_elevated: bool) -> PathBuf {
    if is_elevated {
        PathBuf::from("/var/run/kodegend")
    } else {
        std::env::var("XDG_RUNTIME_DIR")
            .ok()
            .map(PathBuf::from)
            .or_else(dirs::runtime_dir)
            .unwrap_or_else(|| {
                // Fallback: /tmp/kodegend-{uid} for security isolation
                PathBuf::from(format!("/tmp/kodegend-{}", geteuid()))
            })
            .join("kodegend")
    }
}

/// Log directory
///
/// Elevated: /var/log/kodegend
/// User: ~/.local/state/kodegend/logs
pub(super) fn platform_log_dir(is_elevated: bool) -> PathBuf {
    if is_elevated {
        PathBuf::from("/var/log/kodegend")
    } else {
        dirs::state_dir()
            .unwrap_or_else(|| PathBuf::from("~/.local/state"))
            .join("kodegend/logs")
    }
}
