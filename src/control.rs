//! Daemon lifecycle control - delegates to OS-native daemon managers
//!
//! Provides a unified interface for managing the daemon across different operating systems:
//! - macOS: launchd (launchctl)
//! - Linux: systemd (systemctl)
//! - Windows: Service Control Manager (Windows API)

use anyhow::{Context, Result};

// Platform-specific implementations
cfg_if::cfg_if! {
    if #[cfg(target_os = "macos")] {
        mod macos_control;
        use macos_control as platform;
    } else if #[cfg(target_os = "linux")] {
        mod linux_control;
        use linux_control as platform;
    } else if #[cfg(target_os = "windows")] {
        mod windows_control;
        use windows_control as platform;
    } else if #[cfg(unix)] {
        // Generic Unix fallback for BSD and other Unix-like systems
        // Provides basic PID-based control without service manager integration
        //
        // Supported platforms: FreeBSD, OpenBSD, NetBSD, DragonFly BSD, Solaris, etc.
        //
        // Capabilities:
        // - ✅ check_status() - via PID file and process existence
        // - ✅ stop_daemon() - via SIGTERM signal
        // - ❌ start_daemon() - returns helpful error
        // - ❌ restart_daemon() - returns helpful error
        mod generic_control;
        use generic_control as platform;
    } else {
        // Non-Unix, non-Windows platform (extremely rare)
        compile_error!(
            "kodegend is only supported on Unix-like systems and Windows.\n\
             \n\
             Your platform does not appear to be Unix or Windows.\n\
             \n\
             Supported platforms:\n\
             - Unix: macOS, Linux, FreeBSD, OpenBSD, NetBSD, DragonFly BSD, Solaris\n\
             - Windows: Windows 7+\n\
             \n\
             If you believe this is an error, please report an issue:\n\
             https://github.com/kodegen-ai/kodegen/issues"
        );
    }
}

/// Check if daemon is running
///
/// Returns: Ok(true) if running, Ok(false) if stopped
pub fn check_status() -> Result<bool> {
    platform::check_status()
        .context("Failed to check daemon status")
}

/// Start the daemon service
pub fn start_daemon() -> Result<()> {
    platform::start_daemon()
        .context("Failed to start daemon service")
}

/// Stop the daemon service
pub fn stop_daemon() -> Result<()> {
    platform::stop_daemon()
        .context("Failed to stop daemon service")
}

/// Restart the daemon service
pub fn restart_daemon() -> Result<()> {
    platform::restart_daemon()
        .context("Failed to restart daemon service")
}
