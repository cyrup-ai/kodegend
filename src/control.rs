//! Daemon lifecycle control - delegates to OS-native daemon managers
//!
//! Provides a unified interface for managing the daemon across different operating systems:
//! - macOS: launchd (launchctl)
//! - Linux: systemd (systemctl)
//! - Windows: Service Control Manager (Windows API)

use anyhow::Result;

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
    } else {
        compile_error!(
            "kodegend daemon control is not supported on this platform.\n\
             \n\
             Daemon control (start/stop/restart/status) requires platform-specific \n\
             service manager integration:\n\
             \n\
             - macOS: launchd (launchctl)\n\
             - Linux: systemd (systemctl)\n\
             - Windows: Service Control Manager (SCM)\n\
             \n\
             Your platform is not yet supported for service manager integration.\n\
             \n\
             ALTERNATIVES:\n\
             \n\
             1. Run the daemon directly in foreground mode:\n\
                   kodegend run --foreground\n\
             \n\
             2. Request platform support by opening an issue:\n\
                   https://github.com/kodegen-ai/kodegen/issues\n\
             \n\
             3. Contribute platform support for your system:\n\
                   See packages/kodegend/src/control/ for reference implementations\n\
             \n\
             Supported platforms: macOS, Linux, Windows"
        );
    }
}

/// Check if daemon is running
///
/// Returns: Ok(true) if running, Ok(false) if stopped
pub fn check_status() -> Result<bool> {
    platform::check_status()
}

/// Start the daemon service
pub fn start_daemon() -> Result<()> {
    platform::start_daemon()
}

/// Stop the daemon service
pub fn stop_daemon() -> Result<()> {
    platform::stop_daemon()
}

/// Restart the daemon service
pub fn restart_daemon() -> Result<()> {
    platform::restart_daemon()
}
