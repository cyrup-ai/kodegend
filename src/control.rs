//! Control an installed kodegend service via OS-native service managers
//!
//! This module provides CLI commands for managing a **previously installed** kodegend
//! service using the operating system's native service manager. It controls the **kodegend
//! daemon itself**, not services that kodegend manages.
//!
//! # What This Module Does
//!
//! kodegend is a daemon that manages and supervises other services/processes. The **control
//! module** is specifically for controlling **kodegend itself** as a service (starting,
//! stopping, checking status). For managing services that kodegend supervises, see the
//! [`manager`](crate::manager) module.
//!
//! # Platform Support
//!
//! - **macOS**: launchd via `launchctl` (system service)
//! - **Linux**: systemd via `systemctl` (user or system service)
//! - **Windows**: Windows Service Control Manager via Win32 API
//! - **BSD/Unix**: Generic fallback using PID files and POSIX signals (limited functionality)
//!
//! # Prerequisites
//!
//! Before using these commands, the kodegend service must be installed:
//! ```bash
//! kodegend install          # Install as user service (recommended for development)
//! kodegend install --system # Install as system-wide service (requires root/admin)
//! ```
//!
//! Installation creates platform-specific service files:
//! - Linux: `~/.config/systemd/user/kodegend.service` or `/etc/systemd/system/kodegend.service`
//! - macOS: `/Library/LaunchDaemons/kodegend.plist` (currently system-wide only)
//! - Windows: Service registered in SCM database
//! - BSD: No service files (manual startup only)
//!
//! # Public API
//!
//! This module exports four functions that dispatch to platform-specific implementations:
//!
//! - [`check_status()`] - Check if kodegend service is running
//! - [`start_daemon()`] - Start the kodegend service
//! - [`stop_daemon()`] - Stop the kodegend service
//! - [`restart_daemon()`] - Restart the kodegend service
//!
//! # Direct Execution vs Service Control
//!
//! kodegend supports two execution modes:
//!
//! ## 1. Service Manager Mode (Production - Recommended)
//!
//! **Installation**:
//! ```bash
//! kodegend install [--system]  # One-time setup
//! ```
//!
//! **Control via this module**:
//! ```bash
//! kodegend start    # Uses control::start_daemon() → systemctl/launchctl/SCM
//! kodegend stop     # Uses control::stop_daemon()
//! kodegend restart  # Uses control::restart_daemon()
//! kodegend status   # Uses control::check_status()
//! ```
//!
//! **Behavior**:
//! - Service manager (systemd/launchd/SCM) starts kodegend process
//! - kodegend detects service manager via [`platform::running_under_service_manager()`]
//! - kodegend runs in foreground (no self-daemonization needed)
//! - Service manager handles:
//!   - Process supervision and restart on crash
//!   - Logging and output capture
//!   - Auto-start on system boot
//!   - Resource limits and security sandboxing
//!
//! **Advantages**:
//! - ✅ Automatic restart on failure
//! - ✅ Starts on boot
//! - ✅ Centralized logging (journalctl/log show/Event Viewer)
//! - ✅ Security hardening (systemd sandboxing)
//! - ✅ Standard service management commands
//!
//! ## 2. Direct Execution Mode (Development/Testing)
//!
//! **No installation required**:
//! ```bash
//! kodegend run               # Run directly (stays in foreground)
//! kodegend run --foreground  # Same behavior (parameter currently unused)
//! ```
//!
//! **Behavior**:
//! - Manual execution via `kodegend run`
//! - **Always runs in foreground** (current implementation)
//! - Creates PID file for process tracking: `~/.local/state/kodegend/kodegend.pid` or `/var/run/kodegend/kodegend.pid`
//! - No automatic restart (process exits if killed)
//! - Limited lifecycle control:
//!   - ✅ Can stop via SIGTERM (Ctrl+C or `kill -15 <pid>`)
//!   - ❌ Cannot use `kodegend start` (no service installed)
//!   - ❌ No auto-start on boot
//!
//! **Use Cases**:
//! - Development and debugging
//! - Testing configuration changes
//! - Running without installation
//! - Platforms without service manager support (BSD via generic fallback)
//!
//! # Platform-Specific Behavior
//!
//! ## macOS (launchd via launchctl)
//!
//! **Service Configuration**:
//! - Service label: `ai.kodegen.kodegend`
//! - Plist location: `/Library/LaunchDaemons/kodegend.plist`
//! - Implementation: [`control::macos_control`]
//!
//! **Commands**:
//! - Check status: `launchctl list ai.kodegen.kodegend` (parses PID from output)
//! - Start: `launchctl bootstrap system <plist>` + `launchctl kickstart <label>`
//! - Stop: `launchctl kill SIGTERM <label>` + `launchctl bootout system <plist>`
//! - Restart: `launchctl kickstart -k <label>` (kill + restart)
//!
//! **Features**:
//! - Modern launchctl commands with legacy fallback (load/unload)
//! - Exponential backoff verification (wait_for_stopped, wait_for_active)
//! - 500ms delay for resource cleanup between operations
//!
//! ## Linux (systemd via systemctl)
//!
//! **Service Configuration**:
//! - Service name: `kodegend.service`
//! - User service: `~/.config/systemd/user/kodegend.service`
//! - System service: `/etc/systemd/system/kodegend.service`
//! - Implementation: [`control::linux_control`]
//!
//! **Commands**:
//! - Check status: `systemctl [--user] is-active kodegend.service` (exit 0 = active)
//! - Start: `systemctl [--user] start kodegend.service`
//! - Stop: `systemctl [--user] stop kodegend.service`
//! - Restart: `systemctl [--user] restart kodegend.service`
//!
//! **Privilege Detection**:
//! - Auto-detects root via `nix::unistd::getuid().is_root()`
//! - Uses `systemctl` (system) or `systemctl --user` (user) accordingly
//!
//! **Systemd Integration**:
//! - Type=notify: kodegend signals readiness via `sd_notify`
//! - Security hardening: ProtectSystem, NoNewPrivileges, MemoryDenyWriteExecute
//! - Resource limits: LimitNOFILE=65536, LimitNPROC=4096
//! - Auto-restart: Restart=on-failure, RestartSec=5s
//! - Watchdog: WatchdogSec=30s
//!
//! ## Windows (Service Control Manager via Win32 API)
//!
//! **Service Configuration**:
//! - Service name: `kodegend`
//! - Registered in: SCM database (no file-based config)
//! - Implementation: [`control::windows_control`]
//!
//! **Win32 API**:
//! - Status: `OpenSCManagerW` → `OpenServiceW` → `QueryServiceStatusEx`
//!   - Checks: `SERVICE_STATUS_PROCESS.dwCurrentState == SERVICE_RUNNING`
//! - Start: `StartServiceW`
//! - Stop: `ControlService` with `SERVICE_CONTROL_STOP`
//! - Restart: Stop + 1s sleep + start (no native restart API)
//!
//! **RAII Handles**:
//! - `ScManagerHandle`: Wraps `SC_HANDLE` for SCM with automatic cleanup
//! - `ServiceHandle`: Wraps `SC_HANDLE` for service with automatic cleanup
//!
//! **Verification**:
//! - Exponential backoff polling of SCM state
//! - 500ms delay for resource cleanup (file handles, ports)
//!
//! ## Generic Unix Fallback (BSD, Solaris, etc.)
//!
//! **Supported Platforms**: FreeBSD, OpenBSD, NetBSD, DragonFly BSD, Solaris
//!
//! **Implementation**: [`control::generic_control`]
//!
//! **Limited Functionality**:
//! - ✅ `check_status()`: Reads PID file + validates via `kill(pid, 0)`
//! - ✅ `stop_daemon()`: Sends SIGTERM via `kill(pid, SIGTERM)`
//! - ❌ `start_daemon()`: Returns error with manual startup instructions
//! - ❌ `restart_daemon()`: Returns error (no start capability)
//!
//! **PID File Location**:
//! - Root: `/var/run/kodegend/kodegend.pid`
//! - User: `$XDG_RUNTIME_DIR/kodegend/kodegend.pid` or `~/.local/state/kodegend/kodegend.pid`
//!
//! **Manual Startup** (provided in error messages):
//! ```bash
//! # Foreground mode
//! kodegend run --foreground
//!
//! # Background with nohup
//! nohup kodegend run --foreground > /var/log/kodegend.log 2>&1 &
//!
//! # Or create rc.d scripts:
//! # - FreeBSD: /usr/local/etc/rc.d/kodegend
//! # - OpenBSD: /etc/rc.d/kodegend (use rcctl)
//! # - NetBSD: /etc/rc.d/kodegend
//! ```
//!
//! # Error Handling
//!
//! All functions return `Result<T>` with context-rich errors via `anyhow`:
//!
//! **Common Error Cases**:
//! - **Service not installed**: "Failed to open service: kodegend"
//!   - Solution: Run `kodegend install` first
//! - **Insufficient permissions**: "Permission denied" / "Access is denied"
//!   - Solution: Use `sudo` (Linux/macOS) or run as Administrator (Windows)
//! - **Service already running**: `start_daemon()` may succeed idempotently or error
//!   - Solution: Check status first with `kodegend status`
//! - **Service not running**: `stop_daemon()` may succeed idempotently or error
//!   - Solution: Normal behavior if already stopped
//! - **Service manager unavailable**: Platform-specific errors
//!   - Solution: Ensure systemd/launchd is running and accessible
//!
//! # Related Modules
//!
//! - [`daemon`](crate::daemon) - PID file management and systemd readiness notification
//! - [`platform`](crate::platform) - Service manager detection and platform abstraction
//! - [`install`](crate::install) - Service installation and configuration
//! - [`manager`](crate::manager) - Service supervision (what kodegend manages, NOT this module)
//!
//! # Implementation Notes
//!
//! **Conditional Compilation**:
//! ```rust
//! cfg_if::cfg_if! {
//!     if #[cfg(target_os = "macos")] {
//!         mod macos_control;
//!         use macos_control as platform;
//!     } else if #[cfg(target_os = "linux")] {
//!         mod linux_control;
//!         use linux_control as platform;
//!     } else if #[cfg(target_os = "windows")] {
//!         mod windows_control;
//!         use windows_control as platform;
//!     } else if #[cfg(unix)] {
//!         mod generic_control;
//!         use generic_control as platform;
//!     }
//! }
//! ```
//!
//! **Verification Patterns** (macOS/Windows):
//! - Exponential backoff: 1ms → 2ms → 4ms → ... → 100ms cap
//! - Timeout handling: 10s for stop, 30s for start
//! - State polling: Continuously check service manager until desired state reached
//!
//! **Historical Note**:
//! The [`daemon::daemonise()`] function exists for Unix double-fork daemonization
//! but is currently unused (marked `#[allow(dead_code)]`). The implementation has
//! been simplified to always run in foreground and rely on service managers for
//! process lifecycle management. PID files are still created for process tracking.

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

/// Check daemon status with detailed information
///
/// Returns: Ok(ServiceStatus) with rich state details
pub async fn check_status() -> Result<crate::daemon::ServiceStatus> {
    platform::check_status().await
        .context("Failed to check daemon status")
}

/// Start the daemon service
///
/// **This operation is idempotent.** If the service is already running,
/// this function returns `Ok(())` without error. This behavior is guaranteed
/// across all platforms (Linux, macOS, Windows).
///
/// # Platform Implementation
///
/// - **Linux (systemd)**: Uses `systemctl start kodegend.service`
/// - **macOS (launchd)**: Uses `launchctl bootstrap` + `launchctl kickstart`
/// - **Windows (SCM)**: Uses `StartServiceW` Win32 API
///
/// # Returns
///
/// - `Ok(())` - Service is running (either was already running or just started)
/// - `Err(_)` - Service failed to start, not installed, or permission denied
///
/// # Errors
///
/// Returns an error if:
/// - The service is not installed on the system
/// - Insufficient permissions to start the service (requires admin/root)
/// - The service failed to start (check platform logs for details)
/// - Platform service manager is unavailable or malfunctioning
///
/// # Examples
///
/// ```rust
/// // Idempotent - can be called multiple times safely
/// start_daemon()?;
/// start_daemon()?;  // Second call succeeds immediately
/// ```
pub async fn start_daemon() -> Result<()> {
    platform::start_daemon().await.context("Failed to start daemon service")
}

/// Stop the daemon service
///
/// **This operation is idempotent.** If the service is already stopped,
/// this function returns `Ok(())` without error. This behavior is guaranteed
/// across all platforms (Linux, macOS, Windows).
///
/// # Platform Implementation
///
/// - **Linux (systemd)**: Uses `systemctl stop kodegend.service`
/// - **macOS (launchd)**: Uses `launchctl kill` + `launchctl bootout`
/// - **Windows (SCM)**: Uses `ControlService(SERVICE_CONTROL_STOP)` Win32 API
///
/// # Returns
///
/// - `Ok(())` - Service is stopped (either was already stopped or just stopped)
/// - `Err(_)` - Service failed to stop or permission denied
///
/// # Errors
///
/// Returns an error if:
/// - Insufficient permissions to stop the service (requires admin/root)
/// - The service failed to stop gracefully (may require manual intervention)
/// - Platform service manager is unavailable or malfunctioning
///
/// # Examples
///
/// ```rust
/// // Idempotent - can be called multiple times safely
/// stop_daemon()?;
/// stop_daemon()?;  // Second call succeeds immediately
/// ```
pub async fn stop_daemon() -> Result<()> {
    platform::stop_daemon().await.context("Failed to stop daemon service")
}

/// Restart the daemon service
pub async fn restart_daemon() -> Result<()> {
    platform::restart_daemon().await.context("Failed to restart daemon service")
}
