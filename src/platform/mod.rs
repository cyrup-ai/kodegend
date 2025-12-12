//! Platform abstraction layer for cross-platform daemon/service support
//!
//! This module provides a unified API for platform-specific operations:
//! - Process management (PIDs, privilege checking)
//! - Service lifecycle (daemonization vs Windows Services)
//! - File system paths (config, runtime, logs)
//!
//! ## Platform Support
//! - **Unix**: Linux, macOS, FreeBSD (via nix crate)
//! - **Windows**: Windows 7+ (via windows crate)
//!
//! ## Architecture
//!
//! Uses Rust conditional compilation to select platform implementation:
//! - `unix.rs`: Unix platforms (fork-based daemonization)
//! - `windows.rs`: Windows platforms (Service API, HANDLEs, token elevation)
//!
//! ## References
//!
//! Existing Windows patterns in this codebase:
//! - Privilege checking: `install/installer/windows/privileges.rs`
//! - Process APIs: `build/windows_helper.rs`

use std::path::PathBuf;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::*;

// Windows service SCM integration
#[cfg(target_os = "windows")]
pub mod windows_service;
#[cfg(target_os = "windows")]
pub use windows_service::start_windows_service;

// Platform-agnostic type aliases
#[cfg(unix)]
pub type ProcessId = i32; // Unix PIDs are signed 32-bit

#[cfg(windows)]
pub type ProcessId = u32; // Windows process IDs are DWORD (u32)

#[cfg(unix)]
#[allow(dead_code)]
pub type FileHandle = std::os::unix::io::RawFd;

#[cfg(windows)]
#[allow(dead_code)]
pub type FileHandle = std::os::windows::io::RawHandle;

/// Privilege level check (root/admin)
///
/// Returns true if process has elevated privileges:
/// - Unix: Running as root (uid == 0)
/// - Windows: Token contains Administrators group
pub fn is_elevated() -> bool {
    platform_is_elevated()
}

/// Service manager detection (systemd/launchd/SCM)
///
/// Returns true if launched by system service manager:
/// - Unix: systemd (INVOCATION_ID env var) or launchd (macOS)
/// - Windows: Running as Windows Service (no console window)
#[allow(dead_code)]
pub fn running_under_service_manager() -> bool {
    platform_running_under_service_manager()
}

/// Current process identifier
///
/// - Unix: getpid()
/// - Windows: GetCurrentProcessId()
#[allow(dead_code)]
pub fn current_process_id() -> ProcessId {
    platform_current_process_id()
}

/// Check if process exists and is running
///
/// - Unix: kill(pid, None) - signal 0 doesn't send signal, just checks existence
/// - Windows: OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) - succeeds if exists
///
/// Returns Ok(true) if process exists, Ok(false) if not, Err on permission/system error
#[allow(dead_code)] // FALSE POSITIVE: Used by daemon.rs and detection.rs
pub fn is_process_running(pid: ProcessId) -> Result<bool, std::io::Error> {
    platform_is_process_running(pid)
}

/// Validate that a PID is within platform-specific valid range
///
/// Checks:
/// - PID is positive (> 0) on Unix platforms  
/// - PID does not exceed platform-specific maximum
/// - On Linux: reads runtime /proc/sys/kernel/pid_max with fallback
/// - On macOS: enforces 99,999 limit
/// - On FreeBSD: uses kern.pid_max sysctl with fallback
/// - On Windows: validates against zero and reasonable maximum
///
/// Returns:
/// - Ok(()) if PID is valid
/// - Err with detailed message if invalid
///
/// # Security
/// This function prevents dangerous PID values from being used with kill() and other
/// process APIs. It protects against:
/// - Negative PIDs (process group signals)
/// - Zero PID (kernel scheduler / current process group)
/// - Out-of-range PIDs (corrupted or malicious PID files)
///
/// # Example
/// ```no_run
/// use kodegend::platform;
///
/// let pid = 12345;
/// platform::validate_pid_range(pid)?;
/// // PID is now safe to use with kill() or other APIs
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn validate_pid_range(pid: ProcessId) -> Result<(), anyhow::Error> {
    platform_validate_pid_range(pid)
}

/// Get the system's maximum PID value
///
/// Returns the platform-specific maximum PID that can be assigned to processes.
/// This is used for validating PIDs read from files to detect corruption.
///
/// # Platform-Specific Values
/// - **Linux**: Read from /proc/sys/kernel/pid_max (typically 32767, max 4194303)
/// - **macOS**: 99998 (PIDs wrap at 99999)
/// - **FreeBSD**: Read from kern.pid_max sysctl (typically 99999)
/// - **Windows**: 4194304 (conservative limit)
/// - **Other Unix**: 32767 (conservative default)
///
/// # Returns
/// Maximum assignable PID value for current platform
///
/// # Example
/// ```rust
/// let max_pid = platform::get_system_pid_max();
/// if pid > max_pid {
///     bail!("PID {} exceeds system maximum {}", pid, max_pid);
/// }
/// ```
#[cfg(unix)]
#[allow(dead_code)] // Reserved for PID validation in daemon module
pub fn get_system_pid_max() -> ProcessId {
    platform_get_system_pid_max()
}

#[cfg(windows)]
#[allow(dead_code)] // Reserved for PID validation in daemon module
pub fn get_system_pid_max() -> ProcessId {
    platform_get_system_pid_max()
}

/// Verify that a PID belongs to kodegend process
///
/// This prevents PID reuse attacks by checking:
/// 1. Process exists (via is_process_running)
/// 2. Process executable path contains "kodegend"
///
/// Uses sysinfo crate (already a dependency) for cross-platform process introspection.
/// Pattern copied from service/port_cleanup.rs:128-172
///
/// # Arguments
/// * `pid` - Process ID to verify
///
/// # Returns
/// - `Ok(true)`: Process exists AND is kodegend
/// - `Ok(false)`: Process doesn't exist OR is not kodegend (safe to proceed)
/// - `Err`: System error (permission denied, etc.)
///
/// # Security
/// This function is critical for preventing CVE-class PID reuse vulnerabilities.
/// See task/05_daemon_pid_reuse_vulnerability.md for attack scenarios and CVE references.
pub fn verify_kodegend_running(pid: ProcessId) -> Result<bool, std::io::Error> {
    platform_verify_kodegend_running(pid)
}

/// System-wide configuration directory
///
/// - Unix: /etc/kodegend
/// - Windows: %ProgramData%\kodegend
pub fn system_config_dir() -> PathBuf {
    platform_system_config_dir()
}

/// User-specific configuration directory
///
/// - Unix: ~/.config/kodegen/kodegend
/// - Windows: %APPDATA%\kodegen\kodegend
///
/// Delegates to kodegen-config for base path, then appends 'kodegend' subdirectory
pub fn user_config_dir() -> PathBuf {
    platform_user_config_dir()
}

/// Runtime state directory (PID files, sockets)
///
/// - Unix (elevated): /var/run/kodegend
/// - Unix (user): $XDG_RUNTIME_DIR/kodegend or /tmp/kodegend-{uid}
/// - Windows (elevated): %ProgramData%\kodegend\run
/// - Windows (user): %LOCALAPPDATA%\kodegend\run
pub fn runtime_dir(is_elevated: bool) -> PathBuf {
    platform_runtime_dir(is_elevated)
}

/// Log file directory
///
/// - Unix (elevated): /var/log/kodegend
/// - Unix (user): ~/.local/state/kodegend/logs
/// - Windows (elevated): %ProgramData%\kodegend\logs
/// - Windows (user): %LOCALAPPDATA%\kodegend\logs
pub fn log_dir(is_elevated: bool) -> PathBuf {
    platform_log_dir(is_elevated)
}

/// Status socket path for daemon queries
///
/// - Unix (elevated): /var/run/kodegend/status.sock
/// - Unix (user): $XDG_RUNTIME_DIR/kodegend/status.sock or /tmp/kodegend-{uid}/kodegend/status.sock
/// - Windows: \\.\pipe\kodegend\status (named pipe, privilege-independent)
pub fn status_socket_path(is_elevated: bool) -> PathBuf {
    platform_status_socket_path(is_elevated)
}

// Signal handling abstraction
pub mod signal;
#[allow(unused_imports)] // False positive - SignalWatcher is used in manager.rs
pub use signal::{SignalKind, SignalWatcher, watch_signals};

// GUI detection for installation wizard
mod gui_detection;
pub use gui_detection::is_gui_available;

// macOS watchdog for service health monitoring
#[cfg(target_os = "macos")]
pub mod macos_watchdog;
#[cfg(target_os = "macos")]
pub use macos_watchdog::WatchdogHandle;
