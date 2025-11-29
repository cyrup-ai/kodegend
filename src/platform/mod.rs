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
mod windows;
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
pub fn is_process_running(pid: ProcessId) -> Result<bool, std::io::Error> {
    platform_is_process_running(pid)
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

// Signal handling abstraction
pub mod signal;
#[allow(unused_imports)] // False positive - SignalWatcher is used in manager.rs
pub use signal::{SignalKind, SignalWatcher, watch_signals};
