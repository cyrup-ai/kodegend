//! Windows platform implementation (Windows 7+)
//!
//! Uses Windows API via `windows` crate (v0.62, already in Cargo.toml)
//!
//! ## References
//!
//! Existing Windows patterns in kodegend:
//! - `install/installer/windows/privileges.rs` - Token elevation checking
//! - `build/windows_helper.rs` - GetCurrentProcessId(), process enumeration
//!
//! ## Windows APIs Used
//!
//! - `GetCurrentProcessId()` - Current PID (processthreadsapi.h)
//! - `OpenProcess()` - Process handle opening (processthreadsapi.h)
//! - `OpenProcessToken()` + `GetTokenInformation()` - Privilege checking (securitybaseapi.h)
//! - Environment variables - Path detection (%ProgramData%, %APPDATA%, etc.)

mod handles;
pub(crate) use handles::{ProcessHandle, TokenHandle};

pub mod named_pipe;
pub use named_pipe::{NamedPipeStream, connect_named_pipe, create_named_pipe_server};

use anyhow::{Result, bail};
use kodegen_config::KodegenConfig;
use std::mem;
use std::path::PathBuf;
use sysinfo::{Pid, ProcessesToUpdate, System};
use windows::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TokenElevation,
};
use windows::Win32::System::Threading::GetCurrentProcessId;

/// Check if running as Administrator
///
/// Uses Windows Security API to check token elevation.
/// Pattern copied from install/installer/windows/privileges.rs:24-51
///
/// See: https://learn.microsoft.com/en-us/windows/win32/secauthz/asking-the-user-for-credentials
pub(super) fn platform_is_elevated() -> bool {
    // Open current process token - handle auto-closed on drop
    let token = match TokenHandle::open_current_process_query() {
        Ok(t) => t,
        Err(e) => {
            log::warn!("Failed to open process token for privilege check: {}", e);
            log::debug!("Assuming non-elevated due to token access failure");
            return false;
        }
    };

    unsafe {
        // Query token elevation information
        let mut elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut return_length: u32 = 0;

        let result = GetTokenInformation(
            token.as_raw(),
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        if let Err(e) = result {
            log::warn!(
                "Failed to query token elevation information: {} (code: 0x{:08X})",
                e,
                e.code().0
            );
            log::debug!("Assuming non-elevated due to query failure");
            return false;
        }

        let is_elevated = elevation.TokenIsElevated != 0;
        log::debug!(
            "Process elevation status: {}",
            if is_elevated {
                "elevated"
            } else {
                "not elevated"
            }
        );
        is_elevated
    }
    // Token handle automatically closed here
}

/// Detect if running as Windows Service
///
/// Windows Services run without a console window.
/// Use GetConsoleWindow() to detect console presence.
///
/// See: https://learn.microsoft.com/en-us/windows/win32/api/wincon/nf-wincon-getconsolewindow
pub(super) fn platform_running_under_service_manager() -> bool {
    unsafe {
        // If GetConsoleWindow returns NULL, we're likely a service
        // (Services don't have console windows)
        use windows::Win32::System::Console::GetConsoleWindow;
        let is_service = GetConsoleWindow().0 == 0;

        log::debug!(
            "Service manager detection: {} (console window: {})",
            if is_service {
                "running as service"
            } else {
                "interactive mode"
            },
            if is_service { "none" } else { "present" }
        );

        is_service
    }
}

/// Get current process ID
///
/// Uses GetCurrentProcessId() from processthreadsapi.h
/// Pattern from build/windows_helper.rs:69
///
/// See: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid
pub(super) fn platform_current_process_id() -> u32 {
    unsafe { GetCurrentProcessId() }
}

/// Check if a process is running using OpenProcess()
///
/// Uses OpenProcess() with PROCESS_QUERY_LIMITED_INFORMATION.
/// Similar semantics to Unix kill(pid, 0).
///
/// Returns:
/// - Ok(true): Process exists (OpenProcess succeeded or ERROR_ACCESS_DENIED)
/// - Ok(false): Process doesn't exist (ERROR_INVALID_PARAMETER)
/// - Err: Other system errors
///
/// Error handling matches Unix EPERM/ESRCH semantics:
/// - ERROR_ACCESS_DENIED → Ok(true) (like Unix EPERM - process exists, no permission)
/// - ERROR_INVALID_PARAMETER → Ok(false) (like Unix ESRCH - no such process)
///
/// See: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
pub(super) fn platform_is_process_running(pid: u32) -> Result<bool, std::io::Error> {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::Foundation::CloseHandle;
    
    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => {
                let _ = CloseHandle(handle);
                Ok(true)  // Process exists and we can query it
            }
            Err(e) => {
                let error_code = e.code().0 as u32;
                
                // Process doesn't exist (invalid PID)
                if error_code == ERROR_INVALID_PARAMETER.0 {
                    return Ok(false);
                }
                
                // Process exists but access denied (matches Unix EPERM behavior)
                // Common for protected processes: System, CSRSS, higher integrity levels
                if error_code == ERROR_ACCESS_DENIED.0 {
                    return Ok(true);
                }
                
                // Unknown error - propagate to caller
                // Should be rare in practice (disk I/O errors, memory issues, etc.)
                Err(std::io::Error::from_raw_os_error(e.code().0))
            }
        }
    }
}

/// System-wide configuration directory
///
/// Returns: %ProgramData%\kodegend (typically C:\ProgramData\kodegend)
pub(super) fn platform_system_config_dir() -> PathBuf {
    let dir = std::env::var("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            log::warn!("Failed to resolve %ProgramData%, using fallback");
            PathBuf::from("C:\\ProgramData")
        })
        .join("kodegend");

    log::debug!("System config directory: {}", dir.display());

    dir
}

/// User-specific configuration directory
///
/// Returns: %APPDATA%\kodegen\kodegend (typically C:\Users\{user}\AppData\Roaming\kodegen\kodegend)
/// Uses kodegen-config for consistent path resolution
pub(super) fn platform_user_config_dir() -> PathBuf {
    let dir = KodegenConfig::user_config_dir()
        .map(|dir| dir.join("kodegend"))
        .unwrap_or_else(|_| {
            log::warn!("Failed to resolve user config directory, using fallback");
            PathBuf::from("C:\\ProgramData\\kodegen\\kodegend")
        });

    log::debug!("User config directory: {}", dir.display());

    dir
}

/// Runtime directory for PID files
///
/// Elevated: %ProgramData%\kodegend\run
/// User: %LOCALAPPDATA%\kodegend\run
///
/// Uses std::env::var() to properly expand Windows environment variables.
/// Falls back to dirs crate, then to C:\ProgramData if both fail.
pub(super) fn platform_runtime_dir(is_elevated: bool) -> PathBuf {
    let dir = if is_elevated {
        platform_system_config_dir().join("run")
    } else {
        // Try environment variable first (proper expansion)
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(PathBuf::from)
            // Fall back to dirs crate
            .or_else(|| dirs::data_local_dir())
            // Last resort: use system-wide directory with warning
            .unwrap_or_else(|| {
                log::warn!(
                    "Could not determine LOCALAPPDATA or user local data directory. \
                     Falling back to C:\\ProgramData (requires elevation for write access)."
                );
                PathBuf::from("C:\\ProgramData")
            })
            .join("kodegend")
            .join("run")
    };

    log::debug!(
        "Runtime directory (elevated={}): {}",
        is_elevated,
        dir.display()
    );

    dir
}

/// Log directory
///
/// Elevated: %ProgramData%\kodegend\logs
/// User: %LOCALAPPDATA%\kodegend\logs
///
/// Uses std::env::var() to properly expand Windows environment variables.
/// Falls back to dirs crate, then to C:\ProgramData if both fail.
pub(super) fn platform_log_dir(is_elevated: bool) -> PathBuf {
    let dir = if is_elevated {
        platform_system_config_dir().join("logs")
    } else {
        // Try environment variable first (proper expansion)
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(PathBuf::from)
            // Fall back to dirs crate
            .or_else(|| dirs::data_local_dir())
            // Last resort: use system-wide directory with warning
            .unwrap_or_else(|| {
                log::warn!(
                    "Could not determine LOCALAPPDATA or user local data directory. \
                     Falling back to C:\\ProgramData (requires elevation for write access)."
                );
                PathBuf::from("C:\\ProgramData")
            })
            .join("kodegend")
            .join("logs")
    };

    log::debug!(
        "Log directory (elevated={}): {}",
        is_elevated,
        dir.display()
    );

    dir
}

/// Status socket path for daemon queries
///
/// Windows uses named pipes instead of Unix sockets.
/// Format: \\.\pipe\kodegend\status
///
/// Named pipes on Windows are always process-local and do not use the filesystem,
/// so privilege level doesn't affect the path.
pub(super) fn platform_status_socket_path(_is_elevated: bool) -> PathBuf {
    PathBuf::from(r"\\.\pipe\kodegend\status")
}

/// Get the system's maximum PID value for Windows
///
/// Windows doesn't have a documented hard limit for PIDs, but uses DWORD (u32).
/// We use a conservative maximum based on Linux's absolute limit.
///
/// # Returns
/// Reasonable maximum PID value for Windows (4,194,304)
pub(super) fn platform_get_system_pid_max() -> u32 {
    // Windows doesn't have a documented hard limit, but use Linux max as conservative bound
    // This prevents obviously corrupted PID files while allowing legitimate Windows PIDs
    4_194_304
}

/// Platform-specific PID validation for Windows
///
/// Validates that a PID is within the safe range for Windows.
///
/// # Validation Rules
/// 1. PID must not be zero (System Idle Process)
/// 2. PID must not exceed reasonable maximum (4,194,304)
///
/// Windows uses u32 for PIDs, so negative values are impossible.
///
/// # Returns
/// - Ok(()) if PID is valid and safe to use
/// - Err with detailed error message if invalid
pub(super) fn platform_validate_pid_range(pid: u32) -> Result<(), anyhow::Error> {
    // Check 1: PID must not be zero (System Idle Process)
    if pid == 0 {
        bail!(
            "Invalid PID: 0 (System Idle Process)\n\
             \n\
             PID 0 is reserved for the System Idle Process and should never\n\
             appear in a daemon PID file. This indicates corruption."
        );
    }
    
    // Check 2: Platform-specific maximum (detects corrupted PID files)
    let max_pid = platform_get_system_pid_max();
    
    if pid > max_pid {
        bail!(
            "Invalid PID: {} exceeds reasonable maximum {}\n\
             \n\
             While Windows technically supports larger PIDs, this value\n\
             is suspiciously high and likely indicates corruption.",
            pid,
            max_pid
        );
    }
    
    Ok(())
}

/// Verify PID belongs to kodegend using sysinfo
///
/// Uses sysinfo::System to get process info and check executable path.
/// This works on Windows 7+ without additional dependencies.
///
/// Pattern copied from service/port_cleanup.rs:128-138
///
/// # Windows-Specific Considerations
/// - Process names are case-insensitive on Windows
/// - Executable may be "kodegend.exe" (with extension)
/// - System processes may block exe() access → fail-safe to permission error
///
/// # Implementation Details
/// 1. Quick check: Does PID exist? (via OpenProcess)
/// 2. Use sysinfo to get Process object
/// 3. Extract executable path via Process::exe()
/// 4. Verify filename is "kodegend.exe" (case-insensitive)
///
/// # Security
/// Prevents CVE-2020-14977 class attacks on Windows platforms
pub(super) fn platform_verify_kodegend_running(pid: u32) -> Result<bool, std::io::Error> {
    // First check if process exists at all (fast path)
    if !platform_is_process_running(pid)? {
        return Ok(false);
    }

    // Use sysinfo to get process details
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);

    let sysinfo_pid = Pid::from(pid as usize);
    let process = match system.process(sysinfo_pid) {
        Some(p) => p,
        None => {
            // Race condition: process exited between OpenProcess check and sysinfo lookup
            log::debug!(
                "Process {} exited between existence check and verification",
                pid
            );
            return Ok(false);
        }
    };

    // Check executable path
    match process.exe() {
        Some(exe_path) => {
            // Extract filename from path
            let exe_name = exe_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Windows is case-insensitive
            let exe_lower = exe_name.to_lowercase();

            // Accept "kodegend.exe", "kodegend-debug.exe", etc.
            let is_kodegend = exe_lower == "kodegend.exe"
                || exe_lower.starts_with("kodegend")
                || exe_lower == "kodegend"; // During development without .exe

            if is_kodegend {
                log::debug!(
                    "Verified PID {} is kodegend (exe: {})",
                    pid,
                    exe_path.display()
                );
            } else {
                log::debug!("PID {} is NOT kodegend (exe: {})", pid, exe_path.display());
            }

            Ok(is_kodegend)
        }
        None => {
            // Cannot read executable path
            // On Windows this typically means system process or access denied
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Cannot read executable path for PID {}", pid),
            ))
        }
    }
}
