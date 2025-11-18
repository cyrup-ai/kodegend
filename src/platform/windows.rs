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

use std::path::PathBuf;
use std::mem;
use windows::Win32::Foundation::{CloseHandle, HANDLE, ERROR_INVALID_PARAMETER};
use windows::Win32::System::Threading::{
    GetCurrentProcess,
    GetCurrentProcessId,
    OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::Security::{
    GetTokenInformation,
    OpenProcessToken,
    TokenElevation,
    TOKEN_ELEVATION,
    TOKEN_QUERY,
};

/// Check if running as Administrator
///
/// Uses Windows Security API to check token elevation.
/// Pattern copied from install/installer/windows/privileges.rs:24-51
///
/// See: https://learn.microsoft.com/en-us/windows/win32/secauthz/asking-the-user-for-credentials
pub(super) fn platform_is_elevated() -> bool {
    unsafe {
        let mut token_handle: HANDLE = HANDLE::default();

        // Open process token with query access
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        // Query token elevation information
        let mut elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut return_length: u32 = 0;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        CloseHandle(token_handle);

        if result.is_err() {
            return false;
        }

        // TokenIsElevated is non-zero if elevated
        elevation.TokenIsElevated != 0
    }
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
        GetConsoleWindow().0 == 0
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

/// Check if process is running by PID
///
/// Uses OpenProcess() with PROCESS_QUERY_LIMITED_INFORMATION.
/// If OpenProcess succeeds, process exists.
/// If it fails with ERROR_INVALID_PARAMETER, process doesn't exist.
///
/// See: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
pub(super) fn platform_is_process_running(pid: u32) -> Result<bool, std::io::Error> {
    unsafe {
        // Try to open process handle with query access
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => {
                // Process exists - close handle and return true
                let _ = CloseHandle(handle);
                Ok(true)
            }
            Err(e) => {
                // Check error code
                if e.code().0 as u32 == ERROR_INVALID_PARAMETER.0 {
                    // Process doesn't exist
                    Ok(false)
                } else {
                    // Other error (permission denied, etc.)
                    Err(std::io::Error::from_raw_os_error(e.code().0))
                }
            }
        }
    }
}

/// System-wide configuration directory
///
/// Returns: %ProgramData%\kodegend (typically C:\ProgramData\kodegend)
pub(super) fn platform_system_config_dir() -> PathBuf {
    std::env::var("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData"))
        .join("kodegend")
}

/// User-specific configuration directory
///
/// Returns: %APPDATA%\kodegend (typically C:\Users\{user}\AppData\Roaming\kodegend)
/// Uses `dirs` crate for proper Windows path resolution
pub(super) fn platform_user_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("%APPDATA%"))
        .join("kodegend")
}

/// Runtime directory for PID files
///
/// Elevated: %ProgramData%\kodegend\run
/// User: %LOCALAPPDATA%\kodegend\run
pub(super) fn platform_runtime_dir(is_elevated: bool) -> PathBuf {
    if is_elevated {
        platform_system_config_dir().join("run")
    } else {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("%LOCALAPPDATA%"))
            .join("kodegend\\run")
    }
}

/// Log directory
///
/// Elevated: %ProgramData%\kodegend\logs
/// User: %LOCALAPPDATA%\kodegend\logs
pub(super) fn platform_log_dir(is_elevated: bool) -> PathBuf {
    if is_elevated {
        platform_system_config_dir().join("logs")
    } else {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("%LOCALAPPDATA%"))
            .join("kodegend\\logs")
    }
}
