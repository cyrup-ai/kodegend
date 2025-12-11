//! Windows privilege escalation using UAC (User Account Control).
//!
//! This module uses ShellExecuteExW with the "runas" verb to trigger UAC elevation,
//! showing the native Windows authentication dialog.
//!
//! # References
//! - https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw
//! - https://docs.microsoft.com/en-us/windows/win32/shell/launch-uac
//!
//! # Exit Codes
//! - 0: Success
//! - ERROR_CANCELLED (1223): User clicked "No" on UAC dialog

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};
use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// Execute a command with UAC elevation.
///
/// Uses ShellExecuteExW with "runas" verb to show the UAC dialog.
/// This will prompt the user for administrator credentials if not already elevated.
///
/// # Arguments
/// * `command` - Command line to execute with elevated privileges (e.g., "cmd /c mkdir C:\\test")
///
/// # Returns
/// * `Ok(())` on successful execution
/// * `Err(UacError::Cancelled)` if user clicked "No" on UAC dialog (error 1223)
/// * `Err(UacError::Failed)` for other errors
///
/// # Example
/// ```ignore
/// execute_privileged_windows("cmd /c mkdir C:\\Program Files\\Kodegen")?;
/// ```
pub fn execute_privileged_windows(command: &str) -> Result<(), UacError> {
    // Parse command into executable and parameters
    // For simplicity, we assume first token is the executable
    let parts: Vec<&str> = command.splitn(2, ' ').collect();
    let executable = parts[0];
    let parameters = if parts.len() > 1 { parts[1] } else { "" };

    // Convert strings to wide (UTF-16) for Windows API
    let executable_wide: Vec<u16> = OsStr::new(executable)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let parameters_wide: Vec<u16> = OsStr::new(parameters)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb_wide: Vec<u16> = OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // Set up SHELLEXECUTEINFOW structure
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS, // Get process handle so we can wait
            hwnd: HWND(std::ptr::null_mut()),
            lpVerb: PCWSTR(verb_wide.as_ptr()),
            lpFile: PCWSTR(executable_wide.as_ptr()),
            lpParameters: PCWSTR(parameters_wide.as_ptr()),
            lpDirectory: PCWSTR::null(),
            nShow: SW_HIDE.0,
            hInstApp: Default::default(),
            lpIDList: std::ptr::null_mut(),
            lpClass: PCWSTR::null(),
            hkeyClass: Default::default(),
            dwHotKey: 0,
            Anonymous: Default::default(),
            hProcess: Default::default(),
        };

        // Execute with elevation
        if let Err(e) = ShellExecuteExW(&mut info) {
            let code = e.code().0 as u32;
            return if code == 1223 {
                // ERROR_CANCELLED - user clicked "No" on UAC dialog
                Err(UacError::Cancelled)
            } else {
                Err(UacError::Failed {
                    code,
                    message: e.to_string(),
                })
            };
        }

        // Wait for the process to complete
        if !info.hProcess.is_invalid() {
            WaitForSingleObject(info.hProcess, INFINITE);
            
            // Get exit code
            let mut exit_code: u32 = 0;
            if windows::Win32::System::Threading::GetExitCodeProcess(
                info.hProcess,
                &mut exit_code,
            )
            .is_ok()
                && exit_code != 0
            {
                return Err(UacError::CommandFailed(exit_code));
            }

            // Close process handle
            let _ = windows::Win32::Foundation::CloseHandle(info.hProcess);
        }
    }

    Ok(())
}

/// Errors that can occur during UAC elevation
#[derive(Debug)]
pub enum UacError {
    /// User clicked "No" on UAC dialog (error code 1223)
    Cancelled,
    /// ShellExecuteExW failed with other error
    Failed { code: u32, message: String },
    /// Command executed but returned non-zero exit code
    CommandFailed(u32),
}

impl std::fmt::Display for UacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "UAC elevation cancelled by user"),
            Self::Failed { code, message } => {
                write!(f, "UAC elevation failed (code {}): {}", code, message)
            }
            Self::CommandFailed(code) => {
                write!(f, "Elevated command failed with exit code {}", code)
            }
        }
    }
}

impl std::error::Error for UacError {}
