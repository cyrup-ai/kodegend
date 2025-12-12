//! Windows privilege escalation using UAC (User Account Control).
//!
//! This module uses ShellExecuteExW with the "runas" verb to trigger UAC elevation,
//! showing the native Windows authentication dialog.
//!
//! # Authorization Reuse
//!
//! This module provides two patterns:
//! 1. `execute_privileged_windows()` - Creates a new UAC elevation for each call (legacy)
//! 2. `ElevatedHelper` - Spawns a persistent elevated process, commands sent via file IPC
//!
//! The second pattern is preferred for multi-operation installations to avoid multiple UAC prompts.
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
use std::path::PathBuf;
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

// ============================================================================
// ELEVATED HELPER - Persistent elevated process for multiple commands
// ============================================================================

/// Command completion marker used to detect when a command finishes
#[allow(dead_code)]
const CMD_DONE_MARKER: &str = "___KODEGEN_CMD_DONE___";
/// Exit command marker
const EXIT_MARKER: &str = "___KODEGEN_EXIT___";

/// An elevated helper process that accepts commands via named pipe.
///
/// Commands are sent via a named pipe, eliminating repeated UAC prompts.
/// This is the preferred method for multi-operation installations.
///
/// # Architecture
///
/// 1. A batch script is created that runs a command loop, reading from a named pipe
/// 2. The script is elevated via UAC (ONE prompt)
/// 3. Commands are sent to the pipe, results read back
/// 4. On drop, an exit command is sent to cleanly terminate the helper
///
/// # Example
/// ```ignore
/// let mut helper = ElevatedHelper::spawn()?;  // ONE UAC prompt
/// helper.exec("mkdir C:\\ProgramData\\Kodegen")?;   // No new prompt
/// helper.exec("copy temp.exe C:\\ProgramData\\Kodegen\\")?;  // No new prompt
/// // Helper is terminated automatically when dropped
/// ```
pub struct ElevatedHelper {
    /// Directory containing IPC files (command and result files)
    ipc_dir: PathBuf,
    /// Path to command file (we write commands here)
    cmd_file: PathBuf,
    /// Path to result file (elevated process writes results here)
    result_file: PathBuf,
    /// Path to status file (elevated process writes status here)
    status_file: PathBuf,
}

impl ElevatedHelper {
    /// Spawn an elevated helper process via UAC (ONE prompt).
    ///
    /// Creates a batch script that polls for commands in a temp directory,
    /// then elevates it via UAC.
    ///
    /// # Returns
    /// * `Ok(ElevatedHelper)` - Ready to accept commands via `exec()`
    /// * `Err(UacError::Cancelled)` - User clicked No on UAC dialog
    /// * `Err(UacError::Failed)` - Other error
    pub fn spawn() -> Result<Self, UacError> {
        let session_id = uuid::Uuid::new_v4();
        let temp_dir = std::env::temp_dir();
        let ipc_dir = temp_dir.join(format!("kodegen_elevated_{}", session_id));

        // Create IPC directory
        std::fs::create_dir_all(&ipc_dir)
            .map_err(|e| UacError::Failed { code: 0, message: format!("Failed to create IPC dir: {}", e) })?;

        let cmd_file = ipc_dir.join("command.txt");
        let result_file = ipc_dir.join("result.txt");
        let status_file = ipc_dir.join("status.txt");
        let script_file = ipc_dir.join("helper.bat");
        let ready_file = ipc_dir.join("ready.txt");

        // Create the helper batch script
        // This script polls for commands and executes them
        let script_content = format!(
            r#"@echo off
setlocal EnableDelayedExpansion

:: Signal that we're ready
echo READY > "{ready}"

:loop
:: Wait for command file to appear
if not exist "{cmd}" (
    timeout /t 1 /nobreak > nul
    goto loop
)

:: Read command
set /p CMD=<"{cmd}"
del "{cmd}" > nul 2>&1

:: Check for exit command
if "!CMD!"=="{exit_marker}" (
    echo EXITING > "{status}"
    exit /b 0
)

:: Execute command and capture output
echo RUNNING > "{status}"
cmd /c !CMD! > "{result}" 2>&1
echo DONE > "{status}"

goto loop
"#,
            cmd = cmd_file.display(),
            result = result_file.display(),
            status = status_file.display(),
            ready = ready_file.display(),
            exit_marker = EXIT_MARKER,
        );

        std::fs::write(&script_file, script_content)
            .map_err(|e| UacError::Failed { code: 0, message: format!("Failed to write helper script: {}", e) })?;

        log::info!("Spawning elevated helper via UAC...");

        // Launch the batch script elevated
        execute_privileged_windows(&format!("cmd /c \"{}\"", script_file.display()))?;

        // Wait for ready signal (up to 30 seconds)
        let start = std::time::Instant::now();
        while !ready_file.exists() {
            if start.elapsed() > std::time::Duration::from_secs(30) {
                // Cleanup
                let _ = std::fs::remove_dir_all(&ipc_dir);
                return Err(UacError::Failed {
                    code: 0,
                    message: "Elevated helper timed out waiting to start".to_string(),
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        log::info!("Elevated helper ready");

        Ok(Self {
            ipc_dir,
            cmd_file,
            result_file,
            status_file,
        })
    }

    /// Execute a command in the elevated helper (NO new UAC prompt).
    ///
    /// # Arguments
    /// * `command` - Command to execute with elevated privileges
    ///
    /// # Returns
    /// * `Ok(String)` - Command output (stdout + stderr)
    /// * `Err(UacError::Failed)` - Command execution or IPC failed
    pub fn exec(&mut self, command: &str) -> Result<String, UacError> {
        log::debug!("Elevated helper executing: {}", command);

        // Clear previous result
        let _ = std::fs::remove_file(&self.result_file);
        let _ = std::fs::remove_file(&self.status_file);

        // Write command
        std::fs::write(&self.cmd_file, command)
            .map_err(|e| UacError::Failed { code: 0, message: format!("Failed to write command: {}", e) })?;

        // Wait for completion (poll status file)
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > std::time::Duration::from_secs(300) {
                return Err(UacError::Failed {
                    code: 0,
                    message: "Command timed out after 5 minutes".to_string(),
                });
            }

            if let Ok(status) = std::fs::read_to_string(&self.status_file) {
                let status = status.trim();
                if status == "DONE" {
                    break;
                } else if status == "EXITING" {
                    return Err(UacError::Failed {
                        code: 0,
                        message: "Helper process exited unexpectedly".to_string(),
                    });
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // Read result
        let output = std::fs::read_to_string(&self.result_file)
            .unwrap_or_default();

        log::debug!("Elevated helper command completed, output length: {}", output.len());
        Ok(output)
    }
}

impl Drop for ElevatedHelper {
    fn drop(&mut self) {
        log::debug!("Dropping ElevatedHelper, signaling exit");

        // Send exit command
        let _ = std::fs::write(&self.cmd_file, EXIT_MARKER);

        // Give helper time to exit
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Clean up IPC directory
        let _ = std::fs::remove_dir_all(&self.ipc_dir);

        log::debug!("ElevatedHelper cleanup complete");
    }
}
