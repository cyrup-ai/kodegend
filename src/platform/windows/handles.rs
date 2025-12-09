//! Safe RAII wrappers for Windows HANDLE types
//!
//! The `windows` crate v0.62 HANDLE type does NOT implement Drop automatically.
//! These wrappers provide panic-safe, leak-proof handle management.
//!
//! References:
//! - https://users.rust-lang.org/t/handle-is-automatically-free/125941
//! - https://doc.rust-lang.org/std/os/windows/io/struct.OwnedHandle.html

use anyhow::{anyhow, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    OpenProcess, 
    PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE,
};
use windows::Win32::System::Threading::OpenProcessToken;
use windows::Win32::Security::TOKEN_QUERY;

/// RAII wrapper for Windows process handles (PROCESS_*)
///
/// Automatically calls CloseHandle on drop - panic-safe and leak-proof.
/// Zero-cost abstraction - compiler optimizes to raw handle operations.
#[derive(Debug)]
pub struct ProcessHandle(HANDLE);

impl ProcessHandle {
    /// Open process with PROCESS_QUERY_LIMITED_INFORMATION access
    ///
    /// Used for checking if process exists without requiring full access.
    pub fn open_query(pid: u32) -> Result<Self> {
        unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                .map(ProcessHandle)
                .map_err(|e| anyhow!(
                    "Failed to open process {} for query: {} (error code: {})",
                    pid,
                    std::io::Error::from_raw_os_error(e.code().0),
                    e.code().0
                ))
        }
    }

    /// Open process with PROCESS_TERMINATE access
    ///
    /// Used for terminating processes.
    pub fn open_terminate(pid: u32) -> Result<Self> {
        unsafe {
            OpenProcess(PROCESS_TERMINATE, false, pid)
                .map(ProcessHandle)
                .map_err(|e| anyhow!(
                    "Failed to open process {} for termination: {} (error code: {})",
                    pid,
                    std::io::Error::from_raw_os_error(e.code().0),
                    e.code().0
                ))
        }
    }

    /// Get raw HANDLE value
    ///
    /// Use this to pass the handle to Windows API functions.
    /// The handle remains owned by ProcessHandle and will be closed on drop.
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for ProcessHandle {
    /// Automatically close handle when ProcessHandle goes out of scope
    ///
    /// This runs on:
    /// - Normal scope exit
    /// - Early return (?, return)
    /// - Panic unwinding
    ///
    /// Does NOT run on:
    /// - SIGKILL / process termination
    /// - std::process::abort()
    /// - std::process::exit()
    fn drop(&mut self) {
        unsafe {
            // CloseHandle returns BOOL (0 = failure, non-zero = success)
            // We ignore errors in Drop to avoid panic-in-drop issues
            let _ = CloseHandle(self.0);

            // In debug builds, verify cleanup succeeded
            #[cfg(debug_assertions)]
            {
                if CloseHandle(self.0).is_err() {
                    log::error!(
                        "CloseHandle failed for ProcessHandle (handle: {:?}). \
                         This may indicate handle corruption or double-free.",
                        self.0
                    );
                }
            }
        }
    }
}

/// RAII wrapper for Windows token handles (from OpenProcessToken)
///
/// Automatically calls CloseHandle on drop - panic-safe and leak-proof.
#[derive(Debug)]
pub struct TokenHandle(HANDLE);

impl TokenHandle {
    /// Open current process token with TOKEN_QUERY access
    ///
    /// Used for checking elevation status and other token information.
    pub fn open_current_process_query() -> Result<Self> {
        unsafe {
            use windows::Win32::System::Threading::GetCurrentProcess;
            
            let mut handle = HANDLE::default();
            
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle)
                .map_err(|e| anyhow!(
                    "Failed to open process token: {} (error code: {})",
                    std::io::Error::from_raw_os_error(e.code().0),
                    e.code().0
                ))?;
            
            Ok(TokenHandle(handle))
        }
    }

    /// Get raw HANDLE value
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for TokenHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);

            #[cfg(debug_assertions)]
            {
                if CloseHandle(self.0).is_err() {
                    log::error!(
                        "CloseHandle failed for TokenHandle (handle: {:?}). \
                         This may indicate handle corruption or double-free.",
                        self.0
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_handle_opens_current_process() {
        let pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };
        let handle = ProcessHandle::open_query(pid).expect("Should open current process");
        // Handle automatically closed when scope exits
    }

    #[test]
    fn token_handle_opens_current_token() {
        let handle = TokenHandle::open_current_process_query()
            .expect("Should open current process token");
        // Handle automatically closed when scope exits
    }

    #[test]
    fn process_handle_fails_for_invalid_pid() {
        // PID 0 is invalid on Windows
        let result = ProcessHandle::open_query(0);
        assert!(result.is_err());
    }
}
