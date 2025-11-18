//! Privilege management and helper executable handling.

use std::mem;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use once_cell::sync::{Lazy, OnceCell};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::InstallerError;

// Global helper path - initialized once, used everywhere (like macOS implementation)
pub(super) static HELPER_PATH: OnceCell<PathBuf> = OnceCell::new();

// Process-wide lock for helper extraction
pub(super) static HELPER_EXTRACTION_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

// Embedded helper executable data (like macOS APP_ZIP_DATA)
const HELPER_EXE_DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/KodegenHelper.exe"));

/// Check if we have sufficient privileges for service operations
pub(super) fn check_privileges() -> Result<(), InstallerError> {
    let mut token_handle: HANDLE = HANDLE::default();

    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle)
            .map_err(|e| InstallerError::PermissionDenied)?;

        let mut elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut return_length: u32 = 0;

        windows::Win32::Security::GetTokenInformation(
            token_handle,
            windows::Win32::Security::TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        )
        .map_err(|_| InstallerError::PermissionDenied)?;

        CloseHandle(token_handle);

        if elevation.TokenIsElevated == 0 {
            return Err(InstallerError::PermissionDenied);
        }
    }

    Ok(())
}

/// Ensure helper executable is extracted and available
pub(super) fn ensure_helper_path() -> Result<(), InstallerError> {
    // Acquire lock FIRST (released automatically when _guard drops)
    let _guard = HELPER_EXTRACTION_LOCK.lock().map_err(|e| {
        InstallerError::System(format!("Failed to acquire extraction lock: {}", e))
    })?;

    // Double-check pattern: check again after acquiring lock
    if HELPER_PATH.get().is_some() {
        return Ok(());
    }

    // Create unique helper path in temp directory
    let temp_dir = std::env::temp_dir();
    let helper_name = format!("KodegenHelper_{}.exe", std::process::id());
    let helper_path = temp_dir.join(helper_name);

    // Extract embedded helper executable
    std::fs::write(&helper_path, HELPER_EXE_DATA).map_err(|e| {
        InstallerError::System(format!("Failed to extract helper executable: {}", e))
    })?;

    // Verify the helper is properly signed
    verify_helper_signature(&helper_path)?;

    // Store the path globally
    HELPER_PATH
        .set(helper_path)
        .map_err(|_| InstallerError::System("Helper path already initialized".to_string()))?;

    // Lock released here automatically
    Ok(())
}

/// Verify helper executable signature
fn verify_helper_signature(helper_path: &Path) -> Result<(), InstallerError> {
    // Use the signing module to verify the helper
    crate::signing::verify_signature(helper_path).map_err(|e| {
        InstallerError::System(format!("Helper signature verification failed: {}", e))
    })?;
    Ok(())
}
