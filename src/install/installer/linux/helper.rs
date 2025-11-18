//! Helper executable management for Linux platform.
//!
//! This module handles extraction, verification, and initialization of the embedded
//! helper executable used for privileged operations.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::Result;
use once_cell::sync::{Lazy, OnceCell};

use super::InstallerError;

// Global helper path - initialized once, used everywhere
pub(super) static HELPER_PATH: OnceCell<PathBuf> = OnceCell::new();

// Process-wide lock for helper extraction
static HELPER_EXTRACTION_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

// Embedded helper executable data
const HELPER_BINARY_DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/kodegen-helper"));

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
    let helper_name = format!("kodegen-helper-{}", std::process::id());
    let helper_path = temp_dir.join(helper_name);

    // Extract embedded helper executable
    fs::write(&helper_path, HELPER_BINARY_DATA).map_err(|e| {
        InstallerError::System(format!("Failed to extract helper executable: {}", e))
    })?;

    // Make helper executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&helper_path)
            .map_err(|e| {
                InstallerError::System(format!("Failed to get helper metadata: {}", e))
            })?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&helper_path, perms).map_err(|e| {
            InstallerError::System(format!("Failed to set helper permissions: {}", e))
        })?;
    }

    // Verify the helper is properly signed (if signing is available)
    #[cfg(target_os = "macos")]
    if crate::signing::is_signing_available() {
        verify_helper_signature(&helper_path)?;
    }

    // Store the path globally
    HELPER_PATH
        .set(helper_path)
        .map_err(|_| InstallerError::System("Helper path already initialized".to_string()))?;

    // Lock released here automatically
    Ok(())
}

/// Verify helper executable signature (if signing is available)
#[cfg(target_os = "macos")]
fn verify_helper_signature(helper_path: &Path) -> Result<(), InstallerError> {
    // Use the signing module to verify the helper
    crate::signing::verify_signature(helper_path).map_err(|e| {
        InstallerError::System(format!("Helper signature verification failed: {}", e))
    })?;
    Ok(())
}
