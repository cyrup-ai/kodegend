//! Windows-specific path constants and utilities for installation
//!
//! This module provides centralized path management for the Windows installation process.
//! It is separate from the runtime path module (src/platform/windows.rs) which handles
//! paths for the running daemon.
//!
//! ## Path Hierarchy
//!
//! - Installation Paths (this module):
//!   - Binary installation: C:\Program Files\Kodegen\
//!   - Installer data: C:\ProgramData\Kodegen\
//!   - System files: C:\Windows\System32\drivers\etc\hosts
//!
//! - Runtime Paths (platform/windows.rs):
//!   - Daemon config: C:\ProgramData\kodegend\
//!   - User config: %APPDATA%\kodegend\
//!   - Logs: C:\ProgramData\kodegend\logs\

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Installation scope (system-wide vs user-specific)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallScope {
    /// System-wide installation (C:\Program Files, requires admin)
    System,
    /// Per-user installation (C:\Users\{user}\AppData\Local\Programs)
    User,
}

/// Get the appropriate Program Files directory
///
/// Uses environment variables to handle 32-bit vs 64-bit:
/// - %ProgramW6432% - 64-bit Program Files (preferred on 64-bit Windows)
/// - %ProgramFiles% - Platform-specific Program Files
///
/// Falls back to hardcoded path if environment variables unavailable.
pub fn program_files_dir() -> PathBuf {
    // On 64-bit Windows, ProgramW6432 points to the 64-bit Program Files
    // On 32-bit Windows, ProgramW6432 doesn't exist, so use ProgramFiles
    if let Ok(dir) = std::env::var("ProgramW6432") {
        PathBuf::from(dir)
    } else if let Ok(dir) = std::env::var("ProgramFiles") {
        PathBuf::from(dir)
    } else {
        // Fallback for systems where env vars aren't set
        PathBuf::from(r"C:\Program Files")
    }
}

/// Get the ProgramData directory
///
/// Uses %ProgramData% environment variable, falls back to C:\ProgramData
pub fn program_data_dir() -> PathBuf {
    std::env::var("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"))
}

/// Get the installation directory based on scope
///
/// - System: C:\Program Files\Kodegen
/// - User: C:\Users\{user}\AppData\Local\Programs\Kodegen
pub fn install_dir(scope: InstallScope) -> PathBuf {
    match scope {
        InstallScope::System => program_files_dir().join("Kodegen"),
        InstallScope::User => {
            // Use dirs crate for cross-platform path resolution
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default\AppData\Local"))
                .join("Programs")
                .join("Kodegen")
        }
    }
}

/// Get the kodegend executable path
pub fn kodegend_exe(scope: InstallScope) -> PathBuf {
    install_dir(scope).join("kodegend.exe")
}

/// Get the kodegen CLI executable path
#[allow(dead_code)]
pub fn kodegen_exe(scope: InstallScope) -> PathBuf {
    install_dir(scope).join("kodegen.exe")
}

/// Get the installer program data directory
///
/// Returns: C:\ProgramData\Kodegen
///
/// **Note**: Different from runtime daemon data (C:\ProgramData\kodegend)
pub fn installer_data_dir() -> PathBuf {
    program_data_dir().join("Kodegen")
}

/// Get the certificate storage directory
pub fn cert_dir() -> PathBuf {
    installer_data_dir().join("certs")
}

/// Get the service definitions directory
pub fn services_dir() -> PathBuf {
    installer_data_dir().join("services")
}

/// Get the installer log directory
pub fn installer_log_dir() -> PathBuf {
    installer_data_dir().join("logs")
}

/// Get the installer config directory
pub fn installer_config_dir() -> PathBuf {
    installer_data_dir().join("config")
}

/// Get the Windows hosts file path
pub fn hosts_file() -> PathBuf {
    std::env::var("SystemRoot")
        .map(|root| PathBuf::from(root).join(r"System32\drivers\etc\hosts"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts"))
}

/// Create all standard installer directories
pub fn create_installer_directories(scope: InstallScope) -> Result<()> {
    let dirs = vec![
        install_dir(scope),
        installer_data_dir(),
        cert_dir(),
        services_dir(),
        installer_log_dir(),
        installer_config_dir(),
    ];

    for dir in dirs {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create directory: {}", dir.display()))?;
    }

    Ok(())
}

// SECURITY: Unsafe batch command builders removed (CVE-2024-24576 - BatBadBut)
// These functions generated batch scripts that cannot be safely escaped on Windows.
// Replaced with structured command protocol that uses Windows APIs directly.
// See: task/04_HIGH_windows_script_injection_uac.md

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_files_from_env() {
        // This test verifies environment variable usage
        // Actual values depend on system configuration
        let pf_dir = program_files_dir();
        assert!(pf_dir.to_string_lossy().contains("Program Files"));
    }

    #[test]
    fn test_install_paths() {
        let system_path = kodegend_exe(InstallScope::System);
        assert!(system_path.to_string_lossy().contains("Program Files"));
        assert!(system_path.to_string_lossy().ends_with("kodegend.exe"));

        let user_path = kodegend_exe(InstallScope::User);
        assert!(user_path.to_string_lossy().contains("AppData"));
        assert!(user_path.to_string_lossy().ends_with("kodegend.exe"));
    }

    #[test]
    fn test_temp_paths() {
        let temp_cert = temp_cert_file().expect("Failed to create temp cert file");
        let path = temp_cert.path();
        assert!(path.to_string_lossy().contains("kodegen_cert_"));
        assert!(path.extension().and_then(|s| s.to_str()) == Some("crt"));
    }

    // Test for batch commands removed - those unsafe functions have been deleted
    // for security reasons (BatBadBut vulnerability)
}
