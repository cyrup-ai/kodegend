//! Binary staging and system installation for kodegen installer
//!
//! This module handles copying binaries to staging directories and installing them
//! to system paths. It implements privilege separation by staging files as an
//! unprivileged user before installing to system locations with elevated privileges.

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Stage binaries for installation (Phase 2 of privilege separation)
///
/// Copies binaries to a temporary staging directory as an unprivileged user.
/// The actual installation to system paths is deferred until install_with_elevated_privileges().
///
/// Returns the staging directory path for use in privileged installation phase.
pub async fn stage_binaries_for_install(binary_paths: &[PathBuf]) -> Result<PathBuf> {
    use std::fs;

    // Create staging directory in user-writable location
    let staging_dir = std::env::temp_dir().join(format!("kodegen_install_{}", std::process::id()));

    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("Failed to create staging directory: {}", staging_dir.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Copy binaries to staging (no root needed)
        for binary_path in binary_paths {
            let binary_name = binary_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid binary path: {}", binary_path.display()))?;

            let dest_path = staging_dir.join(binary_name);

            fs::copy(binary_path, &dest_path).with_context(|| {
                format!("Failed to copy {} to staging: {}", binary_path.display(), dest_path.display())
            })?;

            // Set executable permissions (755) in staging
            let mut perms = fs::metadata(&dest_path)
                .with_context(|| format!("Failed to read metadata: {}", dest_path.display()))?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&dest_path, perms)
                .with_context(|| format!("Failed to set permissions: {}", dest_path.display()))?;
        }
    }

    #[cfg(windows)]
    {
        // Copy binaries to staging on Windows
        for binary_path in binary_paths {
            let binary_name = binary_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid binary path: {}", binary_path.display()))?;

            let dest_path = staging_dir.join(binary_name);

            fs::copy(binary_path, &dest_path).with_context(|| {
                format!("Failed to copy {} to staging: {}", binary_path.display(), dest_path.display())
            })?;
        }
    }

    Ok(staging_dir)
}

/// Install downloaded binaries to system paths (DEPRECATED - use stage_binaries_for_install instead)
///
/// This function directly installs to system paths and requires root privileges.
/// It is kept for backward compatibility but should not be used in the main installation flow.
///
/// Copies all binaries to appropriate system locations:
/// - Linux: /usr/local/bin
/// - macOS: /usr/local/bin
/// - Windows: C:\Program Files\Kodegen
#[allow(dead_code)]
pub async fn install_binaries_to_system(binary_paths: &[PathBuf]) -> Result<()> {
    use std::fs;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let bin_dir = PathBuf::from("/usr/local/bin");

        // Ensure bin directory exists
        if !bin_dir.exists() {
            fs::create_dir_all(&bin_dir)
                .context("Failed to create /usr/local/bin directory")?;
        }

        // Copy each binary and set executable permissions
        for binary_path in binary_paths {
            let binary_name = binary_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid binary path: {}", binary_path.display()))?;

            let dest_path = bin_dir.join(binary_name);

            fs::copy(binary_path, &dest_path).with_context(|| {
                format!("Failed to copy {} to {}", binary_path.display(), dest_path.display())
            })?;

            // Set executable permissions (755)
            let mut perms = fs::metadata(&dest_path)
                .with_context(|| format!("Failed to read metadata: {}", dest_path.display()))?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&dest_path, perms)
                .with_context(|| format!("Failed to set permissions: {}", dest_path.display()))?;
        }
    }

    #[cfg(windows)]
    {
        let bin_dir = PathBuf::from(r"C:\Program Files\Kodegen");

        if !bin_dir.exists() {
            fs::create_dir_all(&bin_dir)
                .context("Failed to create C:\\Program Files\\Kodegen directory")?;
        }

        for binary_path in binary_paths {
            let binary_name = binary_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid binary path: {}", binary_path.display()))?;

            let dest_path = bin_dir.join(binary_name);

            fs::copy(binary_path, &dest_path).with_context(|| {
                format!("Failed to copy {} to {}", binary_path.display(), dest_path.display())
            })?;
        }
    }

    Ok(())
}
