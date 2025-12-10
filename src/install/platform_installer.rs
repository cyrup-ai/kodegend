//! Platform-specific package installation
//!
//! This module handles proper installation of platform-native packages:
//! - macOS: Mount DMG, copy .app to /Applications/, create symlinks
//! - Linux (DEB): Install via dpkg to /usr/bin/
//! - Linux (RPM): Install via rpm to /usr/bin/
//! - Windows: Run NSIS installer, add to PATH
//!
//! This replaces the incorrect extract-and-copy approach with proper package
//! installation using platform-native tools and package managers.

use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

use crate::install::privilege::PrivilegedExecutor;
use crate::install::core::{InstallProgress, DownloadPhase};
use crate::install::binaries::BINARY_COUNT;

/// Install platform-specific packages
///
/// Takes downloaded package paths and installs them using platform-appropriate methods.
/// Requires elevated privileges for system installation.
pub async fn install_packages(
    package_paths: &[PathBuf],
    executor: &mut PrivilegedExecutor,
    progress_tx: Option<mpsc::Sender<InstallProgress>>,
) -> Result<()> {
    if package_paths.is_empty() {
        return Ok(());
    }

    // Detect platform and install accordingly
    #[cfg(target_os = "macos")]
    {
        install_macos_packages(package_paths, executor, progress_tx).await
    }

    #[cfg(target_os = "linux")]
    {
        install_linux_packages(package_paths, executor, progress_tx).await
    }

    #[cfg(target_os = "windows")]
    {
        install_windows_packages(package_paths, executor, progress_tx).await
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow!("Unsupported platform for package installation"))
    }
}

/// Install macOS DMG packages
///
/// Flow:
/// 1. Mount DMG using hdiutil
/// 2. Copy .app bundle to /Applications/
/// 3. Unmount DMG
/// 4. Create symlinks in /usr/local/bin/
/// 5. Clean up downloaded DMG
#[cfg(target_os = "macos")]
async fn install_macos_packages(
    package_paths: &[PathBuf],
    executor: &mut PrivilegedExecutor,
    progress_tx: Option<mpsc::Sender<InstallProgress>>,
) -> Result<()> {
    use tokio::process::Command;

    for (idx, dmg_path) in package_paths.iter().enumerate() {
        // Emit extracting progress
        if let Some(ref tx) = progress_tx {
            let binary_name = dmg_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("package");
            let _ = tx.try_send(InstallProgress::download(
                binary_name.to_string(),
                idx + 1,
                BINARY_COUNT,
                0,
                0,
                DownloadPhase::Extracting,
                None,
            ));
        }
        if dmg_path.extension().is_none_or(|ext| ext != "dmg") {
            log::warn!("Skipping non-DMG file: {}", dmg_path.display());
            continue;
        }

        log::info!("Installing DMG: {}", dmg_path.display());

        // 1. Mount DMG
        let output = Command::new("hdiutil")
            .args(["attach", dmg_path.to_str().unwrap(), "-nobrowse", "-quiet"])
            .output()
            .await
            .context("Failed to execute hdiutil attach")?;

        if !output.status.success() {
            return Err(anyhow!(
                "Failed to mount DMG {}: {}",
                dmg_path.display(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Parse mount point from hdiutil output
        let mount_point = parse_mount_point(&output.stdout)
            .context("Failed to parse mount point from hdiutil output")?;

        log::info!("DMG mounted at: {}", mount_point.display());

        // 2. Find .app bundle in mount point
        let app_bundle = find_app_bundle(&mount_point).context(format!(
            "Failed to find .app bundle in DMG at {}",
            mount_point.display()
        ))?;

        log::info!("Found app bundle: {}", app_bundle.display());

        // 3. Copy .app to /Applications/ (requires sudo)
        let app_name = app_bundle
            .file_name()
            .ok_or_else(|| anyhow!("Invalid app bundle path"))?;
        let dest_app = PathBuf::from("/Applications").join(app_name);

        // Remove existing app if present
        if dest_app.exists() {
            log::info!("Removing existing app at {}", dest_app.display());
            executor
                .exec(&["rm", "-rf", dest_app.to_str().unwrap()])
                .await
                .context("Failed to remove existing app")?;
        }

        log::info!("Copying app bundle to /Applications/");
        executor
            .exec(&["cp", "-R", app_bundle.to_str().unwrap(), "/Applications/"])
            .await
            .context("Failed to copy .app bundle to /Applications/")?;

        // 4. Unmount DMG
        log::info!("Unmounting DMG");
        let unmount_result = Command::new("hdiutil")
            .args(["detach", mount_point.to_str().unwrap(), "-quiet"])
            .output()
            .await;

        if let Err(e) = unmount_result {
            log::warn!("Failed to unmount DMG (non-fatal): {}", e);
        }

        // 5. Create CLI symlinks for binaries inside .app bundle
        log::info!("Creating CLI symlinks");
        create_macos_symlinks(&dest_app, executor).await?;

        // 6. Clean up downloaded DMG
        log::info!("Cleaning up downloaded DMG");
        if let Err(e) = tokio::fs::remove_file(dmg_path).await {
            log::warn!("Failed to remove DMG file (non-fatal): {}", e);
        }
    }

    Ok(())
}

/// Parse mount point from hdiutil attach output
///
/// hdiutil output format:
/// /dev/disk4s2        /Volumes/Kodegen
#[cfg(target_os = "macos")]
fn parse_mount_point(stdout: &[u8]) -> Result<PathBuf> {
    let output = String::from_utf8_lossy(stdout);

    for line in output.lines() {
        if line.contains("/Volumes/")
            && let Some(mount) = line.split_whitespace().last() {
                return Ok(PathBuf::from(mount));
            }
    }

    Err(anyhow!(
        "Failed to parse mount point from hdiutil output:\n{}",
        output
    ))
}

/// Find .app bundle in DMG mount point
#[cfg(target_os = "macos")]
fn find_app_bundle(mount_point: &Path) -> Result<PathBuf> {
    for entry in std::fs::read_dir(mount_point)
        .context(format!("Failed to read directory: {}", mount_point.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("app") {
            return Ok(path);
        }
    }

    Err(anyhow!(
        "No .app bundle found in DMG at {}",
        mount_point.display()
    ))
}

/// Create symlinks for binaries inside .app bundle
///
/// Creates symlinks in /usr/local/bin/ pointing to binaries in:
/// /Applications/{App}.app/Contents/MacOS/{binary}
#[cfg(target_os = "macos")]
async fn create_macos_symlinks(
    app_bundle: &Path,
    executor: &mut PrivilegedExecutor,
) -> Result<()> {
    let macos_dir = app_bundle.join("Contents/MacOS");

    if !macos_dir.exists() {
        return Err(anyhow!(
            "MacOS directory not found in app bundle: {}",
            macos_dir.display()
        ));
    }

    // Ensure /usr/local/bin exists
    executor
        .exec(&["mkdir", "-p", "/usr/local/bin"])
        .await
        .context("Failed to create /usr/local/bin")?;

    // Find all binaries in MacOS directory and create symlinks
    for entry in std::fs::read_dir(&macos_dir)
        .context(format!("Failed to read MacOS directory: {}", macos_dir.display()))?
    {
        let entry = entry?;
        let binary_path = entry.path();

        // Skip non-executable files
        if !binary_path.is_file() {
            continue;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&binary_path)?;
            let permissions = metadata.permissions();

            // Check if file is executable (has any execute bit set)
            if permissions.mode() & 0o111 == 0 {
                continue;
            }
        }

        let binary_name = binary_path
            .file_name()
            .ok_or_else(|| anyhow!("Invalid binary path"))?;

        let symlink_path = PathBuf::from("/usr/local/bin").join(binary_name);

        // Remove existing symlink if present
        if symlink_path.exists() || symlink_path.is_symlink() {
            log::info!("Removing existing symlink: {}", symlink_path.display());
            executor
                .exec(&["rm", "-f", symlink_path.to_str().unwrap()])
                .await
                .context("Failed to remove existing symlink")?;
        }

        log::info!(
            "Creating symlink: {} → {}",
            symlink_path.display(),
            binary_path.display()
        );

        executor
            .exec(&[
                "ln",
                "-s",
                binary_path.to_str().unwrap(),
                symlink_path.to_str().unwrap(),
            ])
            .await
            .context(format!("Failed to create symlink for {}", binary_name.to_string_lossy()))?;
    }

    Ok(())
}

/// Install Linux packages (DEB or RPM)
///
/// Flow:
/// 1. Detect package type (.deb or .rpm)
/// 2. Install using dpkg/rpm (installs to /usr/bin/)
/// 3. Clean up downloaded package
#[cfg(target_os = "linux")]
async fn install_linux_packages(
    package_paths: &[PathBuf],
    executor: &mut PrivilegedExecutor,
    progress_tx: Option<mpsc::Sender<InstallProgress>>,
) -> Result<()> {
    for (idx, package_path) in package_paths.iter().enumerate() {
        // Emit extracting progress
        if let Some(ref tx) = progress_tx {
            let binary_name = package_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("package");
            let _ = tx.try_send(InstallProgress::download(
                binary_name.to_string(),
                idx + 1,
                BINARY_COUNT,
                0,
                0,
                DownloadPhase::Extracting,
                None,
            ));
        }
        let extension = package_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        match extension {
            "deb" => {
                log::info!("Installing DEB package: {}", package_path.display());
                install_linux_deb(package_path, executor).await?;
            }
            "rpm" => {
                log::info!("Installing RPM package: {}", package_path.display());
                install_linux_rpm(package_path, executor).await?;
            }
            _ => {
                log::warn!("Skipping unknown package type: {}", package_path.display());
            }
        }
    }

    Ok(())
}

/// Install .deb package using dpkg
///
/// Installs to /usr/bin/ automatically (no symlinks needed)
#[cfg(target_os = "linux")]
async fn install_linux_deb(
    deb_path: &Path,
    executor: &mut PrivilegedExecutor,
) -> Result<()> {
    // Install .deb using dpkg
    executor
        .exec(&["dpkg", "-i", deb_path.to_str().unwrap()])
        .await
        .context(format!("Failed to install DEB package: {}", deb_path.display()))?;

    log::info!("DEB package installed successfully");

    // Clean up downloaded .deb
    if let Err(e) = tokio::fs::remove_file(deb_path).await {
        log::warn!("Failed to remove DEB file (non-fatal): {}", e);
    }

    // Binary is now at /usr/bin/kodegen and /usr/bin/kodegend
    // Both are already in PATH - no symlink needed
    Ok(())
}

/// Install .rpm package using rpm
///
/// Installs to /usr/bin/ automatically (no symlinks needed)
#[cfg(target_os = "linux")]
async fn install_linux_rpm(
    rpm_path: &Path,
    executor: &mut PrivilegedExecutor,
) -> Result<()> {
    // Install .rpm using rpm
    executor
        .exec(&["rpm", "-i", rpm_path.to_str().unwrap()])
        .await
        .context(format!("Failed to install RPM package: {}", rpm_path.display()))?;

    log::info!("RPM package installed successfully");

    // Clean up downloaded .rpm
    if let Err(e) = tokio::fs::remove_file(rpm_path).await {
        log::warn!("Failed to remove RPM file (non-fatal): {}", e);
    }

    // Binary is now at /usr/bin/kodegen and /usr/bin/kodegend
    // Both are already in PATH - no symlink needed
    Ok(())
}

/// Install Windows packages
///
/// Flow:
/// 1. Run NSIS installer silently
/// 2. Add installation directory to system PATH
/// 3. Clean up installer
#[cfg(target_os = "windows")]
async fn install_windows_packages(
    package_paths: &[PathBuf],
    executor: &mut PrivilegedExecutor,
    progress_tx: Option<mpsc::Sender<InstallProgress>>,
) -> Result<()> {
    for (idx, installer_path) in package_paths.iter().enumerate() {
        // Emit extracting progress
        if let Some(ref tx) = progress_tx {
            let binary_name = installer_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("package");
            let _ = tx.try_send(InstallProgress::download(
                binary_name.to_string(),
                idx + 1,
                BINARY_COUNT,
                0,
                0,
                DownloadPhase::Extracting,
                None,
            ));
        }
        let extension = installer_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        if extension != "exe" && extension != "msi" {
            log::warn!("Skipping non-installer file: {}", installer_path.display());
            continue;
        }

        log::info!("Installing Windows package: {}", installer_path.display());

        // Run NSIS installer silently
        executor
            .exec(&[installer_path.to_str().unwrap(), "/S"])
            .await
            .context(format!(
                "Failed to run installer: {}",
                installer_path.display()
            ))?;

        log::info!("Installer completed successfully");

        // Add to system PATH
        log::info!("Adding installation directory to PATH");
        add_to_windows_path(r"C:\Program Files\Kodegen", executor)
            .await
            .context("Failed to add to Windows PATH")?;

        // Clean up installer
        if let Err(e) = tokio::fs::remove_file(installer_path).await {
            log::warn!("Failed to remove installer file (non-fatal): {}", e);
        }
    }

    Ok(())
}

/// Add directory to Windows system PATH
///
/// Modifies HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
/// Requires Administrator privileges
#[cfg(target_os = "windows")]
async fn add_to_windows_path(
    dir: &str,
    executor: &mut PrivilegedExecutor,
) -> Result<()> {
    // PowerShell command to add to system PATH
    let ps_command = format!(
        "$currentPath = [Environment]::GetEnvironmentVariable('Path', 'Machine'); \
         if ($currentPath -notlike '*{}*') {{ \
             [Environment]::SetEnvironmentVariable('Path', $currentPath + ';{}', 'Machine') \
         }}",
        dir, dir
    );

    executor
        .exec(&["powershell", "-Command", &ps_command])
        .await
        .context("Failed to modify Windows PATH")?;

    log::info!("Successfully added {} to system PATH", dir);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_mount_point() {
        let output = b"/dev/disk4              GUID_partition_scheme
/dev/disk4s1            Apple_APFS
/dev/disk4s2            /Volumes/Kodegen";

        let mount_point = parse_mount_point(output).unwrap();
        assert_eq!(mount_point, PathBuf::from("/Volumes/Kodegen"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_mount_point_complex() {
        let output = b"/dev/disk5              GUID_partition_scheme
/dev/disk5s1            Apple_HFS                       /Volumes/Kodegen 1.0.0";

        let mount_point = parse_mount_point(output).unwrap();
        assert!(mount_point.to_str().unwrap().contains("/Volumes/"));
    }
}
