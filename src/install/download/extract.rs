//! Package extraction for different platform formats
//!
//! Handles extracting binaries from .deb, .rpm, .dmg, and .zip packages.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::Archive;
use flate2::read::GzDecoder;
use super::platform::Platform;

/// Extract binary from .deb package (ar archive → data.tar.gz → usr/bin/)
pub async fn extract_from_deb(
    deb_path: &Path,
    binary_name: &str,
    output_dir: &Path,
) -> Result<PathBuf> {
    let temp_dir = tempfile::tempdir()?;

    // Step 1: Extract ar archive using 'ar' command (async)
    let output = tokio::process::Command::new("ar")
        .arg("x")
        .arg(deb_path)
        .current_dir(temp_dir.path())
        .output()
        .await?;

    if !output.status.success() {
        return Err(anyhow!("Failed to extract .deb archive: {:?}", output));
    }

    // Step 2: Extract data.tar.gz
    let data_tar_gz = temp_dir.path().join("data.tar.gz");
    if !tokio::fs::try_exists(&data_tar_gz).await? {
        return Err(anyhow!("data.tar.gz not found in .deb archive"));
    }

    let extract_dir = temp_dir.path().join("extracted");
    tokio::fs::create_dir_all(&extract_dir).await?;

    // Wrap CPU-bound tar extraction in spawn_blocking
    let extract_dir_clone = extract_dir.clone();
    let data_tar_gz_clone = data_tar_gz.clone();
    tokio::task::spawn_blocking(move || {
        let tar_gz_file = std::fs::File::open(&data_tar_gz_clone)?;
        let tar = GzDecoder::new(tar_gz_file);
        let mut archive = Archive::new(tar);
        archive.unpack(&extract_dir_clone)?;
        Ok::<_, anyhow::Error>(())
    }).await??;

    // Step 3: Find binary at usr/bin/{binary_name}
    let binary_path = extract_dir.join("usr/bin").join(binary_name);

    if !tokio::fs::try_exists(&binary_path).await? {
        return Err(anyhow!("Binary {} not found at usr/bin/ in .deb package", binary_name));
    }

    // Copy to persistent output directory
    let final_path = output_dir.join(binary_name);
    tokio::fs::copy(&binary_path, &final_path).await?;

    Ok(final_path)
}

/// Extract binary from .rpm package (rpm2cpio | cpio → usr/bin/)
pub async fn extract_from_rpm(
    rpm_path: &Path,
    binary_name: &str,
    output_dir: &Path,
) -> Result<PathBuf> {
    let temp_dir = tempfile::tempdir()?;
    let extract_dir = temp_dir.path().join("extracted");
    tokio::fs::create_dir_all(&extract_dir).await?;

    // Use rpm2cpio to convert RPM to cpio, then extract with cpio (async with manual piping)
    let mut rpm2cpio = tokio::process::Command::new("rpm2cpio")
        .arg(rpm_path)
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let mut cpio = tokio::process::Command::new("cpio")
        .arg("-idm")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .current_dir(&extract_dir)
        .spawn()?;

    // Manually pipe rpm2cpio stdout to cpio stdin
    let mut rpm2cpio_stdout = rpm2cpio.stdout.take()
        .ok_or_else(|| anyhow!("Failed to capture rpm2cpio stdout"))?;
    let mut cpio_stdin = cpio.stdin.take()
        .ok_or_else(|| anyhow!("Failed to capture cpio stdin"))?;

    // Spawn task to copy data between processes
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut rpm2cpio_stdout, &mut cpio_stdin).await;
    });

    // Wait for both processes to complete
    let rpm2cpio_status = rpm2cpio.wait().await?;
    let cpio_status = cpio.wait().await?;

    if !rpm2cpio_status.success() || !cpio_status.success() {
        return Err(anyhow!("Failed to extract .rpm package"));
    }

    // Binary should be at usr/bin/{binary_name}
    let binary_path = extract_dir.join("usr/bin").join(binary_name);

    if !tokio::fs::try_exists(&binary_path).await? {
        return Err(anyhow!("Binary {} not found at usr/bin/ in .rpm package", binary_name));
    }

    // Copy to persistent output directory
    let final_path = output_dir.join(binary_name);
    tokio::fs::copy(&binary_path, &final_path).await?;

    Ok(final_path)
}

/// RAII wrapper for macOS DMG mount point
///
/// Ensures DMG is automatically unmounted when dropped, even on error/panic.
/// Follows the same pattern as ScManagerHandle in src/install/windows.rs
#[cfg(target_os = "macos")]
struct DmgMount {
    mount_point: PathBuf,
}

#[cfg(target_os = "macos")]
impl DmgMount {
    /// Mount a DMG file at the specified mount point (async)
    async fn mount(dmg_path: &Path, mount_point: PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(&mount_point).await?;

        let mount = tokio::process::Command::new("hdiutil")
            .args(["attach", "-mountpoint"])
            .arg(&mount_point)
            .arg(dmg_path)
            .arg("-nobrowse")
            .arg("-quiet")
            .output()
            .await?;

        if !mount.status.success() {
            return Err(anyhow!("Failed to mount .dmg: {:?}", mount));
        }

        Ok(Self { mount_point })
    }

    /// Get the mount point path
    #[inline]
    fn path(&self) -> &Path {
        &self.mount_point
    }
}

#[cfg(target_os = "macos")]
impl Drop for DmgMount {
    fn drop(&mut self) {
        // Always try to unmount with -force flag
        // Ignore errors since we're in cleanup (best effort)
        let _ = Command::new("hdiutil")
            .args(["detach"])
            .arg(&self.mount_point)
            .arg("-force")  // Force unmount even if busy
            .output();
    }
}

/// Extract binary from macOS .dmg (requires hdiutil on macOS)
#[allow(unused_variables)]
pub async fn extract_from_dmg(
    dmg_path: &Path,
    binary_name: &str,
    output_dir: &Path,
) -> Result<PathBuf> {
    #[cfg(not(target_os = "macos"))]
    {
        return Err(anyhow!("DMG extraction only supported on macOS"));
    }

    #[cfg(target_os = "macos")]
    {
        let temp_dir = tempfile::tempdir()?;
        let mount_point = temp_dir.path().join("mount");

        // Mount DMG with RAII guard - auto-unmounts on ANY exit (async)
        let dmg_mount = DmgMount::mount(dmg_path, mount_point).await?;

        // Find .app bundle
        let app_bundle = dmg_mount.path().join(format!("{}.app", binary_name));
        let app_bundle = if tokio::fs::try_exists(&app_bundle).await? {
            app_bundle
        } else {
            // Try without exact name match (async)
            let mut entries = tokio::fs::read_dir(dmg_mount.path()).await?;
            let mut app_bundle = None;

            while let Some(entry) = entries.next_entry().await? {
                if entry.path().extension().and_then(|s| s.to_str()) == Some("app") {
                    app_bundle = Some(entry.path());
                    break;
                }
            }

            if let Some(app_path) = app_bundle {
                app_path
            } else {
                // No manual cleanup needed - Drop handles it
                return Err(anyhow!("No .app bundle found in .dmg"));
            }
        };

        // Binary is at .app/Contents/MacOS/{binary_name}
        let binary_path = app_bundle.join("Contents/MacOS").join(binary_name);

        if !tokio::fs::try_exists(&binary_path).await? {
            // No manual cleanup needed - Drop handles it
            return Err(anyhow!(
                "Binary not found in .app bundle at Contents/MacOS/{}",
                binary_name
            ));
        }

        // Copy binary to persistent output directory (async)
        let final_path = output_dir.join(binary_name);
        tokio::fs::copy(&binary_path, &final_path).await?;
        // ✅ If copy fails, Drop unmounts DMG automatically

        // Drop unmounts DMG here automatically on success
        Ok(final_path)
    }
}

/// Extract binary from Windows ZIP archive
pub async fn extract_from_windows_installer(
    installer_path: &Path,
    binary_name: &str,
    output_dir: &Path,
) -> Result<PathBuf> {
    use zip::ZipArchive;

    // Wrap entire ZIP extraction in spawn_blocking (CPU-bound operation)
    let installer_path = installer_path.to_path_buf();
    let binary_name = binary_name.to_string();
    let output_dir = output_dir.to_path_buf();

    tokio::task::spawn_blocking(move || {
        // Open ZIP archive
        let zip_file = std::fs::File::open(&installer_path)
            .context("Failed to open Windows ZIP archive")?;

        let mut archive = ZipArchive::new(zip_file)
            .context("Failed to read ZIP archive")?;

        // Expected binary filename
        let exe_name = format!("{}.exe", binary_name);

        // Search for binary in ZIP archive (may be at root or in subdirectory)
        let mut binary_found = false;
        let final_path = output_dir.join(&exe_name);

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)
                .context(format!("Failed to read ZIP entry at index {}", i))?;

            // Get the file name (handles both flat and nested structures)
            let file_name = file.name();

            // Check if this is the binary we're looking for
            // Match either:
            // 1. Exact name: "kodegen.exe"
            // 2. In subdirectory: "bin/kodegen.exe" or "kodegen/kodegen.exe"
            if file_name.ends_with(&exe_name) && !file.is_dir() {
                // Extract binary to output directory
                let mut outfile = std::fs::File::create(&final_path)
                    .context("Failed to create extracted binary file")?;

                std::io::copy(&mut file, &mut outfile)
                    .context("Failed to extract binary from ZIP")?;

                binary_found = true;
                break;
            }
        }

        if !binary_found {
            return Err(anyhow!(
                "Binary {} not found in Windows ZIP archive. Archive contains: {}",
                exe_name,
                (0..archive.len())
                    .filter_map(|i| archive.by_index(i).ok().map(|f| f.name().to_string()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        // Verify the extracted binary exists and is readable
        if !final_path.exists() {
            return Err(anyhow!("Binary extraction completed but file not found at {}", final_path.display()));
        }

        Ok::<PathBuf, anyhow::Error>(final_path)
    }).await?
}

/// Extract binary from downloaded package (platform-specific dispatcher)
pub async fn extract_binary_from_package(
    package_path: &Path,
    binary_name: &str,
    platform: Platform,
    output_dir: &Path,
) -> Result<PathBuf> {
    match platform {
        Platform::DebianAmd64 => extract_from_deb(package_path, binary_name, output_dir).await,
        Platform::RpmX8664 => extract_from_rpm(package_path, binary_name, output_dir).await,
        Platform::MacOsArm64 | Platform::MacOsX8664 => extract_from_dmg(package_path, binary_name, output_dir).await,
        Platform::WindowsX8664 => extract_from_windows_installer(package_path, binary_name, output_dir).await,
    }
}
