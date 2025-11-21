//! Binary download and orchestration with progress tracking

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use log::warn;
use sha2::{Sha256, Digest};

use crate::install::core::{InstallProgress, DownloadPhase};
use crate::install::binaries::{BINARIES, BINARY_COUNT};
use super::platform::Platform;
use super::github::get_latest_release;
use super::extract::extract_binary_from_package;

// Download timeout constants following codebase patterns
// (see apple_api.rs:239-241, fluent_voice.rs:9, main.rs:15)
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);  // Initial connection
const DOWNLOAD_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(300); // 5 min no data

/// Verify package integrity using SHA256 checksums
///
/// Downloads checksums.txt from the GitHub release and verifies the package
/// matches its expected checksum. This protects against:
/// - Man-in-the-middle attacks
/// - Compromised GitHub accounts
/// - DNS poisoning / BGP hijacking
/// - Supply chain attacks
async fn verify_package_checksum(
    client: &reqwest::Client,
    repo: &str,
    release_tag: &str,
    asset_name: &str,
    package_path: &Path,
) -> Result<()> {
    // Download checksums.txt from the same release
    let checksums_url = format!(
        "https://github.com/{}/releases/download/{}/checksums.txt",
        repo, release_tag
    );

    let checksums_response = client
        .get(&checksums_url)
        .send()
        .await
        .context(format!(
            "Failed to download checksums.txt from release {}. \
             This file is required for security verification. \
             The release may be incomplete or corrupted.",
            release_tag
        ))?;

    if !checksums_response.status().is_success() {
        return Err(anyhow!(
            "Checksums file not found for release {} (HTTP {}). \
             Cannot verify package integrity. This may indicate an incomplete \
             release or a security issue.",
            release_tag,
            checksums_response.status()
        ));
    }

    let checksums_text = checksums_response
        .text()
        .await
        .context("Failed to read checksums.txt content")?;

    // Parse expected checksum for this asset
    // Format: "checksum  filename" (two spaces or tab separator)
    let expected_checksum = checksums_text
        .lines()
        .find(|line| {
            // Match lines containing the asset name
            // Handle both "checksum  filename" and "checksum filename" formats
            line.contains(asset_name)
        })
        .and_then(|line| {
            // Extract checksum (first whitespace-separated token)
            line.split_whitespace().next()
        })
        .ok_or_else(|| {
            anyhow!(
                "Checksum not found for {} in checksums.txt. \
                 Available checksums:\n{}",
                asset_name,
                checksums_text
                    .lines()
                    .take(10)
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })?;

    // Calculate actual SHA256 checksum of downloaded file
    let file_contents = tokio::fs::read(package_path)
        .await
        .context("Failed to read downloaded package for checksum verification")?;

    let mut hasher = Sha256::new();
    hasher.update(&file_contents);
    let actual_checksum = format!("{:x}", hasher.finalize());

    // Verify checksums match
    if actual_checksum != expected_checksum {
        return Err(anyhow!(
            "SECURITY WARNING: Checksum mismatch for {}!\n\
             Expected: {}\n\
             Got:      {}\n\
             \n\
             The downloaded file does not match the expected checksum.\n\
             This may indicate:\n\
             - A man-in-the-middle attack\n\
             - File corruption during download\n\
             - A compromised release\n\
             \n\
             DO NOT proceed with installation. Delete the downloaded file and:\n\
             1. Verify your network connection is secure\n\
             2. Check if the GitHub repository has been compromised\n\
             3. Contact the maintainers if this persists",
            asset_name,
            expected_checksum,
            actual_checksum
        ));
    }

    Ok(())
}

/// Download a single binary from its GitHub repository with progress reporting
async fn download_binary(
    repo: &str,
    binary_name: &str,
    binary_index: usize,
    platform: Platform,
    progress_tx: mpsc::Sender<InstallProgress>,
    output_dir: &std::path::Path,
) -> Result<PathBuf> {
    // Track if we've already warned about channel closure
    let progress_disabled = Arc::new(AtomicBool::new(false));

    // Helper for critical progress
    let send_critical = |progress: InstallProgress| -> Result<()> {
        if progress_tx.is_closed() {
            return Err(anyhow::anyhow!(
                "Download cancelled: progress channel closed"
            ));
        }
        progress_tx.try_send(progress)
            .map_err(|_| anyhow::anyhow!("Progress channel closed"))?;
        Ok(())
    };

    // Helper for best-effort progress
    let send_best_effort = |progress: InstallProgress| {
        if progress_disabled.load(Ordering::Relaxed) {
            return;
        }
        if let Err(e) = progress_tx.try_send(progress)
            && matches!(e, tokio::sync::mpsc::error::TrySendError::Closed(_))
        {
            warn!("Progress channel closed, continuing download without updates");
            progress_disabled.store(true, Ordering::Relaxed);
        }
    };

    // Phase 1: Discover latest release
    send_critical(InstallProgress::download(
        binary_name.to_string(),
        binary_index,
        BINARY_COUNT,
        0,
        0,
        DownloadPhase::Discovering,
        None,
    ))?;

    let release = get_latest_release(repo).await?;
    let version = Some(release.tag_name.clone());

    // Find matching asset for platform
    let extension = platform.package_extension();
    let asset = release.assets.iter()
        .find(|a| {
            a.name.ends_with(extension) &&
            a.name.starts_with(binary_name)
        })
        .ok_or_else(|| anyhow!(
            "No {} package found for {} in release {}",
            extension,
            binary_name,
            release.tag_name
        ))?;

    let total_bytes = asset.size;

    // Phase 2: Download with progress
    let temp_dir = tempfile::tempdir()?;
    let package_path = temp_dir.path().join(&asset.name);

    // Configure client with connect timeout (following apple_api.rs pattern)
    let client = reqwest::Client::builder()
        .connect_timeout(DOWNLOAD_CONNECT_TIMEOUT)
        .user_agent("kodegen-installer/0.1")
        .build()?;
    let response = client.get(&asset.browser_download_url).send().await?;

    let mut file = tokio::fs::File::create(&package_path).await?;
    let mut downloaded: u64 = 0;

    // Stream chunks with progress updates
    use tokio::io::AsyncWriteExt;
    use futures::StreamExt;

    let mut stream = response.bytes_stream();
    let chunk_threshold = 256 * 1024; // 256KB
    let mut last_progress_bytes = 0u64;

    loop {
        // Wrap stream.next() with timeout to detect inactivity (following fluent_voice.rs pattern)
        let chunk_result = match timeout(DOWNLOAD_INACTIVITY_TIMEOUT, stream.next()).await {
            Ok(Some(Ok(chunk))) => chunk,
            Ok(Some(Err(e))) => return Err(e.into()),
            Ok(None) => break, // Stream ended normally
            Err(_) => {
                // Inactivity timeout triggered - no data received for 5 minutes
                return Err(anyhow!(
                    "Download timeout: No data received for {} seconds while downloading {}. \
                     Downloaded {}/{} bytes ({:.1}%). \
                     Check network connection and retry.",
                    DOWNLOAD_INACTIVITY_TIMEOUT.as_secs(),
                    binary_name,
                    downloaded,
                    total_bytes,
                    (downloaded as f64 / total_bytes as f64) * 100.0
                ));
            }
        };

        file.write_all(&chunk_result).await?;
        downloaded += chunk_result.len() as u64;

        // Emit progress every 256KB or at completion
        if downloaded - last_progress_bytes >= chunk_threshold || downloaded == total_bytes {
            send_best_effort(InstallProgress::download(
                binary_name.to_string(),
                binary_index,
                BINARY_COUNT,
                downloaded,
                total_bytes,
                DownloadPhase::Downloading,
                version.clone(),
            ));
            last_progress_bytes = downloaded;
        }
    }

    // Ensure final progress at 100%
    if downloaded == total_bytes && last_progress_bytes != total_bytes {
        send_best_effort(InstallProgress::download(
            binary_name.to_string(),
            binary_index,
            BINARY_COUNT,
            downloaded,
            total_bytes,
            DownloadPhase::Downloading,
            version.clone(),
        ));
    }

    // CRITICAL SECURITY: Verify package integrity before extraction
    // This protects against MITM attacks, compromised releases, and supply chain attacks
    verify_package_checksum(
        &client,
        repo,
        &release.tag_name,
        &asset.name,
        &package_path,
    )
    .await
    .context(format!(
        "Failed to verify integrity of downloaded package {}. \
         Installation aborted for security reasons.",
        asset.name
    ))?;

    // Phase 3: Extract binary
    send_critical(InstallProgress::download(
        binary_name.to_string(),
        binary_index,
        BINARY_COUNT,
        total_bytes,
        total_bytes,
        DownloadPhase::Extracting,
        version.clone(),
    ))?;

    let binary_path = extract_binary_from_package(
        &package_path,
        binary_name,
        platform,
        output_dir,
    ).await?;

    // Phase 4: Complete
    send_critical(InstallProgress::download(
        binary_name.to_string(),
        binary_index,
        BINARY_COUNT,
        total_bytes,
        total_bytes,
        DownloadPhase::Complete,
        version.clone(),
    ))?;

    Ok(binary_path)
}

/// Download all binaries from their respective GitHub repositories
///
/// The binary list is defined in `crate::binaries::BINARIES`.
pub async fn download_all_binaries(
    progress_tx: mpsc::Sender<InstallProgress>,
) -> Result<Vec<PathBuf>> {
    let platform = Platform::detect()?;

    // Keep TempDir guard alive - auto-cleanup on drop if downloads fail
    let output_dir_guard = tempfile::tempdir()?;
    let output_dir = output_dir_guard.path();

    let mut binaries = Vec::with_capacity(BINARY_COUNT);

    for (i, &binary_name) in BINARIES.iter().enumerate() {
        let binary_path = download_binary(
            binary_name,        // repo name
            binary_name,        // binary name (same as repo)
            i + 1,  // 1-based index
            platform,
            progress_tx.clone(),
            output_dir,
        ).await
        .with_context(|| format!("Failed to download {}", binary_name))?;

        binaries.push(binary_path);
    }

    // All downloads succeeded - persist directory by consuming guard
    let _persistent_dir = output_dir_guard.keep();

    Ok(binaries)
}
