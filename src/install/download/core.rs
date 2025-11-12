//! Binary download and orchestration with progress tracking

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use log::warn;

use crate::install::install::core::{InstallProgress, DownloadPhase};
use crate::install::binaries::{BINARIES, BINARY_COUNT};
use super::platform::Platform;
use super::github::get_latest_release;
use super::extract::extract_binary_from_package;

// Download timeout constants following codebase patterns
// (see apple_api.rs:239-241, fluent_voice.rs:9, main.rs:15)
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);  // Initial connection
const DOWNLOAD_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(300); // 5 min no data

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
