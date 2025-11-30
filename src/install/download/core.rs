//! Binary download and orchestration with progress tracking

use anyhow::{Context, Result, anyhow};
use futures::StreamExt;
use log::warn;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::extract::extract_binary_from_package;
use super::github::get_latest_release;
use super::platform::Platform;
use crate::install::binaries::{BINARIES, BINARY_COUNT};
use crate::install::core::{DownloadPhase, InstallProgress};

// Download timeout constants following codebase patterns
// (see apple_api.rs:239-241, fluent_voice.rs:9, main.rs:15)
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(30); // Initial connection
const DOWNLOAD_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(300); // 5 min no data

// Total download time limit - prevent infinite hangs
const DOWNLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(30 * 60); // 30 minutes

// Retry configuration for transient failures
const MAX_DOWNLOAD_RETRIES: usize = 3;

// Progress heartbeat interval - show activity during stalls
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

// Adaptive timeout thresholds (bytes/sec)
const VERY_SLOW_CONNECTION: f64 = 10_000.0;   // <10 KB/s
const SLOW_CONNECTION: f64 = 100_000.0;        // <100 KB/s

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

    let checksums_response = client.get(&checksums_url).send().await.context(format!(
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

/// Attempt to download binary with resume support
async fn download_with_resume(
    client: &reqwest::Client,
    url: &str,
    package_path: &Path,
    binary_name: &str,
    total_bytes: u64,
    version: Option<String>,
    binary_index: usize,
    send_best_effort: impl Fn(InstallProgress) + Clone,
) -> Result<()> {
    // Check for existing partial download
    let resume_from = if package_path.exists() {
        tokio::fs::metadata(package_path).await?.len()
    } else {
        0
    };

    // Build request with Range header if resuming
    let mut request = client.get(url);
    if resume_from > 0 {
        request = request.header(
            reqwest::header::RANGE, 
            format!("bytes={}-", resume_from)
        );
    }

    let response = request.send().await?;

    // Validate response status
    // 200 OK = full content (resume not supported or new download)
    // 206 Partial Content = resume successful
    if !response.status().is_success() 
        && response.status() != reqwest::StatusCode::PARTIAL_CONTENT 
    {
        return Err(anyhow!(
            "Download failed: HTTP {} for {}", 
            response.status(), 
            binary_name
        ));
    }

    // Open file in append mode if resuming, create if new
    let mut file = if resume_from > 0 && response.status() == reqwest::StatusCode::PARTIAL_CONTENT {
        tokio::fs::OpenOptions::new()
            .append(true)
            .open(package_path)
            .await?
    } else {
        // Server doesn't support resume or this is a new download
        tokio::fs::File::create(package_path).await?
    };

    let mut downloaded = resume_from;
    let download_start = tokio::time::Instant::now();
    let mut last_progress_bytes = downloaded;
    
    // Heartbeat interval for progress updates during stalls
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    use tokio::io::AsyncWriteExt;

    let mut stream = response.bytes_stream();
    let chunk_threshold = 256 * 1024; // 256KB

    loop {
        // Check total download time limit
        if download_start.elapsed() > DOWNLOAD_TOTAL_TIMEOUT {
            return Err(anyhow!(
                "Download exceeded maximum time limit of {} minutes. \n\
                 Downloaded {}/{} bytes ({:.1}%). \n\
                 This may indicate an extremely slow connection or network issue.",
                DOWNLOAD_TOTAL_TIMEOUT.as_secs() / 60,
                downloaded,
                total_bytes,
                (downloaded as f64 / total_bytes as f64) * 100.0
            ));
        }

        // Calculate adaptive timeout based on observed throughput
        let elapsed_secs = download_start.elapsed().as_secs_f64();
        let adaptive_timeout = if elapsed_secs > 1.0 && downloaded > resume_from {
            let avg_speed = (downloaded - resume_from) as f64 / elapsed_secs;
            
            if avg_speed < VERY_SLOW_CONNECTION {
                Duration::from_secs(600)  // 10 min for very slow (<10 KB/s)
            } else if avg_speed < SLOW_CONNECTION {
                Duration::from_secs(300)  // 5 min for slow (<100 KB/s)
            } else {
                Duration::from_secs(120)  // 2 min for normal (≥100 KB/s)
            }
        } else {
            DOWNLOAD_INACTIVITY_TIMEOUT  // Use default until we measure speed
        };

        // Use tokio::select! to handle both chunk streaming and heartbeat
        tokio::select! {
            // Attempt to get next chunk with adaptive timeout
            chunk_result = timeout(adaptive_timeout, stream.next()) => {
                match chunk_result {
                    Ok(Some(Ok(chunk))) => {
                        file.write_all(&chunk).await?;
                        downloaded += chunk.len() as u64;

                        // Emit progress every 256KB or at completion
                        if downloaded - last_progress_bytes >= chunk_threshold 
                            || downloaded == total_bytes 
                        {
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
                    Ok(Some(Err(e))) => {
                        // Network error during chunk download
                        return Err(anyhow!(
                            "Network error while downloading {}: {}. \n\
                             Progress: {}/{} bytes ({:.1}%). \n\
                             Will retry with resume from byte {}.",
                            binary_name,
                            e,
                            downloaded,
                            total_bytes,
                            (downloaded as f64 / total_bytes as f64) * 100.0,
                            downloaded
                        ).into());
                    }
                    Ok(None) => {
                        // Stream ended normally
                        break;
                    }
                    Err(_) => {
                        // Inactivity timeout triggered
                        return Err(anyhow!(
                            "Download timeout: No data received for {:.0} seconds while downloading {}. \n\
                             Downloaded {}/{} bytes ({:.1}%). \n\
                             Average speed: {:.1} KB/s. \n\
                             Will retry with resume from byte {}.",
                            adaptive_timeout.as_secs_f64(),
                            binary_name,
                            downloaded,
                            total_bytes,
                            (downloaded as f64 / total_bytes as f64) * 100.0,
                            (downloaded as f64 / elapsed_secs) / 1024.0,
                            downloaded
                        ));
                    }
                }
            }
            
            // Heartbeat tick - send progress update even if no new data
            _ = heartbeat.tick() => {
                // Send heartbeat progress to show download is still active
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
        progress_tx
            .try_send(progress)
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
    let asset = release
        .assets
        .iter()
        .find(|a| a.name.ends_with(extension) && a.name.starts_with(binary_name))
        .ok_or_else(|| {
            anyhow!(
                "No {} package found for {} in release {}",
                extension,
                binary_name,
                release.tag_name
            )
        })?;

    let total_bytes = asset.size;

    // Phase 2: Download with progress
    let temp_dir = tempfile::tempdir()?;
    let package_path = temp_dir.path().join(&asset.name);

    // Configure client with connect timeout
    let client = reqwest::Client::builder()
        .connect_timeout(DOWNLOAD_CONNECT_TIMEOUT)
        .user_agent("kodegen-installer/0.1")
        .build()?;

    // Retry loop with exponential backoff
    let mut last_error = None;

    for attempt in 1..=MAX_DOWNLOAD_RETRIES {
        match download_with_resume(
            &client,
            &asset.browser_download_url,
            &package_path,
            binary_name,
            total_bytes,
            version.clone(),
            binary_index,
            send_best_effort.clone(),
        ).await {
            Ok(()) => {
                last_error = None;
                break; // Success!
            }
            Err(e) if attempt < MAX_DOWNLOAD_RETRIES => {
                // Retry with exponential backoff: 2s, 4s, 8s
                let delay = Duration::from_secs(2u64.pow(attempt as u32));
                
                warn!(
                    "Download attempt {}/{} failed for {}: {}. Retrying in {} seconds...",
                    attempt,
                    MAX_DOWNLOAD_RETRIES,
                    binary_name,
                    e,
                    delay.as_secs()
                );

                last_error = Some(e);
                tokio::time::sleep(delay).await;
            }
            Err(e) => {
                // Final attempt failed
                last_error = Some(e);
                break;
            }
        }
    }

    // Check if all retries failed
    if let Some(e) = last_error {
        return Err(e).context(format!(
            "Failed to download {} after {} attempts", 
            binary_name, 
            MAX_DOWNLOAD_RETRIES
        ));
    }

    // CRITICAL SECURITY: Verify package integrity before extraction
    // This protects against MITM attacks, compromised releases, and supply chain attacks
    verify_package_checksum(&client, repo, &release.tag_name, &asset.name, &package_path)
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

    let binary_path =
        extract_binary_from_package(&package_path, binary_name, platform, output_dir).await?;

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
///
/// Returns a tuple of (downloaded binary paths, download directory path).
/// The download directory path is returned for cleanup tracking.
pub async fn download_all_binaries(
    progress_tx: mpsc::Sender<InstallProgress>,
) -> Result<(Vec<PathBuf>, PathBuf)> {
    let platform = Platform::detect()?;

    // Keep TempDir guard alive - auto-cleanup on drop if downloads fail
    let output_dir_guard = tempfile::tempdir()?;
    let output_dir = output_dir_guard.path();

    let mut binaries = Vec::with_capacity(BINARY_COUNT);

    for (i, &binary_name) in BINARIES.iter().enumerate() {
        let binary_path = download_binary(
            binary_name, // repo name
            binary_name, // binary name (same as repo)
            i + 1,       // 1-based index
            platform,
            progress_tx.clone(),
            output_dir,
        )
        .await
        .with_context(|| format!("Failed to download {}", binary_name))?;

        binaries.push(binary_path);
    }

    // All downloads succeeded - persist directory and return path for cleanup tracking
    // Use into_path() instead of keep() so caller can track for cleanup
    let download_dir = output_dir_guard.into_path();

    Ok((binaries, download_dir))
}
