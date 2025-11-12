//! Installation orchestration with interactive progress tracking
//!
//! This module handles the main installation flow with progress bars and
//! user feedback for the interactive wizard mode.

use anyhow::{Context, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::io::Write;
use std::path::PathBuf;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tokio::sync::mpsc;

use super::binaries::BINARY_COUNT;
use super::binary_staging;
use super::chromium;
use super::cli::Cli;
use super::download;
use crate::install;
use super::privilege;
use super::wizard;

/// Run installation with wizard-collected options
pub async fn run_install_with_options(options: &wizard::InstallOptions, _cli: &Cli) -> Result<()> {
    use crate::install::install::core::DownloadPhase;

    // Use termcolor for starting message
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(stdout, "\n⚡ Starting installation...\n");
    let _ = stdout.reset();

    // Create multi-progress container for better layout
    let multi = MultiProgress::new();

    // Overall progress bar (shows binary download progress or installation progress)
    let pb_overall = multi.add(ProgressBar::new(100));
    pb_overall.set_style(
        ProgressStyle::default_bar()
            .template("\n[{bar:50.cyan/blue}] {pos:>3}%  {msg}\n")
            .context("Invalid progress bar template")?
            .progress_chars("█▓░"),
    );

    // Current binary download bar (shows MB downloaded)
    let pb_download = multi.add(ProgressBar::new(100));
    pb_download.set_style(
        ProgressStyle::default_bar()
            .template("   [{bar:50.green/blue}] {bytes}/{total_bytes}  {msg}")
            .context("Invalid progress bar template")?
            .progress_chars("█▓░"),
    );

    // Create channel for progress updates (needed before download)
    let (tx, mut rx) = mpsc::channel::<install::core::InstallProgress>(100);

    // Spawn task to update progress bars from installation events (BEFORE download starts)
    let pb_overall_clone = pb_overall.clone();
    let pb_download_clone = pb_download.clone();
    let progress_task = tokio::spawn(async move {
        while let Some(progress) = rx.recv().await {
            if let Some(meta) = &progress.download_metadata {
                // Handle download progress with detailed metadata
                match meta.phase {
                    DownloadPhase::Discovering => {
                        pb_overall_clone.set_position((meta.binary_index * 100 / BINARY_COUNT) as u64);
                        pb_overall_clone.set_message(format!("Binary {}/{}", meta.binary_index, BINARY_COUNT));
                        pb_download_clone.set_message(format!("🔍 Checking {}", meta.binary_name));
                        pb_download_clone.set_position(0);
                    }
                    DownloadPhase::Downloading => {
                        pb_overall_clone.set_position((meta.binary_index * 100 / BINARY_COUNT) as u64);
                        pb_overall_clone.set_message(format!("Binary {}/{}", meta.binary_index, BINARY_COUNT));
                        pb_download_clone.set_length(meta.total_bytes);
                        pb_download_clone.set_position(meta.bytes_downloaded);
                        let percent = if meta.total_bytes > 0 {
                            meta.bytes_downloaded * 100 / meta.total_bytes
                        } else {
                            0
                        };
                        pb_download_clone.set_message(format!("📥 {} - {}%", meta.binary_name, percent));
                    }
                    DownloadPhase::Extracting => {
                        pb_overall_clone.set_position((meta.binary_index * 100 / BINARY_COUNT) as u64);
                        pb_overall_clone.set_message(format!("Binary {}/{}", meta.binary_index, BINARY_COUNT));
                        pb_download_clone.set_message(format!("📦 Extracting {}", meta.binary_name));
                    }
                    DownloadPhase::Complete => {
                        pb_overall_clone.set_position((meta.binary_index * 100 / BINARY_COUNT) as u64);
                        pb_overall_clone.set_message(format!("Binary {}/{}", meta.binary_index, BINARY_COUNT));
                        pb_download_clone.set_message(format!("✅ {}", meta.binary_name));
                    }
                }
            } else {
                // Non-download progress (daemon install, etc.)
                if progress.is_error {
                    pb_overall_clone.set_message(format!("❌ [{}] {}", progress.step, progress.message));
                } else {
                    let pos = (progress.progress * 40.0) as u64 + 60; // Map 0-1 to 60-100
                    pb_overall_clone.set_position(pos);
                    pb_overall_clone.set_message(format!("[{}] {}", progress.step, progress.message));
                }
            }
        }

        pb_overall_clone.finish_with_message("✅ Installation complete");
        pb_download_clone.finish_and_clear();
    });

    // Download all binaries from GitHub with progress reporting
    pb_overall.set_message("Downloading binaries from GitHub...");
    pb_overall.set_position(0);

    let binary_paths = if options.dry_run {
        Vec::new()
    } else {
        download::download_all_binaries(tx.clone()).await?
    };

    pb_overall.set_message("All binaries downloaded");
    pb_overall.set_position(50);

    // Stage binaries for installation (runs as unprivileged user)
    let staging_dir = if !options.dry_run && !binary_paths.is_empty() {
        pb_overall.set_message("Staging binaries...");
        pb_overall.set_position(55);

        let dir = binary_staging::stage_binaries_for_install(&binary_paths).await?;

        pb_overall.set_message("Binaries staged");
        pb_overall.set_position(60);

        Some(dir)
    } else {
        None
    };

    // Determine kodegend path for daemon installation
    let binary_path = if options.dry_run {
        PathBuf::from("./target/release/kodegend")
    } else {
        #[cfg(unix)]
        let path = PathBuf::from("/usr/local/bin/kodegend");

        #[cfg(windows)]
        let path = PathBuf::from(r"C:\Program Files\Kodegen\kodegend.exe");

        path
    };

    // Determine config path
    let config_path = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
        .join("kodegen")
        .join("config.toml");

    pb_overall.set_message("Configuring daemon service...");
    pb_overall.set_position(65);

    // Call installation with real progress channel
    let result = install::config::install_kodegen_daemon(
        binary_path.clone(),
        config_path,
        options.auto_start,
        Some(tx),
    )
    .await;

    // Wait for all progress updates to complete
    progress_task.await.ok();

    // Check if daemon installation failed and get results
    let install_result = result?;

    pb_overall.set_message("Daemon service configured");
    pb_overall.set_position(80);

    // Install Chromium (REQUIRED)
    pb_overall.set_message("Installing Chromium (~100MB)...");
    pb_overall.set_position(85);

    match chromium::install_chromium().await {
        Ok(chromium_path) => {
            pb_overall.set_message("Chromium installed successfully");
            pb_overall.set_position(95);

            let mut stdout = StandardStream::stdout(ColorChoice::Always);
            let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
            let _ = writeln!(
                stdout,
                "\n✓ Chromium installed at: {}",
                chromium_path.display()
            );
            let _ = stdout.reset();
        }
        Err(e) => {
            // Chromium is REQUIRED - fail installation
            pb_overall.set_message("Chromium installation FAILED");
            pb_overall.finish_and_clear();
            pb_download.finish_and_clear();

            let mut stderr = StandardStream::stderr(ColorChoice::Always);
            let _ = stderr.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true));
            let _ = writeln!(stderr, "\n❌ FATAL: Chromium installation failed");
            let _ = stderr.reset();
            let _ = stderr.set_color(ColorSpec::new().set_fg(Some(Color::Red)));
            let _ = writeln!(stderr, "   Error: {e}");
            let _ = stderr.reset();
            let _ = writeln!(stderr, "   Chromium is required for kodegen functionality.");
            let _ = writeln!(stderr, "   Please check:");
            let _ = writeln!(stderr, "   • Network connection is available");
            let _ = writeln!(stderr, "   • ~100MB free disk space");
            let _ = writeln!(
                stderr,
                "   • Firewall allows access to chromium download servers\n"
            );
            return Err(e);
        }
    }

    // Now perform ONLY the privileged operations (Phase 3: Deferred privilege escalation)
    // All unprivileged operations (downloads, extraction, staging) have completed as user
    if let Some(staging_dir) = staging_dir {
        pb_overall.set_message("Installing to system (requires sudo)...");
        pb_overall.set_position(96);

        // Pass certificate content instead of file path
        // Execute privileged operations (copy to /usr/local/bin, update /etc/hosts, import certs)
        privilege::install_with_elevated_privileges(
            &staging_dir,
            install_result.certificate_content.as_deref(),
            &install_result.data_dir,
        )
        .await?;

        pb_overall.set_message("System installation complete");
        pb_overall.set_position(98);
    }

    pb_overall.set_message("Complete!");
    pb_overall.set_position(100);
    pb_overall.finish_and_clear();
    pb_download.finish_and_clear();

    wizard::show_completion(options, &install_result);

    Ok(())
}
