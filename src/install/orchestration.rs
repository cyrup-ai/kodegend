//! CLI presentation layer - displays progress from logic layer
//!
//! This is PRESENTATION ONLY:
//! - Receives progress events from channel
//! - Displays with indicatif progress bars
//! - NO logic, NO downloads, NO checks

use anyhow::{Context, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tokio::sync::mpsc;

use crate::install::core::{DownloadPhase, InstallProgress};

/// Run CLI display - receives progress and shows with progress bars
///
/// This is the CLI presentation layer. It:
/// - Creates indicatif progress bars
/// - Receives InstallProgress events from the channel
/// - Updates progress bars in real-time
///
/// NO logic happens here - all checks/fixes/downloads happen in fix_all_components()
pub async fn run_cli_display(mut rx: mpsc::Receiver<InstallProgress>) -> Result<()> {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);

    // Create multi-progress container for clean layout
    let multi = MultiProgress::new();

    // Overall progress bar
    let pb_overall = multi.add(ProgressBar::new(100));
    pb_overall.set_style(
        ProgressStyle::default_bar()
            .template("\n{msg}")
            .context("Invalid progress bar template")?
    );

    // Download progress bar (for binary downloads)
    let pb_download = multi.add(ProgressBar::new(100));
    pb_download.set_style(
        ProgressStyle::default_bar()
            .template("   [{bar:50.green/blue}] {bytes}/{total_bytes}  {msg}")
            .context("Invalid progress bar template")?
            .progress_chars("█▓░"),
    );
    pb_download.set_position(0);

    // Track completed components for final summary
    let mut completed_components: Vec<String> = Vec::new();
    let mut failed = false;

    // Receive and display progress events
    while let Some(progress) = rx.recv().await {
        if progress.is_error {
            // Error message
            let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)));
            let _ = writeln!(stdout, "{}", progress.message);
            let _ = stdout.reset();
            failed = true;
        } else if let Some(ref meta) = progress.download_metadata {
            // Download progress with detailed metadata
            match meta.phase {
                DownloadPhase::Discovering => {
                    pb_download.set_message(format!("🔍 {}", meta.binary_name));
                    pb_download.set_position(0);
                }
                DownloadPhase::Downloading => {
                    pb_download.set_length(meta.total_bytes);
                    pb_download.set_position(meta.bytes_downloaded);
                    let percent = if meta.total_bytes > 0 {
                        meta.bytes_downloaded * 100 / meta.total_bytes
                    } else {
                        0
                    };
                    pb_download.set_message(format!("📥 {} - {}%", meta.binary_name, percent));
                }
                DownloadPhase::Extracting => {
                    pb_download.set_message(format!("📦 Extracting {}", meta.binary_name));
                }
                DownloadPhase::Complete => {
                    pb_download.set_message(format!("✅ {}", meta.binary_name));
                }
            }
        } else {
            // Component progress
            pb_overall.set_message(progress.message.clone());

            // Track completion
            if progress.progress >= 1.0 && progress.step != "complete" {
                completed_components.push(progress.step.clone());
            }

            // Final completion
            if progress.step == "complete" {
                pb_overall.finish_and_clear();
                pb_download.finish_and_clear();

                if !failed {
                    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)).set_bold(true));
                    let _ = writeln!(stdout, "\n✅ Installation complete!");
                    let _ = stdout.reset();
                }
            }
        }
    }

    // Channel closed - installation complete
    pb_overall.finish_and_clear();
    pb_download.finish_and_clear();

    if failed {
        Err(anyhow::anyhow!("Installation failed"))
    } else {
        Ok(())
    }
}
