//! Installation runners for different modes (GUI, CLI, uninstall)
//!
//! This module provides the top-level runner functions for different installation
//! modes: GUI mode, non-interactive CLI mode, and uninstallation.

use anyhow::{Context, Result};
use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tokio::sync::mpsc;

use super::binary_staging;
use super::chromium;
use super::cli::Cli;
use super::download;
use crate::install;
use super::privilege;

#[cfg(feature = "gui")]
use crate::install::gui;

/// Run installation in GUI mode
#[cfg(feature = "gui")]
pub async fn run_gui_mode(cli: &Cli) -> Result<()> {
    // Delegate to GUI module's run_gui_installation (implemented in SUBTASK 5)
    let result = gui::run_gui_installation(cli).await?;

    // Log completion to stdout for CI/logging integration
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)).set_bold(true));
    let _ = writeln!(stdout, "\n✅ Installation completed successfully");
    let _ = stdout.reset();
    let _ = writeln!(stdout, "   Data directory: {}", result.data_dir.display());

    Ok(())
}

/// Run installation in non-interactive CLI mode
pub async fn run_install(cli: &Cli) -> Result<()> {
    use super::binaries::BINARY_COUNT;
    use crate::install::core::DownloadPhase;

    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)).set_bold(true));
    let _ = writeln!(stdout, "🔧 Kodegen Daemon Installation");
    let _ = stdout.reset();
    let _ = writeln!(stdout, "Platform: {}\n", std::env::consts::OS);

    // Create progress channel for download monitoring
    let (tx, mut rx) = mpsc::channel::<install::core::InstallProgress>(100);

    // Spawn progress consumer task (non-interactive mode - print to stderr)
    let progress_task = tokio::spawn(async move {
        while let Some(progress) = rx.recv().await {
            if let Some(meta) = &progress.download_metadata {
                match meta.phase {
                    DownloadPhase::Discovering => {
                        eprintln!("🔍 Checking {} ({}/{})", meta.binary_name, meta.binary_index, BINARY_COUNT);
                    }
                    DownloadPhase::Downloading => {
                        let mb_dl = meta.bytes_downloaded as f64 / 1_048_576.0;
                        let mb_total = meta.total_bytes as f64 / 1_048_576.0;
                        eprintln!("📥 {} - {:.1}/{:.1} MB", meta.binary_name, mb_dl, mb_total);
                    }
                    DownloadPhase::Extracting => {
                        eprintln!("📦 Extracting {}", meta.binary_name);
                    }
                    DownloadPhase::Complete => {
                        eprintln!("✅ {} complete", meta.binary_name);
                    }
                }
            }
        }
    });

    // Check which binaries need installation
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(stdout, "🔍 Checking installed versions...");
    let _ = stdout.reset();

    // Check kodegen binary version
    use super::detection::binary_needs_installation;
    let needs_kodegen = binary_needs_installation("kodegen").await;

    // Download binaries that need installation
    let binary_paths = if needs_kodegen {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
        let _ = writeln!(stdout, "📥 Downloading binaries from GitHub...");
        let _ = stdout.reset();

        download::download_all_binaries(tx).await?
    } else {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
        let _ = writeln!(stdout, "✓ kodegen is up to date, skipping download\n");
        let _ = stdout.reset();

        Vec::new()
    };

    // Wait for progress task to finish consuming all events
    progress_task.await.ok();

    if !binary_paths.is_empty() {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
        let _ = writeln!(stdout, "✓ Downloaded {} binaries\n", binary_paths.len());
        let _ = stdout.reset();
    }

    // Stage binaries for installation if downloaded (runs as unprivileged user)
    let staging_dir = if !binary_paths.is_empty() {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
        let _ = writeln!(stdout, "📦 Staging binaries...");
        let _ = stdout.reset();

        let dir = binary_staging::stage_binaries_for_install(&binary_paths).await?;

        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
        let _ = writeln!(stdout, "✓ Binaries staged\n");
        let _ = stdout.reset();

        Some(dir)
    } else {
        None
    };

    // If we have binaries to install, verify and install the daemon
    let install_result = if let Some(ref staging_dir) = staging_dir {
        let binary_path = staging_dir.join("kodegend");

        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
        let _ = writeln!(stdout, "\n📍 Daemon binary:");
        let _ = stdout.reset();
        let _ = writeln!(stdout, "   kodegend: {}", binary_path.display());

        // Verify staged daemon binary exists and is executable
        if !binary_path.exists() {
            anyhow::bail!("Staged binary not found: {}", binary_path.display());
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&binary_path)?;
            if metadata.permissions().mode() & 0o111 == 0 {
                anyhow::bail!(
                    "Binary not executable: {}\nRun: chmod +x {}",
                    binary_path.display(),
                    binary_path.display()
                );
            }
        }

        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
        let _ = writeln!(stdout, "✓ Daemon binary verified\n");
        let _ = stdout.reset();

        let _ = writeln!(stdout, "Installing {} to system...", binary_path.display());

        // Determine config path
        let config_path = crate::platform::user_config_dir()
            .join("config.toml");

        // Call the actual installation logic (no progress channel in CLI mode)
        let auto_start = !cli.no_start;
        let result =
            install::config::install_kodegen_daemon(binary_path, config_path, auto_start, None).await?;

        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)).set_bold(true));
        let _ = writeln!(
            stdout,
            "\n✅ Daemon installed to: {}",
            result.data_dir.display()
        );
        let _ = stdout.reset();
        let _ = writeln!(
            stdout,
            "   Service: {}",
            result.service_path.display()
        );

        if !result.certificates_installed {
            let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)));
            let _ = writeln!(stdout, "   ⚠ Certificate installation had issues");
            let _ = stdout.reset();
        }
        if !result.host_entries_added {
            let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Yellow)));
            let _ = writeln!(stdout, "   ⚠ Host entries not added (may require sudo)");
            let _ = stdout.reset();
        }

        Some(result)
    } else {
        None
    };

    // INDEPENDENT CHECK: Install Chromium/Chrome (runs regardless of binary installation)
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(stdout, "\n📦 Installing Chromium (required)...");
    let _ = stdout.reset();

    match chromium::install_chromium().await {
        Ok(chromium_path) => {
            let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
            let _ = writeln!(
                stdout,
                "✓ Chromium installed at: {}",
                chromium_path.display()
            );
            let _ = stdout.reset();
        }
        Err(e) => {
            let mut stderr = StandardStream::stderr(ColorChoice::Always);
            let _ = stderr.set_color(ColorSpec::new().set_fg(Some(Color::Red)).set_bold(true));
            let _ = writeln!(stderr, "\n❌ FATAL: Chromium installation failed");
            let _ = stderr.reset();
            let _ = stderr.set_color(ColorSpec::new().set_fg(Some(Color::Red)));
            let _ = writeln!(stderr, "   Error: {e}");
            let _ = stderr.reset();
            let _ = writeln!(stderr, "   Chromium is required for kodegen functionality.");
            return Err(e);
        }
    }

    // Perform privileged operations if binaries were installed
    if let Some(ref staging_dir_path) = staging_dir
        && let Some(ref result) = install_result
    {
        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
        let _ = writeln!(stdout, "\n📦 Installing to system (requires sudo)...");
        let _ = stdout.reset();

        // Pass certificate content instead of file path
        // Execute privileged operations (copy to /usr/local/bin, update /etc/hosts, import certs)
        privilege::install_with_elevated_privileges(
            staging_dir_path,
            result.certificate_content.as_deref(),
            &result.data_dir,
        )
        .await?;

        let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)));
        let _ = writeln!(stdout, "✓ System installation complete");
        let _ = stdout.reset();
    }

    // INDEPENDENT CHECK: Ensure hosts file is configured (runs regardless of binary installation)
    let _ = writeln!(stdout);
    super::hosts::ensure_hosts_configured().await?;

    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)).set_bold(true));
    let _ = writeln!(stdout, "\n✅ Installation complete");
    let _ = stdout.reset();

    Ok(())
}

/// Run uninstallation
pub async fn run_uninstall(_cli: &Cli) -> Result<()> {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)).set_bold(true));
    let _ = writeln!(stdout, "🗑️  Kodegen Daemon Uninstallation\n");
    let _ = stdout.reset();

    // Call the actual uninstallation logic
    install::uninstall::uninstall_kodegen_daemon()
        .await
        .context("Uninstallation failed")?;

    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)).set_bold(true));
    let _ = writeln!(stdout, "✅ Uninstallation completed successfully!");
    let _ = stdout.reset();
    Ok(())
}
