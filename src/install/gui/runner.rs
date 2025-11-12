//! GUI installation runner - orchestrates installation with progress window

use eframe::egui;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use super::core::InstallProgress;
use super::wizard::InstallationResult;

use super::types::INSTALL_TIMEOUT;
use super::window::InstallWindow;

/// Run GUI installation with progress window
pub async fn run_gui_installation(cli: &crate::Cli) -> anyhow::Result<InstallationResult> {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(stdout, "🎨 Launching GUI installer...");
    let _ = stdout.reset();

    // Create progress channel (large buffer = rarely blocks background thread)
    let (tx, rx) = mpsc::channel::<InstallProgress>(100);

    // Create result channel (oneshot = single result value)
    let (result_tx, mut result_rx) = oneshot::channel();

    // Spawn installation in background tokio task
    let cli_clone = cli.clone();
    tokio::spawn(async move {
        // Download all binaries from GitHub with progress reporting
        let binary_paths = match crate::download::download_all_binaries(tx.clone()).await {
            Ok(paths) => paths,
            Err(e) => {
                let _ = tx.try_send(InstallProgress::error(
                    "binary_download".to_string(),
                    format!("Failed to download binaries: {}", e),
                ));
                let _ = result_tx.send(Err(e));
                return;
            }
        };

        // Install binaries to system paths
        let _ = tx.try_send(InstallProgress::new(
            "binary_install".to_string(),
            0.55,
            format!("Installing {} binaries to system", binary_paths.len()),
        ));

        if let Err(e) = crate::binary_staging::install_binaries_to_system(&binary_paths).await {
            let _ = tx.try_send(InstallProgress::error(
                "binary_install".to_string(),
                format!("Failed to install binaries: {}", e),
            ));
            let _ = result_tx.send(Err(e));
            return;
        }

        let _ = tx.try_send(InstallProgress::new(
            "binary_install".to_string(),
            0.60,
            "Binaries installed successfully".to_string(),
        ));

        // Determine kodegend path
        #[cfg(unix)]
        let kodegend_path = std::path::PathBuf::from("/usr/local/bin/kodegend");

        #[cfg(windows)]
        let kodegend_path = std::path::PathBuf::from(r"C:\Program Files\Kodegen\kodegend.exe");

        #[cfg(not(any(unix, windows)))]
        {
            let err = anyhow::anyhow!("Unsupported platform");
            let _ = tx.try_send(InstallProgress::error(
                "platform".to_string(),
                format!("{}", err),
            ));
            let _ = result_tx.send(Err(err));
            return;
        }

        // Get config path (platform-specific)
        let config_path = match dirs::config_dir() {
            Some(dir) => dir.join("kodegen").join("config.toml"),
            None => {
                let err = anyhow::anyhow!("Could not determine config directory");
                let _ = tx.try_send(InstallProgress::error(
                    "config".to_string(),
                    format!("{}", err),
                ));
                let _ = result_tx.send(Err(err));
                return;
            }
        };

        // Run daemon installation (function already accepts progress channel!)
        let auto_start = !cli_clone.no_start;
        let install_result = crate::install::config::install_kodegen_daemon(
            kodegend_path,
            config_path,
            auto_start,
            Some(tx.clone()), // Progress updates flow through this channel
        )
        .await;

        // Send completion progress (100%)
        if install_result.is_ok() {
            let _ = tx.try_send(InstallProgress::complete(
                "complete".to_string(),
                "Installation finished successfully".to_string(),
            ));
        }

        // Send final result to main thread
        let _ = result_tx.send(install_result);
    });

    // Store result in Arc<Mutex<>> so GUI can access it
    let result_container = Arc::new(Mutex::new(None));
    let result_clone = result_container.clone();

    // Spawn result polling task with timeout protection
    tokio::spawn(async move {
        // Wrap polling loop with timeout (matches fluent_voice.rs pattern)
        let result = timeout(INSTALL_TIMEOUT, async {
            loop {
                match result_rx.try_recv() {
                    Ok(res) => break res,
                    Err(oneshot::error::TryRecvError::Empty) => {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                    Err(oneshot::error::TryRecvError::Closed) => {
                        break Err(anyhow::anyhow!("Installation channel closed unexpectedly"));
                    }
                }
            }
        })
        .await;

        // Handle timeout vs operation result (double-Result unwrap)
        let final_result = match result {
            Ok(res) => res, // Installation completed (success or failure)
            Err(_) => {
                // Timeout elapsed - installation hung
                Err(anyhow::anyhow!(
                    "Installation timed out after {} seconds. \
                     This may indicate a network issue or system problem.\n\n\
                     Please check:\n\
                     • Network connection is active\n\
                     • ~100MB free disk space for Chromium\n\
                     • Firewall allows GitHub/Chrome downloads\n\
                     • System disk is not full",
                    INSTALL_TIMEOUT.as_secs()
                ))
            }
        };

        // Store result (including timeout error) for main thread to retrieve
        if let Ok(mut container) = result_container.lock() {
            *container = Some(final_result);
        }
    });

    // Configure GUI window (runs on main thread)
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 450.0])
            .with_resizable(false)
            .with_title("Kodegen Installation"),
        ..Default::default()
    };

    // Run GUI (blocking until window closes)
    let _ = eframe::run_native(
        "kodegen_install",
        native_options,
        Box::new(move |cc| Ok(Box::new(InstallWindow::new(cc, rx)))),
    );

    // Wait up to 10 seconds for result after window closes
    // Handles race condition if user somehow closed window early despite disabled button
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(r) = result_clone.lock().ok().and_then(|mut g| g.take()) {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;

    match result {
        Ok(install_result) => install_result, // Got result within 10 seconds
        Err(_timeout) => {
            // Timeout - installation didn't complete even with 10 second grace period
            Err(anyhow::anyhow!(
                "Installation window closed before completion.\n\
                 \n\
                 The installation may have completed in the background.\n\
                 To verify, check if the kodegend service is running:\n\
                 \n\
                 macOS/Linux: sudo launchctl list | grep kodegend\n\
                 Windows:     sc query kodegend\n\
                 \n\
                 If the service is running, restart your MCP client (Claude Desktop/Cursor/Zed/Windsurf).\n\
                 If not running, the installation failed - please run the installer again."
            ))
        }
    }
}
