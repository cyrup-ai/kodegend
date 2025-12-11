//! Kodegen installation library
//!
//! This library provides programmatic installation of Kodegen binaries
//! and daemon services, designed to be called by kodegend during startup.
//!
//! # Architecture
//!
//! ONE logic path, TWO presentation layers:
//!
//! ```text
//! ensure_installed()
//!        │
//!        ▼
//!    [LOGIC LAYER]
//!    fix_all_components(progress_tx)
//!    - checks each component
//!    - fixes only what's needed
//!    - emits progress events
//!        │
//!        ▼
//!    progress channel
//!        │
//!    ┌───┴───┐
//!    ▼       ▼
//!   GUI     CLI
//! (egui)  (indicatif)
//!
//! Presentation layers receive events and display them.
//! NO logic, NO downloads, NO checks in presentation.
//! ```

mod binaries;
pub(crate) mod chromium;
pub(crate) mod cleanup;
mod component_fixers;
mod detection;
mod download;
mod gui;
mod hosts;
pub(crate) mod installer;
mod orchestration;
mod platform_installer;
mod privilege;
pub mod runners;
mod wizard;

// Public exports for internal module use
pub use component_fixers::fix_all_components;
pub use detection::InstallationFixReport;

pub(crate) use installer::{core, uninstall};

use anyhow::Result;
use tokio::sync::mpsc;

/// Ensure Kodegen is fully installed - AUTOMAGICAL
///
/// This is called by run_daemon() before starting services.
/// Auto-detects GUI availability and shows appropriate presentation layer.
///
/// # Architecture
///
/// - ONE logic path: `fix_all_components()` handles all checks and fixes
/// - TWO presentation layers: GUI window or CLI progress bars
/// - Progress flows through channel from logic to presentation
///
/// # Behavior
///
/// 1. Create progress channel
/// 2. Detect GUI vs CLI and spawn appropriate presentation
/// 3. Run fix_all_components (emits progress events)
/// 4. Presentation displays events in real-time
/// 5. Return success/failure
///
/// # Threading (macOS)
///
/// On macOS, eframe/winit's EventLoop MUST run on the main OS thread.
/// When called from `Runtime::block_on()`, the future executes on the main thread.
/// Therefore:
/// - GUI mode: Spawn logic to background, run GUI directly (stays on main thread)
/// - CLI mode: Spawn presentation to background, run logic directly
pub async fn ensure_installed() -> Result<()> {
    use crate::platform;

    // Create progress channel - logic sends, presentation receives
    let (tx, rx) = mpsc::channel(100);

    // Detect GUI availability
    let is_gui = platform::is_gui_available();

    if is_gui {
        log::info!("GUI available, launching installation window");

        // GUI MODE: eframe/winit requires EventLoop on main thread (macOS requirement)
        // Since block_on() runs on main thread, we:
        // 1. Spawn installation logic to tokio worker thread
        // 2. Run GUI directly here (stays on main thread via block_on)
        let logic_handle = tokio::spawn(async move {
            fix_all_components(Some(tx)).await
        });

        // Run GUI on main thread (required by winit on macOS)
        // This blocks until the window closes
        gui::run_gui_display(rx).await?;

        // Wait for logic to complete and get the report
        let report = logic_handle.await??;

        if !report.overall_success {
            log_component_errors(&report);
            anyhow::bail!("Installation failed - see errors above");
        }
    } else {
        log::info!("No GUI available, using CLI progress display");
        wizard::show_welcome_banner();

        // CLI MODE: No main thread requirement
        // Spawn presentation to background, run logic in current context
        let presentation_handle = tokio::spawn(async move {
            orchestration::run_cli_display(rx).await
        });

        // Run THE ONLY logic path - all checks and fixes happen here
        let report = fix_all_components(Some(tx)).await?;

        // Wait for presentation to finish (it exits when channel closes)
        let _ = presentation_handle.await;

        if !report.overall_success {
            log_component_errors(&report);
            anyhow::bail!("Installation failed - see errors above");
        }
    }

    log::debug!("All components installed successfully");
    Ok(())
}

/// Log errors from failed component fixes
fn log_component_errors(report: &InstallationFixReport) {
    // Rust toolchain checking removed - bundled apps don't need Rust on user machines

    if let Some(ref result) = report.hosts
        && !result.success
        && let Some(ref error) = result.error
    {
        log::error!("Hosts fix failed: {}", error);
    }

    if let Some(ref result) = report.certificates
        && !result.success
        && let Some(ref error) = result.error
    {
        log::error!("Certificates fix failed: {}", error);
    }

    if let Some(ref result) = report.kodegen_version
        && !result.success
        && let Some(ref error) = result.error
    {
        log::error!("Kodegen version fix failed: {}", error);
    }
}

/// Run privileged installation operations (Windows only, must be elevated)
///
/// This function is called when kodegend.exe is re-executed with the
/// `--run-privileged-install-ops` CLI argument. It performs all operations
/// that require administrator privileges:
///
/// 1. Create installation directory
/// 2. Copy staged files to install directory
/// 3. Add installation directory to system PATH
/// 4. Add hosts entry (idempotent)
/// 5. Flush DNS cache
///
/// # Requirements
///
/// - Must be running with elevated privileges (checked via check_privileges())
/// - staged_files must contain absolute paths to files to install
///
/// # Errors
///
/// Returns error if:
/// - Not running with elevated privileges
/// - File copy operations fail
/// - PATH modification fails
/// - Hosts modification fails
#[cfg(windows)]
pub fn run_privileged_install_ops(staged_files: Vec<String>, scope: installer::windows::paths::InstallScope) -> Result<()> {
    use crate::install::installer::windows::paths::{self};
    use anyhow::Context;
    use std::fs;

    log::info!("Running privileged installation operations (scope: {:?})", scope);

    // Verify we're elevated (required for privileged operations)
    installer::windows::privileges::check_privileges()
        .context("Not running with elevated privileges")?;

    // 1. Create all installer directories atomically
    paths::create_installer_directories(scope)
        .context("Failed to create installer directories")?;
    let install_dir = paths::install_dir(scope);

    // 2. Copy all staged files
    for file in &staged_files {
        let file_path = std::path::Path::new(file);
        let file_name = file_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid file path: {}", file))?;
        let dest_path = install_dir.join(file_name);

        fs::copy(file_path, &dest_path)
            .with_context(|| format!("Failed to copy {} to {}", file, dest_path.display()))?;

        log::info!("Copied {} to {}", file, dest_path.display());
    }

    // 2.5. Add installation directory to system PATH
    component_fixers::add_to_windows_path_sync(scope)
        .context("Failed to add to system PATH")?;

    // 3. Update hosts file (idempotent)
    if !hosts::hosts_entry_exists() {
        installer::config::add_kodegen_host_entries()
            .context("Failed to add hosts entry")?;

        // 4. Flush DNS cache
        std::process::Command::new("ipconfig")
            .arg("/flushdns")
            .status()
            .context("Failed to flush DNS cache")?;

        log::info!("Added hosts entry and flushed DNS");
    } else {
        log::info!("Hosts entry already exists, skipping");
    }

    log::info!("Privileged installation operations completed");
    Ok(())
}
