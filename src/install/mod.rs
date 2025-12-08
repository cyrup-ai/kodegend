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
mod binary_staging;
pub(crate) mod chromium;
pub(crate) mod cleanup;
mod component_fixers;
mod detection;
mod download;
mod gui;
mod hosts;
mod installer;
mod orchestration;
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
pub async fn ensure_installed() -> Result<()> {
    use crate::platform;

    // Create progress channel - logic sends, presentation receives
    let (tx, rx) = mpsc::channel(100);

    // Detect GUI availability and spawn appropriate presentation layer
    let is_gui = platform::is_gui_available();

    if is_gui {
        log::info!("GUI available, launching installation window");
    } else {
        log::info!("No GUI available, using CLI progress display");
        wizard::show_welcome_banner();
    }

    // Spawn presentation layer in background
    // GUI runs on main thread (eframe requirement), CLI runs async
    let presentation_handle = if is_gui {
        // GUI presentation - runs eframe event loop
        tokio::spawn(async move {
            gui::run_gui_display(rx).await
        })
    } else {
        // CLI presentation - runs indicatif progress bars
        tokio::spawn(async move {
            orchestration::run_cli_display(rx).await
        })
    };

    // Run THE ONLY logic path - all checks and fixes happen here
    let report = fix_all_components(Some(tx)).await?;

    // Wait for presentation to finish (it exits when channel closes)
    let _ = presentation_handle.await;

    // Log any errors
    if !report.overall_success {
        log_component_errors(&report);
        anyhow::bail!("Installation failed - see errors above");
    }

    log::debug!("All components installed successfully");
    Ok(())
}

/// Log errors from failed component fixes
fn log_component_errors(report: &InstallationFixReport) {
    if let Some(ref result) = report.toolchain
        && !result.success
        && let Some(ref error) = result.error
    {
        log::error!("Toolchain fix failed: {}", error);
    }

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
