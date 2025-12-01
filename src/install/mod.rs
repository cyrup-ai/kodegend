//! Kodegen installation library
//!
//! This library provides programmatic installation of Kodegen binaries
//! and daemon services, designed to be called by kodegend during startup.

mod binaries;
mod binary_staging;
mod chromium;
pub(crate) mod cleanup;
mod component_fixers;
mod download;
mod gui;
mod hosts;
mod installer;
mod orchestration;
mod privilege;
pub mod runners;
mod wizard;

// NEW MODULES
mod detection;

// Public exports for internal module use
pub use component_fixers::fix_all_components;
pub use detection::InstallationFixReport;

pub(crate) use installer::{config, core, uninstall};

use anyhow::Result;

/// Ensure Kodegen is fully installed - AUTOMAGICAL
///
/// This is called by run_daemon() before starting services.
/// Auto-detects GUI availability and shows appropriate installer UI.
///
/// # Behavior
/// 1. Check all components (toolchain, hosts, certificates, kodegen, chrome)
/// 2. If all installed → return immediately
/// 3. If GUI available → show branded GUI wizard with progress
/// 4. If no GUI → show CLI banner with progress bars
/// 5. Install all missing components automatically (NO PROMPTS)
pub async fn ensure_installed() -> Result<()> {
    use crate::platform;

    // Step 1: Check what components need installation
    let report = ensure_installed_granular().await?;

    if report.overall_success {
        log::debug!("All components already installed");
        return Ok(());
    }

    // Log any component fix failures for debugging
    log_component_errors(&report);

    // Step 2: Determine installation mode based on GUI availability
    log::info!("Components missing, starting installation...");

    let install_result = if platform::is_gui_available() {
        // GUI mode: Show branded wizard window with progress
        log::info!("GUI available, launching installation wizard");
        gui::run_gui_installation().await?
    } else {
        // CLI mode: Show branding banner, then progress bars
        log::info!("No GUI available, using CLI installation");
        wizard::show_welcome_banner();
        orchestration::run_install().await?
    };

    // Step 3: Show completion
    wizard::show_completion(&install_result);

    Ok(())
}

/// Log errors from failed component fixes
///
/// Iterates over each component in the report and logs any error messages
/// from failed fixes. This provides visibility into what went wrong before
/// falling back to GUI/CLI installation.
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

/// Granular installation with detailed reporting
///
/// Checks each component individually and returns a detailed report
/// of what was checked and fixed.
///
/// # Fail-Fast Behavior
/// Components are checked and fixed in order:
/// 1. Hosts entry
/// 2. Certificates
/// 3. Kodegen version
///
/// If any component fix fails, the function returns immediately with the report.
pub async fn ensure_installed_granular() -> Result<InstallationFixReport> {
    fix_all_components().await
}
