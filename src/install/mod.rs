//! Kodegen installation library
//!
//! This library provides programmatic installation of Kodegen binaries
//! and daemon services, designed to be called by kodegend during startup.

mod binaries;
mod binary_staging;
mod chromium;
mod cli;
mod component_fixers;
mod download;
#[cfg(feature = "gui")]
mod gui;
mod hosts;
mod installer;
mod orchestration;
mod privilege;
mod runners;
mod wizard;

// NEW MODULES
mod detection;
mod environment;

// Public exports - Legacy
pub use detection::{InstallationState, check_installation_state};
pub use environment::{is_cli_environment, is_desktop_environment};

// Public exports - Granular component system
pub use detection::{
    ComponentStatus,
    ComponentStatusReport,
    ComponentFixResult,
    InstallationFixReport,
    check_all_components,
    check_hosts_status,
    check_certificates_status,
    check_kodegen_version_status,
};
pub use component_fixers::{
    fix_hosts,
    fix_certificates,
    fix_kodegen_version,
    fix_all_components,
};

// Re-export installer types and modules for internal use
pub use installer::{InstallerBuilder, InstallerError};
pub(crate) use installer::{core, config, uninstall};

use anyhow::Result;
use cli::Cli;

/// Ensure Kodegen is fully installed with GRANULAR component checks
///
/// This is the main entry point for kodegend to call during startup.
/// Checks each component individually and fixes only those that need action.
///
/// # Behavior (NEW - Granular)
/// - Checks each component independently: hosts, certificates, kodegen version
/// - Fixes only components that need action
/// - Uses fail-fast behavior: stops on first component failure
/// - Uses SEPARATE sudo operations for each privileged component
///
/// # Components Checked
/// 1. Hosts entry (127.0.0.1 mcp.kodegen.ai in /etc/hosts)
/// 2. Certificates (valid TLS cert in config_dir/kodegen/certs/)
/// 3. Kodegen version (binary in /usr/local/bin matches crates.io version)
///
/// # Returns
/// - `Ok(())` if all components verified or fixed successfully
/// - `Err(e)` if any component fix fails (fail-fast)
pub async fn ensure_installed() -> Result<()> {
    let report = ensure_installed_granular().await?;

    if report.overall_success {
        Ok(())
    } else {
        // Find first failure and return that error
        if let Some(ref result) = report.hosts
            && !result.success
        {
            return Err(anyhow::anyhow!(
                "Hosts fix failed: {}",
                result.error.as_deref().unwrap_or("unknown error")
            ));
        }
        if let Some(ref result) = report.certificates
            && !result.success
        {
            return Err(anyhow::anyhow!(
                "Certificate fix failed: {}",
                result.error.as_deref().unwrap_or("unknown error")
            ));
        }
        if let Some(ref result) = report.kodegen_version
            && !result.success
        {
            return Err(anyhow::anyhow!(
                "Kodegen version fix failed: {}",
                result.error.as_deref().unwrap_or("unknown error")
            ));
        }
        Err(anyhow::anyhow!("Installation failed"))
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

/// Public API for manual installation (used by main.rs binary)
///
/// This preserves the existing standalone installer behavior.
/// Called when user explicitly runs `kodegen_install` from command line.
pub async fn install_interactive() -> Result<()> {
    let cli = Cli::parse_args();
    
    if cli.is_uninstall() {
        return runners::run_uninstall(&cli).await;
    }
    
    // Wizard or non-interactive based on CLI args
    if wizard::is_non_interactive(&cli) {
        runners::run_install(&cli).await
    } else {
        let options = wizard::run_wizard()?;
        orchestration::run_install_with_options(&options, &cli).await
    }
}
