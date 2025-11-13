//! Kodegen installation library
//!
//! This library provides programmatic installation of Kodegen binaries
//! and daemon services, designed to be called by kodegend during startup.

mod binaries;
mod binary_staging;
mod chromium;
mod cli;
mod download;
#[cfg(feature = "gui")]
mod gui;
mod install;
mod orchestration;
mod privilege;
mod runners;
mod wizard;

// NEW MODULES
mod detection;
mod environment;

// Public exports
pub use detection::{InstallationState, check_installation_state};
pub use environment::{is_cli_environment, is_desktop_environment};

// Re-export installer types and modules for internal use
pub use install::{InstallerBuilder, InstallerError};
pub(crate) use install::{core, config, uninstall};

use anyhow::Result;
use cli::Cli;

/// Ensure Kodegen is fully installed, running installation if needed
///
/// This is the main entry point for kodegend to call during startup.
/// Detects installation state and runs appropriate installation mode.
///
/// # Behavior
/// - `NotInstalled` → run full installation
/// - `PartiallyInstalled` → run full installation (repair mode)
/// - `FullyInstalled` → return immediately (no-op)
///
/// # Environment Detection
/// - Desktop environment (DISPLAY set, not SSH) → GUI installer (if feature enabled)
/// - CLI environment (SSH, no DISPLAY, TTY) → non-interactive CLI installer
///
/// # Returns
/// - `Ok(())` if installation verified or completed successfully
/// - `Err(e)` if installation fails
pub async fn ensure_installed() -> Result<()> {
    let state = check_installation_state();
    
    match state {
        InstallationState::FullyInstalled => {
            log::info!("Installation verified - all components present");
            Ok(())
        }
        InstallationState::NotInstalled | InstallationState::PartiallyInstalled => {
            log::info!("Installation required: {:?}", state);
            run_installation().await
        }
    }
}

/// Run installation with auto-detected environment
///
/// Internal function called by ensure_installed() when installation is needed.
async fn run_installation() -> Result<()> {
    let cli = Cli::default_non_interactive();
    
    if is_desktop_environment() {
        #[cfg(feature = "gui")]
        {
            log::info!("Desktop environment detected, using GUI installer");
            runners::run_gui_mode(&cli).await
        }
        #[cfg(not(feature = "gui"))]
        {
            log::warn!("Desktop environment detected but GUI feature not enabled, using CLI");
            runners::run_install(&cli).await
        }
    } else {
        log::info!("CLI environment detected, using non-interactive installer");
        runners::run_install(&cli).await
    }
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
