//! CLI argument parsing and mode detection for kodegen installer

use clap::Parser;
use std::path::PathBuf;

/// Command-line arguments for kodegen-install
#[derive(Parser, Clone)]
#[command(name = "kodegen-install")]
#[command(version, about = "Install kodegen daemon as a system service")]
pub struct Cli {
    /// Path to kodegend binary to install (used with --from-source or as fallback)
    #[arg(long, default_value = "./target/release/kodegend")]
    pub binary: PathBuf,

    /// Don't start service after install
    #[arg(long)]
    pub no_start: bool,

    /// Show what would be done without doing it
    #[arg(long)]
    pub dry_run: bool,

    /// Uninstall instead of install
    #[arg(long)]
    pub uninstall: bool,

    /// Non-interactive mode for CI/server environments
    ///
    /// Runs installation without any prompts or interaction.
    /// Used for .deb/.rpm postinst scripts.
    #[arg(long)]
    pub no_interaction: bool,
}

impl Cli {
    /// Parse command-line arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Check if running in uninstall mode
    pub fn is_uninstall(&self) -> bool {
        self.uninstall
    }
}
