//! Installation runners for different modes (GUI, CLI, uninstall)
//!
//! This module provides the top-level runner functions for different installation
//! modes. Currently only uninstallation is exposed here; GUI and CLI installation
//! flows are handled directly by mod.rs using gui::run_gui_installation() and
//! orchestration::run_install() respectively.

use anyhow::{Context, Result};
use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

use crate::install;

/// Run uninstallation
pub async fn run_uninstall() -> Result<()> {
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
