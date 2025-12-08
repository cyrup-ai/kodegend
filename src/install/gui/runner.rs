//! GUI presentation layer - displays progress from logic layer
//!
//! This is PRESENTATION ONLY:
//! - Receives progress events from channel
//! - Displays in eframe/egui window
//! - NO logic, NO downloads, NO checks

use eframe::egui;
use tokio::sync::mpsc;

use crate::install::core::InstallProgress;
use super::window::InstallWindow;

/// Run GUI display - receives progress and shows in window
///
/// This is the GUI presentation layer. It:
/// - Creates an eframe window
/// - Receives InstallProgress events from the channel
/// - Displays progress in the window
///
/// NO logic happens here - all checks/fixes/downloads happen in fix_all_components()
pub async fn run_gui_display(rx: mpsc::Receiver<InstallProgress>) -> anyhow::Result<()> {
    log::info!("Starting GUI display...");

    // Configure GUI window
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 450.0])
            .with_resizable(false)
            .with_title("Kodegen Installation"),
        ..Default::default()
    };

    // Run GUI (blocking until window closes)
    // The closure is FnOnce so we can move rx directly
    let result = eframe::run_native(
        "kodegen_install",
        native_options,
        Box::new(move |cc| {
            Ok(Box::new(InstallWindow::new(cc, rx)))
        }),
    );

    match result {
        Ok(()) => {
            log::info!("GUI display completed");
            Ok(())
        }
        Err(e) => {
            log::error!("GUI display error: {}", e);
            Err(anyhow::anyhow!("GUI error: {}", e))
        }
    }
}
