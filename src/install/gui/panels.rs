//! Panel rendering functions for installation GUI

use eframe::egui;

use super::binaries::BINARY_COUNT;

use super::types::BinaryStatus;
use super::window::InstallWindow;

/// Show progress panel during installation
pub fn show_progress_panel(window: &InstallWindow, ui: &mut egui::Ui) {
    // Current step title (e.g., "Creating Directories", "Downloading Chromium")
    ui.label(
        egui::RichText::new(&window.current_step)
            .size(18.0)
            .strong()
            .color(egui::Color32::from_rgb(24, 202, 155)),
    ); // Cyan accent

    ui.add_space(15.0);

    // Overall progress bar with percentage display
    let completed = window
        .binary_statuses
        .iter()
        .filter(|b| b.status == BinaryStatus::Complete)
        .count();

    ui.label(format!("Binaries: {} / {}", completed, BINARY_COUNT));

    let progress_bar = egui::ProgressBar::new(window.progress)
        .desired_width(500.0)
        .show_percentage()
        .animate(true);

    ui.add(progress_bar);

    ui.add_space(10.0);

    // Binary download list (scrollable)
    ui.separator();
    ui.add_space(10.0);

    egui::ScrollArea::vertical()
        .max_height(300.0)
        .show(ui, |ui| {
            for binary in &window.binary_statuses {
                ui.horizontal(|ui| {
                    // Status icon
                    let icon = match binary.status {
                        BinaryStatus::Pending => "⏳",
                        BinaryStatus::Discovering => "🔍",
                        BinaryStatus::Downloading => "📥",
                        BinaryStatus::Extracting => "📦",
                        BinaryStatus::Complete => "✅",
                    };
                    ui.label(icon);

                    // Binary name + version
                    let label = if let Some(ref ver) = binary.version {
                        format!("{} ({})", binary.name, ver)
                    } else {
                        binary.name.clone()
                    };
                    ui.label(label);

                    ui.add_space(10.0);

                    // Progress bar (only show if downloading/extracting)
                    if matches!(
                        binary.status,
                        BinaryStatus::Downloading | BinaryStatus::Extracting
                    ) {
                        ui.add(
                            egui::ProgressBar::new(binary.progress)
                                .desired_width(200.0)
                                .show_percentage(),
                        );
                    }
                });

                ui.add_space(5.0);
            }
        });

    ui.add_space(10.0);
    ui.separator();
    ui.add_space(10.0);

    // Status message
    ui.label(
        egui::RichText::new(&window.current_message)
            .size(14.0)
            .color(egui::Color32::from_rgb(204, 204, 204)),
    );

    ui.add_space(20.0);

    // Special context for Chromium download (longest step, 65-85% progress)
    // Provides user reassurance during long download
    if window.progress >= 0.60 && window.progress < 0.85 {
        ui.label(
            egui::RichText::new("⏳ Downloading Chromium (~100MB)")
                .size(12.0)
                .color(egui::Color32::from_rgb(153, 153, 153)),
        ); // Dim gray
        ui.label(
            egui::RichText::new("This may take 30-60 seconds")
                .size(11.0)
                .color(egui::Color32::from_rgb(153, 153, 153)),
        );
    }
}

/// Show completion panel when installation succeeds
pub fn show_completion_panel(
    window: &mut InstallWindow,
    ui: &mut egui::Ui,
    _frame: &mut eframe::Frame,
) {
    // Success icon (large, prominent)
    ui.label(
        egui::RichText::new("✓")
            .size(64.0)
            .color(egui::Color32::from_rgb(0, 255, 100)),
    ); // Success green

    ui.add_space(10.0);

    // Success title
    ui.label(
        egui::RichText::new("Installation Complete!")
            .size(24.0)
            .strong()
            .color(egui::Color32::from_rgb(0, 255, 100)),
    );

    ui.add_space(20.0);

    // Instructions (what user should do next)
    ui.label(
        egui::RichText::new("Kodegen daemon has been successfully installed.")
            .size(14.0)
            .color(egui::Color32::from_rgb(204, 204, 204)),
    );

    ui.add_space(10.0);

    ui.label(
        egui::RichText::new("Please restart your MCP client to activate:")
            .size(14.0)
            .color(egui::Color32::from_rgb(204, 204, 204)),
    );

    ui.add_space(10.0);

    // Client list (supported MCP clients)
    ui.horizontal(|ui| {
        ui.add_space(100.0); // Center offset
        ui.vertical(|ui| {
            ui.label(
                egui::RichText::new("• Claude Desktop")
                    .size(14.0)
                    .color(egui::Color32::WHITE),
            );
            ui.label(
                egui::RichText::new("• Cursor")
                    .size(14.0)
                    .color(egui::Color32::WHITE),
            );
            ui.label(
                egui::RichText::new("• Windsurf")
                    .size(14.0)
                    .color(egui::Color32::WHITE),
            );
            ui.label(
                egui::RichText::new("• Zed")
                    .size(14.0)
                    .color(egui::Color32::WHITE),
            );
        });
    });

    ui.add_space(20.0);

    // Auto-close timer countdown
    if let Some(start_time) = window.auto_close_timer {
        let elapsed = start_time.elapsed().as_secs();
        let remaining = 3u64.saturating_sub(elapsed);

        if remaining == 0 {
            // Timer expired - close window properly
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        // Show countdown (updates at 60 FPS thanks to ctx.request_repaint())
        ui.label(
            egui::RichText::new(format!("Closing in {}...", remaining))
                .size(12.0)
                .color(egui::Color32::GRAY),
        );

        ui.add_space(10.0);
    }

    // Close button (manual override for immediate exit)
    let close_button = egui::Button::new(egui::RichText::new("Close Now").size(16.0))
        .fill(egui::Color32::from_rgb(24, 202, 155)); // Cyan button

    if ui.add(close_button).clicked() {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
    }
}

/// Show error panel when installation fails
pub fn show_error_panel(
    window: &InstallWindow,
    ui: &mut egui::Ui,
    _frame: &mut eframe::Frame,
) {
    // Error icon (large, prominent)
    ui.label(
        egui::RichText::new("❌")
            .size(64.0)
            .color(egui::Color32::from_rgb(255, 100, 100)),
    ); // Error red

    ui.add_space(10.0);

    // Error title
    ui.label(
        egui::RichText::new("Installation Failed")
            .size(24.0)
            .strong()
            .color(egui::Color32::from_rgb(255, 100, 100)),
    );

    ui.add_space(20.0);

    // Error details (from current_message set by InstallProgress::error())
    ui.label(
        egui::RichText::new(&window.current_message)
            .size(14.0)
            .color(egui::Color32::from_rgb(204, 204, 204)),
    );

    ui.add_space(30.0);

    // Action buttons (horizontal layout)
    ui.horizontal(|ui| {
        // Report Issue button (opens GitHub in browser)
        let report_button = egui::Button::new(egui::RichText::new("Report Issue").size(14.0))
            .fill(egui::Color32::from_rgb(24, 202, 155)); // Cyan (action button)

        if ui.add(report_button).clicked() {
            // Opens GitHub new issue page in default browser
            // opener crate handles cross-platform (macOS/Windows/Linux)
            let _ = opener::open("https://github.com/cyrup-ai/kodegen/issues/new");
        }

        ui.add_space(10.0);

        // Close button (exits with error code)
        let close_button = egui::Button::new(egui::RichText::new("Close").size(14.0))
            .fill(egui::Color32::from_rgb(255, 100, 100)); // Red (destructive action)

        if ui.add(close_button).clicked() {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
    });
}
