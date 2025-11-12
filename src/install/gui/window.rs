//! Main GUI window implementation for installation progress

use eframe::egui;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use super::binaries::BINARIES;
use super::core::{DownloadPhase, InstallProgress};

use super::types::{BinaryDownloadStatus, BinaryStatus};

/// Installation window state
pub struct InstallWindow {
    /// Progress receiver channel (Arc<Mutex<>> for thread safety)
    progress_rx: Arc<Mutex<mpsc::Receiver<InstallProgress>>>,

    /// Current installation state (updated from channel)
    pub current_step: String,
    pub current_message: String,
    pub progress: f32, // 0.0 to 1.0
    pub is_error: bool,
    pub is_complete: bool,

    /// Auto-close timer for success screen (starts when is_complete becomes true)
    pub auto_close_timer: Option<std::time::Instant>,

    /// Branding assets (loaded once at startup)
    pub banner: Option<egui::TextureHandle>,

    /// Per-binary download status (one entry per binary)
    pub binary_statuses: Vec<BinaryDownloadStatus>,
}

impl InstallWindow {
    /// Create new installation window
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        progress_rx: mpsc::Receiver<InstallProgress>,
    ) -> Self {
        // Configure dark theme (KODEGEN branding colors)
        let mut visuals = egui::Visuals::dark();
        visuals.window_fill = egui::Color32::from_rgb(10, 25, 41); // #0a1929 (dark blue)
        visuals.panel_fill = egui::Color32::from_rgb(5, 18, 38); // #051226 (darker blue)
        cc.egui_ctx.set_visuals(visuals);

        // Load banner from embedded assets
        let banner = Self::load_banner(cc);

        // Initialize binary statuses (all pending)
        let binary_statuses = BINARIES
            .iter()
            .enumerate()
            .map(|(i, &name)| BinaryDownloadStatus {
                name: name.to_string(),
                _index: i + 1,
                status: BinaryStatus::Pending,
                progress: 0.0,
                version: None,
            })
            .collect();

        Self {
            progress_rx: Arc::new(Mutex::new(progress_rx)),
            current_step: "Initializing...".to_string(),
            current_message: "Starting installation".to_string(),
            progress: 0.0,
            is_error: false,
            is_complete: false,
            auto_close_timer: None,
            banner,
            binary_statuses,
        }
    }

    /// Load KODEGEN banner from embedded assets
    fn load_banner(cc: &eframe::CreationContext<'_>) -> Option<egui::TextureHandle> {
        // Embedded at compile time (see GUI_1 asset setup)
        let banner_bytes = include_bytes!("../../assets/banner.png");

        // Decode PNG with image crate
        match image::load_from_memory(banner_bytes) {
            Ok(img) => {
                let img_rgba = img.to_rgba8();
                let size = [img_rgba.width() as usize, img_rgba.height() as usize];
                let pixels = img_rgba.into_raw();

                // Convert to egui color format
                let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);

                // Upload to GPU (one-time upload, reused every frame)
                Some(cc.egui_ctx.load_texture(
                    "banner",
                    color_image,
                    egui::TextureOptions::LINEAR, // Linear filtering for smooth scaling
                ))
            }
            Err(e) => {
                eprintln!("Failed to load banner: {}", e);
                None // Fallback to text title (handled in update())
            }
        }
    }

    /// Poll for progress updates (non-blocking)
    pub fn poll_progress(&mut self) {
        // try_lock() = non-blocking (won't stall GUI if contended)
        if let Ok(mut rx) = self.progress_rx.try_lock() {
            // try_recv() = non-blocking (returns immediately if empty)
            while let Ok(progress) = rx.try_recv() {
                // Update per-binary status if download metadata present
                if let Some(meta) = &progress.download_metadata {
                    let idx = meta.binary_index.saturating_sub(1);
                    if let Some(status) = self.binary_statuses.get_mut(idx) {
                        status.progress = if meta.total_bytes > 0 {
                            (meta.bytes_downloaded as f64 / meta.total_bytes as f64) as f32
                        } else {
                            0.0
                        };

                        status.version = meta.version.clone();

                        status.status = match meta.phase {
                            DownloadPhase::Discovering => BinaryStatus::Discovering,
                            DownloadPhase::Downloading => BinaryStatus::Downloading,
                            DownloadPhase::Extracting => BinaryStatus::Extracting,
                            DownloadPhase::Complete => BinaryStatus::Complete,
                        };
                    }
                }

                self.current_step = progress.step;
                self.current_message = progress.message;
                self.progress = progress.progress;
                self.is_error = progress.is_error;

                // Check for completion
                if self.progress >= 1.0 && !self.is_error {
                    self.is_complete = true;

                    // Start auto-close timer when completion detected
                    if self.auto_close_timer.is_none() {
                        self.auto_close_timer = Some(std::time::Instant::now());
                    }
                }
            }
        }
        // If lock fails, skip this frame (will retry next frame at 60 FPS)
    }
}

impl eframe::App for InstallWindow {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // Poll for new progress updates (non-blocking)
        self.poll_progress();

        // Request repaint for smooth animation (60 FPS)
        ctx.request_repaint();

        // Disable close button during installation, re-enable when complete/error
        if !self.is_complete && !self.is_error {
            // Installation in progress - disable close button
            ctx.send_viewport_cmd(egui::ViewportCommand::EnableButtons {
                close: false,    // Close disabled
                minimized: true, // Allow minimize
                maximize: false, // No maximize on fixed-size window
            });
        } else {
            // Installation complete or errored - re-enable close button
            ctx.send_viewport_cmd(egui::ViewportCommand::EnableButtons {
                close: true, // Close enabled
                minimized: true,
                maximize: false,
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                // Banner at top (or fallback to text title)
                if let Some(banner) = &self.banner {
                    // Calculate aspect ratio for responsive sizing
                    let banner_aspect = banner.size()[1] as f32 / banner.size()[0] as f32;
                    let banner_width = ui.available_width();
                    let banner_height = banner_aspect * banner_width;
                    let banner_size = egui::vec2(banner_width, banner_height);

                    ui.add(egui::Image::new((banner.id(), banner_size)));
                } else {
                    // Fallback if banner load failed
                    ui.add_space(20.0);
                    ui.heading(
                        egui::RichText::new("KODEGEN.ᴀɪ")
                            .size(32.0)
                            .color(egui::Color32::from_rgb(24, 202, 155)),
                    ); // Cyan
                }

                ui.add_space(30.0);

                // Progress section (state-based routing)
                if !self.is_complete && !self.is_error {
                    super::panels::show_progress_panel(self, ui);
                } else if self.is_error {
                    super::panels::show_error_panel(self, ui, frame);
                } else {
                    super::panels::show_completion_panel(self, ui, frame);
                }
            });
        });
    }
}
