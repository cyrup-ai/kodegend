//! Native GUI for installation progress display
//!
//! Provides a professional branded window showing real-time installation
//! progress when launched from native installers (.app, .msi, .pkg).
//!
//! ## Architecture
//! - Main thread: Runs eframe GUI event loop (60 FPS)
//! - Background thread: Runs tokio installation task
//! - Communication: mpsc::UnboundedChannel for progress updates
//!
//! ## Integration
//! Receives InstallProgress from install_kodegen_daemon() via channel.
//! See: src/install/core.rs:152
//!
//! ## Module Organization
//! - `types`: Type definitions (BinaryDownloadStatus, BinaryStatus)
//! - `window`: Main InstallWindow implementation with eframe::App trait
//! - `panels`: Panel rendering functions (progress, completion, error)
//! - `runner`: run_gui_installation() entry point

mod panels;
mod runner;
mod types;
mod window;

// Re-export public API
pub use runner::run_gui_installation;
