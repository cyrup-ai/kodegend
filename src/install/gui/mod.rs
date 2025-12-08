//! GUI presentation layer for installation progress
//!
//! This is PRESENTATION ONLY - receives progress events and displays them.
//! NO logic, NO downloads, NO checks happen here.
//!
//! ## Architecture
//!
//! ```text
//! fix_all_components(progress_tx)   <-- LOGIC (elsewhere)
//!         │
//!         ▼
//!    progress channel
//!         │
//!         ▼
//! run_gui_display(rx)               <-- PRESENTATION (here)
//!         │
//!         ▼
//!    InstallWindow (egui)
//! ```
//!
//! ## Module Organization
//! - `types`: Type definitions (BinaryDownloadStatus, BinaryStatus)
//! - `window`: Main InstallWindow implementation with eframe::App trait
//! - `panels`: Panel rendering functions (progress, completion, error)
//! - `runner`: run_gui_display() entry point

mod panels;
mod runner;
mod types;
mod window;

// Re-export public API
pub use runner::run_gui_display;

#[allow(unused_imports)]
pub use types::{BinaryDownloadStatus, BinaryStatus};
