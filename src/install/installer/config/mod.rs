//! Configuration and service setup for installer
//!
//! This module provides configuration generation, service setup, and platform-specific
//! installation logic with zero allocation fast paths and blazing-fast performance.

pub mod certificates;
mod hosts;
mod installer;
mod services;
mod toolchain;

// Re-export public API
pub use hosts::remove_kodegen_host_entries;
pub use installer::install_kodegen_daemon;

// Internal re-exports (kept for potential future use)
#[allow(unused_imports)]
pub use certificates::import_certificate_to_system;
#[allow(unused_imports)]
pub use installer::create_default_configuration;
