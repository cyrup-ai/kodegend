//! Configuration and service setup for installer
//!
//! This module provides configuration generation, service setup, and platform-specific
//! installation logic with zero allocation fast paths and blazing-fast performance.

mod toolchain;
mod certificates;
mod services;
mod hosts;
mod installer;

// Re-export public API
pub use installer::install_kodegen_daemon;
pub use hosts::remove_kodegen_host_entries;

// Internal re-exports (kept for potential future use)
#[allow(unused_imports)]
pub use installer::create_default_configuration;
#[allow(unused_imports)]
pub use certificates::import_certificate_to_system;
