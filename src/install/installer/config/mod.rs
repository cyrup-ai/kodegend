//! Configuration and service setup for installer
//!
//! This module provides configuration generation, service setup, and platform-specific
//! installation logic with zero allocation fast paths and blazing-fast performance.

pub mod certificates;
mod hosts;
mod installer;
pub(crate) mod services;

// Re-export public API
pub use hosts::{add_kodegen_host_entries, remove_kodegen_host_entries};

// Internal re-exports (kept for potential future use)
#[allow(unused_imports)]
pub use certificates::import_certificate_to_system;
#[allow(unused_imports)]
pub use installer::create_default_configuration;
