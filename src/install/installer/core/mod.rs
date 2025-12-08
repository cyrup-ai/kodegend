//! Core installer structures for cross-platform daemon installation
//!
//! This module provides the core installer functionality with certificate generation
//! and service configuration. Used by platform-specific installers (Windows, Linux, macOS).

// Module declarations
mod certificate;
mod context;
mod progress;
mod service;

// Re-export all public types
// Note: CertificateConfig, InstallContext, ServiceConfig are used by Windows installer
// (see privilege.rs:608, services.rs:12) but appear unused on macOS builds
#[allow(unused_imports)]
pub use certificate::CertificateConfig;
#[allow(unused_imports)]
pub use context::InstallContext;
#[allow(unused_imports)]
pub use progress::DownloadPhase;
pub use progress::InstallProgress;
#[allow(unused_imports)]
pub use service::ServiceConfig;
