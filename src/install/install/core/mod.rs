//! Core installer structures and async task management
//!
//! This module provides the core installer functionality with async task handling,
//! certificate generation, and service configuration with zero allocation fast paths
//! and blazing-fast performance.

// Module declarations
mod async_task;
mod progress;
mod certificate;
mod service;
mod context;

// Re-export all public types
pub use async_task::AsyncTask;
pub use progress::{DownloadPhase, InstallProgress};
pub use certificate::CertificateConfig;
pub use service::ServiceConfig;
pub use context::InstallContext;
