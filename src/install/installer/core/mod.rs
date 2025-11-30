//! Core installer structures and async task management
//!
//! This module provides the core installer functionality with async task handling,
//! certificate generation, and service configuration with zero allocation fast paths
//! and blazing-fast performance.

// Module declarations
mod async_task;
mod certificate;
mod context;
mod progress;
mod service;

// Re-export all public types
pub use async_task::AsyncTask;
pub use certificate::CertificateConfig;
pub use context::InstallContext;
#[allow(unused_imports)]
pub use progress::DownloadPhase;
pub use progress::InstallProgress;
pub use service::ServiceConfig;
