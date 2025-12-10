//! GitHub release download
//!
//! This module handles downloading platform-specific packages from GitHub releases
//! with comprehensive progress tracking and checksum verification.
//!
//! ## Module Organization
//!
//! - `platform` - Platform detection and package format selection
//! - `github` - GitHub API interaction for release discovery
//! - `core` - Download orchestration and progress tracking

mod core;
mod github;
mod platform;

// Re-export public API
pub use core::download_all_binaries;
