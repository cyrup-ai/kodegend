//! GitHub release download and package extraction
//!
//! This module handles downloading platform-specific packages from GitHub releases
//! and extracting binaries with comprehensive progress tracking.
//!
//! ## Module Organization
//!
//! - `platform` - Platform detection and package format selection
//! - `github` - GitHub API interaction for release discovery
//! - `extract` - Platform-specific package extraction (DEB, RPM, DMG, ZIP)
//! - `core` - Download orchestration and progress tracking

mod platform;
mod github;
mod extract;
mod core;

// Re-export public API
pub use core::download_all_binaries;
