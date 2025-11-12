//! Canonical registry of Kodegen binaries
//!
//! This module defines the authoritative list of all binaries to be installed.
//! When adding or removing binaries, update ONLY the BINARIES array below.

/// Canonical list of all Kodegen binaries to download and install
///
/// **NEW ARCHITECTURE**: Only 1 binary needed!
/// - kodegen: MCP stdio server (from cyrup-ai/kodegen GitHub releases)
///
/// **WHY NOT kodegend?**
/// kodegend is ALREADY installed - it's what's calling this installer!
/// The user installs kodegend first, then kodegend auto-installs kodegen.
///
/// The 15 HTTP server binaries are NO LONGER needed as separate processes.
/// They are now embedded into kodegend and started as internal tasks.
pub const BINARIES: &[&str] = &[
    "kodegen",
];

/// Total number of binaries (automatically derived from BINARIES.len())
///
/// Use this constant instead of hardcoded counts for progress tracking.
pub const BINARY_COUNT: usize = BINARIES.len();
