//! Cross-platform logging setup
//!
//! Follows the pattern established in src/platform/mod.rs for platform abstraction.
//!
//! ## Platform Behavior
//! - **Unix**: env_logger → stdout/stderr (captured by systemd/syslog)
//! - **Windows Service**: multi_log combining:
//!   - env_logger → stdout/stderr (for console debugging)
//!   - eventlog → Windows Event Log (for Event Viewer)
//!
//! ## Registry Details (Windows)
//! Event source registered at:
//! `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\kodegend`
//!
//! Registration happens during `kodegend install` (requires Administrator).
//! Runtime logging does NOT require elevation.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

use anyhow::Result;

/// Initialize platform-appropriate logging
///
/// This is called early in main() before Tokio runtime creation.
/// See src/main.rs:36 for current env_logger setup.
pub fn init_logging() -> Result<()> {
    platform_init_logging()
}
