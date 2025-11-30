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

/// Standard log format used across all platforms
///
/// Format: [timestamp level file:line] message
/// Example: [2025-11-29T12:34:56.789Z INFO daemon.rs:42] Service started
///
/// This function is shared between Unix and Windows implementations to ensure
/// consistent log output across platforms.
pub(crate) fn kodegend_log_format(
    buf: &mut env_logger::fmt::Formatter,
    record: &log::Record,
) -> std::io::Result<()> {
    use std::io::Write;
    writeln!(
        buf,
        "[{} {} {}:{}] {}",
        buf.timestamp_millis(),
        record.level(),
        record.file().unwrap_or("unknown"),
        record.line().unwrap_or(0),
        record.args()
    )
}

/// Initialize platform-appropriate logging
///
/// This is called early in main() before Tokio runtime creation.
/// See src/main.rs:36 for current env_logger setup.
pub fn init_logging() -> Result<()> {
    platform_init_logging()
}
