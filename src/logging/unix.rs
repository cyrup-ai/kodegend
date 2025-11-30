//! Unix logging via env_logger
//!
//! Maintains existing behavior - logs go to stdout/stderr and are captured by:
//! - systemd (journalctl on Linux)
//! - launchd (unified logging on macOS)
//! - syslog (traditional Unix systems)

use anyhow::Result;
use log::LevelFilter;

pub fn platform_init_logging() -> Result<()> {
    env_logger::Builder::from_default_env()
        .format(super::kodegend_log_format)
        .filter_level(LevelFilter::Info)
        .init();

    Ok(())
}
