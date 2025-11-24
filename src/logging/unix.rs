//! Unix logging via env_logger
//!
//! Maintains existing behavior - logs go to stdout/stderr and are captured by:
//! - systemd (journalctl on Linux)
//! - launchd (unified logging on macOS)
//! - syslog (traditional Unix systems)

use anyhow::Result;
use log::LevelFilter;

pub fn platform_init_logging() -> Result<()> {
    // Preserve exact format from src/main.rs:36-50
    env_logger::Builder::from_default_env()
        .format(|buf, record| {
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
        })
        .filter_level(LevelFilter::Info)
        .init();
    
    Ok(())
}
