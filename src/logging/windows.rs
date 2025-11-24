//! Windows Event Log integration with dual logging
//!
//! Uses multi_log to write to BOTH:
//! 1. env_logger (console/file output for debugging)
//! 2. eventlog (Windows Event Log for Event Viewer)
//!
//! ## Event Source Registration
//! The event source "kodegend" must be registered in the Windows Registry at:
//! `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\kodegend`
//!
//! Registration requires Administrator privileges and happens during:
//! - `kodegend install` command
//! - See: src/install/installer/windows/service_creation.rs
//!
//! ## Event ID Mapping
//! - 1001: Error messages (Red icon in Event Viewer)
//! - 2001: Warning messages (Yellow icon)
//! - 3001: Info messages (Blue icon)
//! - 4001-5001: Debug/Trace (also Blue icon)
//!
//! ## Registry Access
//! - **Registration**: Requires HKLM write access (Administrator only)
//! - **Runtime logging**: Works as any user (no elevation needed)

use anyhow::{Result, Context};
use log::LevelFilter;

pub(super) fn platform_init_logging() -> Result<()> {
    // Create env_logger for console/file output
    let env_logger = env_logger::Builder::from_default_env()
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
        .build();

    // Create EventLog instance for Windows Event Log
    // Note: EventLog::new() will gracefully handle missing registration
    // If not registered, events may appear under generic "Application" source
    let event_logger = eventlog::EventLog::new("kodegend", log::Level::Info)
        .context("Failed to create Windows Event Log logger")?;

    // Combine BOTH loggers using multi_log
    // This enables simultaneous output to console AND Event Viewer
    multi_log::MultiLogger::init(
        vec![
            Box::new(env_logger),
            Box::new(event_logger),
        ],
        log::Level::Info
    ).context("Failed to initialize multi-logger")?;

    log::info!("Logging initialized: console + Windows Event Log");
    
    Ok(())
}
