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

use anyhow::Result;
use log::LevelFilter;

pub(super) fn platform_init_logging() -> Result<()> {
    // Create env_logger for console/file output
    let env_logger = env_logger::Builder::from_default_env()
        .format(super::kodegend_log_format)
        .filter_level(LevelFilter::Info)
        .build();

    // Try to create Event Log logger, but track success/failure
    let mut loggers: Vec<Box<dyn log::Log>> = vec![Box::new(env_logger)];
    let mut event_log_enabled = false;

    match eventlog::EventLog::new("kodegend", log::Level::Info) {
        Ok(event_logger) => {
            loggers.push(Box::new(event_logger));
            event_log_enabled = true;
        }
        Err(e) => {
            // Log to stderr (goes to console before logger is initialized)
            eprintln!("Warning: Failed to create Windows Event Log logger: {}", e);
            eprintln!(
                "Continuing with console-only logging. Run 'kodegend install' with Administrator privileges to enable Event Log."
            );
        }
    }

    // Initialize multi-logger with whatever loggers we have
    match multi_log::MultiLogger::init(loggers, log::Level::Info) {
        Ok(_) => {
            // Success: MultiLogger is active
            // Log accurate status based on what actually succeeded
            if event_log_enabled {
                log::info!("Logging initialized: console + Windows Event Log");
            } else {
                log::warn!("Logging initialized: console only (Windows Event Log unavailable)");
            }
        }
        Err(e) => {
            // MultiLogger failed - fall back to basic env_logger
            eprintln!("Warning: MultiLogger initialization failed: {}", e);
            eprintln!("Falling back to basic console logging");
            
            // Reinitialize with basic env_logger as fallback
            // Use try_init() because MultiLogger may have partially initialized the global logger
            env_logger::Builder::from_default_env()
                .format(super::kodegend_log_format)
                .filter_level(LevelFilter::Info)
                .try_init()
                .unwrap_or_else(|e| {
                    // Even try_init() failed - this is extremely rare
                    eprintln!("CRITICAL: Cannot initialize any logging: {}", e);
                    eprintln!("Service will continue but logs may be lost");
                    // Don't exit - let the service run without logging
                });
            
            // Log warning using the fallback logger (if it initialized successfully)
            log::warn!("Logging initialized in fallback mode (basic console only)");
        }
    }
    
    Ok(())  // Always return Ok - service must start
}
