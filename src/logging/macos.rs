//! macOS Unified Logging via os_log
//!
//! Uses multi_log to write to BOTH:
//! 1. env_logger → stdout/stderr (file output via launchd)
//! 2. oslog → macOS Unified Logging (Console.app integration)
//!
//! This matches the Windows implementation pattern:
//! - Dual output for debugging (files) and production (system integration)
//! - Graceful fallback if os_log unavailable
//! - Maintains backwards compatibility with existing file-based logging
//!
//! ## Console.app Integration
//! After this implementation, logs viewable via:
//! ```bash
//! # Show all kodegend logs
//! log show --predicate 'subsystem == "ai.kodegen.kodegend"'
//!
//! # Stream live logs
//! log stream --predicate 'subsystem == "ai.kodegen.kodegend"'
//! ```
//!
//! ## Reference Implementation
//! Based on Windows Event Log integration: src/logging/windows.rs

use crate::cli_output;
use anyhow::Result;
use log::LevelFilter;

pub(super) fn platform_init_logging() -> Result<()> {
    // Create env_logger for file output (backwards compatibility)
    // launchd captures stdout/stderr to /var/log/{service}/*.log
    let env_logger = env_logger::Builder::from_default_env()
        .format(super::kodegend_log_format)
        .filter_level(LevelFilter::Info)
        .build();

    // Create loggers vec with env_logger
    let mut loggers: Vec<Box<dyn log::Log>> = vec![Box::new(env_logger)];

    // Create OsLogger for macOS Unified Logging
    // Subsystem: ai.kodegen.kodegend (matches bundle identifier)
    // Categories: Created automatically per log target
    // Note: OsLogger::new is infallible (unlike Windows EventLog)
    let oslogger = oslog::OsLogger::new("ai.kodegen.kodegend");
    
    // Box it for multi_log (matches Windows pattern)
    loggers.push(Box::new(oslogger));

    // Initialize multi-logger with whatever loggers we have
    match multi_log::MultiLogger::init(loggers, log::Level::Info) {
        Ok(_) => {
            // Success: MultiLogger is active with both env_logger and oslog
            log::info!("Logging initialized: file + macOS Unified Logging");
            log::info!("View logs: log stream --predicate 'subsystem == \"ai.kodegen.kodegend\"'");
        }
        Err(e) => {
            // MultiLogger failed - fall back to basic env_logger
            cli_output::warning(&format!("MultiLogger initialization failed: {}", e));
            cli_output::warning("Falling back to basic file logging");
            
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
            log::warn!("Logging initialized in fallback mode (file only)");
        }
    }
    
    Ok(())  // Always return Ok - service must start
}
