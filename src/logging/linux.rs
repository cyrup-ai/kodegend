//! Linux systemd journal integration with dual logging
//!
//! Mirrors the Windows Event Log architecture:
//! - env_logger → stdout/stderr (for console debugging)
//! - systemd-journal-logger → systemd journal (for journalctl)
//!
//! Automatically detects systemd environment via INVOCATION_ID or JOURNAL_STREAM
//! environment variables and enables journal logging accordingly.
//!
//! ## Journal Field Mapping
//! - log::error!() → PRIORITY=3 (ERR)
//! - log::warn!()  → PRIORITY=4 (WARNING)
//! - log::info!()  → PRIORITY=6 (INFO)
//! - log::debug!() → PRIORITY=7 (DEBUG)
//!
//! ## Structured Fields
//! - VERSION: Package version from CARGO_PKG_VERSION
//! - COMPONENT: Always "kodegend"
//! - HOSTNAME: System hostname (if available)
//!
//! ## Querying Logs
//! ```bash
//! journalctl -u kodegend                          # All logs
//! journalctl -u kodegend -p err                   # Errors only
//! journalctl -u kodegend COMPONENT=kodegend       # Filter by field
//! journalctl -u kodegend -o json-pretty           # Show all fields
//! ```

use crate::cli_output;
use anyhow::Result;
use log::LevelFilter;

pub(super) fn platform_init_logging() -> Result<()> {
    // Detect if running under systemd by checking environment variables
    let is_systemd = std::env::var("INVOCATION_ID").is_ok() 
        || std::env::var("JOURNAL_STREAM").is_ok();

    if is_systemd {
        // Systemd environment detected - use dual logging
        init_dual_logging()?;
    } else {
        // Non-systemd environment (Docker, manual execution) - fallback to console only
        init_env_logger()?;
    }

    Ok(())
}

/// Initialize dual logging: console + systemd journal
fn init_dual_logging() -> Result<()> {
    // Create env_logger for console/file output
    let env_logger = env_logger::Builder::from_default_env()
        .format(super::kodegend_log_format)
        .filter_level(LevelFilter::Info)
        .build();

    // Try to create systemd journal logger
    let mut loggers: Vec<Box<dyn log::Log>> = vec![Box::new(env_logger)];
    let mut journal_enabled = false;

    match create_journal_logger() {
        Ok(journal_logger) => {
            loggers.push(Box::new(journal_logger));
            journal_enabled = true;
        }
        Err(e) => {
            // Log to stderr (goes to console before logger is initialized)
            cli_output::warning(&format!("Failed to create systemd journal logger: {}", e));
            cli_output::warning(
                "Continuing with console-only logging. Journal integration unavailable."
            );
        }
    }

    // Initialize multi-logger with whatever loggers we have
    match multi_log::MultiLogger::init(loggers, log::Level::Info) {
        Ok(_) => {
            // Success: MultiLogger is active
            if journal_enabled {
                log::info!("Logging initialized: console + systemd journal (direct API)");
            } else {
                log::warn!("Logging initialized: console only (systemd journal unavailable)");
            }
        }
        Err(e) => {
            // MultiLogger failed - fall back to basic env_logger
            cli_output::warning(&format!("MultiLogger initialization failed: {}", e));
            cli_output::warning("Falling back to basic console logging");
            
            // Reinitialize with basic env_logger as fallback
            env_logger::Builder::from_default_env()
                .format(super::kodegend_log_format)
                .filter_level(LevelFilter::Info)
                .try_init()
                .unwrap_or_else(|e| {
                    eprintln!("CRITICAL: Cannot initialize any logging: {}", e);
                    eprintln!("Service will continue but logs may be lost");
                });
            
            log::warn!("Logging initialized in fallback mode (basic console only)");
        }
    }

    Ok(())  // Always return Ok - service must start
}

/// Create systemd journal logger with structured fields
fn create_journal_logger() -> Result<systemd_journal_logger::JournalLog> {
    // Get hostname for structured logging
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    // Create journal logger with process-wide metadata fields
    let journal_log = systemd_journal_logger::JournalLog::new()?
        .with_extra_fields(vec![
            ("VERSION", env!("CARGO_PKG_VERSION")),
            ("COMPONENT", "kodegend"),
            ("HOSTNAME", &hostname),
        ])
        .with_syslog_identifier("kodegend".to_string());

    Ok(journal_log)
}

/// Initialize basic env_logger for non-systemd environments
fn init_env_logger() -> Result<()> {
    env_logger::Builder::from_default_env()
        .format(super::kodegend_log_format)
        .filter_level(LevelFilter::Info)
        .init();
    
    log::info!("Logging initialized: env_logger (stdout/stderr)");
    Ok(())
}
