mod cli;
mod cli_output;
mod config;
mod constants;
mod control;
mod daemon;
mod install;
mod ipc;
mod lifecycle;
mod logging;
mod manager;
mod platform;
mod security;
mod service;
mod signing;
mod state_machine;
mod status;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use kodegen_config::KodegenConfig;
use crate::install::ensure_installed;
use log::{error, info};
use manager::ServiceManager;

fn main() {
    // Windows service mode detection
    // When SCM starts the service, it passes --service argument
    #[cfg(target_os = "windows")]
    {
        if std::env::args().any(|arg| arg == "--service" || arg == "--windows-service") {
            // Running as Windows service - invoke service dispatcher
            if let Err(e) = platform::start_windows_service() {
                cli_output::error(&format!("Windows service error: {}", e));
                std::process::exit(1);
            }
            return;
        }
    }

    // Initialize platform-appropriate logging (Unix or Windows)
    if let Err(e) = logging::init_logging() {
        cli_output::error(&format!("Failed to initialize logging: {}", e));
        std::process::exit(1);
    }

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            cli_output::error(&format!("FATAL: Failed to create Tokio runtime: {e}"));
            cli_output::error("The daemon cannot start without an async runtime.");
            std::process::exit(1);
        }
    };
    if let Err(e) = rt.block_on(real_main()) {
        error!("{e:#}");
        std::process::exit(1);
    }
}

/// Handle uninstall command - uninstall without prompts
async fn handle_uninstall() -> Result<()> {
    use std::io::Write;
    use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let _ = stdout.set_color(ColorSpec::new().set_fg(Some(Color::Cyan)));
    let _ = writeln!(stdout, "Uninstalling kodegend...");
    let _ = stdout.reset();

    // Run uninstall directly - no prompts
    crate::install::runners::run_uninstall().await
}

async fn real_main() -> Result<()> {
    let args = cli::Args::parse();

    // Default behavior: run daemon (automagical installation happens inside)
    match args.sub {
        None => run_daemon(false, None, false).await,
        Some(cli::Cmd::Uninstall) => handle_uninstall().await,
        Some(cli::Cmd::Status) => handle_status().await,
        Some(cli::Cmd::Start) => handle_start().await,
        Some(cli::Cmd::Stop) => handle_stop().await,
        Some(cli::Cmd::Restart) => handle_restart().await,
        Some(cli::Cmd::Vulnerabilities { filter, package, critical_only }) => {
            handle_vulnerabilities(filter.as_deref(), package.as_deref(), critical_only).await
        }
    }
}

async fn run_daemon(
    _force_foreground: bool, // NOTE: Parameter kept for API compatibility but unused
    config_path: Option<String>,
    use_system: bool,
) -> Result<()> {
    // Main process always stays in foreground - service managers handle daemonization

    // Determine config path based on CLI arguments
    let cfg_path = if let Some(path) = config_path {
        // User specified an explicit config path
        PathBuf::from(path)
    } else if use_system {
        // User wants system-wide config
        PathBuf::from("/etc/kodegend/kodegend.toml")
    } else {
        // Default to user config directory
        let config_dir = KodegenConfig::user_config_dir()?.join("kodegend");
        fs::create_dir_all(&config_dir)?;
        config_dir.join("kodegend.toml")
    };

    // Auto-generate config file if it doesn't exist
    if !cfg_path.exists() {
        info!(
            "Config not found at {}, creating default configuration",
            cfg_path.display()
        );

        // Create parent directory if needed
        if let Some(parent) = cfg_path.parent() {
            fs::create_dir_all(parent).context("Failed to create config directory")?;
        }

        // Serialize and write default config
        let default_toml = toml::to_string_pretty(&config::ServiceConfig::default())
            .context("Failed to serialize default config")?;
        fs::write(&cfg_path, default_toml).context("Failed to write config file")?;

        info!("Created default configuration at {}", cfg_path.display());
    }

    // Load config from disk
    let cfg_str = fs::read_to_string(&cfg_path).context("Failed to read config file")?;
    let cfg: config::ServiceConfig = toml::from_str(&cfg_str).context("Failed to parse config")?;

    info!("Using config from: {}", cfg_path.display());

    // Create PID file AFTER daemonization and config loading
    // Store in variable to keep it alive for entire daemon lifetime
    let pid_file =
        daemon::PidFile::create(cfg.pid_file.clone()).context("Failed to create PID file")?;
    // PID file will be automatically cleaned up when pid_file is dropped

    info!("kodegen daemon starting (pid {})", std::process::id());
    info!("PID file location: {}", pid_file.path().display());

    // Installation must complete before starting services
    // This creates TLS certificates and installs required components
    ensure_installed().await?;

    // Create and run service manager
    // Note: Signal handlers are now installed within ServiceManager::run()
    // HTTP servers will be started gracefully inside the service loop
    let mgr = ServiceManager::new(cfg)?;

    info!("kodegen daemon started successfully");

    // Run daemon main loop - blocks until shutdown signal
    mgr.run().await?;

    info!("kodegen daemon exiting - PID file will be cleaned up automatically");
    // _pid_file drops here, automatically removing the PID file

    Ok(())
}

/// Handle status command - check if daemon is running with detailed info
async fn handle_status() -> Result<()> {
    use crate::daemon::ServiceStatus;
    
    // First check if daemon is running via PID file
    let status = match control::check_status().await {
        Ok(s) => s,
        Err(e) => {
            cli_output::error(&format!("Error checking status: {e:#}"));
            std::process::exit(1);
        }
    };
    
    if status.is_running() {
        // Extract PID from running status
        if let Some(pid) = status.pid() {
            // Daemon is running, try to query detailed status via socket
            #[cfg(unix)]
            {
                use crate::status::{StatusQuery, send_message, recv_message, format_duration};
                use std::os::unix::net::UnixStream;

                let is_elevated = crate::platform::is_elevated();
                let socket_path = crate::platform::status_socket_path(is_elevated);
                
                match UnixStream::connect(&socket_path) {
                    Ok(mut stream) => {
                        // Set timeout to prevent hanging
                        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                            .context("Failed to set socket timeout")?;
                        
                        // Send query
                        if let Err(e) = send_message(&mut stream, &StatusQuery::All) {
                            cli_output::error(&format!("kodegend is running (PID: {}) but status query failed: {}", pid, e));
                            std::process::exit(0);
                        }
                        
                        // Receive response
                        let response: crate::status::StatusResponse = match recv_message(&mut stream) {
                            Ok(r) => r,
                            Err(e) => {
                                cli_output::error(&format!("kodegend is running (PID: {}) but failed to receive status: {}", pid, e));
                                std::process::exit(0);
                            }
                        };
                        
                        // Display formatted output
                        cli_output::info("● kodegend.service - KODEGEN Daemon");
                        cli_output::info("   Active: active (running)");
                        cli_output::info(&format!("   Main PID: {}", response.daemon_pid));
                        cli_output::info(&format!("   Uptime: {}", format_duration(response.daemon_uptime)));
                        println!();
                        
                        if response.services.is_empty() {
                            cli_output::info("   No services configured");
                        } else {
                            cli_output::info("   Services:");
                            for svc in response.services {
                                let state_str = format!("{:?}", svc.state).to_lowercase();
                                print!("     {:24} {:10}", svc.name, state_str);
                                
                                if let Some(uptime) = svc.uptime {
                                    print!("  uptime={}", format_duration(uptime));
                                }
                                
                                let restarts_display = if let Some(max) = svc.max_restarts {
                                    format!("{}/{}", svc.restart_count, max)
                                } else {
                                    format!("{}/∞", svc.restart_count)
                                };
                                print!("  restarts={}", restarts_display);
                                
                                if let Some(delay) = svc.next_restart_delay {
                                    print!("  (restarting in {})", format_duration(delay));
                                }
                                
                                if let Some(remaining) = svc.success_window_remaining
                                    && remaining.as_secs() > 0
                                {
                                    print!("  (counter resets in {})", format_duration(remaining));
                                }
                                
                                if let Some(reason) = svc.failure_reason {
                                    print!("  reason=\"{}\"", reason);
                                }
                                
                                println!();
                            }
                        }
                        
                        std::process::exit(0);
                    }
                    Err(_) => {
                        // Socket not available, fall back to basic status
                        cli_output::info("● kodegend.service - KODEGEN Daemon");
                        cli_output::info("   Active: active (running)");
                        cli_output::info(&format!("   Main PID: {}", pid));
                        cli_output::info("   Note: Detailed status not available (socket unavailable)");
                        std::process::exit(0);
                    }
                }
            }

            #[cfg(windows)]
            {
                use crate::status::{StatusQuery, send_message, recv_message, format_duration};
                use crate::platform::windows::named_pipe::connect_named_pipe;

                let is_elevated = crate::platform::is_elevated();
                let socket_path = crate::platform::status_socket_path(is_elevated);
                let path_str = socket_path.to_str().expect("Invalid pipe path");

                match connect_named_pipe(path_str) {
                    Ok(mut stream) => {
                        // Note: Windows Named Pipes don't have set_read_timeout in our wrapper
                        // Timeout is handled at pipe creation level

                        // Send query
                        if let Err(e) = send_message(&mut stream, &StatusQuery::All) {
                            cli_output::error(&format!("kodegend is running (PID: {}) but status query failed: {}", pid, e));
                            std::process::exit(0);
                        }

                        // Receive response
                        let response: crate::status::StatusResponse = match recv_message(&mut stream) {
                            Ok(r) => r,
                            Err(e) => {
                                cli_output::error(&format!("kodegend is running (PID: {}) but failed to receive status: {}", pid, e));
                                std::process::exit(0);
                            }
                        };

                        // Display formatted output (same as Unix)
                        cli_output::info("● kodegend.service - KODEGEN Daemon");
                        cli_output::info("   Active: active (running)");
                        cli_output::info(&format!("   Main PID: {}", response.daemon_pid));
                        cli_output::info(&format!("   Uptime: {}", format_duration(response.daemon_uptime)));
                        println!();

                        if response.services.is_empty() {
                            cli_output::info("   No services configured");
                        } else {
                            cli_output::info("   Services:");
                            for svc in response.services {
                                let state_str = format!("{:?}", svc.state).to_lowercase();
                                print!("     {:24} {:10}", svc.name, state_str);

                                if let Some(uptime) = svc.uptime {
                                    print!("  uptime={}", format_duration(uptime));
                                }

                                let restarts_display = if let Some(max) = svc.max_restarts {
                                    format!("{}/{}", svc.restart_count, max)
                                } else {
                                    format!("{}/∞", svc.restart_count)
                                };
                                print!("  restarts={}", restarts_display);

                                if let Some(delay) = svc.next_restart_delay {
                                    print!("  (restarting in {})", format_duration(delay));
                                }

                                if let Some(remaining) = svc.success_window_remaining
                                    && remaining.as_secs() > 0
                                {
                                    print!("  (counter resets in {})", format_duration(remaining));
                                }

                                if let Some(reason) = svc.failure_reason {
                                    print!("  reason=\"{}\"", reason);
                                }

                                println!();
                            }
                        }

                        std::process::exit(0);
                    }
                    Err(_) => {
                        // Named pipe not available, fall back to basic status
                        cli_output::info("● kodegend.service - KODEGEN Daemon");
                        cli_output::info("   Active: active (running)");
                        cli_output::info(&format!("   Main PID: {}", pid));
                        cli_output::info("   Note: Detailed status not available (named pipe unavailable)");
                        std::process::exit(0);
                    }
                }
            }
            
            #[cfg(not(unix))]
            {
                // Windows: Basic status only for now
                cli_output::info("● kodegend.service - KODEGEN Daemon");
                cli_output::info("   Active: active (running)");
                cli_output::info(&format!("   Main PID: {}", pid));
                std::process::exit(0);
            }
        }
    }
    
    // Handle all non-running states
    cli_output::info("● kodegend.service - KODEGEN Daemon");
    
    // Determine active status based on the specific variant
    match &status {
        ServiceStatus::Zombie { .. } => {
            cli_output::info(&format!("   Active: failed ({})", status.description()));
        }
        _ => {
            cli_output::info(&format!("   Active: inactive ({})", status.description()));
        }
    }
    
    // Show PID if available
    if let Some(pid) = status.pid() {
        match &status {
            ServiceStatus::Zombie { .. } => {
                cli_output::info(&format!("   Main PID: {} (zombie/defunct)", pid));
            }
            _ => {
                // For StaleFile, show it in the warning message below
            }
        }
    }
    
    // Show variant-specific messages
    match status {
        ServiceStatus::StaleFile { pid } => {
            cli_output::warning(&format!("   Stale PID file found (PID: {})", pid));
            cli_output::info("   Cleanup: Remove PID file to clear this warning");
        }
        ServiceStatus::InvalidFile { error } => {
            cli_output::error(&format!("   Invalid PID file: {}", error));
            cli_output::info("   Cleanup: Remove corrupted PID file");
        }
        ServiceStatus::Zombie { .. } => {
            cli_output::info("   Note: Process has exited but parent hasn't reaped it");
            cli_output::info("   Action: Wait for parent process to reap, or reboot");
        }
        ServiceStatus::Stopped => {
            // No additional message for stopped state
        }
        ServiceStatus::Running { .. } => {
            // Should be unreachable - handled above
            unreachable!("Running status should have been handled earlier");
        }
    }
    
    std::process::exit(1)
}

/// Handle start command - start the daemon service
async fn handle_start() -> Result<()> {
    match control::start_daemon().await {
        Ok(()) => {
            cli_output::success("kodegend started successfully");
            std::process::exit(0);
        }
        Err(e) => {
            cli_output::error(&format!("Failed to start: {e:#}"));
            std::process::exit(1);
        }
    }
}

/// Handle stop command - stop the daemon service
async fn handle_stop() -> Result<()> {
    match control::stop_daemon().await {
        Ok(()) => {
            cli_output::success("kodegend stopped successfully");
            std::process::exit(0);
        }
        Err(e) => {
            cli_output::error(&format!("Failed to stop: {e:#}"));
            std::process::exit(1);
        }
    }
}

/// Handle restart command - restart the daemon service
async fn handle_restart() -> Result<()> {
    match control::restart_daemon().await {
        Ok(()) => {
            cli_output::success("kodegend restarted successfully");
            std::process::exit(0);
        }
        Err(e) => {
            cli_output::error(&format!("Failed to restart: {e:#}"));
            std::process::exit(1);
        }
    }
}

/// Handle vulnerabilities command - query vulnerability scan results
/// 
/// Uses `query_vulnerabilities()` from status module which leverages:
/// - SIMD-accelerated pattern matching via `Vulnerability::matches_pattern()`
/// - Exact package matching via `Vulnerability::affects_package()`
async fn handle_vulnerabilities(
    filter: Option<&str>,
    package: Option<&str>,
    critical_only: bool,
) -> Result<()> {
    use crate::security::audit::{VulnerabilityScanner, AuditThresholds, VulnerabilitySeverity};
    use crate::status::query_vulnerabilities;
    
    cli_output::info("Running vulnerability scan...");
    
    // Create scanner with default thresholds
    let thresholds = AuditThresholds::new(0, 2, 10, 50);
    let scanner = VulnerabilityScanner::new(thresholds);
    
    match scanner.scan_dependencies().await {
        Ok(result) => {
            // Use query_vulnerabilities for SIMD-accelerated filtering
            let filtered = query_vulnerabilities(&result, filter, package, critical_only);
            
            if filtered.is_empty() {
                if filter.is_some() || package.is_some() || critical_only {
                    cli_output::success("No vulnerabilities matching filter criteria");
                } else {
                    cli_output::success("No vulnerabilities found");
                }
                std::process::exit(0);
            }
            
            // Show filter info if filtering was applied
            if let Some(pattern) = filter {
                cli_output::info(&format!("Filter pattern: \"{}\"", pattern));
            }
            if let Some(pkg) = package {
                cli_output::info(&format!("Package filter: \"{}\"", pkg));
            }
            
            cli_output::info(&format!(
                "Found {} vulnerabilities{}:",
                filtered.len(),
                if filtered.len() != result.vulnerabilities.len() {
                    format!(" (of {} total)", result.vulnerabilities.len())
                } else {
                    String::new()
                }
            ));
            
            for vuln in &filtered {
                let severity_str = match vuln.severity {
                    VulnerabilitySeverity::Critical => "CRITICAL",
                    VulnerabilitySeverity::High => "HIGH",
                    VulnerabilitySeverity::Medium => "MEDIUM",
                    VulnerabilitySeverity::Low => "LOW",
                    VulnerabilitySeverity::Info => "INFO",
                };
                
                cli_output::info(&format!(
                    "  [{severity_str}] {} in {} v{}", 
                    vuln.id, 
                    vuln.package, 
                    vuln.version
                ));
                
                if let Some(ref patched) = vuln.patched {
                    cli_output::info(&format!("    Patched in: {patched}"));
                }
            }
            
            // Summary of filtered results
            let critical = filtered.iter()
                .filter(|v| v.severity == VulnerabilitySeverity::Critical)
                .count();
            let high = filtered.iter()
                .filter(|v| v.severity == VulnerabilitySeverity::High)
                .count();
            let medium = filtered.iter()
                .filter(|v| v.severity == VulnerabilitySeverity::Medium)
                .count();
            let low = filtered.iter()
                .filter(|v| v.severity == VulnerabilitySeverity::Low)
                .count();
            
            cli_output::info(&format!(
                "Summary: {} critical, {} high, {} medium, {} low",
                critical, high, medium, low
            ));
            
            // Exit with error code if critical vulnerabilities found
            if critical > 0 {
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        Err(e) => {
            cli_output::error(&format!("Vulnerability scan failed: {e:#}"));
            std::process::exit(1);
        }
    }
}
