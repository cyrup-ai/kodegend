mod cli;
mod config;
mod control;
mod daemon;
mod ipc;
mod lifecycle;
mod logging;
mod manager;
mod platform;
mod service;
mod state_machine;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use kodegen_config::KodegenConfig;
use log::{error, info};
use manager::ServiceManager;
use kodegend::install::ensure_installed;

fn main() {
    // Windows service mode detection
    // When SCM starts the service, it passes --service argument
    #[cfg(target_os = "windows")]
    {
        if std::env::args().any(|arg| arg == "--service" || arg == "--windows-service") {
            // Running as Windows service - invoke service dispatcher
            if let Err(e) = platform::start_windows_service() {
                eprintln!("Windows service error: {}", e);
                std::process::exit(1);
            }
            return;
        }
    }

    // Initialize platform-appropriate logging (Unix or Windows)
    if let Err(e) = logging::init_logging() {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("FATAL: Failed to create Tokio runtime: {e}");
            eprintln!("The daemon cannot start without an async runtime.");
            std::process::exit(1);
        }
    };
    if let Err(e) = rt.block_on(real_main()) {
        error!("{e:#}");
        std::process::exit(1);
    }
}

async fn real_main() -> Result<()> {
    let args = cli::Args::parse();

    match args.sub.unwrap_or(cli::Cmd::Run {
        foreground: false,
        config: None,
        system: false,
    }) {
        cli::Cmd::Run {
            foreground,
            config,
            system,
        } => run_daemon(foreground, config, system).await,
        cli::Cmd::Status => handle_status(),
        cli::Cmd::Start => handle_start(),
        cli::Cmd::Stop => handle_stop(),
        cli::Cmd::Restart => handle_restart(),
    }
}

async fn run_daemon(
    _force_foreground: bool,  // NOTE: Parameter kept for API compatibility but unused
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
        let config_dir = KodegenConfig::user_config_dir()?
            .join("kodegend");
        fs::create_dir_all(&config_dir)?;
        config_dir.join("kodegend.toml")
    };

    // Auto-generate config file if it doesn't exist
    if !cfg_path.exists() {
        info!("Config not found at {}, creating default configuration", cfg_path.display());
        
        // Create parent directory if needed
        if let Some(parent) = cfg_path.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create config directory")?;
        }
        
        // Serialize and write default config
        let default_toml = toml::to_string_pretty(&config::ServiceConfig::default())
            .context("Failed to serialize default config")?;
        fs::write(&cfg_path, default_toml)
            .context("Failed to write config file")?;
        
        info!("Created default configuration at {}", cfg_path.display());
    }

    // Load config from disk
    let cfg_str = fs::read_to_string(&cfg_path)
        .context("Failed to read config file")?;
    let cfg: config::ServiceConfig = toml::from_str(&cfg_str)
        .context("Failed to parse config")?;

    info!("Using config from: {}", cfg_path.display());

    // Create PID file AFTER daemonization and config loading
    // Store in variable to keep it alive for entire daemon lifetime
    let pid_file = daemon::PidFile::create(cfg.pid_file.clone())
        .context("Failed to create PID file")?;
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
    
    // Notify systemd we're ready (if running under systemd)
    daemon::systemd_ready();
    
    info!("kodegen daemon started successfully");

    // Run daemon main loop - blocks until shutdown signal
    mgr.run().await?;
    
    info!("kodegen daemon exiting - PID file will be cleaned up automatically");
    // _pid_file drops here, automatically removing the PID file
    
    Ok(())
}

/// Handle status command - check if daemon is running
fn handle_status() -> Result<()> {
    match control::check_status() {
        Ok(true) => {
            println!("kodegend is running");
            std::process::exit(0);
        }
        Ok(false) => {
            println!("kodegend is stopped");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error checking status: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Handle start command - start the daemon service
fn handle_start() -> Result<()> {
    match control::start_daemon() {
        Ok(()) => {
            println!("kodegend started successfully");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Failed to start: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Handle stop command - stop the daemon service
fn handle_stop() -> Result<()> {
    match control::stop_daemon() {
        Ok(()) => {
            println!("kodegend stopped successfully");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Failed to stop: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Handle restart command - restart the daemon service
fn handle_restart() -> Result<()> {
    match control::restart_daemon() {
        Ok(()) => {
            println!("kodegend restarted successfully");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Failed to restart: {e:#}");
            std::process::exit(1);
        }
    }
}
