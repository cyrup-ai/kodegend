mod cli;
mod config;
mod control;
mod daemon;
mod ipc;
mod lifecycle;
mod manager;
mod service;
mod state_machine;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info};
use manager::ServiceManager;

fn main() {
    // Initialize logger with custom format for daemon
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
        .filter_level(log::LevelFilter::Info)
        .init();

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
    force_foreground: bool,
    config_path: Option<String>,
    use_system: bool,
) -> Result<()> {
    let should_stay_foreground = force_foreground || daemon::need_foreground();

    if !should_stay_foreground {
        daemon::daemonise(Path::new("/var/run/kodegend.pid"))?;
    }

    // Determine config path based on CLI arguments
    let cfg_path = if let Some(path) = config_path {
        // User specified an explicit config path
        PathBuf::from(path)
    } else if use_system {
        // User wants system-wide config
        PathBuf::from("/etc/kodegend/kodegend.toml")
    } else {
        // Default to user config directory
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
            .join("kodegend");
        config_dir.join("kodegend.toml")
    };

    // Check installation state before starting services
    use kodegend::install::{check_installation_state, ensure_installed, InstallationState};
    
    info!("Checking Kodegen installation state...");
    let install_state = check_installation_state();
    
    match install_state {
        InstallationState::NotInstalled | InstallationState::PartiallyInstalled => {
            info!("Installation required: {:?}", install_state);
            info!("Running automatic installation...");
            
            ensure_installed().await
                .context("Failed to install Kodegen binaries")?;
            
            info!("Installation completed successfully");
        }
        InstallationState::FullyInstalled => {
            info!("Installation verified - all components present");
        }
    }

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

    manager::install_signal_handlers()?;
    let mut mgr = ServiceManager::new(&cfg)?;

    // Start category HTTP servers
    mgr.start_http_servers(&cfg).await?;

    daemon::systemd_ready(); // tell systemd we are ready
    info!("kodegen daemon started (pid {})", std::process::id());
    mgr.run().await?;
    info!("kodegen daemon exiting");
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
