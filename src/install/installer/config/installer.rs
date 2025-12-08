//! Configuration generation for Kodegen daemon
//!
//! This module provides configuration file generation for the daemon.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use log::info;

/// Create default configuration file with optimized config generation
#[allow(dead_code)] // Library function for installer/setup operations
pub fn create_default_configuration(config_path: &Path) -> Result<()> {
    let config_dir = config_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid configuration path"))?;

    // Create configuration directory if it doesn't exist
    fs::create_dir_all(config_dir).context("Failed to create configuration directory")?;

    // Default configuration content
    let default_config = r#"
# Kodegen Daemon Configuration

[daemon]
# Daemon process settings
pid_file = "/var/run/kodegen/daemon.pid"
log_level = "info"
log_file = "/var/log/kodegen/daemon.log"

[network]
# Network configuration
bind_address = "127.0.0.1"
port = 33399
max_connections = 1000

[security]
# Security settings
enable_tls = true
cert_file = "/usr/local/var/kodegen/certs/server.crt"
key_file = "/usr/local/var/kodegen/certs/server.key"
ca_file = "/usr/local/var/kodegen/certs/ca.crt"

[services]
# Service configuration
enable_autoconfig = true
enable_voice = false

[database]
# Database configuration
url = "surrealkv:///usr/local/var/kodegen/data/kodegen.db"
namespace = "kodegen"
database = "main"

[plugins]
# Plugin configuration
plugin_dir = "/usr/local/var/kodegen/plugins"
enable_sandboxing = true
max_memory_mb = 256
timeout_seconds = 30
"#;

    // Write default configuration
    fs::write(config_path, default_config).context("Failed to write default configuration")?;

    info!("Created default configuration at {config_path:?}");
    Ok(())
}
