//! Main installation flow orchestration for Kodegen daemon
//!
//! This module coordinates the complete installation process including toolchain setup,
//! certificate generation, service configuration, and daemon installation.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use log::{info, warn};
use tokio::sync::mpsc;

use super::super::core::{AsyncTask, CertificateConfig, InstallContext, InstallProgress};
use super::super::fluent_voice;
use super::super::install_daemon_async;
use super::certificates::generate_wildcard_certificate_only;
use super::services::{build_installer_config, configure_services};
use super::toolchain::{ensure_rust_toolchain, verify_rust_toolchain_file};
use crate::install::wizard::InstallationResult;

/// Configure and install the Kodegen daemon with optimized installation flow
pub async fn install_kodegen_daemon(
    exe_path: PathBuf,
    config_path: PathBuf,
    auto_start: bool,
    progress_tx: Option<mpsc::Sender<InstallProgress>>,
) -> Result<InstallationResult> {
    let mut context = InstallContext::new(exe_path.clone());
    context.config_path = config_path.clone();

    // Set progress channel in context (don't capture in closures)
    if let Some(tx) = progress_tx {
        context.set_progress_channel(tx);
    }

    // Build custom certificate configuration using builder pattern
    let cert_config = CertificateConfig::new("Kodegen Local CA".to_string())
        .organization("Kodegen".to_string())
        .country("US".to_string())
        .validity_days(365)
        .key_size(2048)
        .add_san("mcp.kodegen.ai".to_string())
        .add_san("localhost".to_string())
        .add_san("127.0.0.1".to_string())
        .add_san("::1".to_string());

    context.set_certificate_config(cert_config);

    // Chain installation steps with AsyncTask combinators
    let result_context = {
        let ctx = context;
        AsyncTask::from_future(async { verify_rust_toolchain_file() })
            .and_then(|()| async { ensure_rust_toolchain().await })
            .and_then(move |()| async move {
                ctx.validate_prerequisites()?;
                Ok(ctx)
            })
            .and_then(|ctx| async move {
                ctx.create_directories()?;
                Ok(ctx)
            })
            .and_then(|ctx| async move {
                ctx.generate_certificates()?;
                Ok(ctx)
            })
            .and_then(move |mut ctx| async move {
                configure_services(&mut ctx, auto_start)?;
                Ok(ctx)
            })
            .and_then(move |ctx| async move {
                let installer = build_installer_config(&ctx, auto_start)?;
                install_daemon_async(installer).await?;
                Ok(ctx)
            })
            .map(|ctx| {
                info!("Installation pipeline completed successfully");
                ctx
            })
            .map_err(|e: anyhow::Error| {
                anyhow::anyhow!("Installation pipeline failed: {e}")
            })
            .await?
    };

    let mut context = result_context;

    // Track installation results for each component
    let mut certificates_installed = true;
    // Tracks hosts file modification status; returned in InstallationResult
    #[allow(unused_assignments)]
    let mut host_entries_added = true;
    let mut fluent_voice_installed = true;
    let service_started = false; // Will be true if auto_start enabled

    info!("Daemon installed successfully");

    // Generate wildcard certificate and capture content (runs as unprivileged user)
    // Import to trust store is deferred to install_with_elevated_privileges() in main.rs
    let certificate_content = match generate_wildcard_certificate_only().await {
        Ok(content) => {
            info!("Certificate generated successfully");
            Some(content)
        }
        Err(e) => {
            warn!("Failed to generate wildcard certificate: {e}");
            certificates_installed = false;
            None
        }
    };

    // Hosts file modification is deferred to install_with_elevated_privileges() in main.rs
    // This runs as unprivileged user - privileged operations happen at the end of installation
    // add_kodegen_host_entries() is now called from install_with_elevated_privileges()
    
    // Mark as not yet added - will be set to true if privileged ops succeed
    host_entries_added = false;

    // Install fluent-voice components
    let fluent_voice_path = std::path::Path::new("/opt/kodegen/fluent-voice");
    if let Err(e) = fluent_voice::install_fluent_voice(fluent_voice_path).await {
        warn!("Failed to install fluent-voice components: {e}");
        fluent_voice_installed = false;
    }

    // Determine actual service path
    let service_path = get_service_path(&context);

    context.send_critical_progress(InstallProgress::complete(
        "installation".to_string(),
        "Kodegen daemon installed successfully".to_string(),
    ))?;

    // Explicitly drop progress sender to close channel
    context.progress_tx = None;

    Ok(InstallationResult {
        data_dir: context.data_dir.clone(),
        service_path,
        service_started,
        certificates_installed,
        host_entries_added,
        fluent_voice_installed,
        certificate_content,
    })
}

/// Determine the platform-specific service file path (always system-wide for system daemons)
fn get_service_path(_context: &InstallContext) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/LaunchDaemons/com.kodegen.daemon.plist")
    }

    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/etc/systemd/system/kodegend.service")
    }

    #[cfg(target_os = "windows")]
    {
        PathBuf::from("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\kodegend")
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("unknown-platform")
    }
}

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
